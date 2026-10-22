import { Server as SocketIOServer, Socket } from 'socket.io';
import * as Y from 'yjs';
import crypto from 'crypto';
import {
    ActiveCursorPresence,
    AuthenticatedUser,
    ChatMessage,
    CollaboratorRole,
    InlineComment,
    SecurityEvent,
    SharedBreakpoint,
} from '../types';
import {
    containsXssVector,
    sanitizeText,
    scanCodeForThreats,
    verifyToken,
} from '../security/securityMiddleware';
import {
    db,
    getUserRoleInProject,
    logSecurityEvent,
    mapCommentRow,
    mapFileRow,
    mapSecurityLogRow,
    statements,
} from '../db';

/**
 * Ensure dedicated SQLite table exists for storing binary Yjs CRDT state vectors
 * (`Y.encodeStateAsUpdate(ydoc)`) alongside plain text in the `files` table.
 */
db.exec(`
  CREATE TABLE IF NOT EXISTS file_crdt_states (
    file_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    yjs_binary BLOB NOT NULL,
    byte_length INTEGER NOT NULL DEFAULT 0,
    updated_by TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
  );
`);

const crdtStatements = {
    getCrdtState: db.prepare(
        'SELECT yjs_binary, byte_length, updated_at FROM file_crdt_states WHERE file_id = ?'
    ),
    upsertCrdtState: db.prepare(`
    INSERT INTO file_crdt_states (file_id, project_id, yjs_binary, byte_length, updated_by, updated_at)
    VALUES (@fileId, @projectId, @yjsBinary, @byteLength, @updatedBy, @updatedAt)
    ON CONFLICT(file_id) DO UPDATE SET
      yjs_binary = excluded.yjs_binary,
      byte_length = excluded.byte_length,
      updated_by = excluded.updated_by,
      updated_at = excluded.updated_at
  `),
};

const MAX_CRDT_UPDATE_BYTES = 32 * 1024; // 32 KB hard cap per CRDT delta
const HIGH_FREQ_MAX_EVENTS = 40; // Max 40 yjs-update / cursor-update events per 1 second
const HIGH_FREQ_WINDOW_MS = 1_000;
const COLLAB_MAX_EVENTS = 5; // Max 5 chat-message / new-comment events per 10 seconds
const COLLAB_WINDOW_MS = 10_000;
const PERSIST_DEBOUNCE_MS = 750; // Debounce SQLite persistence for high-speed typing

interface ManagedCrdtDocument {
    fileId: string;
    projectId: string;
    ydoc: Y.Doc;
    lastUpdatedBy: string;
    lastUpdatedAt: number;
    debounceTimer: NodeJS.Timeout | null;
    dirty: boolean;
}

interface SocketRateBuckets {
    highFrequencyTimestamps: number[];
    collabTimestamps: number[];
}

interface AuthenticatedSocket extends Socket {
    data: {
        user: AuthenticatedUser;
        clientIp: string;
        joinedProjects: Set<string>;
        activeFileId: string | null;
        activeProjectId: string | null;
        rateBuckets: SocketRateBuckets;
    };
}

// In-memory state stores for active Yjs CRDT documents, cursors, breakpoints, and chat
const activeDocs = new Map<string, ManagedCrdtDocument>();
const projectPresence = new Map<string, Map<string, ActiveCursorPresence>>();
const fileBreakpoints = new Map<string, Map<number, SharedBreakpoint>>();
const projectChatHistory = new Map<string, ChatMessage[]>();

// Live CRDT & WebSocket security telemetry counters
const crdtTelemetry = {
    totalUpdatesApplied: 0,
    totalBytesSynced: 0,
    blockedRbacWrites: 0,
    blockedFloodEvents: 0,
    blockedCorruptedPayloads: 0,
    blockedOversizePayloads: 0,
};

export function getCrdtTelemetry() {
    return {
        ...crdtTelemetry,
        activeDocumentsInMemory: activeDocs.size,
    };
}

function getSocketIp(socket: Socket): string {
    const forwarded = socket.handshake.headers['x-forwarded-for'];
    if (typeof forwarded === 'string' && forwarded.length > 0) {
        return forwarded.split(',')[0].trim();
    }
    return socket.handshake.address || '127.0.0.1';
}

/**
 * Normalizes incoming WebSocket binary payloads (`Buffer`, `Uint8Array`, `ArrayBuffer`,
 * `number[]`, or base64 `string`) into a `Uint8Array`.
 */
function normalizeBinaryUpdate(rawUpdate: unknown): Uint8Array | null {
    try {
        if (!rawUpdate) {
            return null;
        }
        if (rawUpdate instanceof Uint8Array) {
            return new Uint8Array(
                rawUpdate.buffer,
                rawUpdate.byteOffset,
                rawUpdate.byteLength
            );
        }
        if (Buffer.isBuffer(rawUpdate)) {
            return new Uint8Array(
                rawUpdate.buffer,
                rawUpdate.byteOffset,
                rawUpdate.byteLength
            );
        }
        if (rawUpdate instanceof ArrayBuffer) {
            return new Uint8Array(rawUpdate);
        }
        if (Array.isArray(rawUpdate)) {
            if (rawUpdate.length > MAX_CRDT_UPDATE_BYTES + 1024) {
                return null;
            }
            return Uint8Array.from(
                rawUpdate.map((byte) => (typeof byte === 'number' ? byte & 0xff : 0))
            );
        }
        if (typeof rawUpdate === 'string') {
            const buf = Buffer.from(rawUpdate, 'base64');
            return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
        }
        if (
            typeof rawUpdate === 'object' &&
            rawUpdate !== null &&
            'type' in rawUpdate &&
            (rawUpdate as { type?: string }).type === 'Buffer' &&
            Array.isArray((rawUpdate as { data?: unknown[] }).data)
        ) {
            const buf = Buffer.from((rawUpdate as { data: number[] }).data);
            return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
        }
        return null;
    } catch {
        return null;
    }
}

/**
 * Loads or initializes an authoritative `Y.Doc` for a file from SQLite.
 * Restores the binary CRDT state if previously persisted, or seeds the `monaco`
 * shared text type from the file's plain-text column.
 */
function getOrCreateManagedDoc(
    fileId: string,
    projectId: string,
    initialPlainText: string,
    initialAuthor: string
): ManagedCrdtDocument {
    const existing = activeDocs.get(fileId);
    if (existing) {
        return existing;
    }

    const ydoc = new Y.Doc();
    const ytext = ydoc.getText('monaco');

    const storedState = crdtStatements.getCrdtState.get(fileId) as
        | { yjs_binary: Buffer; byte_length: number; updated_at: string }
        | undefined;

    let initializedFromBinary = false;
    if (storedState && storedState.yjs_binary && storedState.yjs_binary.length > 0) {
        try {
            const binaryUint8 = new Uint8Array(
                storedState.yjs_binary.buffer,
                storedState.yjs_binary.byteOffset,
                storedState.yjs_binary.byteLength
            );
            Y.applyUpdate(ydoc, binaryUint8, 'sqlite-bootstrap');
            initializedFromBinary = true;
        } catch {
            initializedFromBinary = false;
        }
    }

    if (!initializedFromBinary) {
        ydoc.transact(() => {
            if (ytext.length > 0) {
                ytext.delete(0, ytext.length);
            }
            if (initialPlainText) {
                ytext.insert(0, initialPlainText);
            }
        }, 'sqlite-bootstrap');
    }

    const managed: ManagedCrdtDocument = {
        fileId,
        projectId,
        ydoc,
        lastUpdatedBy: initialAuthor,
        lastUpdatedAt: Date.now(),
        debounceTimer: null,
        dirty: false,
    };

    activeDocs.set(fileId, managed);
    return managed;
}

/**
 * Immediately persists both the binary `Y.encodeStateAsUpdate(ydoc)` state vector
 * and the plain-text representation to SQLite inside a single atomic transaction.
 */
export function persistCrdtDocNow(managed: ManagedCrdtDocument): void {
    if (managed.debounceTimer) {
        clearTimeout(managed.debounceTimer);
        managed.debounceTimer = null;
    }

    try {
        const binaryState = Y.encodeStateAsUpdate(managed.ydoc);
        const plainText = managed.ydoc.getText('monaco').toString();
        const now = new Date().toISOString();
        const binaryBuffer = Buffer.from(binaryState);

        const persistTx = db.transaction(() => {
            statements.updateFileContent.run({
                id: managed.fileId,
                content: plainText,
                updatedBy: managed.lastUpdatedBy,
                updatedAt: now,
            });

            crdtStatements.upsertCrdtState.run({
                fileId: managed.fileId,
                projectId: managed.projectId,
                yjsBinary: binaryBuffer,
                byteLength: binaryBuffer.length,
                updatedBy: managed.lastUpdatedBy,
                updatedAt: now,
            });

            statements.updateProjectTimestamp.run({
                id: managed.projectId,
                updatedAt: now,
            });
        });

        persistTx();
        managed.dirty = false;
    } catch (err) {
        // Log persistence error without crashing the event loop
        console.error(`[CRDT Persistence Error] fileId=${managed.fileId}:`, err);
    }
}

/**
 * Schedules a debounced SQLite write for both binary Yjs state and plain text.
 */
function scheduleDebouncedPersist(managed: ManagedCrdtDocument): void {
    managed.dirty = true;
    if (managed.debounceTimer) {
        clearTimeout(managed.debounceTimer);
    }
    managed.debounceTimer = setTimeout(() => {
        managed.debounceTimer = null;
        persistCrdtDocNow(managed);
    }, PERSIST_DEBOUNCE_MS);
}

/**
 * Flushes all dirty in-memory Yjs documents to SQLite (used on server shutdown).
 */
export function flushAllCrdtDocsToSqlite(): void {
    for (const managed of activeDocs.values()) {
        if (managed.dirty || managed.debounceTimer) {
            persistCrdtDocNow(managed);
        }
    }
}

/**
 * Broadcasts a security event to all connected collaborators in the project room
 * and emits a targeted alert to the triggering socket.
 */
function broadcastSecurityAlert(
    io: SocketIOServer,
    socket: AuthenticatedSocket,
    projectId: string | null,
    securityEvent: SecurityEvent,
    userMessage: string
): void {
    const payload = {
        alertId: securityEvent.id,
        projectId,
        eventType: securityEvent.eventType,
        severity: securityEvent.severity,
        message: userMessage,
        details: securityEvent.details,
        username: securityEvent.username,
        blocked: securityEvent.blocked,
        createdAt: securityEvent.createdAt,
    };

    socket.emit('security-alert', payload);

    if (projectId) {
        io.to(`project:${projectId}`).emit('security-alert', payload);
        io.to(`project:${projectId}`).emit('security-log-new', securityEvent);
    }
}

/**
 * Per-Socket Sliding-Window / Token-Bucket Rate Limiter.
 * - High-frequency bucket (`yjs-update`, `cursor-update`): max 40 events / 1s
 * - Collaboration bucket (`chat-message`, `new-comment`, `toggle-breakpoint`, `snapshot-restored`): max 5 events / 10s
 */
function checkSocketRateLimit(
    io: SocketIOServer,
    socket: AuthenticatedSocket,
    eventName: string,
    bucketType: 'high_freq' | 'collab'
): boolean {
    const now = Date.now();
    const user = socket.data.user;
    const projectId = socket.data.activeProjectId;

    const isHighFreq = bucketType === 'high_freq';
    const maxEvents = isHighFreq ? HIGH_FREQ_MAX_EVENTS : COLLAB_MAX_EVENTS;
    const windowMs = isHighFreq ? HIGH_FREQ_WINDOW_MS : COLLAB_WINDOW_MS;

    const timestamps = isHighFreq
        ? socket.data.rateBuckets.highFrequencyTimestamps
        : socket.data.rateBuckets.collabTimestamps;

    const cutoff = now - windowMs;
    while (timestamps.length > 0 && timestamps[0] <= cutoff) {
        timestamps.shift();
    }

    if (timestamps.length >= maxEvents) {
        crdtTelemetry.blockedFloodEvents += 1;

        const secEvent = logSecurityEvent({
            projectId,
            userId: user.userId,
            username: user.username,
            eventType: 'WS_FLOOD_THROTTLED',
            severity: 'HIGH',
            details: `WebSocket flood throttled on event "${eventName}" from @${user.username} (${timestamps.length}/${maxEvents} in ${windowMs}ms)`,
            ipAddress: socket.data.clientIp,
            blocked: true,
        });

        broadcastSecurityAlert(
            io,
            socket,
            projectId,
            secEvent,
            `Rate limit exceeded on "${eventName}" (${maxEvents} per ${windowMs / 1000
            }s). Packet dropped.`
        );
        return false;
    }

    timestamps.push(now);
    return true;
}

/**
 * Initializes the JWT-authenticated Socket.IO server and DoS-hardened Yjs CRDT synchronization engine.
 */
export function initializeCrdtSocketServer(io: SocketIOServer): void {
    /**
     * 1. Handshake Authentication Middleware (`io.use`)
     * Verifies HMAC-SHA256 JWT in `socket.handshake.auth.token` before upgrading connection.
     */
    io.use((socket: Socket, next) => {
        const clientIp = getSocketIp(socket);
        const authToken =
            (typeof socket.handshake.auth?.token === 'string' &&
                socket.handshake.auth.token) ||
            (typeof socket.handshake.headers?.authorization === 'string' &&
                socket.handshake.headers.authorization) ||
            (typeof socket.handshake.query?.token === 'string' &&
                socket.handshake.query.token) ||
            '';

        if (!authToken) {
            logSecurityEvent({
                projectId: null,
                userId: null,
                username: 'unauthenticated_socket',
                eventType: 'UNAUTHORIZED_ACCESS_ATTEMPT',
                severity: 'MEDIUM',
                details: `Rejected WebSocket handshake without HMAC-JWT token from IP ${clientIp}`,
                ipAddress: clientIp,
                blocked: true,
            });
            return next(
                new Error('AUTH_TOKEN_MISSING: Valid HMAC-SHA256 JWT required in handshake.auth.token')
            );
        }

        const verifiedPayload = verifyToken(authToken);
        if (!verifiedPayload) {
            logSecurityEvent({
                projectId: null,
                userId: null,
                username: 'invalid_jwt_socket',
                eventType: 'AUTH_TOKEN_INVALID',
                severity: 'HIGH',
                details: `Rejected WebSocket handshake with invalid or expired HMAC-SHA256 JWT from IP ${clientIp}`,
                ipAddress: clientIp,
                blocked: true,
            });
            return next(
                new Error('AUTH_TOKEN_INVALID: HMAC-SHA256 signature verification failed or token expired')
            );
        }

        const authedSocket = socket as AuthenticatedSocket;
        authedSocket.data = {
            user: {
                ...verifiedPayload,
                id: verifiedPayload.userId,
            },
            clientIp,
            joinedProjects: new Set<string>(),
            activeFileId: null,
            activeProjectId: null,
            rateBuckets: {
                highFrequencyTimestamps: [],
                collabTimestamps: [],
            },
        };

        return next();
    });

    io.on('connection', (rawSocket: Socket) => {
        const socket = rawSocket as AuthenticatedSocket;
        const user = socket.data.user;

        /**
         * Event: `join-project`
         * Verifies caller's RBAC role in SQLite, registers live presence, and streams initial state.
         */
        socket.on(
            'join-project',
            (
                payload: { projectId?: string; fileId?: string },
                ack?: (response: Record<string, unknown>) => void
            ) => {
                const projectId = String(payload?.projectId || '').trim();
                if (!projectId) {
                    if (typeof ack === 'function') {
                        ack({ ok: false, error: 'projectId is required' });
                    }
                    return;
                }

                const role = getUserRoleInProject(projectId, user.userId);
                if (!role) {
                    const secEvent = logSecurityEvent({
                        projectId,
                        userId: user.userId,
                        username: user.username,
                        eventType: 'RBAC_VIOLATION_ATTEMPT',
                        severity: 'HIGH',
                        details: `Non-member @${user.username} attempted WebSocket join-project on ${projectId}`,
                        ipAddress: socket.data.clientIp,
                        blocked: true,
                    });
                    broadcastSecurityAlert(
                        io,
                        socket,
                        projectId,
                        secEvent,
                        'Access denied: you are not a member of this project.'
                    );
                    if (typeof ack === 'function') {
                        ack({ ok: false, error: 'RBAC_NOT_A_MEMBER' });
                    }
                    return;
                }

                const projectRoom = `project:${projectId}`;
                socket.join(projectRoom);
                socket.data.joinedProjects.add(projectId);
                socket.data.activeProjectId = projectId;

                if (!projectPresence.has(projectId)) {
                    projectPresence.set(projectId, new Map<string, ActiveCursorPresence>());
                }

                const presenceMap = projectPresence.get(projectId)!;
                const initialPresence: ActiveCursorPresence = {
                    userId: user.userId,
                    username: user.username,
                    displayName: user.displayName,
                    avatarColor: user.avatarColor,
                    role,
                    fileId: String(payload?.fileId || ''),
                    lineNumber: 1,
                    column: 1,
                    lastActiveAt: Date.now(),
                };
                presenceMap.set(socket.id, initialPresence);

                const activeCollaborators = Array.from(presenceMap.values());
                const chatMessages = projectChatHistory.get(projectId) || [];
                const recentLogs = (
                    statements.listSecurityLogsByProject.all(projectId, 50) as Record<
                        string,
                        unknown
                    >[]
                ).map(mapSecurityLogRow);

                io.to(projectRoom).emit('presence-update', {
                    projectId,
                    collaborators: activeCollaborators,
                });

                socket.emit('project-state-sync', {
                    projectId,
                    callerRole: role,
                    collaborators: activeCollaborators,
                    chatMessages,
                    securityLogs: recentLogs,
                });

                if (typeof ack === 'function') {
                    ack({
                        ok: true,
                        projectId,
                        role,
                        collaborators: activeCollaborators,
                        chatMessages,
                        securityLogs: recentLogs,
                    });
                }
            }
        );

        /**
         * Event: `join-file`
         * Joins a file-specific CRDT synchronization room (`file:${fileId}`) and sends
         * the authoritative Yjs state vector (`Y.encodeStateAsUpdate(ydoc)`), plain text,
         * shared breakpoints, and inline comments.
         */
        socket.on(
            'join-file',
            (
                payload: { projectId?: string; fileId?: string },
                ack?: (response: Record<string, unknown>) => void
            ) => {
                const fileId = String(payload?.fileId || '').trim();
                if (!fileId) {
                    if (typeof ack === 'function') {
                        ack({ ok: false, error: 'fileId is required' });
                    }
                    return;
                }

                const fileRow = statements.getFileById.get(fileId) as
                    | Record<string, unknown>
                    | undefined;
                if (!fileRow) {
                    if (typeof ack === 'function') {
                        ack({ ok: false, error: 'File not found' });
                    }
                    return;
                }

                const file = mapFileRow(fileRow);
                const role = getUserRoleInProject(file.projectId, user.userId);
                if (!role) {
                    const secEvent = logSecurityEvent({
                        projectId: file.projectId,
                        userId: user.userId,
                        username: user.username,
                        eventType: 'RBAC_VIOLATION_ATTEMPT',
                        severity: 'HIGH',
                        details: `Unauthorized socket join-file attempt on ${file.name} by @${user.username}`,
                        ipAddress: socket.data.clientIp,
                        blocked: true,
                    });
                    broadcastSecurityAlert(
                        io,
                        socket,
                        file.projectId,
                        secEvent,
                        'Access denied: you are not authorized to open this file.'
                    );
                    if (typeof ack === 'function') {
                        ack({ ok: false, error: 'RBAC_ACCESS_DENIED' });
                    }
                    return;
                }

                // Leave previous file room if switching files
                if (socket.data.activeFileId && socket.data.activeFileId !== fileId) {
                    socket.leave(`file:${socket.data.activeFileId}`);
                }

                const fileRoom = `file:${fileId}`;
                socket.join(fileRoom);
                socket.join(`project:${file.projectId}`);
                socket.data.activeFileId = fileId;
                socket.data.activeProjectId = file.projectId;
                socket.data.joinedProjects.add(file.projectId);

                // Update presence file pointer
                const presenceMap = projectPresence.get(file.projectId);
                if (presenceMap && presenceMap.has(socket.id)) {
                    const current = presenceMap.get(socket.id)!;
                    current.fileId = fileId;
                    current.role = role;
                    current.lastActiveAt = Date.now();
                    io.to(`project:${file.projectId}`).emit('presence-update', {
                        projectId: file.projectId,
                        collaborators: Array.from(presenceMap.values()),
                    });
                }

                const managedDoc = getOrCreateManagedDoc(
                    file.id,
                    file.projectId,
                    file.content,
                    file.updatedBy
                );

                const fullBinaryState = Buffer.from(
                    Y.encodeStateAsUpdate(managedDoc.ydoc)
                );
                const currentPlainText = managedDoc.ydoc.getText('monaco').toString();

                const bpMap =
                    fileBreakpoints.get(fileId) || new Map<number, SharedBreakpoint>();
                const breakpoints = Array.from(bpMap.values()).sort(
                    (a, b) => a.lineNumber - b.lineNumber
                );

                const comments: InlineComment[] = (
                    statements.listCommentsByFile.all(fileId) as Record<string, unknown>[]
                ).map(mapCommentRow);

                const syncPayload = {
                    fileId: file.id,
                    projectId: file.projectId,
                    name: file.name,
                    language: file.language,
                    version: file.version,
                    role,
                    update: fullBinaryState,
                    content: currentPlainText,
                    breakpoints,
                    comments,
                };

                socket.emit('yjs-init', syncPayload);

                if (typeof ack === 'function') {
                    ack({ ok: true, ...syncPayload });
                }
            }
        );

        /**
         * Event: `yjs-update`
         * Hardened CRDT binary synchronization handler:
         * 1. Enforces per-socket token-bucket rate limit (max 40/sec).
         * 2. Queries SQLite for caller's live role (`OWNER`, `EDITOR`, `VIEWER`) on every frame.
         * 3. Blocks `VIEWER` writes, logs `UNAUTHORIZED_CRDT_WRITE_BLOCKED`, and broadcasts security alert.
         * 4. Enforces 32KB max payload size and wraps `Y.applyUpdate` in `try/catch` against binary fuzzing.
         * 5. Debounces persisting both binary `Y.encodeStateAsUpdate(ydoc)` and plain text to SQLite.
         */
        socket.on(
            'yjs-update',
            (
                payload: {
                    projectId?: string;
                    fileId?: string;
                    update?: unknown;
                    content?: string;
                },
                ack?: (response: Record<string, unknown>) => void
            ) => {
                if (!checkSocketRateLimit(io, socket, 'yjs-update', 'high_freq')) {
                    if (typeof ack === 'function') {
                        ack({ ok: false, error: 'WS_FLOOD_THROTTLED' });
                    }
                    return;
                }

                const fileId = String(
                    payload?.fileId || socket.data.activeFileId || ''
                ).trim();
                if (!fileId) {
                    return;
                }

                const fileRow = statements.getFileById.get(fileId) as
                    | Record<string, unknown>
                    | undefined;
                if (!fileRow) {
                    return;
                }

                const file = mapFileRow(fileRow);
                const projectId = file.projectId;

                // Server-side SQLite RBAC check on every CRDT write
                const role = getUserRoleInProject(projectId, user.userId);
                if (!role || role === 'VIEWER') {
                    crdtTelemetry.blockedRbacWrites += 1;

                    const secEvent = logSecurityEvent({
                        projectId,
                        userId: user.userId,
                        username: user.username,
                        eventType: 'UNAUTHORIZED_CRDT_WRITE_BLOCKED',
                        severity: 'HIGH',
                        details: `Blocked unauthorized CRDT write on "${file.name}" from @${user.username
                            } (verified SQLite role: ${role || 'NONE'})`,
                        ipAddress: socket.data.clientIp,
                        blocked: true,
                    });

                    broadcastSecurityAlert(
                        io,
                        socket,
                        projectId,
                        secEvent,
                        `RBAC Violation: Role "${role || 'NONE'
                        }" is read-only. Unauthorized CRDT write to "${file.name}" was blocked.`
                    );

                    // Force-resync the offending VIEWER client with the authoritative server document
                    const managedDoc = getOrCreateManagedDoc(
                        file.id,
                        projectId,
                        file.content,
                        file.updatedBy
                    );
                    socket.emit('yjs-init', {
                        fileId: file.id,
                        projectId,
                        name: file.name,
                        language: file.language,
                        version: file.version,
                        role: role || 'VIEWER',
                        update: Buffer.from(Y.encodeStateAsUpdate(managedDoc.ydoc)),
                        content: managedDoc.ydoc.getText('monaco').toString(),
                        revertedUnauthorizedEdit: true,
                    });

                    if (typeof ack === 'function') {
                        ack({ ok: false, error: 'UNAUTHORIZED_CRDT_WRITE_BLOCKED' });
                    }
                    return;
                }

                // Check project lockdown state
                const projectRow = statements.getProjectById.get(projectId) as
                    | Record<string, unknown>
                    | undefined;
                if (projectRow && Boolean(projectRow.is_locked) && role !== 'OWNER') {
                    crdtTelemetry.blockedRbacWrites += 1;
                    const secEvent = logSecurityEvent({
                        projectId,
                        userId: user.userId,
                        username: user.username,
                        eventType: 'UNAUTHORIZED_CRDT_WRITE_BLOCKED',
                        severity: 'MEDIUM',
                        details: `Blocked CRDT write on locked workspace "${file.name}" by @${user.username} (${role})`,
                        ipAddress: socket.data.clientIp,
                        blocked: true,
                    });
                    broadcastSecurityAlert(
                        io,
                        socket,
                        projectId,
                        secEvent,
                        'Workspace is locked by OWNER. CRDT write rejected.'
                    );
                    if (typeof ack === 'function') {
                        ack({ ok: false, error: 'PROJECT_LOCKED' });
                    }
                    return;
                }

                const managedDoc = getOrCreateManagedDoc(
                    file.id,
                    projectId,
                    file.content,
                    file.updatedBy
                );

                // Handle binary Yjs update delta
                if (payload?.update !== undefined && payload?.update !== null) {
                    const updateUint8 = normalizeBinaryUpdate(payload.update);

                    if (!updateUint8 || updateUint8.byteLength === 0) {
                        crdtTelemetry.blockedCorruptedPayloads += 1;
                        const secEvent = logSecurityEvent({
                            projectId,
                            userId: user.userId,
                            username: user.username,
                            eventType: 'UNAUTHORIZED_CRDT_WRITE_BLOCKED',
                            severity: 'HIGH',
                            details: `Rejected malformed/empty CRDT binary frame on "${file.name}" from @${user.username}`,
                            ipAddress: socket.data.clientIp,
                            blocked: true,
                        });
                        broadcastSecurityAlert(
                            io,
                            socket,
                            projectId,
                            secEvent,
                            'Malformed CRDT binary update rejected.'
                        );
                        return;
                    }

                    // Enforce 32KB max delta size
                    if (updateUint8.byteLength > MAX_CRDT_UPDATE_BYTES) {
                        crdtTelemetry.blockedOversizePayloads += 1;
                        const secEvent = logSecurityEvent({
                            projectId,
                            userId: user.userId,
                            username: user.username,
                            eventType: 'WS_FLOOD_THROTTLED',
                            severity: 'HIGH',
                            details: `Blocked oversized CRDT update (${updateUint8.byteLength} bytes > 32768 max) on "${file.name}" from @${user.username}`,
                            ipAddress: socket.data.clientIp,
                            blocked: true,
                        });
                        broadcastSecurityAlert(
                            io,
                            socket,
                            projectId,
                            secEvent,
                            `CRDT update exceeds 32KB security limit (${updateUint8.byteLength} bytes).`
                        );
                        if (typeof ack === 'function') {
                            ack({ ok: false, error: 'CRDT_PAYLOAD_TOO_LARGE' });
                        }
                        return;
                    }

                    // Apply binary CRDT update inside strict try/catch to prevent corrupted bytes from crashing Y.Doc
                    try {
                        Y.applyUpdate(managedDoc.ydoc, updateUint8, socket.id);
                    } catch (err) {
                        crdtTelemetry.blockedCorruptedPayloads += 1;
                        const errMsg =
                            err instanceof Error ? err.message : 'Invalid Yjs binary encoding';
                        const secEvent = logSecurityEvent({
                            projectId,
                            userId: user.userId,
                            username: user.username,
                            eventType: 'UNAUTHORIZED_CRDT_WRITE_BLOCKED',
                            severity: 'CRITICAL',
                            details: `Neutralized corrupted CRDT binary payload attack on "${file.name}" from @${user.username}: ${errMsg}`,
                            ipAddress: socket.data.clientIp,
                            blocked: true,
                        });
                        broadcastSecurityAlert(
                            io,
                            socket,
                            projectId,
                            secEvent,
                            'Corrupted CRDT binary payload detected and isolated before Y.Doc crash.'
                        );
                        if (typeof ack === 'function') {
                            ack({ ok: false, error: 'CORRUPTED_CRDT_BINARY' });
                        }
                        return;
                    }

                    managedDoc.lastUpdatedBy = user.username;
                    managedDoc.lastUpdatedAt = Date.now();
                    crdtTelemetry.totalUpdatesApplied += 1;
                    crdtTelemetry.totalBytesSynced += updateUint8.byteLength;

                    const currentText = managedDoc.ydoc.getText('monaco').toString();

                    // Broadcast verified binary delta & plain text mirror to peers in the file room
                    socket.to(`file:${fileId}`).emit('yjs-update', {
                        fileId,
                        projectId,
                        update: Buffer.from(updateUint8),
                        content: currentText,
                        updatedBy: user.username,
                        userId: user.userId,
                        timestamp: managedDoc.lastUpdatedAt,
                    });

                    scheduleDebouncedPersist(managedDoc);

                    if (typeof ack === 'function') {
                        ack({
                            ok: true,
                            bytesApplied: updateUint8.byteLength,
                            timestamp: managedDoc.lastUpdatedAt,
                        });
                    }
                    return;
                }

                // Fallback support when a client sends full plain-text string for synchronization
                if (typeof payload?.content === 'string') {
                    const byteLen = Buffer.byteLength(payload.content, 'utf8');
                    if (byteLen > MAX_CRDT_UPDATE_BYTES) {
                        crdtTelemetry.blockedOversizePayloads += 1;
                        const secEvent = logSecurityEvent({
                            projectId,
                            userId: user.userId,
                            username: user.username,
                            eventType: 'WS_FLOOD_THROTTLED',
                            severity: 'HIGH',
                            details: `Blocked oversized CRDT text update (${byteLen} bytes > 32768 max) on "${file.name}" from @${user.username}`,
                            ipAddress: socket.data.clientIp,
                            blocked: true,
                        });
                        broadcastSecurityAlert(
                            io,
                            socket,
                            projectId,
                            secEvent,
                            `CRDT update exceeds 32KB limit (${byteLen} bytes).`
                        );
                        return;
                    }

                    try {
                        let deltaUpdate: Uint8Array | null = null;
                        const updateHandler = (u: Uint8Array) => {
                            deltaUpdate = u;
                        };
                        managedDoc.ydoc.on('update', updateHandler);
                        try {
                            managedDoc.ydoc.transact(() => {
                                const ytext = managedDoc.ydoc.getText('monaco');
                                const existing = ytext.toString();
                                if (existing !== payload.content) {
                                    ytext.delete(0, ytext.length);
                                    ytext.insert(0, payload.content!);
                                }
                            }, socket.id);
                        } finally {
                            managedDoc.ydoc.off('update', updateHandler);
                        }

                        managedDoc.lastUpdatedBy = user.username;
                        managedDoc.lastUpdatedAt = Date.now();
                        crdtTelemetry.totalUpdatesApplied += 1;
                        crdtTelemetry.totalBytesSynced += byteLen;

                        const outboundBinary = deltaUpdate
                            ? Buffer.from(deltaUpdate)
                            : Buffer.from(Y.encodeStateAsUpdate(managedDoc.ydoc));

                        socket.to(`file:${fileId}`).emit('yjs-update', {
                            fileId,
                            projectId,
                            update: outboundBinary,
                            content: payload.content,
                            updatedBy: user.username,
                            userId: user.userId,
                            timestamp: managedDoc.lastUpdatedAt,
                        });

                        scheduleDebouncedPersist(managedDoc);

                        if (typeof ack === 'function') {
                            ack({ ok: true, bytesApplied: byteLen });
                        }
                    } catch {
                        if (typeof ack === 'function') {
                            ack({ ok: false, error: 'CRDT_APPLY_FAILED' });
                        }
                    }
                }
            }
        );

        /**
         * Event: `cursor-update`
         * Rate-limited (40/sec) live collaborator cursor & selection telemetry broadcast.
         */
        socket.on(
            'cursor-update',
            (payload: {
                projectId?: string;
                fileId?: string;
                lineNumber?: number;
                column?: number;
            }) => {
                if (!checkSocketRateLimit(io, socket, 'cursor-update', 'high_freq')) {
                    return;
                }

                const projectId = String(
                    payload?.projectId || socket.data.activeProjectId || ''
                ).trim();
                const fileId = String(
                    payload?.fileId || socket.data.activeFileId || ''
                ).trim();
                if (!projectId || !fileId) {
                    return;
                }

                const role = getUserRoleInProject(projectId, user.userId);
                if (!role) {
                    return;
                }

                const lineNumber = Math.max(
                    1,
                    Math.min(100_000, Number(payload?.lineNumber) || 1)
                );
                const column = Math.max(1, Math.min(2_000, Number(payload?.column) || 1));

                const cursorData: ActiveCursorPresence = {
                    userId: user.userId,
                    username: user.username,
                    displayName: user.displayName,
                    avatarColor: user.avatarColor,
                    role,
                    fileId,
                    lineNumber,
                    column,
                    lastActiveAt: Date.now(),
                };

                if (!projectPresence.has(projectId)) {
                    projectPresence.set(projectId, new Map<string, ActiveCursorPresence>());
                }
                projectPresence.get(projectId)!.set(socket.id, cursorData);

                socket.to(`file:${fileId}`).emit('cursor-update', cursorData);
                socket.to(`project:${projectId}`).emit('cursor-update', cursorData);
            }
        );

        /**
         * Event: `toggle-breakpoint`
         * Synchronizes shared debugging breakpoints across collaborators in real time.
         */
        socket.on(
            'toggle-breakpoint',
            (payload: {
                projectId?: string;
                fileId?: string;
                lineNumber?: number;
                condition?: string;
            }) => {
                if (!checkSocketRateLimit(io, socket, 'toggle-breakpoint', 'collab')) {
                    return;
                }

                const fileId = String(
                    payload?.fileId || socket.data.activeFileId || ''
                ).trim();
                const lineNumber = Math.max(
                    1,
                    Math.min(100_000, Number(payload?.lineNumber) || 1)
                );
                if (!fileId) {
                    return;
                }

                const fileRow = statements.getFileById.get(fileId) as
                    | Record<string, unknown>
                    | undefined;
                if (!fileRow) {
                    return;
                }

                const file = mapFileRow(fileRow);
                const role = getUserRoleInProject(file.projectId, user.userId);
                if (!role || role === 'VIEWER') {
                    const secEvent = logSecurityEvent({
                        projectId: file.projectId,
                        userId: user.userId,
                        username: user.username,
                        eventType: 'RBAC_VIOLATION_ATTEMPT',
                        severity: 'MEDIUM',
                        details: `Blocked VIEWER @${user.username} from toggling shared breakpoint on ${file.name}:${lineNumber}`,
                        ipAddress: socket.data.clientIp,
                        blocked: true,
                    });
                    broadcastSecurityAlert(
                        io,
                        socket,
                        file.projectId,
                        secEvent,
                        'VIEWER role cannot modify shared debugging breakpoints.'
                    );
                    return;
                }

                if (!fileBreakpoints.has(fileId)) {
                    fileBreakpoints.set(fileId, new Map<number, SharedBreakpoint>());
                }
                const bpMap = fileBreakpoints.get(fileId)!;

                if (bpMap.has(lineNumber)) {
                    bpMap.delete(lineNumber);
                } else {
                    bpMap.set(lineNumber, {
                        id: crypto.randomUUID(),
                        fileId,
                        lineNumber,
                        condition: payload?.condition
                            ? sanitizeText(payload.condition, 120)
                            : undefined,
                        createdBy: user.userId,
                        username: user.username,
                        createdAt: new Date().toISOString(),
                    });
                }

                const breakpoints = Array.from(bpMap.values()).sort(
                    (a, b) => a.lineNumber - b.lineNumber
                );

                io.to(`file:${fileId}`).emit('breakpoints-updated', {
                    fileId,
                    projectId: file.projectId,
                    breakpoints,
                    toggledBy: user.username,
                    lineNumber,
                });
                io.to(`project:${file.projectId}`).emit('breakpoints-updated', {
                    fileId,
                    projectId: file.projectId,
                    breakpoints,
                    toggledBy: user.username,
                    lineNumber,
                });
            }
        );

        /**
         * Event: `chat-message`
         * Rate-limited (max 5 per 10s) and XSS-sanitized project room chat.
         */
        socket.on(
            'chat-message',
            (
                payload: { projectId?: string; message?: string },
                ack?: (response: Record<string, unknown>) => void
            ) => {
                if (!checkSocketRateLimit(io, socket, 'chat-message', 'collab')) {
                    if (typeof ack === 'function') {
                        ack({ ok: false, error: 'WS_FLOOD_THROTTLED' });
                    }
                    return;
                }

                const projectId = String(
                    payload?.projectId || socket.data.activeProjectId || ''
                ).trim();
                if (!projectId) {
                    return;
                }

                const role = getUserRoleInProject(projectId, user.userId);
                if (!role) {
                    return;
                }

                const rawMessage = payload?.message;
                const hadXss = containsXssVector(rawMessage);
                const cleanMessage = sanitizeText(rawMessage, 500);

                if (!cleanMessage) {
                    return;
                }

                if (hadXss) {
                    const secEvent = logSecurityEvent({
                        projectId,
                        userId: user.userId,
                        username: user.username,
                        eventType: 'XSS_PAYLOAD_SANITIZED',
                        severity: 'HIGH',
                        details: `Neutralized XSS script payload in live chat message from @${user.username}`,
                        ipAddress: socket.data.clientIp,
                        blocked: true,
                    });
                    broadcastSecurityAlert(
                        io,
                        socket,
                        projectId,
                        secEvent,
                        `XSS payload stripped from chat message by @${user.username}.`
                    );
                }

                const chatEntry: ChatMessage = {
                    id: crypto.randomUUID(),
                    projectId,
                    userId: user.userId,
                    username: user.username,
                    avatarColor: user.avatarColor,
                    role,
                    message: cleanMessage,
                    createdAt: new Date().toISOString(),
                };

                const history = projectChatHistory.get(projectId) || [];
                history.push(chatEntry);
                if (history.length > 100) {
                    history.shift();
                }
                projectChatHistory.set(projectId, history);

                io.to(`project:${projectId}`).emit('chat-message', chatEntry);

                if (typeof ack === 'function') {
                    ack({ ok: true, message: chatEntry, xssSanitized: hadXss });
                }
            }
        );

        /**
         * Event: `new-comment`
         * Rate-limited (max 5 per 10s) and XSS-sanitized inline code review comment broadcast.
         */
        socket.on(
            'new-comment',
            (
                payload: {
                    projectId?: string;
                    fileId?: string;
                    lineNumber?: number;
                    content?: string;
                    comment?: InlineComment;
                },
                ack?: (response: Record<string, unknown>) => void
            ) => {
                if (!checkSocketRateLimit(io, socket, 'new-comment', 'collab')) {
                    if (typeof ack === 'function') {
                        ack({ ok: false, error: 'WS_FLOOD_THROTTLED' });
                    }
                    return;
                }

                const fileId = String(
                    payload?.fileId ||
                    payload?.comment?.fileId ||
                    socket.data.activeFileId ||
                    ''
                ).trim();
                if (!fileId) {
                    return;
                }

                const fileRow = statements.getFileById.get(fileId) as
                    | Record<string, unknown>
                    | undefined;
                if (!fileRow) {
                    return;
                }

                const file = mapFileRow(fileRow);
                const role = getUserRoleInProject(file.projectId, user.userId);
                if (!role) {
                    return;
                }

                // If comment was already created via REST `/api/files/:fileId/comments`, verify and broadcast it
                if (payload?.comment?.id) {
                    const existingRow = statements.getCommentById.get(
                        String(payload.comment.id)
                    ) as Record<string, unknown> | undefined;
                    if (existingRow) {
                        const verifiedComment = mapCommentRow(existingRow);
                        socket
                            .to(`file:${fileId}`)
                            .emit('comment-added', { fileId, comment: verifiedComment });
                        socket
                            .to(`project:${file.projectId}`)
                            .emit('comment-added', { fileId, comment: verifiedComment });
                        if (typeof ack === 'function') {
                            ack({ ok: true, comment: verifiedComment });
                        }
                        return;
                    }
                }

                const rawContent = payload?.content;
                const hadXss = containsXssVector(rawContent);
                const cleanContent = sanitizeText(rawContent, 600);
                if (!cleanContent) {
                    return;
                }

                const lineNumber = Math.max(
                    1,
                    Math.min(50_000, Number(payload?.lineNumber) || 1)
                );

                if (hadXss) {
                    const secEvent = logSecurityEvent({
                        projectId: file.projectId,
                        userId: user.userId,
                        username: user.username,
                        eventType: 'XSS_PAYLOAD_SANITIZED',
                        severity: 'HIGH',
                        details: `Neutralized Stored XSS payload in WebSocket inline comment on ${file.name}:${lineNumber} by @${user.username}`,
                        ipAddress: socket.data.clientIp,
                        blocked: true,
                    });
                    broadcastSecurityAlert(
                        io,
                        socket,
                        file.projectId,
                        secEvent,
                        `Stored XSS payload sanitized on ${file.name}:${lineNumber}.`
                    );
                }

                const commentId = crypto.randomUUID();
                const now = new Date().toISOString();

                statements.insertComment.run({
                    id: commentId,
                    fileId: file.id,
                    projectId: file.projectId,
                    userId: user.userId,
                    username: user.username,
                    lineNumber,
                    content: cleanContent,
                    resolved: 0,
                    createdAt: now,
                });

                const createdRow = statements.getCommentById.get(commentId) as Record<
                    string,
                    unknown
                >;
                const comment = mapCommentRow(createdRow);

                io.to(`file:${fileId}`).emit('comment-added', { fileId, comment });
                io.to(`project:${file.projectId}`).emit('comment-added', {
                    fileId,
                    comment,
                });

                if (typeof ack === 'function') {
                    ack({ ok: true, comment, xssSanitized: hadXss });
                }
            }
        );

        /**
         * Event: `snapshot-restored`
         * Resets the authoritative in-memory Yjs CRDT document when a snapshot is restored,
         * persists the binary state immediately, and broadcasts the restored state to all peers.
         */
        socket.on(
            'snapshot-restored',
            (
                payload: {
                    projectId?: string;
                    fileId?: string;
                    snapshotId?: string;
                },
                ack?: (response: Record<string, unknown>) => void
            ) => {
                if (!checkSocketRateLimit(io, socket, 'snapshot-restored', 'collab')) {
                    return;
                }

                const fileId = String(
                    payload?.fileId || socket.data.activeFileId || ''
                ).trim();
                if (!fileId) {
                    return;
                }

                const fileRow = statements.getFileById.get(fileId) as
                    | Record<string, unknown>
                    | undefined;
                if (!fileRow) {
                    return;
                }

                const file = mapFileRow(fileRow);
                const role = getUserRoleInProject(file.projectId, user.userId);
                if (!role || role === 'VIEWER') {
                    const secEvent = logSecurityEvent({
                        projectId: file.projectId,
                        userId: user.userId,
                        username: user.username,
                        eventType: 'RBAC_VIOLATION_ATTEMPT',
                        severity: 'HIGH',
                        details: `Blocked VIEWER @${user.username} from broadcasting snapshot-restored on ${file.name}`,
                        ipAddress: socket.data.clientIp,
                        blocked: true,
                    });
                    broadcastSecurityAlert(
                        io,
                        socket,
                        file.projectId,
                        secEvent,
                        'VIEWER role cannot restore version snapshots.'
                    );
                    return;
                }

                const managedDoc = getOrCreateManagedDoc(
                    file.id,
                    file.projectId,
                    file.content,
                    user.username
                );

                managedDoc.ydoc.transact(() => {
                    const ytext = managedDoc.ydoc.getText('monaco');
                    ytext.delete(0, ytext.length);
                    ytext.insert(0, file.content);
                }, 'snapshot-restore');

                managedDoc.lastUpdatedBy = user.username;
                managedDoc.lastUpdatedAt = Date.now();
                persistCrdtDocNow(managedDoc);

                const binaryState = Buffer.from(
                    Y.encodeStateAsUpdate(managedDoc.ydoc)
                );

                const restorePayload = {
                    fileId: file.id,
                    projectId: file.projectId,
                    name: file.name,
                    version: file.version,
                    content: file.content,
                    update: binaryState,
                    restoredBy: user.username,
                    snapshotId: payload?.snapshotId || null,
                    timestamp: managedDoc.lastUpdatedAt,
                };

                io.to(`file:${file.id}`).emit('snapshot-restored', restorePayload);
                io.to(`project:${file.projectId}`).emit(
                    'snapshot-restored',
                    restorePayload
                );

                if (typeof ack === 'function') {
                    ack({ ok: true, ...restorePayload });
                }
            }
        );

        /**
         * Handle socket disconnect: clean up presence, flush dirty CRDT state, and notify room.
         */
        socket.on('disconnect', () => {
            for (const projectId of socket.data.joinedProjects) {
                const presenceMap = projectPresence.get(projectId);
                if (presenceMap && presenceMap.has(socket.id)) {
                    presenceMap.delete(socket.id);
                    io.to(`project:${projectId}`).emit('presence-update', {
                        projectId,
                        collaborators: Array.from(presenceMap.values()),
                    });
                }
            }

            if (socket.data.activeFileId) {
                const managed = activeDocs.get(socket.data.activeFileId);
                if (managed && managed.dirty) {
                    persistCrdtDocNow(managed);
                }
            }
        });
    });
}