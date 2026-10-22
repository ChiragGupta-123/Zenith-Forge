import React, {
    useState,
    useEffect,
    useRef,
    useCallback,
    useMemo,
} from 'react';
import Editor, { OnMount } from '@monaco-editor/react';
import type * as Monaco from 'monaco-editor';
import * as Y from 'yjs';
import type { Socket } from 'socket.io-client';
import {
    ShieldAlert,
    ShieldCheck,
    Lock,
    Zap,
    MessageSquarePlus,
    MessageSquare,
    CircleDot,
    Play,
    History,
    Users,
    AlertTriangle,
    CheckCircle2,
    Send,
    X,
    Cpu,
    Sparkles,
} from 'lucide-react';
import {
    CollaboratorPresence,
    CollaboratorRole,
    InlineComment,
    ProjectFile,
    SecuritySeverity,
    SharedBreakpoint,
    SupportedLanguage,
    ThreatRuleMatch,
    User,
} from '../types';

export interface CollaborativeEditorProps {
    projectId: string;
    file: ProjectFile | null;
    userRole: CollaboratorRole;
    currentUser: User;
    isProjectLocked?: boolean;
    socket: Socket | null;
    collaborators?: CollaboratorPresence[];
    breakpoints?: SharedBreakpoint[];
    comments?: InlineComment[];
    burstTriggerCount?: number;
    onRegisterBurstHandler?: (triggerBurst: () => void) => void;
    onContentChange?: (fileId: string, newContent: string) => void;
    onCrdtTelemetryChange?: (telemetry: {
        crdtOpsCountDelta: number;
        yjsByteSize: number;
    }) => void;
    onThreatCountChange?: (
        threatCount: number,
        matchedRules: ThreatRuleMatch[]
    ) => void;
    onBreakpointsChange?: (breakpoints: SharedBreakpoint[]) => void;
    onCommentsChange?: (comments: InlineComment[]) => void;
    onExecuteCode?: (code: string, language: SupportedLanguage) => void;
    onOpenVersionHistory?: () => void;
    onOpenCollabDrawer?: (tab?: 'chat' | 'comments' | 'security' | 'ai') => void;
}

interface RemotePeerCursorState extends CollaboratorPresence {
    selectionStartLineNumber?: number;
    selectionStartColumn?: number;
    selectionEndLineNumber?: number;
    selectionEndColumn?: number;
    isSimulatedBurstPeer?: boolean;
}

interface ClientSecurityRule {
    ruleId: string;
    patternName: string;
    regex: RegExp;
    severity: SecuritySeverity;
    monacoSeverity: 'error' | 'warning';
    description: string;
}

const MAX_CRDT_UPDATE_BYTES = 32 * 1024; // 32KB hard server limit per Yjs delta
const SAFE_TEXT_CHUNK_LENGTH = 14_000; // Chunk large pastes well below 32KB binary cap
const CURSOR_THROTTLE_MS = 40; // Broadcast cursor-update throttled to 40ms
const LINTER_DEBOUNCE_MS = 180; // Debounce live security threat scanner
const CLIENT_HIGH_FREQ_MAX_PER_SEC = 34; // Stay safely under server's 40 events/sec limit
const BURST_WAVE_INTERVAL_MS = 125; // Paced CRDT burst waves (~8 events/sec)

/**
 * Client-side static security threat rules matching backend `securityMiddleware.ts`
 * and Phase 4 requirements (`child_process`, `process.env`, `eval(`,
 * `constructor.constructor`, `os.system`, `subprocess`, `/etc/passwd`, etc.).
 */
const CLIENT_THREAT_RULES: ClientSecurityRule[] = [
    {
        ruleId: 'RCE-001',
        patternName: 'child_process',
        regex: /\bchild_process\b|\b(?:exec|execSync|spawn|spawnSync|execFile|fork)\s*\(/,
        severity: 'CRITICAL',
        monacoSeverity: 'error',
        description: 'Node.js child_process shell/process execution vector detected',
    },
    {
        ruleId: 'ENV-003',
        patternName: 'process.env',
        regex: /\bprocess\s*\.\s*env\b|\bos\s*\.\s*environ\b|\bgetenv\s*\(/,
        severity: 'HIGH',
        monacoSeverity: 'warning',
        description: 'Environment variable / secret exfiltration attempt (process.env)',
    },
    {
        ruleId: 'RCE-EVAL',
        patternName: 'eval(',
        regex: /\beval\s*\(|\bnew\s+Function\s*\(/,
        severity: 'CRITICAL',
        monacoSeverity: 'error',
        description: 'Dynamic code evaluation (eval / new Function) injection vector',
    },
    {
        ruleId: 'ESC-005',
        patternName: 'constructor.constructor',
        regex: /\bconstructor\s*\.\s*constructor\b|\[\s*['"]constructor['"]\s*\]/,
        severity: 'CRITICAL',
        monacoSeverity: 'error',
        description: 'Prototype chain sandbox escape via constructor.constructor',
    },
    {
        ruleId: 'PY-008',
        patternName: 'os.system',
        regex: /\bos\s*\.\s*(?:system|popen|execl|execle|execlp|execv|execve|execvp|spawnl|spawnv|fork|kill)\b/,
        severity: 'CRITICAL',
        monacoSeverity: 'error',
        description: 'Python OS command execution (os.system / os.popen / os.exec*)',
    },
    {
        ruleId: 'PY-009',
        patternName: 'subprocess',
        regex: /\bsubprocess\b|\bpty\s*\.\s*spawn\b|\bcommands\s*\.\s*getoutput\b/,
        severity: 'CRITICAL',
        monacoSeverity: 'error',
        description: 'Python subprocess / pty shell spawning vector',
    },
    {
        ruleId: 'LFI-010',
        patternName: '/etc/passwd',
        regex: /\/etc\/(?:passwd|shadow|hosts|sudoers)|\/proc\/self\/(?:environ|cmdline|maps|mem)|\/root\//,
        severity: 'CRITICAL',
        monacoSeverity: 'error',
        description: 'Sensitive host file read attempt (/etc/passwd, /etc/shadow, /proc/self)',
    },
    {
        ruleId: 'RCE-002',
        patternName: 'fs.',
        regex: /\bfs\s*\.|require\s*\(\s*['"](?:node:)?fs(?:\/promises)?['"]\s*\)/,
        severity: 'HIGH',
        monacoSeverity: 'warning',
        description: 'Direct host filesystem access (Node.js fs module)',
    },
    {
        ruleId: 'ESC-004',
        patternName: 'process.mainModule',
        regex: /\bprocess\s*\.\s*(?:mainModule|binding|dlopen|_linkedBinding)\b/,
        severity: 'CRITICAL',
        monacoSeverity: 'error',
        description: 'Node.js internal module loader / sandbox escape via process.mainModule',
    },
    {
        ruleId: 'ESC-006',
        patternName: '__proto__',
        regex: /\b__proto__\b|\bObject\s*\.\s*setPrototypeOf\b/,
        severity: 'HIGH',
        monacoSeverity: 'warning',
        description: 'Prototype pollution / prototype chain manipulation (__proto__)',
    },
];

const PEER_COLOR_PALETTE: Array<{
    name: 'emerald' | 'cyan' | 'violet' | 'rose' | 'amber' | 'blue';
    hex: string;
}> = [
        { name: 'cyan', hex: '#06b6d4' },
        { name: 'emerald', hex: '#10b981' },
        { name: 'violet', hex: '#8b5cf6' },
        { name: 'rose', hex: '#f43f5e' },
        { name: 'amber', hex: '#f59e0b' },
        { name: 'blue', hex: '#3b82f6' },
    ];

function resolvePeerColorSlot(
    userId: string,
    avatarColor?: string
): { name: 'emerald' | 'cyan' | 'violet' | 'rose' | 'amber' | 'blue'; hex: string } {
    if (avatarColor) {
        const lower = avatarColor.toLowerCase();
        const matched = PEER_COLOR_PALETTE.find(
            (slot) => slot.hex.toLowerCase() === lower
        );
        if (matched) return matched;
    }
    let hash = 0;
    for (let i = 0; i < userId.length; i++) {
        hash = (hash * 31 + userId.charCodeAt(i)) >>> 0;
    }
    return PEER_COLOR_PALETTE[hash % PEER_COLOR_PALETTE.length];
}

function toSafeCssIdentifier(rawId: string): string {
    return rawId.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 48);
}

/**
 * Normalizes incoming Socket.IO binary payloads (`Uint8Array`, `ArrayBuffer`,
 * `number[]`, or `{ type: 'Buffer', data: number[] }`) into a `Uint8Array`.
 */
function normalizeIncomingBinary(raw: unknown): Uint8Array | null {
    try {
        if (!raw) return null;
        if (raw instanceof Uint8Array) {
            return new Uint8Array(raw.buffer, raw.byteOffset, raw.byteLength);
        }
        if (raw instanceof ArrayBuffer) {
            return new Uint8Array(raw);
        }
        if (Array.isArray(raw)) {
            return Uint8Array.from(
                raw.map((b) => (typeof b === 'number' ? b & 0xff : 0))
            );
        }
        if (
            typeof raw === 'object' &&
            raw !== null &&
            'type' in raw &&
            (raw as { type?: string }).type === 'Buffer' &&
            Array.isArray((raw as { data?: unknown[] }).data)
        ) {
            return Uint8Array.from(
                ((raw as { data: unknown[] }).data).map((b) =>
                    typeof b === 'number' ? b & 0xff : 0
                )
            );
        }
        return null;
    } catch {
        return null;
    }
}

/**
 * Client-side XSS sanitizer mirroring backend `sanitizeText` in `securityMiddleware.ts`.
 * Strips ASCII/Unicode control characters and escapes HTML entities before emitting `new-comment`.
 */
export function sanitizeClientCommentText(
    input: string,
    maxLength: number = 600
): { sanitized: string; hadXssPattern: boolean } {
    const xssRegex =
        /(<\s*script\b|javascript\s*:|on(?:error|load|click|mouseover|focus|svg)\s*=|<\s*iframe\b|<\s*img\b[^>]*onerror|<\s*svg\b[^>]*onload|document\.cookie|window\.location)/i;
    const hadXssPattern = xssRegex.test(input);

    const withoutControls = input.replace(
        /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\u2028\u2029]/g,
        ''
    );
    const trimmed = withoutControls.trim().slice(0, maxLength);
    const sanitized = trimmed
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');

    return { sanitized, hadXssPattern };
}

/**
 * Unescapes HTML entities solely for safe React text node rendering (`{text}`),
 * while keeping raw HTML tags neutralized.
 */
function decodeSafeDisplayEntities(escaped: string): string {
    return escaped
        .replace(/&quot;/g, '"')
        .replace(/&#x27;/g, "'")
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/&amp;/g, '&');
}

function mapLanguageToMonaco(language?: SupportedLanguage): string {
    switch (language) {
        case 'python':
            return 'python';
        case 'javascript':
            return 'javascript';
        case 'typescript':
            return 'typescript';
        case 'cpp':
            return 'cpp';
        case 'java':
            return 'java';
        case 'json':
            return 'json';
        case 'markdown':
            return 'markdown';
        default:
            return 'typescript';
    }
}

export const CollaborativeEditor: React.FC<CollaborativeEditorProps> = ({
    projectId,
    file,
    userRole,
    currentUser,
    isProjectLocked = false,
    socket,
    collaborators = [],
    breakpoints: externalBreakpoints,
    comments: externalComments,
    burstTriggerCount = 0,
    onRegisterBurstHandler,
    onContentChange,
    onCrdtTelemetryChange,
    onThreatCountChange,
    onBreakpointsChange,
    onCommentsChange,
    onExecuteCode,
    onOpenVersionHistory,
    onOpenCollabDrawer,
}) => {
    const editorRef = useRef<Monaco.editor.IStandaloneCodeEditor | null>(null);
    const monacoRef = useRef<typeof Monaco | null>(null);
    const ydocRef = useRef<Y.Doc | null>(null);
    const ytextRef = useRef<Y.Text | null>(null);

    // Guard flag preventing feedback loops when applying remote CRDT updates to Monaco
    const isRemoteUpdateRef = useRef<boolean>(false);
    const isBurstingRef = useRef<boolean>(false);

    // Decoration ID collections for clean disposal/updates
    const cursorDecorationIdsRef = useRef<string[]>([]);
    const breakpointDecorationIdsRef = useRef<string[]>([]);
    const commentDecorationIdsRef = useRef<string[]>([]);
    const threatDecorationIdsRef = useRef<string[]>([]);

    // Disposable listeners & timers
    const editorDisposablesRef = useRef<Monaco.IDisposable[]>([]);
    const linterTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
    const cursorThrottleTimerRef = useRef<ReturnType<typeof setTimeout> | null>(
        null
    );
    const burstTimersRef = useRef<Array<ReturnType<typeof setTimeout>>>([]);
    const lastCursorEmitTimeRef = useRef<number>(0);
    const pendingCursorPayloadRef = useRef<{
        lineNumber: number;
        column: number;
    } | null>(null);

    // Sliding-window rate-limit guard for outbound high-frequency events (max 34/sec)
    const highFreqTimestampsRef = useRef<number[]>([]);

    // Latest refs to avoid stale closures inside Monaco & Yjs callbacks
    const activeFileRef = useRef<ProjectFile | null>(file);
    const userRoleRef = useRef<CollaboratorRole>(userRole);
    const isLockedRef = useRef<boolean>(isProjectLocked);
    const socketRef = useRef<Socket | null>(socket);
    const projectIdRef = useRef<string>(projectId);
    const currentUserRef = useRef<User>(currentUser);

    activeFileRef.current = file;
    userRoleRef.current = userRole;
    isLockedRef.current = isProjectLocked;
    socketRef.current = socket;
    projectIdRef.current = projectId;
    currentUserRef.current = currentUser;

    const [editorReady, setEditorReady] = useState<boolean>(false);
    const [activeLineNumber, setActiveLineNumber] = useState<number>(1);
    const [activeColumn, setActiveColumn] = useState<number>(1);
    const [localThreats, setLocalThreats] = useState<ThreatRuleMatch[]>([]);
    const [localBreakpoints, setLocalBreakpoints] = useState<SharedBreakpoint[]>(
        externalBreakpoints || []
    );
    const [localComments, setLocalComments] = useState<InlineComment[]>(
        externalComments || []
    );
    const [remotePeersMap, setRemotePeersMap] = useState<
        Record<string, RemotePeerCursorState>
    >({});

    // Floating inline comment composer state
    const [commentModalLine, setCommentModalLine] = useState<number | null>(null);
    const [commentDraft, setCommentDraft] = useState<string>('');
    const [commentStatusToast, setCommentStatusToast] = useState<string | null>(
        null
    );
    const [isBurstRunning, setIsBurstRunning] = useState<boolean>(false);
    const [rbacRevertNotice, setRbacRevertNotice] = useState<string | null>(null);

    const isReadOnly =
        userRole === 'VIEWER' || (isProjectLocked && userRole !== 'OWNER');

    // Sync controlled breakpoints / comments if parent updates them
    useEffect(() => {
        if (externalBreakpoints) {
            setLocalBreakpoints(externalBreakpoints);
        }
    }, [externalBreakpoints]);

    useEffect(() => {
        if (externalComments) {
            setLocalComments(externalComments);
        }
    }, [externalComments]);

    /**
     * Checks whether the client can safely emit a high-frequency WebSocket event
     * (`yjs-update` or `cursor-update`) without exceeding the backend's 40/sec limit.
     */
    const canEmitHighFreqEvent = useCallback((reserveForCrdt: boolean): boolean => {
        const now = Date.now();
        const cutoff = now - 1000;
        const timestamps = highFreqTimestampsRef.current;
        while (timestamps.length > 0 && timestamps[0] <= cutoff) {
            timestamps.shift();
        }
        const limit = reserveForCrdt
            ? CLIENT_HIGH_FREQ_MAX_PER_SEC
            : CLIENT_HIGH_FREQ_MAX_PER_SEC - 6;
        if (timestamps.length >= limit) {
            return false;
        }
        timestamps.push(now);
        return true;
    }, []);

    /**
     * Reports live Yjs state vector byte size and CRDT operation increments upward to TelemetryBar.
     */
    const reportCrdtTelemetry = useCallback(
        (opsDelta: number) => {
            if (!onCrdtTelemetryChange || !ydocRef.current) return;
            try {
                const stateVectorBytes = Y.encodeStateAsUpdate(
                    ydocRef.current
                ).byteLength;
                onCrdtTelemetryChange({
                    crdtOpsCountDelta: opsDelta,
                    yjsByteSize: stateVectorBytes,
                });
            } catch {
                // Ignore transient encoding errors
            }
        },
        [onCrdtTelemetryChange]
    );

    /**
     * 3. Live Client-Side Security Linter (Debounced)
     * Scans editor model for host access / RCE patterns, sets Monaco squiggle markers,
     * and reports threat count upward to the telemetry bar.
     */
    const runSecurityThreatScan = useCallback(
        (codeText: string) => {
            const editor = editorRef.current;
            const monaco = monacoRef.current;
            if (!editor || !monaco) return;

            const model = editor.getModel();
            if (!model) return;

            const lines = codeText.split(/\r?\n/);
            const matchedRules: ThreatRuleMatch[] = [];
            const markers: Monaco.editor.IMarkerData[] = [];
            const lineDecorations: Monaco.editor.IModelDeltaDecoration[] = [];

            for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
                const lineText = lines[lineIdx];
                const lineNumber = lineIdx + 1;

                for (const rule of CLIENT_THREAT_RULES) {
                    const match = rule.regex.exec(lineText);
                    if (match) {
                        const startCol = Math.max(1, match.index + 1);
                        const endCol = Math.max(
                            startCol + 1,
                            startCol + match[0].length
                        );

                        matchedRules.push({
                            ruleId: rule.ruleId,
                            patternName: rule.patternName,
                            severity: rule.severity,
                            description: rule.description,
                            line: lineNumber,
                            snippet: lineText.trim().slice(0, 120),
                        });

                        markers.push({
                            severity:
                                rule.monacoSeverity === 'error'
                                    ? monaco.MarkerSeverity.Error
                                    : monaco.MarkerSeverity.Warning,
                            message: `Security Policy Warning: Host access / RCE vector will be blocked by DevCollab Sandbox. [${rule.ruleId}: ${rule.description}]`,
                            startLineNumber: lineNumber,
                            startColumn: startCol,
                            endLineNumber: lineNumber,
                            endColumn: endCol,
                            source: 'DevCollab Zero-Trust Linter',
                            code: rule.ruleId,
                        });

                        lineDecorations.push({
                            range: new monaco.Range(
                                lineNumber,
                                1,
                                lineNumber,
                                Math.max(1, lineText.length + 1)
                            ),
                            options: {
                                isWholeLine: true,
                                className:
                                    rule.monacoSeverity === 'error'
                                        ? 'devcollab-threat-line-critical'
                                        : 'devcollab-threat-line-warning',
                                overviewRuler: {
                                    color:
                                        rule.monacoSeverity === 'error'
                                            ? '#f43f5e'
                                            : '#f59e0b',
                                    position: monaco.editor.OverviewRulerLane.Right,
                                },
                            },
                        });
                    }
                }
            }

            monaco.editor.setModelMarkers(
                model,
                'devcollab-security-linter',
                markers
            );
            threatDecorationIdsRef.current = editor.deltaDecorations(
                threatDecorationIdsRef.current,
                lineDecorations
            );

            setLocalThreats(matchedRules);
            if (onThreatCountChange) {
                onThreatCountChange(matchedRules.length, matchedRules);
            }
        },
        [onThreatCountChange]
    );

    const scheduleDebouncedThreatScan = useCallback(
        (codeText: string) => {
            if (linterTimerRef.current) {
                clearTimeout(linterTimerRef.current);
            }
            linterTimerRef.current = setTimeout(() => {
                linterTimerRef.current = null;
                runSecurityThreatScan(codeText);
            }, LINTER_DEBOUNCE_MS);
        },
        [runSecurityThreatScan]
    );

    /**
     * Dynamically injects per-collaborator CSS rules for floating username pills and carets
     * and applies `editor.deltaDecorations` for all active remote cursors & selections on this file.
     */
    const syncRemoteCursorDecorations = useCallback(() => {
        const editor = editorRef.current;
        const monaco = monacoRef.current;
        const currentFile = activeFileRef.current;
        if (!editor || !monaco || !currentFile) return;

        const model = editor.getModel();
        if (!model) return;

        // Combine prop collaborators + live socket cursor map
        const mergedPeers = new Map<string, RemotePeerCursorState>();

        for (const c of collaborators) {
            if (
                c.userId !== currentUserRef.current.id &&
                c.fileId === currentFile.id
            ) {
                mergedPeers.set(c.userId, { ...c });
            }
        }

        for (const [peerId, peerCursor] of Object.entries(remotePeersMap)) {
            if (
                peerId !== currentUserRef.current.id &&
                peerCursor.fileId === currentFile.id
            ) {
                mergedPeers.set(peerId, peerCursor);
            }
        }

        const lineCount = Math.max(1, model.getLineCount());
        const newDecorations: Monaco.editor.IModelDeltaDecoration[] = [];
        const dynamicCssRules: string[] = [];

        for (const peer of mergedPeers.values()) {
            const safeId = toSafeCssIdentifier(peer.userId);
            const colorSlot = resolvePeerColorSlot(peer.userId, peer.avatarColor);
            const clampedLine = Math.max(
                1,
                Math.min(lineCount, peer.lineNumber || 1)
            );
            const maxCol = Math.max(1, model.getLineMaxColumn(clampedLine));
            const clampedCol = Math.max(1, Math.min(maxCol, peer.column || 1));

            const safeUsername = (peer.username || 'peer')
                .replace(/[^a-zA-Z0-9_.-]/g, '')
                .slice(0, 24);
            const safeRole = peer.role || 'EDITOR';
            const pillText = `@${safeUsername} • ${safeRole}`;

            dynamicCssRules.push(`
                .remote-cursor-after-${safeId}::after {
                    content: "${pillText}";
                    background-color: ${colorSlot.hex};
                    border-color: ${colorSlot.hex};
                }
                .remote-cursor-before-${safeId}::before {
                    background-color: ${colorSlot.hex};
                    box-shadow: 0 0 8px ${colorSlot.hex};
                }
            `);

            // Caret + floating username pill decoration
            newDecorations.push({
                range: new monaco.Range(
                    clampedLine,
                    clampedCol,
                    clampedLine,
                    clampedCol
                ),
                options: {
                    stickiness:
                        monaco.editor.TrackedRangeStickiness
                            .NeverGrowsWhenTypingAtEdges,
                    className: `remote-cursor-target remote-cursor-caret-${colorSlot.name}`,
                    beforeContentClassName: `remote-cursor-caret remote-cursor-caret-${colorSlot.name} remote-cursor-before-${safeId}`,
                    afterContentClassName: `remote-cursor-label remote-cursor-label-${colorSlot.name} remote-cursor-after-${safeId}`,
                    hoverMessage: {
                        value: `**@${safeUsername}** (${safeRole}) — Line ${clampedLine}, Col ${clampedCol}`,
                    },
                    overviewRuler: {
                        color: colorSlot.hex,
                        position: monaco.editor.OverviewRulerLane.Center,
                    },
                },
            });

            // Selection range highlight (if peer has a multi-character selection)
            if (
                peer.selectionStartLineNumber &&
                peer.selectionStartColumn &&
                peer.selectionEndLineNumber &&
                peer.selectionEndColumn &&
                (peer.selectionStartLineNumber !== peer.selectionEndLineNumber ||
                    peer.selectionStartColumn !== peer.selectionEndColumn)
            ) {
                const startLine = Math.max(
                    1,
                    Math.min(lineCount, peer.selectionStartLineNumber)
                );
                const endLine = Math.max(
                    1,
                    Math.min(lineCount, peer.selectionEndLineNumber)
                );
                const startCol = Math.max(
                    1,
                    Math.min(
                        model.getLineMaxColumn(startLine),
                        peer.selectionStartColumn
                    )
                );
                const endCol = Math.max(
                    1,
                    Math.min(
                        model.getLineMaxColumn(endLine),
                        peer.selectionEndColumn
                    )
                );

                newDecorations.push({
                    range: new monaco.Range(startLine, startCol, endLine, endCol),
                    options: {
                        className: `remote-cursor-selection remote-cursor-selection-${colorSlot.name}`,
                        stickiness:
                            monaco.editor.TrackedRangeStickiness
                                .NeverGrowsWhenTypingAtEdges,
                    },
                });
            }
        }

        // Update dynamic style sheet for remote cursor username labels
        let styleEl = document.getElementById(
            'devcollab-dynamic-cursor-styles'
        ) as HTMLStyleElement | null;
        if (!styleEl) {
            styleEl = document.createElement('style');
            styleEl.id = 'devcollab-dynamic-cursor-styles';
            document.head.appendChild(styleEl);
        }
        styleEl.textContent = dynamicCssRules.join('\n');

        cursorDecorationIdsRef.current = editor.deltaDecorations(
            cursorDecorationIdsRef.current,
            newDecorations
        );
    }, [collaborators, remotePeersMap]);

    useEffect(() => {
        if (editorReady) {
            syncRemoteCursorDecorations();
        }
    }, [editorReady, syncRemoteCursorDecorations]);

    /**
     * Renders shared red gutter breakpoints using `editor.deltaDecorations`.
     */
    useEffect(() => {
        const editor = editorRef.current;
        const monaco = monacoRef.current;
        const currentFile = activeFileRef.current;
        if (!editor || !monaco || !currentFile || !editorReady) return;

        const model = editor.getModel();
        if (!model) return;

        const maxLine = Math.max(1, model.getLineCount());
        const fileBps = localBreakpoints.filter(
            (bp) => bp.fileId === currentFile.id
        );

        const decorations: Monaco.editor.IModelDeltaDecoration[] = fileBps.map(
            (bp) => {
                const line = Math.max(1, Math.min(maxLine, bp.lineNumber));
                return {
                    range: new monaco.Range(line, 1, line, 1),
                    options: {
                        isWholeLine: true,
                        className: 'devcollab-breakpoint-line',
                        glyphMarginClassName: 'devcollab-breakpoint-glyph',
                        glyphMarginHoverMessage: {
                            value: `🔴 **Shared Breakpoint** (Line ${line}) — Toggled by @${bp.username}${bp.condition ? ` | Condition: \`${bp.condition}\`` : ''
                                }`,
                        },
                        overviewRuler: {
                            color: '#f43f5e',
                            position: monaco.editor.OverviewRulerLane.Left,
                        },
                    },
                };
            }
        );

        breakpointDecorationIdsRef.current = editor.deltaDecorations(
            breakpointDecorationIdsRef.current,
            decorations
        );
    }, [editorReady, localBreakpoints, file?.id]);

    /**
     * Renders inline code-review comment indicators in the Monaco margin/lines.
     */
    useEffect(() => {
        const editor = editorRef.current;
        const monaco = monacoRef.current;
        const currentFile = activeFileRef.current;
        if (!editor || !monaco || !currentFile || !editorReady) return;

        const model = editor.getModel();
        if (!model) return;

        const maxLine = Math.max(1, model.getLineCount());
        const unresolvedByLine = new Map<number, InlineComment[]>();

        for (const comment of localComments) {
            if (comment.fileId !== currentFile.id || comment.resolved) continue;
            const line = Math.max(1, Math.min(maxLine, comment.lineNumber));
            const list = unresolvedByLine.get(line) || [];
            list.push(comment);
            unresolvedByLine.set(line, list);
        }

        const decorations: Monaco.editor.IModelDeltaDecoration[] = [];
        for (const [line, lineComments] of unresolvedByLine.entries()) {
            const hoverLines = lineComments.map(
                (c) =>
                    `💬 **@${c.username}** (Line ${line}): ${decodeSafeDisplayEntities(
                        c.content
                    )}`
            );
            decorations.push({
                range: new monaco.Range(line, 1, line, 1),
                options: {
                    isWholeLine: true,
                    className: 'devcollab-commented-line',
                    linesDecorationsClassName: 'devcollab-comment-gutter-indicator',
                    hoverMessage: {
                        value: hoverLines.join('\n\n'),
                    },
                },
            });
        }

        commentDecorationIdsRef.current = editor.deltaDecorations(
            commentDecorationIdsRef.current,
            decorations
        );
    }, [editorReady, localComments, file?.id]);

    /**
     * Applies a Yjs text delta or state synchronization to the Monaco model inside
     * `isRemoteUpdateRef` without disrupting the local user's cursor or selection.
     */
    const applyYjsDeltaToMonaco = useCallback(
        (
            delta: Array<{
                retain?: number;
                delete?: number;
                insert?: string | unknown[];
            }>,
            expectedFullText: string
        ) => {
            const editor = editorRef.current;
            const monaco = monacoRef.current;
            if (!editor || !monaco) return;

            const model = editor.getModel();
            if (!model) return;

            const currentModelText = model.getValue();
            if (currentModelText === expectedFullText) {
                return;
            }

            const savedSelections = editor.getSelections() || [];

            isRemoteUpdateRef.current = true;
            try {
                if (delta.length > 0) {
                    const editOps: Monaco.editor.IIdentifiedSingleEditOperation[] =
                        [];
                    let modelOffset = 0;

                    for (const op of delta) {
                        if (typeof op.retain === 'number' && op.retain > 0) {
                            modelOffset += op.retain;
                        } else if (typeof op.delete === 'number' && op.delete > 0) {
                            const startPos = model.getPositionAt(modelOffset);
                            const endPos = model.getPositionAt(
                                modelOffset + op.delete
                            );
                            editOps.push({
                                range: new monaco.Range(
                                    startPos.lineNumber,
                                    startPos.column,
                                    endPos.lineNumber,
                                    endPos.column
                                ),
                                text: '',
                                forceMoveMarkers: false,
                            });
                            modelOffset += op.delete;
                        } else if (typeof op.insert === 'string' && op.insert.length > 0) {
                            const pos = model.getPositionAt(modelOffset);
                            editOps.push({
                                range: new monaco.Range(
                                    pos.lineNumber,
                                    pos.column,
                                    pos.lineNumber,
                                    pos.column
                                ),
                                text: op.insert,
                                forceMoveMarkers: true,
                            });
                        }
                    }

                    if (editOps.length > 0) {
                        // pushEditOperations shifts savedSelections automatically around remote edits
                        model.pushEditOperations(savedSelections, editOps, () => null);
                    }
                }

                // Reconcile if full-state bootstrap (`yjs-init` / `snapshot-restored`) differed
                if (model.getValue() !== expectedFullText) {
                    const fullRange = model.getFullModelRange();
                    model.pushEditOperations(
                        savedSelections,
                        [
                            {
                                range: fullRange,
                                text: expectedFullText,
                                forceMoveMarkers: false,
                            },
                        ],
                        () => null
                    );

                    // Clamp and restore selections so cursor is never lost
                    if (savedSelections.length > 0) {
                        const maxLine = Math.max(1, model.getLineCount());
                        const clampedSelections = savedSelections.map((sel) => {
                            const sLine = Math.max(
                                1,
                                Math.min(maxLine, sel.selectionStartLineNumber)
                            );
                            const sCol = Math.max(
                                1,
                                Math.min(
                                    model.getLineMaxColumn(sLine),
                                    sel.selectionStartColumn
                                )
                            );
                            const pLine = Math.max(
                                1,
                                Math.min(maxLine, sel.positionLineNumber)
                            );
                            const pCol = Math.max(
                                1,
                                Math.min(
                                    model.getLineMaxColumn(pLine),
                                    sel.positionColumn
                                )
                            );
                            return new monaco.Selection(sLine, sCol, pLine, pCol);
                        });
                        editor.setSelections(clampedSelections);
                    }
                }
            } finally {
                isRemoteUpdateRef.current = false;
            }

            if (activeFileRef.current && onContentChange) {
                onContentChange(activeFileRef.current.id, expectedFullText);
            }
            scheduleDebouncedThreatScan(expectedFullText);
        },
        [onContentChange, scheduleDebouncedThreatScan]
    );

    /**
     * Emits a binary Yjs delta over the JWT-authenticated Socket.IO connection,
     * guaranteeing the frame is <= 32KB (`MAX_CRDT_UPDATE_BYTES`) and respects the rate limit.
     */
    const emitBinaryYjsUpdate = useCallback(
        (updateBytes: Uint8Array, currentText: string) => {
            const sock = socketRef.current;
            const currentFile = activeFileRef.current;
            if (!sock || !currentFile) return;

            if (updateBytes.byteLength === 0) return;

            if (updateBytes.byteLength > MAX_CRDT_UPDATE_BYTES) {
                // Safety guard: never send a packet > 32KB to the backend
                return;
            }

            if (!canEmitHighFreqEvent(true)) {
                return;
            }

            sock.emit('yjs-update', {
                projectId: projectIdRef.current,
                fileId: currentFile.id,
                update: Array.from(updateBytes),
                content: currentText,
            });

            reportCrdtTelemetry(1);
        },
        [canEmitHighFreqEvent, reportCrdtTelemetry]
    );

    /**
     * 1. Yjs + Monaco Two-Way CRDT Lifecycle per Active File
     * Recreates and destroys `Y.Doc` cleanly on file switch, binds `ytext.observe`,
     * and wires Socket.IO events (`join-file`, `yjs-init`, `yjs-update`, `snapshot-restored`,
     * `cursor-update`, `presence-update`, `breakpoints-updated`, `comment-added`).
     */
    useEffect(() => {
        if (!file) return;

        // Destroy any previous Y.Doc instance cleanly
        if (ydocRef.current) {
            ydocRef.current.destroy();
            ydocRef.current = null;
            ytextRef.current = null;
        }

        const ydoc = new Y.Doc();
        const ytext = ydoc.getText('monaco');
        ydocRef.current = ydoc;
        ytextRef.current = ytext;

        // Seed initial content locally with 'bootstrap' origin before server state arrives
        if (file.content) {
            ydoc.transact(() => {
                ytext.insert(0, file.content);
            }, 'local-bootstrap');
        }

        // Observe Y.Text mutations originating from remote peers or CRDT conflict burst
        const handleYTextObserver = (
            event: Y.YTextEvent,
            transaction: Y.Transaction
        ) => {
            if (
                transaction.origin === 'local-monaco' ||
                transaction.origin === 'local-bootstrap'
            ) {
                return;
            }
            const updatedText = ytext.toString();
            const delta = event.delta as Array<{
                retain?: number;
                delete?: number;
                insert?: string | unknown[];
            }>;
            applyYjsDeltaToMonaco(delta, updatedText);
        };

        ytext.observe(handleYTextObserver);

        // Ensure Monaco displays the file content immediately upon switching files
        if (editorRef.current) {
            const model = editorRef.current.getModel();
            if (model && model.getValue() !== file.content) {
                isRemoteUpdateRef.current = true;
                try {
                    model.setValue(file.content || '');
                } finally {
                    isRemoteUpdateRef.current = false;
                }
            }
            runSecurityThreatScan(file.content || '');
        }

        // Clear stale remote cursors from previous file
        setRemotePeersMap({});
        if (editorRef.current && cursorDecorationIdsRef.current.length > 0) {
            cursorDecorationIdsRef.current = editorRef.current.deltaDecorations(
                cursorDecorationIdsRef.current,
                []
            );
        }

        const sock = socket;
        if (!sock) {
            return () => {
                ytext.unobserve(handleYTextObserver);
                ydoc.destroy();
            };
        }

        const applyAuthoritativeServerSync = (payload: {
            fileId?: string;
            update?: unknown;
            content?: string;
            breakpoints?: SharedBreakpoint[];
            comments?: InlineComment[];
            revertedUnauthorizedEdit?: boolean;
        }) => {
            if (!payload || payload.fileId !== file.id) return;

            if (payload.revertedUnauthorizedEdit) {
                setRbacRevertNotice(
                    'Server RBAC Guard blocked unauthorized write and force-reverted document state.'
                );
                setTimeout(() => setRbacRevertNotice(null), 5000);
            }

            const binaryUpdate = normalizeIncomingBinary(payload.update);
            if (binaryUpdate && binaryUpdate.byteLength > 0) {
                try {
                    if (payload.revertedUnauthorizedEdit) {
                        // Reset local Y.Doc to authoritative server binary state
                        ydoc.transact(() => {
                            if (ytext.length > 0) {
                                ytext.delete(0, ytext.length);
                            }
                            if (typeof payload.content === 'string') {
                                ytext.insert(0, payload.content);
                            }
                        }, 'server-rbac-revert');
                    } else {
                        // Replace local bootstrap with authoritative server Y.Doc state
                        const currentStr = ytext.toString();
                        if (
                            typeof payload.content === 'string' &&
                            currentStr !== payload.content
                        ) {
                            ydoc.transact(() => {
                                if (ytext.length > 0) {
                                    ytext.delete(0, ytext.length);
                                }
                            }, 'local-bootstrap');
                        }
                        Y.applyUpdate(ydoc, binaryUpdate, 'yjs-init');
                    }
                } catch {
                    // Fallback to plain text if binary frame couldn't be applied
                    if (typeof payload.content === 'string') {
                        ydoc.transact(() => {
                            ytext.delete(0, ytext.length);
                            ytext.insert(0, payload.content!);
                        }, 'yjs-init');
                    }
                }
            } else if (
                typeof payload.content === 'string' &&
                ytext.toString() !== payload.content
            ) {
                ydoc.transact(() => {
                    ytext.delete(0, ytext.length);
                    ytext.insert(0, payload.content!);
                }, 'yjs-init');
            }

            const syncedText = ytext.toString();
            applyYjsDeltaToMonaco([], syncedText);
            reportCrdtTelemetry(1);

            if (Array.isArray(payload.breakpoints)) {
                setLocalBreakpoints(payload.breakpoints);
                onBreakpointsChange?.(payload.breakpoints);
            }
            if (Array.isArray(payload.comments)) {
                setLocalComments(payload.comments);
                onCommentsChange?.(payload.comments);
            }
        };

        const handleYjsInit = (payload: {
            fileId?: string;
            update?: unknown;
            content?: string;
            breakpoints?: SharedBreakpoint[];
            comments?: InlineComment[];
            revertedUnauthorizedEdit?: boolean;
        }) => {
            applyAuthoritativeServerSync(payload);
        };

        const handleRemoteYjsUpdate = (payload: {
            fileId?: string;
            projectId?: string;
            update?: unknown;
            content?: string;
            updatedBy?: string;
            userId?: string;
        }) => {
            if (!payload || payload.fileId !== file.id) return;

            const binaryUpdate = normalizeIncomingBinary(payload.update);
            if (
                binaryUpdate &&
                binaryUpdate.byteLength > 0 &&
                binaryUpdate.byteLength <= MAX_CRDT_UPDATE_BYTES
            ) {
                try {
                    Y.applyUpdate(ydoc, binaryUpdate, 'remote-peer');
                    reportCrdtTelemetry(1);
                    return;
                } catch {
                    // Ignore corrupted binary update
                }
            }

            // Fallback if remote sent plain text content
            if (
                typeof payload.content === 'string' &&
                ytext.toString() !== payload.content
            ) {
                ydoc.transact(() => {
                    ytext.delete(0, ytext.length);
                    ytext.insert(0, payload.content!);
                }, 'remote-peer');
                reportCrdtTelemetry(1);
            }
        };

        const handleSnapshotRestored = (payload: {
            fileId?: string;
            content?: string;
            update?: unknown;
        }) => {
            if (!payload || payload.fileId !== file.id) return;
            if (typeof payload.content === 'string') {
                ydoc.transact(() => {
                    ytext.delete(0, ytext.length);
                    ytext.insert(0, payload.content!);
                }, 'snapshot-restored');
                const binaryUpdate = normalizeIncomingBinary(payload.update);
                if (binaryUpdate && binaryUpdate.byteLength > 0) {
                    try {
                        Y.applyUpdate(ydoc, binaryUpdate, 'snapshot-restored');
                    } catch {
                        // Keep transacted text
                    }
                }
                applyYjsDeltaToMonaco([], ytext.toString());
                reportCrdtTelemetry(1);
            }
        };

        const handleRemoteCursorUpdate = (
            payload: CollaboratorPresence & {
                selectionStartLineNumber?: number;
                selectionStartColumn?: number;
                selectionEndLineNumber?: number;
                selectionEndColumn?: number;
            }
        ) => {
            if (
                !payload ||
                !payload.userId ||
                payload.userId === currentUserRef.current.id
            ) {
                return;
            }
            if (payload.fileId !== file.id) {
                setRemotePeersMap((prev) => {
                    if (!prev[payload.userId]) return prev;
                    const next = { ...prev };
                    delete next[payload.userId];
                    return next;
                });
                return;
            }

            setRemotePeersMap((prev) => ({
                ...prev,
                [payload.userId]: {
                    ...payload,
                    lastActiveAt: Date.now(),
                },
            }));
        };

        const handlePresenceUpdate = (payload: {
            projectId?: string;
            collaborators?: CollaboratorPresence[];
        }) => {
            if (!payload || !Array.isArray(payload.collaborators)) return;
            const activeOnFile = new Map<string, RemotePeerCursorState>();
            for (const c of payload.collaborators) {
                if (
                    c.userId !== currentUserRef.current.id &&
                    c.fileId === file.id
                ) {
                    activeOnFile.set(c.userId, { ...c });
                }
            }
            setRemotePeersMap((prev) => {
                const next: Record<string, RemotePeerCursorState> = {};
                // Retain simulated burst peers if currently bursting
                for (const [k, v] of Object.entries(prev)) {
                    if (v.isSimulatedBurstPeer) {
                        next[k] = v;
                    }
                }
                for (const [uid, pres] of activeOnFile.entries()) {
                    next[uid] = {
                        ...pres,
                        ...(prev[uid]
                            ? {
                                lineNumber:
                                    pres.lineNumber || prev[uid].lineNumber,
                                column: pres.column || prev[uid].column,
                            }
                            : {}),
                    };
                }
                return next;
            });
        };

        const handleBreakpointsUpdated = (payload: {
            fileId?: string;
            breakpoints?: SharedBreakpoint[];
        }) => {
            if (
                !payload ||
                payload.fileId !== file.id ||
                !Array.isArray(payload.breakpoints)
            ) {
                return;
            }
            setLocalBreakpoints(payload.breakpoints);
            onBreakpointsChange?.(payload.breakpoints);
        };

        const handleCommentAdded = (payload: {
            fileId?: string;
            comment?: InlineComment;
        }) => {
            if (!payload || payload.fileId !== file.id || !payload.comment) {
                return;
            }
            const incoming = payload.comment;
            setLocalComments((prev) => {
                if (prev.some((c) => c.id === incoming.id)) return prev;
                const updated = [...prev, incoming];
                onCommentsChange?.(updated);
                return updated;
            });
        };

        sock.on('yjs-init', handleYjsInit);
        sock.on('yjs-update', handleRemoteYjsUpdate);
        sock.on('snapshot-restored', handleSnapshotRestored);
        sock.on('cursor-update', handleRemoteCursorUpdate);
        sock.on('presence-update', handlePresenceUpdate);
        sock.on('breakpoints-updated', handleBreakpointsUpdated);
        sock.on('comment-added', handleCommentAdded);

        // Join file room and receive authoritative CRDT state vector
        sock.emit(
            'join-file',
            { projectId, fileId: file.id },
            (ack?: {
                ok?: boolean;
                fileId?: string;
                update?: unknown;
                content?: string;
                breakpoints?: SharedBreakpoint[];
                comments?: InlineComment[];
            }) => {
                if (ack && ack.ok) {
                    applyAuthoritativeServerSync(ack);
                }
            }
        );

        return () => {
            sock.off('yjs-init', handleYjsInit);
            sock.off('yjs-update', handleRemoteYjsUpdate);
            sock.off('snapshot-restored', handleSnapshotRestored);
            sock.off('cursor-update', handleRemoteCursorUpdate);
            sock.off('presence-update', handlePresenceUpdate);
            sock.off('breakpoints-updated', handleBreakpointsUpdated);
            sock.off('comment-added', handleCommentAdded);

            ytext.unobserve(handleYTextObserver);
            ydoc.destroy();
            if (ydocRef.current === ydoc) {
                ydocRef.current = null;
                ytextRef.current = null;
            }
        };
    }, [
        file?.id,
        projectId,
        socket,
        applyYjsDeltaToMonaco,
        reportCrdtTelemetry,
        runSecurityThreatScan,
        onBreakpointsChange,
        onCommentsChange,
    ]);

    /**
     * Keep Monaco readOnly option synchronized with `userRole` and `isProjectLocked`.
     */
    useEffect(() => {
        if (editorRef.current) {
            editorRef.current.updateOptions({
                readOnly: isReadOnly,
            });
        }
    }, [isReadOnly]);

    /**
     * 1d. "Simulate CRDT Conflict Burst" Handler
     * Spawns 3 concurrent simulated peer Y.Docs, generates overlapping CRDT insertions,
     * merges deltas via `Y.mergeUpdates`, and paces emission across 4 waves (125ms interval,
     * ~8 events/sec) so it never trips the 40 events/sec `WS_FLOOD_THROTTLED` server limit.
     */
    const triggerSimulatedConflictBurst = useCallback(() => {
        const ydoc = ydocRef.current;
        const ytext = ytextRef.current;
        const currentFile = activeFileRef.current;
        if (!ydoc || !ytext || !currentFile || isBurstingRef.current) {
            return;
        }

        if (
            userRoleRef.current === 'VIEWER' ||
            (isLockedRef.current && userRoleRef.current !== 'OWNER')
        ) {
            setRbacRevertNotice(
                'CRDT Conflict Burst requires EDITOR or OWNER permissions (VIEWER role is read-only).'
            );
            setTimeout(() => setRbacRevertNotice(null), 4000);
            return;
        }

        isBurstingRef.current = true;
        setIsBurstRunning(true);

        // Clear any old burst timers
        for (const t of burstTimersRef.current) {
            clearTimeout(t);
        }
        burstTimersRef.current = [];

        const baseStateVector = Y.encodeStateAsUpdate(ydoc);

        // Create 3 isolated Y.Doc instances representing concurrent peers editing simultaneously
        const peerA = new Y.Doc();
        const peerB = new Y.Doc();
        const peerC = new Y.Doc();

        Y.applyUpdate(peerA, baseStateVector);
        Y.applyUpdate(peerB, baseStateVector);
        Y.applyUpdate(peerC, baseStateVector);

        const commentPrefix =
            currentFile.language === 'python'
                ? '#'
                : currentFile.language === 'markdown'
                    ? '>'
                    : '//';

        const timestampTag = new Date().toISOString().slice(11, 19);

        const waves: Array<{
            mergedUpdate: Uint8Array;
            peerCursors: RemotePeerCursorState[];
        }> = [];

        // Wave 1: Concurrent header banner insertions from Peer A & Peer B at offset 0
        {
            const waveUpdates: Uint8Array[] = [];
            const captureA = (u: Uint8Array) => waveUpdates.push(u);
            const captureB = (u: Uint8Array) => waveUpdates.push(u);
            peerA.on('update', captureA);
            peerB.on('update', captureB);

            peerA.transact(() => {
                peerA
                    .getText('monaco')
                    .insert(
                        0,
                        `${commentPrefix} [CRDT-Peer-A @aria_sec_lead ${timestampTag}] Zero-Trust state vector verified\n`
                    );
            });
            peerB.transact(() => {
                peerB
                    .getText('monaco')
                    .insert(
                        0,
                        `${commentPrefix} [CRDT-Peer-B @liam_core_dev ${timestampTag}] Concurrent Y.Text delta merged\n`
                    );
            });

            peerA.off('update', captureA);
            peerB.off('update', captureB);

            const merged = Y.mergeUpdates(waveUpdates);
            Y.applyUpdate(peerA, merged);
            Y.applyUpdate(peerB, merged);
            Y.applyUpdate(peerC, merged);

            waves.push({
                mergedUpdate: merged,
                peerCursors: [
                    {
                        userId: 'sim-peer-aria',
                        username: 'aria_sec_lead',
                        displayName: 'Aria Vance (CRDT Sim)',
                        avatarColor: '#10b981',
                        role: 'OWNER',
                        fileId: currentFile.id,
                        lineNumber: 1,
                        column: 42,
                        lastActiveAt: Date.now(),
                        isSimulatedBurstPeer: true,
                    },
                    {
                        userId: 'sim-peer-liam',
                        username: 'liam_core_dev',
                        displayName: 'Liam Chen (CRDT Sim)',
                        avatarColor: '#06b6d4',
                        role: 'EDITOR',
                        fileId: currentFile.id,
                        lineNumber: 2,
                        column: 38,
                        lastActiveAt: Date.now(),
                        isSimulatedBurstPeer: true,
                    },
                ],
            });
        }

        // Wave 2: Peer C & Peer A concurrent mid-document edits merged with Y.mergeUpdates
        {
            const waveUpdates: Uint8Array[] = [];
            const captureC = (u: Uint8Array) => waveUpdates.push(u);
            peerC.on('update', captureC);

            peerC.transact(() => {
                const tC = peerC.getText('monaco');
                tC.insert(
                    0,
                    `${commentPrefix} [CRDT-Peer-C @sec_verifier ${timestampTag}] Commutative idempotency check: PASS\n`
                );
            });

            peerC.off('update', captureC);
            const merged = Y.mergeUpdates(waveUpdates);

            waves.push({
                mergedUpdate: merged,
                peerCursors: [
                    {
                        userId: 'sim-peer-aria',
                        username: 'aria_sec_lead',
                        displayName: 'Aria Vance (CRDT Sim)',
                        avatarColor: '#10b981',
                        role: 'OWNER',
                        fileId: currentFile.id,
                        lineNumber: 2,
                        column: 55,
                        lastActiveAt: Date.now(),
                        isSimulatedBurstPeer: true,
                    },
                    {
                        userId: 'sim-peer-liam',
                        username: 'liam_core_dev',
                        displayName: 'Liam Chen (CRDT Sim)',
                        avatarColor: '#06b6d4',
                        role: 'EDITOR',
                        fileId: currentFile.id,
                        lineNumber: 3,
                        column: 48,
                        lastActiveAt: Date.now(),
                        isSimulatedBurstPeer: true,
                    },
                    {
                        userId: 'sim-peer-verifier',
                        username: 'sec_verifier',
                        displayName: 'CRDT Verifier Node',
                        avatarColor: '#8b5cf6',
                        role: 'EDITOR',
                        fileId: currentFile.id,
                        lineNumber: 1,
                        column: 64,
                        lastActiveAt: Date.now(),
                        isSimulatedBurstPeer: true,
                    },
                ],
            });
        }

        waves.forEach((wave, index) => {
            const timer = setTimeout(() => {
                if (!ydocRef.current || activeFileRef.current?.id !== currentFile.id) {
                    return;
                }

                // Render simulated peer cursors
                setRemotePeersMap((prev) => {
                    const next = { ...prev };
                    for (const pc of wave.peerCursors) {
                        next[pc.userId] = pc;
                    }
                    return next;
                });

                // Apply merged binary update to local Y.Doc and broadcast if within 32KB cap
                if (wave.mergedUpdate.byteLength <= MAX_CRDT_UPDATE_BYTES) {
                    Y.applyUpdate(
                        ydocRef.current,
                        wave.mergedUpdate,
                        'crdt-burst'
                    );
                    const updatedStr = ydocRef.current
                        .getText('monaco')
                        .toString();
                    emitBinaryYjsUpdate(wave.mergedUpdate, updatedStr);
                }
            }, index * BURST_WAVE_INTERVAL_MS);

            burstTimersRef.current.push(timer);
        });

        // Clean up simulated burst cursors and temp Y.Docs after convergence completes
        const cleanupTimer = setTimeout(() => {
            peerA.destroy();
            peerB.destroy();
            peerC.destroy();
            isBurstingRef.current = false;
            setIsBurstRunning(false);
            setRemotePeersMap((prev) => {
                const next: Record<string, RemotePeerCursorState> = {};
                for (const [k, v] of Object.entries(prev)) {
                    if (!v.isSimulatedBurstPeer) {
                        next[k] = v;
                    }
                }
                return next;
            });
        }, waves.length * BURST_WAVE_INTERVAL_MS + 750);

        burstTimersRef.current.push(cleanupTimer);
    }, [emitBinaryYjsUpdate]);

    // Register burst handler with parent if requested
    useEffect(() => {
        if (onRegisterBurstHandler) {
            onRegisterBurstHandler(triggerSimulatedConflictBurst);
        }
    }, [onRegisterBurstHandler, triggerSimulatedConflictBurst]);

    // Trigger burst when parent increments `burstTriggerCount`
    const prevBurstCountRef = useRef<number>(burstTriggerCount);
    useEffect(() => {
        if (burstTriggerCount > prevBurstCountRef.current) {
            prevBurstCountRef.current = burstTriggerCount;
            triggerSimulatedConflictBurst();
        }
    }, [burstTriggerCount, triggerSimulatedConflictBurst]);

    /**
     * Deliberate RBAC Probe for VIEWER Demo: sends a raw `yjs-update` packet while in VIEWER role
     * so hackathon judges can watch the server reject it (`UNAUTHORIZED_CRDT_WRITE_BLOCKED`),
     * emit a `security-alert`, and force-resync the document.
     */
    const handleTestViewerRbacWriteProbe = useCallback(() => {
        const sock = socketRef.current;
        const currentFile = activeFileRef.current;
        if (!sock || !currentFile) return;

        const probeDoc = new Y.Doc();
        probeDoc
            .getText('monaco')
            .insert(0, '// UNAUTHORIZED VIEWER WRITE ATTEMPT\n');
        const forgedUpdate = Y.encodeStateAsUpdate(probeDoc);
        probeDoc.destroy();

        sock.emit('yjs-update', {
            projectId: projectIdRef.current,
            fileId: currentFile.id,
            update: Array.from(forgedUpdate),
            content: '// UNAUTHORIZED VIEWER WRITE ATTEMPT\n' + currentFile.content,
        });
    }, []);

    /**
     * 4a. Shared Breakpoint Toggle Handler (`toggle-breakpoint`)
     */
    const handleToggleBreakpoint = useCallback((lineNumber: number) => {
        const sock = socketRef.current;
        const currentFile = activeFileRef.current;
        if (!currentFile) return;

        // Optimistically update if caller has write permissions
        if (
            userRoleRef.current !== 'VIEWER' &&
            (!isLockedRef.current || userRoleRef.current === 'OWNER')
        ) {
            setLocalBreakpoints((prev) => {
                const exists = prev.some(
                    (bp) =>
                        bp.fileId === currentFile.id &&
                        bp.lineNumber === lineNumber
                );
                if (exists) {
                    return prev.filter(
                        (bp) =>
                            !(
                                bp.fileId === currentFile.id &&
                                bp.lineNumber === lineNumber
                            )
                    );
                }
                return [
                    ...prev,
                    {
                        id: `bp-${Date.now()}-${lineNumber}`,
                        fileId: currentFile.id,
                        lineNumber,
                        createdBy: currentUserRef.current.id,
                        username: currentUserRef.current.username,
                        createdAt: new Date().toISOString(),
                    },
                ];
            });
        }

        if (sock) {
            sock.emit('toggle-breakpoint', {
                projectId: projectIdRef.current,
                fileId: currentFile.id,
                lineNumber,
            });
        }
    }, []);

    /**
     * 4b. Inline Code-Review Comment Submission (`new-comment`, sanitized client-side before send)
     */
    const handleSubmitInlineComment = useCallback(
        (e: React.FormEvent) => {
            e.preventDefault();
            const currentFile = activeFileRef.current;
            if (!currentFile || commentModalLine === null) return;

            const { sanitized, hadXssPattern } = sanitizeClientCommentText(
                commentDraft,
                600
            );
            if (!sanitized) return;

            const targetLine = commentModalLine;
            setCommentDraft('');
            setCommentModalLine(null);

            if (hadXssPattern) {
                setCommentStatusToast(
                    `Client XSS Guard escaped dangerous HTML/script entities on Line ${targetLine}.`
                );
                setTimeout(() => setCommentStatusToast(null), 4000);
            }

            const sock = socketRef.current;
            if (sock) {
                sock.emit(
                    'new-comment',
                    {
                        projectId: projectIdRef.current,
                        fileId: currentFile.id,
                        lineNumber: targetLine,
                        content: sanitized,
                    },
                    (ack?: {
                        ok?: boolean;
                        comment?: InlineComment;
                        error?: string;
                    }) => {
                        if (ack?.ok && ack.comment) {
                            const created = ack.comment;
                            setLocalComments((prev) => {
                                if (prev.some((c) => c.id === created.id)) {
                                    return prev;
                                }
                                const next = [...prev, created];
                                onCommentsChange?.(next);
                                return next;
                            });
                        }
                    }
                );
            } else {
                // Local fallback when socket is offline
                const fallbackComment: InlineComment = {
                    id: `local-comment-${Date.now()}`,
                    fileId: currentFile.id,
                    projectId: projectIdRef.current,
                    userId: currentUserRef.current.id,
                    username: currentUserRef.current.username,
                    lineNumber: targetLine,
                    content: sanitized,
                    resolved: false,
                    createdAt: new Date().toISOString(),
                };
                setLocalComments((prev) => {
                    const next = [...prev, fallbackComment];
                    onCommentsChange?.(next);
                    return next;
                });
            }
        },
        [commentDraft, commentModalLine, onCommentsChange]
    );

    /**
     * Throttled (40ms) cursor & selection broadcaster (`cursor-update`).
     */
    const broadcastCursorPosition = useCallback(
        (lineNumber: number, column: number) => {
            // Pause cursor broadcasts during a CRDT conflict burst so high_freq rate bucket stays clean
            if (isBurstingRef.current) return;

            const sock = socketRef.current;
            const currentFile = activeFileRef.current;
            if (!sock || !currentFile) return;

            const now = Date.now();
            const elapsed = now - lastCursorEmitTimeRef.current;

            const sendNow = (line: number, col: number) => {
                if (!canEmitHighFreqEvent(false)) return;
                lastCursorEmitTimeRef.current = Date.now();
                sock.emit('cursor-update', {
                    projectId: projectIdRef.current,
                    fileId: currentFile.id,
                    lineNumber: line,
                    column: col,
                });
            };

            if (elapsed >= CURSOR_THROTTLE_MS) {
                if (cursorThrottleTimerRef.current) {
                    clearTimeout(cursorThrottleTimerRef.current);
                    cursorThrottleTimerRef.current = null;
                }
                sendNow(lineNumber, column);
            } else {
                pendingCursorPayloadRef.current = { lineNumber, column };
                if (!cursorThrottleTimerRef.current) {
                    cursorThrottleTimerRef.current = setTimeout(() => {
                        cursorThrottleTimerRef.current = null;
                        const pending = pendingCursorPayloadRef.current;
                        if (pending) {
                            pendingCursorPayloadRef.current = null;
                            sendNow(pending.lineNumber, pending.column);
                        }
                    }, CURSOR_THROTTLE_MS - elapsed);
                }
            }
        },
        [canEmitHighFreqEvent]
    );

    /**
     * Monaco Editor `onMount` initialization:
     * Binds `onDidChangeModelContent`, `onDidChangeCursorPosition`, and `onMouseDown` (glyph margin).
     */
    const handleEditorDidMount: OnMount = useCallback(
        (editor, monaco) => {
            editorRef.current = editor;
            monacoRef.current = monaco;
            setEditorReady(true);

            // Dispose any previous listeners
            for (const d of editorDisposablesRef.current) {
                d.dispose();
            }
            editorDisposablesRef.current = [];

            // 1. Model Content Change -> Yjs CRDT Transaction + Binary Delta Emission
            const contentDisposable = editor.onDidChangeModelContent(
                (event) => {
                    if (isRemoteUpdateRef.current) {
                        return;
                    }

                    const ydoc = ydocRef.current;
                    const ytext = ytextRef.current;
                    const currentFile = activeFileRef.current;
                    if (!ydoc || !ytext || !currentFile) return;

                    // Client-side RBAC guard (server also enforces SQLite RBAC on every yjs-update)
                    if (
                        userRoleRef.current === 'VIEWER' ||
                        (isLockedRef.current && userRoleRef.current !== 'OWNER')
                    ) {
                        return;
                    }

                    // Sort changes in descending offset order so multi-cursor edits apply cleanly
                    const sortedChanges = [...event.changes].sort(
                        (a, b) => b.rangeOffset - a.rangeOffset
                    );

                    const capturedDeltas: Uint8Array[] = [];
                    const updateCollector = (
                        update: Uint8Array,
                        origin: unknown
                    ) => {
                        if (origin === 'local-monaco') {
                            capturedDeltas.push(update);
                        }
                    };

                    ydoc.on('update', updateCollector);
                    try {
                        for (const change of sortedChanges) {
                            // If insertion text is very large, chunk it to stay well below 32KB per delta
                            if (change.text.length > SAFE_TEXT_CHUNK_LENGTH) {
                                ydoc.transact(() => {
                                    if (change.rangeLength > 0) {
                                        ytext.delete(
                                            change.rangeOffset,
                                            change.rangeLength
                                        );
                                    }
                                }, 'local-monaco');

                                let offset = change.rangeOffset;
                                for (
                                    let i = 0;
                                    i < change.text.length;
                                    i += SAFE_TEXT_CHUNK_LENGTH
                                ) {
                                    const slice = change.text.slice(
                                        i,
                                        i + SAFE_TEXT_CHUNK_LENGTH
                                    );
                                    ydoc.transact(() => {
                                        ytext.insert(offset, slice);
                                    }, 'local-monaco');
                                    offset += slice.length;
                                }
                            } else {
                                ydoc.transact(() => {
                                    if (change.rangeLength > 0) {
                                        ytext.delete(
                                            change.rangeOffset,
                                            change.rangeLength
                                        );
                                    }
                                    if (change.text.length > 0) {
                                        ytext.insert(
                                            change.rangeOffset,
                                            change.text
                                        );
                                    }
                                }, 'local-monaco');
                            }
                        }
                    } finally {
                        ydoc.off('update', updateCollector);
                    }

                    const fullText = ytext.toString();

                    if (capturedDeltas.length === 1) {
                        emitBinaryYjsUpdate(capturedDeltas[0], fullText);
                    } else if (capturedDeltas.length > 1) {
                        const merged = Y.mergeUpdates(capturedDeltas);
                        if (merged.byteLength <= MAX_CRDT_UPDATE_BYTES) {
                            emitBinaryYjsUpdate(merged, fullText);
                        } else {
                            // Emit chunked deltas paced by 35ms if total paste exceeded 32KB
                            capturedDeltas.forEach((chunkDelta, idx) => {
                                if (
                                    chunkDelta.byteLength <=
                                    MAX_CRDT_UPDATE_BYTES
                                ) {
                                    setTimeout(() => {
                                        emitBinaryYjsUpdate(
                                            chunkDelta,
                                            ytextRef.current?.toString() ||
                                            fullText
                                        );
                                    }, idx * 35);
                                }
                            });
                        }
                    }

                    if (onContentChange) {
                        onContentChange(currentFile.id, fullText);
                    }
                    scheduleDebouncedThreatScan(fullText);
                }
            );

            // 2. Cursor Position Change -> Throttled (40ms) `cursor-update`
            const cursorDisposable = editor.onDidChangeCursorPosition((e) => {
                const line = e.position.lineNumber;
                const col = e.position.column;
                setActiveLineNumber(line);
                setActiveColumn(col);
                broadcastCursorPosition(line, col);
            });

            // 3. Gutter Glyph Margin Click -> Shared Breakpoint or Line Comment Action
            const mouseDisposable = editor.onMouseDown((e) => {
                const targetType = e.target.type;
                const lineNumber = e.target.position?.lineNumber;
                if (!lineNumber) return;

                if (
                    targetType ===
                    monaco.editor.MouseTargetType.GUTTER_GLYPH_MARGIN
                ) {
                    handleToggleBreakpoint(lineNumber);
                } else if (
                    targetType ===
                    monaco.editor.MouseTargetType.GUTTER_LINE_DECORATIONS
                ) {
                    setCommentModalLine(lineNumber);
                }
            });

            editorDisposablesRef.current.push(
                contentDisposable,
                cursorDisposable,
                mouseDisposable
            );

            if (activeFileRef.current) {
                runSecurityThreatScan(activeFileRef.current.content || '');
            }
        },
        [
            broadcastCursorPosition,
            emitBinaryYjsUpdate,
            handleToggleBreakpoint,
            onContentChange,
            runSecurityThreatScan,
            scheduleDebouncedThreatScan,
        ]
    );

    // Master cleanup on unmount
    useEffect(() => {
        return () => {
            if (linterTimerRef.current) {
                clearTimeout(linterTimerRef.current);
            }
            if (cursorThrottleTimerRef.current) {
                clearTimeout(cursorThrottleTimerRef.current);
            }
            for (const t of burstTimersRef.current) {
                clearTimeout(t);
            }
            for (const d of editorDisposablesRef.current) {
                d.dispose();
            }
            editorDisposablesRef.current = [];
            if (ydocRef.current) {
                ydocRef.current.destroy();
                ydocRef.current = null;
            }
        };
    }, []);

    const activeFilePeers = useMemo(() => {
        if (!file) return [];
        const map = new Map<string, RemotePeerCursorState>();
        for (const c of collaborators) {
            if (c.userId !== currentUser.id && c.fileId === file.id) {
                map.set(c.userId, c);
            }
        }
        for (const [uid, peer] of Object.entries(remotePeersMap)) {
            if (uid !== currentUser.id && peer.fileId === file.id) {
                map.set(uid, peer);
            }
        }
        return Array.from(map.values());
    }, [collaborators, currentUser.id, file, remotePeersMap]);

    const activeLineComments = useMemo(() => {
        if (!file) return [];
        const targetLine = commentModalLine ?? activeLineNumber;
        return localComments.filter(
            (c) => c.fileId === file.id && c.lineNumber === targetLine
        );
    }, [activeLineNumber, commentModalLine, file, localComments]);

    const activeFileBreakpoints = useMemo(() => {
        if (!file) return [];
        return localBreakpoints.filter((bp) => bp.fileId === file.id);
    }, [file, localBreakpoints]);

    if (!file) {
        return (
            <div className="flex-1 bg-[#090D16] flex flex-col items-center justify-center p-8 text-center select-none">
                <div className="w-12 h-12 rounded-2xl bg-[#0F1624] border border-slate-800 flex items-center justify-center mb-3">
                    <Cpu className="w-6 h-6 text-cyan-400" />
                </div>
                <h3 className="text-sm font-semibold text-white">
                    No Active File Selected
                </h3>
                <p className="text-xs text-slate-400 mt-1 max-w-sm">
                    Select a source file from the left sidebar tree or create a new
                    validated file to initialize the Yjs CRDT synchronization engine.
                </p>
            </div>
        );
    }

    return (
        <div className="flex-1 flex flex-col min-w-0 min-h-0 bg-[#090D16] relative">
            {/* 4c. Top Security Banner for VIEWER Role or Locked Workspace */}
            {isReadOnly && (
                <div className="bg-violet-950/60 border-b border-violet-500/40 px-4 py-2 flex items-center justify-between gap-3 text-xs">
                    <div className="flex items-center gap-2 text-violet-200 min-w-0">
                        <Lock className="w-4 h-4 text-violet-400 shrink-0" />
                        <span className="truncate">
                            <strong className="text-white font-semibold">
                                Zero-Trust Read-Only Enforcement ({userRole}):
                            </strong>{' '}
                            Monaco editor is locked client-side, and the backend SQLite
                            RBAC guard independently verifies and rejects any forged{' '}
                            <code className="font-mono text-violet-300">
                                yjs-update
                            </code>{' '}
                            frames.
                        </span>
                    </div>
                    {userRole === 'VIEWER' && (
                        <button
                            type="button"
                            onClick={handleTestViewerRbacWriteProbe}
                            className="shrink-0 px-2.5 py-1 rounded bg-rose-500/20 hover:bg-rose-500/30 border border-rose-500/40 text-rose-200 font-mono text-[11px] transition flex items-center gap-1.5"
                            title="Send a forged CRDT binary write frame over the socket to verify server-side SQLite RBAC rejection"
                        >
                            <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                            <span>Probe Server RBAC Block</span>
                        </button>
                    )}
                </div>
            )}

            {/* Server RBAC / Security Notice Banner */}
            {rbacRevertNotice && (
                <div className="bg-rose-950/80 border-b border-rose-500/50 px-4 py-1.5 flex items-center justify-between text-xs text-rose-200">
                    <div className="flex items-center gap-2">
                        <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />
                        <span className="font-mono">{rbacRevertNotice}</span>
                    </div>
                    <button
                        type="button"
                        onClick={() => setRbacRevertNotice(null)}
                        className="text-rose-300 hover:text-white"
                    >
                        <X className="w-3.5 h-3.5" />
                    </button>
                </div>
            )}

            {/* Client XSS Sanitization Toast */}
            {commentStatusToast && (
                <div className="bg-amber-950/80 border-b border-amber-500/40 px-4 py-1.5 flex items-center justify-between text-xs text-amber-200">
                    <div className="flex items-center gap-2">
                        <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                        <span className="font-mono">{commentStatusToast}</span>
                    </div>
                    <button
                        type="button"
                        onClick={() => setCommentStatusToast(null)}
                        className="text-amber-300 hover:text-white"
                    >
                        <X className="w-3.5 h-3.5" />
                    </button>
                </div>
            )}

            {/* Editor Top Action & Telemetry Header Bar */}
            <div className="h-10 shrink-0 bg-[#0F1624]/90 border-b border-slate-800/80 px-3 flex items-center justify-between gap-2 select-none">
                {/* Active File Tab & Live Threat / Breakpoint Badges */}
                <div className="flex items-center gap-2.5 min-w-0">
                    <div className="flex items-center gap-2 px-2.5 py-1 rounded-md bg-[#090D16] border border-slate-800 text-xs font-mono text-white">
                        <span className="w-2 h-2 rounded-full bg-cyan-400" />
                        <span className="truncate max-w-[180px] font-semibold">
                            {file.name}
                        </span>
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 uppercase">
                            {file.language}
                        </span>
                    </div>

                    {/* Live Security Linter Status Badge */}
                    {localThreats.length > 0 ? (
                        <button
                            type="button"
                            onClick={() => onOpenCollabDrawer?.('security')}
                            className="flex items-center gap-1.5 px-2 py-0.5 rounded border bg-rose-500/15 border-rose-500/40 text-rose-300 text-[11px] font-mono hover:bg-rose-500/25 transition"
                            title={localThreats
                                .map(
                                    (t) =>
                                        `Line ${t.line}: [${t.ruleId}] ${t.description}`
                                )
                                .join('\n')}
                        >
                            <ShieldAlert className="w-3.5 h-3.5 text-rose-400 animate-pulse" />
                            <span>
                                {localThreats.length} Security Threat
                                {localThreats.length === 1 ? '' : 's'}
                            </span>
                        </button>
                    ) : (
                        <div className="hidden sm:flex items-center gap-1.5 px-2 py-0.5 rounded border bg-emerald-500/10 border-emerald-500/30 text-emerald-300 text-[11px] font-mono">
                            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                            <span>AST Linter: Clean</span>
                        </div>
                    )}

                    {/* Shared Breakpoints Count Pill */}
                    <button
                        type="button"
                        onClick={() => handleToggleBreakpoint(activeLineNumber)}
                        disabled={isReadOnly}
                        className="hidden md:flex items-center gap-1.5 px-2 py-0.5 rounded border bg-slate-900/90 border-slate-800 hover:border-rose-500/40 text-slate-300 text-[11px] font-mono transition disabled:opacity-50"
                        title="Click to toggle shared breakpoint on current cursor line (or click the left gutter margin)"
                    >
                        <CircleDot className="w-3 h-3 text-rose-400" />
                        <span>
                            BP (L{activeLineNumber}): {activeFileBreakpoints.length}
                        </span>
                    </button>
                </div>

                {/* Right Controls: Live Collaborator Carets, Floating Line Comment Trigger, CRDT Burst, Run */}
                <div className="flex items-center gap-2">
                    {/* Active Remote Collaborators in this File */}
                    {activeFilePeers.length > 0 && (
                        <div className="hidden lg:flex items-center gap-1.5 pr-2 border-r border-slate-800">
                            <Users className="w-3.5 h-3.5 text-cyan-400" />
                            <div className="flex items-center gap-1">
                                {activeFilePeers.slice(0, 4).map((peer) => {
                                    const slot = resolvePeerColorSlot(
                                        peer.userId,
                                        peer.avatarColor
                                    );
                                    return (
                                        <span
                                            key={peer.userId}
                                            className="px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold text-white flex items-center gap-1"
                                            style={{
                                                backgroundColor: `${slot.hex}25`,
                                                border: `1px solid ${slot.hex}80`,
                                            }}
                                            title={`@${peer.username} (${peer.role}) at Line ${peer.lineNumber}, Col ${peer.column}`}
                                        >
                                            <span
                                                className="w-1.5 h-1.5 rounded-full"
                                                style={{
                                                    backgroundColor: slot.hex,
                                                }}
                                            />
                                            @{peer.username}:L{peer.lineNumber}
                                        </span>
                                    );
                                })}
                            </div>
                        </div>
                    )}

                    {/* Floating Line Action: Open Inline Code-Review Comment */}
                    <button
                        type="button"
                        onClick={() =>
                            setCommentModalLine((prev) =>
                                prev === activeLineNumber ? null : activeLineNumber
                            )
                        }
                        className="px-2.5 py-1 rounded-md bg-violet-500/15 hover:bg-violet-500/25 border border-violet-500/40 text-violet-200 text-[11px] font-mono transition flex items-center gap-1.5"
                        title="Add an XSS-sanitized inline code-review comment on the active line"
                    >
                        <MessageSquarePlus className="w-3.5 h-3.5 text-violet-400" />
                        <span>Comment L{activeLineNumber}</span>
                    </button>

                    {/* Quick CRDT Burst Trigger */}
                    <button
                        type="button"
                        onClick={triggerSimulatedConflictBurst}
                        disabled={isBurstRunning || isReadOnly}
                        className="hidden sm:flex px-2.5 py-1 rounded-md bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 text-cyan-300 text-[11px] font-mono transition items-center gap-1.5 disabled:opacity-40"
                        title="Simulate multi-peer concurrent Yjs CRDT insertions (rate-paced below 40/sec)"
                    >
                        <Zap
                            className={`w-3.5 h-3.5 text-cyan-400 ${isBurstRunning ? 'animate-bounce' : ''
                                }`}
                        />
                        <span>{isBurstRunning ? 'Bursting...' : 'CRDT Burst'}</span>
                    </button>

                    {onOpenVersionHistory && (
                        <button
                            type="button"
                            onClick={onOpenVersionHistory}
                            className="p-1.5 rounded-md bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 transition"
                            title="Open Version History & SHA-256 Snapshots"
                        >
                            <History className="w-3.5 h-3.5" />
                        </button>
                    )}

                    {onExecuteCode && (
                        <button
                            type="button"
                            onClick={() => {
                                const code =
                                    editorRef.current?.getValue() ?? file.content;
                                onExecuteCode(code, file.language);
                            }}
                            className="px-2.5 py-1 rounded-md bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/40 text-emerald-200 text-[11px] font-mono font-semibold transition flex items-center gap-1.5"
                            title="Execute code in isolated Zero-Trust Sandbox"
                        >
                            <Play className="w-3.5 h-3.5 text-emerald-400 fill-emerald-400" />
                            <span>Run Sandbox</span>
                        </button>
                    )}
                </div>
            </div>

            {/* 4b. Floating Inline Code-Review Comment Popover */}
            {commentModalLine !== null && (
                <div className="absolute right-6 top-12 w-96 rounded-xl bg-[#0F1624] border border-violet-500/50 shadow-2xl p-3 z-30">
                    <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800">
                        <div className="flex items-center gap-1.5 text-xs font-mono text-violet-300 font-semibold">
                            <MessageSquare className="w-3.5 h-3.5 text-violet-400" />
                            <span>
                                Inline Code Review — {file.name}:L{commentModalLine}
                            </span>
                        </div>
                        <button
                            type="button"
                            onClick={() => setCommentModalLine(null)}
                            className="text-slate-400 hover:text-white"
                        >
                            <X className="w-3.5 h-3.5" />
                        </button>
                    </div>

                    {/* Existing comments on this line */}
                    {activeLineComments.length > 0 && (
                        <div className="max-h-36 overflow-y-auto space-y-1.5 mb-2.5 pr-1">
                            {activeLineComments.map((c) => (
                                <div
                                    key={c.id}
                                    className="p-2 rounded-lg bg-[#090D16] border border-slate-800 text-xs"
                                >
                                    <div className="flex items-center justify-between text-[10px] font-mono text-slate-400 mb-0.5">
                                        <span className="text-cyan-400 font-semibold">
                                            @{c.username}
                                        </span>
                                        <span>
                                            {new Date(
                                                c.createdAt
                                            ).toLocaleTimeString()}
                                        </span>
                                    </div>
                                    <p className="text-slate-200 break-words">
                                        {decodeSafeDisplayEntities(c.content)}
                                    </p>
                                </div>
                            ))}
                        </div>
                    )}

                    <form onSubmit={handleSubmitInlineComment} className="space-y-2">
                        <textarea
                            value={commentDraft}
                            onChange={(e) => setCommentDraft(e.target.value)}
                            placeholder={`Add security or code review note on line ${commentModalLine} (XSS-sanitized)...`}
                            rows={2}
                            maxLength={600}
                            className="w-full rounded-lg bg-[#090D16] border border-slate-700 focus:border-violet-400 px-2.5 py-1.5 text-xs text-white placeholder-slate-500 outline-none resize-none font-sans"
                            autoFocus
                        />
                        <div className="flex items-center justify-between">
                            <span className="text-[10px] font-mono text-slate-400 flex items-center gap-1">
                                <Sparkles className="w-3 h-3 text-emerald-400" />
                                Client &amp; Server XSS Sanitized
                            </span>
                            <button
                                type="submit"
                                disabled={!commentDraft.trim()}
                                className="px-3 py-1 rounded-md bg-violet-600 hover:bg-violet-500 disabled:opacity-40 text-white text-xs font-mono font-semibold flex items-center gap-1.5 transition"
                            >
                                <Send className="w-3 h-3" />
                                <span>Post Comment</span>
                            </button>
                        </div>
                    </form>
                </div>
            )}

            {/* Monaco Editor Container */}
            <div className="flex-1 min-h-0 relative">
                <Editor
                    height="100%"
                    theme="vs-dark"
                    path={file.id}
                    language={mapLanguageToMonaco(file.language)}
                    defaultValue={file.content}
                    onMount={handleEditorDidMount}
                    options={{
                        readOnly: isReadOnly,
                        domReadOnly: isReadOnly,
                        glyphMargin: true,
                        minimap: { enabled: true, scale: 1 },
                        fontSize: 13,
                        fontFamily:
                            "'JetBrains Mono', 'Fira Code', 'Cascadia Code', Consolas, monospace",
                        lineNumbers: 'on',
                        roundedSelection: true,
                        scrollBeyondLastLine: false,
                        automaticLayout: true,
                        padding: { top: 12, bottom: 12 },
                        cursorBlinking: 'smooth',
                        cursorSmoothCaretAnimation: 'on',
                        smoothScrolling: true,
                        renderLineHighlight: 'all',
                        bracketPairColorization: { enabled: true },
                    }}
                />
            </div>

            {/* Bottom Sub-Status Strip inside Editor */}
            <div className="h-6 shrink-0 bg-[#0F1624] border-t border-slate-800/80 px-3 flex items-center justify-between text-[10px] font-mono text-slate-400 select-none">
                <div className="flex items-center gap-3">
                    <span>
                        Ln {activeLineNumber}, Col {activeColumn}
                    </span>
                    <span>•</span>
                    <span>Y.Text(&apos;monaco&apos;) CRDT Bound</span>
                    <span>•</span>
                    <span className="flex items-center gap-1 text-slate-300">
                        {localThreats.length === 0 ? (
                            <>
                                <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                                <span>0 Blocked Signatures</span>
                            </>
                        ) : (
                            <>
                                <AlertTriangle className="w-3 h-3 text-rose-400" />
                                <span className="text-rose-300">
                                    {localThreats.length} Sandbox Policy Warning
                                    {localThreats.length === 1 ? '' : 's'}
                                </span>
                            </>
                        )}
                    </span>
                </div>
                <div className="flex items-center gap-3">
                    <span>
                        Shared Breakpoints: {activeFileBreakpoints.length}
                    </span>
                    <span>•</span>
                    <span>
                        Active File Comments:{' '}
                        {
                            localComments.filter(
                                (c) => c.fileId === file.id && !c.resolved
                            ).length
                        }
                    </span>
                </div>
            </div>
        </div>
    );
};

export default CollaborativeEditor;