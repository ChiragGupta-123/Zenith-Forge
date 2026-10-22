import Database from 'better-sqlite3';
import crypto from 'crypto';
import path from 'path';
import {
    CollaboratorRole,
    InlineComment,
    Project,
    ProjectFile,
    ProjectMember,
    SecurityEvent,
    SecuritySeverity,
    SupportedLanguage,
    User,
    VersionSnapshot,
} from './types';
import { registerSecurityAuditLogger } from './security/securityMiddleware';

const DB_FILE_PATH =
    process.env.DEVCOLLAB_DB_PATH || path.resolve(process.cwd(), 'devcollab.sqlite');

export const db: Database.Database = new Database(DB_FILE_PATH);

// Enable Write-Ahead Logging (WAL) for high-concurrency real-time reads/writes & strict foreign keys
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('synchronous = NORMAL');
db.pragma('busy_timeout = 5000');

/**
 * Initialize schema using strict constraints and indices.
 * All queries in this module use 100% parameterized prepared statements to guarantee SQL Injection immunity.
 */
function initializeSchema(): void {
    db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      display_name TEXT NOT NULL,
      avatar_color TEXT NOT NULL,
      created_at TEXT NOT NULL,
      last_seen_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS projects (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT NOT NULL,
      owner_id TEXT NOT NULL,
      invite_code TEXT NOT NULL UNIQUE,
      is_locked INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS project_members (
      project_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      username TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('OWNER', 'EDITOR', 'VIEWER')),
      avatar_color TEXT NOT NULL,
      joined_at TEXT NOT NULL,
      PRIMARY KEY (project_id, user_id),
      FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS files (
      id TEXT PRIMARY KEY,
      project_id TEXT NOT NULL,
      name TEXT NOT NULL,
      language TEXT NOT NULL,
      content TEXT NOT NULL,
      version INTEGER NOT NULL DEFAULT 1,
      updated_by TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      UNIQUE(project_id, name),
      FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS snapshots (
      id TEXT PRIMARY KEY,
      file_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      version INTEGER NOT NULL,
      label TEXT NOT NULL,
      content TEXT NOT NULL,
      hash TEXT NOT NULL,
      created_by TEXT NOT NULL,
      created_by_username TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
      FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS comments (
      id TEXT PRIMARY KEY,
      file_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      username TEXT NOT NULL,
      line_number INTEGER NOT NULL,
      content TEXT NOT NULL,
      resolved INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
      FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS security_logs (
      id TEXT PRIMARY KEY,
      project_id TEXT,
      user_id TEXT,
      username TEXT,
      event_type TEXT NOT NULL,
      severity TEXT NOT NULL CHECK(severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
      details TEXT NOT NULL,
      ip_address TEXT NOT NULL DEFAULT '127.0.0.1',
      blocked INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_project_members_user ON project_members(user_id);
    CREATE INDEX IF NOT EXISTS idx_files_project ON files(project_id);
    CREATE INDEX IF NOT EXISTS idx_snapshots_file ON snapshots(file_id, version DESC);
    CREATE INDEX IF NOT EXISTS idx_comments_file ON comments(file_id, line_number ASC);
    CREATE INDEX IF NOT EXISTS idx_security_logs_project ON security_logs(project_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_security_logs_created ON security_logs(created_at DESC);
  `);
}

initializeSchema();

/**
 * 100% Parameterized Prepared Statements — zero dynamic SQL concatenation.
 */
export const statements = {
    // Users
    getUserById: db.prepare('SELECT * FROM users WHERE id = ?'),
    getUserByUsername: db.prepare('SELECT * FROM users WHERE username = ?'),
    insertUser: db.prepare(`
    INSERT INTO users (id, username, display_name, avatar_color, created_at, last_seen_at)
    VALUES (@id, @username, @displayName, @avatarColor, @createdAt, @lastSeenAt)
  `),
    updateUserLastSeen: db.prepare(`
    UPDATE users SET last_seen_at = @lastSeenAt, display_name = @displayName WHERE id = @id
  `),

    // Projects
    getProjectById: db.prepare('SELECT * FROM projects WHERE id = ?'),
    getProjectByInviteCode: db.prepare('SELECT * FROM projects WHERE invite_code = ?'),
    listProjectsForUser: db.prepare(`
    SELECT p.*, pm.role AS user_role,
      (SELECT COUNT(*) FROM files f WHERE f.project_id = p.id) AS file_count
    FROM projects p
    INNER JOIN project_members pm ON pm.project_id = p.id
    WHERE pm.user_id = ?
    ORDER BY p.updated_at DESC
  `),
    insertProject: db.prepare(`
    INSERT INTO projects (id, name, description, owner_id, invite_code, is_locked, created_at, updated_at)
    VALUES (@id, @name, @description, @ownerId, @inviteCode, @isLocked, @createdAt, @updatedAt)
  `),
    updateProjectTimestamp: db.prepare(`
    UPDATE projects SET updated_at = @updatedAt WHERE id = @id
  `),
    updateProjectLock: db.prepare(`
    UPDATE projects SET is_locked = @isLocked, updated_at = @updatedAt WHERE id = @id
  `),
    updateProjectInviteCode: db.prepare(`
    UPDATE projects SET invite_code = @inviteCode, updated_at = @updatedAt WHERE id = @id
  `),
    deleteProject: db.prepare('DELETE FROM projects WHERE id = ?'),

    // Project Members & RBAC
    getMemberRole: db.prepare(`
    SELECT role FROM project_members WHERE project_id = ? AND user_id = ?
  `),
    getProjectMembers: db.prepare(`
    SELECT pm.project_id, pm.user_id, pm.username, u.display_name, pm.role, pm.avatar_color, pm.joined_at
    FROM project_members pm
    LEFT JOIN users u ON u.id = pm.user_id
    WHERE pm.project_id = ?
    ORDER BY CASE pm.role WHEN 'OWNER' THEN 1 WHEN 'EDITOR' THEN 2 ELSE 3 END, pm.joined_at ASC
  `),
    upsertProjectMember: db.prepare(`
    INSERT INTO project_members (project_id, user_id, username, role, avatar_color, joined_at)
    VALUES (@projectId, @userId, @username, @role, @avatarColor, @joinedAt)
    ON CONFLICT(project_id, user_id) DO UPDATE SET
      role = excluded.role,
      username = excluded.username,
      avatar_color = excluded.avatar_color
  `),
    updateMemberRole: db.prepare(`
    UPDATE project_members SET role = @role WHERE project_id = @projectId AND user_id = @userId
  `),
    removeProjectMember: db.prepare(`
    DELETE FROM project_members WHERE project_id = ? AND user_id = ?
  `),

    // Files
    getFileById: db.prepare('SELECT * FROM files WHERE id = ?'),
    getFileByProjectAndName: db.prepare(
        'SELECT * FROM files WHERE project_id = ? AND name = ?'
    ),
    listFilesByProject: db.prepare(`
    SELECT * FROM files WHERE project_id = ? ORDER BY name ASC
  `),
    insertFile: db.prepare(`
    INSERT INTO files (id, project_id, name, language, content, version, updated_by, created_at, updated_at)
    VALUES (@id, @projectId, @name, @language, @content, @version, @updatedBy, @createdAt, @updatedAt)
  `),
    updateFileContent: db.prepare(`
    UPDATE files
    SET content = @content,
        version = version + 1,
        updated_by = @updatedBy,
        updated_at = @updatedAt
    WHERE id = @id
  `),
    renameFile: db.prepare(`
    UPDATE files
    SET name = @name,
        language = @language,
        updated_by = @updatedBy,
        updated_at = @updatedAt
    WHERE id = @id
  `),
    deleteFile: db.prepare('DELETE FROM files WHERE id = ?'),

    // Version Snapshots
    getSnapshotById: db.prepare('SELECT * FROM snapshots WHERE id = ?'),
    listSnapshotsByFile: db.prepare(`
    SELECT * FROM snapshots WHERE file_id = ? ORDER BY version DESC, created_at DESC
  `),
    insertSnapshot: db.prepare(`
    INSERT INTO snapshots (id, file_id, project_id, version, label, content, hash, created_by, created_by_username, created_at)
    VALUES (@id, @fileId, @projectId, @version, @label, @content, @hash, @createdBy, @createdByUsername, @createdAt)
  `),

    // Inline Comments
    getCommentById: db.prepare('SELECT * FROM comments WHERE id = ?'),
    listCommentsByFile: db.prepare(`
    SELECT * FROM comments WHERE file_id = ? ORDER BY line_number ASC, created_at ASC
  `),
    listCommentsByProject: db.prepare(`
    SELECT * FROM comments WHERE project_id = ? ORDER BY created_at DESC
  `),
    insertComment: db.prepare(`
    INSERT INTO comments (id, file_id, project_id, user_id, username, line_number, content, resolved, created_at)
    VALUES (@id, @fileId, @projectId, @userId, @username, @lineNumber, @content, @resolved, @createdAt)
  `),
    updateCommentResolved: db.prepare(`
    UPDATE comments SET resolved = @resolved WHERE id = @id
  `),
    deleteComment: db.prepare('DELETE FROM comments WHERE id = ?'),

    // Security Audit Logs
    insertSecurityLog: db.prepare(`
    INSERT INTO security_logs (id, project_id, user_id, username, event_type, severity, details, ip_address, blocked, created_at)
    VALUES (@id, @projectId, @userId, @username, @eventType, @severity, @details, @ipAddress, @blocked, @createdAt)
  `),
    listSecurityLogsByProject: db.prepare(`
    SELECT * FROM security_logs
    WHERE project_id = ? OR project_id IS NULL
    ORDER BY created_at DESC
    LIMIT ?
  `),
    listAllSecurityLogs: db.prepare(`
    SELECT * FROM security_logs ORDER BY created_at DESC LIMIT ?
  `),
};

export function computeSha256Hash(content: string): string {
    return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
}

export function generateInviteCode(prefix: string = 'DC'): string {
    const randomHex = crypto.randomBytes(4).toString('hex').toUpperCase();
    return `${prefix}-${randomHex.slice(0, 4)}-${randomHex.slice(4, 8)}`;
}

/**
 * Records a security telemetry event into SQLite using prepared statements.
 */
export function logSecurityEvent(params: {
    projectId?: string | null;
    userId?: string | null;
    username?: string | null;
    eventType: string;
    severity: SecuritySeverity;
    details: string;
    ipAddress?: string;
    blocked?: boolean;
}): SecurityEvent {
    const event: SecurityEvent = {
        id: crypto.randomUUID(),
        projectId: params.projectId ?? null,
        userId: params.userId ?? null,
        username: params.username ?? 'system',
        eventType: params.eventType,
        severity: params.severity,
        details: params.details,
        ipAddress: params.ipAddress || '127.0.0.1',
        blocked: Boolean(params.blocked),
        createdAt: new Date().toISOString(),
    };

    statements.insertSecurityLog.run({
        id: event.id,
        projectId: event.projectId,
        userId: event.userId,
        username: event.username,
        eventType: event.eventType,
        severity: event.severity,
        details: event.details,
        ipAddress: event.ipAddress,
        blocked: event.blocked ? 1 : 0,
        createdAt: event.createdAt,
    });

    return event;
}

// Wire middleware security audit events directly into SQLite
registerSecurityAuditLogger((event) => {
    logSecurityEvent(event);
});

/**
 * Queries SQLite for the caller's actual RBAC role on a project.
 */
export function getUserRoleInProject(
    projectId: string,
    userId: string
): CollaboratorRole | null {
    const row = statements.getMemberRole.get(projectId, userId) as
        | { role: CollaboratorRole }
        | undefined;
    return row ? row.role : null;
}

/**
 * Row mappers from SQLite snake_case columns to TypeScript camelCase interfaces.
 */
export function mapUserRow(row: Record<string, unknown>): User {
    return {
        id: String(row.id),
        username: String(row.username),
        displayName: String(row.display_name),
        avatarColor: String(row.avatar_color),
        createdAt: String(row.created_at),
        lastSeenAt: String(row.last_seen_at),
    };
}

export function mapProjectRow(row: Record<string, unknown>): Project {
    return {
        id: String(row.id),
        name: String(row.name),
        description: String(row.description),
        ownerId: String(row.owner_id),
        inviteCode: String(row.invite_code),
        isLocked: Boolean(row.is_locked),
        createdAt: String(row.created_at),
        updatedAt: String(row.updated_at),
        role: row.user_role ? (String(row.user_role) as CollaboratorRole) : undefined,
        fileCount:
            typeof row.file_count === 'number' ? row.file_count : undefined,
    };
}

export function mapMemberRow(row: Record<string, unknown>): ProjectMember {
    return {
        projectId: String(row.project_id),
        userId: String(row.user_id),
        username: String(row.username),
        displayName: row.display_name ? String(row.display_name) : String(row.username),
        role: String(row.role) as CollaboratorRole,
        avatarColor: String(row.avatar_color),
        joinedAt: String(row.joined_at),
    };
}

export function mapFileRow(row: Record<string, unknown>): ProjectFile {
    return {
        id: String(row.id),
        projectId: String(row.project_id),
        name: String(row.name),
        language: String(row.language) as SupportedLanguage,
        content: String(row.content),
        version: Number(row.version),
        updatedBy: String(row.updated_by),
        createdAt: String(row.created_at),
        updatedAt: String(row.updated_at),
    };
}

export function mapSnapshotRow(row: Record<string, unknown>): VersionSnapshot {
    return {
        id: String(row.id),
        fileId: String(row.file_id),
        projectId: String(row.project_id),
        version: Number(row.version),
        label: String(row.label),
        content: String(row.content),
        hash: String(row.hash),
        createdBy: String(row.created_by),
        createdByUsername: String(row.created_by_username),
        createdAt: String(row.created_at),
    };
}

export function mapCommentRow(row: Record<string, unknown>): InlineComment {
    return {
        id: String(row.id),
        fileId: String(row.file_id),
        projectId: String(row.project_id),
        userId: String(row.user_id),
        username: String(row.username),
        lineNumber: Number(row.line_number),
        content: String(row.content),
        resolved: Boolean(row.resolved),
        createdAt: String(row.created_at),
    };
}

export function mapSecurityLogRow(row: Record<string, unknown>): SecurityEvent {
    return {
        id: String(row.id),
        projectId: row.project_id ? String(row.project_id) : null,
        userId: row.user_id ? String(row.user_id) : null,
        username: row.username ? String(row.username) : null,
        eventType: String(row.event_type),
        severity: String(row.severity) as SecuritySeverity,
        details: String(row.details),
        ipAddress: String(row.ip_address),
        blocked: Boolean(row.blocked),
        createdAt: String(row.created_at),
    };
}

export const DEMO_PROJECT_ID = 'proj-quantum-router-001';
export const DEMO_INVITE_CODE = 'QRE-2026-ZERO';

/**
 * Seeds the "Quantum Router Engine" demo project with 3 starter files
 * (`main.py`, `algorithm.js`, `README.md`), snapshots, comments, and security logs.
 */
function seedDemoData(): void {
    const existing = statements.getProjectById.get(DEMO_PROJECT_ID);
    if (existing) {
        return;
    }

    const now = new Date().toISOString();
    const leadId = 'user-sec-architect-001';
    const leadUsername = 'aria_sec_lead';

    const starterMainPy = `#!/usr/bin/env python3
"""
Quantum Router Engine (QRE) — Zero-Trust Entanglement-Aware Packet Telemetry
Computes minimum-decoherence routing paths across quantum repeater nodes.
"""

import heapq
import math
from typing import Dict, List, Tuple


class QuantumRepeaterGraph:
    def __init__(self) -> None:
        self.adjacency: Dict[str, List[Tuple[str, float, float]]] = {}

    def add_entangled_link(
        self, source: str, target: str, latency_ms: float, fidelity: float
    ) -> None:
        if not (0.5 <= fidelity <= 1.0):
            raise ValueError("Link fidelity must be between 0.50 and 1.00")
        for u, v in ((source, target), (target, source)):
            self.adjacency.setdefault(u, []).append((v, latency_ms, fidelity))

    def shortest_high_fidelity_path(
        self, origin: str, destination: str
    ) -> Tuple[List[str], float, float]:
        # Priority queue stores: (effective_cost, current_node, path, cumulative_latency, joint_fidelity)
        pq: List[Tuple[float, str, List[str], float, float]] = [
            (0.0, origin, [origin], 0.0, 1.0)
        ]
        visited_best: Dict[str, float] = {}

        while pq:
            cost, node, path, total_lat, joint_fid = heapq.heappop(pq)
            if node == destination:
                return path, round(total_lat, 2), round(joint_fid, 4)

            if node in visited_best and visited_best[node] <= cost:
                continue
            visited_best[node] = cost

            for neighbor, edge_lat, edge_fid in self.adjacency.get(node, []):
                new_fid = joint_fid * edge_fid
                decoherence_penalty = -math.log(max(new_fid, 1e-9)) * 25.0
                new_cost = total_lat + edge_lat + decoherence_penalty
                heapq.heappush(
                    pq,
                    (new_cost, neighbor, path + [neighbor], total_lat + edge_lat, new_fid),
                )

        return [], float("inf"), 0.0


if __name__ == "__main__":
    router = QuantumRepeaterGraph()
    router.add_entangled_link("QNode-Alpha", "QNode-Relay-1", 4.2, 0.985)
    router.add_entangled_link("QNode-Relay-1", "QNode-Core-X", 6.1, 0.978)
    router.add_entangled_link("QNode-Alpha", "QNode-Direct-LowFid", 7.5, 0.860)
    router.add_entangled_link("QNode-Direct-LowFid", "QNode-Core-X", 2.4, 0.890)
    router.add_entangled_link("QNode-Core-X", "QNode-Omega", 3.8, 0.992)

    route, latency, fidelity = router.shortest_high_fidelity_path(
        "QNode-Alpha", "QNode-Omega"
    )
    print("=== Quantum Router Engine Telemetry ===")
    print(f"Optimal Route      : {' -> '.join(route)}")
    print(f"End-to-End Latency : {latency} ms")
    print(f"Entangled Fidelity : {fidelity * 100:.2f}%")
`;

    const starterAlgorithmJs = `/**
 * Quantum Router Engine — Adaptive Congestion & Zero-Trust Packet Verifier
 * Evaluates node saturation and verifies HMAC packet tags in real time.
 */

function verifyPacketIntegrity(packet, sharedSecret) {
  if (!packet || typeof packet.payload !== 'string' || typeof packet.nonce !== 'string') {
    return { valid: false, reason: 'MALFORMED_PACKET_ENVELOPE' };
  }
  // Deterministic FNV-1a 32-bit digest for ultra-low-latency edge verification
  const input = \`\${packet.nonce}:\${packet.payload}:\${sharedSecret}\`;
  let hash = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  const computedTag = hash.toString(16).padStart(8, '0');
  return {
    valid: computedTag === packet.tag,
    computedTag,
    reason: computedTag === packet.tag ? 'INTEGRITY_VERIFIED' : 'SIGNATURE_MISMATCH',
  };
}

function allocateChannelBandwidth(nodes) {
  const totalDemand = nodes.reduce((sum, n) => sum + n.demandGbps, 0);
  return nodes.map((node) => {
    const weight = totalDemand > 0 ? node.demandGbps / totalDemand : 0;
    const allocatedGbps = Number((weight * 100 * node.trustScore).toFixed(2));
    return {
      nodeId: node.id,
      allocatedGbps,
      utilizationPct: Number(((allocatedGbps / Math.max(node.demandGbps, 1)) * 100).toFixed(1)),
    };
  });
}

const sampleNodes = [
  { id: 'QNode-Alpha', demandGbps: 42, trustScore: 0.99 },
  { id: 'QNode-Relay-1', demandGbps: 35, trustScore: 0.96 },
  { id: 'QNode-Omega', demandGbps: 28, trustScore: 0.98 },
];

console.log('=== Adaptive Quantum Channel Allocation ===');
for (const entry of allocateChannelBandwidth(sampleNodes)) {
  console.log(\`[\${entry.nodeId}] Allocated: \${entry.allocatedGbps} Gbps (\${entry.utilizationPct}% target)\`);
}
`;

    const starterReadmeMd = `# Quantum Router Engine (QRE)

Welcome to **DevCollab** — a Zero-Trust, Real-Time Collaborative Coding Platform built for high-assurance engineering teams.

## Architecture & Security Highlights
- **Zero-Dependency HMAC-SHA256 JWT Authentication**: Every HTTP request and WebSocket frame is cryptographically verified using Node's native \`crypto\` module with constant-time signature validation.
- **Server-Side RBAC Enforcement**: Collaborator permissions (\`OWNER\`, \`EDITOR\`, \`VIEWER\`) are queried directly from SQLite in WAL mode on every mutation. Unauthorized writes trigger \`403 Forbidden\` and record an immutable \`RBAC_VIOLATION_ATTEMPT\` audit event.
- **Multi-Layer Execution Sandbox**: Static threat analysis (\`scanCodeForThreats\`) blocks RCE, prototype pollution, filesystem probes, and fork bombs before spawning memory- and time-bounded child processes.
- **Path Traversal & Stored XSS Immunity**: Strict filename allowlisting (\`validateSafeFilename\`) and HTML entity sanitization (\`sanitizeText\`) neutralize injection payloads at the edge.

## Starter Files
1. \`main.py\` — Entanglement-aware Dijkstra pathfinder balancing latency and decoherence fidelity.
2. \`algorithm.js\` — Adaptive quantum channel bandwidth allocator and FNV-1a packet verifier.
3. \`README.md\` — Architecture overview and security verification guide.
`;

    const seedTx = db.transaction(() => {
        statements.insertUser.run({
            id: leadId,
            username: leadUsername,
            displayName: 'Aria Vance (Principal SecEng)',
            avatarColor: '#10b981',
            createdAt: now,
            lastSeenAt: now,
        });

        statements.insertProject.run({
            id: DEMO_PROJECT_ID,
            name: 'Quantum Router Engine',
            description:
                'Zero-Trust entanglement-aware packet routing engine with real-time telemetry and sandboxed verification.',
            ownerId: leadId,
            inviteCode: DEMO_INVITE_CODE,
            isLocked: 0,
            createdAt: now,
            updatedAt: now,
        });

        statements.upsertProjectMember.run({
            projectId: DEMO_PROJECT_ID,
            userId: leadId,
            username: leadUsername,
            role: 'OWNER',
            avatarColor: '#10b981',
            joinedAt: now,
        });

        const seedFiles: Array<{
            id: string;
            name: string;
            language: SupportedLanguage;
            content: string;
            commentLine: number;
            commentText: string;
        }> = [
                {
                    id: 'file-qre-main-py',
                    name: 'main.py',
                    language: 'python',
                    content: starterMainPy,
                    commentLine: 33,
                    commentText:
                        'Verified decoherence log-penalty scaling factor against boundary fidelity 0.50.',
                },
                {
                    id: 'file-qre-algo-js',
                    name: 'algorithm.js',
                    language: 'javascript',
                    content: starterAlgorithmJs,
                    commentLine: 11,
                    commentText:
                        'Constant-time HMAC verification enforced at ingress gateway before FNV edge tag check.',
                },
                {
                    id: 'file-qre-readme-md',
                    name: 'README.md',
                    language: 'markdown',
                    content: starterReadmeMd,
                    commentLine: 5,
                    commentText:
                        'Zero-Trust security audit telemetry is active and streaming to the CollabDrawer.',
                },
            ];

        for (const f of seedFiles) {
            statements.insertFile.run({
                id: f.id,
                projectId: DEMO_PROJECT_ID,
                name: f.name,
                language: f.language,
                content: f.content,
                version: 1,
                updatedBy: leadUsername,
                createdAt: now,
                updatedAt: now,
            });

            statements.insertSnapshot.run({
                id: crypto.randomUUID(),
                fileId: f.id,
                projectId: DEMO_PROJECT_ID,
                version: 1,
                label: `Initial hardened baseline (${f.name})`,
                content: f.content,
                hash: computeSha256Hash(f.content),
                createdBy: leadId,
                createdByUsername: leadUsername,
                createdAt: now,
            });

            statements.insertComment.run({
                id: crypto.randomUUID(),
                fileId: f.id,
                projectId: DEMO_PROJECT_ID,
                userId: leadId,
                username: leadUsername,
                lineNumber: f.commentLine,
                content: f.commentText,
                resolved: 0,
                createdAt: now,
            });
        }

        // Seed realistic initial security audit log entries
        const initialSecurityEvents: Array<{
            eventType: string;
            severity: SecuritySeverity;
            details: string;
            blocked: number;
        }> = [
                {
                    eventType: 'PROJECT_CREATED',
                    severity: 'INFO',
                    details:
                        'Initialized "Quantum Router Engine" workspace with SQLite WAL mode, prepared statements, and SHA-256 snapshot integrity.',
                    blocked: 0,
                },
                {
                    eventType: 'PATH_TRAVERSAL_BLOCKED',
                    severity: 'HIGH',
                    details:
                        'Blocked automated probe attempting to create "../../etc/passwd" — rejected by validateSafeFilename.',
                    blocked: 1,
                },
                {
                    eventType: 'SANDBOX_EXECUTION_BLOCKED',
                    severity: 'CRITICAL',
                    details:
                        'Static Threat Scanner blocked RCE payload matching rule [RCE-001] child_process.execSync("cat /etc/shadow").',
                    blocked: 1,
                },
                {
                    eventType: 'RBAC_VIOLATION_ATTEMPT',
                    severity: 'HIGH',
                    details:
                        'Blocked VIEWER role attempt to overwrite main.py — server-side SQLite RBAC guard returned 403 Forbidden.',
                    blocked: 1,
                },
            ];

        for (const secEvent of initialSecurityEvents) {
            statements.insertSecurityLog.run({
                id: crypto.randomUUID(),
                projectId: DEMO_PROJECT_ID,
                userId: leadId,
                username: leadUsername,
                eventType: secEvent.eventType,
                severity: secEvent.severity,
                details: secEvent.details,
                ipAddress: '127.0.0.1',
                blocked: secEvent.blocked,
                createdAt: now,
            });
        }
    });

    seedTx();
}

seedDemoData();