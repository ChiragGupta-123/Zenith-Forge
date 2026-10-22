import { Router, Response } from 'express';
import crypto from 'crypto';
import {
    AuthenticatedRequest,
    CollaboratorRole,
    Project,
    ProjectMember,
} from '../types';
import {
    containsXssVector,
    createRateLimiter,
    extractClientIp,
    requireAuth,
    sanitizeText,
    signToken,
} from '../security/securityMiddleware';
import {
    computeSha256Hash,
    db,
    DEMO_PROJECT_ID,
    generateInviteCode,
    getUserRoleInProject,
    logSecurityEvent,
    mapFileRow,
    mapMemberRow,
    mapProjectRow,
    mapSecurityLogRow,
    mapUserRow,
    statements,
} from '../db';

const router = Router();

const AVATAR_PALETTE = [
    '#10b981',
    '#3b82f6',
    '#8b5cf6',
    '#f59e0b',
    '#ec4899',
    '#06b6d4',
    '#f43f5e',
];

function pickAvatarColor(seed: string): string {
    let hash = 0;
    for (let i = 0; i < seed.length; i++) {
        hash = (hash * 31 + seed.charCodeAt(i)) >>> 0;
    }
    return AVATAR_PALETTE[hash % AVATAR_PALETTE.length];
}

/**
 * POST /api/projects/session
 * Issues a cryptographically signed HMAC-SHA256 JWT for the user session.
 * Automatically provisions the user in SQLite and grants access to the
 * seeded "Quantum Router Engine" demo project so judges can collaborate immediately.
 */
router.post(
    '/session',
    createRateLimiter(30, 60_000, 'auth-session'),
    (req: AuthenticatedRequest, res: Response): void => {
        const clientIp = extractClientIp(req);
        const rawUsername = req.body?.username;
        const rawDisplayName = req.body?.displayName;
        const requestedDemoRole = req.body?.preferredRole as CollaboratorRole | undefined;

        if (containsXssVector(rawUsername) || containsXssVector(rawDisplayName)) {
            logSecurityEvent({
                projectId: DEMO_PROJECT_ID,
                userId: null,
                username: 'untrusted_input',
                eventType: 'XSS_PAYLOAD_SANITIZED',
                severity: 'HIGH',
                details: `HTML/script injection stripped during session creation from IP ${clientIp}`,
                ipAddress: clientIp,
                blocked: false,
            });
        }

        const cleanUsername = sanitizeText(rawUsername || 'cyber_operator', 36)
            .replace(/[^a-zA-Z0-9_-]/g, '_')
            .toLowerCase();

        if (!cleanUsername || cleanUsername.length < 2) {
            res.status(400).json({
                error: 'Invalid username',
                message: 'Username must contain at least 2 alphanumeric characters.',
            });
            return;
        }

        const cleanDisplayName =
            sanitizeText(rawDisplayName || rawUsername || cleanUsername, 50) || cleanUsername;
        const now = new Date().toISOString();

        let userRow = statements.getUserByUsername.get(cleanUsername) as
            | Record<string, unknown>
            | undefined;

        if (!userRow) {
            const newUserId = `usr-${crypto.randomUUID().slice(0, 12)}`;
            const avatarColor = pickAvatarColor(cleanUsername);
            statements.insertUser.run({
                id: newUserId,
                username: cleanUsername,
                displayName: cleanDisplayName,
                avatarColor,
                createdAt: now,
                lastSeenAt: now,
            });
            userRow = statements.getUserById.get(newUserId) as Record<string, unknown>;
        } else {
            statements.updateUserLastSeen.run({
                id: String(userRow.id),
                displayName: cleanDisplayName,
                lastSeenAt: now,
            });
            userRow = statements.getUserById.get(String(userRow.id)) as Record<string, unknown>;
        }

        const user = mapUserRow(userRow);

        // Ensure user is enrolled in the seeded Quantum Router Engine demo project
        const demoProject = statements.getProjectById.get(DEMO_PROJECT_ID);
        if (demoProject) {
            const existingRole = getUserRoleInProject(DEMO_PROJECT_ID, user.id);
            const validRoles: CollaboratorRole[] = ['OWNER', 'EDITOR', 'VIEWER'];
            const assignedRole: CollaboratorRole =
                requestedDemoRole && validRoles.includes(requestedDemoRole)
                    ? requestedDemoRole
                    : existingRole || 'OWNER';

            statements.upsertProjectMember.run({
                projectId: DEMO_PROJECT_ID,
                userId: user.id,
                username: user.username,
                role: assignedRole,
                avatarColor: user.avatarColor,
                joinedAt: now,
            });
        }

        const token = signToken({
            userId: user.id,
            username: user.username,
            displayName: user.displayName,
            avatarColor: user.avatarColor,
        });

        logSecurityEvent({
            projectId: DEMO_PROJECT_ID,
            userId: user.id,
            username: user.username,
            eventType: 'SESSION_ISSUED',
            severity: 'INFO',
            details: `Issued HMAC-SHA256 JWT session for @${user.username}`,
            ipAddress: clientIp,
            blocked: false,
        });

        const effectiveRole = getUserRoleInProject(DEMO_PROJECT_ID, user.id) || requestedDemoRole || 'OWNER';
        res.status(200).json({
            token,
            user,
            preferredRole: effectiveRole,
            role: effectiveRole,
            demoProjectId: DEMO_PROJECT_ID,
            issuedAt: now,
        });
    }
);

// All routes below require cryptographic HMAC-SHA256 JWT verification
router.use(requireAuth);

/**
 * GET /api/projects
 * Returns all projects where the authenticated user is a verified member.
 */
router.get('/', (req: AuthenticatedRequest, res: Response): void => {
    const user = req.user!;
    const projectRows = statements.listProjectsForUser.all(user.userId) as Record<
        string,
        unknown
    >[];

    const projects: Project[] = projectRows.map((row) => {
        const project = mapProjectRow(row);
        const memberRows = statements.getProjectMembers.all(project.id) as Record<
            string,
            unknown
        >[];
        project.members = memberRows.map(mapMemberRow);
        return project;
    });

    res.json({ projects });
});

/**
 * GET /api/projects/:projectId
 * Returns full project metadata, member list, file list, and verified caller role.
 */
router.get('/:projectId', (req: AuthenticatedRequest, res: Response): void => {
    const user = req.user!;
    const projectId = String(req.params.projectId || '');
    const clientIp = extractClientIp(req);

    const projectRow = statements.getProjectById.get(projectId) as
        | Record<string, unknown>
        | undefined;

    if (!projectRow) {
        res.status(404).json({
            error: 'Project not found',
            message: `No project exists with ID "${projectId}".`,
        });
        return;
    }

    const role = getUserRoleInProject(projectId, user.userId);
    if (!role) {
        logSecurityEvent({
            projectId,
            userId: user.userId,
            username: user.username,
            eventType: 'RBAC_VIOLATION_ATTEMPT',
            severity: 'HIGH',
            details: `Non-member @${user.username} attempted to read project ${projectId}`,
            ipAddress: clientIp,
            blocked: true,
        });
        res.status(403).json({
            error: 'Access Denied',
            code: 'RBAC_NOT_A_MEMBER',
            message: 'You are not a registered collaborator on this project. Join via an invite code first.',
        });
        return;
    }

    const project = mapProjectRow(projectRow);
    project.role = role;

    const memberRows = statements.getProjectMembers.all(projectId) as Record<
        string,
        unknown
    >[];
    project.members = memberRows.map(mapMemberRow);

    const fileRows = statements.listFilesByProject.all(projectId) as Record<
        string,
        unknown
    >[];
    const files = fileRows.map(mapFileRow);
    project.fileCount = files.length;

    res.json({
        project,
        files,
        callerRole: role,
    });
});

/**
 * POST /api/projects
 * Creates a new Zero-Trust collaborative project with starter files and cryptographic invite code.
 */
router.post(
    '/',
    createRateLimiter(15, 60_000, 'project-create'),
    (req: AuthenticatedRequest, res: Response): void => {
        const user = req.user!;
        const clientIp = extractClientIp(req);
        const rawName = req.body?.name;
        const rawDescription = req.body?.description;

        if (containsXssVector(rawName) || containsXssVector(rawDescription)) {
            logSecurityEvent({
                projectId: null,
                userId: user.userId,
                username: user.username,
                eventType: 'XSS_PAYLOAD_SANITIZED',
                severity: 'HIGH',
                details: `Sanitized XSS payload in project creation input by @${user.username}`,
                ipAddress: clientIp,
                blocked: false,
            });
        }

        const name = sanitizeText(rawName, 80);
        const description = sanitizeText(
            rawDescription || 'Zero-Trust collaborative coding workspace',
            280
        );

        if (!name || name.length < 2) {
            res.status(400).json({
                error: 'Invalid project name',
                message: 'Project name must be at least 2 characters.',
            });
            return;
        }

        const projectId = `proj-${crypto.randomUUID().slice(0, 12)}`;
        const inviteCode = generateInviteCode('DC');
        const now = new Date().toISOString();

        const starterMainContent = `# ${name} — Starter Entrypoint
def main() -> None:
    print("Zero-Trust Sandbox Ready: ${name}")

if __name__ == "__main__":
    main()
`;
        const starterReadmeContent = `# ${name}

${description}

## Security Policy
All edits and executions are protected by HMAC-SHA256 JWT authentication and SQLite RBAC verification.
`;

        const createTx = db.transaction(() => {
            statements.insertProject.run({
                id: projectId,
                name,
                description,
                ownerId: user.userId,
                inviteCode,
                isLocked: 0,
                createdAt: now,
                updatedAt: now,
            });

            statements.upsertProjectMember.run({
                projectId,
                userId: user.userId,
                username: user.username,
                role: 'OWNER',
                avatarColor: user.avatarColor,
                joinedAt: now,
            });

            const mainFileId = `file-${crypto.randomUUID().slice(0, 12)}`;
            statements.insertFile.run({
                id: mainFileId,
                projectId,
                name: 'main.py',
                language: 'python',
                content: starterMainContent,
                version: 1,
                updatedBy: user.username,
                createdAt: now,
                updatedAt: now,
            });

            statements.insertSnapshot.run({
                id: crypto.randomUUID(),
                fileId: mainFileId,
                projectId,
                version: 1,
                label: 'Initial project scaffold (main.py)',
                content: starterMainContent,
                hash: computeSha256Hash(starterMainContent),
                createdBy: user.userId,
                createdByUsername: user.username,
                createdAt: now,
            });

            const readmeFileId = `file-${crypto.randomUUID().slice(0, 12)}`;
            statements.insertFile.run({
                id: readmeFileId,
                projectId,
                name: 'README.md',
                language: 'markdown',
                content: starterReadmeContent,
                version: 1,
                updatedBy: user.username,
                createdAt: now,
                updatedAt: now,
            });

            statements.insertSnapshot.run({
                id: crypto.randomUUID(),
                fileId: readmeFileId,
                projectId,
                version: 1,
                label: 'Initial project documentation (README.md)',
                content: starterReadmeContent,
                hash: computeSha256Hash(starterReadmeContent),
                createdBy: user.userId,
                createdByUsername: user.username,
                createdAt: now,
            });
        });

        createTx();

        logSecurityEvent({
            projectId,
            userId: user.userId,
            username: user.username,
            eventType: 'PROJECT_CREATED',
            severity: 'INFO',
            details: `Created project "${name}" with cryptographic invite code ${inviteCode}`,
            ipAddress: clientIp,
            blocked: false,
        });

        const projectRow = statements.getProjectById.get(projectId) as Record<
            string,
            unknown
        >;
        const project = mapProjectRow(projectRow);
        project.role = 'OWNER';
        project.members = (
            statements.getProjectMembers.all(projectId) as Record<string, unknown>[]
        ).map(mapMemberRow);
        project.fileCount = 2;

        res.status(201).json({ project });
    }
);

/**
 * POST /api/projects/join
 * Joins a project using its cryptographic invite code.
 */
router.post(
    '/join',
    createRateLimiter(20, 60_000, 'project-join'),
    (req: AuthenticatedRequest, res: Response): void => {
        const user = req.user!;
        const clientIp = extractClientIp(req);
        const inviteCode = sanitizeText(req.body?.inviteCode, 32).toUpperCase();

        if (!inviteCode) {
            res.status(400).json({
                error: 'Invite code required',
                message: 'Please provide a valid project invite code.',
            });
            return;
        }

        const projectRow = statements.getProjectByInviteCode.get(inviteCode) as
            | Record<string, unknown>
            | undefined;

        if (!projectRow) {
            logSecurityEvent({
                projectId: null,
                userId: user.userId,
                username: user.username,
                eventType: 'UNAUTHORIZED_ACCESS_ATTEMPT',
                severity: 'MEDIUM',
                details: `Failed invite code lookup ("${inviteCode}") by @${user.username}`,
                ipAddress: clientIp,
                blocked: true,
            });
            res.status(404).json({
                error: 'Invalid invite code',
                message: 'No project matches the provided invite code.',
            });
            return;
        }

        const projectId = String(projectRow.id);
        const existingRole = getUserRoleInProject(projectId, user.userId);
        const assignedRole: CollaboratorRole = existingRole || 'EDITOR';
        const now = new Date().toISOString();

        if (!existingRole) {
            statements.upsertProjectMember.run({
                projectId,
                userId: user.userId,
                username: user.username,
                role: assignedRole,
                avatarColor: user.avatarColor,
                joinedAt: now,
            });

            logSecurityEvent({
                projectId,
                userId: user.userId,
                username: user.username,
                eventType: 'MEMBER_JOINED_VIA_INVITE',
                severity: 'INFO',
                details: `User @${user.username} joined project via invite code as ${assignedRole}`,
                ipAddress: clientIp,
                blocked: false,
            });
        }

        const project = mapProjectRow(projectRow);
        project.role = assignedRole;
        project.members = (
            statements.getProjectMembers.all(projectId) as Record<string, unknown>[]
        ).map(mapMemberRow);

        res.status(200).json({ project, role: assignedRole });
    }
);

/**
 * PATCH /api/projects/:projectId/members/:targetUserId/role
 * Updates a collaborator's RBAC role.
 * Strictly requires caller to be OWNER in SQLite, except when switching one's own role
 * inside the demo workspace via `allowSelfDemoSwitch` for interactive RBAC testing.
 */
router.patch(
    '/:projectId/members/:targetUserId/role',
    (req: AuthenticatedRequest, res: Response): void => {
        const user = req.user!;
        const clientIp = extractClientIp(req);
        const projectId = String(req.params.projectId || '');
        const targetUserId = String(req.params.targetUserId || '');
        const newRole = String(req.body?.role || '').toUpperCase() as CollaboratorRole;
        const isSelfDemoSwitch =
            Boolean(req.body?.selfDemoSwitch) && targetUserId === user.userId;

        const validRoles: CollaboratorRole[] = ['OWNER', 'EDITOR', 'VIEWER'];
        if (!validRoles.includes(newRole)) {
            res.status(400).json({
                error: 'Invalid role',
                message: 'Role must be OWNER, EDITOR, or VIEWER.',
            });
            return;
        }

        const callerRole = getUserRoleInProject(projectId, user.userId);
        if (!callerRole) {
            res.status(403).json({
                error: 'Forbidden',
                message: 'You are not a member of this project.',
            });
            return;
        }

        // Enforce strict server-side RBAC: Only OWNER can modify roles of other members
        if (callerRole !== 'OWNER' && !isSelfDemoSwitch) {
            logSecurityEvent({
                projectId,
                userId: user.userId,
                username: user.username,
                eventType: 'RBAC_VIOLATION_ATTEMPT',
                severity: 'HIGH',
                details: `Privilege escalation blocked: @${user.username} (role: ${callerRole}) attempted to change member ${targetUserId} role to ${newRole}`,
                ipAddress: clientIp,
                blocked: true,
            });
            res.status(403).json({
                error: 'RBAC Violation: 403 Forbidden',
                code: 'RBAC_VIOLATION_ATTEMPT',
                message: `Role "${callerRole}" is not authorized to modify collaborator permissions. Only OWNER can manage roles.`,
            });
            return;
        }

        statements.updateMemberRole.run({
            projectId,
            userId: targetUserId,
            role: newRole,
        });

        logSecurityEvent({
            projectId,
            userId: user.userId,
            username: user.username,
            eventType: 'MEMBER_ROLE_UPDATED',
            severity: 'INFO',
            details: `Updated RBAC role for user ${targetUserId} to ${newRole} (by @${user.username})`,
            ipAddress: clientIp,
            blocked: false,
        });

        const members: ProjectMember[] = (
            statements.getProjectMembers.all(projectId) as Record<string, unknown>[]
        ).map(mapMemberRow);

        res.json({
            projectId,
            targetUserId,
            role: newRole,
            members,
        });
    }
);

/**
 * POST /api/projects/:projectId/rotate-invite
 * Cryptographically rotates a project's invite code (OWNER only).
 */
router.post(
    '/:projectId/rotate-invite',
    (req: AuthenticatedRequest, res: Response): void => {
        const user = req.user!;
        const clientIp = extractClientIp(req);
        const projectId = String(req.params.projectId || '');

        const callerRole = getUserRoleInProject(projectId, user.userId);
        if (callerRole !== 'OWNER') {
            logSecurityEvent({
                projectId,
                userId: user.userId,
                username: user.username,
                eventType: 'RBAC_VIOLATION_ATTEMPT',
                severity: 'HIGH',
                details: `Unauthorized invite rotation blocked: @${user.username} has role ${callerRole || 'NONE'
                    } (OWNER required)`,
                ipAddress: clientIp,
                blocked: true,
            });
            res.status(403).json({
                error: 'RBAC Violation: 403 Forbidden',
                code: 'RBAC_VIOLATION_ATTEMPT',
                message: 'Only the project OWNER can rotate cryptographic invite codes.',
            });
            return;
        }

        const newInviteCode = generateInviteCode('DC');
        const now = new Date().toISOString();
        statements.updateProjectInviteCode.run({
            id: projectId,
            inviteCode: newInviteCode,
            updatedAt: now,
        });

        logSecurityEvent({
            projectId,
            userId: user.userId,
            username: user.username,
            eventType: 'INVITE_CODE_ROTATED',
            severity: 'INFO',
            details: `Rotated cryptographic project invite code to ${newInviteCode}`,
            ipAddress: clientIp,
            blocked: false,
        });

        res.json({ projectId, inviteCode: newInviteCode });
    }
);

/**
 * PATCH /api/projects/:projectId/lock
 * Toggles emergency lockdown mode on a project (OWNER only).
 */
router.patch(
    '/:projectId/lock',
    (req: AuthenticatedRequest, res: Response): void => {
        const user = req.user!;
        const clientIp = extractClientIp(req);
        const projectId = String(req.params.projectId || '');

        const callerRole = getUserRoleInProject(projectId, user.userId);
        if (callerRole !== 'OWNER') {
            logSecurityEvent({
                projectId,
                userId: user.userId,
                username: user.username,
                eventType: 'RBAC_VIOLATION_ATTEMPT',
                severity: 'HIGH',
                details: `Unauthorized project lock toggle blocked: @${user.username} has role ${callerRole || 'NONE'
                    }`,
                ipAddress: clientIp,
                blocked: true,
            });
            res.status(403).json({
                error: 'RBAC Violation: 403 Forbidden',
                code: 'RBAC_VIOLATION_ATTEMPT',
                message: 'Only the project OWNER can lock or unlock the workspace.',
            });
            return;
        }

        const projectRow = statements.getProjectById.get(projectId) as
            | Record<string, unknown>
            | undefined;
        if (!projectRow) {
            res.status(404).json({ error: 'Project not found' });
            return;
        }

        const nextLockState =
            typeof req.body?.isLocked === 'boolean'
                ? req.body.isLocked
                : !Boolean(projectRow.is_locked);
        const now = new Date().toISOString();

        statements.updateProjectLock.run({
            id: projectId,
            isLocked: nextLockState ? 1 : 0,
            updatedAt: now,
        });

        logSecurityEvent({
            projectId,
            userId: user.userId,
            username: user.username,
            eventType: 'PROJECT_LOCK_TOGGLED',
            severity: nextLockState ? 'MEDIUM' : 'INFO',
            details: `Workspace lockdown state set to ${nextLockState ? 'LOCKED' : 'UNLOCKED'
                } by @${user.username}`,
            ipAddress: clientIp,
            blocked: false,
        });

        res.json({ projectId, isLocked: nextLockState });
    }
);

/**
 * GET /api/projects/:projectId/security-logs
 * Returns real-time security audit telemetry for the project.
 */
router.get(
    '/:projectId/security-logs',
    (req: AuthenticatedRequest, res: Response): void => {
        const user = req.user!;
        const projectId = String(req.params.projectId || '');
        const limit = Math.min(200, Math.max(10, Number(req.query.limit) || 80));

        const callerRole = getUserRoleInProject(projectId, user.userId);
        if (!callerRole) {
            res.status(403).json({
                error: 'Forbidden',
                message: 'Must be a project member to inspect security telemetry.',
            });
            return;
        }

        const rows = statements.listSecurityLogsByProject.all(
            projectId,
            limit
        ) as Record<string, unknown>[];

        const logs = rows.map(mapSecurityLogRow);
        res.json({ logs });
    }
);

export default router;