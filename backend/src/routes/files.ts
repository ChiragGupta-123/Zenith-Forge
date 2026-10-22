import { Router, Response } from 'express';
import crypto from 'crypto';
import { AuthenticatedRequest, CollaboratorRole } from '../types';
import {
    containsXssVector,
    createRateLimiter,
    extractClientIp,
    requireAuth,
    sanitizeText,
    scanCodeForThreats,
    validateSafeFilename,
} from '../security/securityMiddleware';
import {
    computeSha256Hash,
    db,
    getUserRoleInProject,
    logSecurityEvent,
    mapCommentRow,
    mapFileRow,
    mapSnapshotRow,
    statements,
} from '../db';

const router = Router();

// Enforce HMAC-SHA256 JWT authentication across all file routes
router.use(requireAuth);

/**
 * Helper to verify that the caller has write privileges (`OWNER` or `EDITOR`)
 * in SQLite. If caller is `VIEWER` or non-member, logs `RBAC_VIOLATION_ATTEMPT`
 * and sends `403 Forbidden`.
 */
function verifyWritePermission(
    req: AuthenticatedRequest,
    res: Response,
    projectId: string,
    actionDescription: string
): CollaboratorRole | null {
    const user = req.user!;
    const clientIp = extractClientIp(req);

    const projectRow = statements.getProjectById.get(projectId) as
        | Record<string, unknown>
        | undefined;
    if (!projectRow) {
        res.status(404).json({
            error: 'Project not found',
            message: `Project "${projectId}" does not exist.`,
        });
        return null;
    }

    const role = getUserRoleInProject(projectId, user.userId);
    if (!role || role === 'VIEWER') {
        logSecurityEvent({
            projectId,
            userId: user.userId,
            username: user.username,
            eventType: 'RBAC_VIOLATION_ATTEMPT',
            severity: 'HIGH',
            details: `Blocked ${role || 'NON_MEMBER'
                } @${user.username} from performing write operation: ${actionDescription}`,
            ipAddress: clientIp,
            blocked: true,
        });
        res.status(403).json({
            error: 'RBAC Violation: 403 Forbidden',
            code: 'RBAC_VIOLATION_ATTEMPT',
            message: `Your role (${role || 'NONE'
                }) is read-only. Modifying files, snapshots, or project structure requires EDITOR or OWNER permissions.`,
        });
        return null;
    }

    // Enforce workspace lockdown if project is locked and user is not OWNER
    if (Boolean(projectRow.is_locked) && role !== 'OWNER') {
        logSecurityEvent({
            projectId,
            userId: user.userId,
            username: user.username,
            eventType: 'RBAC_VIOLATION_ATTEMPT',
            severity: 'MEDIUM',
            details: `Write blocked during workspace lockdown: @${user.username} attempted ${actionDescription}`,
            ipAddress: clientIp,
            blocked: true,
        });
        res.status(423).json({
            error: 'Workspace Locked',
            code: 'PROJECT_LOCKED',
            message: 'This project is currently locked by the OWNER. Only the OWNER can modify files while locked.',
        });
        return null;
    }

    return role;
}

/**
 * GET /api/files/project/:projectId
 * Lists all files in a project for authorized members.
 */
router.get(
    '/project/:projectId',
    (req: AuthenticatedRequest, res: Response): void => {
        const user = req.user!;
        const projectId = String(req.params.projectId || '');

        const role = getUserRoleInProject(projectId, user.userId);
        if (!role) {
            res.status(403).json({
                error: 'Access Denied',
                message: 'You must be a member of this project to view its files.',
            });
            return;
        }

        const rows = statements.listFilesByProject.all(projectId) as Record<
            string,
            unknown
        >[];
        res.json({
            files: rows.map(mapFileRow),
            callerRole: role,
        });
    }
);

/**
 * GET /api/files/:fileId
 * Fetches a single file, its version snapshots, and inline comments.
 */
router.get('/:fileId', (req: AuthenticatedRequest, res: Response): void => {
    const user = req.user!;
    const fileId = String(req.params.fileId || '');

    const fileRow = statements.getFileById.get(fileId) as
        | Record<string, unknown>
        | undefined;
    if (!fileRow) {
        res.status(404).json({ error: 'File not found' });
        return;
    }

    const file = mapFileRow(fileRow);
    const role = getUserRoleInProject(file.projectId, user.userId);
    if (!role) {
        res.status(403).json({
            error: 'Access Denied',
            message: 'You are not authorized to view this file.',
        });
        return;
    }

    const snapshots = (
        statements.listSnapshotsByFile.all(fileId) as Record<string, unknown>[]
    ).map(mapSnapshotRow);

    const comments = (
        statements.listCommentsByFile.all(fileId) as Record<string, unknown>[]
    ).map(mapCommentRow);

    res.json({
        file,
        snapshots,
        comments,
        callerRole: role,
    });
});

/**
 * POST /api/files
 * Creates a new file inside a project after validating RBAC and path-traversal safety.
 */
router.post(
    '/',
    createRateLimiter(30, 60_000, 'file-create'),
    (req: AuthenticatedRequest, res: Response): void => {
        const user = req.user!;
        const clientIp = extractClientIp(req);
        const projectId = String(req.body?.projectId || '');
        const rawName = req.body?.name;
        const rawContent = typeof req.body?.content === 'string' ? req.body.content : '';

        if (!projectId) {
            res.status(400).json({ error: 'projectId is required' });
            return;
        }

        const role = verifyWritePermission(
            req,
            res,
            projectId,
            `create file "${String(rawName || '')}"`
        );
        if (!role) {
            return;
        }

        const filenameCheck = validateSafeFilename(rawName);
        if (!filenameCheck.valid || !filenameCheck.language) {
            logSecurityEvent({
                projectId,
                userId: user.userId,
                username: user.username,
                eventType: 'PATH_TRAVERSAL_BLOCKED',
                severity: 'CRITICAL',
                details: `Blocked unsafe filename creation "${String(rawName).slice(
                    0,
                    80
                )}" by @${user.username}: ${filenameCheck.reason}`,
                ipAddress: clientIp,
                blocked: true,
            });
            res.status(400).json({
                error: 'Unsafe Filename Blocked',
                code: 'PATH_TRAVERSAL_BLOCKED',
                message: filenameCheck.reason || 'Filename rejected by Zero-Trust validator.',
            });
            return;
        }

        const existing = statements.getFileByProjectAndName.get(
            projectId,
            filenameCheck.sanitizedName
        );
        if (existing) {
            res.status(409).json({
                error: 'Duplicate filename',
                message: `A file named "${filenameCheck.sanitizedName}" already exists in this project.`,
            });
            return;
        }

        if (rawContent.length > 500_000) {
            res.status(413).json({
                error: 'Payload Too Large',
                message: 'File content exceeds the 500 KB maximum limit.',
            });
            return;
        }

        const threatScan = scanCodeForThreats(rawContent, filenameCheck.language);
        if (!threatScan.safe) {
            logSecurityEvent({
                projectId,
                userId: user.userId,
                username: user.username,
                eventType: 'STATIC_THREAT_DETECTED',
                severity: threatScan.riskScore >= 45 ? 'HIGH' : 'MEDIUM',
                details: `Static scanner flagged new file "${filenameCheck.sanitizedName
                    }" (risk score ${threatScan.riskScore}/100): ${threatScan.threats.join('; ')}`,
                ipAddress: clientIp,
                blocked: false,
            });
        }

        const fileId = `file-${crypto.randomUUID().slice(0, 12)}`;
        const now = new Date().toISOString();

        const createFileTx = db.transaction(() => {
            statements.insertFile.run({
                id: fileId,
                projectId,
                name: filenameCheck.sanitizedName,
                language: filenameCheck.language!,
                content: rawContent,
                version: 1,
                updatedBy: user.username,
                createdAt: now,
                updatedAt: now,
            });

            statements.insertSnapshot.run({
                id: crypto.randomUUID(),
                fileId,
                projectId,
                version: 1,
                label: `Created ${filenameCheck.sanitizedName}`,
                content: rawContent,
                hash: computeSha256Hash(rawContent),
                createdBy: user.userId,
                createdByUsername: user.username,
                createdAt: now,
            });

            statements.updateProjectTimestamp.run({
                id: projectId,
                updatedAt: now,
            });
        });

        createFileTx();

        const createdRow = statements.getFileById.get(fileId) as Record<
            string,
            unknown
        >;
        res.status(201).json({
            file: mapFileRow(createdRow),
            threatScan,
        });
    }
);

/**
 * PUT /api/files/:fileId
 * Updates a file's content after verifying RBAC permissions in SQLite.
 */
router.put(
    '/:fileId',
    createRateLimiter(120, 60_000, 'file-update'),
    (req: AuthenticatedRequest, res: Response): void => {
        const user = req.user!;
        const clientIp = extractClientIp(req);
        const fileId = String(req.params.fileId || '');
        const content = typeof req.body?.content === 'string' ? req.body.content : '';
        const createSnapshotFlag = Boolean(req.body?.createSnapshot);
        const snapshotLabel = sanitizeText(
            req.body?.snapshotLabel || 'Manual checkpoint',
            100
        );

        const fileRow = statements.getFileById.get(fileId) as
            | Record<string, unknown>
            | undefined;
        if (!fileRow) {
            res.status(404).json({ error: 'File not found' });
            return;
        }

        const existingFile = mapFileRow(fileRow);
        const role = verifyWritePermission(
            req,
            res,
            existingFile.projectId,
            `update file "${existingFile.name}"`
        );
        if (!role) {
            return;
        }

        if (content.length > 500_000) {
            res.status(413).json({
                error: 'Payload Too Large',
                message: 'File content exceeds the 500 KB maximum limit.',
            });
            return;
        }

        const threatScan = scanCodeForThreats(content, existingFile.language);
        if (!threatScan.safe) {
            logSecurityEvent({
                projectId: existingFile.projectId,
                userId: user.userId,
                username: user.username,
                eventType: 'STATIC_THREAT_DETECTED',
                severity: threatScan.riskScore >= 45 ? 'HIGH' : 'MEDIUM',
                details: `Threat signature detected while editing "${existingFile.name
                    }" (risk ${threatScan.riskScore}/100): ${threatScan.threats[0]}`,
                ipAddress: clientIp,
                blocked: false,
            });
        }

        const now = new Date().toISOString();
        const nextVersion = existingFile.version + 1;

        const updateTx = db.transaction(() => {
            statements.updateFileContent.run({
                id: fileId,
                content,
                updatedBy: user.username,
                updatedAt: now,
            });

            if (createSnapshotFlag) {
                statements.insertSnapshot.run({
                    id: crypto.randomUUID(),
                    fileId,
                    projectId: existingFile.projectId,
                    version: nextVersion,
                    label: snapshotLabel,
                    content,
                    hash: computeSha256Hash(content),
                    createdBy: user.userId,
                    createdByUsername: user.username,
                    createdAt: now,
                });
            }

            statements.updateProjectTimestamp.run({
                id: existingFile.projectId,
                updatedAt: now,
            });
        });

        updateTx();

        const updatedRow = statements.getFileById.get(fileId) as Record<
            string,
            unknown
        >;
        res.json({
            file: mapFileRow(updatedRow),
            threatScan,
        });
    }
);

/**
 * PATCH /api/files/:fileId/rename
 * Renames a file with strict `validateSafeFilename` traversal protection and RBAC verification.
 */
router.patch(
    '/:fileId/rename',
    createRateLimiter(30, 60_000, 'file-rename'),
    (req: AuthenticatedRequest, res: Response): void => {
        const user = req.user!;
        const clientIp = extractClientIp(req);
        const fileId = String(req.params.fileId || '');
        const rawNewName = req.body?.name;

        const fileRow = statements.getFileById.get(fileId) as
            | Record<string, unknown>
            | undefined;
        if (!fileRow) {
            res.status(404).json({ error: 'File not found' });
            return;
        }

        const existingFile = mapFileRow(fileRow);
        const role = verifyWritePermission(
            req,
            res,
            existingFile.projectId,
            `rename file "${existingFile.name}" to "${String(rawNewName || '')}"`
        );
        if (!role) {
            return;
        }

        const filenameCheck = validateSafeFilename(rawNewName);
        if (!filenameCheck.valid || !filenameCheck.language) {
            logSecurityEvent({
                projectId: existingFile.projectId,
                userId: user.userId,
                username: user.username,
                eventType: 'PATH_TRAVERSAL_BLOCKED',
                severity: 'CRITICAL',
                details: `Blocked unsafe file rename "${String(rawNewName).slice(
                    0,
                    80
                )}" on "${existingFile.name}" by @${user.username}: ${filenameCheck.reason}`,
                ipAddress: clientIp,
                blocked: true,
            });
            res.status(400).json({
                error: 'Unsafe Filename Blocked',
                code: 'PATH_TRAVERSAL_BLOCKED',
                message: filenameCheck.reason || 'Filename rejected by Zero-Trust validator.',
            });
            return;
        }

        const duplicate = statements.getFileByProjectAndName.get(
            existingFile.projectId,
            filenameCheck.sanitizedName
        ) as Record<string, unknown> | undefined;

        if (duplicate && String(duplicate.id) !== fileId) {
            res.status(409).json({
                error: 'Duplicate filename',
                message: `Another file named "${filenameCheck.sanitizedName}" already exists in this project.`,
            });
            return;
        }

        const now = new Date().toISOString();
        statements.renameFile.run({
            id: fileId,
            name: filenameCheck.sanitizedName,
            language: filenameCheck.language,
            updatedBy: user.username,
            updatedAt: now,
        });

        const updatedRow = statements.getFileById.get(fileId) as Record<
            string,
            unknown
        >;
        res.json({ file: mapFileRow(updatedRow) });
    }
);

/**
 * DELETE /api/files/:fileId
 * Deletes a file from a project (requires OWNER or EDITOR role).
 */
router.delete('/:fileId', (req: AuthenticatedRequest, res: Response): void => {
    const fileId = String(req.params.fileId || '');
    const fileRow = statements.getFileById.get(fileId) as
        | Record<string, unknown>
        | undefined;

    if (!fileRow) {
        res.status(404).json({ error: 'File not found' });
        return;
    }

    const existingFile = mapFileRow(fileRow);
    const role = verifyWritePermission(
        req,
        res,
        existingFile.projectId,
        `delete file "${existingFile.name}"`
    );
    if (!role) {
        return;
    }

    statements.deleteFile.run(fileId);
    res.json({ deleted: true, fileId, name: existingFile.name });
});

/**
 * GET /api/files/:fileId/snapshots
 * Lists immutable SHA-256 version snapshots for a file.
 */
router.get(
    '/:fileId/snapshots',
    (req: AuthenticatedRequest, res: Response): void => {
        const user = req.user!;
        const fileId = String(req.params.fileId || '');

        const fileRow = statements.getFileById.get(fileId) as
            | Record<string, unknown>
            | undefined;
        if (!fileRow) {
            res.status(404).json({ error: 'File not found' });
            return;
        }

        const file = mapFileRow(fileRow);
        const role = getUserRoleInProject(file.projectId, user.userId);
        if (!role) {
            res.status(403).json({ error: 'Access Denied' });
            return;
        }

        const rows = statements.listSnapshotsByFile.all(fileId) as Record<
            string,
            unknown
        >[];
        res.json({ snapshots: rows.map(mapSnapshotRow) });
    }
);

/**
 * POST /api/files/:fileId/snapshots
 * Creates a cryptographically hashed (SHA-256) version snapshot of a file.
 */
router.post(
    '/:fileId/snapshots',
    createRateLimiter(30, 60_000, 'snapshot-create'),
    (req: AuthenticatedRequest, res: Response): void => {
        const user = req.user!;
        const clientIp = extractClientIp(req);
        const fileId = String(req.params.fileId || '');

        const fileRow = statements.getFileById.get(fileId) as
            | Record<string, unknown>
            | undefined;
        if (!fileRow) {
            res.status(404).json({ error: 'File not found' });
            return;
        }

        const file = mapFileRow(fileRow);
        const role = verifyWritePermission(
            req,
            res,
            file.projectId,
            `create version snapshot for "${file.name}"`
        );
        if (!role) {
            return;
        }

        if (containsXssVector(req.body?.label)) {
            logSecurityEvent({
                projectId: file.projectId,
                userId: user.userId,
                username: user.username,
                eventType: 'XSS_PAYLOAD_SANITIZED',
                severity: 'HIGH',
                details: `Sanitized XSS vector in snapshot label for "${file.name}" by @${user.username}`,
                ipAddress: clientIp,
                blocked: false,
            });
        }

        const label =
            sanitizeText(req.body?.label, 120) || `Snapshot v${file.version}`;
        const contentToSave =
            typeof req.body?.content === 'string' ? req.body.content : file.content;
        const hash = computeSha256Hash(contentToSave);
        const snapshotId = crypto.randomUUID();
        const now = new Date().toISOString();

        statements.insertSnapshot.run({
            id: snapshotId,
            fileId: file.id,
            projectId: file.projectId,
            version: file.version,
            label,
            content: contentToSave,
            hash,
            createdBy: user.userId,
            createdByUsername: user.username,
            createdAt: now,
        });

        logSecurityEvent({
            projectId: file.projectId,
            userId: user.userId,
            username: user.username,
            eventType: 'SNAPSHOT_CREATED',
            severity: 'INFO',
            details: `Created SHA-256 verified snapshot "${label}" (${hash.slice(
                0,
                12
            )}...) for ${file.name}`,
            ipAddress: clientIp,
            blocked: false,
        });

        const createdSnapshot = statements.getSnapshotById.get(
            snapshotId
        ) as Record<string, unknown>;
        res.status(201).json({ snapshot: mapSnapshotRow(createdSnapshot) });
    }
);

/**
 * POST /api/files/:fileId/restore/:snapshotId
 * Restores a file to a previous snapshot after verifying its SHA-256 content hash.
 */
router.post(
    '/:fileId/restore/:snapshotId',
    (req: AuthenticatedRequest, res: Response): void => {
        const user = req.user!;
        const clientIp = extractClientIp(req);
        const fileId = String(req.params.fileId || '');
        const snapshotId = String(req.params.snapshotId || '');

        const fileRow = statements.getFileById.get(fileId) as
            | Record<string, unknown>
            | undefined;
        if (!fileRow) {
            res.status(404).json({ error: 'File not found' });
            return;
        }

        const file = mapFileRow(fileRow);
        const role = verifyWritePermission(
            req,
            res,
            file.projectId,
            `restore snapshot on "${file.name}"`
        );
        if (!role) {
            return;
        }

        const snapshotRow = statements.getSnapshotById.get(snapshotId) as
            | Record<string, unknown>
            | undefined;
        if (!snapshotRow) {
            res.status(404).json({ error: 'Snapshot not found' });
            return;
        }

        const snapshot = mapSnapshotRow(snapshotRow);
        if (snapshot.fileId !== file.id) {
            res.status(400).json({
                error: 'Snapshot mismatch',
                message: 'Selected snapshot does not belong to the target file.',
            });
            return;
        }

        // Verify cryptographic SHA-256 integrity of snapshot content
        const recomputedHash = computeSha256Hash(snapshot.content);
        if (recomputedHash !== snapshot.hash) {
            logSecurityEvent({
                projectId: file.projectId,
                userId: user.userId,
                username: user.username,
                eventType: 'UNAUTHORIZED_ACCESS_ATTEMPT',
                severity: 'CRITICAL',
                details: `Snapshot SHA-256 integrity mismatch detected on ${file.name} (expected ${snapshot.hash.slice(
                    0,
                    12
                )}, got ${recomputedHash.slice(0, 12)})`,
                ipAddress: clientIp,
                blocked: true,
            });
            res.status(422).json({
                error: 'Snapshot Integrity Verification Failed',
                message: 'SHA-256 digest mismatch; snapshot cannot be trusted.',
            });
            return;
        }

        const now = new Date().toISOString();
        statements.updateFileContent.run({
            id: file.id,
            content: snapshot.content,
            updatedBy: user.username,
            updatedAt: now,
        });

        logSecurityEvent({
            projectId: file.projectId,
            userId: user.userId,
            username: user.username,
            eventType: 'SNAPSHOT_RESTORED',
            severity: 'INFO',
            details: `Restored "${file.name}" to snapshot "${snapshot.label}" (SHA-256 verified: ${snapshot.hash.slice(
                0,
                12
            )}...)`,
            ipAddress: clientIp,
            blocked: false,
        });

        const updatedFileRow = statements.getFileById.get(file.id) as Record<
            string,
            unknown
        >;
        res.json({
            file: mapFileRow(updatedFileRow),
            restoredSnapshot: snapshot,
        });
    }
);

/**
 * GET /api/files/:fileId/comments
 * Lists inline review comments for a file.
 */
router.get(
    '/:fileId/comments',
    (req: AuthenticatedRequest, res: Response): void => {
        const user = req.user!;
        const fileId = String(req.params.fileId || '');

        const fileRow = statements.getFileById.get(fileId) as
            | Record<string, unknown>
            | undefined;
        if (!fileRow) {
            res.status(404).json({ error: 'File not found' });
            return;
        }

        const file = mapFileRow(fileRow);
        const role = getUserRoleInProject(file.projectId, user.userId);
        if (!role) {
            res.status(403).json({ error: 'Access Denied' });
            return;
        }

        const rows = statements.listCommentsByFile.all(fileId) as Record<
            string,
            unknown
        >[];
        res.json({ comments: rows.map(mapCommentRow) });
    }
);

/**
 * POST /api/files/:fileId/comments
 * Adds a Stored-XSS-sanitized inline comment to a specific line number.
 */
router.post(
    '/:fileId/comments',
    createRateLimiter(40, 60_000, 'comment-create'),
    (req: AuthenticatedRequest, res: Response): void => {
        const user = req.user!;
        const clientIp = extractClientIp(req);
        const fileId = String(req.params.fileId || '');
        const rawContent = req.body?.content;
        const lineNumber = Math.max(1, Math.min(50_000, Number(req.body?.lineNumber) || 1));

        const fileRow = statements.getFileById.get(fileId) as
            | Record<string, unknown>
            | undefined;
        if (!fileRow) {
            res.status(404).json({ error: 'File not found' });
            return;
        }

        const file = mapFileRow(fileRow);
        const role = getUserRoleInProject(file.projectId, user.userId);
        if (!role) {
            res.status(403).json({
                error: 'Access Denied',
                message: 'Only project members can post inline comments.',
            });
            return;
        }

        const hadXssPayload = containsXssVector(rawContent);
        const sanitizedContent = sanitizeText(rawContent, 600);

        if (!sanitizedContent) {
            res.status(400).json({
                error: 'Empty comment',
                message: 'Comment content cannot be empty.',
            });
            return;
        }

        if (hadXssPayload) {
            logSecurityEvent({
                projectId: file.projectId,
                userId: user.userId,
                username: user.username,
                eventType: 'XSS_PAYLOAD_SANITIZED',
                severity: 'HIGH',
                details: `Neutralized Stored XSS payload in inline comment on ${file.name}:${lineNumber} by @${user.username}`,
                ipAddress: clientIp,
                blocked: true,
            });
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
            content: sanitizedContent,
            resolved: 0,
            createdAt: now,
        });

        const createdRow = statements.getCommentById.get(commentId) as Record<
            string,
            unknown
        >;
        res.status(201).json({
            comment: mapCommentRow(createdRow),
            xssSanitized: hadXssPayload,
        });
    }
);

/**
 * PATCH /api/files/comments/:commentId/resolve
 * Marks an inline comment as resolved or active.
 */
router.patch(
    '/comments/:commentId/resolve',
    (req: AuthenticatedRequest, res: Response): void => {
        const user = req.user!;
        const commentId = String(req.params.commentId || '');

        const commentRow = statements.getCommentById.get(commentId) as
            | Record<string, unknown>
            | undefined;
        if (!commentRow) {
            res.status(404).json({ error: 'Comment not found' });
            return;
        }

        const comment = mapCommentRow(commentRow);
        const role = verifyWritePermission(
            req,
            res,
            comment.projectId,
            `resolve inline comment on line ${comment.lineNumber}`
        );
        if (!role) {
            return;
        }

        const nextResolved =
            typeof req.body?.resolved === 'boolean'
                ? req.body.resolved
                : !comment.resolved;

        statements.updateCommentResolved.run({
            id: commentId,
            resolved: nextResolved ? 1 : 0,
        });

        const updatedRow = statements.getCommentById.get(commentId) as Record<
            string,
            unknown
        >;
        res.json({ comment: mapCommentRow(updatedRow) });
    }
);

/**
 * DELETE /api/files/comments/:commentId
 * Deletes an inline comment (allowed for comment author, EDITOR, or OWNER).
 */
router.delete(
    '/comments/:commentId',
    (req: AuthenticatedRequest, res: Response): void => {
        const user = req.user!;
        const commentId = String(req.params.commentId || '');

        const commentRow = statements.getCommentById.get(commentId) as
            | Record<string, unknown>
            | undefined;
        if (!commentRow) {
            res.status(404).json({ error: 'Comment not found' });
            return;
        }

        const comment = mapCommentRow(commentRow);
        const role = verifyWritePermission(
            req,
            res,
            comment.projectId,
            `delete inline comment ${commentId}`
        );
        if (!role) {
            return;
        }

        statements.deleteComment.run(commentId);
        res.json({ deleted: true, commentId });
    }
);

export default router;