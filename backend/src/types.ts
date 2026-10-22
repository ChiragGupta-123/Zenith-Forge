import { Request } from 'express';

export type CollaboratorRole = 'OWNER' | 'EDITOR' | 'VIEWER';

export type SupportedLanguage =
    | 'python'
    | 'javascript'
    | 'typescript'
    | 'cpp'
    | 'java'
    | 'markdown'
    | 'json';

export type SecuritySeverity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type RedTeamAttackType = 'rce' | 'traversal' | 'rbac';

export type SandboxRuntimeType =
    | 'piston'
    | 'local-vm'
    | 'sandbox-guard'
    | 'offline-unavailable';

export interface User {
    id: string;
    username: string;
    displayName: string;
    avatarColor: string;
    createdAt: string;
    lastSeenAt: string;
}

export interface JwtPayload {
    userId: string;
    username: string;
    displayName: string;
    avatarColor: string;
    iat: number;
    exp: number;
    jti: string;
}

export interface AuthenticatedUser extends JwtPayload {
    id: string;
}

export interface AuthenticatedRequest extends Request {
    user?: AuthenticatedUser;
    clientIp?: string;
}

export interface ProjectMember {
    projectId: string;
    userId: string;
    username: string;
    displayName?: string;
    role: CollaboratorRole;
    avatarColor: string;
    joinedAt: string;
}

export interface Project {
    id: string;
    name: string;
    description: string;
    ownerId: string;
    inviteCode: string;
    isLocked: boolean;
    createdAt: string;
    updatedAt: string;
    role?: CollaboratorRole;
    members?: ProjectMember[];
    fileCount?: number;
}

export interface ProjectFile {
    id: string;
    projectId: string;
    name: string;
    language: SupportedLanguage;
    content: string;
    version: number;
    updatedBy: string;
    createdAt: string;
    updatedAt: string;
}

export interface VersionSnapshot {
    id: string;
    fileId: string;
    projectId: string;
    version: number;
    label: string;
    content: string;
    hash: string;
    createdBy: string;
    createdByUsername: string;
    createdAt: string;
}

export interface InlineComment {
    id: string;
    fileId: string;
    projectId: string;
    userId: string;
    username: string;
    lineNumber: number;
    content: string;
    resolved: boolean;
    createdAt: string;
}

export interface SecurityEvent {
    id: string;
    projectId: string | null;
    userId: string | null;
    username: string | null;
    eventType: string;
    severity: SecuritySeverity;
    details: string;
    ipAddress: string;
    blocked: boolean;
    createdAt: string;
}

export interface SecurityAlertBanner {
    alertId: string;
    projectId: string | null;
    eventType: string;
    severity: SecuritySeverity;
    message: string;
    details: string;
    username: string | null;
    blocked: boolean;
    createdAt: string;
}

export interface FilenameValidationResult {
    valid: boolean;
    sanitizedName: string;
    language: SupportedLanguage | null;
    reason?: string;
}

export interface ThreatRuleMatch {
    ruleId: string;
    patternName: string;
    severity: SecuritySeverity;
    description: string;
    line: number;
    snippet: string;
}

export interface ThreatScanResult {
    safe: boolean;
    threats: string[];
    riskScore: number;
    matchedRules: ThreatRuleMatch[];
}

export interface ActiveCursorPresence {
    userId: string;
    username: string;
    displayName: string;
    avatarColor: string;
    role: CollaboratorRole;
    fileId: string;
    lineNumber: number;
    column: number;
    lastActiveAt: number;
}

export interface SharedBreakpoint {
    id: string;
    fileId: string;
    lineNumber: number;
    condition?: string;
    createdBy: string;
    username: string;
    createdAt: string;
}

export interface ChatMessage {
    id: string;
    projectId: string;
    userId: string;
    username: string;
    avatarColor: string;
    role: CollaboratorRole;
    message: string;
    createdAt: string;
}

export interface ExecutionStartedEvent {
    executionId: string;
    projectId: string;
    fileId?: string;
    fileName: string;
    language: SupportedLanguage;
    startedBy: string;
    userId: string;
    startedAt: string;
}

export interface ExecutionResult {
    id: string;
    projectId: string;
    fileId?: string;
    fileName?: string;
    language: SupportedLanguage;
    stdout: string;
    stderr: string;
    exitCode: number | null;
    executionTimeMs: number;
    durationMs: number;
    memoryUsedKb: number;
    memoryPolicy: string;
    timedOut: boolean;
    sandboxBlocked: boolean;
    blocked: boolean;
    threatsDetected: string[];
    riskScore: number;
    threatScan: ThreatScanResult;
    executedBy: string;
    executedAt: string;
    runtime: SandboxRuntimeType;
    isolationLayer?: string;
}

export interface RedTeamSimulationResult {
    attackType: RedTeamAttackType;
    blocked: boolean;
    defense: string;
    payloadPreview: string;
    eventId: string;
    attackName: string;
    payloadSummary: string;
    httpStatus: number;
    defenseLayer: string;
    securityEvent?: SecurityEvent;
    details: string;
    timestamp: string;
}