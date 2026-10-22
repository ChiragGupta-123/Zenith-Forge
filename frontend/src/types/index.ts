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

export interface User {
    id: string;
    username: string;
    displayName: string;
    avatarColor: string;
    createdAt: string;
    lastSeenAt: string;
}

export interface PersonaSession {
    token: string;
    user: User;
    preferredRole: CollaboratorRole;
    demoProjectId: string;
    issuedAt: string;
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

export interface ExecutionResult {
    id: string;
    projectId: string;
    fileId?: string;
    language: SupportedLanguage;
    stdout: string;
    stderr: string;
    exitCode: number | null;
    executionTimeMs: number;
    memoryUsedKb: number;
    timedOut: boolean;
    sandboxBlocked: boolean;
    threatsDetected: string[];
    riskScore: number;
    executedBy: string;
    executedAt: string;
    isolationLayer?: string;
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

export interface CursorPosition {
    lineNumber: number;
    column: number;
}

export interface CollaboratorPresence {
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

export interface RedTeamSimulationResult {
    attackType: RedTeamAttackType;
    attackName: string;
    payloadSummary: string;
    blocked: boolean;
    httpStatus: number;
    defenseLayer: string;
    securityEvent?: SecurityEvent;
    details: string;
    timestamp: string;
}

export interface AiSecurityFinding {
    line: number;
    severity: SecuritySeverity;
    title: string;
    recommendation: string;
    cweId?: string;
}

export interface AiSecurityReview {
    summary: string;
    overallRiskScore: number;
    safeToDeploy: boolean;
    findings: AiSecurityFinding[];
    hardenedSnippet?: string;
    analyzedAt: string;
}

export interface CrdtTelemetryState {
    syncOpsCount: number;
    vectorByteSize: number;
    blockedIntrusionsCount: number;
    connectedPeersCount: number;
    wsLatencyMs: number;
}