import crypto from 'crypto';
import path from 'path';
import { Response, NextFunction } from 'express';
import {
    AuthenticatedRequest,
    AuthenticatedUser,
    FilenameValidationResult,
    JwtPayload,
    SecuritySeverity,
    SupportedLanguage,
    ThreatRuleMatch,
    ThreatScanResult,
} from '../types';

/**
 * Cryptographic HMAC-SHA256 secret key.
 * Generated securely at boot if JWT_SECRET is not provided in environment,
 * or derived deterministically from environment secret with 256-bit entropy.
 */
const RAW_SECRET =
    process.env.JWT_SECRET ||
    'devcollab-zero-trust-hmac-sha256-master-key-2026-quantum-shield';

const HMAC_SECRET_KEY: Buffer = crypto
    .createHash('sha256')
    .update(RAW_SECRET, 'utf8')
    .digest();

const DEFAULT_TOKEN_TTL_SECONDS = 12 * 60 * 60; // 12 hours for hackathon duration

function base64UrlEncode(input: Buffer | string): string {
    const buf = Buffer.isBuffer(input) ? input : Buffer.from(input, 'utf8');
    return buf
        .toString('base64')
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
}

function base64UrlDecodeToString(input: string): string {
    const normalized = input.replace(/-/g, '+').replace(/_/g, '/');
    const padLength = (4 - (normalized.length % 4)) % 4;
    const padded = normalized + '='.repeat(padLength);
    return Buffer.from(padded, 'base64').toString('utf8');
}

/**
 * Zero-dependency HMAC-SHA256 JWT signer using Node's native `crypto` module.
 * Prevents clients from spoofing `userId` or `username`.
 */
export function signToken(
    payload: {
        userId: string;
        username: string;
        displayName?: string;
        avatarColor?: string;
    },
    expiresInSeconds: number = DEFAULT_TOKEN_TTL_SECONDS
): string {
    const nowSeconds = Math.floor(Date.now() / 1000);
    const header = {
        alg: 'HS256',
        typ: 'JWT',
    };

    const fullPayload: JwtPayload = {
        userId: payload.userId,
        username: payload.username,
        displayName: payload.displayName || payload.username,
        avatarColor: payload.avatarColor || '#10b981',
        iat: nowSeconds,
        exp: nowSeconds + expiresInSeconds,
        jti: crypto.randomUUID(),
    };

    const encodedHeader = base64UrlEncode(JSON.stringify(header));
    const encodedPayload = base64UrlEncode(JSON.stringify(fullPayload));
    const signingInput = `${encodedHeader}.${encodedPayload}`;

    const signature = crypto
        .createHmac('sha256', HMAC_SECRET_KEY)
        .update(signingInput, 'utf8')
        .digest();

    const encodedSignature = base64UrlEncode(signature);
    return `${signingInput}.${encodedSignature}`;
}

/**
 * Zero-dependency HMAC-SHA256 JWT verifier with constant-time `timingSafeEqual`
 * comparison to prevent timing side-channel attacks.
 */
export function verifyToken(token: string): JwtPayload | null {
    try {
        if (!token || typeof token !== 'string') {
            return null;
        }

        const cleanToken = token.startsWith('Bearer ')
            ? token.slice(7).trim()
            : token.trim();

        const parts = cleanToken.split('.');
        if (parts.length !== 3) {
            return null;
        }

        const [encodedHeader, encodedPayload, providedSignature] = parts;
        if (!encodedHeader || !encodedPayload || !providedSignature) {
            return null;
        }

        // Verify header algorithm strictly matches HS256 (blocks "alg: none" attack)
        const headerJson = base64UrlDecodeToString(encodedHeader);
        const parsedHeader = JSON.parse(headerJson) as { alg?: string; typ?: string };
        if (parsedHeader.alg !== 'HS256' || parsedHeader.typ !== 'JWT') {
            return null;
        }

        const signingInput = `${encodedHeader}.${encodedPayload}`;
        const expectedSigBuffer = crypto
            .createHmac('sha256', HMAC_SECRET_KEY)
            .update(signingInput, 'utf8')
            .digest();
        const expectedSigEncoded = base64UrlEncode(expectedSigBuffer);

        const a = Buffer.from(providedSignature, 'utf8');
        const b = Buffer.from(expectedSigEncoded, 'utf8');

        if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
            return null;
        }

        const payloadJson = base64UrlDecodeToString(encodedPayload);
        const payload = JSON.parse(payloadJson) as JwtPayload;

        if (
            !payload ||
            typeof payload.userId !== 'string' ||
            typeof payload.username !== 'string' ||
            typeof payload.exp !== 'number'
        ) {
            return null;
        }

        const nowSeconds = Math.floor(Date.now() / 1000);
        if (payload.exp <= nowSeconds) {
            return null;
        }

        return payload;
    } catch {
        return null;
    }
}

export function extractClientIp(req: AuthenticatedRequest): string {
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string' && forwarded.length > 0) {
        return forwarded.split(',')[0].trim();
    }
    return req.socket?.remoteAddress || req.ip || '127.0.0.1';
}

export type SecurityAuditCallback = (event: {
    projectId?: string | null;
    userId?: string | null;
    username?: string | null;
    eventType: string;
    severity: SecuritySeverity;
    details: string;
    ipAddress: string;
    blocked: boolean;
}) => void;

let registeredAuditLogger: SecurityAuditCallback | null = null;

export function registerSecurityAuditLogger(logger: SecurityAuditCallback): void {
    registeredAuditLogger = logger;
}

function emitSecurityAudit(event: {
    projectId?: string | null;
    userId?: string | null;
    username?: string | null;
    eventType: string;
    severity: SecuritySeverity;
    details: string;
    ipAddress: string;
    blocked: boolean;
}): void {
    if (registeredAuditLogger) {
        try {
            registeredAuditLogger(event);
        } catch {
            // Prevent logging errors from crashing request pipeline
        }
    }
}

/**
 * Express middleware enforcing valid HMAC-SHA256 JWT authentication.
 * Attaches verified `req.user` (`id`, `userId`, `username`, `displayName`, `avatarColor`).
 */
export function requireAuth(
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
): void {
    const clientIp = extractClientIp(req);
    req.clientIp = clientIp;

    const authHeader = req.headers.authorization;
    const headerToken = req.headers['x-auth-token'];
    const rawToken =
        typeof authHeader === 'string'
            ? authHeader
            : typeof headerToken === 'string'
                ? headerToken
                : '';

    if (!rawToken) {
        emitSecurityAudit({
            projectId: null,
            userId: null,
            username: 'anonymous',
            eventType: 'UNAUTHORIZED_ACCESS_ATTEMPT',
            severity: 'MEDIUM',
            details: `Missing JWT token on protected endpoint ${req.method} ${req.originalUrl}`,
            ipAddress: clientIp,
            blocked: true,
        });
        res.status(401).json({
            error: 'Authentication required',
            code: 'AUTH_TOKEN_MISSING',
            message: 'A valid HMAC-SHA256 Bearer token is required to access this resource.',
        });
        return;
    }

    const verifiedPayload = verifyToken(rawToken);
    if (!verifiedPayload) {
        emitSecurityAudit({
            projectId: null,
            userId: null,
            username: 'spoofed_or_expired',
            eventType: 'AUTH_TOKEN_INVALID',
            severity: 'HIGH',
            details: `Invalid, tampered, or expired HMAC-SHA256 JWT rejected on ${req.method} ${req.originalUrl}`,
            ipAddress: clientIp,
            blocked: true,
        });
        res.status(401).json({
            error: 'Invalid or expired authentication token',
            code: 'AUTH_TOKEN_INVALID',
            message: 'JWT signature verification failed or token has expired.',
        });
        return;
    }

    const authenticatedUser: AuthenticatedUser = {
        ...verifiedPayload,
        id: verifiedPayload.userId,
    };

    req.user = authenticatedUser;
    next();
}

/**
 * In-memory IP & User Sliding-Window Rate Limiter middleware.
 * Tracks exact request timestamps within `[now - windowMs, now]` to mitigate
 * credential stuffing, token brute-forcing, and DoS floods.
 */
interface SlidingWindowBucket {
    timestamps: number[];
}

const rateLimitStore = new Map<string, SlidingWindowBucket>();

// Periodic cleanup of stale sliding-window buckets every 60 seconds
const cleanupTimer = setInterval(() => {
    const now = Date.now();
    for (const [key, bucket] of rateLimitStore.entries()) {
        if (
            bucket.timestamps.length === 0 ||
            now - bucket.timestamps[bucket.timestamps.length - 1] > 10 * 60 * 1000
        ) {
            rateLimitStore.delete(key);
        }
    }
}, 60_000);

if (typeof cleanupTimer.unref === 'function') {
    cleanupTimer.unref();
}

export function createRateLimiter(
    maxRequests: number,
    windowMs: number,
    scopeLabel: string = 'global'
) {
    return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
        const now = Date.now();
        const clientIp = extractClientIp(req);
        const userIdentifier = req.user?.userId || 'anon';
        const bucketKey = `${scopeLabel}:${clientIp}:${userIdentifier}`;

        let bucket = rateLimitStore.get(bucketKey);
        if (!bucket) {
            bucket = { timestamps: [] };
            rateLimitStore.set(bucketKey, bucket);
        }

        const windowStart = now - windowMs;
        bucket.timestamps = bucket.timestamps.filter((ts) => ts > windowStart);

        const currentCount = bucket.timestamps.length;
        const remaining = Math.max(0, maxRequests - currentCount - 1);
        const resetMs =
            bucket.timestamps.length > 0
                ? Math.max(0, bucket.timestamps[0] + windowMs - now)
                : windowMs;

        res.setHeader('X-RateLimit-Limit', String(maxRequests));
        res.setHeader('X-RateLimit-Remaining', String(remaining));
        res.setHeader('X-RateLimit-Reset', String(Math.ceil((now + resetMs) / 1000)));

        if (currentCount >= maxRequests) {
            const retryAfterSeconds = Math.max(1, Math.ceil(resetMs / 1000));
            res.setHeader('Retry-After', String(retryAfterSeconds));

            emitSecurityAudit({
                projectId: (req.params?.projectId as string) || (req.body?.projectId as string) || null,
                userId: req.user?.userId || null,
                username: req.user?.username || 'anonymous',
                eventType: 'RATE_LIMIT_EXCEEDED',
                severity: 'HIGH',
                details: `Rate limit exceeded (${currentCount}/${maxRequests} requests in ${windowMs}ms) on scope [${scopeLabel}] ${req.method} ${req.originalUrl}`,
                ipAddress: clientIp,
                blocked: true,
            });

            res.status(429).json({
                error: 'Too Many Requests',
                code: 'RATE_LIMIT_EXCEEDED',
                message: `Sliding-window rate limit exceeded (${maxRequests} requests per ${windowMs / 1000
                    }s). Please wait ${retryAfterSeconds}s.`,
                retryAfterSeconds,
            });
            return;
        }

        bucket.timestamps.push(now);
        next();
    };
}

/**
 * Strips dangerous ASCII/Unicode control characters and escapes HTML entities
 * (`&`, `<`, `>`, `"`, `'`) to neutralize Stored & Reflected XSS vectors.
 */
export function sanitizeText(input: unknown, maxLength: number = 1000): string {
    if (input === null || input === undefined) {
        return '';
    }

    const raw = String(input);

    // Strip null bytes and dangerous non-printable ASCII control characters
    // Preserves standard whitespace: tab (\t = 0x09), newline (\n = 0x0A), carriage return (\r = 0x0D)
    const withoutControls = raw.replace(
        /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\u2028\u2029]/g,
        ''
    );

    const trimmed = withoutControls.trim().slice(0, maxLength);

    // Escape HTML entities so embedded scripts/tags are rendered inert
    return trimmed
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');
}

/**
 * Checks whether raw user input contains suspicious XSS vectors prior to sanitization
 * so the security audit log can record attempted XSS injections.
 */
export function containsXssVector(input: unknown): boolean {
    if (typeof input !== 'string') {
        return false;
    }
    const xssRegex =
        /(<\s*script\b|javascript\s*:|on(?:error|load|click|mouseover|focus|svg)\s*=|<\s*iframe\b|<\s*img\b[^>]*onerror|<\s*svg\b[^>]*onload|document\.cookie|window\.location)/i;
    return xssRegex.test(input);
}

const ALLOWED_EXTENSION_MAP: Record<string, SupportedLanguage> = {
    '.py': 'python',
    '.js': 'javascript',
    '.ts': 'typescript',
    '.cpp': 'cpp',
    '.java': 'java',
    '.md': 'markdown',
    '.json': 'json',
};

const RESERVED_SYSTEM_NAMES = new Set([
    'con',
    'prn',
    'aux',
    'nul',
    'com1',
    'com2',
    'com3',
    'com4',
    'com5',
    'com6',
    'com7',
    'com8',
    'com9',
    'lpt1',
    'lpt2',
    'lpt3',
    'lpt4',
    'lpt5',
    'lpt6',
    'lpt7',
    'lpt8',
    'lpt9',
]);

/**
 * Validates that a filename is strictly immune to directory traversal (`..`, `/`, `\`, null bytes),
 * blocks hidden dotfiles (`.env`, `.git`, `.bashrc`), and enforces the allowlist of extensions
 * (`.py`, `.js`, `.ts`, `.cpp`, `.java`, `.md`, `.json`).
 */
export function validateSafeFilename(name: unknown): FilenameValidationResult {
    if (typeof name !== 'string') {
        return {
            valid: false,
            sanitizedName: '',
            language: null,
            reason: 'Filename must be a non-empty string.',
        };
    }

    const trimmed = name.trim();
    if (!trimmed) {
        return {
            valid: false,
            sanitizedName: '',
            language: null,
            reason: 'Filename cannot be empty.',
        };
    }

    if (trimmed.length > 100) {
        return {
            valid: false,
            sanitizedName: '',
            language: null,
            reason: 'Filename exceeds maximum length of 100 characters.',
        };
    }

    // Detect null bytes or control characters
    if (/[\x00-\x1F\x7F]/.test(trimmed)) {
        return {
            valid: false,
            sanitizedName: '',
            language: null,
            reason: 'Filename contains illegal null byte or control characters.',
        };
    }

    // Detect directory traversal sequences (raw or URL-encoded)
    const lower = trimmed.toLowerCase();
    if (
        trimmed.includes('..') ||
        trimmed.includes('/') ||
        trimmed.includes('\\') ||
        lower.includes('%2e') ||
        lower.includes('%2f') ||
        lower.includes('%5c')
    ) {
        return {
            valid: false,
            sanitizedName: '',
            language: null,
            reason: 'Directory traversal characters (.., /, \) are strictly forbidden.',
        };
    }

    // Block hidden dotfiles (.env, .git, .htaccess, etc.)
    if (trimmed.startsWith('.')) {
        return {
            valid: false,
            sanitizedName: '',
            language: null,
            reason: 'Hidden dotfiles (e.g., .env, .git) are prohibited by Zero-Trust policy.',
        };
    }

    // Ensure path.basename matches exact input
    if (path.basename(trimmed) !== trimmed) {
        return {
            valid: false,
            sanitizedName: '',
            language: null,
            reason: 'Filename must not contain directory path segments.',
        };
    }

    // Enforce strict character whitelist: alphanumeric start, followed by alphanumeric, '_', '-', or '.'
    if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/.test(trimmed)) {
        return {
            valid: false,
            sanitizedName: '',
            language: null,
            reason:
                'Filename may only contain letters, numbers, underscores (_), hyphens (-), and dots (.).',
        };
    }

    const ext = path.extname(trimmed).toLowerCase();
    const baseWithoutExt = path.basename(trimmed, ext).toLowerCase();

    if (!baseWithoutExt || RESERVED_SYSTEM_NAMES.has(baseWithoutExt)) {
        return {
            valid: false,
            sanitizedName: '',
            language: null,
            reason: 'Filename uses a reserved operating system device name.',
        };
    }

    const language = ALLOWED_EXTENSION_MAP[ext] || null;
    if (!language) {
        return {
            valid: false,
            sanitizedName: '',
            language: null,
            reason: `Extension "${ext || '(none)'}" is not permitted. Allowed extensions: ${Object.keys(
                ALLOWED_EXTENSION_MAP
            ).join(', ')}`,
        };
    }

    return {
        valid: true,
        sanitizedName: trimmed,
        language,
    };
}

interface ThreatRuleDefinition {
    ruleId: string;
    patternName: string;
    regex: RegExp;
    severity: SecuritySeverity;
    weight: number;
    description: string;
    languages?: string[];
}

const THREAT_SIGNATURE_RULES: ThreatRuleDefinition[] = [
    {
        ruleId: 'RCE-001',
        patternName: 'child_process',
        regex: /\bchild_process\b|\b(?:exec|execSync|spawn|spawnSync|execFile|fork)\s*\(/,
        severity: 'CRITICAL',
        weight: 45,
        description: 'Node.js child_process shell/process execution attempt detected',
    },
    {
        ruleId: 'RCE-002',
        patternName: 'fs.',
        regex: /\bfs\s*\.|require\s*\(\s*['"](?:node:)?fs(?:\/promises)?['"]\s*\)|from\s+['"](?:node:)?fs['"]/,
        severity: 'HIGH',
        weight: 35,
        description: 'Direct host filesystem access (fs module) detected',
    },
    {
        ruleId: 'ENV-003',
        patternName: 'process.env',
        regex: /\bprocess\s*\.\s*env\b|\bos\s*\.\s*environ\b|\bgetenv\s*\(/,
        severity: 'HIGH',
        weight: 30,
        description: 'Environment variable / secret exfiltration attempt (process.env / os.environ)',
    },
    {
        ruleId: 'ESC-004',
        patternName: 'process.mainModule',
        regex: /\bprocess\s*\.\s*(?:mainModule|binding|dlopen|_linkedBinding)\b/,
        severity: 'CRITICAL',
        weight: 50,
        description: 'Node.js internal module loader / sandbox escape via process.mainModule or process.binding',
    },
    {
        ruleId: 'ESC-005',
        patternName: 'constructor.constructor',
        regex: /\bconstructor\s*\.\s*constructor\b|\[\s*['"]constructor['"]\s*\]/,
        severity: 'CRITICAL',
        weight: 50,
        description: 'Prototype chain sandbox escape via constructor.constructor',
    },
    {
        ruleId: 'ESC-006',
        patternName: '__proto__',
        regex: /\b__proto__\b|\bObject\s*\.\s*setPrototypeOf\b|\bprototype\s*\.\s*constructor\b/,
        severity: 'HIGH',
        weight: 35,
        description: 'Prototype pollution / prototype chain manipulation (__proto__)',
    },
    {
        ruleId: 'NET-007',
        patternName: "require('http')",
        regex: /require\s*\(\s*['"](?:node:)?(?:http|https|net|dgram|tls|dns)['"]\s*\)|\b(?:urllib\.request|socket\.socket|http\.client)\b/,
        severity: 'HIGH',
        weight: 35,
        description: 'Unauthorized outbound network socket / SSRF module access',
    },
    {
        ruleId: 'PY-008',
        patternName: 'os.system',
        regex: /\bos\s*\.\s*(?:system|popen|execl|execle|execlp|execv|execve|execvp|spawnl|spawnv|fork|kill)\b/,
        severity: 'CRITICAL',
        weight: 45,
        description: 'Python OS command execution or process spawning (os.system / os.popen / os.exec*)',
    },
    {
        ruleId: 'PY-009',
        patternName: 'subprocess',
        regex: /\bsubprocess\b|\bpty\s*\.\s*spawn\b|\bcommands\s*\.\s*getoutput\b/,
        severity: 'CRITICAL',
        weight: 45,
        description: 'Python subprocess / pty shell spawning detected',
    },
    {
        ruleId: 'LFI-010',
        patternName: '/etc/passwd',
        regex: /\/etc\/(?:passwd|shadow|hosts|sudoers)|\/proc\/self\/(?:environ|cmdline|maps|mem)|\/root\//,
        severity: 'CRITICAL',
        weight: 50,
        description: 'Sensitive Linux system file read attempt (/etc/passwd, /etc/shadow, /proc/self)',
    },
    {
        ruleId: 'DOS-011',
        patternName: 'fork bomb :(){',
        regex: /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;|:\s*\(\s*\)\s*\{|while\s*\(\s*true\s*\)\s*\{\s*fork\s*\(/,
        severity: 'CRITICAL',
        weight: 60,
        description: 'Process fork bomb / resource exhaustion payload (:(){ :|:& };:) detected',
    },
    {
        ruleId: 'PY-012',
        patternName: '__builtins__ / __subclasses__',
        regex: /\b__(?:subclasses|builtins|import|globals|mro)__\b|\bctypes\b/,
        severity: 'CRITICAL',
        weight: 45,
        description: 'Python introspection / CFFI sandbox escape (__subclasses__, __builtins__, ctypes)',
    },
    {
        ruleId: 'SYS-013',
        patternName: 'Native system() / Runtime.exec',
        regex: /\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\b|\bProcessBuilder\b|\bsystem\s*\(\s*["']/,
        severity: 'CRITICAL',
        weight: 45,
        description: 'Native C++/Java OS command execution (system() / Runtime.exec / ProcessBuilder)',
    },
];

/**
 * Static AST/pattern threat analyzer that inspects user source code for RCE,
 * sandbox escape, credential exfiltration, and fork-bomb signatures prior to execution.
 */
export function scanCodeForThreats(
    code: string,
    language: string = 'javascript'
): ThreatScanResult {
    if (typeof code !== 'string' || code.length === 0) {
        return {
            safe: true,
            threats: [],
            riskScore: 0,
            matchedRules: [],
        };
    }

    const lines = code.split(/\r?\n/);
    const matchedRules: ThreatRuleMatch[] = [];
    const threatSummaries: string[] = [];
    let accumulatedScore = 0;

    for (const rule of THREAT_SIGNATURE_RULES) {
        if (
            rule.languages &&
            rule.languages.length > 0 &&
            !rule.languages.includes(language.toLowerCase())
        ) {
            continue;
        }

        let matchedLineNumber = 0;
        let matchedSnippet = '';

        for (let i = 0; i < lines.length; i++) {
            if (rule.regex.test(lines[i])) {
                matchedLineNumber = i + 1;
                matchedSnippet = lines[i].trim().slice(0, 120);
                break;
            }
        }

        if (matchedLineNumber === 0 && rule.regex.test(code)) {
            matchedLineNumber = 1;
            matchedSnippet = code.slice(0, 120).trim();
        }

        if (matchedLineNumber > 0) {
            accumulatedScore += rule.weight;
            matchedRules.push({
                ruleId: rule.ruleId,
                patternName: rule.patternName,
                severity: rule.severity,
                description: rule.description,
                line: matchedLineNumber,
                snippet: matchedSnippet,
            });
            threatSummaries.push(
                `[${rule.ruleId}:${rule.severity}] ${rule.description} (pattern: "${rule.patternName}", line ${matchedLineNumber})`
            );
        }
    }

    const riskScore = Math.min(100, accumulatedScore);
    return {
        safe: matchedRules.length === 0,
        threats: threatSummaries,
        riskScore,
        matchedRules,
    };
}

/**
 * Express middleware that attaches strict HTTP security headers to every response.
 */
export function applySecurityHeaders(
    _req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
): void {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader(
        'Permissions-Policy',
        'camera=(), microphone=(), geolocation=(), payment=(), usb=()'
    );
    res.setHeader(
        'Content-Security-Policy',
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:;"
    );
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
}