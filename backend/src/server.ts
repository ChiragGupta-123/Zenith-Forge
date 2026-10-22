import http from 'http';
import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { Server as SocketIOServer } from 'socket.io';
import projectsRouter from './routes/projects';
import filesRouter from './routes/files';
import executeRouter from './routes/execute';
import {
    flushAllCrdtDocsToSqlite,
    getCrdtTelemetry,
    initializeCrdtSocketServer,
} from './socket/crdtServer';
import { createRateLimiter, extractClientIp } from './security/securityMiddleware';
import { DEMO_INVITE_CODE, DEMO_PROJECT_ID, logSecurityEvent } from './db';
import { AuthenticatedRequest } from './types';

dotenv.config();

const PORT = Number(process.env.PORT) || 4000;
const ALLOWED_ORIGINS = (
    process.env.CORS_ORIGINS ||
    'http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000,http://127.0.0.1:3000,http://localhost:4173'
)
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);

export const app = express();
export const httpServer = http.createServer(app);

app.disable('x-powered-by');
app.use((_req: Request, res: Response, next: NextFunction): void => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader(
        'Content-Security-Policy',
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self' http://localhost:* http://127.0.0.1:* ws://localhost:* ws://127.0.0.1:* wss://localhost:*; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    );
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader(
        'Permissions-Policy',
        'camera=(), microphone=(), geolocation=(), payment=(), usb=()'
    );
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
});

app.use(
    cors({
        origin: (origin, callback) => {
            if (!origin || ALLOWED_ORIGINS.includes(origin)) {
                callback(null, true);
                return;
            }
            callback(new Error(`Origin ${origin} blocked by Zero-Trust CORS policy`));
        },
        methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization', 'X-Auth-Token'],
        exposedHeaders: [
            'X-RateLimit-Limit',
            'X-RateLimit-Remaining',
            'X-RateLimit-Reset',
            'Retry-After',
        ],
        credentials: true,
    })
);

app.use(express.json({ limit: '100kb', strict: true }));
app.use(express.urlencoded({ extended: false, limit: '100kb' }));

app.use('/api', createRateLimiter(240, 60_000, 'api-global'));

app.get('/api/health', (_req: Request, res: Response): void => {
    res.status(200).json({
        status: 'ok',
        service: 'devcollab-zero-trust-backend',
        uptimeSeconds: Math.floor(process.uptime()),
        demoProjectId: DEMO_PROJECT_ID,
        demoInviteCode: DEMO_INVITE_CODE,
        securityControls: {
            jwtAlgorithm: 'HMAC-SHA256 (native crypto.timingSafeEqual)',
            sqliteMode: 'WAL + 100% Prepared Statements',
            jsonPayloadLimit: '100kb',
            wsMaxHttpBufferSize: 65536,
            crdtMaxDeltaBytes: 32768,
            headers: [
                'X-Content-Type-Options: nosniff',
                'X-Frame-Options: DENY',
                'Referrer-Policy: no-referrer',
                'Content-Security-Policy',
            ],
        },
        crdtTelemetry: getCrdtTelemetry(),
        timestamp: new Date().toISOString(),
    });
});

app.use('/api/projects', projectsRouter);
app.use('/api/files', filesRouter);
app.use('/api/execute', executeRouter);

export const io = new SocketIOServer(httpServer, {
    cors: {
        origin: ALLOWED_ORIGINS,
        methods: ['GET', 'POST'],
        credentials: true,
    },
    maxHttpBufferSize: 65536,
    pingTimeout: 20_000,
    pingInterval: 25_000,
    transports: ['websocket', 'polling'],
});

app.set('io', io);

initializeCrdtSocketServer(io);

app.use(
    (
        err: Error & { status?: number; type?: string; body?: unknown },
        req: AuthenticatedRequest,
        res: Response,
        _next: NextFunction
    ): void => {
        const clientIp = extractClientIp(req);

        if (err.type === 'entity.too.large' || err.status === 413) {
            logSecurityEvent({
                projectId: null,
                userId: req.user?.userId || null,
                username: req.user?.username || 'anonymous',
                eventType: 'RATE_LIMIT_EXCEEDED',
                severity: 'HIGH',
                details: `Blocked oversized HTTP JSON payload (>100kb) on ${req.method} ${req.originalUrl}`,
                ipAddress: clientIp,
                blocked: true,
            });
            res.status(413).json({
                error: 'Payload Too Large',
                code: 'JSON_LIMIT_EXCEEDED',
                message: 'Request body exceeds the 100KB security limit.',
            });
            return;
        }

        if (err instanceof SyntaxError && 'body' in err) {
            res.status(400).json({
                error: 'Malformed JSON',
                code: 'INVALID_JSON_PAYLOAD',
                message: 'Request body contains invalid JSON syntax.',
            });
            return;
        }

        res.status(err.status || 500).json({
            error: 'Internal Server Error',
            message: err.message || 'An unexpected error occurred.',
        });
    }
);

if (require.main === module) {
    httpServer.listen(PORT, () => {
        console.log(
            `[DevCollab Zero-Trust Server] Listening on http://localhost:${PORT} (WS maxHttpBufferSize=65536, JSON limit=100kb)`
        );
    });
}

function handleGracefulShutdown(signal: string): void {
    console.log(`[DevCollab] Received ${signal}. Flushing Yjs CRDT state to SQLite...`);
    flushAllCrdtDocsToSqlite();
    io.close(() => {
        httpServer.close(() => {
            process.exit(0);
        });
    });
}

process.on('SIGINT', () => handleGracefulShutdown('SIGINT'));
process.on('SIGTERM', () => handleGracefulShutdown('SIGTERM'));