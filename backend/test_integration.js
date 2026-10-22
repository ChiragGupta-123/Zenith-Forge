const http = require('http');
const crypto = require('crypto');
const { io: ioClient } = require('socket.io-client');
const Y = require('yjs');
const { db, DEMO_PROJECT_ID, DEMO_INVITE_CODE, computeSha256Hash } = require('./dist/db');
const { signToken, verifyToken, validateSafeFilename, scanCodeForThreats } = require('./dist/security/securityMiddleware');
const { app, httpServer, io } = require('./dist/server');

const PORT = 4099;

async function runTests() {
    console.log('====================================================');
    console.log('DEVCOLLAB COMPREHENSIVE INTEGRATION & SECURITY SUITE');
    console.log('====================================================\n');

    const results = [];
    function record(name, pass, detail) {
        results.push({ name, pass, detail });
        console.log(`[${pass ? 'PASS' : 'FAIL'}] ${name}: ${detail}`);
    }

    // 1. Database & Schema Verification
    try {
        const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").all();
        const tableNames = tables.map(t => t.name);
        const required = ['comments', 'files', 'project_members', 'projects', 'security_logs', 'snapshots', 'users'];
        const allPresent = required.every(r => tableNames.includes(r));
        const demoProj = db.prepare("SELECT * FROM projects WHERE id = ?").get(DEMO_PROJECT_ID);
        const demoFiles = db.prepare("SELECT name FROM files WHERE project_id = ?").all(DEMO_PROJECT_ID);
        record('Database Schema & Seed', allPresent && !!demoProj && demoFiles.length >= 3,
            `Tables found: [${tableNames.join(', ')}]. Demo project: ${demoProj?.name}. Files: ${demoFiles.map(f => f.name).join(', ')}`);
    } catch (err) {
        record('Database Schema & Seed', false, err.message);
    }

    // 2. Authentication & HMAC-SHA256 JWT Verification
    try {
        const ownerToken = signToken({ userId: 'usr-aria', username: 'aria_sec_lead', displayName: 'Aria', avatarColor: '#10b981' });
        const verified = verifyToken(ownerToken);
        const tampered = ownerToken.slice(0, -5) + 'xxxxx';
        const tamperedVerified = verifyToken(tampered);
        const noneAlgToken = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url') + '.' +
                             Buffer.from(JSON.stringify({ userId: 'hacker', username: 'hacker', exp: Math.floor(Date.now() / 1000) + 3600 })).toString('base64url') + '.';
        const noneVerified = verifyToken(noneAlgToken);
        record('HMAC-SHA256 JWT Security',
            verified?.username === 'aria_sec_lead' && tamperedVerified === null && noneVerified === null,
            'Verified valid token, rejected tampered signature, rejected alg:none spoof');
    } catch (err) {
        record('HMAC-SHA256 JWT Security', false, err.message);
    }

    // 3. Filename Validation & Directory Traversal Rejection
    try {
        const t1 = validateSafeFilename('../../.env');
        const t2 = validateSafeFilename('..\\..\\windows\\system32\\calc.exe');
        const t3 = validateSafeFilename('test\x00.js');
        const t4 = validateSafeFilename('.git');
        const t5 = validateSafeFilename('valid_router.py');
        record('Zero-Trust Filename Traversal Defense',
            !t1.valid && !t2.valid && !t3.valid && !t4.valid && t5.valid,
            `Rejected traversal (../../.env: ${t1.reason}), null bytes, dotfiles; allowed valid_router.py`);
    } catch (err) {
        record('Zero-Trust Filename Traversal Defense', false, err.message);
    }

    // 4. Pre-Execution Static AST Threat Scanner
    try {
        const rceMalicious = "const { execSync } = require('child_process'); execSync('whoami');";
        const envExfil = "const secret = process.env.JWT_SECRET;";
        const protoEscape = "this.constructor.constructor('return process')();";
        const safeCode = "console.log('Calculating quantum hash:', 42);";

        const scan1 = scanCodeForThreats(rceMalicious, 'javascript');
        const scan2 = scanCodeForThreats(envExfil, 'javascript');
        const scan3 = scanCodeForThreats(protoEscape, 'javascript');
        const scanSafe = scanCodeForThreats(safeCode, 'javascript');

        record('Pre-Execution Static Threat Scan',
            !scan1.safe && !scan2.safe && !scan3.safe && scanSafe.safe && scanSafe.threats.length === 0,
            `RCE score: ${scan1.riskScore}/100, ENV score: ${scan2.riskScore}/100, Proto score: ${scan3.riskScore}/100, Safe: clean`);
    } catch (err) {
        record('Pre-Execution Static Threat Scan', false, err.message);
    }

    // Start HTTP Server on test port
    await new Promise((resolve) => {
        httpServer.listen(PORT, () => {
            console.log(`\nTest server listening on http://localhost:${PORT}`);
            resolve();
        });
    });

    // Helper for HTTP requests
    async function apiRequest(method, path, body = null, token = null) {
        return new Promise((resolve, reject) => {
            const url = new URL(`http://localhost:${PORT}${path}`);
            const headers = { 'Content-Type': 'application/json' };
            if (token) headers['Authorization'] = `Bearer ${token}`;

            const req = http.request(url, { method, headers }, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    let json = null;
                    try { json = JSON.parse(data); } catch { json = data; }
                    resolve({ status: res.statusCode, headers: res.headers, data: json });
                });
            });
            req.on('error', reject);
            if (body) req.write(JSON.stringify(body));
            req.end();
        });
    }

    // 5. Health Check Endpoint
    try {
        const health = await apiRequest('GET', '/api/health');
        record('GET /api/health Endpoint', health.status === 200 && health.data?.status === 'ok',
            `Status: ${health.data?.status}, Service: ${health.data?.service}`);
    } catch (err) {
        record('GET /api/health Endpoint', false, err.message);
    }

    // 6. Session Generation for Multiple Personas (OWNER, EDITOR, VIEWER)
    let ownerSession, editorSession, viewerSession;
    try {
        const s1 = await apiRequest('POST', '/api/projects/session', { username: 'aria_sec_lead', displayName: 'Aria', preferredRole: 'OWNER' });
        const s2 = await apiRequest('POST', '/api/projects/session', { username: 'liam_core_dev', displayName: 'Liam', preferredRole: 'EDITOR' });
        const s3 = await apiRequest('POST', '/api/projects/session', { username: 'maya_auditor', displayName: 'Maya', preferredRole: 'VIEWER' });

        ownerSession = s1.data;
        editorSession = s2.data;
        viewerSession = s3.data;

        record('Multi-Persona Session & RBAC Enrollment',
            s1.status === 200 && s2.status === 200 && s3.status === 200 &&
            ownerSession.preferredRole === 'OWNER' && editorSession.preferredRole === 'EDITOR' && viewerSession.preferredRole === 'VIEWER',
            `Created OWNER (@${ownerSession.user.username}), EDITOR (@${editorSession.user.username}), VIEWER (@${viewerSession.user.username})`);
    } catch (err) {
        record('Multi-Persona Session & RBAC Enrollment', false, err.message);
    }

    // 7. REST RBAC Enforcement: VIEWER Write Denial
    let demoFiles;
    try {
        const filesRes = await apiRequest('GET', `/api/files/project/${DEMO_PROJECT_ID}`, null, ownerSession.token);
        demoFiles = filesRes.data?.files || [];
        const targetFile = demoFiles[0];

        // VIEWER attempts to modify file
        const viewerPut = await apiRequest('PUT', `/api/files/${targetFile.id}`, { content: '// Hacked by VIEWER' }, viewerSession.token);
        // EDITOR modifies file
        const editorPut = await apiRequest('PUT', `/api/files/${targetFile.id}`, { content: targetFile.content + '\n# Verified by Liam' }, editorSession.token);

        record('REST RBAC File Mutation Guard',
            viewerPut.status === 403 && (editorPut.status === 200 || editorPut.status === 204),
            `VIEWER write rejected with HTTP ${viewerPut.status} (${viewerPut.data?.error || viewerPut.data?.code}). EDITOR write accepted (${editorPut.status}).`);
    } catch (err) {
        record('REST RBAC File Mutation Guard', false, err.message);
    }

    // 8. Version Snapshots & Content Hash Integrity
    try {
        const targetFile = demoFiles[0];
        const snapshotRes = await apiRequest('POST', `/api/files/${targetFile.id}/snapshots`, {
            label: 'v1.1 — Security Test Baseline',
            content: targetFile.content
        }, ownerSession.token);

        const expectedHash = computeSha256Hash(targetFile.content);
        const actualHash = snapshotRes.data?.snapshot?.hash;

        record('Snapshot SHA-256 Content Integrity',
            snapshotRes.status === 201 && actualHash === expectedHash,
            `Snapshot created: id=${snapshotRes.data?.snapshot?.id}, SHA-256=${actualHash?.slice(0, 16)}... (matches computeSha256Hash)`);
    } catch (err) {
        record('Version Snapshots & Content Hash Integrity', false, err.message);
    }

    // 9. Red-Team Simulator Backend Paths
    try {
        const rceAttack = await apiRequest('POST', '/api/execute/red-team', { projectId: DEMO_PROJECT_ID, attackType: 'rce' }, ownerSession.token);
        const travAttack = await apiRequest('POST', '/api/execute/red-team', { projectId: DEMO_PROJECT_ID, attackType: 'traversal' }, ownerSession.token);
        const rbacAttack = await apiRequest('POST', '/api/execute/red-team', { projectId: DEMO_PROJECT_ID, attackType: 'rbac' }, ownerSession.token);

        const logsRes = await apiRequest('GET', `/api/execute/security-logs/${DEMO_PROJECT_ID}`, null, ownerSession.token);
        const logs = logsRes.data?.logs || [];

        record('Red-Team Attack Simulator (RCE, Traversal, RBAC)',
            rceAttack.status === 200 && rceAttack.data?.blocked === true &&
            travAttack.status === 200 && travAttack.data?.blocked === true &&
            rbacAttack.status === 200 && rbacAttack.data?.blocked === true &&
            logs.length >= 3,
            `RCE blocked: ${rceAttack.data?.defenseLayer}. Traversal blocked: ${travAttack.data?.defenseLayer}. RBAC blocked: ${rbacAttack.data?.defenseLayer}. Audit logs count: ${logs.length}`);
    } catch (err) {
        record('Red-Team Attack Simulator (RCE, Traversal, RBAC)', false, err.message);
    }

    // 10. Code Execution & Offline Fallback Sandbox
    try {
        // Safe JavaScript code
        const safeExec = await apiRequest('POST', '/api/execute/run', {
            projectId: DEMO_PROJECT_ID,
            language: 'javascript',
            code: 'console.log("Quantum Engine Check: OK"); const x = 20 + 22; console.log("Result:", x);'
        }, ownerSession.token);

        // Hostile RCE attempt
        const hostileExec = await apiRequest('POST', '/api/execute/run', {
            projectId: DEMO_PROJECT_ID,
            language: 'javascript',
            code: 'require("child_process").execSync("whoami");'
        }, ownerSession.token);

        record('Execution Sandbox (Hardened Worker VM & RCE Defense)',
            (safeExec.status === 200 && safeExec.data?.stdout?.includes('Quantum Engine Check: OK')) &&
            hostileExec.status === 403 && hostileExec.data?.sandboxBlocked === true,
            `Safe execution output: "${safeExec.data?.stdout?.trim()}". Hostile code blocked with HTTP 403 (Risk Score ${hostileExec.data?.riskScore}/100)`);
    } catch (err) {
        record('Execution Sandbox (Hardened Worker VM & RCE Defense)', false, err.message);
    }

    // 11. Zero-Key Deterministic Offline AI Security Assistant
    try {
        const aiExplain = await apiRequest('POST', '/api/execute/ai-assist', {
            projectId: DEMO_PROJECT_ID,
            action: 'explain',
            language: 'javascript',
            code: 'function verifyPacket(buf) { return buf.length > 0; }'
        }, ownerSession.token);

        const aiAudit = await apiRequest('POST', '/api/execute/ai-assist', {
            projectId: DEMO_PROJECT_ID,
            action: 'security-audit',
            language: 'javascript',
            code: 'function evalInput(cmd) { return eval(cmd); }'
        }, ownerSession.token);

        record('Offline Deterministic AI Security Co-Pilot',
            aiExplain.status === 200 && aiExplain.data?.summary &&
            aiAudit.status === 200 && aiAudit.data?.overallRiskScore > 0,
            `Explain summary: "${aiExplain.data?.summary?.slice(0, 50)}...". Audit risk score: ${aiAudit.data?.overallRiskScore}/100. Provider: ${aiAudit.data?.provider}`);
    } catch (err) {
        record('Offline Deterministic AI Security Co-Pilot', false, err.message);
    }

    // 12. Socket.IO Handshake Authentication
    let unauthRejected = false;
    try {
        await new Promise((resolve) => {
            const badSocket = ioClient(`http://localhost:${PORT}`, {
                auth: { token: 'invalid.tampered.token' },
                transports: ['websocket'],
                reconnection: false
            });
            badSocket.on('connect_error', (err) => {
                unauthRejected = true;
                badSocket.disconnect();
                resolve();
            });
            badSocket.on('connect', () => {
                badSocket.disconnect();
                resolve();
            });
            setTimeout(() => { badSocket.disconnect(); resolve(); }, 1500);
        });
        record('Socket.IO JWT Handshake Guard', unauthRejected, 'Unauthenticated/tampered WebSocket connection rejected immediately during handshake');
    } catch (err) {
        record('Socket.IO JWT Handshake Guard', false, err.message);
    }

    // 13. Two Independent Collaborators: Real-Time Concurrent Yjs CRDT Synchronization
    try {
        const clientA = ioClient(`http://localhost:${PORT}`, {
            auth: { token: ownerSession.token },
            transports: ['websocket'],
            reconnection: false
        });
        const clientB = ioClient(`http://localhost:${PORT}`, {
            auth: { token: editorSession.token },
            transports: ['websocket'],
            reconnection: false
        });

        await Promise.all([
            new Promise(res => clientA.on('connect', res)),
            new Promise(res => clientB.on('connect', res)),
        ]);

        const targetFile = demoFiles[0];

        // Join project & file
        clientA.emit('join-project', { projectId: DEMO_PROJECT_ID });
        clientB.emit('join-project', { projectId: DEMO_PROJECT_ID });

        const [initA, initB] = await Promise.all([
            new Promise(res => clientA.emit('join-file', { projectId: DEMO_PROJECT_ID, fileId: targetFile.id }, res)),
            new Promise(res => clientB.emit('join-file', { projectId: DEMO_PROJECT_ID, fileId: targetFile.id }, res)),
        ]);

        // Create local Y.Docs for Client A and Client B
        const ydocA = new Y.Doc();
        const ydocB = new Y.Doc();

        if (initA.update) Y.applyUpdate(ydocA, Buffer.from(initA.update));
        if (initB.update) Y.applyUpdate(ydocB, Buffer.from(initB.update));

        let receivedByB = false;
        let receivedByA = false;

        clientB.on('yjs-update', (payload) => {
            if (payload.update) {
                Y.applyUpdate(ydocB, Buffer.from(payload.update));
                receivedByB = true;
            }
        });

        clientA.on('yjs-update', (payload) => {
            if (payload.update) {
                Y.applyUpdate(ydocA, Buffer.from(payload.update));
                receivedByA = true;
            }
        });

        // Client A makes an edit
        let deltaA = null;
        const subA = (u, origin) => { if (origin === 'local') deltaA = u; };
        ydocA.on('update', subA);
        ydocA.transact(() => {
            ydocA.getText('monaco').insert(0, '# [CONCURRENT EDIT A] ');
        }, 'local');
        ydocA.off('update', subA);

        clientA.emit('yjs-update', {
            projectId: DEMO_PROJECT_ID,
            fileId: targetFile.id,
            update: Array.from(deltaA)
        });

        // Client B simultaneously makes an edit at line end
        let deltaB = null;
        const subB = (u, origin) => { if (origin === 'local') deltaB = u; };
        ydocB.on('update', subB);
        ydocB.transact(() => {
            const t = ydocB.getText('monaco');
            t.insert(t.length, ' # [CONCURRENT EDIT B]');
        }, 'local');
        ydocB.off('update', subB);

        clientB.emit('yjs-update', {
            projectId: DEMO_PROJECT_ID,
            fileId: targetFile.id,
            update: Array.from(deltaB)
        });

        // Wait for cross-network synchronization
        await new Promise(r => setTimeout(r, 600));

        const finalA = ydocA.getText('monaco').toString();
        const finalB = ydocB.getText('monaco').toString();
        const converged = finalA === finalB && finalA.includes('[CONCURRENT EDIT A]') && finalA.includes('[CONCURRENT EDIT B]');

        record('Two-Client Concurrent Yjs CRDT Convergence', converged,
            `Client A text length: ${finalA.length}, Client B text length: ${finalB.length}. Converged identically: ${converged}`);

        clientA.disconnect();
        clientB.disconnect();
    } catch (err) {
        record('Two-Client Concurrent Yjs CRDT Convergence', false, err.message);
    }

    // 14. Socket.IO VIEWER CRDT Write Denial
    try {
        const clientViewer = ioClient(`http://localhost:${PORT}`, {
            auth: { token: viewerSession.token },
            transports: ['websocket'],
            reconnection: false
        });

        await new Promise(res => clientViewer.on('connect', res));
        const targetFile = demoFiles[0];

        let viewerBlockedAlert = false;
        clientViewer.on('security-alert', (alert) => {
            if (alert.eventType === 'UNAUTHORIZED_CRDT_WRITE_BLOCKED') {
                viewerBlockedAlert = true;
            }
        });

        const ack = await new Promise((resolve) => {
            clientViewer.emit('yjs-update', {
                projectId: DEMO_PROJECT_ID,
                fileId: targetFile.id,
                update: [1, 2, 3],
                content: 'VIEWER CRDT INJECTION'
            }, resolve);
            setTimeout(() => resolve({ ok: false, timeout: true }), 1000);
        });

        await new Promise(r => setTimeout(r, 300));
        record('Socket.IO VIEWER CRDT Write Rejection',
            ack?.ok === false && ack?.error === 'UNAUTHORIZED_CRDT_WRITE_BLOCKED' && viewerBlockedAlert,
            `Server responded: ok=${ack?.ok}, error=${ack?.error}. Security alert broadcast: ${viewerBlockedAlert}`);

        clientViewer.disconnect();
    } catch (err) {
        record('Socket.IO VIEWER CRDT Write Rejection', false, err.message);
    }

    // Close server
    await new Promise((resolve) => {
        io.close(() => {
            httpServer.close(() => {
                resolve();
            });
        });
    });

    console.log('\n====================================================');
    console.log(`TEST SUMMARY: ${results.filter(r => r.pass).length} / ${results.length} PASSED`);
    console.log('====================================================');

    process.exit(results.every(r => r.pass) ? 0 : 1);
}

runTests().catch(err => {
    console.error('Fatal test error:', err);
    process.exit(1);
});

