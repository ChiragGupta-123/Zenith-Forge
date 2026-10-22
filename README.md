# DevCollab — Zero-Trust, Real-Time Collaborative Coding Platform

> **Obsidian Studio IDE** — A real-time multiplayer code editor featuring Yjs CRDT synchronization, role-based access control (RBAC), multi-layered execution defense, live AST threat telemetry, and an offline deterministic security co-pilot.

---

## 1. Architecture Overview

DevCollab is engineered as a decoupled, zero-trust collaborative development environment:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        DEVCOLLAB OBSIDIAN STUDIO                       │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
           ┌────────────────────────┴────────────────────────┐
           ▼                                                 ▼
┌──────────────────────┐                          ┌──────────────────────┐
│  FRONTEND (React 18) │                          │  BACKEND (Node 22+)  │
│  - Monaco Code Editor│                          │  - Express REST API  │
│  - Yjs Local Replica │ ── JWT Handshake (WS) ──▶│  - Socket.IO Server  │
│  - Remote Carets/Pills│◀── Yjs Binary Deltas ───│  - SQLite (WAL Mode) │
│  - Telemetry Bar     │                          │  - RBAC Guard        │
│  - Execution Console │                          │  - Static AST Linter │
└──────────────────────┘                          └──────────┬───────────┘
                                                             │
                              ┌──────────────────────────────┼──────────────────────────────┐
                              ▼                              ▼                              ▼
                 ┌──────────────────────────┐   ┌──────────────────────────┐   ┌──────────────────────────┐
                 │ LAYER 2: AST SCANNER     │   │ LAYER 3: PISTON RUNNER   │   │ LAYER 4: WORKER VM       │
                 │ Static signature analysis│   │ Isolated Container API   │   │ Hardened V8 Context      │
                 │ Blocks RCE & Traversal   │   │ 3s timeout / 128MB RAM   │   │ 2.5s / 64MB heap ceiling │
                 └──────────────────────────┘   └──────────────────────────┘   └──────────────────────────┘
```

### Key Technical Pillars

1. **Conflict-Free Real-Time Collaboration (CRDTs)**:
   - Uses `Yjs` shared documents (`Y.Doc` and `Y.Text('monaco')`).
   - Monaco change events are mapped to character offsets and emitted as binary `Uint8Array` deltas over Socket.IO.
   - Remote updates are received, applied via `Y.applyUpdate`, and pushed directly into Monaco models while preserving user selection and caret stability.

2. **Zero-Trust Identity & RBAC Enforcement**:
   - Zero-dependency HMAC-SHA256 JSON Web Tokens (JWT) using Node's native `crypto` module (`crypto.timingSafeEqual` against timing side-channels).
   - Strict role hierarchy: `OWNER` (full administrative control, locking, invite rotation), `EDITOR` (read/write access), `VIEWER` (read-only audit role).
   - Every WebSocket CRDT frame (`yjs-update`) and REST mutation queries SQLite for the caller's live role and rejects unauthorized modifications.

3. **Multi-Layered Execution Defense**:
   - **Layer 1**: Server-Side SQLite RBAC (`VIEWER` cannot execute code or mutate state).
   - **Layer 2**: Static AST/Pattern Threat Scanner (`scanCodeForThreats`) blocking dangerous signatures (`child_process`, `fs`, `eval`, `constructor.constructor`, `process.env`, `os.system`, `/etc/passwd`).
   - **Layer 3**: Remote isolated container execution via Piston (configurable timeout and 128MB memory ceiling).
   - **Layer 4**: Hardened Worker VM Fallback (`vm.createContext` with `codeGeneration: strings/wasm` disabled, isolated V8 Worker heap, frozen safe console). Fails closed for non-JS/TS when remote runner is offline.

4. **Security Telemetry & Red-Team Attack Simulator**:
   - Live audit logging into SQLite `security_logs`.
   - Built-in Red-Team attack probes exercising actual backend defenses (`rce`, `traversal`, `rbac`).

5. **AI Co-Pilot with Deterministic Zero-Key Fallback**:
   - Supported actions: `explain`, `debug`, `security-audit`, `tests`.
   - Calls Google Gemini 2.5 Flash if `GEMINI_API_KEY` is provided; seamlessly falls back to the deterministic heuristic AST analyzer without any API key.

---

## 2. Prerequisites & Local Environment

- **Operating System**: Windows 10/11 (PowerShell), macOS, or Linux.
- **Node.js**: Node.js **>= 20.0.0** (Node.js 22.x or 24.x recommended).
- **Package Manager**: `npm` (v10+).
- **No external services required**: Does **not** require Docker or Redis to run locally.

---

## 3. Installation & Setup

### Step 1: Install Backend Dependencies

Open PowerShell and navigate to the project root:

```powershell
cd backend
npm install
npm run build
```

### Step 2: Install Frontend Dependencies

In a second PowerShell terminal:

```powershell
cd frontend
npm install
npm run build
```

---

## 4. Environment Variables

### Backend Configuration (`backend/.env`)

Copy `backend/.env.example` to `backend/.env`:

```env
PORT=4000
JWT_SECRET=devcollab-zero-trust-hmac-sha256-master-key-2026-quantum-shield
CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173
DEVCOLLAB_DB_PATH=./devcollab.sqlite
PISTON_URL=https://emkc.org/api/v2/piston/execute
GEMINI_API_KEY=
```

### Frontend Configuration (`frontend/.env`)

Copy `frontend/.env.example` to `frontend/.env`:

```env
VITE_API_URL=http://localhost:4000/api
VITE_SOCKET_URL=http://localhost:4000
```

---

## 5. Running the Application

### Terminal 1: Backend Service

```powershell
cd backend
npm start
```
*Backend runs on `http://localhost:4000` with WebSocket endpoint `ws://localhost:4000`.*

### Terminal 2: Frontend Studio

```powershell
cd frontend
npm run dev
```
*Frontend runs on `http://localhost:5173`.*

Open your browser at **`http://localhost:5173`**.

---

## 6. Verification & Automated Testing

A comprehensive automated integration and security test suite is included in `backend/test_integration.js`.

Run the test suite via PowerShell:

```powershell
cd backend
npm test
```

### Test Coverage Matrix (14 / 14 Verified Checks)

| Test Item | Verification Target | Status |
| :--- | :--- | :---: |
| 1. Database Schema & Seed | SQLite WAL initialization, foreign keys, demo project & starter files | **PASS** |
| 2. HMAC-SHA256 JWT Security | Native crypto sign/verify, tampered token rejection, `alg:none` spoof rejection | **PASS** |
| 3. Traversal Defense | `validateSafeFilename` blocks `../../.env`, null bytes, and dotfiles | **PASS** |
| 4. Static AST Threat Scanner | `scanCodeForThreats` flags RCE, `process.env`, prototype chain exploits | **PASS** |
| 5. GET /api/health | Uptime, zero-trust security configuration, and active CRDT telemetry | **PASS** |
| 6. Multi-Persona Sessions | Dynamic issuance for `aria_sec_lead` (OWNER), `liam_core_dev` (EDITOR), `maya_auditor` (VIEWER) | **PASS** |
| 7. REST RBAC Mutation Guard | VIEWER write attempts return HTTP 403; EDITOR write attempts succeed | **PASS** |
| 8. Snapshot SHA-256 Hash | Creation and content-integrity verification against stored cryptographic hash | **PASS** |
| 9. Red-Team Attack Simulator | Controlled simulation of `rce`, `traversal`, and `rbac` probes recorded in SQLite | **PASS** |
| 10. Execution Sandbox | Hardened Worker VM executes safe JS/TS; blocks hostile execution with 403 | **PASS** |
| 11. Zero-Key AI Co-Pilot | Offline deterministic heuristic engine generates explanations and security findings | **PASS** |
| 12. Socket.IO Handshake Guard | Rejects unauthenticated connections and invalid JWT signatures | **PASS** |
| 13. Two-Client CRDT Merge | Independent Socket.IO clients apply concurrent edits; both replicas converge identically | **PASS** |
| 14. Socket.IO VIEWER Denial | Real-time `yjs-update` write from VIEWER blocked and security alert broadcast | **PASS** |

---

## 7. Interactive Collaboration & Hackathon Demo Guide

### Testing Concurrent Editing with 2 Browser Windows

1. Open Window 1: Navigate to `http://localhost:5173`. Select persona **`aria_sec_lead (OWNER)`**.
2. Open Window 2 (Incognito / Private Window): Navigate to `http://localhost:5173`. Select persona **`liam_core_dev (EDITOR)`**.
3. Open `algorithm.js` in both windows.
4. Move your cursor in Window 1: Observe the live colored cursor pill (`@aria_sec_lead • OWNER`) rendering in real-time in Window 2.
5. Type simultaneously in both windows: Changes synchronize seamlessly through Yjs CRDT binary deltas without overwriting or selection jumps.

### Testing VIEWER Role Enforcement

1. Open Window 3: Navigate to `http://localhost:5173` and select **`maya_auditor (VIEWER)`**.
2. Observe the purple **`READ-ONLY (VIEWER)`** badge. Monaco editor is set to read-only.
3. If an unauthorized client attempts to dispatch synthetic CRDT write packets via WebSocket or REST, the backend intercepts the request, rejects it with `403 Forbidden`, records an audit event, and broadcasts a high-severity security alert.

### Testing the 3-Peer CRDT Conflict Burst

1. In the bottom telemetry bar, click **`CRDT Conflict Burst`**.
2. DevCollab spins up 3 independent client replicas (`peerA`, `peerB`, `peerC`), simulates concurrent modifications at the same offsets, merges state vectors with `Y.mergeUpdates`, and converges cleanly in the Monaco editor.

### Testing the Red-Team Attack Simulator

1. In the bottom telemetry bar, click **`Red-Team: Test Defenses`**.
2. Select any attack vector:
   - **Malicious RCE Payload**: Tests Layer 2 AST threat detection.
   - **Path Traversal (`../../.env`)**: Tests filename traversal guards.
   - **VIEWER RBAC Bypass**: Tests server-side role validation.
3. Observe the immediate rejection, detailed threat mitigation breakdown, and real-time security alert toast.

---

## 8. Security Boundaries & Known Limitations

- **Sandboxed Execution Boundary**: Node.js `vm` is **not** a secure operating-system level sandbox for arbitrary adversarial native code. While DevCollab implements a hardened 4-layer defense (RBAC + static AST pattern scanner + `codeGeneration: strings/wasm` disabled + isolated V8 Worker with 64MB heap ceiling), running truly untrusted arbitrary code in production requires an isolated container sandbox (such as Piston or Firecracker microVMs).
- **Static Heuristic Scanner**: The threat scanner inspects known dangerous signatures and patterns. Static analysis is a heuristic defense and cannot guarantee detection of all obfuscated or novel zero-day attack vectors.
- **Offline Code Execution**: In offline mode (when Piston is unreachable), code execution is supported for JavaScript and TypeScript via the hardened local worker VM. Python, C++, and Java fail closed and report that container isolation is required.

---

## 9. License

MIT License. Designed and built for the DevCollab Hackathon
