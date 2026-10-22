import React, { useState, useRef, useEffect } from 'react';
import {
    ShieldCheck,
    ShieldAlert,
    Activity,
    Cpu,
    Zap,
    Crosshair,
    ChevronUp,
    Lock,
    Wifi,
    WifiOff,
    Terminal,
    FileWarning,
    UserX,
} from 'lucide-react';
import {
    CollaboratorRole,
    RedTeamAttackType,
} from '../types';

interface TelemetryBarProps {
    wsConnected: boolean;
    jwtVerified: boolean;
    activeRole: CollaboratorRole;
    crdtOpsCount: number;
    yjsByteSize: number;
    blockedIntrusionsCount: number;
    simulatingAttack: boolean;
    onSimulateConflictBurst: () => void;
    onSimulateRedTeamAttack: (attackType: RedTeamAttackType) => Promise<void>;
    onOpenSecurityAuditTab?: () => void;
}

export const TelemetryBar: React.FC<TelemetryBarProps> = ({
    wsConnected,
    jwtVerified,
    activeRole,
    crdtOpsCount,
    yjsByteSize,
    blockedIntrusionsCount,
    simulatingAttack,
    onSimulateConflictBurst,
    onSimulateRedTeamAttack,
    onOpenSecurityAuditTab,
}) => {
    const [showAttackMenu, setShowAttackMenu] = useState<boolean>(false);
    const [bursting, setBursting] = useState<boolean>(false);
    const dropdownRef = useRef<HTMLDivElement | null>(null);

    useEffect(() => {
        const handleClickOutside = (e: MouseEvent) => {
            if (
                dropdownRef.current &&
                !dropdownRef.current.contains(e.target as Node)
            ) {
                setShowAttackMenu(false);
            }
        };
        document.addEventListener('mousedown', handleClickOutside);
        return () => document.removeEventListener('mousedown', handleClickOutside);
    }, []);

    const handleBurstClick = () => {
        setBursting(true);
        onSimulateConflictBurst();
        setTimeout(() => setBursting(false), 900);
    };

    const handleAttackOption = async (attackType: RedTeamAttackType) => {
        setShowAttackMenu(false);
        await onSimulateRedTeamAttack(attackType);
    };

    const formattedBytes =
        yjsByteSize >= 1024
            ? `${(yjsByteSize / 1024).toFixed(2)} KB`
            : `${yjsByteSize} B`;

    return (
        <footer className="h-9 shrink-0 bg-[#090D16] border-t border-slate-800/90 px-4 flex items-center justify-between text-[11px] font-mono select-none z-30">
            {/* Left Telemetry Indicators */}
            <div className="flex items-center gap-3 overflow-x-auto no-scrollbar">
                {/* WebSocket Connection Status */}
                <div className="flex items-center gap-1.5">
                    {wsConnected ? (
                        <>
                            <Wifi className="w-3.5 h-3.5 text-emerald-400" />
                            <span className="text-emerald-400 font-semibold">WS:LIVE</span>
                        </>
                    ) : (
                        <>
                            <WifiOff className="w-3.5 h-3.5 text-rose-400" />
                            <span className="text-rose-400 font-semibold">WS:OFFLINE</span>
                        </>
                    )}
                </div>

                <span className="text-slate-700">|</span>

                {/* JWT Auth Verified Badge */}
                <div
                    className={`flex items-center gap-1.5 px-2 py-0.5 rounded border ${jwtVerified
                            ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                            : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
                        }`}
                    title="Zero-dependency HMAC-SHA256 JWT verified via crypto.timingSafeEqual"
                >
                    <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                    <span>JWT Auth Verified (HS256)</span>
                </div>

                {/* Active Role Badge */}
                <div
                    className={`flex items-center gap-1.5 px-2 py-0.5 rounded border ${activeRole === 'OWNER'
                            ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-300'
                            : activeRole === 'EDITOR'
                                ? 'bg-cyan-500/15 border-cyan-500/40 text-cyan-300'
                                : 'bg-violet-500/15 border-violet-500/40 text-violet-300'
                        }`}
                >
                    <Lock className="w-3 h-3" />
                    <span>Role: {activeRole}</span>
                </div>

                <span className="text-slate-700 hidden sm:inline">|</span>

                {/* CRDT Sync Ops Counter */}
                <div
                    className="hidden sm:flex items-center gap-1.5 text-cyan-300"
                    title="Total Yjs CRDT state updates synchronized in real time"
                >
                    <Activity className="w-3.5 h-3.5 text-cyan-400" />
                    <span>CRDT Sync Ops:</span>
                    <strong className="text-white">{crdtOpsCount}</strong>
                </div>

                {/* Yjs Vector Byte Size */}
                <div
                    className="hidden md:flex items-center gap-1.5 text-slate-300"
                    title="Current Y.encodeStateAsUpdate(ydoc) binary vector size (32KB max cap)"
                >
                    <Cpu className="w-3.5 h-3.5 text-violet-400" />
                    <span>Yjs Vector:</span>
                    <strong className="text-violet-300">{formattedBytes}</strong>
                </div>

                {/* Blocked Intrusion Counter */}
                <button
                    type="button"
                    onClick={onOpenSecurityAuditTab}
                    className={`flex items-center gap-1.5 px-2 py-0.5 rounded border transition ${blockedIntrusionsCount > 0
                            ? 'bg-rose-500/15 border-rose-500/40 text-rose-300 hover:bg-rose-500/25'
                            : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'
                        }`}
                    title="Click to inspect blocked intrusions in the Security Audit Log"
                >
                    <ShieldAlert
                        className={`w-3.5 h-3.5 ${blockedIntrusionsCount > 0
                                ? 'text-rose-400 animate-pulse'
                                : 'text-slate-500'
                            }`}
                    />
                    <span>Blocked Intrusions:</span>
                    <strong
                        className={
                            blockedIntrusionsCount > 0 ? 'text-rose-300' : 'text-slate-300'
                        }
                    >
                        {blockedIntrusionsCount}
                    </strong>
                </button>
            </div>

            {/* Right Interactive Demo Controls: CRDT Burst & Red-Team Attack Simulator */}
            <div className="flex items-center gap-2">
                {/* Simulate CRDT Conflict Burst Button */}
                <button
                    type="button"
                    onClick={handleBurstClick}
                    disabled={bursting}
                    className={`px-2.5 py-1 rounded-md border text-[11px] font-mono font-medium transition flex items-center gap-1.5 ${bursting
                            ? 'bg-cyan-500/30 border-cyan-400 text-white'
                            : 'bg-cyan-500/10 hover:bg-cyan-500/20 border-cyan-500/30 text-cyan-300'
                        }`}
                    title="Simulate concurrent multi-peer Yjs CRDT conflict resolution burst"
                >
                    <Zap
                        className={`w-3.5 h-3.5 text-cyan-400 ${bursting ? 'animate-bounce' : ''
                            }`}
                    />
                    <span>
                        {bursting ? 'Merging CRDT Vectors...' : 'Simulate CRDT Conflict Burst'}
                    </span>
                </button>

                {/* Simulate Hacker Attack (Red-Team) Dropdown */}
                <div className="relative" ref={dropdownRef}>
                    <button
                        type="button"
                        onClick={() => setShowAttackMenu((prev) => !prev)}
                        disabled={simulatingAttack}
                        className="px-2.5 py-1 rounded-md bg-rose-500/15 hover:bg-rose-500/25 border border-rose-500/40 text-rose-300 text-[11px] font-mono font-semibold transition flex items-center gap-1.5 shadow-sm shadow-rose-950/50"
                    >
                        <Crosshair
                            className={`w-3.5 h-3.5 text-rose-400 ${simulatingAttack ? 'animate-spin' : ''
                                }`}
                        />
                        <span>
                            {simulatingAttack
                                ? 'Running Exploit Probe...'
                                : 'Simulate Hacker Attack (Red-Team)'}
                        </span>
                        <ChevronUp
                            className={`w-3 h-3 transition-transform ${showAttackMenu ? 'rotate-180' : ''
                                }`}
                        />
                    </button>

                    {showAttackMenu && (
                        <div className="absolute right-0 bottom-9 w-80 rounded-xl bg-[#0F1624] border border-slate-700/90 shadow-2xl p-1.5 space-y-1 z-50">
                            <div className="px-2.5 py-1.5 border-b border-slate-800 flex items-center justify-between">
                                <span className="text-[10px] font-mono uppercase tracking-wider text-rose-400 font-semibold">
                                    Red-Team Cyber-Defense Simulator
                                </span>
                                <span className="text-[9px] text-slate-400">Live Probes</span>
                            </div>

                            <button
                                type="button"
                                onClick={() => handleAttackOption('rce')}
                                className="w-full text-left px-2.5 py-2 rounded-lg hover:bg-rose-500/15 transition flex items-start gap-2.5 group"
                            >
                                <Terminal className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                                <div>
                                    <div className="text-xs font-semibold text-white group-hover:text-rose-200">
                                        Test RCE Exploit
                                    </div>
                                    <p className="text-[10px] text-slate-400 leading-tight">
                                        Injects <code>child_process.execSync(&apos;cat /etc/passwd&apos;)</code> &amp; prototype escape against AST Threat Scanner
                                    </p>
                                </div>
                            </button>

                            <button
                                type="button"
                                onClick={() => handleAttackOption('traversal')}
                                className="w-full text-left px-2.5 py-2 rounded-lg hover:bg-amber-500/15 transition flex items-start gap-2.5 group"
                            >
                                <FileWarning className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                                <div>
                                    <div className="text-xs font-semibold text-white group-hover:text-amber-200">
                                        Test Path Traversal ../../.env
                                    </div>
                                    <p className="text-[10px] text-slate-400 leading-tight">
                                        Attempts directory escape &amp; hidden dotfile creation via <code>POST /api/files</code>
                                    </p>
                                </div>
                            </button>

                            <button
                                type="button"
                                onClick={() => handleAttackOption('rbac')}
                                className="w-full text-left px-2.5 py-2 rounded-lg hover:bg-violet-500/15 transition flex items-start gap-2.5 group"
                            >
                                <UserX className="w-4 h-4 text-violet-400 shrink-0 mt-0.5" />
                                <div>
                                    <div className="text-xs font-semibold text-white group-hover:text-violet-200">
                                        Test Viewer Write Bypass
                                    </div>
                                    <p className="text-[10px] text-slate-400 leading-tight">
                                        Attempts unauthorized file write using a <code>VIEWER</code> JWT against SQLite RBAC middleware
                                    </p>
                                </div>
                            </button>
                        </div>
                    )}
                </div>
            </div>
        </footer>
    );
};

export default TelemetryBar;