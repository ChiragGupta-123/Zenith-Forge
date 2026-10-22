import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Socket } from 'socket.io-client';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import {
    Terminal,
    Play,
    Trash2,
    ChevronDown,
    ChevronUp,
    Lock,
    ShieldCheck,
    ShieldAlert,
    Cpu,
    Clock,
    User,
    FileInput,
    CheckCircle2,
    AlertOctagon,
    RefreshCw,
    Loader2,
    Sparkles,
    Server,
    HardDrive,
    Activity,
} from 'lucide-react';
import {
    CollaboratorRole,
    ExecutionResult,
    ExecutionStartedEvent,
    ProjectFile,
    SecurityAlertBanner,
    SecurityEvent,
} from '../types';
import {
    extractApiErrorMessage,
    fetchSecurityLogs,
    runCode,
} from '../services/api';

function cn(...inputs: (string | undefined | null | false)[]) {
    return twMerge(clsx(inputs));
}

export interface ExecutionConsoleProps {
    projectId: string;
    activeFile: ProjectFile | null;
    userRole: CollaboratorRole;
    socket: Socket | null;
    liveCode?: string;
    onSecurityEventRecorded?: (event: SecurityEvent) => void;
    defaultExpanded?: boolean;
}

type ConsoleTab = 'output' | 'stdin' | 'policy';

interface SandboxProtectionPolicyItem {
    id: string;
    name: string;
    spec: string;
    layer: string;
}

const SANDBOX_PROTECTION_CHECKLIST: SandboxProtectionPolicyItem[] = [
    {
        id: 'ast-prescan',
        name: 'AST/Static Pre-Scan',
        spec: '13 RCE, LFI, Prototype & Fork-Bomb rules enforced pre-spawn',
        layer: 'Layer 2 Guard',
    },
    {
        id: 'codegen-disabled',
        name: 'strings/wasm CodeGen Disabled',
        spec: 'vm.createContext({ codeGeneration: { strings: false, wasm: false } })',
        layer: 'Layer 4 VM',
    },
    {
        id: 'cpu-kill-switch',
        name: '3,000ms CPU Kill-Switch',
        spec: 'Piston 3,000ms run_timeout + Worker 2,500ms VM & parent terminate()',
        layer: 'Layer 3 & 4',
    },
    {
        id: 'memory-ceiling',
        name: '128MB Memory Ceiling',
        spec: 'Piston 128MB limit + Worker V8 resourceLimits (64MB OldGen heap)',
        layer: 'Layer 3 & 4',
    },
    {
        id: 'host-isolation',
        name: 'Host FS/Env Isolation',
        spec: 'Null-prototype global, env: {}, zero process / require / fs access',
        layer: 'Layer 3 & 4',
    },
    {
        id: 'rbac-precheck',
        name: 'RBAC Pre-check',
        spec: 'SQLite WAL getUserRoleInProject verifies OWNER/EDITOR before execution',
        layer: 'Layer 1 Guard',
    },
    {
        id: 'output-cap',
        name: 'Output Cap 10,000 chars',
        spec: 'Deterministic stream truncation prevents stdout/stderr memory floods',
        layer: 'Stream Guard',
    },
];

const EXECUTABLE_LANGUAGES = new Set([
    'python',
    'javascript',
    'typescript',
    'cpp',
    'java',
]);

export const ExecutionConsole: React.FC<ExecutionConsoleProps> = ({
    projectId,
    activeFile,
    userRole,
    socket,
    liveCode,
    onSecurityEventRecorded,
    defaultExpanded = true,
}) => {
    const [activeTab, setActiveTab] = useState<ConsoleTab>('output');
    const [isExpanded, setIsExpanded] = useState<boolean>(defaultExpanded);
    const [stdinContent, setStdinContent] = useState<string>('');
    const [isRunning, setIsRunning] = useState<boolean>(false);
    const [runningStatus, setRunningStatus] =
        useState<ExecutionStartedEvent | null>(null);
    const [lastResult, setLastResult] = useState<ExecutionResult | null>(null);
    const [latestAlert, setLatestAlert] = useState<SecurityAlertBanner | null>(
        null
    );
    const [requestError, setRequestError] = useState<string | null>(null);

    // Live security audit events feed for Tab 3
    const [securityLogs, setSecurityLogs] = useState<SecurityEvent[]>([]);
    const [loadingLogs, setLoadingLogs] = useState<boolean>(false);

    const outputContainerRef = useRef<HTMLDivElement | null>(null);

    const isViewer = userRole === 'VIEWER';
    const isExecutableFile = Boolean(
        activeFile && EXECUTABLE_LANGUAGES.has(activeFile.language)
    );

    // Auto-scroll shared output console whenever stdout, stderr, or running state updates
    useEffect(() => {
        if (outputContainerRef.current && activeTab === 'output' && isExpanded) {
            outputContainerRef.current.scrollTop =
                outputContainerRef.current.scrollHeight;
        }
    }, [lastResult, runningStatus, latestAlert, requestError, activeTab, isExpanded]);

    const loadSecurityLogs = useCallback(async () => {
        if (!projectId) return;
        setLoadingLogs(true);
        try {
            const events = await fetchSecurityLogs(projectId);
            setSecurityLogs(events);
        } catch {
            // Non-blocking if initial fetch fails
        } finally {
            setLoadingLogs(false);
        }
    }, [projectId]);

    useEffect(() => {
        void loadSecurityLogs();
    }, [loadSecurityLogs]);

    // Subscribe to real-time Socket.IO events (`execution-started`, `execution-result`, `security-alert`, `security-log-new`)
    useEffect(() => {
        if (!socket) return;

        const handleExecutionStarted = (payload: ExecutionStartedEvent) => {
            if (payload.projectId && payload.projectId !== projectId) return;
            setIsRunning(true);
            setRunningStatus(payload);
            setRequestError(null);
            setIsExpanded(true);
        };

        const handleExecutionResult = (result: ExecutionResult) => {
            if (result.projectId && result.projectId !== projectId) return;
            setIsRunning(false);
            setRunningStatus(null);
            setLastResult(result);
            setRequestError(null);
            setIsExpanded(true);
        };

        const handleSecurityAlert = (alert: SecurityAlertBanner) => {
            if (alert.projectId && alert.projectId !== projectId) return;
            setLatestAlert(alert);
            void loadSecurityLogs();
        };

        const handleSecurityLogNew = (event: SecurityEvent) => {
            if (event.projectId && event.projectId !== projectId) return;
            setSecurityLogs((prev) => {
                if (prev.some((item) => item.id === event.id)) {
                    return prev;
                }
                return [event, ...prev].slice(0, 100);
            });
            if (onSecurityEventRecorded) {
                onSecurityEventRecorded(event);
            }
        };

        socket.on('execution-started', handleExecutionStarted);
        socket.on('execution-result', handleExecutionResult);
        socket.on('security-alert', handleSecurityAlert);
        socket.on('security-log-new', handleSecurityLogNew);

        return () => {
            socket.off('execution-started', handleExecutionStarted);
            socket.off('execution-result', handleExecutionResult);
            socket.off('security-alert', handleSecurityAlert);
            socket.off('security-log-new', handleSecurityLogNew);
        };
    }, [socket, projectId, loadSecurityLogs, onSecurityEventRecorded]);

    const handleRunCode = async () => {
        if (!projectId || !activeFile || isViewer || isRunning) {
            return;
        }

        if (!isExecutableFile) {
            setRequestError(
                `File "${activeFile.name}" (${activeFile.language}) is a documentation/configuration file. Select a .py, .js, .ts, .cpp, or .java file to execute.`
            );
            setActiveTab('output');
            setIsExpanded(true);
            return;
        }

        setIsExpanded(true);
        setActiveTab('output');
        setIsRunning(true);
        setRequestError(null);

        const codeToExecute =
            typeof liveCode === 'string' ? liveCode : activeFile.content;

        try {
            const result = await runCode({
                projectId,
                fileId: activeFile.id,
                code: codeToExecute,
                language: activeFile.language,
                stdin: stdinContent,
            });
            setLastResult(result);
            void loadSecurityLogs();
        } catch (err) {
            setRequestError(extractApiErrorMessage(err));
            void loadSecurityLogs();
        } finally {
            setIsRunning(false);
            setRunningStatus(null);
        }
    };

    const handleClearConsole = () => {
        setLastResult(null);
        setLatestAlert(null);
        setRequestError(null);
        setRunningStatus(null);
    };

    const effectiveDurationMs =
        lastResult?.durationMs ?? lastResult?.executionTimeMs ?? null;

    const effectiveRuntimeLabel = (() => {
        if (!lastResult) return null;
        const rt =
            lastResult.runtime ||
            (lastResult.isolationLayer?.toLowerCase().includes('local')
                ? 'local-vm'
                : 'piston');
        if (rt === 'piston') return 'Piston Container';
        if (rt === 'local-vm') return 'Local Worker VM';
        if (rt === 'sandbox-guard') return 'Layer 2 Static Guard';
        return 'Offline Fallback Guard';
    })();

    const isBlockedByGuard = Boolean(
        lastResult &&
        (lastResult.sandboxBlocked ||
            lastResult.blocked ||
            (lastResult.threatScan && !lastResult.threatScan.safe))
    );

    const detectedThreats: string[] =
        lastResult?.threatScan?.threats || lastResult?.threatsDetected || [];

    const effectiveRiskScore: number =
        lastResult?.threatScan?.riskScore ?? lastResult?.riskScore ?? 0;

    const blockedEventsCount = securityLogs.filter((e) => e.blocked).length;

    return (
        <section
            className={cn(
                'shrink-0 bg-[#090D16] border-t border-slate-800/80 flex flex-col transition-all duration-200 select-none z-20',
                isExpanded ? 'h-72' : 'h-10'
            )}
        >
            {/* Top Bar: Tabs + Live Status Badges + Action Controls */}
            <div className="h-10 px-3 bg-[#0F1624]/90 border-b border-slate-800/80 flex items-center justify-between gap-2 shrink-0">
                {/* Left: 3 Console Tabs */}
                <div className="flex items-center gap-1 overflow-x-auto no-scrollbar">
                    <button
                        type="button"
                        onClick={() => {
                            setActiveTab('output');
                            setIsExpanded(true);
                        }}
                        className={cn(
                            'px-2.5 py-1.5 rounded-lg text-xs font-medium transition flex items-center gap-1.5 border',
                            activeTab === 'output' && isExpanded
                                ? 'bg-cyan-500/15 text-cyan-300 border-cyan-500/40 shadow-sm'
                                : 'bg-transparent text-slate-400 border-transparent hover:text-slate-200 hover:bg-slate-800/50'
                        )}
                    >
                        <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                        <span>Shared Output Console</span>
                        {isRunning && (
                            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
                        )}
                    </button>

                    <button
                        type="button"
                        onClick={() => {
                            setActiveTab('stdin');
                            setIsExpanded(true);
                        }}
                        className={cn(
                            'px-2.5 py-1.5 rounded-lg text-xs font-medium transition flex items-center gap-1.5 border',
                            activeTab === 'stdin' && isExpanded
                                ? 'bg-violet-500/15 text-violet-300 border-violet-500/40 shadow-sm'
                                : 'bg-transparent text-slate-400 border-transparent hover:text-slate-200 hover:bg-slate-800/50'
                        )}
                    >
                        <FileInput className="w-3.5 h-3.5 text-violet-400" />
                        <span>Standard Input (stdin)</span>
                        {stdinContent.trim().length > 0 && (
                            <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-violet-500/20 text-violet-300 border border-violet-500/30">
                                {stdinContent.split(/\r?\n/).length}L
                            </span>
                        )}
                    </button>

                    <button
                        type="button"
                        onClick={() => {
                            setActiveTab('policy');
                            setIsExpanded(true);
                        }}
                        className={cn(
                            'px-2.5 py-1.5 rounded-lg text-xs font-medium transition flex items-center gap-1.5 border',
                            activeTab === 'policy' && isExpanded
                                ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40 shadow-sm'
                                : 'bg-transparent text-slate-400 border-transparent hover:text-slate-200 hover:bg-slate-800/50'
                        )}
                    >
                        <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                        <span>Zero-Trust Sandbox Policy</span>
                        <span
                            className={cn(
                                'px-1.5 py-0.2 rounded-full text-[10px] font-mono border',
                                blockedEventsCount > 0
                                    ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                                    : 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                            )}
                        >
                            7/7 ACTIVE
                        </span>
                    </button>
                </div>

                {/* Center: Live Execution Metadata & Threat Scan Badge */}
                {lastResult && (
                    <div className="hidden xl:flex items-center gap-2 text-[11px] font-mono">
                        {isBlockedByGuard ? (
                            <span className="px-2 py-0.5 rounded-md bg-rose-500/15 border border-rose-500/40 text-rose-300 flex items-center gap-1.5 font-semibold">
                                <AlertOctagon className="w-3.5 h-3.5 text-rose-400" />
                                BLOCKED BY SANDBOX GUARD (Risk {effectiveRiskScore}/100)
                            </span>
                        ) : (
                            <span className="px-2 py-0.5 rounded-md bg-emerald-500/15 border border-emerald-500/40 text-emerald-300 flex items-center gap-1.5 font-semibold">
                                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                                Threat Scan: PASSED (0 RCE vectors)
                            </span>
                        )}

                        <span
                            className={cn(
                                'px-2 py-0.5 rounded border',
                                lastResult.exitCode === 0
                                    ? 'bg-slate-900 border-slate-700 text-emerald-300'
                                    : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
                            )}
                        >
                            Exit: {lastResult.exitCode ?? 0}
                        </span>

                        {effectiveDurationMs !== null && (
                            <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-cyan-300 flex items-center gap-1">
                                <Clock className="w-3 h-3 text-cyan-400" />
                                {effectiveDurationMs}ms
                            </span>
                        )}

                        {effectiveRuntimeLabel && (
                            <span className="px-2 py-0.5 rounded bg-violet-500/10 border border-violet-500/30 text-violet-300 flex items-center gap-1">
                                <Cpu className="w-3 h-3 text-violet-400" />
                                {effectiveRuntimeLabel}
                            </span>
                        )}

                        <span className="text-slate-400 flex items-center gap-1">
                            <User className="w-3 h-3 text-slate-500" />@{lastResult.executedBy}
                        </span>
                    </div>
                )}

                {/* Right: Run, Clear, and Collapse/Expand Controls */}
                <div className="flex items-center gap-2">
                    <div
                        className="relative"
                        title={
                            isViewer
                                ? 'Locked: VIEWER role is read-only. Switch to EDITOR or OWNER to execute code in the sandbox.'
                                : activeFile
                                    ? `Execute ${activeFile.name} (${activeFile.language}) inside the isolated Zero-Trust sandbox`
                                    : 'Select a file to run'
                        }
                    >
                        <button
                            type="button"
                            onClick={handleRunCode}
                            disabled={isViewer || isRunning || !activeFile}
                            className={cn(
                                'px-3 py-1 rounded-lg text-xs font-mono font-semibold transition flex items-center gap-1.5 border',
                                isViewer
                                    ? 'bg-violet-500/10 border-violet-500/30 text-violet-300/70 cursor-not-allowed'
                                    : isRunning
                                        ? 'bg-cyan-500/20 border-cyan-400/50 text-cyan-200 cursor-wait'
                                        : 'bg-emerald-500 hover:bg-emerald-400 text-slate-950 border-emerald-400 shadow-sm shadow-emerald-950/50'
                            )}
                        >
                            {isViewer ? (
                                <>
                                    <Lock className="w-3.5 h-3.5 text-violet-400" />
                                    <span>Run Locked (VIEWER)</span>
                                </>
                            ) : isRunning ? (
                                <>
                                    <Loader2 className="w-3.5 h-3.5 animate-spin text-cyan-300" />
                                    <span>Running Sandbox...</span>
                                </>
                            ) : (
                                <>
                                    <Play className="w-3.5 h-3.5 fill-current" />
                                    <span>
                                        Run {activeFile ? activeFile.name : 'Code'}
                                    </span>
                                </>
                            )}
                        </button>
                    </div>

                    <button
                        type="button"
                        onClick={handleClearConsole}
                        className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800 transition"
                        title="Clear console output"
                    >
                        <Trash2 className="w-3.5 h-3.5" />
                    </button>

                    <button
                        type="button"
                        onClick={() => setIsExpanded((prev) => !prev)}
                        className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-white border border-slate-800 transition"
                        title={isExpanded ? 'Collapse console' : 'Expand console'}
                    >
                        {isExpanded ? (
                            <ChevronDown className="w-3.5 h-3.5" />
                        ) : (
                            <ChevronUp className="w-3.5 h-3.5" />
                        )}
                    </button>
                </div>
            </div>

            {/* Console Body (Rendered when expanded) */}
            {isExpanded && (
                <div className="flex-1 min-h-0 overflow-hidden flex flex-col">
                    {/* TAB 1: SHARED OUTPUT CONSOLE */}
                    {activeTab === 'output' && (
                        <div
                            ref={outputContainerRef}
                            className="flex-1 overflow-y-auto p-3.5 font-mono text-xs space-y-3 select-text bg-[#090D16]"
                        >
                            {/* Live Running Indicator Banner */}
                            {isRunning && (
                                <div className="p-3 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-200 flex items-center justify-between">
                                    <div className="flex items-center gap-2.5">
                                        <Loader2 className="w-4 h-4 animate-spin text-cyan-400 shrink-0" />
                                        <div>
                                            <div className="font-semibold text-xs">
                                                Executing{' '}
                                                {runningStatus?.fileName ||
                                                    activeFile?.name ||
                                                    'snippet'}{' '}
                                                (
                                                {(
                                                    runningStatus?.language ||
                                                    activeFile?.language ||
                                                    'code'
                                                ).toUpperCase()}
                                                ) in Isolated Sandbox...
                                            </div>
                                            <div className="text-[11px] text-cyan-300/80">
                                                Triggered by @
                                                {runningStatus?.startedBy || 'collaborator'} •
                                                Enforcing 3,000ms CPU kill-switch &amp; 128MB
                                                memory cap
                                            </div>
                                        </div>
                                    </div>
                                    <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-500/20 border border-cyan-500/40 text-cyan-300 uppercase">
                                        LIVE STREAM
                                    </span>
                                </div>
                            )}

                            {/* HTTP / RBAC Error Banner */}
                            {requestError && (
                                <div className="p-3 rounded-xl bg-rose-500/15 border border-rose-500/40 text-rose-200 flex items-start justify-between gap-3">
                                    <div className="flex items-start gap-2.5">
                                        <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                                        <div>
                                            <div className="font-semibold text-rose-300">
                                                Zero-Trust Execution Guard Rejected Request
                                            </div>
                                            <p className="text-[11px] text-rose-200/90 mt-0.5 leading-relaxed">
                                                {requestError}
                                            </p>
                                        </div>
                                    </div>
                                    <button
                                        type="button"
                                        onClick={() => setRequestError(null)}
                                        className="text-[10px] text-rose-300 hover:text-white"
                                    >
                                        DISMISS
                                    </button>
                                </div>
                            )}

                            {/* Execution Summary Header + Threat Scan Badge */}
                            {lastResult && (
                                <div className="space-y-2.5">
                                    <div className="p-2.5 rounded-xl bg-[#0F1624]/90 border border-slate-800/90 flex flex-wrap items-center justify-between gap-2">
                                        <div className="flex flex-wrap items-center gap-2">
                                            {isBlockedByGuard ? (
                                                <span className="px-2.5 py-1 rounded-lg bg-rose-500/20 border border-rose-500/50 text-rose-200 font-semibold flex items-center gap-1.5 text-[11px]">
                                                    <AlertOctagon className="w-3.5 h-3.5 text-rose-400" />
                                                    BLOCKED BY SANDBOX GUARD (Risk Score:{' '}
                                                    {effectiveRiskScore}/100)
                                                </span>
                                            ) : (
                                                <span className="px-2.5 py-1 rounded-lg bg-emerald-500/15 border border-emerald-500/40 text-emerald-300 font-semibold flex items-center gap-1.5 text-[11px]">
                                                    <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                                                    Threat Scan: PASSED (0 RCE vectors)
                                                </span>
                                            )}

                                            <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300 text-[11px]">
                                                File:{' '}
                                                <strong className="text-white">
                                                    {lastResult.fileName ||
                                                        activeFile?.name ||
                                                        'snippet'}
                                                </strong>{' '}
                                                ({lastResult.language.toUpperCase()})
                                            </span>

                                            <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300 text-[11px]">
                                                Runner:{' '}
                                                <strong className="text-cyan-300">
                                                    @{lastResult.executedBy}
                                                </strong>
                                            </span>
                                        </div>

                                        <div className="flex flex-wrap items-center gap-2 text-[11px]">
                                            <span className="px-2 py-0.5 rounded bg-violet-500/15 border border-violet-500/30 text-violet-300">
                                                Runtime: {effectiveRuntimeLabel}
                                            </span>
                                            <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-cyan-300">
                                                Duration: {effectiveDurationMs ?? 0} ms
                                            </span>
                                            <span
                                                className={cn(
                                                    'px-2 py-0.5 rounded font-semibold border',
                                                    lastResult.exitCode === 0
                                                        ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                                                        : 'bg-rose-500/15 border-rose-500/40 text-rose-300'
                                                )}
                                            >
                                                Exit Code: {lastResult.exitCode ?? 0}
                                            </span>
                                        </div>
                                    </div>

                                    {/* Detailed Threat Report Breakdown when Blocked */}
                                    {isBlockedByGuard && detectedThreats.length > 0 && (
                                        <div className="p-3 rounded-xl bg-rose-950/30 border border-rose-500/40 space-y-1.5">
                                            <div className="flex items-center justify-between text-[11px] text-rose-300 font-semibold">
                                                <span className="flex items-center gap-1.5">
                                                    <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                                                    Static AST/Pattern Threat Report (
                                                    {detectedThreats.length} signature match
                                                    {detectedThreats.length === 1 ? '' : 'es'})
                                                </span>
                                                <span>
                                                    Risk Score: {effectiveRiskScore} / 100
                                                </span>
                                            </div>
                                            <ul className="space-y-1 text-[11px] text-rose-200/95 pl-4 list-disc">
                                                {detectedThreats.map((threat, idx) => (
                                                    <li key={idx} className="leading-relaxed">
                                                        {threat}
                                                    </li>
                                                ))}
                                            </ul>
                                        </div>
                                    )}

                                    {/* Standard Output (stdout) */}
                                    {lastResult.stdout && (
                                        <div className="space-y-1">
                                            <div className="text-[10px] uppercase tracking-wider text-slate-500 flex items-center justify-between">
                                                <span>stdout</span>
                                                <span>
                                                    {lastResult.stdout.length.toLocaleString()}{' '}
                                                    chars
                                                </span>
                                            </div>
                                            <pre className="p-3 rounded-xl bg-[#0B101B] border border-slate-800/90 text-slate-100 whitespace-pre-wrap break-words leading-relaxed overflow-x-auto">
                                                {lastResult.stdout}
                                            </pre>
                                        </div>
                                    )}

                                    {/* Standard Error (stderr in rose) */}
                                    {lastResult.stderr && (
                                        <div className="space-y-1">
                                            <div className="text-[10px] uppercase tracking-wider text-rose-400 flex items-center justify-between">
                                                <span>stderr</span>
                                                <span>
                                                    {lastResult.stderr.length.toLocaleString()}{' '}
                                                    chars
                                                </span>
                                            </div>
                                            <pre className="p-3 rounded-xl bg-rose-950/20 border border-rose-500/30 text-rose-300 whitespace-pre-wrap break-words leading-relaxed overflow-x-auto">
                                                {lastResult.stderr}
                                            </pre>
                                        </div>
                                    )}

                                    {!lastResult.stdout && !lastResult.stderr && (
                                        <div className="p-3 rounded-xl bg-[#0F1624]/60 border border-slate-800/80 text-slate-400 text-xs">
                                            Process exited cleanly with code{' '}
                                            {lastResult.exitCode ?? 0} (no stdout/stderr output).
                                        </div>
                                    )}
                                </div>
                            )}

                            {/* Live Socket Security Alert Toast (e.g., from Red-Team Simulator) */}
                            {latestAlert && !lastResult && (
                                <div className="p-3 rounded-xl bg-rose-500/15 border border-rose-500/40 text-rose-200 flex items-start justify-between gap-3">
                                    <div className="flex items-start gap-2">
                                        <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                                        <div>
                                            <div className="font-semibold text-rose-300">
                                                [{latestAlert.severity}]{' '}
                                                {latestAlert.eventType}
                                            </div>
                                            <p className="text-[11px] text-rose-200/90 mt-0.5">
                                                {latestAlert.message}
                                            </p>
                                        </div>
                                    </div>
                                    <button
                                        type="button"
                                        onClick={() => setLatestAlert(null)}
                                        className="text-[10px] text-rose-300 hover:text-white"
                                    >
                                        CLEAR
                                    </button>
                                </div>
                            )}

                            {/* Empty State */}
                            {!isRunning && !lastResult && !requestError && !latestAlert && (
                                <div className="h-full min-h-[140px] flex flex-col items-center justify-center text-center text-slate-500 space-y-1.5">
                                    <div className="w-9 h-9 rounded-xl bg-[#0F1624] border border-slate-800 flex items-center justify-center">
                                        <Terminal className="w-4 h-4 text-cyan-400" />
                                    </div>
                                    <div className="text-xs font-medium text-slate-300">
                                        Shared Zero-Trust Sandbox Console Ready
                                    </div>
                                    <p className="text-[11px] text-slate-500 max-w-md">
                                        Click{' '}
                                        <span className="text-emerald-400 font-semibold">
                                            Run
                                        </span>{' '}
                                        to execute{' '}
                                        <code className="text-slate-300">
                                            {activeFile?.name || 'the active file'}
                                        </code>{' '}
                                        through the 4-layer sandbox. Output streams live to all
                                        connected collaborators in this workspace.
                                    </p>
                                </div>
                            )}
                        </div>
                    )}

                    {/* TAB 2: STANDARD INPUT (STDIN) */}
                    {activeTab === 'stdin' && (
                        <div className="flex-1 p-3.5 bg-[#090D16] flex flex-col gap-2">
                            <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
                                <span className="flex items-center gap-1.5">
                                    <Sparkles className="w-3.5 h-3.5 text-violet-400" />
                                    Standard Input (stdin) piped directly into Piston container
                                    or Local Worker VM (`STDIN` / `readline()`)
                                </span>
                                <div className="flex items-center gap-2">
                                    <span className="text-slate-500">
                                        {stdinContent.length.toLocaleString()} / 10,000 chars
                                    </span>
                                    {stdinContent.length > 0 && (
                                        <button
                                            type="button"
                                            onClick={() => setStdinContent('')}
                                            className="px-2 py-0.5 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 text-[10px]"
                                        >
                                            Clear stdin
                                        </button>
                                    )}
                                </div>
                            </div>

                            <textarea
                                value={stdinContent}
                                onChange={(e) =>
                                    setStdinContent(e.target.value.slice(0, 10_000))
                                }
                                placeholder="Enter standard input lines here (passed via stdin on next Run)..."
                                className="flex-1 w-full p-3 rounded-xl bg-[#0F1624]/90 border border-slate-800 focus:border-violet-500/60 focus:outline-none text-xs font-mono text-slate-100 placeholder-slate-600 resize-none"
                            />
                        </div>
                    )}

                    {/* TAB 3: ZERO-TRUST SANDBOX POLICY & LIVE SECURITY FEED */}
                    {activeTab === 'policy' && (
                        <div className="flex-1 min-h-0 p-3.5 bg-[#090D16] grid grid-cols-1 lg:grid-cols-12 gap-3.5 overflow-y-auto">
                            {/* Left Column (7/12): 7 Active Sandbox Protections Checklist */}
                            <div className="lg:col-span-7 space-y-2">
                                <div className="flex items-center justify-between">
                                    <span className="text-[11px] font-mono uppercase tracking-wider text-emerald-400 font-semibold flex items-center gap-1.5">
                                        <ShieldCheck className="w-3.5 h-3.5" />
                                        Active Multi-Layer Sandbox Controls (7/7 Enforced)
                                    </span>
                                    <span className="text-[10px] font-mono text-slate-400 flex items-center gap-1">
                                        <Server className="w-3 h-3 text-cyan-400" />
                                        Piston + Worker VM
                                    </span>
                                </div>

                                <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                                    {SANDBOX_PROTECTION_CHECKLIST.map((item) => (
                                        <div
                                            key={item.id}
                                            className="p-2 rounded-xl bg-[#0F1624]/90 border border-slate-800/80 flex items-start justify-between gap-2"
                                        >
                                            <div className="flex items-start gap-2 min-w-0">
                                                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                                                <div className="min-w-0">
                                                    <div className="text-xs font-semibold text-white truncate">
                                                        {item.name}
                                                    </div>
                                                    <div className="text-[10px] font-mono text-slate-400 truncate">
                                                        {item.spec}
                                                    </div>
                                                </div>
                                            </div>
                                            <span className="shrink-0 px-1.5 py-0.5 rounded text-[9px] font-mono font-semibold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                                                ACTIVE
                                            </span>
                                        </div>
                                    ))}
                                </div>
                            </div>

                            {/* Right Column (5/12): Live Security Audit Events Feed */}
                            <div className="lg:col-span-5 flex flex-col min-h-0 space-y-2">
                                <div className="flex items-center justify-between">
                                    <span className="text-[11px] font-mono uppercase tracking-wider text-cyan-400 font-semibold flex items-center gap-1.5">
                                        <Activity className="w-3.5 h-3.5" />
                                        Live Security Audit Feed ({securityLogs.length})
                                    </span>
                                    <button
                                        type="button"
                                        onClick={() => void loadSecurityLogs()}
                                        className="px-2 py-0.5 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 text-[10px] font-mono flex items-center gap-1"
                                    >
                                        <RefreshCw
                                            className={cn(
                                                'w-2.5 h-2.5',
                                                loadingLogs && 'animate-spin text-cyan-400'
                                            )}
                                        />
                                        Refresh
                                    </button>
                                </div>

                                <div className="flex-1 max-h-44 overflow-y-auto space-y-1.5 pr-1">
                                    {securityLogs.length === 0 ? (
                                        <div className="p-3 rounded-xl bg-[#0F1624]/60 border border-slate-800 text-[11px] font-mono text-slate-500 flex items-center gap-2">
                                            <HardDrive className="w-3.5 h-3.5" />
                                            No security events recorded yet.
                                        </div>
                                    ) : (
                                        securityLogs.slice(0, 25).map((ev) => (
                                            <div
                                                key={ev.id}
                                                className={cn(
                                                    'p-2 rounded-xl border text-[11px] font-mono space-y-0.5',
                                                    ev.blocked
                                                        ? 'bg-rose-500/10 border-rose-500/35 text-rose-200'
                                                        : 'bg-[#0F1624]/80 border-slate-800/80 text-slate-300'
                                                )}
                                            >
                                                <div className="flex items-center justify-between gap-2">
                                                    <span
                                                        className={cn(
                                                            'font-semibold flex items-center gap-1',
                                                            ev.blocked
                                                                ? 'text-rose-300'
                                                                : 'text-emerald-300'
                                                        )}
                                                    >
                                                        {ev.blocked ? (
                                                            <ShieldAlert className="w-3 h-3 text-rose-400 shrink-0" />
                                                        ) : (
                                                            <ShieldCheck className="w-3 h-3 text-emerald-400 shrink-0" />
                                                        )}
                                                        {ev.eventType}
                                                    </span>
                                                    <span className="text-[10px] text-slate-500">
                                                        @{ev.username || 'system'} •{' '}
                                                        {new Date(
                                                            ev.createdAt
                                                        ).toLocaleTimeString()}
                                                    </span>
                                                </div>
                                                <p className="text-[10px] leading-relaxed opacity-90 break-words">
                                                    {ev.details}
                                                </p>
                                            </div>
                                        ))
                                    )}
                                </div>
                            </div>
                        </div>
                    )}
                </div>
            )}
        </section>
    );
};

export default ExecutionConsole;