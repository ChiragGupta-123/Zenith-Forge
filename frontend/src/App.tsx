import React, { useState, useEffect, useRef, useCallback } from 'react';
import { io, Socket } from 'socket.io-client';
import * as Y from 'yjs';
import {
    ShieldCheck,
    ShieldAlert,
    ArrowLeft,
    KeyRound,
    Copy,
    Check,
    Lock,
    Unlock,
    Save,
    GitCompare,
    Play,
    X,
    Loader2,
    Sparkles,
    RefreshCw,
} from 'lucide-react';
import {
    ChatMessage,
    CollaboratorPresence,
    CollaboratorRole,
    InlineComment,
    PersonaSession,
    Project,
    ProjectFile,
    RedTeamAttackType,
    SecurityAlertBanner,
    SecurityEvent,
    SharedBreakpoint,
} from './types';
import {
    PRESET_PERSONAS,
    SOCKET_SERVER_URL,
    createFile,
    createFileSnapshot,
    createOrSwitchSession,
    createProject,
    deleteFile,
    extractApiErrorMessage,
    fetchProjectDetails,
    fetchProjects,
    getActiveSession,
    joinProjectByInvite,
    renameFile,
    rotateProjectInviteCode,
    simulateRedTeamAttack,
    toggleProjectLock,
    updateCollaboratorRole,
    updateFileContent,
} from './services/api';
import { Dashboard } from './components/Dashboard';
import { SidebarFileTree } from './components/SidebarFileTree';
import { CollaborativeEditor } from './components/CollaborativeEditor';
import { ExecutionConsole } from './components/ExecutionConsole';
import { CollabDrawer, CollabDrawerTab } from './components/CollabDrawer';
import { VersionHistoryModal } from './components/VersionHistoryModal';
import { TelemetryBar } from './components/TelemetryBar';

export const App: React.FC = () => {
    // Session & Dashboard State
    const [session, setSession] = useState<PersonaSession | null>(() =>
        getActiveSession()
    );
    const [projects, setProjects] = useState<Project[]>([]);
    const [loadingProjects, setLoadingProjects] = useState<boolean>(true);

    // Active IDE Studio State
    const [activeProject, setActiveProject] = useState<Project | null>(null);
    const [files, setFiles] = useState<ProjectFile[]>([]);
    const [activeFile, setActiveFile] = useState<ProjectFile | null>(null);
    const [liveEditorCode, setLiveEditorCode] = useState<string>('');
    const [callerRole, setCallerRole] = useState<CollaboratorRole>('OWNER');

    // Real-Time Socket.IO & Yjs CRDT State
    const [socket, setSocket] = useState<Socket | null>(null);
    const [wsConnected, setWsConnected] = useState<boolean>(false);
    const [collaborators, setCollaborators] = useState<CollaboratorPresence[]>(
        []
    );
    const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
    const [securityLogs, setSecurityLogs] = useState<SecurityEvent[]>([]);
    const [breakpoints, setBreakpoints] = useState<SharedBreakpoint[]>([]);
    const [comments, setComments] = useState<InlineComment[]>([]);
    const [cursorLine, setCursorLine] = useState<number>(1);

    // Live CRDT Telemetry Counters
    const [crdtOpsCount, setCrdtOpsCount] = useState<number>(0);
    const [yjsByteSize, setYjsByteSize] = useState<number>(0);
    const [simulatingAttack, setSimulatingAttack] = useState<boolean>(false);

    // Modals, Drawers & Security Alert Toast State
    const [showVersionHistory, setShowVersionHistory] =
        useState<boolean>(false);
    const [drawerTabOverride, setDrawerTabOverride] =
        useState<CollabDrawerTab | null>(null);
    const [securityToast, setSecurityToast] =
        useState<SecurityAlertBanner | null>(null);
    const [savingSnapshot, setSavingSnapshot] = useState<boolean>(false);
    const [copiedInvite, setCopiedInvite] = useState<boolean>(false);
    const [studioNotice, setStudioNotice] = useState<string | null>(null);

    const activeYDocRef = useRef<Y.Doc | null>(null);
    const toastTimeoutRef = useRef<number | null>(null);
    const burstTriggerRef = useRef<(() => void) | null>(null);

    const triggerSecurityToast = useCallback((alert: SecurityAlertBanner) => {
        setSecurityToast(alert);
        if (toastTimeoutRef.current) {
            window.clearTimeout(toastTimeoutRef.current);
        }
        toastTimeoutRef.current = window.setTimeout(() => {
            setSecurityToast(null);
        }, 7000);
    }, []);

    // Load all projects for the authenticated persona
    const loadWorkspaceProjects = useCallback(async () => {
        setLoadingProjects(true);
        try {
            const list = await fetchProjects();
            setProjects(list);
        } catch {
            // Handled by session initialization
        } finally {
            setLoadingProjects(false);
        }
    }, []);

    // Bootstrap default HMAC-SHA256 JWT persona on first visit
    useEffect(() => {
        let mounted = true;
        async function bootstrapSession() {
            setLoadingProjects(true);
            try {
                let current = getActiveSession();
                if (!current) {
                    const defaultPreset = PRESET_PERSONAS[0];
                    current = await createOrSwitchSession(
                        defaultPreset.username,
                        defaultPreset.displayName,
                        defaultPreset.preferredRole
                    );
                }
                if (!mounted) return;
                setSession(current);
                const list = await fetchProjects();
                if (!mounted) return;
                setProjects(list);
            } catch {
                // Retry with fresh session if stored token expired
                try {
                    const fallback = await createOrSwitchSession(
                        PRESET_PERSONAS[0].username,
                        PRESET_PERSONAS[0].displayName,
                        PRESET_PERSONAS[0].preferredRole
                    );
                    if (!mounted) return;
                    setSession(fallback);
                    const list = await fetchProjects();
                    if (mounted) setProjects(list);
                } catch {
                    // Backend may still be booting
                }
            } finally {
                if (mounted) setLoadingProjects(false);
            }
        }
        void bootstrapSession();
        return () => {
            mounted = false;
        };
    }, []);

    // Open a project inside the real-time IDE Studio
    const handleOpenProject = useCallback(async (projectSummary: Project) => {
        try {
            const details = await fetchProjectDetails(projectSummary.id);
            setActiveProject(details.project);
            setFiles(details.files);
            setCallerRole(details.callerRole);

            const initialFile = details.files[0] || null;
            setActiveFile(initialFile);
            setLiveEditorCode(initialFile?.content || '');
            setCrdtOpsCount(1);
            setYjsByteSize(
                initialFile
                    ? new TextEncoder().encode(initialFile.content).byteLength
                    : 0
            );
        } catch (err) {
            alert(extractApiErrorMessage(err));
        }
    }, []);

    // Manage authenticated Socket.IO connection when inside an active project
    useEffect(() => {
        if (!activeProject || !session?.token) {
            if (socket) {
                socket.disconnect();
                setSocket(null);
                setWsConnected(false);
            }
            return;
        }

        const newSocket = io(SOCKET_SERVER_URL, {
            auth: { token: session.token },
            transports: ['websocket', 'polling'],
            reconnection: true,
            reconnectionAttempts: 10,
        });

        setSocket(newSocket);

        newSocket.on('connect', () => {
            setWsConnected(true);
            newSocket.emit('join-project', {
                projectId: activeProject.id,
                fileId: activeFile?.id,
            });
            if (activeFile?.id) {
                newSocket.emit('join-file', {
                    projectId: activeProject.id,
                    fileId: activeFile.id,
                });
            }
        });

        newSocket.on('disconnect', () => {
            setWsConnected(false);
        });

        newSocket.on(
            'project-state-sync',
            (payload: {
                callerRole?: CollaboratorRole;
                collaborators?: CollaboratorPresence[];
                chatMessages?: ChatMessage[];
                securityLogs?: SecurityEvent[];
            }) => {
                if (payload.callerRole) {
                    setCallerRole(payload.callerRole);
                }
                if (Array.isArray(payload.collaborators)) {
                    setCollaborators(payload.collaborators);
                }
                if (Array.isArray(payload.chatMessages)) {
                    setChatMessages(payload.chatMessages);
                }
                if (Array.isArray(payload.securityLogs)) {
                    setSecurityLogs(payload.securityLogs);
                }
            }
        );

        newSocket.on(
            'presence-update',
            (payload: {
                projectId: string;
                collaborators: CollaboratorPresence[];
            }) => {
                if (payload.projectId === activeProject.id) {
                    setCollaborators(payload.collaborators || []);
                }
            }
        );

        newSocket.on('cursor-update', (cursor: CollaboratorPresence) => {
            setCollaborators((prev) => {
                const others = prev.filter((c) => c.userId !== cursor.userId);
                return [...others, cursor];
            });
        });

        newSocket.on(
            'yjs-init',
            (payload: {
                fileId: string;
                content?: string;
                update?: ArrayBuffer | Uint8Array | { data?: number[] };
                breakpoints?: SharedBreakpoint[];
                comments?: InlineComment[];
            }) => {
                if (typeof payload.content === 'string') {
                    setLiveEditorCode(payload.content);
                    setYjsByteSize(
                        new TextEncoder().encode(payload.content).byteLength
                    );
                }
                if (Array.isArray(payload.breakpoints)) {
                    setBreakpoints(payload.breakpoints);
                }
                if (Array.isArray(payload.comments)) {
                    setComments(payload.comments);
                }
                setCrdtOpsCount((prev) => prev + 1);
            }
        );

        newSocket.on(
            'yjs-update',
            (payload: { fileId: string; content?: string }) => {
                if (typeof payload.content === 'string') {
                    setLiveEditorCode(payload.content);
                    setYjsByteSize(
                        new TextEncoder().encode(payload.content).byteLength
                    );
                }
                setCrdtOpsCount((prev) => prev + 1);
            }
        );

        newSocket.on(
            'snapshot-restored',
            (payload: {
                fileId: string;
                content: string;
                restoredBy: string;
                version?: number;
            }) => {
                setLiveEditorCode(payload.content);
                setFiles((prev) =>
                    prev.map((f) =>
                        f.id === payload.fileId
                            ? {
                                ...f,
                                content: payload.content,
                                version: payload.version ?? f.version + 1,
                            }
                            : f
                    )
                );
                setActiveFile((prev) =>
                    prev && prev.id === payload.fileId
                        ? {
                            ...prev,
                            content: payload.content,
                            version: payload.version ?? prev.version + 1,
                        }
                        : prev
                );
                setStudioNotice(
                    `Live buffer restored from verified SHA-256 snapshot by @${payload.restoredBy}`
                );
                setTimeout(() => setStudioNotice(null), 4000);
            }
        );

        newSocket.on('security-alert', (alert: SecurityAlertBanner) => {
            triggerSecurityToast(alert);
        });

        newSocket.on('security-log-new', (event: SecurityEvent) => {
            setSecurityLogs((prev) => {
                if (prev.some((e) => e.id === event.id)) return prev;
                return [event, ...prev].slice(0, 100);
            });
        });

        return () => {
            newSocket.disconnect();
            setWsConnected(false);
        };
    }, [activeProject?.id, session?.token, triggerSecurityToast]);

    // Emit `join-file` when switching active files inside the studio
    const handleSelectFile = useCallback(
        (file: ProjectFile) => {
            setActiveFile(file);
            setLiveEditorCode(file.content);
            setYjsByteSize(new TextEncoder().encode(file.content).byteLength);
            if (socket && socket.connected && activeProject) {
                socket.emit('join-file', {
                    projectId: activeProject.id,
                    fileId: file.id,
                });
            }
        },
        [socket, activeProject]
    );

    // Dashboard & Persona Handlers
    const handleSwitchPersona = async (
        username: string,
        displayName: string,
        role: CollaboratorRole
    ) => {
        const nextSession = await createOrSwitchSession(
            username,
            displayName,
            role
        );
        setSession(nextSession);
        await loadWorkspaceProjects();
        if (activeProject) {
            const refreshed = await fetchProjectDetails(activeProject.id);
            setActiveProject(refreshed.project);
            setFiles(refreshed.files);
            setCallerRole(refreshed.callerRole);
        }
    };

    const handleCreateProject = async (name: string, description: string) => {
        const created = await createProject(name, description);
        setProjects((prev) => [created, ...prev]);
    };

    const handleJoinByInvite = async (inviteCode: string) => {
        const { project } = await joinProjectByInvite(inviteCode);
        await loadWorkspaceProjects();
        await handleOpenProject(project);
    };

    // File Tree Mutation Handlers
    const handleCreateFile = async (name: string) => {
        if (!activeProject) return;
        const { file } = await createFile(
            activeProject.id,
            name,
            `# ${name}\n`
        );
        setFiles((prev) =>
            [...prev, file].sort((a, b) => a.name.localeCompare(b.name))
        );
        handleSelectFile(file);
    };

    const handleRenameFile = async (fileId: string, newName: string) => {
        const updated = await renameFile(fileId, newName);
        setFiles((prev) =>
            prev
                .map((f) => (f.id === fileId ? updated : f))
                .sort((a, b) => a.name.localeCompare(b.name))
        );
        if (activeFile?.id === fileId) {
            setActiveFile(updated);
        }
    };

    const handleDeleteFile = async (fileId: string) => {
        await deleteFile(fileId);
        setFiles((prev) => {
            const remaining = prev.filter((f) => f.id !== fileId);
            if (activeFile?.id === fileId) {
                const next = remaining[0] || null;
                setActiveFile(next);
                setLiveEditorCode(next?.content || '');
            }
            return remaining;
        });
    };

    const handleChangeMemberRole = async (
        targetUserId: string,
        newRole: CollaboratorRole,
        selfDemoSwitch: boolean = false
    ) => {
        if (!activeProject) return;
        const res = await updateCollaboratorRole(
            activeProject.id,
            targetUserId,
            newRole,
            selfDemoSwitch
        );
        setActiveProject((prev) =>
            prev ? { ...prev, members: res.members } : prev
        );
        if (targetUserId === session?.user.id) {
            setCallerRole(res.role);
        }
    };

    // Top Header Actions: Copy Invite, Rotate Invite, Lock Workspace, Save Snapshot
    const handleCopyInviteCode = () => {
        if (!activeProject) return;
        navigator.clipboard.writeText(activeProject.inviteCode);
        setCopiedInvite(true);
        setTimeout(() => setCopiedInvite(false), 2000);
    };

    const handleRotateInvite = async () => {
        if (!activeProject) return;
        try {
            const res = await rotateProjectInviteCode(activeProject.id);
            setActiveProject((prev) =>
                prev ? { ...prev, inviteCode: res.inviteCode } : prev
            );
            setStudioNotice(`Rotated invite code to ${res.inviteCode}`);
            setTimeout(() => setStudioNotice(null), 3500);
        } catch (err) {
            alert(extractApiErrorMessage(err));
        }
    };

    const handleToggleWorkspaceLock = async () => {
        if (!activeProject) return;
        try {
            const res = await toggleProjectLock(
                activeProject.id,
                !activeProject.isLocked
            );
            setActiveProject((prev) =>
                prev ? { ...prev, isLocked: res.isLocked } : prev
            );
            setStudioNotice(
                res.isLocked
                    ? 'Workspace LOCKED (Only OWNER can edit or run code)'
                    : 'Workspace UNLOCKED for collaborative editing'
            );
            setTimeout(() => setStudioNotice(null), 3500);
        } catch (err) {
            alert(extractApiErrorMessage(err));
        }
    };

    const handleQuickSaveSnapshot = async () => {
        if (!activeFile || callerRole === 'VIEWER' || savingSnapshot) return;
        setSavingSnapshot(true);
        try {
            await updateFileContent(activeFile.id, liveEditorCode, false);
            const snap = await createFileSnapshot(
                activeFile.id,
                `Checkpoint (${new Date().toLocaleTimeString()})`,
                liveEditorCode
            );
            setStudioNotice(
                `Saved SHA-256 snapshot "${snap.label}" (${snap.hash.slice(
                    0,
                    12
                )}...)`
            );
            setTimeout(() => setStudioNotice(null), 4000);
        } catch (err) {
            alert(extractApiErrorMessage(err));
        } finally {
            setSavingSnapshot(false);
        }
    };

    // TelemetryBar Handlers: Conflict Burst & Red-Team Simulator
    const handleSimulateConflictBurst = () => {
        if (burstTriggerRef.current) {
            burstTriggerRef.current();
            setCrdtOpsCount((prev) => prev + 12);
            return;
        }
        if (!activeFile || callerRole === 'VIEWER') return;
        const stamp = new Date().toISOString().slice(11, 23);
        const burstComment =
            activeFile.language === 'python'
                ? `\n# [CRDT Vector Merge Verified @ ${stamp} by @${session?.user.username}]`
                : `\n// [CRDT Vector Merge Verified @ ${stamp} by @${session?.user.username}]`;
        const nextCode = liveEditorCode + burstComment;
        setLiveEditorCode(nextCode);
        setCrdtOpsCount((prev) => prev + 5);
        setYjsByteSize(new TextEncoder().encode(nextCode).byteLength);
        if (socket && socket.connected && activeProject) {
            socket.emit('yjs-update', {
                projectId: activeProject.id,
                fileId: activeFile.id,
                content: nextCode,
            });
        }
    };

    const handleSimulateRedTeamAttack = async (
        attackType: RedTeamAttackType
    ) => {
        if (!activeProject || simulatingAttack) return;
        setSimulatingAttack(true);
        try {
            const sim = await simulateRedTeamAttack(
                activeProject.id,
                attackType
            );
            if (sim.securityEvent) {
                setSecurityLogs((prev) => [
                    sim.securityEvent!,
                    ...prev.filter((e) => e.id !== sim.securityEvent!.id),
                ]);
            }
            triggerSecurityToast({
                alertId: sim.eventId || `sim-${Date.now()}`,
                projectId: activeProject.id,
                eventType:
                    attackType === 'rce'
                        ? 'SANDBOX_ESCAPE_BLOCKED'
                        : attackType === 'traversal'
                            ? 'PATH_TRAVERSAL_BLOCKED'
                            : 'RBAC_VIOLATION_ATTEMPT',
                severity: attackType === 'rce' ? 'CRITICAL' : 'HIGH',
                message: `${sim.attackName} Blocked by ${sim.defense || sim.defenseLayer
                    }`,
                details: sim.details,
                username: session?.user.username || 'redteam',
                blocked: true,
                createdAt: sim.timestamp || new Date().toISOString(),
            });
            setDrawerTabOverride('security');
        } finally {
            setSimulatingAttack(false);
        }
    };

    const blockedIntrusionsCount = securityLogs.filter((e) => e.blocked).length;

    // Render Dashboard when no project is currently open in Studio
    if (!activeProject) {
        return (
            <Dashboard
                session={session}
                projects={projects}
                loading={loadingProjects}
                onSelectProject={handleOpenProject}
                onSwitchPersona={handleSwitchPersona}
                onCreateProject={handleCreateProject}
                onJoinByInvite={handleJoinByInvite}
                onRefreshProjects={loadWorkspaceProjects}
            />
        );
    }

    return (
        <div className="h-screen w-screen overflow-hidden bg-[#090D16] text-slate-100 flex flex-col select-none">
            {/* Sleek Floating Toast Notification on `security-alert` Broadcasts */}
            {securityToast && (
                <div className="fixed top-16 right-6 z-50 w-96 rounded-2xl bg-[#0F1624]/95 border-2 border-rose-500/70 shadow-2xl shadow-rose-950/80 p-4 backdrop-blur-xl animate-in fade-in slide-in-from-top-3">
                    <div className="flex items-start justify-between gap-2.5">
                        <div className="flex items-start gap-2.5">
                            <div className="w-8 h-8 rounded-xl bg-rose-500/20 border border-rose-500/40 flex items-center justify-center shrink-0 mt-0.5">
                                <ShieldAlert className="w-4 h-4 text-rose-400 animate-pulse" />
                            </div>
                            <div className="space-y-1">
                                <div className="flex items-center gap-2">
                                    <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-rose-500/25 text-rose-200 border border-rose-500/50">
                                        {securityToast.severity} • BLOCKED
                                    </span>
                                    <span className="text-xs font-mono font-bold text-white">
                                        {securityToast.eventType}
                                    </span>
                                </div>
                                <p className="text-xs font-medium text-rose-200 leading-snug">
                                    {securityToast.message}
                                </p>
                                <p className="text-[10px] font-mono text-slate-400 line-clamp-2">
                                    {securityToast.details}
                                </p>
                            </div>
                        </div>
                        <button
                            type="button"
                            onClick={() => setSecurityToast(null)}
                            className="p-1 rounded-lg text-slate-400 hover:text-white"
                        >
                            <X className="w-3.5 h-3.5" />
                        </button>
                    </div>
                </div>
            )}

            {/* Top IDE Studio Header */}
            <header className="h-13 shrink-0 bg-[#0F1624]/95 border-b border-slate-800/80 px-4 py-2 flex items-center justify-between gap-3 z-30">
                {/* Left: Back Button + Project Title + Invite Code Copy Pill + Lock Control */}
                <div className="flex items-center gap-3 min-w-0">
                    <button
                        type="button"
                        onClick={() => setActiveProject(null)}
                        className="px-2.5 py-1.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs font-medium text-slate-300 hover:text-white flex items-center gap-1.5 transition"
                        title="Return to Workspaces Dashboard"
                    >
                        <ArrowLeft className="w-3.5 h-3.5 text-cyan-400" />
                        <span className="hidden sm:inline">Workspaces</span>
                    </button>

                    <div className="flex items-center gap-2 min-w-0">
                        <div className="w-7 h-7 rounded-lg bg-cyan-500/15 border border-cyan-500/40 flex items-center justify-center shrink-0">
                            <ShieldCheck className="w-4 h-4 text-cyan-400" />
                        </div>
                        <div className=" truncate">
                            <div className="flex items-center gap-2">
                                <span className="font-bold text-sm text-white truncate">
                                    {activeProject.name}
                                </span>
                                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                                    {callerRole}
                                </span>
                            </div>
                        </div>
                    </div>

                    {/* Invite Code Copy Pill */}
                    <div className="hidden md:flex items-center gap-1">
                        <button
                            type="button"
                            onClick={handleCopyInviteCode}
                            className="px-2.5 py-1 rounded-lg bg-[#090D16] hover:bg-slate-900 border border-slate-800 text-[11px] font-mono text-slate-300 flex items-center gap-1.5 transition"
                            title="Click to copy cryptographic project invite code"
                        >
                            <KeyRound className="w-3 h-3 text-cyan-400" />
                            <span>{activeProject.inviteCode}</span>
                            {copiedInvite ? (
                                <Check className="w-3 h-3 text-emerald-400" />
                            ) : (
                                <Copy className="w-3 h-3 text-slate-500" />
                            )}
                        </button>

                        {callerRole === 'OWNER' && (
                            <button
                                type="button"
                                onClick={handleRotateInvite}
                                className="p-1.5 rounded-lg bg-[#090D16] hover:bg-slate-900 border border-slate-800 text-slate-400 hover:text-cyan-300 transition"
                                title="Rotate project invite code (OWNER only)"
                            >
                                <RefreshCw className="w-3 h-3" />
                            </button>
                        )}

                        {callerRole === 'OWNER' && (
                            <button
                                type="button"
                                onClick={handleToggleWorkspaceLock}
                                className={`px-2 py-1 rounded-lg border text-[10px] font-mono flex items-center gap-1 transition ${activeProject.isLocked
                                        ? 'bg-rose-500/15 border-rose-500/40 text-rose-300'
                                        : 'bg-[#090D16] border-slate-800 text-slate-400 hover:text-white'
                                    }`}
                                title="Toggle Emergency Workspace Lockdown (OWNER only)"
                            >
                                {activeProject.isLocked ? (
                                    <>
                                        <Lock className="w-3 h-3 text-rose-400" />
                                        <span>LOCKED</span>
                                    </>
                                ) : (
                                    <>
                                        <Unlock className="w-3 h-3 text-emerald-400" />
                                        <span>UNLOCKED</span>
                                    </>
                                )}
                            </button>
                        )}
                    </div>
                </div>

                {/* Center: Status Banner or Active Collaborator Avatar Stack with Glowing Rings */}
                <div className="flex items-center gap-3">
                    {studioNotice && (
                        <div className="hidden lg:flex items-center gap-1.5 px-3 py-1 rounded-full bg-cyan-500/15 border border-cyan-500/40 text-cyan-200 text-xs font-mono">
                            <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                            <span>{studioNotice}</span>
                        </div>
                    )}

                    {/* Live Collaborator Avatar Stack with Glowing Status Rings */}
                    <div className="flex items-center gap-2">
                        <span className="hidden xl:inline text-[11px] font-mono text-slate-400">
                            Peers ({Math.max(1, collaborators.length)}):
                        </span>
                        <div className="flex items-center -space-x-1.5">
                            {(collaborators.length > 0
                                ? collaborators
                                : [
                                    {
                                        userId: session?.user.id || 'self',
                                        username:
                                            session?.user.username || 'you',
                                        displayName:
                                            session?.user.displayName ||
                                            'You',
                                        avatarColor:
                                            session?.user.avatarColor ||
                                            '#10b981',
                                        role: callerRole,
                                        fileId: activeFile?.id || '',
                                        lineNumber: cursorLine,
                                        column: 1,
                                        lastActiveAt: Date.now(),
                                    },
                                ]
                            )
                                .slice(0, 6)
                                .map((peer) => (
                                    <div
                                        key={peer.userId}
                                        className="relative group"
                                        title={`@${peer.username} (${peer.role}) • Line ${peer.lineNumber}, Col ${peer.column}`}
                                    >
                                        <div
                                            className="w-7 h-7 rounded-full flex items-center justify-center text-[10px] font-bold text-slate-950 ring-2 ring-emerald-400/80 shadow-md shadow-emerald-500/20"
                                            style={{
                                                backgroundColor:
                                                    peer.avatarColor,
                                            }}
                                        >
                                            {peer.username
                                                .slice(0, 2)
                                                .toUpperCase()}
                                        </div>
                                        <span className="absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 rounded-full bg-emerald-400 ring-2 ring-[#0F1624]" />
                                    </div>
                                ))}
                        </div>
                    </div>
                </div>

                {/* Right: Save Snapshot, Version Diff, and Run in Sandbox CTAs */}
                <div className="flex items-center gap-2">
                    <button
                        type="button"
                        onClick={handleQuickSaveSnapshot}
                        disabled={
                            callerRole === 'VIEWER' ||
                            savingSnapshot ||
                            !activeFile
                        }
                        className="px-3 py-1.5 rounded-xl bg-slate-900 hover:bg-slate-800 disabled:opacity-40 border border-slate-700/80 text-xs font-mono text-slate-200 flex items-center gap-1.5 transition"
                        title={
                            callerRole === 'VIEWER'
                                ? 'VIEWER role cannot save snapshots'
                                : 'Save immutable SHA-256 checkpoint of active buffer'
                        }
                    >
                        {savingSnapshot ? (
                            <Loader2 className="w-3.5 h-3.5 animate-spin text-cyan-400" />
                        ) : (
                            <Save className="w-3.5 h-3.5 text-cyan-400" />
                        )}
                        <span className="hidden sm:inline">Save Snapshot</span>
                    </button>

                    <button
                        type="button"
                        onClick={() => setShowVersionHistory(true)}
                        disabled={!activeFile}
                        className="px-3 py-1.5 rounded-xl bg-violet-500/15 hover:bg-violet-500/25 border border-violet-500/40 text-xs font-mono font-semibold text-violet-200 flex items-center gap-1.5 transition"
                        title="Open Monaco Side-by-Side Version Diff & 1-Click Rollback Studio"
                    >
                        <GitCompare className="w-3.5 h-3.5 text-violet-400" />
                        <span className="hidden sm:inline">Version Diff</span>
                    </button>

                    <button
                        type="button"
                        disabled={callerRole === 'VIEWER' || !activeFile}
                        onClick={() => {
                            window.dispatchEvent(
                                new CustomEvent('devcollab:trigger-sandbox-run')
                            );
                        }}
                        className={`px-3.5 py-1.5 rounded-xl text-xs font-mono font-semibold flex items-center gap-1.5 transition border ${callerRole === 'VIEWER'
                                ? 'bg-violet-500/10 border-violet-500/30 text-violet-300/60 cursor-not-allowed'
                                : 'bg-gradient-to-r from-emerald-500 to-cyan-500 hover:from-emerald-400 hover:to-cyan-400 text-slate-950 border-emerald-400 shadow-lg shadow-emerald-950/50'
                            }`}
                        title={
                            callerRole === 'VIEWER'
                                ? 'Locked: VIEWER role cannot execute code'
                                : 'Execute active file in 4-Layer Hardened Sandbox'
                        }
                    >
                        {callerRole === 'VIEWER' ? (
                            <>
                                <Lock className="w-3.5 h-3.5" />
                                <span>Sandbox Locked</span>
                            </>
                        ) : (
                            <>
                                <Play className="w-3.5 h-3.5 fill-current" />
                                <span>Run in Sandbox</span>
                            </>
                        )}
                    </button>
                </div>
            </header>

            {/* Main 3-Column Studio Body: SidebarFileTree | Editor + ExecutionConsole | CollabDrawer */}
            <div className="flex-1 min-h-0 flex overflow-hidden">
                <SidebarFileTree
                    projectId={activeProject.id}
                    projectName={activeProject.name}
                    isProjectLocked={activeProject.isLocked}
                    files={files}
                    activeFileId={activeFile?.id || null}
                    callerRole={callerRole}
                    currentUserId={session?.user.id || ''}
                    members={activeProject.members || []}
                    collaborators={collaborators}
                    onSelectFile={handleSelectFile}
                    onCreateFile={handleCreateFile}
                    onRenameFile={handleRenameFile}
                    onDeleteFile={handleDeleteFile}
                    onChangeMemberRole={handleChangeMemberRole}
                />

                {/* Center Split Column: Monaco + Yjs Collaborative Editor (Top) & ExecutionConsole (Bottom) */}
                <div className="flex-1 flex flex-col min-w-0 min-h-0 overflow-hidden bg-[#090D16]">
                    <div className="flex-1 min-h-0 overflow-hidden relative">
                        <CollaborativeEditor
                            projectId={activeProject.id}
                            file={activeFile}
                            activeFile={activeFile}
                            userRole={callerRole}
                            callerRole={callerRole}
                            isProjectLocked={activeProject.isLocked}
                            socket={socket}
                            currentUser={session?.user || null}
                            collaborators={collaborators}
                            breakpoints={breakpoints}
                            comments={comments}
                            onCodeChange={(nextCode: string) => {
                                setLiveEditorCode(nextCode);
                                setYjsByteSize(
                                    new TextEncoder().encode(nextCode)
                                        .byteLength
                                );
                            }}
                            onCursorChange={(pos: {
                                lineNumber: number;
                                column: number;
                            }) => {
                                setCursorLine(pos.lineNumber);
                            }}
                            onYDocReady={(ydocInstance: Y.Doc) => {
                                activeYDocRef.current = ydocInstance;
                            }}
                            onRegisterBurstHandler={(trigger) => { burstTriggerRef.current = trigger; }}
                            onOpenVersionHistory={() =>
                                setShowVersionHistory(true)
                            }
                        />
                    </div>

                    <ExecutionConsole
                        projectId={activeProject.id}
                        activeFile={activeFile}
                        userRole={callerRole}
                        socket={socket}
                        liveCode={liveEditorCode}
                        onSecurityEventRecorded={(ev) => {
                            setSecurityLogs((prev) =>
                                prev.some((x) => x.id === ev.id)
                                    ? prev
                                    : [ev, ...prev]
                            );
                        }}
                    />
                </div>

                {/* Right-Hand 5-Tab Collaboration & Security Drawer */}
                <CollabDrawer
                    projectId={activeProject.id}
                    activeFile={activeFile}
                    liveCode={liveEditorCode}
                    userRole={callerRole}
                    currentUsername={session?.user.username}
                    currentCursorLine={cursorLine}
                    socket={socket}
                    activeTabOverride={drawerTabOverride}
                    initialComments={comments}
                    initialChatMessages={chatMessages}
                    initialBreakpoints={breakpoints}
                    initialSecurityLogs={securityLogs}
                    onApplyCodeSnippet={(patchedCode) =>
                        setLiveEditorCode(patchedCode)
                    }
                    onSecurityEventRecorded={(ev) => {
                        setSecurityLogs((prev) =>
                            prev.some((x) => x.id === ev.id)
                                ? prev
                                : [ev, ...prev]
                        );
                    }}
                />
            </div>

            {/* Bottom Live Security & CRDT Telemetry Bar */}
            <TelemetryBar
                wsConnected={wsConnected}
                jwtVerified={Boolean(session?.token)}
                activeRole={callerRole}
                crdtOpsCount={crdtOpsCount}
                yjsByteSize={yjsByteSize}
                blockedIntrusionsCount={blockedIntrusionsCount}
                simulatingAttack={simulatingAttack}
                onSimulateConflictBurst={handleSimulateConflictBurst}
                onSimulateRedTeamAttack={handleSimulateRedTeamAttack}
                onOpenSecurityAuditTab={() => setDrawerTabOverride('security')}
            />

            {/* Phase 6 Recoverable Version History & Side-by-Side Diff Modal */}
            {showVersionHistory && (
                <VersionHistoryModal
                    isOpen={showVersionHistory}
                    onClose={() => setShowVersionHistory(false)}
                    projectId={activeProject.id}
                    file={activeFile}
                    liveContent={liveEditorCode}
                    userRole={callerRole}
                    socket={socket}
                    ydoc={activeYDocRef.current}
                    onSnapshotRestored={(updatedFile, restoredSnapshot) => {
                        setActiveFile(updatedFile);
                        setLiveEditorCode(restoredSnapshot.content);
                        setFiles((prev) =>
                            prev.map((f) =>
                                f.id === updatedFile.id ? updatedFile : f
                            )
                        );
                    }}
                />
            )}
        </div>
    );
};

export default App;