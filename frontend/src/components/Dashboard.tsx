import React, { useState } from 'react';
import {
    ShieldCheck,
    Terminal,
    Cpu,
    Lock,
    Unlock,
    Copy,
    Check,
    Plus,
    KeyRound,
    Users,
    FileCode2,
    ArrowRight,
    Sparkles,
    UserCheck,
    RefreshCw,
    AlertTriangle,
    Layers,
    Activity,
} from 'lucide-react';
import {
    CollaboratorRole,
    PersonaSession,
    Project,
} from '../types';
import {
    PRESET_PERSONAS,
    PresetPersona,
    extractApiErrorMessage,
} from '../services/api';

interface DashboardProps {
    session: PersonaSession | null;
    projects: Project[];
    loading: boolean;
    onSelectProject: (project: Project) => void;
    onSwitchPersona: (
        username: string,
        displayName: string,
        role: CollaboratorRole
    ) => Promise<void>;
    onCreateProject: (name: string, description: string) => Promise<void>;
    onJoinByInvite: (inviteCode: string) => Promise<void>;
    onRefreshProjects: () => Promise<void>;
}

const ROLE_BADGE_STYLES: Record<
    CollaboratorRole,
    { bg: string; text: string; border: string; label: string }
> = {
    OWNER: {
        bg: 'bg-emerald-500/15',
        text: 'text-emerald-300',
        border: 'border-emerald-500/40',
        label: 'OWNER • FULL CONTROL',
    },
    EDITOR: {
        bg: 'bg-cyan-500/15',
        text: 'text-cyan-300',
        border: 'border-cyan-500/40',
        label: 'EDITOR • READ/WRITE',
    },
    VIEWER: {
        bg: 'bg-violet-500/15',
        text: 'text-violet-300',
        border: 'border-violet-500/40',
        label: 'VIEWER • READ-ONLY',
    },
};

export const Dashboard: React.FC<DashboardProps> = ({
    session,
    projects,
    loading,
    onSelectProject,
    onSwitchPersona,
    onCreateProject,
    onJoinByInvite,
    onRefreshProjects,
}) => {
    const [copiedInviteId, setCopiedInviteId] = useState<string | null>(null);
    const [inviteInput, setInviteInput] = useState<string>('QRE-2026-ZERO');
    const [joiningInvite, setJoiningInvite] = useState<boolean>(false);
    const [switchingUser, setSwitchingUser] = useState<string | null>(null);

    // Create Project Modal State
    const [showCreateModal, setShowCreateModal] = useState<boolean>(false);
    const [newProjectName, setNewProjectName] = useState<string>('');
    const [newProjectDesc, setNewProjectDesc] = useState<string>('');
    const [creatingProject, setCreatingProject] = useState<boolean>(false);

    // Custom Persona Modal State
    const [showCustomPersonaModal, setShowCustomPersonaModal] =
        useState<boolean>(false);
    const [customUsername, setCustomUsername] = useState<string>('');
    const [customDisplayName, setCustomDisplayName] = useState<string>('');
    const [customRole, setCustomRole] = useState<CollaboratorRole>('EDITOR');

    const [bannerError, setBannerError] = useState<string | null>(null);
    const [bannerSuccess, setBannerSuccess] = useState<string | null>(null);

    const handleCopyInvite = (e: React.MouseEvent, project: Project) => {
        e.stopPropagation();
        navigator.clipboard.writeText(project.inviteCode);
        setCopiedInviteId(project.id);
        setTimeout(() => setCopiedInviteId(null), 2000);
    };

    const handlePresetPersonaSelect = async (preset: PresetPersona) => {
        setBannerError(null);
        setSwitchingUser(preset.username);
        try {
            await onSwitchPersona(
                preset.username,
                preset.displayName,
                preset.preferredRole
            );
            setBannerSuccess(
                `Switched active HMAC-SHA256 JWT identity to @${preset.username} (${preset.preferredRole})`
            );
            setTimeout(() => setBannerSuccess(null), 4000);
        } catch (err) {
            setBannerError(extractApiErrorMessage(err));
        } finally {
            setSwitchingUser(null);
        }
    };

    const handleCreateCustomPersona = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!customUsername.trim()) return;
        setBannerError(null);
        setSwitchingUser(customUsername);
        try {
            await onSwitchPersona(
                customUsername.trim(),
                customDisplayName.trim() || customUsername.trim(),
                customRole
            );
            setShowCustomPersonaModal(false);
            setCustomUsername('');
            setCustomDisplayName('');
            setBannerSuccess(
                `Issued new HMAC-SHA256 JWT session for @${customUsername.trim()} (${customRole})`
            );
            setTimeout(() => setBannerSuccess(null), 4000);
        } catch (err) {
            setBannerError(extractApiErrorMessage(err));
        } finally {
            setSwitchingUser(null);
        }
    };

    const handleJoinSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!inviteInput.trim()) return;
        setBannerError(null);
        setJoiningInvite(true);
        try {
            await onJoinByInvite(inviteInput.trim().toUpperCase());
            setBannerSuccess(
                `Successfully verified invite code "${inviteInput
                    .trim()
                    .toUpperCase()}" and joined workspace.`
            );
            setTimeout(() => setBannerSuccess(null), 4000);
        } catch (err) {
            setBannerError(extractApiErrorMessage(err));
        } finally {
            setJoiningInvite(false);
        }
    };

    const handleCreateProjectSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!newProjectName.trim()) return;
        setBannerError(null);
        setCreatingProject(true);
        try {
            await onCreateProject(
                newProjectName.trim(),
                newProjectDesc.trim() ||
                'Zero-Trust real-time collaborative engineering workspace'
            );
            setNewProjectName('');
            setNewProjectDesc('');
            setShowCreateModal(false);
            setBannerSuccess(
                `Provisioned workspace "${newProjectName.trim()}" with cryptographic invite code.`
            );
            setTimeout(() => setBannerSuccess(null), 4000);
        } catch (err) {
            setBannerError(extractApiErrorMessage(err));
        } finally {
            setCreatingProject(false);
        }
    };

    const tokenPreview = session?.token
        ? `${session.token.slice(0, 18)}...${session.token.slice(-12)}`
        : 'issuing...';

    return (
        <div className="min-h-screen bg-[#090D16] text-slate-100 flex flex-col selection:bg-cyan-500/30 selection:text-cyan-200">
            {/* Ambient Obsidian Glow */}
            <div className="pointer-events-none fixed inset-0 overflow-hidden z-0">
                <div className="absolute -top-40 left-1/4 w-[520px] h-[520px] bg-cyan-500/8 rounded-full blur-[130px]" />
                <div className="absolute top-20 right-1/4 w-[460px] h-[460px] bg-violet-500/8 rounded-full blur-[130px]" />
                <div className="absolute bottom-0 left-1/2 w-[600px] h-[300px] bg-emerald-500/5 rounded-full blur-[140px]" />
            </div>

            {/* Top Navigation & Instant Persona Switcher */}
            <header className="sticky top-0 z-30 border-b border-slate-800/80 bg-[#090D16]/90 backdrop-blur-xl">
                <div className="max-w-7xl mx-auto px-6 py-3.5 flex flex-wrap items-center justify-between gap-4">
                    {/* Brand Identity */}
                    <div className="flex items-center gap-3.5">
                        <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/25 via-violet-500/20 to-emerald-500/25 border border-cyan-500/40 flex items-center justify-center shadow-lg shadow-cyan-950/50">
                            <ShieldCheck className="w-5 h-5 text-cyan-400" />
                        </div>
                        <div>
                            <div className="flex items-center gap-2.5">
                                <span className="font-bold tracking-tight text-lg text-white">
                                    DevCollab
                                </span>
                                <span className="text-[11px] font-mono uppercase tracking-wider px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                                    Zero-Trust v2.4
                                </span>
                            </div>
                            <p className="text-xs text-slate-400">
                                Real-Time CRDT Collaborative Coding &amp; Cyber-Defense Platform
                            </p>
                        </div>
                    </div>

                    {/* Instant Persona Switcher Bar */}
                    <div className="flex flex-wrap items-center gap-2">
                        <span className="text-xs font-medium text-slate-400 mr-1 flex items-center gap-1.5">
                            <UserCheck className="w-3.5 h-3.5 text-cyan-400" />
                            Persona Switcher:
                        </span>

                        {PRESET_PERSONAS.map((preset) => {
                            const isCurrent = session?.user.username === preset.username;
                            const isBusy = switchingUser === preset.username;
                            return (
                                <button
                                    key={preset.username}
                                    onClick={() => handlePresetPersonaSelect(preset)}
                                    disabled={Boolean(switchingUser)}
                                    className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all flex items-center gap-2 border ${isCurrent
                                            ? 'bg-[#131C31] border-cyan-400/60 text-white shadow-sm shadow-cyan-500/20'
                                            : 'bg-[#0F1624]/80 border-slate-800/80 text-slate-300 hover:border-slate-700 hover:text-white'
                                        }`}
                                >
                                    <span
                                        className="w-2 h-2 rounded-full"
                                        style={{ backgroundColor: preset.accentColor }}
                                    />
                                    <span>@{preset.username}</span>
                                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-900/90 text-slate-300 border border-slate-700/70">
                                        {preset.preferredRole}
                                    </span>
                                    {isBusy && (
                                        <RefreshCw className="w-3 h-3 animate-spin text-cyan-400" />
                                    )}
                                </button>
                            );
                        })}

                        <button
                            onClick={() => setShowCustomPersonaModal(true)}
                            className="px-2.5 py-1.5 rounded-lg text-xs font-medium bg-violet-500/15 hover:bg-violet-500/25 text-violet-300 border border-violet-500/30 transition flex items-center gap-1"
                            title="Create or switch to a custom user persona"
                        >
                            <Plus className="w-3.5 h-3.5" />
                            Custom Identity
                        </button>
                    </div>
                </div>

                {/* Active JWT Cryptographic Telemetry Strip */}
                <div className="border-t border-slate-800/60 bg-[#0B101B]/90 px-6 py-1.5">
                    <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono text-slate-400">
                        <div className="flex items-center gap-4">
                            <span className="flex items-center gap-1.5 text-emerald-400">
                                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                                AUTH: HMAC-SHA256 VERIFIED
                            </span>
                            <span>
                                USER:{' '}
                                <strong className="text-slate-200">
                                    {session?.user.displayName || 'Initializing...'}
                                </strong>{' '}
                                (@{session?.user.username || '...'})
                            </span>
                            <span className="hidden md:inline text-slate-500">
                                JWT: <code className="text-cyan-400/90">{tokenPreview}</code>
                            </span>
                        </div>
                        <div className="flex items-center gap-3">
                            <span className="text-cyan-400">
                                SQLite WAL Prepared Statements: ACTIVE
                            </span>
                            <span className="text-slate-600">•</span>
                            <span className="text-violet-400">
                                WS Frame Cap: 64KB / CRDT Cap: 32KB
                            </span>
                        </div>
                    </div>
                </div>
            </header>

            {/* Main Content Container */}
            <main className="relative z-10 flex-1 max-w-7xl w-full mx-auto px-6 py-8 space-y-8">
                {/* Status / Alert Feedback Banners */}
                {bannerError && (
                    <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/40 text-rose-200 text-xs flex items-center justify-between">
                        <div className="flex items-center gap-2.5">
                            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                            <span>{bannerError}</span>
                        </div>
                        <button
                            onClick={() => setBannerError(null)}
                            className="text-rose-300 hover:text-white text-xs font-mono"
                        >
                            DISMISS
                        </button>
                    </div>
                )}

                {bannerSuccess && (
                    <div className="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/40 text-emerald-200 text-xs flex items-center justify-between">
                        <div className="flex items-center gap-2.5">
                            <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
                            <span>{bannerSuccess}</span>
                        </div>
                        <button
                            onClick={() => setBannerSuccess(null)}
                            className="text-emerald-300 hover:text-white text-xs font-mono"
                        >
                            OK
                        </button>
                    </div>
                )}

                {/* 3 Security & Architecture Hero Cards */}
                <section className="grid grid-cols-1 md:grid-cols-3 gap-5">
                    {/* Card 1: Zero-Trust Auth */}
                    <div className="rounded-2xl bg-[#0F1624]/90 border border-slate-800/80 p-5 shadow-xl relative overflow-hidden group hover:border-emerald-500/40 transition">
                        <div className="flex items-center justify-between mb-3">
                            <span className="text-[11px] font-mono uppercase tracking-wider px-2.5 py-0.5 rounded-md bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                                Layer 01 • Identity &amp; RBAC
                            </span>
                            <Lock className="w-4 h-4 text-emerald-400" />
                        </div>
                        <h3 className="text-sm font-semibold text-white mb-1.5">
                            Zero-Trust Auth: HMAC-SHA256 JWT + Socket Guard
                        </h3>
                        <p className="text-xs text-slate-400 leading-relaxed mb-3">
                            Zero-dependency native <code className="text-emerald-300">crypto.timingSafeEqual</code>{' '}
                            JWT verification on every REST mutation and Socket.IO handshake. Server queries SQLite for live{' '}
                            <code className="text-slate-200">OWNER / EDITOR / VIEWER</code> permissions.
                        </p>
                        <div className="pt-2.5 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono text-slate-400">
                            <span>Spoof Protection: 100%</span>
                            <span className="text-emerald-400">alg:HS256 Enforced</span>
                        </div>
                    </div>

                    {/* Card 2: Yjs CRDT Engine */}
                    <div className="rounded-2xl bg-[#0F1624]/90 border border-slate-800/80 p-5 shadow-xl relative overflow-hidden group hover:border-cyan-500/40 transition">
                        <div className="flex items-center justify-between mb-3">
                            <span className="text-[11px] font-mono uppercase tracking-wider px-2.5 py-0.5 rounded-md bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
                                Layer 02 • Real-Time Sync
                            </span>
                            <Layers className="w-4 h-4 text-cyan-400" />
                        </div>
                        <h3 className="text-sm font-semibold text-white mb-1.5">
                            CRDT Engine: Yjs Binary State Vectors
                        </h3>
                        <p className="text-xs text-slate-400 leading-relaxed mb-3">
                            Conflict-free sub-millisecond code merging powered by Yjs state vectors, guarded by a 40 ops/sec per-socket token bucket, 32KB delta ceiling, and binary fuzzing isolation.
                        </p>
                        <div className="pt-2.5 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono text-slate-400">
                            <span>Persistence: WAL + BLOB</span>
                            <span className="text-cyan-400">SHA-256 Snapshots</span>
                        </div>
                    </div>

                    {/* Card 3: Multi-Layer Sandbox Defense */}
                    <div className="rounded-2xl bg-[#0F1624]/90 border border-slate-800/80 p-5 shadow-xl relative overflow-hidden group hover:border-violet-500/40 transition">
                        <div className="flex items-center justify-between mb-3">
                            <span className="text-[11px] font-mono uppercase tracking-wider px-2.5 py-0.5 rounded-md bg-violet-500/15 text-violet-300 border border-violet-500/30">
                                Layer 03 • Execution Shield
                            </span>
                            <Cpu className="w-4 h-4 text-violet-400" />
                        </div>
                        <h3 className="text-sm font-semibold text-white mb-1.5">
                            Sandbox Defense: AST Scanner + Isolated VM/Piston
                        </h3>
                        <p className="text-xs text-slate-400 leading-relaxed mb-3">
                            Pre-execution static threat scanner intercepts <code className="text-rose-300">child_process</code>,{' '}
                            <code className="text-rose-300">os.system</code>, <code className="text-rose-300">/etc/passwd</code>, and fork bombs before running inside an env-stripped, timeout-bounded sandbox.
                        </p>
                        <div className="pt-2.5 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono text-slate-400">
                            <span>13 Threat Signatures</span>
                            <span className="text-violet-400">Red-Team Ready</span>
                        </div>
                    </div>
                </section>

                {/* Action Bar: Join via Cryptographic Invite Code + Create Project */}
                <section className="rounded-2xl bg-[#0F1624]/90 border border-slate-800/80 p-5 flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-4">
                    <form
                        onSubmit={handleJoinSubmit}
                        className="flex-1 flex flex-col sm:flex-row items-stretch sm:items-center gap-3"
                    >
                        <div className="relative flex-1 max-w-md">
                            <KeyRound className="w-4 h-4 text-cyan-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
                            <input
                                type="text"
                                value={inviteInput}
                                onChange={(e) => setInviteInput(e.target.value)}
                                placeholder="Enter cryptographic invite code (e.g. QRE-2026-ZERO)"
                                className="w-full pl-10 pr-28 py-2.5 rounded-xl bg-[#090D16] border border-slate-800 text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/60"
                            />
                            <button
                                type="button"
                                onClick={() => setInviteInput('QRE-2026-ZERO')}
                                className="absolute right-2 top-1/2 -translate-y-1/2 text-[10px] font-mono px-2 py-1 rounded bg-slate-800/90 hover:bg-slate-700 text-cyan-300 transition"
                            >
                                Use Demo Code
                            </button>
                        </div>
                        <button
                            type="submit"
                            disabled={joiningInvite}
                            className="px-4 py-2.5 rounded-xl bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-300 border border-cyan-500/40 text-xs font-semibold transition flex items-center justify-center gap-2"
                        >
                            <Users className="w-3.5 h-3.5" />
                            {joiningInvite ? 'Verifying Code...' : 'Join via Invite Code'}
                        </button>
                    </form>

                    <div className="flex items-center gap-3">
                        <button
                            onClick={() => onRefreshProjects()}
                            className="px-3.5 py-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 text-xs font-medium transition flex items-center gap-1.5"
                            title="Refresh project workspaces"
                        >
                            <RefreshCw
                                className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-cyan-400' : ''}`}
                            />
                            Refresh
                        </button>

                        <button
                            onClick={() => setShowCreateModal(true)}
                            className="px-4 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-violet-600 hover:from-cyan-400 hover:to-violet-500 text-slate-950 font-semibold text-xs shadow-lg shadow-cyan-500/20 transition flex items-center gap-2"
                        >
                            <Plus className="w-4 h-4 stroke-[2.5]" />
                            New Zero-Trust Workspace
                        </button>
                    </div>
                </section>

                {/* Workspaces Grid */}
                <section className="space-y-4">
                    <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2.5">
                            <Terminal className="w-4 h-4 text-cyan-400" />
                            <h2 className="text-base font-semibold text-white">
                                Active Collaborative Workspaces
                            </h2>
                            <span className="text-xs font-mono px-2 py-0.5 rounded-full bg-slate-800/90 text-slate-300">
                                {projects.length}
                            </span>
                        </div>
                        <span className="text-xs text-slate-400">
                            Click any workspace to launch the real-time Yjs CRDT Studio
                        </span>
                    </div>

                    {loading && projects.length === 0 ? (
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                            {[1, 2].map((n) => (
                                <div
                                    key={n}
                                    className="h-52 rounded-2xl bg-[#0F1624]/60 border border-slate-800/60 animate-pulse p-6"
                                />
                            ))}
                        </div>
                    ) : (
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                            {projects.map((project) => {
                                const callerRole: CollaboratorRole = project.role || 'EDITOR';
                                const badge = ROLE_BADGE_STYLES[callerRole];
                                const isCopied = copiedInviteId === project.id;

                                return (
                                    <div
                                        key={project.id}
                                        onClick={() => onSelectProject(project)}
                                        className="group cursor-pointer rounded-2xl bg-[#0F1624]/90 border border-slate-800/80 hover:border-cyan-500/50 p-6 transition-all duration-200 shadow-xl hover:shadow-cyan-950/30 flex flex-col justify-between"
                                    >
                                        <div>
                                            {/* Top Row: Title + Role Badge */}
                                            <div className="flex items-start justify-between gap-3 mb-3">
                                                <div className="flex items-center gap-2.5">
                                                    <div className="w-9 h-9 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-center group-hover:border-cyan-500/40 transition">
                                                        <FileCode2 className="w-4 h-4 text-cyan-400" />
                                                    </div>
                                                    <div>
                                                        <div className="flex items-center gap-2">
                                                            <h3 className="font-semibold text-base text-white group-hover:text-cyan-300 transition">
                                                                {project.name}
                                                            </h3>
                                                            {project.isLocked ? (
                                                                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono bg-rose-500/15 text-rose-300 border border-rose-500/30">
                                                                    <Lock className="w-2.5 h-2.5" />
                                                                    LOCKED
                                                                </span>
                                                            ) : (
                                                                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                                                                    <Unlock className="w-2.5 h-2.5" />
                                                                    ACTIVE
                                                                </span>
                                                            )}
                                                        </div>
                                                        <span className="text-[11px] font-mono text-slate-500">
                                                            ID: {project.id}
                                                        </span>
                                                    </div>
                                                </div>

                                                <span
                                                    className={`px-2.5 py-1 rounded-lg text-[10px] font-mono font-semibold border ${badge.bg} ${badge.text} ${badge.border}`}
                                                >
                                                    {badge.label}
                                                </span>
                                            </div>

                                            {/* Description */}
                                            <p className="text-xs text-slate-400 leading-relaxed mb-5 line-clamp-2">
                                                {project.description}
                                            </p>
                                        </div>

                                        {/* Footer: Invite Code + Collaborator Avatars + Launch Button */}
                                        <div className="pt-4 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-3">
                                            <div className="flex items-center gap-2">
                                                <button
                                                    type="button"
                                                    onClick={(e) => handleCopyInvite(e, project)}
                                                    className="px-2.5 py-1 rounded-lg bg-[#090D16] hover:bg-slate-900 border border-slate-800 text-[11px] font-mono text-slate-300 flex items-center gap-1.5 transition"
                                                    title="Copy cryptographic invite code"
                                                >
                                                    <KeyRound className="w-3 h-3 text-cyan-400" />
                                                    <span>{project.inviteCode}</span>
                                                    {isCopied ? (
                                                        <Check className="w-3 h-3 text-emerald-400" />
                                                    ) : (
                                                        <Copy className="w-3 h-3 text-slate-500" />
                                                    )}
                                                </button>

                                                <span className="text-xs text-slate-400 flex items-center gap-1 ml-1">
                                                    <Activity className="w-3.5 h-3.5 text-emerald-400" />
                                                    {project.fileCount ?? 3} files
                                                </span>
                                            </div>

                                            <div className="flex items-center gap-3">
                                                {/* Member Avatar Stack */}
                                                {project.members && project.members.length > 0 && (
                                                    <div className="flex -space-x-2">
                                                        {project.members.slice(0, 4).map((m) => (
                                                            <div
                                                                key={m.userId}
                                                                className="w-6 h-6 rounded-full border-2 border-[#0F1624] flex items-center justify-center text-[10px] font-bold text-slate-950"
                                                                style={{ backgroundColor: m.avatarColor }}
                                                                title={`@${m.username} (${m.role})`}
                                                            >
                                                                {m.username.slice(0, 2).toUpperCase()}
                                                            </div>
                                                        ))}
                                                    </div>
                                                )}

                                                <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-cyan-400 group-hover:translate-x-0.5 transition">
                                                    Open Studio
                                                    <ArrowRight className="w-3.5 h-3.5" />
                                                </span>
                                            </div>
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    )}
                </section>
            </main>

            {/* Create New Project Modal */}
            {showCreateModal && (
                <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
                    <div className="w-full max-w-md rounded-2xl bg-[#0F1624] border border-slate-800 p-6 shadow-2xl">
                        <div className="flex items-center justify-between mb-4">
                            <div className="flex items-center gap-2">
                                <Sparkles className="w-4 h-4 text-cyan-400" />
                                <h3 className="text-base font-semibold text-white">
                                    Create Zero-Trust Workspace
                                </h3>
                            </div>
                            <button
                                onClick={() => setShowCreateModal(false)}
                                className="text-slate-400 hover:text-white text-xs font-mono"
                            >
                                ESC
                            </button>
                        </div>

                        <form onSubmit={handleCreateProjectSubmit} className="space-y-4">
                            <div>
                                <label className="block text-xs font-medium text-slate-300 mb-1.5">
                                    Workspace Name
                                </label>
                                <input
                                    type="text"
                                    required
                                    maxLength={80}
                                    value={newProjectName}
                                    onChange={(e) => setNewProjectName(e.target.value)}
                                    placeholder="e.g. Zero-Knowledge Auth Microservice"
                                    className="w-full px-3.5 py-2.5 rounded-xl bg-[#090D16] border border-slate-800 text-xs text-white focus:outline-none focus:border-cyan-500"
                                />
                            </div>

                            <div>
                                <label className="block text-xs font-medium text-slate-300 mb-1.5">
                                    Security Scope &amp; Description
                                </label>
                                <textarea
                                    rows={3}
                                    maxLength={280}
                                    value={newProjectDesc}
                                    onChange={(e) => setNewProjectDesc(e.target.value)}
                                    placeholder="Describe the collaborative engineering goals and security boundary..."
                                    className="w-full px-3.5 py-2.5 rounded-xl bg-[#090D16] border border-slate-800 text-xs text-white focus:outline-none focus:border-cyan-500"
                                />
                            </div>

                            <div className="flex items-center justify-end gap-2 pt-2">
                                <button
                                    type="button"
                                    onClick={() => setShowCreateModal(false)}
                                    className="px-4 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-300 text-xs font-medium"
                                >
                                    Cancel
                                </button>
                                <button
                                    type="submit"
                                    disabled={creatingProject}
                                    className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs"
                                >
                                    {creatingProject ? 'Provisioning...' : 'Create Workspace'}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            {/* Custom Persona Switcher Modal */}
            {showCustomPersonaModal && (
                <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
                    <div className="w-full max-w-md rounded-2xl bg-[#0F1624] border border-slate-800 p-6 shadow-2xl">
                        <div className="flex items-center justify-between mb-4">
                            <div className="flex items-center gap-2">
                                <UserCheck className="w-4 h-4 text-violet-400" />
                                <h3 className="text-base font-semibold text-white">
                                    Issue Custom HMAC-JWT Persona
                                </h3>
                            </div>
                            <button
                                onClick={() => setShowCustomPersonaModal(false)}
                                className="text-slate-400 hover:text-white text-xs font-mono"
                            >
                                ESC
                            </button>
                        </div>

                        <form onSubmit={handleCreateCustomPersona} className="space-y-4">
                            <div>
                                <label className="block text-xs font-medium text-slate-300 mb-1.5">
                                    Handle / Username
                                </label>
                                <input
                                    type="text"
                                    required
                                    maxLength={32}
                                    value={customUsername}
                                    onChange={(e) => setCustomUsername(e.target.value)}
                                    placeholder="e.g. dev_sec_ops_01"
                                    className="w-full px-3.5 py-2.5 rounded-xl bg-[#090D16] border border-slate-800 text-xs font-mono text-white focus:outline-none focus:border-violet-500"
                                />
                            </div>

                            <div>
                                <label className="block text-xs font-medium text-slate-300 mb-1.5">
                                    Display Name
                                </label>
                                <input
                                    type="text"
                                    maxLength={50}
                                    value={customDisplayName}
                                    onChange={(e) => setCustomDisplayName(e.target.value)}
                                    placeholder="e.g. Elena Rostova (Red-Team Lead)"
                                    className="w-full px-3.5 py-2.5 rounded-xl bg-[#090D16] border border-slate-800 text-xs text-white focus:outline-none focus:border-violet-500"
                                />
                            </div>

                            <div>
                                <label className="block text-xs font-medium text-slate-300 mb-1.5">
                                    Initial Demo Project Role
                                </label>
                                <select
                                    value={customRole}
                                    onChange={(e) =>
                                        setCustomRole(e.target.value as CollaboratorRole)
                                    }
                                    className="w-full px-3.5 py-2.5 rounded-xl bg-[#090D16] border border-slate-800 text-xs text-white focus:outline-none focus:border-violet-500"
                                >
                                    <option value="OWNER">OWNER (Full Project &amp; Role Control)</option>
                                    <option value="EDITOR">EDITOR (Real-Time Code &amp; Sandbox Write)</option>
                                    <option value="VIEWER">VIEWER (Read-Only Audit Mode)</option>
                                </select>
                            </div>

                            <div className="flex items-center justify-end gap-2 pt-2">
                                <button
                                    type="button"
                                    onClick={() => setShowCustomPersonaModal(false)}
                                    className="px-4 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-300 text-xs font-medium"
                                >
                                    Cancel
                                </button>
                                <button
                                    type="submit"
                                    className="px-4 py-2 rounded-xl bg-violet-500 hover:bg-violet-400 text-white font-semibold text-xs"
                                >
                                    Issue Signed JWT
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
};

export default Dashboard;