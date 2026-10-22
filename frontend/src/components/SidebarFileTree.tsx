import React, { useState } from 'react';
import {
    FileCode,
    FileText,
    FileJson,
    Plus,
    Edit3,
    Trash2,
    Lock,
    ShieldAlert,
    Users,
    Check,
    X,
    FolderGit2,
    ChevronRight,
    Eye,
    Shield,
} from 'lucide-react';
import {
    CollaboratorPresence,
    CollaboratorRole,
    ProjectFile,
    ProjectMember,
} from '../types';
import { extractApiErrorMessage } from '../services/api';

interface SidebarFileTreeProps {
    projectId: string;
    projectName: string;
    isProjectLocked: boolean;
    files: ProjectFile[];
    activeFileId: string | null;
    callerRole: CollaboratorRole;
    currentUserId: string;
    members: ProjectMember[];
    collaborators: CollaboratorPresence[];
    onSelectFile: (file: ProjectFile) => void;
    onCreateFile: (name: string) => Promise<void>;
    onRenameFile: (fileId: string, newName: string) => Promise<void>;
    onDeleteFile: (fileId: string) => Promise<void>;
    onChangeMemberRole: (
        targetUserId: string,
        newRole: CollaboratorRole,
        selfDemoSwitch?: boolean
    ) => Promise<void>;
}

const ALLOWED_EXTENSIONS = [
    '.py',
    '.js',
    '.ts',
    '.cpp',
    '.java',
    '.md',
    '.json',
];

function getLanguageBadge(name: string) {
    const lower = name.toLowerCase();
    if (lower.endsWith('.py')) {
        return { label: 'PY', color: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30' };
    }
    if (lower.endsWith('.js')) {
        return { label: 'JS', color: 'text-amber-300 bg-amber-500/10 border-amber-500/30' };
    }
    if (lower.endsWith('.ts')) {
        return { label: 'TS', color: 'text-blue-400 bg-blue-500/10 border-blue-500/30' };
    }
    if (lower.endsWith('.cpp')) {
        return { label: 'C++', color: 'text-violet-300 bg-violet-500/10 border-violet-500/30' };
    }
    if (lower.endsWith('.java')) {
        return { label: 'JAVA', color: 'text-rose-300 bg-rose-500/10 border-rose-500/30' };
    }
    if (lower.endsWith('.json')) {
        return { label: 'JSON', color: 'text-emerald-300 bg-emerald-500/10 border-emerald-500/30' };
    }
    return { label: 'MD', color: 'text-slate-300 bg-slate-500/10 border-slate-500/30' };
}

function renderFileIcon(name: string) {
    const lower = name.toLowerCase();
    if (lower.endsWith('.md')) {
        return <FileText className="w-3.5 h-3.5 text-slate-400 shrink-0" />;
    }
    if (lower.endsWith('.json')) {
        return <FileJson className="w-3.5 h-3.5 text-emerald-400 shrink-0" />;
    }
    return <FileCode className="w-3.5 h-3.5 text-cyan-400 shrink-0" />;
}

/**
 * Client-side pre-check mirroring backend `validateSafeFilename`
 * (Can be bypassed with the "Send Raw to Test Server Block" toggle to demonstrate backend defense).
 */
function checkClientFilenameWarning(name: string): string | null {
    const trimmed = name.trim();
    if (!trimmed) return 'Filename is required.';
    if (
        trimmed.includes('..') ||
        trimmed.includes('/') ||
        trimmed.includes('\\')
    ) {
        return 'Directory traversal characters (.., /, \\) detected!';
    }
    if (trimmed.startsWith('.')) {
        return 'Hidden dotfiles (.env, .git) are restricted by Zero-Trust policy.';
    }
    const hasAllowedExt = ALLOWED_EXTENSIONS.some((ext) =>
        trimmed.toLowerCase().endsWith(ext)
    );
    if (!hasAllowedExt) {
        return `Allowed extensions: ${ALLOWED_EXTENSIONS.join(', ')}`;
    }
    return null;
}

export const SidebarFileTree: React.FC<SidebarFileTreeProps> = ({
    projectName,
    isProjectLocked,
    files,
    activeFileId,
    callerRole,
    currentUserId,
    members,
    collaborators,
    onSelectFile,
    onCreateFile,
    onRenameFile,
    onDeleteFile,
    onChangeMemberRole,
}) => {
    const [isCreating, setIsCreating] = useState<boolean>(false);
    const [newFilename, setNewFilename] = useState<string>('');
    const [renamingFileId, setRenamingFileId] = useState<string | null>(null);
    const [renameValue, setRenameValue] = useState<string>('');
    const [errorBanner, setErrorBanner] = useState<string | null>(null);
    const [busyAction, setBusyAction] = useState<boolean>(false);

    const isReadOnlyViewer = callerRole === 'VIEWER';
    const isWriteLocked =
        isReadOnlyViewer || (isProjectLocked && callerRole !== 'OWNER');

    const clientWarning = isCreating
        ? checkClientFilenameWarning(newFilename)
        : null;

    const handleCreateSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!newFilename.trim()) return;
        setErrorBanner(null);
        setBusyAction(true);
        try {
            await onCreateFile(newFilename.trim());
            setNewFilename('');
            setIsCreating(false);
        } catch (err) {
            setErrorBanner(extractApiErrorMessage(err));
        } finally {
            setBusyAction(false);
        }
    };

    const handleRenameSubmit = async (fileId: string) => {
        if (!renameValue.trim()) {
            setRenamingFileId(null);
            return;
        }
        setErrorBanner(null);
        setBusyAction(true);
        try {
            await onRenameFile(fileId, renameValue.trim());
            setRenamingFileId(null);
        } catch (err) {
            setErrorBanner(extractApiErrorMessage(err));
        } finally {
            setBusyAction(false);
        }
    };

    const handleDeleteClick = async (
        e: React.MouseEvent,
        file: ProjectFile
    ) => {
        e.stopPropagation();
        if (files.length <= 1) {
            setErrorBanner('Workspace must retain at least 1 active file.');
            return;
        }
        setErrorBanner(null);
        setBusyAction(true);
        try {
            await onDeleteFile(file.id);
        } catch (err) {
            setErrorBanner(extractApiErrorMessage(err));
        } finally {
            setBusyAction(false);
        }
    };

    const handleRoleSelect = async (
        targetUserId: string,
        nextRole: CollaboratorRole,
        selfSwitch: boolean = false
    ) => {
        setErrorBanner(null);
        try {
            await onChangeMemberRole(targetUserId, nextRole, selfSwitch);
        } catch (err) {
            setErrorBanner(extractApiErrorMessage(err));
        }
    };

    return (
        <aside className="w-72 shrink-0 bg-[#0F1624]/95 border-r border-slate-800/80 flex flex-col h-full select-none">
            {/* Workspace Header */}
            <div className="p-3.5 border-b border-slate-800/80 flex items-center justify-between">
                <div className="flex items-center gap-2 min-w-0">
                    <FolderGit2 className="w-4 h-4 text-cyan-400 shrink-0" />
                    <span className="text-xs font-semibold text-white truncate">
                        {projectName}
                    </span>
                </div>

                <div className="flex items-center gap-1.5">
                    {isWriteLocked ? (
                        <span
                            className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-violet-500/15 text-violet-300 border border-violet-500/30 text-[10px] font-mono"
                            title="VIEWER role is strictly read-only"
                        >
                            <Lock className="w-2.5 h-2.5" />
                            READ-ONLY
                        </span>
                    ) : (
                        <button
                            onClick={() => {
                                setErrorBanner(null);
                                setIsCreating((prev) => !prev);
                            }}
                            className="p-1.5 rounded-lg bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-300 border border-cyan-500/30 transition"
                            title="Create new file (.py, .js, .ts, .cpp, .java, .md, .json)"
                        >
                            <Plus className="w-3.5 h-3.5" />
                        </button>
                    )}
                </div>
            </div>

            {/* Security / Validation Alert Banner inside Sidebar */}
            {errorBanner && (
                <div className="m-2.5 p-2.5 rounded-xl bg-rose-500/15 border border-rose-500/40 text-rose-200 text-[11px] space-y-1">
                    <div className="flex items-start justify-between gap-2">
                        <div className="flex items-center gap-1.5 font-semibold text-rose-300">
                            <ShieldAlert className="w-3.5 h-3.5 shrink-0" />
                            <span>Zero-Trust Guard Blocked</span>
                        </div>
                        <button
                            onClick={() => setErrorBanner(null)}
                            className="text-rose-300 hover:text-white"
                        >
                            <X className="w-3 h-3" />
                        </button>
                    </div>
                    <p className="text-[10px] text-rose-200/90 leading-relaxed font-mono">
                        {errorBanner}
                    </p>
                </div>
            )}

            {/* New File Input Form */}
            {isCreating && (
                <form
                    onSubmit={handleCreateSubmit}
                    className="p-2.5 mx-2.5 mt-2 rounded-xl bg-[#090D16] border border-slate-800 space-y-2"
                >
                    <div className="flex items-center justify-between">
                        <span className="text-[10px] font-mono uppercase text-cyan-400">
                            New Safe File
                        </span>
                        <button
                            type="button"
                            onClick={() => setNewFilename('../../.env')}
                            className="text-[9px] font-mono text-rose-400 hover:underline"
                            title="Pre-fill a malicious traversal filename to test server-side blocking"
                        >
                            Test ../../.env
                        </button>
                    </div>

                    <input
                        type="text"
                        autoFocus
                        value={newFilename}
                        onChange={(e) => setNewFilename(e.target.value)}
                        placeholder="e.g. router_test.py"
                        className="w-full px-2.5 py-1.5 rounded-lg bg-[#0F1624] border border-slate-700 text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
                    />

                    {clientWarning && (
                        <p className="text-[10px] font-mono text-amber-300 leading-tight">
                            ⚠ {clientWarning} (Submit to test server-side block &amp; audit log)
                        </p>
                    )}

                    <div className="flex items-center justify-end gap-1.5">
                        <button
                            type="button"
                            onClick={() => {
                                setIsCreating(false);
                                setNewFilename('');
                            }}
                            className="px-2 py-1 rounded text-[10px] text-slate-400 hover:text-white"
                        >
                            Cancel
                        </button>
                        <button
                            type="submit"
                            disabled={busyAction}
                            className="px-2.5 py-1 rounded bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-[10px]"
                        >
                            Create
                        </button>
                    </div>
                </form>
            )}

            {/* File Explorer List */}
            <div className="flex-1 overflow-y-auto px-2 py-2.5 space-y-1">
                <div className="px-2 pb-1 flex items-center justify-between text-[10px] font-mono uppercase tracking-wider text-slate-500">
                    <span>Workspace Files ({files.length})</span>
                    <span>Live Presence</span>
                </div>

                {files.map((file) => {
                    const isSelected = file.id === activeFileId;
                    const isRenaming = renamingFileId === file.id;
                    const badge = getLanguageBadge(file.name);
                    const filePeers = collaborators.filter((c) => c.fileId === file.id);

                    return (
                        <div
                            key={file.id}
                            onClick={() => onSelectFile(file)}
                            className={`group rounded-xl px-2.5 py-2 transition flex items-center justify-between gap-2 cursor-pointer border ${isSelected
                                    ? 'bg-cyan-500/12 border-cyan-500/40 text-white shadow-sm'
                                    : 'bg-transparent border-transparent hover:bg-slate-800/50 text-slate-300'
                                }`}
                        >
                            <div className="flex items-center gap-2 min-w-0 flex-1">
                                <ChevronRight
                                    className={`w-3 h-3 shrink-0 transition-transform ${isSelected ? 'rotate-90 text-cyan-400' : 'text-slate-600'
                                        }`}
                                />
                                {renderFileIcon(file.name)}

                                {isRenaming ? (
                                    <div
                                        className="flex items-center gap-1 flex-1"
                                        onClick={(e) => e.stopPropagation()}
                                    >
                                        <input
                                            type="text"
                                            autoFocus
                                            value={renameValue}
                                            onChange={(e) => setRenameValue(e.target.value)}
                                            onKeyDown={(e) => {
                                                if (e.key === 'Enter') handleRenameSubmit(file.id);
                                                if (e.key === 'Escape') setRenamingFileId(null);
                                            }}
                                            className="w-full px-1.5 py-0.5 rounded bg-[#090D16] border border-cyan-500 text-xs font-mono text-white"
                                        />
                                        <button
                                            onClick={() => handleRenameSubmit(file.id)}
                                            className="text-emerald-400 hover:text-emerald-300"
                                        >
                                            <Check className="w-3.5 h-3.5" />
                                        </button>
                                        <button
                                            onClick={() => setRenamingFileId(null)}
                                            className="text-slate-400 hover:text-white"
                                        >
                                            <X className="w-3.5 h-3.5" />
                                        </button>
                                    </div>
                                ) : (
                                    <span className="text-xs font-mono truncate">{file.name}</span>
                                )}
                            </div>

                            <div className="flex items-center gap-1.5 shrink-0">
                                {/* Live Collaborator Presence Dots on this file */}
                                {filePeers.length > 0 && (
                                    <div className="flex items-center -space-x-1 mr-1">
                                        {filePeers.slice(0, 3).map((peer) => (
                                            <span
                                                key={`${peer.userId}-${peer.fileId}`}
                                                className="w-2.5 h-2.5 rounded-full ring-2 ring-[#0F1624]"
                                                style={{ backgroundColor: peer.avatarColor }}
                                                title={`@${peer.username} (${peer.role}) — Line ${peer.lineNumber}, Col ${peer.column}`}
                                            />
                                        ))}
                                    </div>
                                )}

                                <span
                                    className={`text-[9px] font-mono px-1.5 py-0.5 rounded border ${badge.color}`}
                                >
                                    {badge.label}
                                </span>

                                {/* Action Icons: Rename / Delete or Lock Icon for VIEWER */}
                                {isWriteLocked ? (
                                    <Lock
                                        className="w-3 h-3 text-slate-600"
                                        title="Locked (Read-Only Role)"
                                    />
                                ) : (
                                    <div className="hidden group-hover:flex items-center gap-1">
                                        <button
                                            type="button"
                                            onClick={(e) => {
                                                e.stopPropagation();
                                                setRenamingFileId(file.id);
                                                setRenameValue(file.name);
                                            }}
                                            className="p-1 rounded hover:bg-slate-700/70 text-slate-400 hover:text-cyan-300"
                                            title="Rename file"
                                        >
                                            <Edit3 className="w-3 h-3" />
                                        </button>
                                        <button
                                            type="button"
                                            onClick={(e) => handleDeleteClick(e, file)}
                                            className="p-1 rounded hover:bg-rose-500/20 text-slate-400 hover:text-rose-400"
                                            title="Delete file"
                                        >
                                            <Trash2 className="w-3 h-3" />
                                        </button>
                                    </div>
                                )}
                            </div>
                        </div>
                    );
                })}
            </div>

            {/* Sidebar Footer: Live RBAC Role Manager & Self-Role Simulator */}
            <div className="p-3 border-t border-slate-800/80 bg-[#0B101D] space-y-3">
                {/* Quick Self-Role Simulator for Single-Browser Testing */}
                <div className="space-y-1.5">
                    <div className="flex items-center justify-between text-[10px] font-mono uppercase tracking-wider text-slate-400">
                        <span className="flex items-center gap-1">
                            <Shield className="w-3 h-3 text-cyan-400" />
                            Active RBAC Role
                        </span>
                        <span className="text-cyan-400 font-semibold">{callerRole}</span>
                    </div>

                    <div className="grid grid-cols-3 gap-1 bg-[#090D16] p-1 rounded-lg border border-slate-800">
                        {(['OWNER', 'EDITOR', 'VIEWER'] as CollaboratorRole[]).map((r) => {
                            const active = callerRole === r;
                            return (
                                <button
                                    key={r}
                                    type="button"
                                    onClick={() => handleRoleSelect(currentUserId, r, true)}
                                    className={`py-1 rounded text-[10px] font-mono font-semibold transition ${active
                                            ? r === 'VIEWER'
                                                ? 'bg-violet-500/25 text-violet-200 border border-violet-500/40'
                                                : r === 'EDITOR'
                                                    ? 'bg-cyan-500/25 text-cyan-200 border border-cyan-500/40'
                                                    : 'bg-emerald-500/25 text-emerald-200 border border-emerald-500/40'
                                            : 'text-slate-400 hover:text-white'
                                        }`}
                                    title={`Switch your active SQLite role to ${r} to test RBAC permissions`}
                                >
                                    {r}
                                </button>
                            );
                        })}
                    </div>
                </div>

                {/* Collaborator Role Manager (OWNER can promote/demote any member) */}
                <div className="space-y-1.5">
                    <div className="flex items-center justify-between text-[10px] font-mono uppercase tracking-wider text-slate-400">
                        <span className="flex items-center gap-1">
                            <Users className="w-3 h-3 text-emerald-400" />
                            Team RBAC ({members.length})
                        </span>
                        {callerRole === 'OWNER' ? (
                            <span className="text-[9px] text-emerald-400">OWNER MANAGE</span>
                        ) : (
                            <span className="text-[9px] text-slate-500 flex items-center gap-0.5">
                                <Eye className="w-2.5 h-2.5" /> VIEW
                            </span>
                        )}
                    </div>

                    <div className="max-h-32 overflow-y-auto space-y-1 pr-0.5">
                        {members.map((member) => {
                            const isOnline = collaborators.some(
                                (c) => c.userId === member.userId
                            );
                            return (
                                <div
                                    key={member.userId}
                                    className="px-2 py-1.5 rounded-lg bg-[#090D16]/90 border border-slate-800/80 flex items-center justify-between gap-2 text-xs"
                                >
                                    <div className="flex items-center gap-2 min-w-0">
                                        <span className="relative flex h-2 w-2 shrink-0">
                                            <span
                                                className="w-2 h-2 rounded-full"
                                                style={{ backgroundColor: member.avatarColor }}
                                            />
                                            {isOnline && (
                                                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                                            )}
                                        </span>
                                        <span className="font-mono text-[11px] text-slate-200 truncate">
                                            @{member.username}
                                        </span>
                                    </div>

                                    {callerRole === 'OWNER' ? (
                                        <select
                                            value={member.role}
                                            onChange={(e) =>
                                                handleRoleSelect(
                                                    member.userId,
                                                    e.target.value as CollaboratorRole,
                                                    member.userId === currentUserId
                                                )
                                            }
                                            className="bg-[#0F1624] border border-slate-700 rounded px-1.5 py-0.5 text-[10px] font-mono text-cyan-300 focus:outline-none focus:border-cyan-500"
                                        >
                                            <option value="OWNER">OWNER</option>
                                            <option value="EDITOR">EDITOR</option>
                                            <option value="VIEWER">VIEWER</option>
                                        </select>
                                    ) : (
                                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                                            {member.role}
                                        </span>
                                    )}
                                </div>
                            );
                        })}
                    </div>
                </div>
            </div>
        </aside>
    );
};

export default SidebarFileTree;