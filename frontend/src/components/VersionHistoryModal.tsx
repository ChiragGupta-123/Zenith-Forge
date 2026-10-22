import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { DiffEditor } from '@monaco-editor/react';
import { Socket } from 'socket.io-client';
import * as Y from 'yjs';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import {
    History,
    GitCommit,
    RotateCcw,
    ShieldCheck,
    ShieldAlert,
    Lock,
    Plus,
    X,
    CheckCircle2,
    Clock,
    User,
    Hash,
    Columns,
    AlignJustify,
    Loader2,
    Sparkles,
    FileCode2,
    RefreshCw,
} from 'lucide-react';
import {
    CollaboratorRole,
    ProjectFile,
    VersionSnapshot,
} from '../types';
import {
    createFileSnapshot,
    extractApiErrorMessage,
    fetchFileSnapshots,
    restoreFileSnapshot,
} from '../services/api';

function cn(...inputs: (string | undefined | null | false)[]) {
    return twMerge(clsx(inputs));
}

export interface VersionHistoryModalProps {
    isOpen?: boolean;
    onClose: () => void;
    projectId: string;
    file?: ProjectFile | null;
    activeFile?: ProjectFile | null;
    liveContent?: string;
    currentCode?: string;
    userRole?: CollaboratorRole;
    callerRole?: CollaboratorRole;
    socket?: Socket | null;
    ydoc?: Y.Doc | null;
    initialSnapshots?: VersionSnapshot[];
    onSnapshotCreated?: (snapshot: VersionSnapshot) => void;
    onSnapshotRestored?: (
        restoredFile: ProjectFile,
        restoredSnapshot: VersionSnapshot
    ) => void;
    onApplyRestoredContent?: (newContent: string) => void;
}

/**
 * Computes line-level diff metrics (+added / -removed) between historical snapshot and live buffer.
 */
function computeLineDiffMetrics(
    originalText: string,
    modifiedText: string
): { added: number; removed: number; identical: boolean } {
    if (originalText === modifiedText) {
        return { added: 0, removed: 0, identical: true };
    }
    const origLines = originalText.split(/\r?\n/);
    const modLines = modifiedText.split(/\r?\n/);

    const origCounts = new Map<string, number>();
    for (const line of origLines) {
        origCounts.set(line, (origCounts.get(line) || 0) + 1);
    }

    let common = 0;
    for (const line of modLines) {
        const count = origCounts.get(line) || 0;
        if (count > 0) {
            common += 1;
            origCounts.set(line, count - 1);
        }
    }

    const removed = Math.max(0, origLines.length - common);
    const added = Math.max(0, modLines.length - common);
    return { added, removed, identical: false };
}

function mapMonacoLanguage(lang: string): string {
    const normalized = lang.toLowerCase();
    if (normalized === 'cpp') return 'cpp';
    if (normalized === 'python') return 'python';
    if (normalized === 'javascript') return 'javascript';
    if (normalized === 'typescript') return 'typescript';
    if (normalized === 'java') return 'java';
    if (normalized === 'json') return 'json';
    return 'markdown';
}

export const VersionHistoryModal: React.FC<VersionHistoryModalProps> = ({
    isOpen = true,
    onClose,
    projectId,
    file,
    activeFile,
    liveContent,
    currentCode,
    userRole,
    callerRole,
    socket,
    ydoc,
    initialSnapshots,
    onSnapshotCreated,
    onSnapshotRestored,
    onApplyRestoredContent,
}) => {
    const targetFile = file ?? activeFile ?? null;
    const effectiveRole: CollaboratorRole = userRole ?? callerRole ?? 'EDITOR';
    const isViewer = effectiveRole === 'VIEWER';

    const [snapshots, setSnapshots] = useState<VersionSnapshot[]>(
        initialSnapshots || []
    );
    const [selectedSnapshotId, setSelectedSnapshotId] = useState<string | null>(
        initialSnapshots?.[0]?.id || null
    );
    const [loadingSnapshots, setLoadingSnapshots] = useState<boolean>(false);
    const [snapshotLabel, setSnapshotLabel] = useState<string>('');
    const [creatingSnapshot, setCreatingSnapshot] = useState<boolean>(false);
    const [restoringSnapshot, setRestoringSnapshot] = useState<boolean>(false);
    const [sideBySide, setSideBySide] = useState<boolean>(true);
    const [errorMessage, setErrorMessage] = useState<string | null>(null);
    const [successMessage, setSuccessMessage] = useState<string | null>(null);

    // Derive current live CRDT buffer string
    const effectiveLiveBuffer = useMemo(() => {
        if (typeof liveContent === 'string') return liveContent;
        if (typeof currentCode === 'string') return currentCode;
        if (ydoc) {
            try {
                const ytext = ydoc.getText('monaco').toString();
                if (ytext.length > 0) return ytext;
            } catch {
                // Fall back to targetFile.content
            }
        }
        return targetFile?.content ?? '';
    }, [liveContent, currentCode, ydoc, targetFile]);

    const loadSnapshots = useCallback(async () => {
        if (!targetFile?.id) return;
        setLoadingSnapshots(true);
        setErrorMessage(null);
        try {
            const list = await fetchFileSnapshots(targetFile.id);
            setSnapshots(list);
            setSelectedSnapshotId((prev) => {
                if (prev && list.some((s) => s.id === prev)) return prev;
                return list[0]?.id || null;
            });
        } catch (err) {
            setErrorMessage(extractApiErrorMessage(err));
        } finally {
            setLoadingSnapshots(false);
        }
    }, [targetFile?.id]);

    useEffect(() => {
        if (isOpen && targetFile?.id) {
            void loadSnapshots();
        }
    }, [isOpen, targetFile?.id, loadSnapshots]);

    // Listen for live `snapshot-restored` broadcasts from peers while modal is open
    useEffect(() => {
        if (!socket || !isOpen || !targetFile?.id) return;

        const handleRemoteRestore = (payload: {
            fileId?: string;
            restoredBy?: string;
            snapshotId?: string;
        }) => {
            if (payload.fileId === targetFile.id) {
                void loadSnapshots();
                setSuccessMessage(
                    `Live buffer synchronized with snapshot restored by @${payload.restoredBy || 'peer'
                    }.`
                );
            }
        };

        socket.on('snapshot-restored', handleRemoteRestore);
        return () => {
            socket.off('snapshot-restored', handleRemoteRestore);
        };
    }, [socket, isOpen, targetFile?.id, loadSnapshots]);

    const selectedSnapshot = useMemo(
        () => snapshots.find((s) => s.id === selectedSnapshotId) || snapshots[0] || null,
        [snapshots, selectedSnapshotId]
    );

    const diffMetrics = useMemo(() => {
        if (!selectedSnapshot) {
            return { added: 0, removed: 0, identical: true };
        }
        return computeLineDiffMetrics(
            selectedSnapshot.content,
            effectiveLiveBuffer
        );
    }, [selectedSnapshot, effectiveLiveBuffer]);

    if (!isOpen || !targetFile) {
        return null;
    }

    const handleCreateSnapshot = async (e: React.FormEvent) => {
        e.preventDefault();
        if (isViewer || creatingSnapshot) return;

        const cleanLabel =
            snapshotLabel.trim() ||
            `Checkpoint v${targetFile.version} (${new Date().toLocaleTimeString()})`;

        setCreatingSnapshot(true);
        setErrorMessage(null);
        setSuccessMessage(null);

        try {
            const created = await createFileSnapshot(
                targetFile.id,
                cleanLabel,
                effectiveLiveBuffer
            );
            setSnapshots((prev) => [
                created,
                ...prev.filter((s) => s.id !== created.id),
            ]);
            setSelectedSnapshotId(created.id);
            setSnapshotLabel('');
            setSuccessMessage(
                `Saved immutable snapshot "${created.label}" with SHA-256 hash ${created.hash.slice(
                    0,
                    16
                )}...`
            );
            if (onSnapshotCreated) {
                onSnapshotCreated(created);
            }
        } catch (err) {
            setErrorMessage(extractApiErrorMessage(err));
        } finally {
            setCreatingSnapshot(false);
        }
    };

    /**
     * 1-Click Rollback & Restore to All Peers:
     * 1. Verifies SHA-256 content hash on the server via `POST /api/files/:fileId/restore/:snapshotId`.
     * 2. Overwrites the local `Y.Doc` shared text (`ydoc.getText('monaco')`) inside an atomic transaction
     *    so local Monaco + Yjs state updates immediately.
     * 3. Emits `snapshot-restored` (and `yjs-update`) over Socket.IO so the authoritative server `Y.Doc`
     *    and all connected browsers synchronize in real time (instant recovery from rogue edits).
     */
    const handleRollbackAndRestore = async () => {
        if (!selectedSnapshot || isViewer || restoringSnapshot) return;

        setRestoringSnapshot(true);
        setErrorMessage(null);
        setSuccessMessage(null);

        try {
            const { file: updatedFile, restoredSnapshot } =
                await restoreFileSnapshot(targetFile.id, selectedSnapshot.id);

            // 1. Overwrite live Y.Doc inside a transaction if a Y.Doc reference was passed
            if (ydoc) {
                let encodedUpdate: Uint8Array | null = null;
                const updateListener = (update: Uint8Array) => {
                    encodedUpdate = update;
                };
                ydoc.on('update', updateListener);
                try {
                    ydoc.transact(() => {
                        const ytext = ydoc.getText('monaco');
                        if (ytext.length > 0) {
                            ytext.delete(0, ytext.length);
                        }
                        ytext.insert(0, restoredSnapshot.content);
                    }, 'snapshot-rollback');
                } finally {
                    ydoc.off('update', updateListener);
                }

                if (socket && encodedUpdate) {
                    socket.emit('yjs-update', {
                        projectId,
                        fileId: targetFile.id,
                        update: Array.from(encodedUpdate as Uint8Array),
                        content: restoredSnapshot.content,
                    });
                }
            }

            // 2. Broadcast authoritative `snapshot-restored` event to synchronize all connected peers
            if (socket) {
                socket.emit('snapshot-restored', {
                    projectId,
                    fileId: targetFile.id,
                    snapshotId: restoredSnapshot.id,
                });
            }

            if (onApplyRestoredContent) {
                onApplyRestoredContent(restoredSnapshot.content);
            }
            if (onSnapshotRestored) {
                onSnapshotRestored(updatedFile, restoredSnapshot);
            }

            setSuccessMessage(
                `Rolled back "${targetFile.name}" to "${restoredSnapshot.label
                }" (SHA-256 verified: ${restoredSnapshot.hash.slice(
                    0,
                    12
                )}...) and synchronized all connected peers.`
            );
        } catch (err) {
            setErrorMessage(extractApiErrorMessage(err));
        } finally {
            setRestoringSnapshot(false);
        }
    };

    return (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4 select-none">
            <div className="w-full max-w-6xl h-[86vh] rounded-2xl bg-[#090D16] border border-slate-800/90 shadow-2xl flex flex-col overflow-hidden">
                {/* Modal Header */}
                <div className="px-5 py-3.5 bg-[#0F1624] border-b border-slate-800/80 flex flex-wrap items-center justify-between gap-3 shrink-0">
                    <div className="flex items-center gap-3">
                        <div className="w-9 h-9 rounded-xl bg-cyan-500/15 border border-cyan-500/40 flex items-center justify-center">
                            <History className="w-4 h-4 text-cyan-400" />
                        </div>
                        <div>
                            <div className="flex items-center gap-2">
                                <h2 className="text-sm font-bold text-white">
                                    Recoverable Version History &amp; SHA-256 Diff Studio
                                </h2>
                                <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 flex items-center gap-1">
                                    <ShieldCheck className="w-3 h-3 text-emerald-400" />
                                    SHA-256 Integrity Enforced
                                </span>
                            </div>
                            <p className="text-[11px] font-mono text-slate-400">
                                File:{' '}
                                <strong className="text-cyan-300">
                                    {targetFile.name}
                                </strong>{' '}
                                ({targetFile.language.toUpperCase()}) • Compare any
                                immutable checkpoint against live Yjs CRDT buffer
                            </p>
                        </div>
                    </div>

                    <div className="flex items-center gap-2">
                        {/* Side-by-Side vs Inline Diff Mode Toggle */}
                        <button
                            type="button"
                            onClick={() => setSideBySide((prev) => !prev)}
                            className="px-2.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs font-mono text-slate-300 flex items-center gap-1.5 transition"
                            title="Toggle Side-by-Side vs Inline Diff View"
                        >
                            {sideBySide ? (
                                <>
                                    <Columns className="w-3.5 h-3.5 text-cyan-400" />
                                    <span>Side-by-Side Diff</span>
                                </>
                            ) : (
                                <>
                                    <AlignJustify className="w-3.5 h-3.5 text-violet-400" />
                                    <span>Inline Unified Diff</span>
                                </>
                            )}
                        </button>

                        <button
                            type="button"
                            onClick={() => void loadSnapshots()}
                            className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-400 hover:text-white transition"
                            title="Refresh snapshots"
                        >
                            <RefreshCw
                                className={cn(
                                    'w-3.5 h-3.5',
                                    loadingSnapshots && 'animate-spin text-cyan-400'
                                )}
                            />
                        </button>

                        <button
                            type="button"
                            onClick={onClose}
                            className="px-2.5 py-1.5 rounded-lg bg-slate-900 hover:bg-rose-500/20 border border-slate-800 hover:border-rose-500/40 text-slate-400 hover:text-rose-200 text-xs font-mono flex items-center gap-1 transition"
                        >
                            <X className="w-3.5 h-3.5" />
                            <span>ESC</span>
                        </button>
                    </div>
                </div>

                {/* Status / Alert Feedback Banners */}
                {errorMessage && (
                    <div className="mx-5 mt-3 p-3 rounded-xl bg-rose-500/15 border border-rose-500/40 text-rose-200 text-xs font-mono flex items-center justify-between">
                        <div className="flex items-center gap-2">
                            <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />
                            <span>{errorMessage}</span>
                        </div>
                        <button
                            type="button"
                            onClick={() => setErrorMessage(null)}
                            className="text-[10px] text-rose-300 hover:text-white"
                        >
                            DISMISS
                        </button>
                    </div>
                )}

                {successMessage && (
                    <div className="mx-5 mt-3 p-3 rounded-xl bg-emerald-500/15 border border-emerald-500/40 text-emerald-200 text-xs font-mono flex items-center justify-between">
                        <div className="flex items-center gap-2">
                            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                            <span>{successMessage}</span>
                        </div>
                        <button
                            type="button"
                            onClick={() => setSuccessMessage(null)}
                            className="text-[10px] text-emerald-300 hover:text-white"
                        >
                            OK
                        </button>
                    </div>
                )}

                {/* Main Split Layout: Left Snapshot Timeline + Right Side-by-Side Monaco DiffEditor */}
                <div className="flex-1 min-h-0 flex flex-col lg:flex-row overflow-hidden">
                    {/* Left Column: Save New Snapshot Form + Immutable Snapshot List */}
                    <div className="w-full lg:w-80 shrink-0 bg-[#0F1624]/90 border-b lg:border-b-0 lg:border-r border-slate-800/80 flex flex-col min-h-0">
                        {/* Create Immutable Snapshot Form */}
                        <div className="p-3.5 border-b border-slate-800/80 space-y-2.5">
                            <div className="flex items-center justify-between">
                                <span className="text-[11px] font-mono uppercase tracking-wider text-cyan-400 font-semibold flex items-center gap-1.5">
                                    <Sparkles className="w-3.5 h-3.5" />
                                    Save Immutable Snapshot
                                </span>
                                {isViewer && (
                                    <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-violet-500/15 text-violet-300 border border-violet-500/30 flex items-center gap-1">
                                        <Lock className="w-2.5 h-2.5" />
                                        VIEWER
                                    </span>
                                )}
                            </div>

                            <form
                                onSubmit={handleCreateSnapshot}
                                className="space-y-2"
                            >
                                <input
                                    type="text"
                                    disabled={isViewer || creatingSnapshot}
                                    maxLength={120}
                                    value={snapshotLabel}
                                    onChange={(e) =>
                                        setSnapshotLabel(e.target.value)
                                    }
                                    placeholder={
                                        isViewer
                                            ? 'Read-only role cannot create snapshots'
                                            : 'e.g. Pre-refactor verified baseline'
                                    }
                                    className="w-full px-3 py-2 rounded-xl bg-[#090D16] border border-slate-800 text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 disabled:opacity-50"
                                />
                                <button
                                    type="submit"
                                    disabled={isViewer || creatingSnapshot}
                                    className={cn(
                                        'w-full py-2 px-3 rounded-xl text-xs font-mono font-semibold transition flex items-center justify-center gap-1.5 border',
                                        isViewer
                                            ? 'bg-violet-500/10 border-violet-500/30 text-violet-300/60 cursor-not-allowed'
                                            : 'bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-300 border-cyan-500/40'
                                    )}
                                >
                                    {creatingSnapshot ? (
                                        <>
                                            <Loader2 className="w-3.5 h-3.5 animate-spin" />
                                            <span>Computing SHA-256...</span>
                                        </>
                                    ) : isViewer ? (
                                        <>
                                            <Lock className="w-3.5 h-3.5" />
                                            <span>Locked for VIEWER</span>
                                        </>
                                    ) : (
                                        <>
                                            <Plus className="w-3.5 h-3.5" />
                                            <span>
                                                Checkpoint Live Buffer (SHA-256)
                                            </span>
                                        </>
                                    )}
                                </button>
                            </form>
                        </div>

                        {/* Snapshot Timeline List */}
                        <div className="px-3.5 py-2 border-b border-slate-800/60 flex items-center justify-between text-[10px] font-mono uppercase tracking-wider text-slate-400">
                            <span>Version Checkpoints ({snapshots.length})</span>
                            <span>SHA-256 Digest</span>
                        </div>

                        <div className="flex-1 overflow-y-auto p-2.5 space-y-2">
                            {loadingSnapshots && snapshots.length === 0 ? (
                                <div className="p-6 text-center text-xs font-mono text-slate-500 flex flex-col items-center gap-2">
                                    <Loader2 className="w-4 h-4 animate-spin text-cyan-400" />
                                    <span>Loading SHA-256 checkpoints...</span>
                                </div>
                            ) : snapshots.length === 0 ? (
                                <div className="p-6 text-center text-xs font-mono text-slate-500">
                                    No snapshots recorded for this file yet.
                                </div>
                            ) : (
                                snapshots.map((snap, index) => {
                                    const isSelected =
                                        selectedSnapshot?.id === snap.id;
                                    const isMatchesLive =
                                        snap.content === effectiveLiveBuffer;

                                    return (
                                        <button
                                            key={snap.id}
                                            type="button"
                                            onClick={() =>
                                                setSelectedSnapshotId(snap.id)
                                            }
                                            className={cn(
                                                'w-full text-left p-3 rounded-xl border transition space-y-1.5',
                                                isSelected
                                                    ? 'bg-cyan-500/12 border-cyan-500/50 text-white shadow-md shadow-cyan-950/30'
                                                    : 'bg-[#090D16]/80 border-slate-800/80 hover:border-slate-700 text-slate-300'
                                            )}
                                        >
                                            <div className="flex items-start justify-between gap-2">
                                                <div className="flex items-center gap-1.5 min-w-0">
                                                    <GitCommit
                                                        className={cn(
                                                            'w-3.5 h-3.5 shrink-0',
                                                            isSelected
                                                                ? 'text-cyan-400'
                                                                : 'text-slate-500'
                                                        )}
                                                    />
                                                    <span className="text-xs font-semibold truncate">
                                                        {snap.label}
                                                    </span>
                                                </div>
                                                <span className="shrink-0 px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-900 border border-slate-700 text-cyan-300">
                                                    v{snap.version}
                                                    {index === 0 ? ' • LATEST' : ''}
                                                </span>
                                            </div>

                                            <div className="flex items-center justify-between text-[10px] font-mono text-slate-400">
                                                <span className="flex items-center gap-1">
                                                    <User className="w-3 h-3 text-slate-500" />
                                                    @{snap.createdByUsername}
                                                </span>
                                                <span className="flex items-center gap-1">
                                                    <Clock className="w-3 h-3 text-slate-500" />
                                                    {new Date(
                                                        snap.createdAt
                                                    ).toLocaleTimeString()}
                                                </span>
                                            </div>

                                            <div className="pt-1 border-t border-slate-800/70 flex items-center justify-between text-[10px] font-mono">
                                                <span
                                                    className="text-emerald-400/90 flex items-center gap-1"
                                                    title={`SHA-256: ${snap.hash}`}
                                                >
                                                    <Hash className="w-2.5 h-2.5" />
                                                    {snap.hash.slice(0, 14)}...
                                                </span>
                                                {isMatchesLive ? (
                                                    <span className="px-1.5 py-0.2 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 text-[9px]">
                                                        MATCHES LIVE
                                                    </span>
                                                ) : (
                                                    <span className="text-slate-500 text-[9px]">
                                                        {snap.content.length} chars
                                                    </span>
                                                )}
                                            </div>
                                        </button>
                                    );
                                })
                            )}
                        </div>
                    </div>

                    {/* Right Column: Side-by-Side Monaco DiffEditor + Rollback Action Bar */}
                    <div className="flex-1 flex flex-col min-w-0 min-h-0 bg-[#090D16]">
                        {/* Diff Comparison Header & Rollback Button */}
                        <div className="px-4 py-2.5 bg-[#0B101B] border-b border-slate-800/80 flex flex-wrap items-center justify-between gap-3 shrink-0">
                            {selectedSnapshot ? (
                                <div className="flex flex-wrap items-center gap-2.5 text-xs font-mono">
                                    <span className="px-2.5 py-1 rounded-lg bg-violet-500/15 border border-violet-500/30 text-violet-300 flex items-center gap-1.5">
                                        <History className="w-3.5 h-3.5 text-violet-400" />
                                        Original: {selectedSnapshot.label} (v
                                        {selectedSnapshot.version})
                                    </span>

                                    <span className="text-slate-500">vs</span>

                                    <span className="px-2.5 py-1 rounded-lg bg-cyan-500/15 border border-cyan-500/30 text-cyan-300 flex items-center gap-1.5">
                                        <FileCode2 className="w-3.5 h-3.5 text-cyan-400" />
                                        Modified: Current Live CRDT Buffer
                                    </span>

                                    {/* Line Diff Summary Badges */}
                                    {diffMetrics.identical ? (
                                        <span className="px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-[11px]">
                                            Identical to Live Buffer
                                        </span>
                                    ) : (
                                        <div className="flex items-center gap-1.5 text-[11px]">
                                            <span className="px-2 py-0.5 rounded bg-emerald-500/15 border border-emerald-500/30 text-emerald-300">
                                                +{diffMetrics.added} lines in live
                                            </span>
                                            <span className="px-2 py-0.5 rounded bg-rose-500/15 border border-rose-500/30 text-rose-300">
                                                -{diffMetrics.removed} lines from
                                                snapshot
                                            </span>
                                        </div>
                                    )}
                                </div>
                            ) : (
                                <span className="text-xs font-mono text-slate-400">
                                    Select a snapshot on the left to inspect diff
                                </span>
                            )}

                            {/* 1-Click Rollback & Restore to All Peers Button */}
                            {selectedSnapshot && (
                                <div
                                    title={
                                        isViewer
                                            ? 'VIEWER role cannot rollback files. Switch to OWNER or EDITOR.'
                                            : 'Verify SHA-256 digest, overwrite live Y.Doc inside a transaction, and sync all connected browsers immediately'
                                    }
                                >
                                    <button
                                        type="button"
                                        onClick={handleRollbackAndRestore}
                                        disabled={isViewer || restoringSnapshot}
                                        className={cn(
                                            'px-3.5 py-1.5 rounded-xl text-xs font-mono font-semibold transition flex items-center gap-2 border',
                                            isViewer
                                                ? 'bg-violet-500/10 border-violet-500/30 text-violet-300/60 cursor-not-allowed'
                                                : 'bg-gradient-to-r from-emerald-500 to-cyan-500 hover:from-emerald-400 hover:to-cyan-400 text-slate-950 border-emerald-400 shadow-lg shadow-emerald-950/50'
                                        )}
                                    >
                                        {restoringSnapshot ? (
                                            <>
                                                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                                                <span>
                                                    Verifying SHA-256 &amp; Syncing
                                                    Peers...
                                                </span>
                                            </>
                                        ) : isViewer ? (
                                            <>
                                                <Lock className="w-3.5 h-3.5" />
                                                <span>
                                                    Rollback Locked (VIEWER)
                                                </span>
                                            </>
                                        ) : (
                                            <>
                                                <RotateCcw className="w-3.5 h-3.5 stroke-[2.2]" />
                                                <span>
                                                    Rollback &amp; Restore to All
                                                    Peers
                                                </span>
                                            </>
                                        )}
                                    </button>
                                </div>
                            )}
                        </div>

                        {/* SHA-256 Cryptographic Metadata Strip */}
                        {selectedSnapshot && (
                            <div className="px-4 py-1.5 bg-[#090D16] border-b border-slate-800/70 flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono text-slate-400">
                                <div className="flex items-center gap-2 truncate">
                                    <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                                    <span className="text-slate-400">
                                        Snapshot SHA-256:
                                    </span>
                                    <code className="text-emerald-300 truncate">
                                        {selectedSnapshot.hash}
                                    </code>
                                </div>
                                <div className="text-slate-500">
                                    Author: @{selectedSnapshot.createdByUsername} •{' '}
                                    {new Date(
                                        selectedSnapshot.createdAt
                                    ).toLocaleString()}
                                </div>
                            </div>
                        )}

                        {/* Monaco Side-by-Side DiffEditor */}
                        <div className="flex-1 min-h-0 relative">
                            {selectedSnapshot ? (
                                <DiffEditor
                                    height="100%"
                                    theme="vs-dark"
                                    language={mapMonacoLanguage(
                                        targetFile.language
                                    )}
                                    original={selectedSnapshot.content}
                                    modified={effectiveLiveBuffer}
                                    options={{
                                        renderSideBySide: sideBySide,
                                        readOnly: true,
                                        originalEditable: false,
                                        minimap: { enabled: false },
                                        fontSize: 12,
                                        fontFamily:
                                            "'JetBrains Mono', 'Fira Code', Menlo, Monaco, Consolas, monospace",
                                        scrollBeyondLastLine: false,
                                        automaticLayout: true,
                                        renderOverviewRuler: true,
                                        diffWordWrap: 'on',
                                        padding: { top: 12, bottom: 12 },
                                    }}
                                />
                            ) : (
                                <div className="h-full flex items-center justify-center text-xs font-mono text-slate-500">
                                    Select a snapshot from the timeline to compare
                                    against the live CRDT buffer.
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default VersionHistoryModal;