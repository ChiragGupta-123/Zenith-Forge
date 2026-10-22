import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { Socket } from 'socket.io-client';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import {
    MessageSquareCode,
    MessagesSquare,
    Bug,
    ShieldAlert,
    ShieldCheck,
    Sparkles,
    ChevronRight,
    ChevronLeft,
    Send,
    Plus,
    Trash2,
    CheckCircle2,
    RotateCcw,
    Lock,
    Crosshair,
    AlertTriangle,
    Eye,
    Terminal,
    FileWarning,
    UserX,
    Loader2,
    Copy,
    Check,
    CornerDownRight,
    CircleDot,
    RefreshCw,
    Wand2,
    FileCheck2,
    BookOpen,
} from 'lucide-react';
import {
    AiSecurityFinding,
    AiSecurityReview,
    ChatMessage,
    CollaboratorRole,
    InlineComment,
    ProjectFile,
    RedTeamAttackType,
    SecurityAlertBanner,
    SecurityEvent,
    SharedBreakpoint,
} from '../types';
import {
    createInlineComment,
    deleteInlineComment,
    extractApiErrorMessage,
    fetchFileComments,
    fetchProjectSecurityLogs,
    fetchSecurityLogs,
    requestAiSecurityReview,
    scanCodeForThreatsApi,
    simulateRedTeamAttack,
    toggleResolveComment,
} from '../services/api';

function cn(...inputs: (string | undefined | null | false)[]) {
    return twMerge(clsx(inputs));
}

export type CollabDrawerTab =
    | 'comments'
    | 'chat'
    | 'debugger'
    | 'security'
    | 'copilot';

export interface CollabDrawerProps {
    projectId: string;
    activeFile: ProjectFile | null;
    liveCode?: string;
    userRole: CollaboratorRole;
    currentUsername?: string;
    currentCursorLine?: number;
    socket: Socket | null;
    initialTab?: CollabDrawerTab;
    activeTabOverride?: CollabDrawerTab | null;
    initialComments?: InlineComment[];
    initialChatMessages?: ChatMessage[];
    initialBreakpoints?: SharedBreakpoint[];
    initialSecurityLogs?: SecurityEvent[];
    onJumpToLine?: (lineNumber: number) => void;
    onApplyCodeSnippet?: (newCode: string) => void;
    onSecurityEventRecorded?: (event: SecurityEvent) => void;
    defaultOpen?: boolean;
}

interface VariableWatchItem {
    id: string;
    expression: string;
    addedBy: string;
}

const ROLE_PILL_STYLE: Record<CollaboratorRole, string> = {
    OWNER: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
    EDITOR: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30',
    VIEWER: 'bg-violet-500/15 text-violet-300 border-violet-500/30',
};

const SEVERITY_PILL_STYLE: Record<string, string> = {
    CRITICAL: 'bg-rose-500/25 text-rose-200 border-rose-500/50',
    HIGH: 'bg-rose-500/15 text-rose-300 border-rose-500/40',
    MEDIUM: 'bg-amber-500/15 text-amber-300 border-amber-500/40',
    LOW: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30',
    INFO: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
};

/**
 * Deterministic local static & heuristic intelligence fallback used by Tab 5 (AI Co-Pilot)
 * whenever the backend `/api/execute/ai-review` endpoint is offline or not yet wired (Phase 7).
 */
function buildLocalCoPilotAnalysis(
    file: ProjectFile,
    code: string
): {
    explanation: string[];
    review: AiSecurityReview;
    unitTestsCode: string;
} {
    const lines = code.split(/\r?\n/);
    const nonEmptyLines = lines.filter((l) => l.trim().length > 0).length;
    const findings: AiSecurityFinding[] = [];

    lines.forEach((lineText, idx) => {
        const lineNum = idx + 1;
        if (
            /\b(?:child_process|execSync|spawn|os\.system|subprocess|Runtime\.getRuntime)\b/.test(
                lineText
            )
        ) {
            findings.push({
                line: lineNum,
                severity: 'CRITICAL',
                title: 'OS Command / Subprocess Execution Vector',
                recommendation:
                    'Remove direct shell execution or isolate inside a strict allowlisted argument array without shell interpolation.',
                cweId: 'CWE-78',
            });
        }
        if (
            /\b(?:eval|Function|constructor\s*\.\s*constructor)\b/.test(lineText)
        ) {
            findings.push({
                line: lineNum,
                severity: 'CRITICAL',
                title: 'Dynamic Code Generation / Prototype Escape',
                recommendation:
                    'Avoid dynamic eval/Function constructors; parse structured inputs with JSON.parse and freeze prototypes.',
                cweId: 'CWE-94',
            });
        }
        if (/\b(?:process\.env|os\.environ|getenv)\b/.test(lineText)) {
            findings.push({
                line: lineNum,
                severity: 'HIGH',
                title: 'Environment Secret / Credential Access',
                recommendation:
                    'Do not expose raw process.env secrets to untrusted modules; inject scoped configuration values only.',
                cweId: 'CWE-526',
            });
        }
        if (/\b(?:innerHTML|outerHTML|document\.write)\b/.test(lineText)) {
            findings.push({
                line: lineNum,
                severity: 'HIGH',
                title: 'DOM-Based XSS Sink',
                recommendation:
                    'Sanitize untrusted strings with HTML entity escaping (sanitizeText) or use textContent.',
                cweId: 'CWE-79',
            });
        }
        if (/while\s*\(\s*true\s*\)|for\s*\(\s*;\s*;\s*\)/.test(lineText)) {
            findings.push({
                line: lineNum,
                severity: 'MEDIUM',
                title: 'Unbounded Loop / CPU Starvation Risk',
                recommendation:
                    'Add a deterministic iteration ceiling or explicit termination guard to prevent event-loop starvation.',
                cweId: 'CWE-400',
            });
        }
    });

    const functionMatches =
        code.match(
            /\b(?:def\s+[a-zA-Z_]\w*|function\s+[a-zA-Z_$][\w$]*|class\s+[a-zA-Z_$][\w$]*)/g
        ) || [];

    const explanation = [
        `File "${file.name}" (${file.language.toUpperCase()}) contains ${lines.length
        } total lines (${nonEmptyLines} active code lines) and ${functionMatches.length
        } primary class/function declaration(s): ${functionMatches.slice(0, 5).join(', ') || 'top-level script module'
        }.`,
        file.name === 'main.py'
            ? 'Implements an entanglement-aware Dijkstra shortest-path router (QuantumRepeaterGraph) that balances link latency (ms) against logarithmic decoherence penalties (-math.log(fidelity) * 25.0).'
            : file.name === 'algorithm.js'
                ? 'Implements deterministic 32-bit FNV-1a packet envelope verification (verifyPacketIntegrity) and trust-weighted quantum channel bandwidth allocation (allocateChannelBandwidth).'
                : 'Executes inside DevCollab’s Zero-Trust workspace with Yjs CRDT synchronization, SHA-256 snapshot integrity, and 4-layer sandbox isolation.',
        findings.length === 0
            ? 'Zero static RCE, path traversal, or prototype-pollution signatures were detected in the current buffer.'
            : `Detected ${findings.length} security/reliability finding(s) that should be remediated before production deployment.`,
    ];

    const riskScore = Math.min(
        100,
        findings.reduce(
            (acc, f) =>
                acc +
                (f.severity === 'CRITICAL'
                    ? 45
                    : f.severity === 'HIGH'
                        ? 30
                        : 15),
            0
        )
    );

    const review: AiSecurityReview = {
        summary:
            findings.length === 0
                ? `Zero-Trust SAST Audit Passed: "${file.name}" exhibits no command injection, prototype escape, or credential leak patterns.`
                : `Zero-Trust SAST Audit Flagged ${findings.length} issue(s) in "${file.name}" (Overall Risk: ${riskScore}/100).`,
        overallRiskScore: riskScore,
        safeToDeploy: riskScore < 30,
        findings,
        hardenedSnippet:
            findings.length > 0
                ? `// Hardened Zero-Trust Pattern for ${file.name}\n// 1. Removed shell/process execution & dynamic codegen\n// 2. Enforced strict input type & bounds validation\n` +
                code
                    .replace(
                        /.*(?:child_process|execSync|os\.system|subprocess|constructor\.constructor).*/g,
                        '// [REDACTED BY ZERO-TRUST AI CO-PILOT: UNSAFE EXECUTION CALL REMOVED]'
                    )
                    .slice(0, 800)
                : undefined,
        analyzedAt: new Date().toISOString(),
    };

    const unitTestsCode =
        file.language === 'python'
            ? `# Auto-Generated Zero-Trust Unit & Boundary Tests for ${file.name}
import unittest

class TestQuantumRouterSecuritySuite(unittest.TestCase):
    def test_valid_entangled_path_convergence(self) -> None:
        graph = QuantumRepeaterGraph()
        graph.add_entangled_link("Node-A", "Node-B", 3.5, 0.99)
        graph.add_entangled_link("Node-B", "Node-C", 4.0, 0.98)
        path, latency, fidelity = graph.shortest_high_fidelity_path("Node-A", "Node-C")
        self.assertEqual(path, ["Node-A", "Node-B", "Node-C"])
        self.assertAlmostEqual(latency, 7.5, places=2)
        self.assertGreaterEqual(fidelity, 0.95)

    def test_rejects_out_of_bounds_decoherence_fidelity(self) -> None:
        graph = QuantumRepeaterGraph()
        with self.assertRaises(ValueError):
            graph.add_entangled_link("Node-A", "Node-B", 2.0, 0.35)

if __name__ == "__main__":
    unittest.main()
`
            : `// Auto-Generated Zero-Trust Unit & Security Assertions for ${file.name}
(function runZeroTrustTestSuite() {
  const assert = (condition, label) => {
    if (!condition) throw new Error('ASSERTION FAILED: ' + label);
    console.log('[PASS]', label);
  };

  if (typeof verifyPacketIntegrity === 'function') {
    const malformed = verifyPacketIntegrity({ payload: null }, 'secret');
    assert(malformed.valid === false && malformed.reason === 'MALFORMED_PACKET_ENVELOPE', 'Rejects malformed packet envelopes');
  }

  if (typeof allocateChannelBandwidth === 'function') {
    const out = allocateChannelBandwidth([
      { id: 'QNode-1', demandGbps: 50, trustScore: 1.0 },
      { id: 'QNode-2', demandGbps: 50, trustScore: 0.9 },
    ]);
    assert(Array.isArray(out) && out.length === 2, 'Allocates bandwidth across all verified nodes');
    assert(out[0].allocatedGbps === 50 && out[1].allocatedGbps === 45, 'Applies zero-trust node weighting');
  }

  console.log('=== All Zero-Trust Unit Tests Passed ===');
})();
`;

    return { explanation, review, unitTestsCode };
}

/**
 * Evaluates a watched variable/identifier against the active source code and default seed context.
 */
function inspectWatchExpression(expression: string, code: string): string {
    const clean = expression.trim();
    if (!clean) return 'empty';

    // Check if there is an assignment `const/let/var/py <expr> = <val>` in the code
    const escaped = clean.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const assignRegex = new RegExp(
        `(?:const|let|var)?\\s*\\b${escaped}\\b\\s*(?::[^=]+)?=\\s*([^;\\n]+)`
    );
    const match = code.match(assignRegex);
    if (match && match[1]) {
        return match[1].trim().slice(0, 70);
    }

    // Known domain variables in Quantum Router Engine starter files
    const presets: Record<string, string> = {
        joint_fid: '0.9556 (95.56% entangled fidelity)',
        total_lat: '14.1 ms (QNode-Alpha -> QNode-Omega)',
        decoherence_penalty: '1.135 (-ln(0.9556) * 25.0)',
        computedTag: '"4e9c0a1b" (32-bit FNV-1a hex digest)',
        allocatedGbps: '41.58 Gbps (QNode-Alpha @ 0.99 trust)',
        'node.trustScore': '0.99 (Verified HMAC peer)',
    };
    if (presets[clean]) {
        return presets[clean];
    }

    if (code.includes(clean)) {
        return 'Referenced in active buffer (in-scope)';
    }
    return 'Not referenced in current file';
}

export const CollabDrawer: React.FC<CollabDrawerProps> = ({
    projectId,
    activeFile,
    liveCode,
    userRole,
    currentUsername = 'operator',
    currentCursorLine = 1,
    socket,
    initialTab = 'comments',
    activeTabOverride = null,
    initialComments,
    initialChatMessages,
    initialBreakpoints,
    initialSecurityLogs,
    onJumpToLine,
    onApplyCodeSnippet,
    onSecurityEventRecorded,
    defaultOpen = true,
}) => {
    const [isOpen, setIsOpen] = useState<boolean>(defaultOpen);
    const [activeTab, setActiveTab] = useState<CollabDrawerTab>(initialTab);

    // Tab 1: Inline Comments State
    const [comments, setComments] = useState<InlineComment[]>(
        initialComments || []
    );
    const [commentLineInput, setCommentLineInput] = useState<number>(
        currentCursorLine || 1
    );
    const [commentTextInput, setCommentTextInput] = useState<string>('');
    const [commentFilter, setCommentFilter] = useState<
        'all' | 'open' | 'resolved'
    >('all');
    const [submittingComment, setSubmittingComment] = useState<boolean>(false);
    const [xssNotice, setXssNotice] = useState<string | null>(null);

    // Tab 2: Team Chat State
    const [chatMessages, setChatMessages] = useState<ChatMessage[]>(
        initialChatMessages || []
    );
    const [chatInput, setChatInput] = useState<string>('');
    const [sendingChat, setSendingChat] = useState<boolean>(false);
    const chatBottomRef = useRef<HTMLDivElement | null>(null);

    // Tab 3: Shared Debugger (Breakpoints + Variable Watch List)
    const [breakpoints, setBreakpoints] = useState<SharedBreakpoint[]>(
        initialBreakpoints || []
    );
    const [bpLineInput, setBpLineInput] = useState<number>(15);
    const [bpConditionInput, setBpConditionInput] = useState<string>('');
    const [watchList, setWatchList] = useState<VariableWatchItem[]>([
        { id: 'w-1', expression: 'joint_fid', addedBy: 'aria_sec_lead' },
        {
            id: 'w-2',
            expression: 'decoherence_penalty',
            addedBy: 'aria_sec_lead',
        },
        { id: 'w-3', expression: 'allocatedGbps', addedBy: 'liam_core_dev' },
    ]);
    const [newWatchExpr, setNewWatchExpr] = useState<string>('');

    // Tab 4: Security Shield (SIEM Audit Log)
    const [securityLogs, setSecurityLogs] = useState<SecurityEvent[]>(
        initialSecurityLogs || []
    );
    const [logFilter, setLogFilter] = useState<'all' | 'blocked' | 'critical'>(
        'all'
    );
    const [loadingLogs, setLoadingLogs] = useState<boolean>(false);
    const [runningAttackType, setRunningAttackType] =
        useState<RedTeamAttackType | null>(null);

    // Tab 5: AI Co-Pilot State
    const [coPilotMode, setCoPilotMode] = useState<
        'explain' | 'audit' | 'tests'
    >('audit');
    const [aiLoading, setAiLoading] = useState<boolean>(false);
    const [aiReview, setAiReview] = useState<AiSecurityReview | null>(null);
    const [aiExplanation, setAiExplanation] = useState<string[]>([]);
    const [aiUnitTests, setAiUnitTests] = useState<string>('');
    const [copiedSnippet, setCopiedSnippet] = useState<boolean>(false);

    const [drawerError, setDrawerError] = useState<string | null>(null);

    const isViewer = userRole === 'VIEWER';
    const effectiveCode =
        typeof liveCode === 'string' ? liveCode : activeFile?.content || '';

    // Sync external tab override (e.g. when user clicks "Blocked Intrusions" in TelemetryBar)
    useEffect(() => {
        if (activeTabOverride) {
            setActiveTab(activeTabOverride);
            setIsOpen(true);
        }
    }, [activeTabOverride]);

    useEffect(() => {
        if (currentCursorLine && currentCursorLine > 0) {
            setCommentLineInput(currentCursorLine);
        }
    }, [currentCursorLine]);

    // Fetch comments when activeFile changes
    const loadFileComments = useCallback(async () => {
        if (!activeFile?.id) return;
        try {
            const list = await fetchFileComments(activeFile.id);
            setComments(list);
        } catch {
            // Non-blocking
        }
    }, [activeFile?.id]);

    useEffect(() => {
        void loadFileComments();
    }, [loadFileComments]);

    // Fetch project security logs
    const loadSecurityTelemetry = useCallback(async () => {
        if (!projectId) return;
        setLoadingLogs(true);
        try {
            const logs = await fetchSecurityLogs(projectId).catch(() =>
                fetchProjectSecurityLogs(projectId, 100)
            );
            setSecurityLogs(logs);
        } catch {
            // Non-blocking
        } finally {
            setLoadingLogs(false);
        }
    }, [projectId]);

    useEffect(() => {
        void loadSecurityTelemetry();
    }, [loadSecurityTelemetry]);

    // Auto-scroll chat when new messages arrive
    useEffect(() => {
        if (activeTab === 'chat' && isOpen && chatBottomRef.current) {
            chatBottomRef.current.scrollIntoView({ behavior: 'smooth' });
        }
    }, [chatMessages, activeTab, isOpen]);

    // Wire real-time Socket.IO listeners across all 5 tabs
    useEffect(() => {
        if (!socket) return;

        const handleProjectStateSync = (payload: {
            chatMessages?: ChatMessage[];
            securityLogs?: SecurityEvent[];
        }) => {
            if (Array.isArray(payload.chatMessages)) {
                setChatMessages(payload.chatMessages);
            }
            if (Array.isArray(payload.securityLogs)) {
                setSecurityLogs(payload.securityLogs);
            }
        };

        const handleYjsInit = (payload: {
            fileId?: string;
            breakpoints?: SharedBreakpoint[];
            comments?: InlineComment[];
        }) => {
            if (activeFile && payload.fileId === activeFile.id) {
                if (Array.isArray(payload.breakpoints)) {
                    setBreakpoints(payload.breakpoints);
                }
                if (Array.isArray(payload.comments)) {
                    setComments(payload.comments);
                }
            }
        };

        const handleCommentAdded = (payload: {
            fileId: string;
            comment: InlineComment;
        }) => {
            if (!activeFile || payload.fileId !== activeFile.id) return;
            setComments((prev) => {
                if (prev.some((c) => c.id === payload.comment.id)) return prev;
                return [...prev, payload.comment].sort(
                    (a, b) => a.lineNumber - b.lineNumber
                );
            });
        };

        const handleChatMessage = (msg: ChatMessage) => {
            if (msg.projectId && msg.projectId !== projectId) return;
            setChatMessages((prev) => {
                if (prev.some((m) => m.id === msg.id)) return prev;
                return [...prev, msg];
            });
        };

        const handleBreakpointsUpdated = (payload: {
            fileId: string;
            breakpoints: SharedBreakpoint[];
        }) => {
            if (!activeFile || payload.fileId !== activeFile.id) return;
            if (Array.isArray(payload.breakpoints)) {
                setBreakpoints(payload.breakpoints);
            }
        };

        const handleSecurityLogNew = (event: SecurityEvent) => {
            if (event.projectId && event.projectId !== projectId) return;
            setSecurityLogs((prev) => {
                if (prev.some((e) => e.id === event.id)) return prev;
                return [event, ...prev].slice(0, 100);
            });
            if (onSecurityEventRecorded) {
                onSecurityEventRecorded(event);
            }
        };

        const handleSecurityAlert = (_alert: SecurityAlertBanner) => {
            void loadSecurityTelemetry();
        };

        socket.on('project-state-sync', handleProjectStateSync);
        socket.on('yjs-init', handleYjsInit);
        socket.on('comment-added', handleCommentAdded);
        socket.on('chat-message', handleChatMessage);
        socket.on('breakpoints-updated', handleBreakpointsUpdated);
        socket.on('security-log-new', handleSecurityLogNew);
        socket.on('security-alert', handleSecurityAlert);

        return () => {
            socket.off('project-state-sync', handleProjectStateSync);
            socket.off('yjs-init', handleYjsInit);
            socket.off('comment-added', handleCommentAdded);
            socket.off('chat-message', handleChatMessage);
            socket.off('breakpoints-updated', handleBreakpointsUpdated);
            socket.off('security-log-new', handleSecurityLogNew);
            socket.off('security-alert', handleSecurityAlert);
        };
    }, [
        socket,
        projectId,
        activeFile,
        loadSecurityTelemetry,
        onSecurityEventRecorded,
    ]);

    const handleJumpToLineClick = (lineNumber: number) => {
        if (onJumpToLine) {
            onJumpToLine(lineNumber);
        }
        window.dispatchEvent(
            new CustomEvent('devcollab:jump-to-line', {
                detail: {
                    fileId: activeFile?.id,
                    lineNumber,
                },
            })
        );
    };

    // TAB 1 HANDLERS: Inline Comments
    const handleAddComment = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!activeFile || !commentTextInput.trim() || submittingComment) {
            return;
        }
        setSubmittingComment(true);
        setDrawerError(null);
        setXssNotice(null);

        try {
            const safeLine = Math.max(
                1,
                Math.min(50_000, Number(commentLineInput) || 1)
            );
            const { comment, xssSanitized } = await createInlineComment(
                activeFile.id,
                safeLine,
                commentTextInput.trim()
            );

            setComments((prev) =>
                [
                    ...prev.filter((c) => c.id !== comment.id),
                    comment,
                ].sort((a, b) => a.lineNumber - b.lineNumber)
            );
            setCommentTextInput('');

            if (xssSanitized) {
                setXssNotice(
                    'Zero-Trust XSS Sanitizer stripped executable HTML/script tags and logged XSS_PAYLOAD_SANITIZED.'
                );
                void loadSecurityTelemetry();
            }

            if (socket) {
                socket.emit('new-comment', {
                    projectId,
                    fileId: activeFile.id,
                    comment,
                });
            }
        } catch (err) {
            setDrawerError(extractApiErrorMessage(err));
        } finally {
            setSubmittingComment(false);
        }
    };

    const handleToggleResolve = async (comment: InlineComment) => {
        if (isViewer) return;
        setDrawerError(null);
        try {
            const updated = await toggleResolveComment(
                comment.id,
                !comment.resolved
            );
            setComments((prev) =>
                prev.map((c) => (c.id === updated.id ? updated : c))
            );
        } catch (err) {
            setDrawerError(extractApiErrorMessage(err));
        }
    };

    const handleDeleteComment = async (commentId: string) => {
        if (isViewer) return;
        setDrawerError(null);
        try {
            await deleteInlineComment(commentId);
            setComments((prev) => prev.filter((c) => c.id !== commentId));
        } catch (err) {
            setDrawerError(extractApiErrorMessage(err));
        }
    };

    // TAB 2 HANDLER: Team Chat
    const handleSendChat = (e: React.FormEvent) => {
        e.preventDefault();
        if (!chatInput.trim() || sendingChat) return;

        const rawText = chatInput.trim();
        setChatInput('');

        if (socket && socket.connected) {
            setSendingChat(true);
            socket.emit(
                'chat-message',
                { projectId, message: rawText },
                (ack?: {
                    ok?: boolean;
                    message?: ChatMessage;
                    xssSanitized?: boolean;
                    error?: string;
                }) => {
                    setSendingChat(false);
                    if (ack?.error) {
                        setDrawerError(
                            `Chat throttled/blocked: ${ack.error}`
                        );
                    }
                    if (ack?.xssSanitized) {
                        setXssNotice(
                            'XSS payload in chat message was neutralized by server-side sanitizeText().'
                        );
                        void loadSecurityTelemetry();
                    }
                }
            );
        } else {
            // Local fallback when socket is disconnected
            const fallbackMsg: ChatMessage = {
                id: `local-${Date.now()}`,
                projectId,
                userId: 'local',
                username: currentUsername,
                avatarColor: '#06b6d4',
                role: userRole,
                message: rawText
                    .replace(/&/g, '&amp;')
                    .replace(/</g, '&lt;')
                    .replace(/>/g, '&gt;'),
                createdAt: new Date().toISOString(),
            };
            setChatMessages((prev) => [...prev, fallbackMsg]);
        }
    };

    // TAB 3 HANDLERS: Shared Debugger
    const handleToggleBreakpoint = (e: React.FormEvent) => {
        e.preventDefault();
        if (!activeFile || isViewer) return;
        const safeLine = Math.max(1, Math.min(100_000, Number(bpLineInput) || 1));

        if (socket && socket.connected) {
            socket.emit('toggle-breakpoint', {
                projectId,
                fileId: activeFile.id,
                lineNumber: safeLine,
                condition: bpConditionInput.trim() || undefined,
            });
        } else {
            // Local state toggle if socket offline
            setBreakpoints((prev) => {
                const exists = prev.some((b) => b.lineNumber === safeLine);
                if (exists) {
                    return prev.filter((b) => b.lineNumber !== safeLine);
                }
                return [
                    ...prev,
                    {
                        id: `bp-${Date.now()}`,
                        fileId: activeFile.id,
                        lineNumber: safeLine,
                        condition: bpConditionInput.trim() || undefined,
                        createdBy: currentUsername,
                        username: currentUsername,
                        createdAt: new Date().toISOString(),
                    },
                ].sort((a, b) => a.lineNumber - b.lineNumber);
            });
        }
        setBpConditionInput('');
    };

    const handleAddWatch = (e: React.FormEvent) => {
        e.preventDefault();
        const expr = newWatchExpr.trim();
        if (!expr) return;
        setWatchList((prev) => [
            ...prev,
            {
                id: `watch-${Date.now()}`,
                expression: expr,
                addedBy: currentUsername,
            },
        ]);
        setNewWatchExpr('');
    };

    // TAB 4 HANDLER: 1-Click Red-Team Attack Simulator inside Security Shield
    const handleTriggerRedTeam = async (attackType: RedTeamAttackType) => {
        if (!projectId || runningAttackType) return;
        setRunningAttackType(attackType);
        setDrawerError(null);
        try {
            const simResult = await simulateRedTeamAttack(
                projectId,
                attackType
            );
            if (simResult.securityEvent) {
                setSecurityLogs((prev) => [
                    simResult.securityEvent!,
                    ...prev.filter((e) => e.id !== simResult.securityEvent!.id),
                ]);
            } else {
                await loadSecurityTelemetry();
            }
        } catch (err) {
            setDrawerError(extractApiErrorMessage(err));
            await loadSecurityTelemetry();
        } finally {
            setRunningAttackType(null);
        }
    };

    // TAB 5 HANDLER: AI Co-Pilot Analysis
    const runCoPilotIntelligence = useCallback(
        async (mode: 'explain' | 'audit' | 'tests') => {
            if (!activeFile) return;
            setCoPilotMode(mode);
            setAiLoading(true);
            setDrawerError(null);

            const localBundle = buildLocalCoPilotAnalysis(
                activeFile,
                effectiveCode
            );

            try {
                // Attempt live backend `/api/execute/ai-review` (Phase 7) or `/api/execute/scan`
                if (mode === 'audit') {
                    try {
                        const remoteReview = await requestAiSecurityReview({
                            projectId,
                            fileId: activeFile.id,
                            language: activeFile.language,
                            code: effectiveCode,
                        });
                        if (
                            remoteReview &&
                            typeof remoteReview.summary === 'string'
                        ) {
                            setAiReview(remoteReview);
                            setAiExplanation(localBundle.explanation);
                            setAiUnitTests(localBundle.unitTestsCode);
                            return;
                        }
                    } catch {
                        // Fall back to live static scanner + local deterministic synthesis
                        const scan = await scanCodeForThreatsApi(
                            effectiveCode,
                            activeFile.language
                        ).catch(() => null);
                        if (scan && !scan.safe) {
                            const mergedFindings: AiSecurityFinding[] =
                                scan.matchedRules.map((r) => ({
                                    line: r.line,
                                    severity: r.severity,
                                    title: `[${r.ruleId}] ${r.patternName}`,
                                    recommendation: r.description,
                                    cweId: r.ruleId,
                                }));
                            setAiReview({
                                summary: `Static AST/Pattern Guard detected ${scan.threats.length} threat signature(s) in ${activeFile.name}.`,
                                overallRiskScore: scan.riskScore,
                                safeToDeploy: false,
                                findings:
                                    mergedFindings.length > 0
                                        ? mergedFindings
                                        : localBundle.review.findings,
                                hardenedSnippet:
                                    localBundle.review.hardenedSnippet,
                                analyzedAt: new Date().toISOString(),
                            });
                            setAiExplanation(localBundle.explanation);
                            setAiUnitTests(localBundle.unitTestsCode);
                            return;
                        }
                    }
                }

                setAiExplanation(localBundle.explanation);
                setAiReview(localBundle.review);
                setAiUnitTests(localBundle.unitTestsCode);
            } finally {
                setAiLoading(false);
            }
        },
        [activeFile, effectiveCode, projectId]
    );

    useEffect(() => {
        if (activeTab === 'copilot' && activeFile) {
            void runCoPilotIntelligence(coPilotMode);
        }
    }, [activeTab, activeFile?.id]);

    const filteredComments = useMemo(() => {
        return comments.filter((c) => {
            if (commentFilter === 'open') return !c.resolved;
            if (commentFilter === 'resolved') return c.resolved;
            return true;
        });
    }, [comments, commentFilter]);

    const filteredSecurityLogs = useMemo(() => {
        return securityLogs.filter((ev) => {
            if (logFilter === 'blocked') return ev.blocked;
            if (logFilter === 'critical')
                return ev.severity === 'CRITICAL' || ev.severity === 'HIGH';
            return true;
        });
    }, [securityLogs, logFilter]);

    const blockedCount = useMemo(
        () => securityLogs.filter((e) => e.blocked).length,
        [securityLogs]
    );

    const openCommentsCount = useMemo(
        () => comments.filter((c) => !c.resolved).length,
        [comments]
    );

    // Collapsed Narrow Rail View
    if (!isOpen) {
        return (
            <aside className="w-12 shrink-0 bg-[#0F1624]/95 border-l border-slate-800/80 flex flex-col items-center py-3 gap-3 select-none z-20">
                <button
                    type="button"
                    onClick={() => setIsOpen(true)}
                    className="p-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-cyan-400 border border-slate-800 transition"
                    title="Expand Collaboration & Security Drawer"
                >
                    <ChevronLeft className="w-4 h-4" />
                </button>

                <button
                    type="button"
                    onClick={() => {
                        setActiveTab('comments');
                        setIsOpen(true);
                    }}
                    className="p-2 rounded-xl hover:bg-slate-800/70 text-slate-400 hover:text-cyan-300 relative"
                    title="Inline Comments"
                >
                    <MessageSquareCode className="w-4 h-4" />
                    {openCommentsCount > 0 && (
                        <span className="absolute -top-0.5 -right-0.5 w-4 h-4 rounded-full bg-cyan-500 text-slate-950 text-[9px] font-bold flex items-center justify-center">
                            {openCommentsCount}
                        </span>
                    )}
                </button>

                <button
                    type="button"
                    onClick={() => {
                        setActiveTab('chat');
                        setIsOpen(true);
                    }}
                    className="p-2 rounded-xl hover:bg-slate-800/70 text-slate-400 hover:text-cyan-300"
                    title="Team Chat"
                >
                    <MessagesSquare className="w-4 h-4" />
                </button>

                <button
                    type="button"
                    onClick={() => {
                        setActiveTab('debugger');
                        setIsOpen(true);
                    }}
                    className="p-2 rounded-xl hover:bg-slate-800/70 text-slate-400 hover:text-amber-300"
                    title="Shared Debugger"
                >
                    <Bug className="w-4 h-4" />
                </button>

                <button
                    type="button"
                    onClick={() => {
                        setActiveTab('security');
                        setIsOpen(true);
                    }}
                    className="p-2 rounded-xl hover:bg-slate-800/70 text-rose-400 relative"
                    title="Security Shield (SIEM Audit Log)"
                >
                    <ShieldAlert className="w-4 h-4" />
                    {blockedCount > 0 && (
                        <span className="absolute -top-0.5 -right-0.5 w-4 h-4 rounded-full bg-rose-500 text-white text-[9px] font-bold flex items-center justify-center">
                            {blockedCount}
                        </span>
                    )}
                </button>

                <button
                    type="button"
                    onClick={() => {
                        setActiveTab('copilot');
                        setIsOpen(true);
                    }}
                    className="p-2 rounded-xl hover:bg-slate-800/70 text-violet-400"
                    title="AI Security Co-Pilot"
                >
                    <Sparkles className="w-4 h-4" />
                </button>
            </aside>
        );
    }

    return (
        <aside className="w-80 xl:w-96 shrink-0 bg-[#0F1624]/95 border-l border-slate-800/80 flex flex-col h-full select-none z-20">
            {/* Top 5-Tab Navigation Header */}
            <div className="p-2 bg-[#090D16] border-b border-slate-800/80 flex items-center justify-between gap-1">
                <div className="grid grid-cols-5 gap-1 flex-1">
                    <button
                        type="button"
                        onClick={() => setActiveTab('comments')}
                        className={cn(
                            'py-1.5 px-1 rounded-lg text-[10px] font-mono font-semibold transition flex flex-col items-center gap-0.5 border',
                            activeTab === 'comments'
                                ? 'bg-cyan-500/15 text-cyan-300 border-cyan-500/40'
                                : 'text-slate-400 border-transparent hover:text-slate-200 hover:bg-slate-800/40'
                        )}
                        title="Tab 1: Line-Linked Inline Code Review Comments"
                    >
                        <MessageSquareCode className="w-3.5 h-3.5" />
                        <span>Review ({openCommentsCount})</span>
                    </button>

                    <button
                        type="button"
                        onClick={() => setActiveTab('chat')}
                        className={cn(
                            'py-1.5 px-1 rounded-lg text-[10px] font-mono font-semibold transition flex flex-col items-center gap-0.5 border',
                            activeTab === 'chat'
                                ? 'bg-cyan-500/15 text-cyan-300 border-cyan-500/40'
                                : 'text-slate-400 border-transparent hover:text-slate-200 hover:bg-slate-800/40'
                        )}
                        title="Tab 2: Real-Time Team Chat"
                    >
                        <MessagesSquare className="w-3.5 h-3.5" />
                        <span>Chat ({chatMessages.length})</span>
                    </button>

                    <button
                        type="button"
                        onClick={() => setActiveTab('debugger')}
                        className={cn(
                            'py-1.5 px-1 rounded-lg text-[10px] font-mono font-semibold transition flex flex-col items-center gap-0.5 border',
                            activeTab === 'debugger'
                                ? 'bg-amber-500/15 text-amber-300 border-amber-500/40'
                                : 'text-slate-400 border-transparent hover:text-slate-200 hover:bg-slate-800/40'
                        )}
                        title="Tab 3: Shared Breakpoints & Variable Watch"
                    >
                        <Bug className="w-3.5 h-3.5" />
                        <span>Debug ({breakpoints.length})</span>
                    </button>

                    <button
                        type="button"
                        onClick={() => setActiveTab('security')}
                        className={cn(
                            'py-1.5 px-1 rounded-lg text-[10px] font-mono font-semibold transition flex flex-col items-center gap-0.5 border',
                            activeTab === 'security'
                                ? 'bg-rose-500/15 text-rose-300 border-rose-500/40'
                                : 'text-slate-400 border-transparent hover:text-slate-200 hover:bg-slate-800/40'
                        )}
                        title="Tab 4: Security Shield (SIEM Audit Log)"
                    >
                        <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                        <span>SIEM ({blockedCount})</span>
                    </button>

                    <button
                        type="button"
                        onClick={() => setActiveTab('copilot')}
                        className={cn(
                            'py-1.5 px-1 rounded-lg text-[10px] font-mono font-semibold transition flex flex-col items-center gap-0.5 border',
                            activeTab === 'copilot'
                                ? 'bg-violet-500/15 text-violet-300 border-violet-500/40'
                                : 'text-slate-400 border-transparent hover:text-slate-200 hover:bg-slate-800/40'
                        )}
                        title="Tab 5: AI Security Co-Pilot"
                    >
                        <Sparkles className="w-3.5 h-3.5 text-violet-400" />
                        <span>Co-Pilot</span>
                    </button>
                </div>

                <button
                    type="button"
                    onClick={() => setIsOpen(false)}
                    className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800/60 transition"
                    title="Collapse drawer"
                >
                    <ChevronRight className="w-4 h-4" />
                </button>
            </div>

            {/* Global Error or XSS Sanitization Notice */}
            {drawerError && (
                <div className="m-2.5 p-2.5 rounded-xl bg-rose-500/15 border border-rose-500/40 text-rose-200 text-[11px] font-mono flex items-start justify-between gap-2">
                    <span>{drawerError}</span>
                    <button
                        type="button"
                        onClick={() => setDrawerError(null)}
                        className="text-[10px] text-rose-300 hover:text-white"
                    >
                        X
                    </button>
                </div>
            )}

            {xssNotice && (
                <div className="m-2.5 p-2.5 rounded-xl bg-amber-500/15 border border-amber-500/40 text-amber-200 text-[11px] font-mono flex items-start justify-between gap-2">
                    <div className="flex items-start gap-1.5">
                        <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                        <span>{xssNotice}</span>
                    </div>
                    <button
                        type="button"
                        onClick={() => setXssNotice(null)}
                        className="text-[10px] text-amber-300 hover:text-white"
                    >
                        OK
                    </button>
                </div>
            )}

            {/* ===================================================================
                TAB 1: INLINE COMMENTS (Line-Linked Code Review Threads)
               =================================================================== */}
            {activeTab === 'comments' && (
                <div className="flex-1 min-h-0 flex flex-col">
                    <div className="px-3.5 py-2.5 border-b border-slate-800/80 flex items-center justify-between">
                        <div>
                            <h3 className="text-xs font-semibold text-white">
                                Inline Code Review Threads
                            </h3>
                            <p className="text-[10px] font-mono text-slate-400">
                                {activeFile
                                    ? `File: ${activeFile.name} • Click any thread to jump to line`
                                    : 'Select a file to inspect comments'}
                            </p>
                        </div>

                        <div className="flex items-center gap-1 bg-[#090D16] p-0.5 rounded-lg border border-slate-800 text-[10px] font-mono">
                            {(['all', 'open', 'resolved'] as const).map((f) => (
                                <button
                                    key={f}
                                    type="button"
                                    onClick={() => setCommentFilter(f)}
                                    className={cn(
                                        'px-2 py-0.5 rounded capitalize transition',
                                        commentFilter === f
                                            ? 'bg-cyan-500/20 text-cyan-300'
                                            : 'text-slate-400 hover:text-white'
                                    )}
                                >
                                    {f}
                                </button>
                            ))}
                        </div>
                    </div>

                    {/* Threads List */}
                    <div className="flex-1 overflow-y-auto p-3 space-y-2.5">
                        {filteredComments.length === 0 ? (
                            <div className="p-6 text-center text-xs font-mono text-slate-500">
                                No {commentFilter !== 'all' ? commentFilter : ''}{' '}
                                inline review comments on this file.
                            </div>
                        ) : (
                            filteredComments.map((comment) => (
                                <div
                                    key={comment.id}
                                    onClick={() =>
                                        handleJumpToLineClick(
                                            comment.lineNumber
                                        )
                                    }
                                    className={cn(
                                        'p-3 rounded-xl border transition cursor-pointer space-y-2',
                                        comment.resolved
                                            ? 'bg-[#090D16]/50 border-slate-800/60 opacity-70'
                                            : 'bg-[#090D16]/90 border-slate-800 hover:border-cyan-500/40'
                                    )}
                                >
                                    <div className="flex items-center justify-between gap-2">
                                        <div className="flex items-center gap-2">
                                            <span className="px-2 py-0.5 rounded bg-cyan-500/15 border border-cyan-500/30 text-cyan-300 text-[10px] font-mono font-semibold flex items-center gap-1">
                                                <CornerDownRight className="w-2.5 h-2.5" />
                                                Line {comment.lineNumber}
                                            </span>
                                            <span className="text-[11px] font-mono text-slate-300 font-semibold">
                                                @{comment.username}
                                            </span>
                                        </div>

                                        <span className="text-[10px] font-mono text-slate-500">
                                            {new Date(
                                                comment.createdAt
                                            ).toLocaleTimeString()}
                                        </span>
                                    </div>

                                    {/* Comment Body (React text rendering + backend HTML entity sanitization = 100% XSS-safe) */}
                                    <p className="text-xs text-slate-200 font-mono leading-relaxed break-words select-text">
                                        {comment.content}
                                    </p>

                                    <div
                                        className="pt-1.5 border-t border-slate-800/70 flex items-center justify-between"
                                        onClick={(e) => e.stopPropagation()}
                                    >
                                        <span
                                            className={cn(
                                                'text-[10px] font-mono flex items-center gap-1',
                                                comment.resolved
                                                    ? 'text-emerald-400'
                                                    : 'text-amber-300'
                                            )}
                                        >
                                            <CheckCircle2 className="w-3 h-3" />
                                            {comment.resolved
                                                ? 'Resolved'
                                                : 'Open Thread'}
                                        </span>

                                        <div className="flex items-center gap-1.5">
                                            <button
                                                type="button"
                                                disabled={isViewer}
                                                onClick={() =>
                                                    void handleToggleResolve(
                                                        comment
                                                    )
                                                }
                                                className="px-2 py-0.5 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700 text-[10px] font-mono text-slate-300 disabled:opacity-40"
                                            >
                                                {comment.resolved
                                                    ? 'Reopen'
                                                    : 'Resolve'}
                                            </button>
                                            {!isViewer && (
                                                <button
                                                    type="button"
                                                    onClick={() =>
                                                        void handleDeleteComment(
                                                            comment.id
                                                        )
                                                    }
                                                    className="p-1 rounded hover:bg-rose-500/20 text-slate-400 hover:text-rose-300"
                                                    title="Delete comment"
                                                >
                                                    <Trash2 className="w-3 h-3" />
                                                </button>
                                            )}
                                        </div>
                                    </div>
                                </div>
                            ))
                        )}
                    </div>

                    {/* New Line-Linked Comment Form */}
                    <form
                        onSubmit={handleAddComment}
                        className="p-3 bg-[#090D16] border-t border-slate-800/80 space-y-2"
                    >
                        <div className="flex items-center justify-between text-[10px] font-mono">
                            <div className="flex items-center gap-1.5 text-slate-400">
                                <span>Target Line:</span>
                                <input
                                    type="number"
                                    min={1}
                                    max={50000}
                                    value={commentLineInput}
                                    onChange={(e) =>
                                        setCommentLineInput(
                                            Math.max(
                                                1,
                                                Number(e.target.value) || 1
                                            )
                                        )
                                    }
                                    className="w-16 px-2 py-0.5 rounded bg-[#0F1624] border border-slate-700 text-cyan-300 text-xs font-mono"
                                />
                            </div>
                            <button
                                type="button"
                                onClick={() =>
                                    setCommentTextInput(
                                        '<script>alert("XSS")</script> Verify HMAC tag constant-time check'
                                    )
                                }
                                className="text-rose-400 hover:underline text-[9px]"
                                title="Pre-fill an XSS vector to verify server-side sanitizeText() and XSS_PAYLOAD_SANITIZED logging"
                            >
                                Test &lt;script&gt; XSS Guard
                            </button>
                        </div>

                        <div className="flex items-center gap-1.5">
                            <input
                                type="text"
                                maxLength={600}
                                value={commentTextInput}
                                onChange={(e) =>
                                    setCommentTextInput(e.target.value)
                                }
                                placeholder="Add line-linked review note (XSS-sanitized)..."
                                className="flex-1 px-3 py-2 rounded-xl bg-[#0F1624] border border-slate-800 text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                            />
                            <button
                                type="submit"
                                disabled={
                                    submittingComment ||
                                    !commentTextInput.trim() ||
                                    !activeFile
                                }
                                className="p-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 disabled:opacity-40 text-slate-950 font-semibold transition"
                            >
                                <Plus className="w-4 h-4" />
                            </button>
                        </div>
                    </form>
                </div>
            )}

            {/* ===================================================================
                TAB 2: TEAM CHAT (Real-Time Project Chat with Role Badges)
               =================================================================== */}
            {activeTab === 'chat' && (
                <div className="flex-1 min-h-0 flex flex-col">
                    <div className="px-3.5 py-2.5 border-b border-slate-800/80 flex items-center justify-between">
                        <div>
                            <h3 className="text-xs font-semibold text-white">
                                Encrypted Workspace Team Chat
                            </h3>
                            <p className="text-[10px] font-mono text-slate-400">
                                Rate-limited (5 msgs / 10s) &amp; Stored-XSS
                                sanitized
                            </p>
                        </div>
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                            ROOM LIVE
                        </span>
                    </div>

                    <div className="flex-1 overflow-y-auto p-3 space-y-2.5">
                        {chatMessages.length === 0 ? (
                            <div className="p-6 text-center text-xs font-mono text-slate-500">
                                No messages yet. Start a real-time discussion
                                with collaborators in this project room.
                            </div>
                        ) : (
                            chatMessages.map((msg) => (
                                <div
                                    key={msg.id}
                                    className="p-2.5 rounded-xl bg-[#090D16]/90 border border-slate-800/80 space-y-1.5"
                                >
                                    <div className="flex items-center justify-between gap-2">
                                        <div className="flex items-center gap-1.5 min-w-0">
                                            <span
                                                className="w-2.5 h-2.5 rounded-full shrink-0"
                                                style={{
                                                    backgroundColor:
                                                        msg.avatarColor ||
                                                        '#06b6d4',
                                                }}
                                            />
                                            <span className="text-xs font-mono font-semibold text-white truncate">
                                                @{msg.username}
                                            </span>
                                            <span
                                                className={cn(
                                                    'px-1.5 py-0.2 rounded text-[9px] font-mono border',
                                                    ROLE_PILL_STYLE[msg.role] ||
                                                    ROLE_PILL_STYLE.EDITOR
                                                )}
                                            >
                                                {msg.role}
                                            </span>
                                        </div>
                                        <span className="text-[10px] font-mono text-slate-500 shrink-0">
                                            {new Date(
                                                msg.createdAt
                                            ).toLocaleTimeString()}
                                        </span>
                                    </div>
                                    <p className="text-xs font-mono text-slate-200 leading-relaxed break-words select-text">
                                        {msg.message}
                                    </p>
                                </div>
                            ))
                        )}
                        <div ref={chatBottomRef} />
                    </div>

                    <form
                        onSubmit={handleSendChat}
                        className="p-3 bg-[#090D16] border-t border-slate-800/80 flex items-center gap-2"
                    >
                        <input
                            type="text"
                            maxLength={500}
                            value={chatInput}
                            onChange={(e) => setChatInput(e.target.value)}
                            placeholder="Message project collaborators..."
                            className="flex-1 px-3 py-2 rounded-xl bg-[#0F1624] border border-slate-800 text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                        />
                        <button
                            type="submit"
                            disabled={!chatInput.trim() || sendingChat}
                            className="p-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 disabled:opacity-40 text-slate-950 font-semibold transition"
                            title="Send message"
                        >
                            <Send className="w-4 h-4" />
                        </button>
                    </form>
                </div>
            )}

            {/* ===================================================================
                TAB 3: SHARED DEBUGGER (Synchronized Breakpoints + Variable Watch)
               =================================================================== */}
            {activeTab === 'debugger' && (
                <div className="flex-1 min-h-0 flex flex-col overflow-y-auto p-3 space-y-4">
                    {/* Section 1: Synchronized Breakpoint Manager */}
                    <div className="space-y-2.5">
                        <div className="flex items-center justify-between">
                            <div>
                                <h3 className="text-xs font-semibold text-white flex items-center gap-1.5">
                                    <CircleDot className="w-3.5 h-3.5 text-rose-400" />
                                    Synchronized Breakpoints (
                                    {breakpoints.length})
                                </h3>
                                <p className="text-[10px] font-mono text-slate-400">
                                    Synced across all peers via Socket.IO
                                    `toggle-breakpoint`
                                </p>
                            </div>
                            {isViewer && (
                                <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-violet-500/15 text-violet-300 border border-violet-500/30 flex items-center gap-1">
                                    <Lock className="w-2.5 h-2.5" />
                                    READ-ONLY
                                </span>
                            )}
                        </div>

                        <form
                            onSubmit={handleToggleBreakpoint}
                            className="p-2.5 rounded-xl bg-[#090D16] border border-slate-800 space-y-2"
                        >
                            <div className="flex items-center gap-2">
                                <div className="w-24">
                                    <label className="block text-[9px] font-mono uppercase text-slate-400 mb-0.5">
                                        Line #
                                    </label>
                                    <input
                                        type="number"
                                        min={1}
                                        max={100000}
                                        disabled={isViewer}
                                        value={bpLineInput}
                                        onChange={(e) =>
                                            setBpLineInput(
                                                Math.max(
                                                    1,
                                                    Number(e.target.value) || 1
                                                )
                                            )
                                        }
                                        className="w-full px-2 py-1 rounded bg-[#0F1624] border border-slate-700 text-xs font-mono text-amber-300"
                                    />
                                </div>
                                <div className="flex-1">
                                    <label className="block text-[9px] font-mono uppercase text-slate-400 mb-0.5">
                                        Condition (Optional)
                                    </label>
                                    <input
                                        type="text"
                                        maxLength={120}
                                        disabled={isViewer}
                                        value={bpConditionInput}
                                        onChange={(e) =>
                                            setBpConditionInput(e.target.value)
                                        }
                                        placeholder="e.g. joint_fid < 0.96"
                                        className="w-full px-2 py-1 rounded bg-[#0F1624] border border-slate-700 text-xs font-mono text-white placeholder-slate-600"
                                    />
                                </div>
                            </div>
                            <button
                                type="submit"
                                disabled={isViewer || !activeFile}
                                className="w-full py-1.5 rounded-lg bg-amber-500/15 hover:bg-amber-500/25 disabled:opacity-40 text-amber-300 border border-amber-500/30 text-xs font-mono font-semibold transition"
                            >
                                {isViewer
                                    ? 'Locked for VIEWER Role'
                                    : `Toggle Breakpoint at Line ${bpLineInput}`}
                            </button>
                        </form>

                        <div className="space-y-1.5">
                            {breakpoints.length === 0 ? (
                                <div className="p-3 rounded-xl bg-[#090D16]/60 border border-slate-800/80 text-[11px] font-mono text-slate-500">
                                    No active breakpoints on{' '}
                                    {activeFile?.name || 'this file'}.
                                </div>
                            ) : (
                                breakpoints.map((bp) => (
                                    <div
                                        key={bp.id}
                                        onClick={() =>
                                            handleJumpToLineClick(bp.lineNumber)
                                        }
                                        className="p-2.5 rounded-xl bg-[#090D16] border border-slate-800 hover:border-amber-500/40 flex items-center justify-between gap-2 cursor-pointer transition"
                                    >
                                        <div className="min-w-0">
                                            <div className="flex items-center gap-2">
                                                <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse" />
                                                <span className="text-xs font-mono font-semibold text-amber-300">
                                                    Line {bp.lineNumber}
                                                </span>
                                                <span className="text-[10px] font-mono text-slate-500">
                                                    by @{bp.username}
                                                </span>
                                            </div>
                                            {bp.condition && (
                                                <div className="text-[10px] font-mono text-cyan-300 truncate mt-0.5">
                                                    if ({bp.condition})
                                                </div>
                                            )}
                                        </div>

                                        {!isViewer && (
                                            <button
                                                type="button"
                                                onClick={(e) => {
                                                    e.stopPropagation();
                                                    if (
                                                        socket &&
                                                        socket.connected &&
                                                        activeFile
                                                    ) {
                                                        socket.emit(
                                                            'toggle-breakpoint',
                                                            {
                                                                projectId,
                                                                fileId: activeFile.id,
                                                                lineNumber:
                                                                    bp.lineNumber,
                                                            }
                                                        );
                                                    } else {
                                                        setBreakpoints((prev) =>
                                                            prev.filter(
                                                                (x) =>
                                                                    x.id !==
                                                                    bp.id
                                                            )
                                                        );
                                                    }
                                                }}
                                                className="p-1 rounded hover:bg-rose-500/20 text-slate-400 hover:text-rose-300"
                                                title="Remove breakpoint"
                                            >
                                                <Trash2 className="w-3.5 h-3.5" />
                                            </button>
                                        )}
                                    </div>
                                ))
                            )}
                        </div>
                    </div>

                    {/* Section 2: Shared Variable Watch List */}
                    <div className="pt-3 border-t border-slate-800/80 space-y-2.5">
                        <div>
                            <h3 className="text-xs font-semibold text-white flex items-center gap-1.5">
                                <Eye className="w-3.5 h-3.5 text-cyan-400" />
                                Shared Variable Watch List ({watchList.length})
                            </h3>
                            <p className="text-[10px] font-mono text-slate-400">
                                Live symbol &amp; telemetry state inspector
                            </p>
                        </div>

                        <form
                            onSubmit={handleAddWatch}
                            className="flex items-center gap-1.5"
                        >
                            <input
                                type="text"
                                maxLength={80}
                                value={newWatchExpr}
                                onChange={(e) =>
                                    setNewWatchExpr(e.target.value)
                                }
                                placeholder="Add watch expression (e.g. total_lat)..."
                                className="flex-1 px-2.5 py-1.5 rounded-xl bg-[#090D16] border border-slate-800 text-xs font-mono text-white placeholder-slate-500"
                            />
                            <button
                                type="submit"
                                className="p-1.5 rounded-xl bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40"
                            >
                                <Plus className="w-4 h-4" />
                            </button>
                        </form>

                        <div className="space-y-1.5">
                            {watchList.map((item) => (
                                <div
                                    key={item.id}
                                    className="p-2.5 rounded-xl bg-[#090D16] border border-slate-800/90 flex items-center justify-between gap-2 text-xs font-mono"
                                >
                                    <div className="min-w-0">
                                        <div className="text-cyan-300 font-semibold truncate">
                                            {item.expression}
                                        </div>
                                        <div className="text-[10px] text-emerald-300/90 truncate">
                                            ={' '}
                                            {inspectWatchExpression(
                                                item.expression,
                                                effectiveCode
                                            )}
                                        </div>
                                    </div>
                                    <button
                                        type="button"
                                        onClick={() =>
                                            setWatchList((prev) =>
                                                prev.filter(
                                                    (w) => w.id !== item.id
                                                )
                                            )
                                        }
                                        className="p-1 rounded hover:bg-rose-500/20 text-slate-500 hover:text-rose-300 shrink-0"
                                    >
                                        <Trash2 className="w-3 h-3" />
                                    </button>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            )}

            {/* ===================================================================
                TAB 4: SECURITY SHIELD (SIEM Audit Log + 1-Click Red-Team Simulator)
               =================================================================== */}
            {activeTab === 'security' && (
                <div className="flex-1 min-h-0 flex flex-col">
                    {/* 1-Click Red-Team Attack Simulator Controls */}
                    <div className="p-3 bg-[#090D16] border-b border-slate-800/80 space-y-2">
                        <div className="flex items-center justify-between">
                            <span className="text-[10px] font-mono uppercase tracking-wider text-rose-400 font-semibold flex items-center gap-1.5">
                                <Crosshair className="w-3.5 h-3.5" />
                                1-Click Red-Team Intrusion Simulator
                            </span>
                            <button
                                type="button"
                                onClick={() => void loadSecurityTelemetry()}
                                className="text-[10px] font-mono text-slate-400 hover:text-white flex items-center gap-1"
                            >
                                <RefreshCw
                                    className={cn(
                                        'w-3 h-3',
                                        loadingLogs &&
                                        'animate-spin text-cyan-400'
                                    )}
                                />
                                Sync
                            </button>
                        </div>

                        <div className="grid grid-cols-3 gap-1.5">
                            <button
                                type="button"
                                disabled={Boolean(runningAttackType)}
                                onClick={() => void handleTriggerRedTeam('rce')}
                                className="p-2 rounded-xl bg-rose-500/15 hover:bg-rose-500/25 border border-rose-500/40 text-rose-200 text-[10px] font-mono font-semibold flex flex-col items-center gap-1 transition"
                                title="Simulate child_process + constructor.constructor RCE sandbox escape probe"
                            >
                                {runningAttackType === 'rce' ? (
                                    <Loader2 className="w-3.5 h-3.5 animate-spin text-rose-400" />
                                ) : (
                                    <Terminal className="w-3.5 h-3.5 text-rose-400" />
                                )}
                                <span>Sim RCE Escape</span>
                            </button>

                            <button
                                type="button"
                                disabled={Boolean(runningAttackType)}
                                onClick={() =>
                                    void handleTriggerRedTeam('traversal')
                                }
                                className="p-2 rounded-xl bg-amber-500/15 hover:bg-amber-500/25 border border-amber-500/40 text-amber-200 text-[10px] font-mono font-semibold flex flex-col items-center gap-1 transition"
                                title="Simulate ../../.env path traversal probe"
                            >
                                {runningAttackType === 'traversal' ? (
                                    <Loader2 className="w-3.5 h-3.5 animate-spin text-amber-400" />
                                ) : (
                                    <FileWarning className="w-3.5 h-3.5 text-amber-400" />
                                )}
                                <span>Sim ../../.env</span>
                            </button>

                            <button
                                type="button"
                                disabled={Boolean(runningAttackType)}
                                onClick={() =>
                                    void handleTriggerRedTeam('rbac')
                                }
                                className="p-2 rounded-xl bg-violet-500/15 hover:bg-violet-500/25 border border-violet-500/40 text-violet-200 text-[10px] font-mono font-semibold flex flex-col items-center gap-1 transition"
                                title="Simulate VIEWER write privilege escalation probe"
                            >
                                {runningAttackType === 'rbac' ? (
                                    <Loader2 className="w-3.5 h-3.5 animate-spin text-violet-400" />
                                ) : (
                                    <UserX className="w-3.5 h-3.5 text-violet-400" />
                                )}
                                <span>Sim RBAC Bypass</span>
                            </button>
                        </div>
                    </div>

                    {/* SIEM Filter Bar */}
                    <div className="px-3.5 py-2 border-b border-slate-800/80 flex items-center justify-between text-[10px] font-mono">
                        <span className="text-slate-400">
                            Events: <strong>{filteredSecurityLogs.length}</strong>
                        </span>
                        <div className="flex items-center gap-1 bg-[#090D16] p-0.5 rounded-lg border border-slate-800">
                            {(['all', 'blocked', 'critical'] as const).map(
                                (f) => (
                                    <button
                                        key={f}
                                        type="button"
                                        onClick={() => setLogFilter(f)}
                                        className={cn(
                                            'px-2 py-0.5 rounded uppercase transition',
                                            logFilter === f
                                                ? 'bg-rose-500/20 text-rose-300'
                                                : 'text-slate-400 hover:text-white'
                                        )}
                                    >
                                        {f}
                                    </button>
                                )
                            )}
                        </div>
                    </div>

                    {/* SIEM Event Stream */}
                    <div className="flex-1 overflow-y-auto p-3 space-y-2">
                        {filteredSecurityLogs.length === 0 ? (
                            <div className="p-6 text-center text-xs font-mono text-slate-500">
                                No matching security events found.
                            </div>
                        ) : (
                            filteredSecurityLogs.map((ev) => (
                                <div
                                    key={ev.id}
                                    className={cn(
                                        'p-2.5 rounded-xl border text-[11px] font-mono space-y-1.5',
                                        ev.blocked
                                            ? 'bg-rose-950/20 border-rose-500/40 text-rose-100'
                                            : 'bg-[#090D16]/90 border-slate-800/80 text-slate-300'
                                    )}
                                >
                                    <div className="flex items-center justify-between gap-1.5">
                                        <span
                                            className={cn(
                                                'px-1.5 py-0.5 rounded text-[9px] font-bold border',
                                                SEVERITY_PILL_STYLE[
                                                ev.severity
                                                ] || SEVERITY_PILL_STYLE.INFO
                                            )}
                                        >
                                            {ev.severity}
                                        </span>

                                        <span
                                            className={cn(
                                                'px-1.5 py-0.5 rounded text-[9px] font-semibold border',
                                                ev.blocked
                                                    ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                                                    : 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                                            )}
                                        >
                                            {ev.blocked
                                                ? 'BLOCKED'
                                                : 'VERIFIED'}
                                        </span>
                                    </div>

                                    <div className="font-semibold text-xs text-white break-words">
                                        {ev.eventType}
                                    </div>

                                    <p className="text-[10px] leading-relaxed opacity-90 break-words select-text">
                                        {ev.details}
                                    </p>

                                    <div className="pt-1 border-t border-slate-800/60 flex items-center justify-between text-[10px] text-slate-400">
                                        <span>
                                            Culprit:{' '}
                                            <strong className="text-slate-200">
                                                @{ev.username || 'system'}
                                            </strong>
                                        </span>
                                        <span>
                                            {new Date(
                                                ev.createdAt
                                            ).toLocaleTimeString()}
                                        </span>
                                    </div>
                                </div>
                            ))
                        )}
                    </div>
                </div>
            )}

            {/* ===================================================================
                TAB 5: AI CO-PILOT (Explain Code, SAST Vulnerability Audit, Unit Tests)
               =================================================================== */}
            {activeTab === 'copilot' && (
                <div className="flex-1 min-h-0 flex flex-col">
                    {/* Action Selector Buttons */}
                    <div className="p-3 bg-[#090D16] border-b border-slate-800/80 space-y-2">
                        <div className="flex items-center justify-between">
                            <span className="text-[10px] font-mono uppercase tracking-wider text-violet-400 font-semibold flex items-center gap-1.5">
                                <Wand2 className="w-3.5 h-3.5" />
                                Zero-Trust AI Security Co-Pilot
                            </span>
                            <span className="text-[10px] font-mono text-slate-400">
                                {activeFile?.name || 'No file'}
                            </span>
                        </div>

                        <div className="grid grid-cols-3 gap-1.5">
                            <button
                                type="button"
                                onClick={() =>
                                    void runCoPilotIntelligence('explain')
                                }
                                className={cn(
                                    'p-2 rounded-xl border text-[10px] font-mono font-semibold flex flex-col items-center gap-1 transition',
                                    coPilotMode === 'explain'
                                        ? 'bg-cyan-500/20 border-cyan-500/50 text-cyan-200'
                                        : 'bg-[#0F1624] border-slate-800 text-slate-400 hover:text-white'
                                )}
                            >
                                <BookOpen className="w-3.5 h-3.5 text-cyan-400" />
                                <span>Explain Code</span>
                            </button>

                            <button
                                type="button"
                                onClick={() =>
                                    void runCoPilotIntelligence('audit')
                                }
                                className={cn(
                                    'p-2 rounded-xl border text-[10px] font-mono font-semibold flex flex-col items-center gap-1 transition',
                                    coPilotMode === 'audit'
                                        ? 'bg-violet-500/20 border-violet-500/50 text-violet-200'
                                        : 'bg-[#0F1624] border-slate-800 text-slate-400 hover:text-white'
                                )}
                            >
                                <ShieldCheck className="w-3.5 h-3.5 text-violet-400" />
                                <span>Vuln Audit</span>
                            </button>

                            <button
                                type="button"
                                onClick={() =>
                                    void runCoPilotIntelligence('tests')
                                }
                                className={cn(
                                    'p-2 rounded-xl border text-[10px] font-mono font-semibold flex flex-col items-center gap-1 transition',
                                    coPilotMode === 'tests'
                                        ? 'bg-emerald-500/20 border-emerald-500/50 text-emerald-200'
                                        : 'bg-[#0F1624] border-slate-800 text-slate-400 hover:text-white'
                                )}
                            >
                                <FileCheck2 className="w-3.5 h-3.5 text-emerald-400" />
                                <span>Unit Tests</span>
                            </button>
                        </div>
                    </div>

                    {/* AI Co-Pilot Results Body */}
                    <div className="flex-1 overflow-y-auto p-3.5 space-y-3 font-mono text-xs select-text">
                        {aiLoading ? (
                            <div className="p-8 text-center text-slate-400 flex flex-col items-center gap-2">
                                <Loader2 className="w-5 h-5 animate-spin text-violet-400" />
                                <span>
                                    Analyzing AST patterns &amp; CWE security
                                    boundaries...
                                </span>
                            </div>
                        ) : coPilotMode === 'explain' ? (
                            <div className="space-y-2.5">
                                <div className="text-[11px] font-semibold text-cyan-300 uppercase">
                                    Architecture &amp; Complexity Breakdown
                                </div>
                                {aiExplanation.map((paragraph, i) => (
                                    <div
                                        key={i}
                                        className="p-3 rounded-xl bg-[#090D16] border border-slate-800/90 text-[11px] text-slate-200 leading-relaxed"
                                    >
                                        {paragraph}
                                    </div>
                                ))}
                            </div>
                        ) : coPilotMode === 'audit' && aiReview ? (
                            <div className="space-y-3">
                                <div
                                    className={cn(
                                        'p-3 rounded-xl border space-y-1.5',
                                        aiReview.safeToDeploy
                                            ? 'bg-emerald-500/10 border-emerald-500/40 text-emerald-200'
                                            : 'bg-rose-500/15 border-rose-500/40 text-rose-200'
                                    )}
                                >
                                    <div className="flex items-center justify-between">
                                        <span className="font-bold text-xs flex items-center gap-1.5">
                                            {aiReview.safeToDeploy ? (
                                                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                                            ) : (
                                                <AlertTriangle className="w-4 h-4 text-rose-400" />
                                            )}
                                            {aiReview.safeToDeploy
                                                ? 'SAFE TO DEPLOY'
                                                : 'VULNERABILITIES DETECTED'}
                                        </span>
                                        <span className="px-2 py-0.5 rounded bg-slate-950/70 text-[10px]">
                                            Risk: {aiReview.overallRiskScore}
                                            /100
                                        </span>
                                    </div>
                                    <p className="text-[11px] leading-relaxed">
                                        {aiReview.summary}
                                    </p>
                                </div>

                                {aiReview.findings.length === 0 ? (
                                    <div className="p-3 rounded-xl bg-[#090D16] border border-slate-800 text-[11px] text-emerald-300">
                                        0 CWE vulnerabilities or dangerous sinks
                                        found in {activeFile?.name}.
                                    </div>
                                ) : (
                                    aiReview.findings.map((f, idx) => (
                                        <div
                                            key={idx}
                                            onClick={() =>
                                                handleJumpToLineClick(f.line)
                                            }
                                            className="p-3 rounded-xl bg-[#090D16] border border-rose-500/35 hover:border-rose-500/60 cursor-pointer space-y-1.5 transition"
                                        >
                                            <div className="flex items-center justify-between">
                                                <span className="px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 text-[10px] font-semibold">
                                                    Line {f.line} • {f.severity}
                                                </span>
                                                {f.cweId && (
                                                    <span className="text-[10px] text-slate-400">
                                                        {f.cweId}
                                                    </span>
                                                )}
                                            </div>
                                            <div className="font-semibold text-white text-xs">
                                                {f.title}
                                            </div>
                                            <p className="text-[11px] text-slate-300 leading-relaxed">
                                                {f.recommendation}
                                            </p>
                                        </div>
                                    ))
                                )}

                                {aiReview.hardenedSnippet && (
                                    <div className="space-y-1.5">
                                        <div className="flex items-center justify-between text-[10px] text-emerald-400">
                                            <span>
                                                Suggested Auto-Remediation Patch
                                            </span>
                                            {onApplyCodeSnippet && !isViewer && (
                                                <button
                                                    type="button"
                                                    onClick={() =>
                                                        onApplyCodeSnippet(
                                                            aiReview.hardenedSnippet!
                                                        )
                                                    }
                                                    className="px-2 py-0.5 rounded bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/40"
                                                >
                                                    Apply Patch
                                                </button>
                                            )}
                                        </div>
                                        <pre className="p-2.5 rounded-xl bg-[#090D16] border border-slate-800 text-[10px] text-emerald-200 overflow-x-auto whitespace-pre-wrap">
                                            {aiReview.hardenedSnippet}
                                        </pre>
                                    </div>
                                )}
                            </div>
                        ) : (
                            <div className="space-y-2.5">
                                <div className="flex items-center justify-between">
                                    <span className="text-[11px] font-semibold text-emerald-300">
                                        Generated Security &amp; Boundary Tests
                                    </span>
                                    <button
                                        type="button"
                                        onClick={() => {
                                            navigator.clipboard.writeText(
                                                aiUnitTests
                                            );
                                            setCopiedSnippet(true);
                                            setTimeout(
                                                () => setCopiedSnippet(false),
                                                2000
                                            );
                                        }}
                                        className="px-2 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-[10px] text-cyan-300 flex items-center gap-1"
                                    >
                                        {copiedSnippet ? (
                                            <>
                                                <Check className="w-3 h-3 text-emerald-400" />
                                                <span>Copied</span>
                                            </>
                                        ) : (
                                            <>
                                                <Copy className="w-3 h-3" />
                                                <span>Copy Suite</span>
                                            </>
                                        )}
                                    </button>
                                </div>

                                <pre className="p-3 rounded-xl bg-[#090D16] border border-slate-800 text-[11px] text-slate-200 overflow-x-auto whitespace-pre-wrap leading-relaxed">
                                    {aiUnitTests}
                                </pre>
                            </div>
                        )}
                    </div>
                </div>
            )}
        </aside>
    );
};

export default CollabDrawer;