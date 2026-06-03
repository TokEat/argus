import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { getNodes, getQueueDepth, listTasks } from '../services/api';

// ============================================================
// Types: Layered Copilot Context
// ============================================================

/** Layer 1: Session identity — low-frequency, set by BasicLayout */
export interface CopilotIdentity {
    tenant_id: string;
    user_id: string;
    role: string;
    username: string;
    active_project_id: string;
    active_project_name: string;
}

/** Layer 2: Page focus — updated on route/entity changes */
export interface CopilotFocus {
    module: string;
    route: string;
    entity_type?: string;       // task | vuln | asset | node | rule
    entity_id?: string;
    entity_summary?: string;
    action_context?: string;    // creating | editing | viewing | debugging
}

/** Layer 4: Global ambient — 30s polling */
export interface AgentSummary {
    agent_id: string;
    ip: string;
    status: string;
    version: string;
    os: string;
    capacity: number;
    running_tasks: number;
    cpu: number;
    mem: number;
}

export interface QueueSummary {
    total_depth: number;
    ready_batches: number;
    pending_batches: number;
    ready_targets: number;
    pending_targets: number;
}

export interface ActiveScanSummary {
    id: string;
    name: string;
    status: string;
    total_targets: number;
    completed_targets: number;
    created_at: string;
}

export interface CopilotAmbient {
    agents: {
        total: number;
        online: number;
        offline: number;
        top_busy: AgentSummary[];
    };
    queue: QueueSummary;
    active_scans: ActiveScanSummary[];
}

export interface CopilotRequestContext {
    _identity: CopilotIdentity;
    _focus: CopilotFocus;
    data: Record<string, unknown>;
    _ambient: CopilotAmbient;
}

/** Backward-compatible PageContext (flat map, still used by useAutoContext) */
export interface PageContext {
    module?: string;
    route?: string;
    title?: string;
    selected_data?: unknown;
    [key: string]: unknown;
}

/** Editable target for rule/config inline editing */
export interface AIEditableTarget {
    id: string;
    type: 'poc' | 'exp' | 'workflow' | 'fingerprint' | 'dir' | 'text';
    label: string;
    getContent: () => string;
    applyContent: (content: string) => void;
    canApplyContent?: (content: string) => { ok: boolean; reason?: string };
    saveDraft?: (contentOverride?: string) => Promise<void>;
}

// ============================================================
// Context State
// ============================================================

interface GlobalAIState {
    visible: boolean;
    /** Full layered context — sent to backend as page_context */
    copilotContext: CopilotRequestContext;
    /** Backward-compatible flat context (derived from copilotContext + data) */
    pageContext: PageContext;
    editableTarget?: AIEditableTarget;

    // Actions
    openGlobalAI: (contextData?: PageContext) => void;
    closeGlobalAI: () => void;
    setPageContext: React.Dispatch<React.SetStateAction<PageContext>>;
    setIdentity: React.Dispatch<React.SetStateAction<CopilotIdentity>>;
    setFocus: React.Dispatch<React.SetStateAction<CopilotFocus>>;
    setData: React.Dispatch<React.SetStateAction<Record<string, unknown>>>;
    registerEditableTarget: (target: AIEditableTarget) => () => void;
}

const GlobalAIContext = createContext<GlobalAIState | undefined>(undefined);

// ============================================================
// Defaults
// ============================================================

const defaultIdentity: CopilotIdentity = {
    tenant_id: 'default',
    user_id: '',
    role: 'viewer',
    username: '',
    active_project_id: '',
    active_project_name: '',
};

const defaultFocus: CopilotFocus = {
    module: 'global',
    route: '',
};

const defaultAmbient: CopilotAmbient = {
    agents: { total: 0, online: 0, offline: 0, top_busy: [] },
    queue: { total_depth: 0, ready_batches: 0, pending_batches: 0, ready_targets: 0, pending_targets: 0 },
    active_scans: [],
};

// ============================================================
// Provider
// ============================================================

export const GlobalAIProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
    const [visible, setVisible] = useState(false);
    const [pageContext, setPageContext] = useState<PageContext>({});
    const [editableTarget, setEditableTarget] = useState<AIEditableTarget | undefined>();

    // Layered context state
    const [identity, setIdentity] = useState<CopilotIdentity>(defaultIdentity);
    const [focus, setFocus] = useState<CopilotFocus>(defaultFocus);
    const [data, setData] = useState<Record<string, unknown>>({});
    const [ambient, setAmbient] = useState<CopilotAmbient>(defaultAmbient);

    // ---- Ambient Context: 30s polling for global platform state ----
    useEffect(() => {
        let cancelled = false;

        const poll = async () => {
            try {
                const [nodesResult, queueResult, tasksResult] = await Promise.allSettled([
                    getNodes(),
                    getQueueDepth(),
                    listTasks(),
                ]);

                if (cancelled) return;

                // --- Agents ---
                let agentFleet: CopilotAmbient['agents'] | undefined;
                if (nodesResult.status === 'fulfilled') {
                    const nodes = nodesResult.value;
                    const online = nodes.filter((n: API.AgentNode) => n.Status === 'Alive');
                    const sorted = [...online].sort((a, b) => (b.RunningTasks || 0) - (a.RunningTasks || 0));
                    const capped = sorted.slice(0, 10);
                    agentFleet = {
                        total: nodes.length,
                        online: online.length,
                        offline: nodes.length - online.length,
                        top_busy: capped.map((n: API.AgentNode) => ({
                            agent_id: n.AgentID,
                            ip: n.IP,
                            status: n.Status,
                            version: n.Version,
                            os: n.OS || '',
                            capacity: n.Capacity || 1,
                            running_tasks: n.RunningTasks || 0,
                            cpu: Math.round(n.CPUUsage || 0),
                            mem: Math.round(n.MemUsage || 0),
                        })),
                    };
                }

                // --- Queue ---
                let queueStats: QueueSummary | undefined;
                if (queueResult.status === 'fulfilled') {
                    const q = queueResult.value;
                    queueStats = {
                        total_depth: Object.values(q.depth || {}).reduce((s, v) => s + (v as number), 0),
                        ready_batches: q.ready_batches || 0,
                        pending_batches: q.pending_batches || 0,
                        ready_targets: q.ready_targets || 0,
                        pending_targets: q.pending_targets || 0,
                    };
                }

                // --- Active Scans ---
                let activeScans: ActiveScanSummary[] | undefined;
                if (tasksResult.status === 'fulfilled') {
                    const tasks = tasksResult.value;
                    activeScans = tasks
                        .filter(t => String(t.Status || '').toUpperCase() === 'RUNNING')
                        .slice(0, 5)
                        .map((t: API.RootTask) => ({
                            id: t.ID || '',
                            name: t.Name || '',
                            status: t.Status || '',
                            total_targets: t.TotalTargets || 0,
                            completed_targets: t.CompletedTargets || 0,
                            created_at: t.CreatedAt || '',
                        }));
                }

                setAmbient(prev => ({
                    agents: agentFleet || prev.agents,
                    queue: queueStats || prev.queue,
                    active_scans: activeScans || prev.active_scans,
                }));
            } catch {
                // silent — ambient data is best-effort
            }
        };

        poll();
        const timer = setInterval(poll, 30_000);
        return () => { cancelled = true; clearInterval(timer); };
    }, []);

    // ---- Derive backward-compatible flat pageContext ----
    const mergedPageContext = useMemo<PageContext>(() => ({
        ...pageContext,
        // Inject identity (read-only for LLM)
        _identity: identity,
        // Inject focus
        _focus: {
            ...focus,
            ...(('module' in pageContext) ? { module: pageContext.module } : {}),
            ...(('route' in pageContext) ? { route: pageContext.route } : {}),
        },
        // Inject ambient
        _ambient: ambient,
    }), [pageContext, identity, focus, ambient]);

    // ---- Build structured copilotContext for backend ----
    const copilotContext = useMemo<CopilotRequestContext>(() => {
        const pageData: Record<string, unknown> = {};
        Object.entries(pageContext).forEach(([key, value]) => {
            if (key === 'module' || key === 'route' || key === '_identity' || key === '_focus' || key === '_ambient') {
                return;
            }
            pageData[key] = value;
        });

        return {
            _identity: identity,
            _focus: {
                ...focus,
                ...(('module' in pageContext) ? { module: pageContext.module } : {}),
                ...(('route' in pageContext) ? { route: pageContext.route } : {}),
            },
            data: {
                ...pageData,
                ...data,
            },
            _ambient: ambient,
        };
    }, [identity, focus, pageContext, data, ambient]);

    const openGlobalAI = useCallback((contextData?: PageContext) => {
        if (contextData) {
            setPageContext((prev) => ({ ...prev, ...contextData }));
        }
        setVisible(true);
    }, []);

    const closeGlobalAI = useCallback(() => {
        setVisible(false);
    }, []);

    const registerEditableTarget = useCallback((target: AIEditableTarget) => {
        setEditableTarget(target);
        return () => {
            setEditableTarget((current) => current?.id === target.id ? undefined : current);
        };
    }, []);

    return (
        <GlobalAIContext.Provider value={{
            visible,
            copilotContext,
            pageContext: mergedPageContext,
            editableTarget,
            openGlobalAI,
            closeGlobalAI,
            setPageContext,
            setIdentity,
            setFocus,
            setData,
            registerEditableTarget,
        }}>
            {children}
        </GlobalAIContext.Provider>
    );
};

// ============================================================
// Hooks
// ============================================================

export const useGlobalAI = () => {
    const context = useContext(GlobalAIContext);
    if (!context) {
        throw new Error('useGlobalAI must be used within a GlobalAIProvider');
    }
    return context;
};

/**
 * Backward-compatible hook for pages to inject local state into context.
 * Existing callers don't need to change.
 */
export const useAutoContext = (localContext: PageContext) => {
    const { setPageContext } = useGlobalAI();

    useEffect(() => {
        setPageContext((prev) => ({ ...prev, ...localContext }));

        return () => {
            setPageContext((prev) => {
                const cleaned = { ...prev };
                Object.keys(localContext).forEach(key => {
                    delete cleaned[key];
                });
                return cleaned;
            });
        };
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [JSON.stringify(localContext)]);
};

/**
 * Hook for pages to declare their focus context (what the user is looking at).
 * Automatically cleans up on unmount.
 *
 * @example
 * useFocusContext({ module: 'task_results', action_context: 'viewing' });
 */
export const useFocusContext = (focus: Partial<CopilotFocus>) => {
    const { setFocus } = useGlobalAI();
    const focusRef = useRef(focus);

    useEffect(() => {
        focusRef.current = focus;
        setFocus(prev => ({ ...prev, ...focus }));

        return () => {
            setFocus(prev => {
                const cleaned = { ...prev };
                Object.keys(focusRef.current).forEach(k => {
                    delete cleaned[k as keyof CopilotFocus];
                });
                return cleaned;
            });
        };
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [JSON.stringify(focus)]);
};

/**
 * Hook for components to inject the currently selected entity detail.
 * When entity is undefined/null, cleans up previously injected data.
 *
 * @example
 * useEntityContext(selectedVuln ? {
 *   type: 'vuln', id: selectedVuln.ID,
 *   summary: `${selectedVuln.Severity} ${selectedVuln.Plugin} on ${selectedVuln.Target}`,
 *   data: selectedVuln
 * } : undefined);
 */
export const useEntityContext = (entity?: {
    type: string;
    id: string;
    summary: string;
    data?: unknown;
}) => {
    const { setFocus, setData } = useGlobalAI();
    const prevEntityRef = useRef<typeof entity>(undefined);

    useEffect(() => {
        // Clean up previous entity
        if (prevEntityRef.current && prevEntityRef.current.id !== entity?.id) {
            setFocus(prev => {
                const cleaned = { ...prev };
                delete cleaned.entity_type;
                delete cleaned.entity_id;
                delete cleaned.entity_summary;
                return cleaned;
            });
            setData(prev => {
                const cleaned = { ...prev };
                delete cleaned[`selected_${prevEntityRef.current!.type}`];
                return cleaned;
            });
        }

        if (entity) {
            setFocus(prev => ({
                ...prev,
                entity_type: entity.type,
                entity_id: entity.id,
                entity_summary: entity.summary,
            }));
            if (entity.data !== undefined) {
                setData(prev => ({ ...prev, [`selected_${entity.type}`]: entity.data }));
            }
        }

        prevEntityRef.current = entity;
    }, [entity?.id, entity?.type, entity?.summary]);
};
