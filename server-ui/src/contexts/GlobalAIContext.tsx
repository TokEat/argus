import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { getNodes } from '../services/api';

export interface PageContext {
    module?: string;
    route?: string;
    title?: string;
    selected_data?: unknown;
    [key: string]: unknown;
}

export interface AIEditableTarget {
    id: string;
    type: 'poc' | 'workflow' | 'fingerprint' | 'dir' | 'text';
    label: string;
    getContent: () => string;
    applyContent: (content: string) => void;
    saveDraft?: () => Promise<void>;
}

interface GlobalAIState {
    visible: boolean;
    pageContext: PageContext;
    editableTarget?: AIEditableTarget;
    openGlobalAI: (contextData?: PageContext) => void;
    closeGlobalAI: () => void;
    setPageContext: React.Dispatch<React.SetStateAction<PageContext>>;
    registerEditableTarget: (target: AIEditableTarget) => () => void;
}

const GlobalAIContext = createContext<GlobalAIState | undefined>(undefined);

export const GlobalAIProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
    const [visible, setVisible] = useState(false);
    const [pageContext, setContext] = useState<PageContext>({});
    const [editableTarget, setEditableTarget] = useState<AIEditableTarget | undefined>();
    const [ambientContext, setAmbientContext] = useState<Record<string, unknown>>({});

    // Ambient Context: 30s polling for agent fleet status
    useEffect(() => {
        let cancelled = false;
        const poll = async () => {
            try {
                const nodes = await getNodes();
                if (cancelled) return;
                const online = nodes.filter((n: API.AgentNode) => n.Status === 'Alive');
                const sorted = [...online].sort((a, b) => (b.RunningTasks || 0) - (a.RunningTasks || 0));
                const capped = sorted.length > 20 ? sorted.slice(0, 20) : sorted;
                setAmbientContext((prev) => ({
                    ...prev,
                    agent_fleet: {
                        total: nodes.length,
                        online: online.length,
                        offline: nodes.length - online.length,
                        agents: capped.map((n: API.AgentNode) => ({
                            agent_id: n.AgentID,
                            ip: n.IP,
                            status: n.Status,
                            version: n.Version,
                            os: n.OS,
                            capacity: n.Capacity,
                            running_tasks: n.RunningTasks,
                            cpu: Math.round(n.CPUUsage || 0),
                            mem: Math.round(n.MemUsage || 0),
                        })),
                        ...(sorted.length > 20 ? { _truncated_note: `showing top 20 of ${sorted.length} online agents` } : {}),
                    },
                }));
            } catch {
                // silent — ambient data is best-effort
            }
        };
        poll();
        const timer = setInterval(poll, 30_000);
        return () => { cancelled = true; clearInterval(timer); };
    }, []);

    // Merge page context with ambient context
    const mergedContext = useMemo<PageContext>(() => ({
        ...pageContext,
        _ambient: ambientContext,
    }), [pageContext, ambientContext]);

    const openGlobalAI = (contextData?: PageContext) => {
        if (contextData) {
            setContext((prev) => ({ ...prev, ...contextData }));
        }
        setVisible(true);
    };

    const closeGlobalAI = () => {
        setVisible(false);
    };

    const registerEditableTarget = useCallback((target: AIEditableTarget) => {
        setEditableTarget(target);
        return () => {
            setEditableTarget((current) => current?.id === target.id ? undefined : current);
        };
    }, []);

    return (
        <GlobalAIContext.Provider value={{ visible, pageContext: mergedContext, editableTarget, openGlobalAI, closeGlobalAI, setPageContext: setContext, registerEditableTarget }}>
            {children}
        </GlobalAIContext.Provider>
    );
};

export const useGlobalAI = () => {
    const context = useContext(GlobalAIContext);
    if (!context) {
        throw new Error('useGlobalAI must be used within a GlobalAIProvider');
    }
    return context;
};

/**
 * Hook for pages to automatically inject local state into the Global AI context.
 * It merges the localContext with the existing pageContext (which contains the route info).
 * On unmount, it clears the injected local data.
 */
export const useAutoContext = (localContext: PageContext) => {
    const { setPageContext } = useGlobalAI();

    useEffect(() => {
        setPageContext((prev) => ({ ...prev, ...localContext }));

        return () => {
            // Clean up: remove the keys that were injected by this hook
            setPageContext((prev) => {
                const cleaned = { ...prev };
                Object.keys(localContext).forEach(key => {
                    delete cleaned[key];
                });
                return cleaned;
            });
        };
        // We only want to trigger this when localContext values actually change.
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [JSON.stringify(localContext)]);
};
