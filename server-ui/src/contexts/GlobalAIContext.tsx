import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';
import type { ReactNode } from 'react';

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
        <GlobalAIContext.Provider value={{ visible, pageContext, editableTarget, openGlobalAI, closeGlobalAI, setPageContext: setContext, registerEditableTarget }}>
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
