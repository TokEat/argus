export const PROJECTS_CHANGED_EVENT = 'argus:projects-changed';

export function notifyProjectsChanged(preferredProjectId?: string): void {
    window.dispatchEvent(new CustomEvent(PROJECTS_CHANGED_EVENT, {
        detail: { preferredProjectId: preferredProjectId || '' },
    }));
}

export function projectChangePreference(event: Event): string {
    if (!(event instanceof CustomEvent)) return '';
    const detail = event.detail as { preferredProjectId?: unknown } | undefined;
    return typeof detail?.preferredProjectId === 'string' ? detail.preferredProjectId : '';
}
