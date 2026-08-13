import { describe, expect, it, vi } from 'vitest';
import { notifyProjectsChanged, PROJECTS_CHANGED_EVENT, projectChangePreference } from './projectSelection';

describe('project selection events', () => {
    it('publishes the newly created project as the preferred immediate selection', () => {
        const listener = vi.fn();
        window.addEventListener(PROJECTS_CHANGED_EVENT, listener);

        notifyProjectsChanged('project-new');

        expect(listener).toHaveBeenCalledTimes(1);
        expect(projectChangePreference(listener.mock.calls[0][0])).toBe('project-new');
        window.removeEventListener(PROJECTS_CHANGED_EVENT, listener);
    });
});
