import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const { listProjectsMock } = vi.hoisted(() => ({
    listProjectsMock: vi.fn(),
}));

vi.mock('../services/api', () => ({
    listProjects: listProjectsMock,
}));

vi.mock('../routes', () => ({
    menuRoutes: [],
}));

vi.mock('../utils/auth', () => ({
    canAccessRole: () => false,
    getCurrentUserRole: () => 'viewer',
    roleLabel: { viewer: '只读用户' },
}));

vi.mock('../contexts/GlobalAIContext', () => ({
    useGlobalAI: () => ({
        visible: false,
        pageContext: {},
        copilotContext: {},
        editableTarget: undefined,
        openGlobalAI: vi.fn(),
        closeGlobalAI: vi.fn(),
        setPageContext: vi.fn(),
        setIdentity: vi.fn(),
    }),
}));

import BasicLayout from './BasicLayout';
import { notifyProjectsChanged } from '../utils/projectSelection';

const project = (id: string, name: string): API.Project => ({
    ID: id,
    Name: name,
    Status: 'active',
} as API.Project);

const renderLayout = () => render(
    <MemoryRouter initialEntries={['/projects']}>
        <Routes>
            <Route element={<BasicLayout />}>
                <Route path="/projects" element={<div>项目页面</div>} />
            </Route>
        </Routes>
    </MemoryRouter>,
);

describe('BasicLayout project selector', () => {
    beforeEach(() => {
        localStorage.clear();
        localStorage.setItem('token', 'test-token');
        listProjectsMock.mockReset();
    });

    it('refreshes selectable projects when project management reports a change', async () => {
        listProjectsMock
            .mockResolvedValueOnce([project('project-old', '旧项目')])
            .mockResolvedValueOnce([
                project('project-old', '旧项目'),
                project('project-new', '新项目'),
            ]);
        localStorage.setItem('active_project_id', 'project-old');
        renderLayout();

        await waitFor(() => expect(listProjectsMock).toHaveBeenCalledTimes(1));
        act(() => notifyProjectsChanged());
        await waitFor(() => expect(listProjectsMock).toHaveBeenCalledTimes(2));

        fireEvent.mouseDown(screen.getByRole('combobox'));
        expect(await screen.findByRole('option', { name: '新项目' })).toBeInTheDocument();
        expect(localStorage.getItem('active_project_id')).toBe('project-old');
    });

    it('falls back to an accessible active project when the selected project disappears', async () => {
        listProjectsMock
            .mockResolvedValueOnce([project('project-old', '旧项目')])
            .mockResolvedValueOnce([project('project-new', '新项目')]);
        localStorage.setItem('active_project_id', 'project-old');
        renderLayout();

        await waitFor(() => expect(listProjectsMock).toHaveBeenCalledTimes(1));
        act(() => notifyProjectsChanged());

        await waitFor(() => expect(localStorage.getItem('active_project_id')).toBe('project-new'));
        expect(screen.getByText('新项目')).toBeInTheDocument();
    });

    it('ignores an older project response that finishes after the latest refresh', async () => {
        let resolveInitial: (projects: API.Project[]) => void = () => undefined;
        let resolveRefresh: (projects: API.Project[]) => void = () => undefined;
        listProjectsMock
            .mockImplementationOnce(() => new Promise<API.Project[]>((resolve) => { resolveInitial = resolve; }))
            .mockImplementationOnce(() => new Promise<API.Project[]>((resolve) => { resolveRefresh = resolve; }));
        renderLayout();

        await waitFor(() => expect(listProjectsMock).toHaveBeenCalledTimes(1));
        act(() => notifyProjectsChanged());
        await waitFor(() => expect(listProjectsMock).toHaveBeenCalledTimes(2));
        await act(async () => resolveRefresh([project('project-new', '新项目')]));
        await waitFor(() => expect(screen.getByText('新项目')).toBeInTheDocument());
        await act(async () => resolveInitial([project('project-old', '旧项目')]));

        fireEvent.mouseDown(screen.getByRole('combobox'));
        expect(await screen.findByRole('option', { name: '新项目' })).toBeInTheDocument();
        expect(screen.queryByRole('option', { name: '旧项目' })).not.toBeInTheDocument();
        expect(localStorage.getItem('active_project_id')).toBe('project-new');
    });

    it('removes the project change listener when the layout unmounts', async () => {
        listProjectsMock.mockResolvedValue([project('project-old', '旧项目')]);
        const view = renderLayout();
        await waitFor(() => expect(listProjectsMock).toHaveBeenCalledTimes(1));

        view.unmount();
        act(() => notifyProjectsChanged());

        expect(listProjectsMock).toHaveBeenCalledTimes(1);
    });

    it('ignores an in-flight project response after the layout unmounts', async () => {
        let resolveInitial: (projects: API.Project[]) => void = () => undefined;
        listProjectsMock.mockImplementationOnce(
            () => new Promise<API.Project[]>((resolve) => { resolveInitial = resolve; }),
        );
        const view = renderLayout();
        await waitFor(() => expect(listProjectsMock).toHaveBeenCalledTimes(1));

        view.unmount();
        await act(async () => resolveInitial([project('project-old', '旧项目')]));

        expect(localStorage.getItem('active_project_id')).toBeNull();
    });
});
