import { describe, expect, it, vi, beforeEach, type Mock } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { App } from 'antd';
import { MemoryRouter } from 'react-router-dom';
import TaskManagement from './TaskManagement';
import { listTasks } from '../services/api';

vi.mock('gsap', () => ({
    default: {
        context: (_fn: () => void) => ({ revert: vi.fn() }),
        from: vi.fn(),
    },
}));

vi.mock('../components/NetworkCanvas', () => ({
    default: () => <div data-testid="network-canvas" />,
}));

vi.mock('../contexts/GlobalAIContext', () => ({
    useAutoContext: vi.fn(),
}));

vi.mock('../utils/auth', () => ({
    canAccessRole: () => true,
}));

vi.mock('../services/api', () => ({
    listTasks: vi.fn(),
    listProjects: vi.fn().mockResolvedValue([{ ID: 'project-1', Name: '默认项目', Status: 'active' }]),
    getNodes: vi.fn().mockResolvedValue([
        {
            AgentID: 'agent-1',
            Status: 'Alive',
            Tags: '{"cloud":"aliyun","region":"cn-hangzhou","target_type":"all"}',
            Capacity: 4,
            RunningTasks: 1,
        },
    ]),
    createTask: vi.fn().mockResolvedValue({ status: 'ok' }),
    previewTaskSelector: vi.fn().mockResolvedValue({
        matched_nodes: 1,
        available_slots: 3,
        reasons: [],
        effective_selectors: [{ cloud: 'aliyun', target_type: 'all' }],
    }),
    connectWebSocket: vi.fn(() => ({ close: vi.fn() })),
    deleteTask: vi.fn(),
    cancelTask: vi.fn(),
    getTaskDetail: vi.fn(),
}));

describe('TaskManagement', () => {
    const listTasksMock = listTasks as unknown as Mock;

    beforeEach(() => {
        localStorage.setItem('active_project_id', 'project-1');
        listTasksMock.mockReset();
        listTasksMock.mockResolvedValue({
            items: [],
            total: 0,
            page: 1,
            page_size: 20,
            has_more: false,
        });
    });

    it('exposes agent selector controls in the create task dialog', async () => {
        const user = userEvent.setup();
        render(
            <MemoryRouter>
                <App>
                    <TaskManagement />
                </App>
            </MemoryRouter>
        );

        await user.click(await screen.findByRole('button', { name: /创建任务/i }));

        expect(screen.getByText(/匹配在线节点/)).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /添加标签条件/i })).toBeInTheDocument();
    });

    it('requests the next page from the server when table pagination changes', async () => {
        const user = userEvent.setup();
        listTasksMock.mockImplementation(async (params?: unknown) => {
            const page = typeof params === 'object' && params && 'page' in params
                ? Number((params as { page?: number }).page || 1)
                : 1;
            return {
                items: [{
                    ID: `task-${page}`,
                    Name: `Task ${page}`,
                    Status: 'Queued',
                    TotalTargets: 1,
                    CompletedTargets: 0,
                    TotalChunks: 1,
                    CompletedChunks: 0,
                    Priority: 1,
                    CreatedAt: '2026-07-05T08:00:00Z',
                } as API.RootTask],
                total: 25,
                page,
                page_size: 20,
                has_more: page * 20 < 25,
            };
        });

        render(
            <MemoryRouter>
                <App>
                    <TaskManagement />
                </App>
            </MemoryRouter>
        );

        expect(await screen.findByText('Task 1')).toBeInTheDocument();
        await user.click(screen.getByRole('listitem', { name: '2' }));
        expect(await screen.findByText('Task 2')).toBeInTheDocument();
        expect(listTasksMock).toHaveBeenLastCalledWith({
            projectId: 'project-1',
            page: 2,
            pageSize: 20,
        });
    });
});
