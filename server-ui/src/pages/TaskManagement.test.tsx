import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { App } from 'antd';
import { MemoryRouter } from 'react-router-dom';
import TaskManagement from './TaskManagement';

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
    listTasks: vi.fn().mockResolvedValue([]),
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
    beforeEach(() => {
        localStorage.setItem('active_project_id', 'project-1');
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
});
