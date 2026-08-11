import { beforeEach, describe, expect, it, type Mock, vi } from 'vitest';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { App } from 'antd';
import { MemoryRouter } from 'react-router-dom';
import TaskManagement from './TaskManagement';
import { createTask, listProjects, listTasks, validateTargets } from '../services/api';

const { canAccessRoleMock } = vi.hoisted(() => ({
    canAccessRoleMock: vi.fn(() => true),
}));

vi.mock('../components/NetworkCanvas', () => ({
    default: () => <div data-testid="network-canvas" />,
}));

vi.mock('../contexts/GlobalAIContext', () => ({
    useAutoContext: vi.fn(),
}));

vi.mock('../utils/auth', () => ({
    canAccessRole: canAccessRoleMock,
}));

vi.mock('../services/api', () => ({
    listTasks: vi.fn(),
    listProjects: vi.fn(),
    getNodes: vi.fn().mockResolvedValue([]),
    createTask: vi.fn().mockResolvedValue({ status: 'ok' }),
    validateTargets: vi.fn().mockResolvedValue({ valid: [], invalid: [], summary: {} }),
    previewTaskSelector: vi.fn().mockResolvedValue({
        matched_nodes: 0,
        available_slots: 0,
        reasons: [],
        effective_selectors: [],
    }),
    connectWebSocket: vi.fn(() => ({ close: vi.fn() })),
    deleteTask: vi.fn(),
    cancelTask: vi.fn(),
    stopTask: vi.fn(),
    pauseTask: vi.fn(),
    resumeTask: vi.fn(),
    retryTask: vi.fn(),
    getTaskDetail: vi.fn(),
    previewTaskRiskValidation: vi.fn(),
    executeTaskRiskValidation: vi.fn(),
    listPocRulesPage: vi.fn(),
    getTaskConfigRevisions: vi.fn(),
    updateTaskConfig: vi.fn(),
    appendTargets: vi.fn(),
    pauseTaskBatch: vi.fn(),
    resumeTaskBatch: vi.fn(),
    stopTaskBatch: vi.fn(),
    retryTaskBatch: vi.fn(),
    archiveTaskBatch: vi.fn(),
}));

describe('TaskManagement direct-only task creation', () => {
    const createTaskMock = createTask as unknown as Mock;
    const listProjectsMock = listProjects as unknown as Mock;
    const listTasksMock = listTasks as unknown as Mock;
    const validateTargetsMock = validateTargets as unknown as Mock;

    beforeEach(() => {
        localStorage.setItem('active_project_id', 'project-1');
        canAccessRoleMock.mockReturnValue(true);
        createTaskMock.mockClear();
        listProjectsMock.mockResolvedValue([{ ID: 'project-1', Name: '默认项目', Status: 'active' }]);
        listTasksMock.mockResolvedValue({ items: [], total: 0, page: 1, page_size: 20, has_more: false });
        validateTargetsMock.mockResolvedValue({ valid: [], invalid: [], summary: {} });
    });

    it('only exposes direct targets and strips legacy provider configuration', async () => {
        const user = userEvent.setup();
        render(<MemoryRouter><App><TaskManagement /></App></MemoryRouter>);

        await user.click(await screen.findByRole('button', { name: /创建任务/i }));
        const dialog = screen.getByRole('dialog', { name: '创建扫描任务' });
        expect(within(dialog).queryByText('目标来源')).not.toBeInTheDocument();
        expect(within(dialog).queryByText('网络空间搜索引擎')).not.toBeInTheDocument();
        expect(within(dialog).queryByText(/Hunter 每页数量/)).not.toBeInTheDocument();
        expect(within(dialog).queryByText(/Fofa 最大数量/)).not.toBeInTheDocument();
        expect(within(dialog).queryByText(/Quake 最大数量/)).not.toBeInTheDocument();
        expect(within(dialog).queryByPlaceholderText(/APIConfigFilePath/)).not.toBeInTheDocument();

        await user.type(screen.getByPlaceholderText(/192\.168\.1\.10/), 'https://example.test');
        await user.click(within(dialog).getByRole('button', { name: /高级设置/ }));
        await user.click(within(dialog).getByRole('button', { name: /高级配置/ }));
        fireEvent.change(screen.getByLabelText('额外 Agent 配置 JSON'), {
            target: { value: '{"hunter":true,"Fofa":true,"Quake":true,"OnlyIPPort":true,"APIConfigFilePath":"config/api-config.yaml"}' },
        });
        await user.click(within(dialog).getByRole('button', { name: /创\s*建/ }));

        await waitFor(() => expect(createTaskMock).toHaveBeenCalled());
        const config = createTaskMock.mock.calls[0][0].config;
        [
            'Hunter', 'HunterPageSize', 'HunterMaxPageCount',
            'Fofa', 'FofaMaxCount', 'Quake', 'QuakeSize',
            'OnlyIPPort', 'LowPerceptionMode',
            'hunter', 'APIConfigFilePath',
        ].forEach((key) => expect(config).not.toHaveProperty(key));
    });
});
