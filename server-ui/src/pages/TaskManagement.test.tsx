import { describe, expect, it, vi, beforeEach, type Mock } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { App } from 'antd';
import { MemoryRouter } from 'react-router-dom';
import TaskManagement from './TaskManagement';
import { createTask, listTasks, validateTargets } from '../services/api';

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
    validateTargets: vi.fn().mockResolvedValue({ valid: [], invalid: [], summary: {} }),
    previewTaskSelector: vi.fn().mockResolvedValue({
        matched_nodes: 1,
        available_slots: 3,
        reasons: [],
        effective_selectors: [{ cloud: 'aliyun', target_type: 'all' }],
    }),
    connectWebSocket: vi.fn(() => ({ close: vi.fn() })),
    deleteTask: vi.fn(),
    cancelTask: vi.fn(),
    pauseTask: vi.fn(),
    resumeTask: vi.fn(),
    getTaskDetail: vi.fn(),
}));

describe('TaskManagement', () => {
    const listTasksMock = listTasks as unknown as Mock;
    const createTaskMock = createTask as unknown as Mock;
    const validateTargetsMock = validateTargets as unknown as Mock;

    beforeEach(() => {
        localStorage.setItem('active_project_id', 'project-1');
        listTasksMock.mockReset();
        createTaskMock.mockClear();
        validateTargetsMock.mockReset();
        validateTargetsMock.mockResolvedValue({ valid: [], invalid: [], summary: {} });
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

    it('uses positive wording for negative scan config switches', async () => {
        const user = userEvent.setup();
        render(
            <MemoryRouter>
                <App>
                    <TaskManagement />
                </App>
            </MemoryRouter>
        );

        await user.click(await screen.findByRole('button', { name: /创建任务/i }));
        await user.click(screen.getByText('主机发现'));
        await user.click(screen.getByText('子域名探测'));
        await user.click(screen.getByText('Web 探针'));
        await user.click(screen.getByText('漏洞探测'));

        expect(getFormItemByLabel('主机发现')).toBeInTheDocument();
        expect(getFormItemByLabel('ICMP 探测')).toBeInTheDocument();
        expect(getFormItemByLabel('子域爆破')).toBeInTheDocument();
        expect(getFormItemByLabel('被动枚举')).toBeInTheDocument();
        expect(getFormItemByLabel('域名绑定探测')).toBeInTheDocument();
        expect(getFormItemByLabel('主动目录指纹')).toBeInTheDocument();
        expect(getFormItemByLabel('漏洞探测')).toBeInTheDocument();
        expect(getFormItemByLabel('通用 POC')).toBeInTheDocument();
        expect(screen.queryByText('跳过主机发现')).not.toBeInTheDocument();
        expect(screen.queryByText('禁用 ICMP 探测')).not.toBeInTheDocument();
        expect(screen.queryByText('关闭漏洞探测')).not.toBeInTheDocument();
        expect(screen.queryByText('禁用通用 POC')).not.toBeInTheDocument();
    });

    it('submits negative config fields when positive scan switches are turned off', async () => {
        const user = userEvent.setup();
        render(
            <MemoryRouter>
                <App>
                    <TaskManagement />
                </App>
            </MemoryRouter>
        );

        await user.click(await screen.findByRole('button', { name: /创建任务/i }));
        await user.type(screen.getByPlaceholderText('输入任务名称'), '分页与开关回归任务');
        await user.type(screen.getByPlaceholderText(/192\.168\.1\.10/), '127.0.0.1');
        await user.click(screen.getByText('主机发现'));
        await user.click(screen.getByText('漏洞探测'));
        await user.click(getSwitchByFormLabel('主机发现'));
        await user.click(getSwitchByFormLabel('ICMP 探测'));
        await user.click(getSwitchByFormLabel('漏洞探测'));
        await user.click(getSwitchByFormLabel('通用 POC'));
        const dialog = screen.getByRole('dialog', { name: '创建扫描任务' });
        await user.click(within(dialog).getByRole('button', { name: /创\s*建/ }));

        await waitFor(() => expect(createTaskMock).toHaveBeenCalledWith(expect.objectContaining({
            config: expect.objectContaining({
                SkipHostDiscovery: true,
                NoICMPPing: true,
                NoPoc: true,
                DisableGeneralPoc: true,
            }),
        })));
    });

    it('shows invalid targets and explicitly skips them before creating', async () => {
		const user = userEvent.setup();
		validateTargetsMock.mockResolvedValue({
			valid: ['http://127.0.0.1:18080'],
			invalid: [{ target: 'invalid target', reason: '无法识别的目标格式' }],
			summary: { mode: 'direct', total: 2, urls: 1 },
		});
		render(
			<MemoryRouter>
				<App>
					<TaskManagement />
				</App>
			</MemoryRouter>
		);

		await user.click(await screen.findByRole('button', { name: /创建任务/i }));
		await user.type(screen.getByPlaceholderText('输入任务名称'), '目标预校验任务');
		await user.type(screen.getByPlaceholderText(/192\.168\.1\.10/), 'http://127.0.0.1:18080{enter}invalid target');
		const createDialog = screen.getByRole('dialog', { name: '创建扫描任务' });
		await user.click(within(createDialog).getByRole('button', { name: /创\s*建/ }));

		expect(await screen.findByText('目标预校验')).toBeInTheDocument();
		expect(await screen.findByDisplayValue('invalid target')).toBeInTheDocument();
		await user.click(screen.getByRole('button', { name: '跳过无效项并创建' }));

		await waitFor(() => expect(createTaskMock).toHaveBeenCalledWith(expect.objectContaining({
			skip_unsupported: true,
			targets: expect.stringContaining('invalid target'),
		})));
	});

	it('revalidates corrected invalid targets before creating', async () => {
		const user = userEvent.setup();
		validateTargetsMock
			.mockResolvedValueOnce({
				valid: ['http://127.0.0.1:18080'],
				invalid: [{ target: 'bad target', reason: '无法识别的目标格式' }],
				summary: { mode: 'direct', total: 2, urls: 1 },
			})
			.mockResolvedValueOnce({
				valid: ['http://127.0.0.1:18080', 'https://example.test'],
				invalid: [],
				summary: { mode: 'direct', total: 2, urls: 2 },
			});
		render(
			<MemoryRouter>
				<App>
					<TaskManagement />
				</App>
			</MemoryRouter>
		);

		await user.click(await screen.findByRole('button', { name: /创建任务/i }));
		await user.type(screen.getByPlaceholderText('输入任务名称'), '目标修正任务');
		await user.type(screen.getByPlaceholderText(/192\.168\.1\.10/), 'http://127.0.0.1:18080{enter}bad target');
		await user.click(within(screen.getByRole('dialog', { name: '创建扫描任务' })).getByRole('button', { name: /创\s*建/ }));

		const invalidInput = await screen.findByDisplayValue('bad target');
		await user.clear(invalidInput);
		await user.type(invalidInput, 'https://example.test');
		await user.click(screen.getByRole('button', { name: '重新校验并创建' }));

		await waitFor(() => expect(validateTargetsMock).toHaveBeenCalledTimes(2));
		await waitFor(() => expect(createTaskMock).toHaveBeenCalledWith(expect.objectContaining({
			skip_unsupported: false,
			targets: 'http://127.0.0.1:18080\nhttps://example.test',
		})));
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

    it('shows pause and resume actions for pausable task states', async () => {
        listTasksMock.mockResolvedValue({
            items: [
                {
                    ID: 'task-running',
                    Name: 'Running Task',
                    Status: 'Running',
                    TotalTargets: 1,
                    CompletedTargets: 0,
                    TotalChunks: 1,
                    CompletedChunks: 0,
                    Priority: 1,
                    CreatedAt: '2026-07-05T08:00:00Z',
                } as API.RootTask,
                {
                    ID: 'task-paused',
                    Name: 'Paused Task',
                    Status: 'Paused',
                    TotalTargets: 1,
                    CompletedTargets: 0,
                    TotalChunks: 1,
                    CompletedChunks: 0,
                    Priority: 1,
                    CreatedAt: '2026-07-05T08:00:00Z',
                } as API.RootTask,
            ],
            total: 2,
            page: 1,
            page_size: 20,
            has_more: false,
        });

        render(
            <MemoryRouter>
                <App>
                    <TaskManagement />
                </App>
            </MemoryRouter>
        );

        expect(await screen.findByText('Running Task')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /暂停/ })).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /恢复/ })).toBeInTheDocument();
    });

    it('does not show pause action for pending tasks because backend only accepts queued running and partial done', async () => {
        listTasksMock.mockResolvedValue({
            items: [
                {
                    ID: 'task-pending',
                    Name: 'Pending Task',
                    Status: 'Pending',
                    TotalTargets: 1,
                    CompletedTargets: 0,
                    TotalChunks: 1,
                    CompletedChunks: 0,
                    Priority: 1,
                    CreatedAt: '2026-07-05T08:00:00Z',
                } as API.RootTask,
            ],
            total: 1,
            page: 1,
            page_size: 20,
            has_more: false,
        });

        render(
            <MemoryRouter>
                <App>
                    <TaskManagement />
                </App>
            </MemoryRouter>
        );

        expect(await screen.findByText('Pending Task')).toBeInTheDocument();
        expect(screen.queryByRole('button', { name: /暂停/ })).not.toBeInTheDocument();
    });
});

function getFormItemByLabel(label: string): HTMLElement {
    const formItem = screen
        .getAllByText(label)
        .map((node) => node.closest('.ant-form-item'))
        .find(Boolean);
    expect(formItem).toBeTruthy();
    return formItem as HTMLElement;
}

function getSwitchByFormLabel(label: string): HTMLElement {
    return getFormItemByLabel(label).querySelector('[role="switch"]') as HTMLElement;
}
