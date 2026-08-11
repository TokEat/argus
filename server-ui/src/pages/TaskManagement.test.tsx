import { describe, expect, it, vi, beforeEach, type Mock } from 'vitest';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { App } from 'antd';
import { MemoryRouter } from 'react-router-dom';
import TaskManagement from './TaskManagement';
import { appendTargets, archiveTaskBatch, createTask, deleteTask, executeTaskRiskValidation, getTaskConfigRevisions, getTaskDetail, listPocRulesPage, listProjects, listTasks, pauseTaskBatch, previewTaskRiskValidation, resumeTaskBatch, retryTask, retryTaskBatch, stopTaskBatch, updateTaskConfig, validateTargets } from '../services/api';

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

describe('TaskManagement', () => {
    const listTasksMock = listTasks as unknown as Mock;
    const listProjectsMock = listProjects as unknown as Mock;
    const createTaskMock = createTask as unknown as Mock;
    const deleteTaskMock = deleteTask as unknown as Mock;
    const validateTargetsMock = validateTargets as unknown as Mock;
    const getTaskDetailMock = getTaskDetail as unknown as Mock;
	const previewTaskRiskValidationMock = previewTaskRiskValidation as unknown as Mock;
	const executeTaskRiskValidationMock = executeTaskRiskValidation as unknown as Mock;
	const listPocRulesPageMock = listPocRulesPage as unknown as Mock;
    const getTaskConfigRevisionsMock = getTaskConfigRevisions as unknown as Mock;
    const updateTaskConfigMock = updateTaskConfig as unknown as Mock;
    const appendTargetsMock = appendTargets as unknown as Mock;
    const retryTaskMock = retryTask as unknown as Mock;
    const pauseTaskBatchMock = pauseTaskBatch as unknown as Mock;
    const resumeTaskBatchMock = resumeTaskBatch as unknown as Mock;
    const stopTaskBatchMock = stopTaskBatch as unknown as Mock;
    const retryTaskBatchMock = retryTaskBatch as unknown as Mock;
    const archiveTaskBatchMock = archiveTaskBatch as unknown as Mock;

    beforeEach(() => {
        localStorage.setItem('active_project_id', 'project-1');
        listTasksMock.mockReset();
        listProjectsMock.mockReset();
        listProjectsMock.mockResolvedValue([{ ID: 'project-1', Name: '默认项目', Status: 'active' }]);
        createTaskMock.mockClear();
        deleteTaskMock.mockClear();
        validateTargetsMock.mockReset();
        getTaskDetailMock.mockReset();
		previewTaskRiskValidationMock.mockReset();
		executeTaskRiskValidationMock.mockReset();
		listPocRulesPageMock.mockReset();
        getTaskConfigRevisionsMock.mockReset();
        updateTaskConfigMock.mockReset();
        appendTargetsMock.mockReset();
        retryTaskMock.mockReset();
        pauseTaskBatchMock.mockReset();
        resumeTaskBatchMock.mockReset();
        stopTaskBatchMock.mockReset();
        retryTaskBatchMock.mockReset();
        archiveTaskBatchMock.mockReset();
        canAccessRoleMock.mockReturnValue(true);
        validateTargetsMock.mockResolvedValue({ valid: [], invalid: [], summary: {} });
        appendTargetsMock.mockResolvedValue({
            status: 'appended', new_subtasks: 1, new_batches: 1, new_targets: 1,
            duplicate_targets: 0, config_version: 1, total_chunks: 2, total_targets: 2,
        });
        retryTaskMock.mockResolvedValue({ status: 'retried', retried_batches: 1, completed_skipped: 0, paused_skipped: 0, dispatch_pending: 0 });
        pauseTaskBatchMock.mockResolvedValue({ status: 'paused' });
        resumeTaskBatchMock.mockResolvedValue({ status: 'resumed' });
        stopTaskBatchMock.mockResolvedValue({ status: 'stop_requested' });
        retryTaskBatchMock.mockResolvedValue({ status: 'retried' });
        archiveTaskBatchMock.mockResolvedValue({ status: 'archived' });
		listPocRulesPageMock.mockResolvedValue({ items: [], total: 0, page: 1, page_size: 200, has_more: false });
		executeTaskRiskValidationMock.mockResolvedValue({
			status: 'scheduled', task_id: 'task-risk-preview', batch_id: 'batch-risk', attempt_id: 'attempt-risk',
			candidate_count: 1, target_count: 1, poc_count: 1, estimated_requests: 4,
			config_version: 2, rule_version: 'rules-current-v2', dispatch_pending: 0,
		});
        listTasksMock.mockResolvedValue({
            items: [],
            total: 0,
            page: 1,
            page_size: 20,
            has_more: false,
        });
    });

    it('keeps manual agent selector controls inside advanced settings', async () => {
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
        expect(screen.queryByRole('button', { name: /添加标签条件/i })).not.toBeInTheDocument();
        await user.click(screen.getByRole('button', { name: /高级设置/i }));
        expect(screen.getByRole('button', { name: /添加标签条件/i })).toBeInTheDocument();
    });

    it('creates a safe external map task with only a target', async () => {
        const user = userEvent.setup();
        render(
            <MemoryRouter>
                <App>
                    <TaskManagement />
                </App>
            </MemoryRouter>
        );

        await user.click(await screen.findByRole('button', { name: /创建任务/i }));
        expect(screen.getByText(/自动安全测绘/)).toBeInTheDocument();
        await user.type(screen.getByPlaceholderText(/192\.168\.1\.10/), 'https://example.test');
        await user.click(within(screen.getByRole('dialog', { name: '创建扫描任务' })).getByRole('button', { name: /创\s*建/ }));

        await waitFor(() => expect(createTaskMock).toHaveBeenCalledWith(expect.objectContaining({
            project_id: 'project-1',
            name: undefined,
            targets: 'https://example.test',
            priority: 1,
            timeout_sec: 3600,
            config: expect.objectContaining({
                Subdomain: true,
                NoSubdomainBruteForce: true,
                NoSubFinder: false,
                NoDirSearch: true,
                NoPoc: true,
                GolangPoc: false,
                DisableGeneralPoc: true,
            }),
        }), expect.any(String)));
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
        await user.click(screen.getByRole('button', { name: /高级设置/i }));
        await user.click(screen.getByText('主机发现'));
        await user.click(screen.getByText('子域名探测'));
        await user.click(screen.getByText('Web 探针'));
        await user.click(screen.getByText('风险验证'));

        expect(getFormItemByLabel('主机发现')).toBeInTheDocument();
        expect(getFormItemByLabel('ICMP 探测')).toBeInTheDocument();
        expect(getFormItemByLabel('子域爆破')).toBeInTheDocument();
        expect(getFormItemByLabel('被动枚举')).toBeInTheDocument();
        expect(getFormItemByLabel('域名绑定探测')).toBeInTheDocument();
        expect(getFormItemByLabel('主动目录指纹')).toBeInTheDocument();
        expect(screen.getByText('POC 已与普通资产扫描隔离')).toBeInTheDocument();
        expect(screen.queryByLabelText('漏洞探测')).not.toBeInTheDocument();
        expect(screen.queryByLabelText('通用 POC')).not.toBeInTheDocument();
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
        await user.type(screen.getByPlaceholderText('自动生成任务名称'), '分页与开关回归任务');
        await user.type(screen.getByPlaceholderText(/192\.168\.1\.10/), '127.0.0.1');
        await user.click(screen.getByRole('button', { name: /高级设置/i }));
        await user.click(screen.getByText('主机发现'));
        await user.click(getSwitchByFormLabel('主机发现'));
        await user.click(getSwitchByFormLabel('ICMP 探测'));
        const dialog = screen.getByRole('dialog', { name: '创建扫描任务' });
        await user.click(within(dialog).getByRole('button', { name: /创\s*建/ }));

        await waitFor(() => expect(createTaskMock).toHaveBeenCalledWith(expect.objectContaining({
            config: expect.objectContaining({
                SkipHostDiscovery: true,
                NoICMPPing: true,
                NoPoc: true,
                DisableGeneralPoc: true,
            }),
        }), expect.any(String)));
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
		await user.type(screen.getByPlaceholderText('自动生成任务名称'), '目标预校验任务');
		await user.type(screen.getByPlaceholderText(/192\.168\.1\.10/), 'http://127.0.0.1:18080{enter}invalid target');
		const createDialog = screen.getByRole('dialog', { name: '创建扫描任务' });
		await user.click(within(createDialog).getByRole('button', { name: /创\s*建/ }));

		expect(await screen.findByText('目标预校验')).toBeInTheDocument();
		expect(await screen.findByDisplayValue('invalid target')).toBeInTheDocument();
		await user.click(screen.getByRole('button', { name: '跳过无效项并创建' }));

		await waitFor(() => expect(createTaskMock).toHaveBeenCalledWith(expect.objectContaining({
			skip_unsupported: true,
			targets: expect.stringContaining('invalid target'),
		}), expect.any(String)));
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
		await user.type(screen.getByPlaceholderText('自动生成任务名称'), '目标修正任务');
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
		}), expect.any(String)));
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

    it('shows state-specific task actions in an accessible overflow menu', async () => {
        const user = userEvent.setup();
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
                {
                    ID: 'task-completed',
                    Name: 'Completed Task',
                    Status: 'FINISHED',
                    TotalTargets: 1,
                    CompletedTargets: 1,
                    TotalChunks: 1,
                    CompletedChunks: 1,
                    Priority: 1,
                    CreatedAt: '2026-07-05T08:00:00Z',
                } as API.RootTask,
            ],
            total: 3,
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
        await user.click(screen.getByRole('button', { name: '管理任务 Running Task' }));
        expect(await screen.findByRole('menuitem', { name: /暂停/ })).toBeInTheDocument();
        expect(screen.getByRole('menuitem', { name: /立即停止/ })).toBeInTheDocument();
        expect(screen.queryByRole('menuitem', { name: /归档/ })).not.toBeInTheDocument();

        await user.keyboard('{Escape}');
        await user.click(screen.getByRole('button', { name: '管理任务 Paused Task' }));
        expect(await screen.findByRole('menuitem', { name: /恢复/ })).toBeInTheDocument();
        const openMenus = screen.getAllByRole('menu');
        expect(within(openMenus[openMenus.length - 1]).getByRole('menuitem', { name: /立即停止/ })).toBeInTheDocument();

        await user.keyboard('{Escape}');
        await user.click(screen.getByRole('button', { name: '管理任务 Completed Task' }));
        expect(await screen.findByRole('menuitem', { name: /归档/ })).toBeInTheDocument();
    });

    it('treats legacy pending task state as queued for task actions', async () => {
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
        await userEvent.setup().click(screen.getByRole('button', { name: '管理任务 Pending Task' }));
        expect(screen.getByRole('menuitem', { name: /暂停/ })).toBeInTheDocument();
        expect(screen.queryByRole('menuitem', { name: /归档/ })).not.toBeInTheDocument();
    });

    it('archives terminal tasks with result-preserving confirmation copy', async () => {
        const user = userEvent.setup();
        listTasksMock.mockResolvedValue({
            items: [{
                ID: 'task-archive',
                Name: 'Archive Task',
                Status: 'FINISHED',
                TotalTargets: 1,
                CompletedTargets: 1,
                TotalChunks: 1,
                CompletedChunks: 1,
                Priority: 1,
                CreatedAt: '2026-07-05T08:00:00Z',
            } as API.RootTask],
            total: 1,
            page: 1,
            page_size: 20,
            has_more: false,
        });
        deleteTaskMock.mockResolvedValue({ status: 'archived' });

        render(
            <MemoryRouter>
                <App>
                    <TaskManagement />
                </App>
            </MemoryRouter>
        );

        expect(await screen.findByText('Archive Task')).toBeInTheDocument();
        await user.click(screen.getByRole('button', { name: '管理任务 Archive Task' }));
        await user.click(await screen.findByRole('menuitem', { name: /归档/ }));
        const dialog = await screen.findByRole('dialog', { name: '确认归档任务？' });
        expect(within(dialog).getByText(/扫描结果与操作审计会继续保留/)).toBeInTheDocument();
        await user.click(within(dialog).getByRole('button', { name: /确\s*认/ }));
        await waitFor(() => expect(deleteTaskMock).toHaveBeenCalledWith('task-archive'));
    });

    it('loads archived tasks separately from the active task list', async () => {
        const user = userEvent.setup();
        listTasksMock.mockImplementation(async (params?: unknown) => {
            const archived = typeof params === 'object' && params && 'archived' in params
                ? (params as { archived?: string }).archived
                : undefined;
            return {
                items: archived === 'only' ? [{
                    ID: 'task-archived',
                    Name: 'Archived Task',
                    Status: 'FINISHED',
                    ArchivedAt: '2026-08-09T01:00:00Z',
                    TotalTargets: 1,
                    CompletedTargets: 1,
                    TotalChunks: 1,
                    CompletedChunks: 1,
                    Priority: 1,
                    CreatedAt: '2026-07-05T08:00:00Z',
                } as API.RootTask] : [],
                total: archived === 'only' ? 1 : 0,
                page: 1,
                page_size: 20,
                has_more: false,
            };
        });

        render(
            <MemoryRouter>
                <App>
                    <TaskManagement />
                </App>
            </MemoryRouter>
        );

        await user.click(await screen.findByRole('switch', { name: '查看归档任务' }));
        expect(await screen.findByText('Archived Task')).toBeInTheDocument();
        expect(screen.getAllByText('已归档').length).toBeGreaterThan(0);
        expect(listTasksMock).toHaveBeenLastCalledWith(expect.objectContaining({ archived: 'only', page: 1 }));
        expect(screen.queryByRole('button', { name: '管理任务 Archived Task' })).not.toBeInTheDocument();
    });

    it('creates a new task configuration revision from task details', async () => {
        const user = userEvent.setup();
        listTasksMock.mockResolvedValue({
            items: [{
                ID: 'task-config',
                Name: 'Config Task',
                Status: 'Running',
                TotalTargets: 1,
                CompletedTargets: 0,
                TotalChunks: 1,
                CompletedChunks: 0,
                Priority: 1,
                CurrentConfigVersion: 1,
                CreatedAt: '2026-08-09T01:00:00Z',
            } as API.RootTask],
            total: 1,
            page: 1,
            page_size: 20,
            has_more: false,
        });
        const detail = {
            task: {
                id: 'task-config', name: 'Config Task', status: 'Running', priority: 1,
                total_chunks: 1, completed_chunks: 0, total_targets: 1, completed_targets: 0,
                timeout_sec: 60, original_targets: '["https://example.test"]',
                config: { NoPoc: true, WebTimeout: 10 }, rule_version: 'rules-v1', current_config_version: 1,
                created_at: '2026-08-09T01:00:00Z', updated_at: '2026-08-09T01:00:00Z',
            },
            sub_tasks: [], status_distribution: {}, reason_stats: [], audits: [],
            result_stats: { assets: 0, fingerprints: 0, vulns: 0, severity: {} },
        } satisfies API.TaskDetailResponse;
        const revisionV1: API.TaskConfigRevision = {
            version: 1,
            config: { NoPoc: true, WebTimeout: 10 },
            config_hash: 'hash-v1',
            priority: 1,
            timeout_sec: 60,
            agent_selector: {},
            agent_selector_rules: {},
            created_by: '1',
            change_note: 'initial configuration',
            created_at: '2026-08-09T01:00:00Z',
        };
        const revisionV2: API.TaskConfigRevision = { ...revisionV1, version: 2, timeout_sec: 120, config_hash: 'hash-v2', change_note: 'increase timeout' };
        getTaskDetailMock.mockResolvedValue(detail);
        getTaskConfigRevisionsMock
            .mockResolvedValueOnce({ task_id: 'task-config', current_config_version: 1, items: [revisionV1] })
            .mockResolvedValue({ task_id: 'task-config', current_config_version: 2, items: [revisionV2, revisionV1] });
        updateTaskConfigMock.mockResolvedValue({
            status: 'configuration_saved', unchanged: false, current_config_version: 2, revision: revisionV2,
        });

        render(
            <MemoryRouter>
                <App>
                    <TaskManagement />
                </App>
            </MemoryRouter>
        );

        expect(await screen.findByText('Config Task')).toBeInTheDocument();
        await user.click(screen.getByRole('button', { name: /详情/ }));
        await user.click(await screen.findByRole('button', { name: /更新配置/ }));
        const modalHint = await screen.findByText(/新版本只用于之后新增的批次/);
        const dialog = modalHint.closest('[role="dialog"]') as HTMLElement;
        expect(dialog).toBeTruthy();
        const timeoutInput = within(dialog).getByLabelText('批次超时（秒）');
        await user.clear(timeoutInput);
        await user.type(timeoutInput, '120');
        await user.type(within(dialog).getByPlaceholderText(/说明本次调整/), 'increase timeout');
        await user.click(within(dialog).getByRole('button', { name: /保存为新版本/ }));

        await waitFor(() => expect(updateTaskConfigMock).toHaveBeenCalledWith('task-config', expect.objectContaining({
            timeout_sec: 120,
            change_note: 'increase timeout',
            config: { NoPoc: true, WebTimeout: 10 },
        })));
    });

    it('shows immutable attempt history separately from the current batch', async () => {
        const user = userEvent.setup();
        listTasksMock.mockResolvedValue({
            items: [{
                ID: 'task-history', Name: 'History Task', Status: 'FINISHED', TotalTargets: 1, CompletedTargets: 1,
                TotalChunks: 1, CompletedChunks: 1, Priority: 1, CreatedAt: '2026-08-09T01:00:00Z',
            } as API.RootTask],
            total: 1, page: 1, page_size: 20, has_more: false,
        });
        const currentAttempt: API.SubTaskSummary = {
            id: 'batch-1-attempt-2', batch_id: 'batch-1', attempt_no: 2, parent_attempt_id: 'batch-1-attempt-1',
            trigger: 'automatic_retry', status: 'Done', agent_id: 'agent-new', target_count: 1, retry_count: 1,
            max_retry: 3, priority: 1, timeout_sec: 60, config_version: 2, rule_version: 'rules-v2',
            created_at: '2026-08-09T01:01:00Z', updated_at: '2026-08-09T01:02:00Z',
        };
        getTaskDetailMock.mockResolvedValue({
            task: {
                id: 'task-history', name: 'History Task', status: 'FINISHED', priority: 1,
                total_chunks: 1, completed_chunks: 1, total_targets: 1, completed_targets: 1,
                timeout_sec: 60, original_targets: '["https://example.test"]', config: {},
                rule_version: 'rules-v2', current_config_version: 2,
                created_at: '2026-08-09T01:00:00Z', updated_at: '2026-08-09T01:02:00Z',
            },
            sub_tasks: [currentAttempt],
            attempts: [{
                ...currentAttempt, id: 'batch-1-attempt-1', attempt_no: 1, parent_attempt_id: '', trigger: 'initial',
                status: 'Failed', agent_id: 'agent-old', failure_reason: 'connection reset', config_version: 1, rule_version: 'rules-v1',
            }, currentAttempt],
            status_distribution: { Done: 1 }, reason_stats: [], audits: [],
            result_stats: { assets: 1, fingerprints: 0, vulns: 0, severity: {} },
        } satisfies API.TaskDetailResponse);
        getTaskConfigRevisionsMock.mockResolvedValue({ task_id: 'task-history', current_config_version: 2, items: [] });

        render(
            <MemoryRouter>
                <App><TaskManagement /></App>
            </MemoryRouter>
        );

        expect(await screen.findByText('History Task')).toBeInTheDocument();
        await user.click(screen.getByRole('button', { name: /详情/ }));
        expect(await screen.findByText('执行尝试历史 (2)')).toBeInTheDocument();
        expect(screen.getByText('connection reset')).toBeInTheDocument();
        expect(screen.getByText('失败重试')).toBeInTheDocument();
        expect(screen.getByText('agent-old')).toBeInTheDocument();
    });

    it('explains executed, reused, in-flight, and invalidated scan work', async () => {
        const user = userEvent.setup();
        listTasksMock.mockResolvedValue({
            items: [{
                ID: 'task-coverage', Name: 'Coverage Task', Status: 'FINISHED', TotalTargets: 3, CompletedTargets: 3,
                TotalChunks: 1, CompletedChunks: 1, Priority: 1, CreatedAt: '2026-08-09T01:00:00Z',
            } as API.RootTask],
            total: 1, page: 1, page_size: 20, has_more: false,
        });
        getTaskDetailMock.mockResolvedValue({
            task: {
                id: 'task-coverage', name: 'Coverage Task', status: 'FINISHED', priority: 1,
                total_chunks: 1, completed_chunks: 1, total_targets: 3, completed_targets: 3,
                timeout_sec: 60, original_targets: '["https://a.test","https://b.test","https://c.test"]', config: {},
                rule_version: 'rules-v1', current_config_version: 1,
                created_at: '2026-08-09T01:00:00Z', updated_at: '2026-08-09T01:02:00Z',
            },
            sub_tasks: [], attempts: [], status_distribution: {}, reason_stats: [], audits: [],
            coverage_explanation: {
                schema_version: 'argus.task-coverage-explanation/v1',
                summary: {
                    executed_work_items: 1, reused_stages: 2, in_flight_work_items: 1,
                    invalidated_stages: 1, expired_stages: 1, saved_stages: 2, saved_targets: 1,
                },
                items: [
                    {
                        link_type: 'executed', status: 'completed', normalized_target: 'https://b.test', stage: 'fingerprint', network_zone: 'public',
                        source: { task_id: 'task-coverage', task_name: 'Coverage Task', batch_id: 'batch-1', attempt_id: 'attempt-1' },
                        reason: 'claimed_for_execution', created_at: '2026-08-09T01:01:00Z',
                    },
                    {
                        link_type: 'reused', status: 'active', normalized_target: 'https://a.test', stage: 'port_scan', network_zone: 'public',
                        source: { task_id: 'task-source', task_name: 'Source Task', batch_id: 'source-batch', attempt_id: 'source-attempt' },
                        reason: 'checkpoint_resume', created_at: '2026-08-09T01:00:30Z',
                    },
                    {
                        link_type: 'in_flight', status: 'waiting', normalized_target: 'https://c.test', stage: 'fingerprint', network_zone: 'public',
                        source: { task_id: 'task-source', task_name: 'Source Task', batch_id: 'source-batch', attempt_id: 'source-attempt' },
                        reason: 'active_work_claim', created_at: '2026-08-09T01:00:20Z',
                    },
                ],
                invalidations: [{
                    normalized_target: 'https://a.test', stage: 'http_probe', status: 'invalidated',
                    reason: 'upstream_content_changed:port_scan',
                    source: { task_id: 'task-source', task_name: 'Source Task', batch_id: 'source-batch', attempt_id: 'source-attempt' },
                    invalidated_at: '2026-08-09T01:03:00Z', valid_until: null,
                }],
                items_truncated: false,
                invalidations_truncated: false,
            },
            result_stats: { assets: 3, fingerprints: 1, vulns: 0, severity: {} },
        } satisfies API.TaskDetailResponse);
        getTaskConfigRevisionsMock.mockResolvedValue({ task_id: 'task-coverage', current_config_version: 1, items: [] });

        render(<MemoryRouter><App><TaskManagement /></App></MemoryRouter>);
        expect(await screen.findByText('Coverage Task')).toBeInTheDocument();
        await user.click(screen.getByRole('button', { name: /详情/ }));

        expect(await screen.findByText('扫描复用与覆盖')).toBeInTheDocument();
        expect(screen.getByText('已节省 2 个扫描阶段、1 个完整目标')).toBeInTheDocument();
        expect(screen.getByText('实际执行')).toBeInTheDocument();
        expect(screen.getByText('历史复用')).toBeInTheDocument();
        expect(screen.getAllByText('执行中关联').length).toBeGreaterThan(0);
        expect(screen.getAllByText('Source Task').length).toBeGreaterThan(0);
        expect(screen.getByText('有效检查点恢复')).toBeInTheDocument();
        expect(screen.getByText('失效与过期原因')).toBeInTheDocument();
        expect(screen.getByText('上游内容变化（端口扫描）')).toBeInTheDocument();
    });

	it('lets viewers preview fingerprint-matched POCs without exposing execution', async () => {
		const user = userEvent.setup();
		canAccessRoleMock.mockReturnValue(false);
		listTasksMock.mockResolvedValue({
			items: [{
				ID: 'task-risk-preview', Name: 'Risk Preview Task', Status: 'FINISHED', TotalTargets: 1, CompletedTargets: 1,
				TotalChunks: 1, CompletedChunks: 1, Priority: 1, CreatedAt: '2026-08-09T01:00:00Z',
			} as API.RootTask],
			total: 1, page: 1, page_size: 20, has_more: false,
		});
		getTaskDetailMock.mockResolvedValue({
			task: {
				id: 'task-risk-preview', name: 'Risk Preview Task', status: 'FINISHED', priority: 1,
				total_chunks: 1, completed_chunks: 1, total_targets: 1, completed_targets: 1,
				timeout_sec: 60, original_targets: '["https://risk.example"]', config: { NoPoc: true },
				rule_version: 'rules-task-v1', current_config_version: 2,
				created_at: '2026-08-09T01:00:00Z', updated_at: '2026-08-09T01:01:00Z',
			},
			sub_tasks: [], attempts: [], status_distribution: {}, reason_stats: [], audits: [],
			result_stats: { assets: 1, fingerprints: 1, vulns: 0, severity: {} },
		} satisfies API.TaskDetailResponse);
		getTaskConfigRevisionsMock.mockResolvedValue({ task_id: 'task-risk-preview', current_config_version: 2, items: [] });
		previewTaskRiskValidationMock.mockResolvedValue({
			task: { id: 'task-risk-preview', name: 'Risk Preview Task', project_id: 'project-1' },
			task_rule_version: 'rules-task-v1', rule_version: 'rules-current-v2', config_version: 2,
			generated_at: '2026-08-09T02:00:00Z', plan_hash: 'a'.repeat(64),
			summary: {
				fingerprint_hits: 1, unique_assets: 1, products: 1, workflow_rules: 1, poc_rules: 1,
				candidates: 1, estimated_requests: 4, second_confirmation_required: true,
				second_confirmation_items: 1, unmatched_products: 0, excluded_mappings: 0,
			},
			items: [{
				asset: { target: 'https://risk.example:443', url: 'https://risk.example:443', protocol: 'Web', port: 443, title: 'Risk App', service: 'https' },
				endpoint: 'https://risk.example:443', products: ['nginx'], match_types: ['root'], workflow_sources: ['workflow.yaml'],
				poc_name: 'nginx-risk', poc_file: 'nginx-risk.yaml', severity: 'high', execution_class: 'verification',
				risk_level: 'high', requires_second_confirmation: true, poc_content_hash: 'poc-hash',
				template_request_estimate: 4, estimated_requests: 4, estimate_basis: 'template_upper_bound',
			}],
			unmatched_products: [], excluded: [], page: 1, page_size: 50, total: 1, has_more: false,
		} satisfies API.RiskValidationPreviewResponse);

		render(
			<MemoryRouter>
				<App><TaskManagement /></App>
			</MemoryRouter>
		);

		expect(await screen.findByText('Risk Preview Task')).toBeInTheDocument();
		await user.click(screen.getByRole('button', { name: /详情/ }));
		await user.click(await screen.findByRole('button', { name: /风险验证预览/ }));
		await waitFor(() => expect(previewTaskRiskValidationMock).toHaveBeenCalledWith('task-risk-preview', 1, 50, { specified_pocs: [] }));
		const previewNotice = await screen.findByText('此页面只生成预览，不会执行任何 POC');
		const dialog = previewNotice.closest('[role="dialog"]') as HTMLElement | null;
		if (!dialog) throw new Error('risk validation preview dialog not found');
		expect(within(dialog).getByText('此页面只生成预览，不会执行任何 POC')).toBeInTheDocument();
		expect(within(dialog).getByText('rules-current-v2')).toBeInTheDocument();
		expect(within(dialog).getByText('https://risk.example:443')).toBeInTheDocument();
		expect(within(dialog).getByText('nginx')).toBeInTheDocument();
		expect(within(dialog).getByText('nginx-risk')).toBeInTheDocument();
		expect(within(dialog).getByText('HIGH')).toBeInTheDocument();
		expect(within(dialog).queryByRole('button', { name: /执行|确认验证/ })).not.toBeInTheDocument();
	});

    it('reuses one idempotency key after a network failure, then creates a fresh intent after success', async () => {
        const user = userEvent.setup();
        createTaskMock
            .mockRejectedValueOnce(Object.assign(new Error('Network Error'), { code: 'ERR_NETWORK' }))
            .mockResolvedValue({ status: 'ok', task_id: 'task-1' });
        render(<MemoryRouter><App><TaskManagement /></App></MemoryRouter>);

        await user.click(await screen.findByRole('button', { name: /创建任务/i }));
        await user.type(screen.getByPlaceholderText(/192\.168\.1\.10/), 'https://retry.example.test');
        const create = within(screen.getByRole('dialog', { name: '创建扫描任务' })).getByRole('button', { name: /创\s*建/ });
        await user.click(create);
        await waitFor(() => expect(createTaskMock).toHaveBeenCalledTimes(1));
        const firstKey = createTaskMock.mock.calls[0][1];

        await user.click(create);
        await waitFor(() => expect(createTaskMock).toHaveBeenCalledTimes(2));
        expect(createTaskMock.mock.calls[1][1]).toBe(firstKey);

        await user.click(await screen.findByRole('button', { name: /创建任务/i }));
        await user.type(screen.getByPlaceholderText(/192\.168\.1\.10/), 'https://new-intent.example.test');
        await user.click(within(screen.getByRole('dialog', { name: '创建扫描任务' })).getByRole('button', { name: /创\s*建/ }));
        await waitFor(() => expect(createTaskMock).toHaveBeenCalledTimes(3));
        expect(createTaskMock.mock.calls[2][1]).not.toBe(firstKey);
    });

    it('clears the key after a 409 conflict before the user creates again', async () => {
        const user = userEvent.setup();
        createTaskMock
            .mockRejectedValueOnce('Idempotency-Key was already used for a different task creation request')
            .mockResolvedValue({ status: 'ok', task_id: 'task-1' });
        render(<MemoryRouter><App><TaskManagement /></App></MemoryRouter>);

        await user.click(await screen.findByRole('button', { name: /创建任务/i }));
        await user.type(screen.getByPlaceholderText(/192\.168\.1\.10/), 'https://conflict.example.test');
        const create = within(screen.getByRole('dialog', { name: '创建扫描任务' })).getByRole('button', { name: /创\s*建/ });
        await user.click(create);
        await waitFor(() => expect(createTaskMock).toHaveBeenCalledTimes(1));
        const conflictKey = createTaskMock.mock.calls[0][1];
        expect(await screen.findByText(/创建请求冲突/)).toBeInTheDocument();

        await user.click(create);
        await waitFor(() => expect(createTaskMock).toHaveBeenCalledTimes(2));
        expect(createTaskMock.mock.calls[1][1]).not.toBe(conflictKey);
    });

    it('invalidates a pending unsupported-target payload when the project changes', async () => {
        const user = userEvent.setup();
        listProjectsMock.mockResolvedValue([
            { ID: 'project-1', Name: '项目一', Status: 'active' },
            { ID: 'project-2', Name: '项目二', Status: 'active' },
        ]);
        validateTargetsMock.mockResolvedValue({
            valid: ['https://valid.example.test'],
            invalid: [{ target: 'bad target', reason: 'invalid' }],
            summary: {},
        });
        render(<MemoryRouter><App><TaskManagement /></App></MemoryRouter>);

        await user.click(await screen.findByRole('button', { name: /创建任务/i }));
        await user.type(screen.getByPlaceholderText(/192\.168\.1\.10/), 'https://valid.example.test{enter}bad target');
        await user.click(within(screen.getByRole('dialog', { name: '创建扫描任务' })).getByRole('button', { name: /创\s*建/ }));
        expect(await screen.findByText('目标预校验')).toBeInTheDocument();

		await user.click(screen.getByRole('button', { name: '返回修改' }));
		const projectSelect = screen.getByRole('combobox', { name: '所属项目' });
		fireEvent.mouseDown(projectSelect);
		await user.click(await screen.findByText('项目二'));
		expect(createTaskMock).not.toHaveBeenCalled();
    });

	it('requires explicit double confirmation before an operator creates a high-risk validation batch', async () => {
		const user = userEvent.setup();
		listTasksMock.mockResolvedValue({
			items: [{
				ID: 'task-risk-preview', Name: 'Risk Execute Task', Status: 'FINISHED', TotalTargets: 1, CompletedTargets: 1,
				TotalChunks: 1, CompletedChunks: 1, Priority: 1, CreatedAt: '2026-08-09T01:00:00Z',
			} as API.RootTask],
			total: 1, page: 1, page_size: 20, has_more: false,
		});
		const detail = {
			task: {
				id: 'task-risk-preview', name: 'Risk Execute Task', status: 'FINISHED', priority: 1,
				total_chunks: 1, completed_chunks: 1, total_targets: 1, completed_targets: 1,
				timeout_sec: 60, original_targets: '["https://risk.example"]', config: { NoPoc: true },
				rule_version: 'rules-task-v1', current_config_version: 2,
				created_at: '2026-08-09T01:00:00Z', updated_at: '2026-08-09T01:01:00Z',
			},
			sub_tasks: [], attempts: [], status_distribution: {}, reason_stats: [], audits: [],
			result_stats: { assets: 1, fingerprints: 1, vulns: 0, severity: {} },
		} satisfies API.TaskDetailResponse;
		getTaskDetailMock.mockResolvedValue(detail);
		getTaskConfigRevisionsMock.mockResolvedValue({ task_id: 'task-risk-preview', current_config_version: 2, items: [] });
		previewTaskRiskValidationMock.mockResolvedValue({
			task: { id: 'task-risk-preview', name: 'Risk Execute Task', project_id: 'project-1' },
			task_rule_version: 'rules-task-v1', rule_version: 'rules-current-v2', config_version: 2,
			generated_at: '2026-08-09T02:00:00Z', plan_hash: 'b'.repeat(64),
			summary: {
				fingerprint_hits: 1, unique_assets: 1, products: 1, workflow_rules: 1, poc_rules: 1,
				candidates: 1, estimated_requests: 4, second_confirmation_required: true,
				second_confirmation_items: 1, unmatched_products: 0, excluded_mappings: 0,
			},
			items: [{
				asset: { target: 'https://risk.example', url: 'https://risk.example', protocol: 'Web', port: 443, title: 'Risk App', service: 'https' },
				endpoint: 'https://risk.example', products: ['nginx'], match_types: ['root'], workflow_sources: ['workflow.yaml'],
				poc_name: 'nginx-risk', poc_file: 'nginx-risk.yaml', severity: 'high', execution_class: 'verification',
				risk_level: 'high', requires_second_confirmation: true, poc_content_hash: 'poc-hash',
				template_request_estimate: 4, estimated_requests: 4, estimate_basis: 'template_upper_bound',
			}],
			unmatched_products: [], excluded: [], page: 1, page_size: 50, total: 1, has_more: false,
		} satisfies API.RiskValidationPreviewResponse);

		render(<MemoryRouter><App><TaskManagement /></App></MemoryRouter>);
		expect(await screen.findByText('Risk Execute Task')).toBeInTheDocument();
		await user.click(screen.getByRole('button', { name: /详情/ }));
		await user.click(await screen.findByRole('button', { name: /风险验证预览/ }));
		const executeButton = await screen.findByRole('button', { name: '确认并创建风险验证批次' });
		expect(executeButton).toBeDisabled();
		await user.click(screen.getByRole('checkbox', { name: /我确认这些目标均在当前项目授权范围内/ }));
		expect(executeButton).toBeDisabled();
		await user.click(screen.getByRole('checkbox', { name: /我已复核高风险或风险未分类规则/ }));
		expect(executeButton).toBeEnabled();
		let resolvePending!: (response: API.ExecuteRiskValidationResponse) => void;
		executeTaskRiskValidationMock
			.mockRejectedValueOnce({ status: 409, message: 'Idempotency-Key conflict' })
			.mockImplementationOnce(() => new Promise<API.ExecuteRiskValidationResponse>((resolve) => { resolvePending = resolve; }));
		await user.click(executeButton);
		await waitFor(() => expect(executeTaskRiskValidationMock).toHaveBeenCalledTimes(1));
		const conflictKey = executeTaskRiskValidationMock.mock.calls[0][2];
		expect(await screen.findByText(/风险验证请求冲突/)).toBeInTheDocument();
		fireEvent.click(executeButton);
		fireEvent.click(executeButton);
		await waitFor(() => expect(executeTaskRiskValidationMock).toHaveBeenCalledTimes(2));
		expect(executeTaskRiskValidationMock.mock.calls[1][2]).not.toBe(conflictKey);
		await waitFor(() => expect(executeTaskRiskValidationMock).toHaveBeenCalledWith('task-risk-preview', {
			plan_hash: 'b'.repeat(64), specified_pocs: [], selected: [],
			confirmed: true, second_confirmation: true,
		}, expect.any(String)));
		resolvePending({ status: 'scheduled', replayed: true, task_id: 'task-risk-preview', batch_id: 'batch-risk', attempt_id: 'attempt-risk', candidate_count: 1, target_count: 1, poc_count: 1, estimated_requests: 4, config_version: 2, rule_version: 'rules-current-v2', dispatch_pending: 1 });
		expect(await screen.findByText(/风险验证已确认，已复用此前结果，等待队列恢复/)).toBeInTheDocument();
		await waitFor(() => expect(screen.queryByRole('dialog', { name: '风险验证预览' })).not.toBeInTheDocument());
		expect(getTaskDetailMock.mock.calls.filter(([taskId]) => taskId === 'task-risk-preview').length).toBeGreaterThanOrEqual(2);
	});

    it('adds a normalized batch from task details and refreshes the task', async () => {
        const user = userEvent.setup();
        listTasksMock.mockResolvedValue({
            items: [{
                ID: 'task-append', Name: 'Append Task', Status: 'FINISHED', TotalTargets: 1, CompletedTargets: 1,
                TotalChunks: 1, CompletedChunks: 1, Priority: 1, CreatedAt: '2026-08-09T01:00:00Z',
            } as API.RootTask],
            total: 1, page: 1, page_size: 20, has_more: false,
        });
        const detail: API.TaskDetailResponse = {
            task: {
                id: 'task-append', name: 'Append Task', status: 'FINISHED', priority: 1,
                total_chunks: 1, completed_chunks: 1, total_targets: 1, completed_targets: 1,
                timeout_sec: 60, original_targets: '["https://existing.test"]', config: { NoPoc: true },
                rule_version: 'rules-v1', current_config_version: 1,
                created_at: '2026-08-09T01:00:00Z', updated_at: '2026-08-09T01:02:00Z',
            },
            sub_tasks: [], attempts: [], status_distribution: {}, reason_stats: [], audits: [],
            result_stats: { assets: 1, fingerprints: 0, vulns: 0, severity: {} },
        };
        getTaskDetailMock.mockResolvedValue(detail);
        getTaskConfigRevisionsMock.mockResolvedValue({ task_id: 'task-append', current_config_version: 1, items: [] });

        render(
            <MemoryRouter>
                <App><TaskManagement /></App>
            </MemoryRouter>
        );

        expect(await screen.findByText('Append Task')).toBeInTheDocument();
        await user.click(screen.getByRole('button', { name: /详情/ }));
        await user.click(await screen.findByRole('button', { name: /增加批次/ }));
        const targetInput = await screen.findByLabelText('新增批次目标');
        const dialog = targetInput.closest('[role="dialog"]') as HTMLElement;
        expect(dialog).toBeTruthy();
        await user.type(targetInput, 'HTTPS://NEW.EXAMPLE.TEST/');
        await user.click(within(dialog).getByRole('button', { name: /增加批次/ }));

        await waitFor(() => expect(appendTargetsMock).toHaveBeenCalledWith('task-append', 'HTTPS://NEW.EXAMPLE.TEST/', expect.any(String)));
        await waitFor(() => expect(getTaskDetailMock).toHaveBeenCalledTimes(2));
    });

    it('reuses an append key after a network failure and clears it after a conflict or edit', async () => {
        const user = userEvent.setup();
        listTasksMock.mockResolvedValue({
            items: [{ ID: 'task-append-intent', Name: 'Append Intent Task', Status: 'FINISHED', TotalTargets: 1, CompletedTargets: 1, TotalChunks: 1, CompletedChunks: 1, Priority: 1, CreatedAt: '2026-08-09T01:00:00Z' } as API.RootTask],
            total: 1, page: 1, page_size: 20, has_more: false,
        });
        getTaskDetailMock.mockResolvedValue({
            task: { id: 'task-append-intent', name: 'Append Intent Task', status: 'FINISHED', priority: 1, total_chunks: 1, completed_chunks: 1, total_targets: 1, completed_targets: 1, timeout_sec: 60, original_targets: '[]', config: { NoPoc: true }, rule_version: 'rules-v1', current_config_version: 1, created_at: '2026-08-09T01:00:00Z', updated_at: '2026-08-09T01:00:00Z' },
            sub_tasks: [], attempts: [], status_distribution: {}, reason_stats: [], audits: [], result_stats: { assets: 0, fingerprints: 0, vulns: 0, severity: {} },
        } satisfies API.TaskDetailResponse);
        getTaskConfigRevisionsMock.mockResolvedValue({ task_id: 'task-append-intent', current_config_version: 1, items: [] });
        appendTargetsMock
            .mockRejectedValueOnce(Object.assign(new Error('Network Error'), { code: 'ERR_NETWORK' }))
            .mockRejectedValueOnce('Idempotency-Key was already used for a different append request')
            .mockResolvedValue({ status: 'unchanged', replayed: false, new_subtasks: 0, new_batches: 0, new_targets: 0, duplicate_targets: 1, config_version: 1, total_chunks: 1, total_targets: 1 });

        render(<MemoryRouter><App><TaskManagement /></App></MemoryRouter>);
        await user.click(await screen.findByRole('button', { name: /详情/ }));
        await user.click(await screen.findByRole('button', { name: /增加批次/ }));
        const input = await screen.findByLabelText('新增批次目标');
        const dialog = input.closest('[role="dialog"]') as HTMLElement;
        const submit = within(dialog).getByRole('button', { name: /增加批次/ });
        await user.type(input, 'https://retry.example.test');
        await user.click(submit);
        await waitFor(() => expect(appendTargetsMock).toHaveBeenCalledTimes(1));
        const firstKey = appendTargetsMock.mock.calls[0][2];

        await user.click(submit);
        await waitFor(() => expect(appendTargetsMock).toHaveBeenCalledTimes(2));
        expect(appendTargetsMock.mock.calls[1][2]).toBe(firstKey);
        expect(await screen.findByText(/追加请求冲突/)).toBeInTheDocument();

        await user.type(input, '\nhttps://edited.example.test');
        await user.click(submit);
        await waitFor(() => expect(appendTargetsMock).toHaveBeenCalledTimes(3));
        expect(appendTargetsMock.mock.calls[2][2]).not.toBe(firstKey);
    });

    it('manages a batch from task details with an explicit confirmation', async () => {
        const user = userEvent.setup();
        listTasksMock.mockResolvedValue({
            items: [{
                ID: 'task-batches', Name: 'Batch Control Task', Status: 'Running', TotalTargets: 2, CompletedTargets: 0,
                TotalChunks: 2, CompletedChunks: 0, Priority: 1, CreatedAt: '2026-08-09T01:00:00Z',
            } as API.RootTask],
            total: 1, page: 1, page_size: 20, has_more: false,
        });
        const batch: API.TaskBatchSummary = {
            id: 'batch-pending', sequence: 0, kind: 'asset_scan', target_type: 'url', target_count: 1,
            status: 'Failed', display_status: 'Failed', control_state: 'active', config_version: 1,
            rule_version: 'rules-v1', priority: 1, timeout_sec: 60, current_attempt_no: 1, attempt_count: 1,
            latest_attempt_id: 'batch-pending-attempt-1', retry_count: 0, max_retry: 3,
            created_at: '2026-08-09T01:00:00Z', updated_at: '2026-08-09T01:00:00Z',
        };
        const detail: API.TaskDetailResponse = {
            task: {
                id: 'task-batches', name: 'Batch Control Task', status: 'Running', priority: 1,
                total_chunks: 2, completed_chunks: 0, total_targets: 2, completed_targets: 0,
                timeout_sec: 60, original_targets: '["https://one.test","https://two.test"]', config: { NoPoc: true },
                rule_version: 'rules-v1', current_config_version: 1,
                created_at: '2026-08-09T01:00:00Z', updated_at: '2026-08-09T01:00:00Z',
            },
            sub_tasks: [], batches: [batch, { ...batch, id: 'batch-archived', sequence: 1, status: 'Done', display_status: 'Done', archived_at: '2026-08-09T02:00:00Z' }],
            attempts: [], status_distribution: { Pending: 1 }, reason_stats: [], audits: [],
            result_stats: { assets: 0, fingerprints: 0, vulns: 0, severity: {} },
        };
        getTaskDetailMock.mockResolvedValue(detail);
        getTaskConfigRevisionsMock.mockResolvedValue({ task_id: 'task-batches', current_config_version: 1, items: [] });
        retryTaskBatchMock
            .mockRejectedValueOnce(Object.assign(new Error('Network Error'), { code: 'ERR_NETWORK' }))
            .mockResolvedValueOnce({ status: 'retried', replayed: true, dispatch_pending: 1 });

        render(
            <MemoryRouter>
                <App><TaskManagement /></App>
            </MemoryRouter>
        );

        expect(await screen.findByText('Batch Control Task')).toBeInTheDocument();
        await user.click(screen.getByRole('button', { name: /详情/ }));
        await user.click(await screen.findByRole('button', { name: '管理批次 batch-pending' }));
        await user.click(await screen.findByText('重试批次'));
        const confirmationText = await screen.findByText(/将保留历史执行/);
        const dialog = confirmationText.closest('[role="dialog"]') as HTMLElement;
        expect(dialog).toBeTruthy();
        await user.click(within(dialog).getByRole('button', { name: '确 认' }));

        await waitFor(() => expect(retryTaskBatchMock).toHaveBeenCalledWith('task-batches', 'batch-pending', expect.any(String)));
        const firstKey = retryTaskBatchMock.mock.calls[0][2];
        expect(await screen.findByText(/批次重试未确认完成/)).toBeInTheDocument();
        await user.click(screen.getByLabelText('Close'));
        await user.click(screen.getByRole('button', { name: /详情/ }));
        await screen.findByRole('button', { name: '管理批次 batch-pending' });
        await user.click(await screen.findByRole('button', { name: '管理批次 batch-pending' }));
        const retryActions = await screen.findAllByText('重试批次');
        await user.click(retryActions.at(-1) as HTMLElement);
        const retryDescriptions = await screen.findAllByText(/将保留历史执行/);
        const retryDialog = retryDescriptions.at(-1)?.closest('[role="dialog"]') as HTMLElement;
        await user.click(within(retryDialog).getByRole('button', { name: /确?认/ }));
        await waitFor(() => expect(retryTaskBatchMock).toHaveBeenCalledTimes(2));
        expect(retryTaskBatchMock.mock.calls[1][2]).toBe(firstKey);
        expect(await screen.findByText(/批次重试已确认，已复用此前结果.*等待队列恢复/)).toBeInTheDocument();
        await waitFor(() => expect(getTaskDetailMock).toHaveBeenCalledTimes(3));
        expect(screen.queryByRole('button', { name: '管理批次 batch-archived' })).not.toBeInTheDocument();
    });

    it('retries only unsuccessful batches from a failed task', async () => {
        const user = userEvent.setup();
        listTasksMock.mockResolvedValue({
            items: [{
                ID: 'task-failed', Name: 'Failed Task', Status: 'Failed', TotalTargets: 2, CompletedTargets: 1,
                TotalChunks: 2, CompletedChunks: 1, Priority: 1, CreatedAt: '2026-08-09T01:00:00Z',
            } as API.RootTask],
            total: 1, page: 1, page_size: 20, has_more: false,
        });

        render(
            <MemoryRouter>
                <App><TaskManagement /></App>
            </MemoryRouter>
        );

        expect(await screen.findByText('Failed Task')).toBeInTheDocument();
        await user.click(screen.getByRole('button', { name: '管理任务 Failed Task' }));
        await user.click(await screen.findByText('重试失败批次'));
        const confirmationText = await screen.findByText(/成功批次不会重复扫描/);
        const dialog = confirmationText.closest('[role="dialog"]') as HTMLElement;
        expect(dialog).toBeTruthy();
        await user.click(within(dialog).getByRole('button', { name: '确 认' }));

        await waitFor(() => expect(retryTaskMock).toHaveBeenCalledWith('task-failed', expect.any(String)));
        await waitFor(() => expect(listTasksMock).toHaveBeenCalledTimes(2));
    });

    it('reuses a retry key after a network failure', async () => {
        const user = userEvent.setup();
        listTasksMock.mockResolvedValue({
            items: [{
                ID: 'task-retry-intent', Name: 'Retry Intent Task', Status: 'Failed', TotalTargets: 1, CompletedTargets: 0,
                TotalChunks: 1, CompletedChunks: 0, Priority: 1, CreatedAt: '2026-08-09T01:00:00Z',
            } as API.RootTask],
            total: 1, page: 1, page_size: 20, has_more: false,
        });
        retryTaskMock
            .mockRejectedValueOnce(Object.assign(new Error('Network Error'), { code: 'ERR_NETWORK' }))
            .mockResolvedValueOnce({ status: 'retried', replayed: true, retried_batches: 1, completed_skipped: 0, paused_skipped: 0, dispatch_pending: 1 });

        render(<MemoryRouter><App><TaskManagement /></App></MemoryRouter>);
        expect(await screen.findByText('Retry Intent Task')).toBeInTheDocument();
        const openRetryConfirm = async () => {
            await user.click(screen.getByRole('button', { name: '管理任务 Retry Intent Task' }));
            await user.click(await screen.findByText('重试失败批次'));
            const confirmationText = await screen.findByText(/成功批次不会重复扫描/);
            return confirmationText.closest('[role="dialog"]') as HTMLElement;
        };

        const dialog = await openRetryConfirm();
        fireEvent.click(within(dialog).getByRole('button', { name: /确 认/ }));
        await waitFor(() => expect(retryTaskMock).toHaveBeenCalledTimes(1));
        const firstKey = retryTaskMock.mock.calls[0][1];
        fireEvent.click(within(dialog).getByRole('button', { name: /确 认/ }));
        await waitFor(() => expect(retryTaskMock).toHaveBeenCalledTimes(2));
        expect(retryTaskMock.mock.calls[1][1]).toBe(firstKey);
        await waitFor(() => expect(screen.getByText(/已复用此前结果.*等待队列恢复/)).toBeInTheDocument());
    });

    it('clears retry intent after a conflict and prevents duplicate pending submits', async () => {
        const user = userEvent.setup();
        listTasksMock.mockResolvedValue({
            items: [{ ID: 'task-retry-guard', Name: 'Retry Guard Task', Status: 'Failed', TotalTargets: 1, CompletedTargets: 0, TotalChunks: 1, CompletedChunks: 0, Priority: 1, CreatedAt: '2026-08-09T01:00:00Z' } as API.RootTask],
            total: 1, page: 1, page_size: 20, has_more: false,
        });
        let resolvePending!: (value: API.TaskRetryResponse) => void;
        retryTaskMock
            .mockRejectedValueOnce('Idempotency-Key was already used for a different retry request')
            .mockImplementationOnce(() => new Promise<API.TaskRetryResponse>((resolve) => { resolvePending = resolve; }));

        render(<MemoryRouter><App><TaskManagement /></App></MemoryRouter>);
        expect(await screen.findByText('Retry Guard Task')).toBeInTheDocument();
        await user.click(screen.getByRole('button', { name: '管理任务 Retry Guard Task' }));
        await user.click(await screen.findByText('重试失败批次'));
        const dialog = (await screen.findByText(/成功批次不会重复扫描/)).closest('[role="dialog"]') as HTMLElement;
        fireEvent.click(within(dialog).getByRole('button', { name: /确 认/ }));
        await waitFor(() => expect(retryTaskMock).toHaveBeenCalledTimes(1));
        const conflictKey = retryTaskMock.mock.calls[0][1];
        expect(await screen.findByText(/重试请求冲突/)).toBeInTheDocument();

        fireEvent.click(within(dialog).getByRole('button', { name: /确 认/ }));
        await waitFor(() => expect(retryTaskMock).toHaveBeenCalledTimes(2));
        expect(retryTaskMock.mock.calls[1][1]).not.toBe(conflictKey);
        fireEvent.click(within(dialog).getByRole('button', { name: /确 认/ }));
        await new Promise((resolve) => setTimeout(resolve, 0));
        expect(retryTaskMock).toHaveBeenCalledTimes(2);
        resolvePending({ status: 'retried', replayed: false, retried_batches: 1, completed_skipped: 0, paused_skipped: 0, dispatch_pending: 0 });
    });

    it('keeps a newer task retry intent and lock when an older task request settles', async () => {
        listTasksMock.mockResolvedValue({
            items: [
                { ID: 'task-retry-a', Name: 'Retry Task A', Status: 'Failed', TotalTargets: 1, CompletedTargets: 0, TotalChunks: 1, CompletedChunks: 0, Priority: 1, CreatedAt: '2026-08-09T01:00:00Z' } as API.RootTask,
                { ID: 'task-retry-b', Name: 'Retry Task B', Status: 'Failed', TotalTargets: 1, CompletedTargets: 0, TotalChunks: 1, CompletedChunks: 0, Priority: 1, CreatedAt: '2026-08-09T01:00:00Z' } as API.RootTask,
            ],
            total: 2, page: 1, page_size: 20, has_more: false,
        });
        let rejectA!: (reason?: unknown) => void;
        let resolveB!: (value: API.TaskRetryResponse) => void;
        retryTaskMock
            .mockImplementationOnce(() => new Promise<API.TaskRetryResponse>((_, reject) => { rejectA = reject; }))
            .mockImplementationOnce(() => new Promise<API.TaskRetryResponse>((resolve) => { resolveB = resolve; }));

        render(<MemoryRouter><App><TaskManagement /></App></MemoryRouter>);
        expect(await screen.findByText('Retry Task A')).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: '管理任务 Retry Task A' }));
        fireEvent.click(await screen.findByText('重试失败批次'));
        const dialogA = (await screen.findByText(/任务“Retry Task A”中失败/)).closest('[role="dialog"]') as HTMLElement;
        fireEvent.click(within(dialogA).getByRole('button', { name: /确 认/ }));
        await waitFor(() => expect(retryTaskMock).toHaveBeenCalledTimes(1));

        fireEvent.click(screen.getByRole('button', { name: '管理任务 Retry Task B' }));
        const retryActions = await screen.findAllByText('重试失败批次');
        fireEvent.click(retryActions.at(-1) as HTMLElement);
        const dialogs = await screen.findAllByText(/成功批次不会重复扫描/);
        const dialogB = dialogs.at(-1)?.closest('[role="dialog"]') as HTMLElement;
        fireEvent.click(within(dialogB).getByRole('button', { name: /确 认/ }));
        await waitFor(() => expect(retryTaskMock).toHaveBeenCalledTimes(2));
        expect(retryTaskMock.mock.calls[0][0]).toBe('task-retry-a');
        expect(retryTaskMock.mock.calls[1][0]).toBe('task-retry-b');

        rejectA(new Error('Retry Task A failed'));
        await waitFor(() => expect(screen.getByText('Retry Task A failed')).toBeInTheDocument());
        fireEvent.click(within(dialogB).getByRole('button', { name: /确 认/ }));
        await new Promise((resolve) => setTimeout(resolve, 0));
        expect(retryTaskMock).toHaveBeenCalledTimes(2);
        resolveB({ status: 'retried', replayed: false, retried_batches: 1, completed_skipped: 0, paused_skipped: 0, dispatch_pending: 0 });
    });

    it('explains when task management actions require operator permission', async () => {
        canAccessRoleMock.mockReturnValue(false);
        listTasksMock.mockResolvedValue({
            items: [{
                ID: 'task-viewer',
                Name: 'Viewer Task',
                Status: 'Running',
                TotalTargets: 1,
                CompletedTargets: 0,
                TotalChunks: 1,
                CompletedChunks: 0,
                Priority: 1,
                CreatedAt: '2026-07-05T08:00:00Z',
            } as API.RootTask],
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

        expect(await screen.findByText('Viewer Task')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: '更多操作（需要操作员权限）' })).toBeDisabled();
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
