import { describe, expect, it, vi, beforeEach, type Mock } from 'vitest';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { App } from 'antd';
import { MemoryRouter } from 'react-router-dom';
import TaskManagement from './TaskManagement';
import { appendTargets, archiveTaskBatch, createTask, deleteTask, executeTaskRiskValidation, getTaskConfigRevisions, getTaskDetail, listPocRulesPage, listProjects, listTasks, pauseTaskBatch, previewScanPlan, previewTaskRiskValidation, resumeTaskBatch, retryTask, retryTaskBatch, stopTaskBatch, updateTaskConfig, validateTargets } from '../services/api';

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
    getCurrentUserRole: vi.fn(() => 'admin'),
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
    previewScanPlan: vi.fn(),
    listCredentialDictionaries: vi.fn().mockResolvedValue([]),
    listTaskCredentialFindings: vi.fn().mockResolvedValue([]),
    revealCredentialFinding: vi.fn(),
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
    const previewScanPlanMock = previewScanPlan as unknown as Mock;
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
        previewScanPlanMock.mockReset();
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
        previewScanPlanMock.mockImplementation(async (request: API.ScanPlanPreviewRequest) => {
            if ((request.policy.capabilities.risk_validation || request.policy.capabilities.credential_validation) && !request.policy.authorization.validation_confirmed) {
                throw 'POC or credential validation requires one explicit authorization confirmation';
            }
            return ({
            policy: request.policy,
            policy_hash: 'policy-hash', plan_hash: 'plan-hash', rule_version: 'rules-v1',
            port_count: request.policy.port_profile === 'common-100' ? 134 : request.policy.port_profile === 'all' ? 65535 : 1000,
            target_summary: { total: 1 }, stages: [
                { id: 'host_discovery', enabled: true }, { id: 'port_scan', enabled: true },
                { id: 'protocol_identification', enabled: true }, { id: 'fingerprint', enabled: true },
                { id: 'risk_validation', enabled: request.policy.capabilities.risk_validation },
                { id: 'credential_validation', enabled: request.policy.capabilities.credential_validation },
            ],
            matched_agents: 1, available_slots: 3, estimated_requests: 1000,
            custom_credential_pairs: 0, credential_pair_limit: 50000,
            validation_budget: { target_concurrency: 2, rate_limit: 10, credential_max_per_target: 50000, risk_budget_basis: 'sealed' },
            });
        });
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

    it('shows a semantic two-column scan plan without host paths or raw scanner JSON', async () => {
        const user = userEvent.setup();
        render(<MemoryRouter><App><TaskManagement /></App></MemoryRouter>);

        await user.click(await screen.findByRole('button', { name: /创建任务/i }));
        expect(screen.getByText('项目与目标')).toBeInTheDocument();
        expect(screen.getByText('实时执行计划')).toBeInTheDocument();
        expect(screen.getByRole('radio', { name: /标准 · Top1000/ })).toBeChecked();
        expect(screen.queryByText('弱口令文件')).not.toBeInTheDocument();
        expect(screen.queryByText('额外 Agent 配置 JSON')).not.toBeInTheDocument();
        expect(screen.queryByText('POC 已与普通资产扫描隔离')).not.toBeInTheDocument();
		expect(screen.getByText('GoPoc 是内部执行框架，不是第三个扫描开关')).toBeInTheDocument();
		expect(screen.getByText(/漏洞类 GoPoc 与 Nuclei 统一归入自动 POC/)).toBeInTheDocument();
    });

    it('creates the task with the exact Server plan hash after one authorization confirmation', async () => {
        const user = userEvent.setup();
        render(<MemoryRouter><App><TaskManagement /></App></MemoryRouter>);

        await user.click(await screen.findByRole('button', { name: /创建任务/i }));
        await user.type(screen.getByPlaceholderText(/192\.168\.1\.10/), 'https://example.test');
        expect(await screen.findByText(/requires one explicit authorization confirmation/)).toBeInTheDocument();
        await user.click(screen.getByRole('checkbox', { name: /我确认全部目标/ }));
        await waitFor(() => expect(screen.getByText('plan-hash'.slice(0, 16) + '…')).toBeInTheDocument());
        await user.click(screen.getByRole('button', { name: '按此计划创建' }));

        await waitFor(() => expect(createTaskMock).toHaveBeenCalledWith(expect.objectContaining({
            project_id: 'project-1', targets: 'https://example.test', plan_hash: 'plan-hash',
            policy: expect.objectContaining({
                schema_version: 'argus.scan-policy/v1', preset: 'standard', port_profile: 'top-1000',
                capabilities: expect.objectContaining({ risk_validation: true, credential_validation: false }),
                authorization: { validation_confirmed: true },
            }),
        }), expect.any(String)));
    });

    it('keeps weak credentials opt-in and always explains built-in dictionary union', async () => {
        const user = userEvent.setup();
        render(<MemoryRouter><App><TaskManagement /></App></MemoryRouter>);

        await user.click(await screen.findByRole('button', { name: /创建任务/i }));
        expect(screen.queryByText('增量凭据字典')).not.toBeInTheDocument();
        await user.click(getSwitchByFormLabel('弱口令验证'));
        expect(await screen.findByText('内置服务字典始终参与验证')).toBeInTheDocument();
        expect(screen.getByText(/只做增量补充/)).toBeInTheDocument();
        expect(screen.getByRole('button', { name: '管理字典' })).toBeInTheDocument();
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


    it('reuses one idempotency key after a network failure, then creates a fresh intent after success', async () => {
        const user = userEvent.setup();
        createTaskMock
            .mockRejectedValueOnce(Object.assign(new Error('Network Error'), { code: 'ERR_NETWORK' }))
            .mockResolvedValue({ status: 'ok', task_id: 'task-1' });
        render(<MemoryRouter><App><TaskManagement /></App></MemoryRouter>);

        await user.click(await screen.findByRole('button', { name: /创建任务/i }));
        await user.type(screen.getByPlaceholderText(/192\.168\.1\.10/), 'https://retry.example.test');
        await user.click(screen.getByRole('checkbox', { name: /我确认全部目标/ }));
        await screen.findByText('plan-hash'.slice(0, 16) + '…');
        const create = within(screen.getByRole('dialog', { name: '创建扫描任务' })).getByRole('button', { name: /创\s*建/ });
        await user.click(create);
        await waitFor(() => expect(createTaskMock).toHaveBeenCalledTimes(1));
        const firstKey = createTaskMock.mock.calls[0][1];

        await user.click(create);
        await waitFor(() => expect(createTaskMock).toHaveBeenCalledTimes(2));
        expect(createTaskMock.mock.calls[1][1]).toBe(firstKey);

        await user.click(await screen.findByRole('button', { name: /创建任务/i }));
        await user.type(screen.getByPlaceholderText(/192\.168\.1\.10/), 'https://new-intent.example.test');
        await user.click(screen.getByRole('checkbox', { name: /我确认全部目标/ }));
        await screen.findByText('plan-hash'.slice(0, 16) + '…');
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
        await user.click(screen.getByRole('checkbox', { name: /我确认全部目标/ }));
        await screen.findByText('plan-hash'.slice(0, 16) + '…');
        const create = within(screen.getByRole('dialog', { name: '创建扫描任务' })).getByRole('button', { name: /创\s*建/ });
        await user.click(create);
        await waitFor(() => expect(createTaskMock).toHaveBeenCalledTimes(1));
        const conflictKey = createTaskMock.mock.calls[0][1];
        expect(await screen.findByText(/创建请求冲突/)).toBeInTheDocument();

        await user.click(create);
        await waitFor(() => expect(createTaskMock).toHaveBeenCalledTimes(2));
        expect(createTaskMock.mock.calls[1][1]).not.toBe(conflictKey);
    });

    it('recompiles the pending Server plan when the project changes', async () => {
        const user = userEvent.setup();
        listProjectsMock.mockResolvedValue([
            { ID: 'project-1', Name: '项目一', Status: 'active' },
            { ID: 'project-2', Name: '项目二', Status: 'active' },
        ]);
        render(<MemoryRouter><App><TaskManagement /></App></MemoryRouter>);

        await user.click(await screen.findByRole('button', { name: /创建任务/i }));
        await user.type(screen.getByPlaceholderText(/192\.168\.1\.10/), 'https://valid.example.test');
        await user.click(screen.getByRole('checkbox', { name: /我确认全部目标/ }));
        await waitFor(() => expect(previewScanPlanMock).toHaveBeenCalledWith(expect.objectContaining({ project_id: 'project-1' })));
        const projectSelect = screen.getByRole('combobox', { name: '所属项目' });
        fireEvent.mouseDown(projectSelect);
        await user.click(await screen.findByText('项目二'));
        await waitFor(() => expect(previewScanPlanMock).toHaveBeenLastCalledWith(expect.objectContaining({ project_id: 'project-2' })));
        expect(createTaskMock).not.toHaveBeenCalled();
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
