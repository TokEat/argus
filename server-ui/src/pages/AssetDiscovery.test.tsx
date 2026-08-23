import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { App } from 'antd';
import AssetDiscovery from './AssetDiscovery';

const apiMocks = vi.hoisted(() => ({
    listProjects: vi.fn(),
    listTasks: vi.fn(),
    listProjectAssetDiscoveryQueries: vi.fn(),
    getProjectAssetDiscoveryQuery: vi.fn(),
    queryProjectAssetDiscovery: vi.fn(),
    exportProjectAssetDiscoveryQuery: vi.fn(),
    listProjectAssetDiscoveryNotebookItems: vi.fn(),
    listAccessibleAssetDiscoveryNotebookItems: vi.fn(),
    updateProjectAssetDiscoveryNotebookItem: vi.fn(),
    setProjectAssetDiscoveryNotebookItemRemoved: vi.fn(),
    archiveProjectAssetDiscoveryNotebookItems: vi.fn(),
    previewProjectAssetDiscoveryNotebookDistribution: vi.fn(),
    materializeProjectAssetDiscoveryNotebookDistribution: vi.fn(),
}));

vi.mock('../services/api', () => apiMocks);
vi.mock('../features/assetDiscovery/api', () => ({
    listProjectAssetDiscoveryQueries: apiMocks.listProjectAssetDiscoveryQueries,
    getProjectAssetDiscoveryQuery: apiMocks.getProjectAssetDiscoveryQuery,
    queryProjectAssetDiscovery: apiMocks.queryProjectAssetDiscovery,
    exportProjectAssetDiscoveryQuery: apiMocks.exportProjectAssetDiscoveryQuery,
    listProjectAssetDiscoveryNotebookItems: apiMocks.listProjectAssetDiscoveryNotebookItems,
    listAccessibleAssetDiscoveryNotebookItems: apiMocks.listAccessibleAssetDiscoveryNotebookItems,
    updateProjectAssetDiscoveryNotebookItem: apiMocks.updateProjectAssetDiscoveryNotebookItem,
    setProjectAssetDiscoveryNotebookItemRemoved: apiMocks.setProjectAssetDiscoveryNotebookItemRemoved,
    archiveProjectAssetDiscoveryNotebookItems: apiMocks.archiveProjectAssetDiscoveryNotebookItems,
    previewProjectAssetDiscoveryNotebookDistribution: apiMocks.previewProjectAssetDiscoveryNotebookDistribution,
    materializeProjectAssetDiscoveryNotebookDistribution: apiMocks.materializeProjectAssetDiscoveryNotebookDistribution,
}));

const project: API.Project = {
    ID: 'project-1',
    TenantID: 'default',
    Name: '互联网暴露面',
    Description: '',
    Status: 'active',
    CreatedAt: '2026-08-10T00:00:00Z',
};

const secondProject: API.Project = {
    ...project,
    ID: 'project-2',
    Name: '内网资产盘点',
};

const summary: API.AssetDiscoveryQuerySummary = {
    id: 11,
    audit_id: 21,
    provider: 'fofa',
    expression: 'domain="history.example.invalid"',
    config_version: 7,
    requested_limit: 100,
    provider_total: 9,
    returned_count: 1,
    skipped_rows: 0,
    truncated: false,
    created_by: '9',
    created_at: '2026-08-10T00:05:00Z',
};

const historyResponse: API.AssetDiscoveryQueryHistory = {
    schema_version: 'argus.asset-discovery-query-history/v1',
    project_id: project.ID,
    items: [summary],
    total: 1,
    page: 1,
    page_size: 20,
    has_more: false,
    generated_at: '2026-08-10T00:06:00Z',
};

const notebookResponse: API.AssetDiscoveryNotebookList = {
    schema_version: 'argus.asset-discovery-notebook/v1', project_id: project.ID, items: [{
        id: 301, target: 'https://notebook.example.invalid:443', source_count: 1,
        first_archived_at: '2026-08-10T00:00:00Z', last_archived_at: '2026-08-10T00:00:00Z', created_by: '9',
        tags: ['重点'], note: '待复核',
    }], total: 1,
    page: 1, page_size: 20, has_more: false, generated_at: '2026-08-10T00:06:00Z',
};

const appendableTask: API.RootTask = {
    ID: 'task-1', TenantID: 'default', UserID: '9', Name: '持续扫描', OriginalTargets: '', Status: 'RUNNING',
    TotalChunks: 1, CompletedChunks: 0, TotalTargets: 1, CompletedTargets: 0, Config: '{}', CurrentConfigVersion: 4,
    CreatedAt: '2026-08-10T00:00:00Z', UpdatedAt: '2026-08-10T00:00:00Z',
};

const completedTask: API.RootTask = {
    ...appendableTask,
    ID: 'task-completed',
    Name: '已完成可重新运行',
    Status: 'COMPLETED',
};

const taskPage = (items: API.RootTask[], page = 1, total = items.length, hasMore = false): API.PagedResponse<API.RootTask> => ({
    items,
    total,
    page,
    page_size: 100,
    has_more: hasMore,
});

const distributionPreview: API.AssetDiscoveryNotebookDistributionPreview = {
    schema_version: 'argus.asset-discovery-notebook-distribution-preview/v1', project: { id: project.ID, status: 'active' },
    task: { id: appendableTask.ID, name: appendableTask.Name, status: appendableTask.Status, config_version: 4, rule_version: 'rules-v2' },
    counts: { requested: 1, selected: 1, fresh: 1, duplicates: 0, project_scope_added: 1, project_seed_targets_added: 1 },
    items: [{ item_id: 301, target: 'https://notebook.example.invalid:443', disposition: 'new' }],
    target_summary: { mode: 'direct', total: 1, ips: 0, ip_ports: 0, cidrs: 0, ip_ranges: 0, domains: 0, domain_ports: 0, urls: 1, search_inputs: 0 },
    batch_profile: { total_targets: 1, total_batches: 1, batches_by_type: { url: 1 }, batch_size: { url: 100 } }, plan_hash: 'plan-preview-1', generated_at: '2026-08-10T00:06:00Z',
};

const distributionResult: API.AssetDiscoveryNotebookDistributionMaterializeResult = {
    schema_version: 'argus.asset-discovery-notebook-distribution/v1',
    project_id: project.ID,
    task: { id: appendableTask.ID, status: 'RUNNING' },
    intent_id: 1,
    replayed: false,
    outcome: 'materialized',
    counts: { requested: 1, fresh: 1, duplicates: 0, project_scope_added: 1, project_seed_targets_added: 1, batches_created: 1, attempts_created: 1 },
    batch_ids: ['batch-1'],
    attempt_ids: ['attempt-1'],
    dispatch: { dispatched: 1, pending: 0 },
};

const detailResponse: API.AssetDiscoveryQueryDetail = {
    schema_version: 'argus.asset-discovery-query-history/v1',
    project_id: project.ID,
    query: summary,
    assets: [{
        id: 101,
        position: 0,
        target: 'https://history.example.invalid:443',
        domain: 'history.example.invalid',
        port: 443,
        protocol: 'https',
        source: 'fofa',
        observed_at: '2026-08-10T00:05:00Z',
    }],
    total: 1,
    page: 1,
    page_size: 100,
    has_more: false,
    generated_at: '2026-08-10T00:06:00Z',
};

const previewResponse: API.AssetDiscoveryQueryPreview = {
    schema_version: 'argus.asset-discovery-query-preview/v1',
    project_id: project.ID,
    audit_id: 22,
    snapshot_id: 77,
    provider: 'fofa',
    provider_total: 1,
    returned_count: 1,
    page: 1,
    page_size: 100,
    has_more: false,
    skipped_rows: 0,
    truncated: false,
    assets: [{
        target: 'https://new.example.invalid:443',
        domain: 'new.example.invalid',
        port: 443,
        protocol: 'https',
        source: 'fofa',
    }],
};

const setRole = (role: 'viewer' | 'operator' | 'admin') => {
    const payload = btoa(JSON.stringify({ role, tenant_id: 'default', user_id: '9' }));
    localStorage.setItem('token', `header.${payload}.signature`);
};

const renderPage = () => render(<App><AssetDiscovery /></App>);

const selectNotebookItem = async () => {
    const target = await screen.findByText('https://notebook.example.invalid:443');
    const checkbox = target.closest('tr')?.querySelector('input[type="checkbox"]');
    if (!checkbox) throw new Error('notebook selection checkbox was not rendered');
    fireEvent.click(checkbox);
};

describe('AssetDiscovery', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        localStorage.clear();
        localStorage.setItem('active_project_id', project.ID);
        apiMocks.listProjects.mockResolvedValue([project]);
        apiMocks.listTasks.mockResolvedValue(taskPage([appendableTask]));
        apiMocks.listProjectAssetDiscoveryQueries.mockResolvedValue(historyResponse);
        apiMocks.getProjectAssetDiscoveryQuery.mockResolvedValue(detailResponse);
        apiMocks.queryProjectAssetDiscovery.mockResolvedValue(previewResponse);
        apiMocks.exportProjectAssetDiscoveryQuery.mockResolvedValue(new Blob(['csv'], { type: 'text/csv' }));
        apiMocks.listProjectAssetDiscoveryNotebookItems.mockResolvedValue(notebookResponse);
        apiMocks.listAccessibleAssetDiscoveryNotebookItems.mockResolvedValue({ ...notebookResponse, project_id: '' });
        apiMocks.updateProjectAssetDiscoveryNotebookItem.mockResolvedValue(undefined);
        apiMocks.setProjectAssetDiscoveryNotebookItemRemoved.mockResolvedValue(undefined);
        apiMocks.archiveProjectAssetDiscoveryNotebookItems.mockResolvedValue({
            schema_version: 'argus.asset-discovery-notebook/v1', project_id: project.ID, snapshot_id: summary.id,
            requested_count: 1, created_count: 1, linked_source_count: 1, already_archived_count: 0, total_count: 1,
        });
        apiMocks.previewProjectAssetDiscoveryNotebookDistribution.mockResolvedValue(distributionPreview);
        apiMocks.materializeProjectAssetDiscoveryNotebookDistribution.mockResolvedValue(distributionResult);
    });

    it('loads project-scoped history for viewers without exposing query controls', async () => {
        setRole('viewer');
        renderPage();

        await waitFor(() => {
            expect(apiMocks.listProjectAssetDiscoveryQueries).toHaveBeenCalledWith(project.ID, {
                page: 1,
                pageSize: 20,
                provider: undefined,
            });
        });
        expect(await screen.findByText('domain="history.example.invalid"')).toBeInTheDocument();
        expect(screen.getByText('当前账号为只读角色')).toBeInTheDocument();
        expect(screen.queryByRole('button', { name: /开始测绘/ })).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: '归档到笔记本' })).not.toBeInTheDocument();
    });

    it('lets operators archive persisted assets and refreshes the notebook', async () => {
        setRole('operator');
        const user = userEvent.setup();
        renderPage();
        await user.click(await screen.findByRole('button', { name: /查看/ }, { timeout: 5000 }));
        const checkbox = (await screen.findAllByRole('checkbox')).at(-1) as HTMLElement;
        await user.click(checkbox);
        await user.click(screen.getByRole('button', { name: '归档到笔记本' }));
        await waitFor(() => expect(apiMocks.archiveProjectAssetDiscoveryNotebookItems).toHaveBeenCalledWith(project.ID, summary.id, [101]));
        await waitFor(() => expect(apiMocks.listProjectAssetDiscoveryNotebookItems.mock.calls.length).toBeGreaterThanOrEqual(2));
        expect((screen.getAllByRole('checkbox').at(-1) as HTMLElement)).not.toBeChecked();
    });

    it('lets operators preview selected notebook distribution without executing it', async () => {
        setRole('operator');
        const user = userEvent.setup();
        renderPage();

        await selectNotebookItem();
        fireEvent.mouseDown(screen.getByRole('combobox', { name: '追加到现有任务' }));
        await user.click(await screen.findByText(/持续扫描/));
        await user.click(screen.getByRole('button', { name: '预览分发' }));

        await waitFor(() => expect(apiMocks.previewProjectAssetDiscoveryNotebookDistribution).toHaveBeenCalledWith(project.ID, appendableTask.ID, [301]));
        expect(await screen.findByText('尚未执行')).toBeInTheDocument();
        expect(screen.getByText('任务配置版本')).toBeInTheDocument();
        expect(screen.getByText('预计 Scope 增量')).toBeInTheDocument();
    });

    it('keeps completed tasks available for distribution preview', async () => {
        setRole('operator');
        const user = userEvent.setup();
        apiMocks.listTasks.mockResolvedValue(taskPage([appendableTask, completedTask]));
        renderPage();

        await waitFor(() => expect(apiMocks.listTasks).toHaveBeenCalledWith({ projectId: project.ID, page: 1, pageSize: 100, archived: 'active' }));
        fireEvent.mouseDown(screen.getByRole('combobox', { name: '追加到现有任务' }));
        expect(await screen.findByText(/已完成可重新运行 · COMPLETED/)).toBeInTheDocument();
        await user.click(screen.getByText(/已完成可重新运行 · COMPLETED/));
    });

    it('confirms a preview with its plan hash and an Idempotency-Key, then clears and refreshes', async () => {
        setRole('operator');
        const user = userEvent.setup();
        renderPage();

        await selectNotebookItem();
        fireEvent.mouseDown(screen.getByRole('combobox', { name: '追加到现有任务' }));
        await user.click(await screen.findByText(/持续扫描/));
        await user.click(screen.getByRole('button', { name: '预览分发' }));
        await screen.findByText('尚未执行');
        await user.click(screen.getByRole('button', { name: '确认追加并创建批次' }));

        await waitFor(() => expect(apiMocks.materializeProjectAssetDiscoveryNotebookDistribution).toHaveBeenCalledWith(
            project.ID,
            { task_id: appendableTask.ID, item_ids: [301], plan_hash: distributionPreview.plan_hash },
            expect.any(String),
        ));
        expect(await screen.findByText(/已追加 1 个目标并创建 1 个批次/)).toBeInTheDocument();
        expect(screen.queryByText('尚未执行')).not.toBeInTheDocument();
        await waitFor(() => expect(apiMocks.listProjectAssetDiscoveryNotebookItems.mock.calls.length).toBeGreaterThanOrEqual(2));
        await waitFor(() => expect(apiMocks.listTasks.mock.calls.length).toBeGreaterThanOrEqual(2));
    });

    it('prevents double confirms and reuses the same key after a recoverable network failure', async () => {
        setRole('operator');
        const user = userEvent.setup();
        let rejectFirst: (reason?: unknown) => void = () => undefined;
        apiMocks.materializeProjectAssetDiscoveryNotebookDistribution
            .mockImplementationOnce(() => new Promise((_resolve, reject) => { rejectFirst = reject; }))
            .mockResolvedValueOnce(distributionResult);
        renderPage();

        await selectNotebookItem();
        fireEvent.mouseDown(screen.getByRole('combobox', { name: '追加到现有任务' }));
        await user.click(await screen.findByText(/持续扫描/));
        await user.click(screen.getByRole('button', { name: '预览分发' }));
        await screen.findByText('尚未执行');
        const confirm = screen.getByRole('button', { name: '确认追加并创建批次' });
        fireEvent.click(confirm);
        fireEvent.click(confirm);
        await waitFor(() => expect(apiMocks.materializeProjectAssetDiscoveryNotebookDistribution).toHaveBeenCalledTimes(1));
        expect(screen.getByRole('combobox', { name: '追加到现有任务' })).toBeDisabled();
        expect((await screen.findAllByRole('checkbox')).at(-1)).toBeDisabled();
        const firstKey = apiMocks.materializeProjectAssetDiscoveryNotebookDistribution.mock.calls[0][2];
        await act(async () => { rejectFirst('network unavailable'); await Promise.resolve(); });
        expect(await screen.findByText('network unavailable')).toBeInTheDocument();

        await waitFor(() => expect(screen.getByRole('button', { name: /确认追加并创建批次/ })).not.toBeDisabled());
        await user.click(screen.getByRole('button', { name: /确认追加并创建批次/ }));
        await waitFor(() => expect(apiMocks.materializeProjectAssetDiscoveryNotebookDistribution).toHaveBeenCalledTimes(2));
        expect(apiMocks.materializeProjectAssetDiscoveryNotebookDistribution.mock.calls[1][2]).toBe(firstKey);
    });

    it('clears and refreshes an all-duplicate confirmation without claiming a new batch', async () => {
        setRole('operator');
        const user = userEvent.setup();
        apiMocks.materializeProjectAssetDiscoveryNotebookDistribution.mockResolvedValue({
            ...distributionResult,
            outcome: 'unchanged',
            counts: { ...distributionResult.counts, fresh: 0, duplicates: 1, project_scope_added: 0, project_seed_targets_added: 0, batches_created: 0, attempts_created: 0 },
            batch_ids: [],
            attempt_ids: [],
            dispatch: { dispatched: 0, pending: 0 },
        });
        renderPage();

        await selectNotebookItem();
        fireEvent.mouseDown(screen.getByRole('combobox', { name: '追加到现有任务' }));
        await user.click(await screen.findByText(/持续扫描/));
        await user.click(screen.getByRole('button', { name: '预览分发' }));
        await screen.findByText('尚未执行');
        await user.click(screen.getByRole('button', { name: '确认追加并创建批次' }));

        expect(await screen.findByText('选中目标均已在任务中，未创建新批次')).toBeInTheDocument();
        expect(screen.queryByText('尚未执行')).not.toBeInTheDocument();
        await waitFor(() => expect(apiMocks.listProjectAssetDiscoveryNotebookItems.mock.calls.length).toBeGreaterThanOrEqual(2));
        await waitFor(() => expect(apiMocks.listTasks.mock.calls.length).toBeGreaterThanOrEqual(2));
    });

    it('invalidates an expired preview instead of retrying the materialize request', async () => {
        setRole('operator');
        const user = userEvent.setup();
        apiMocks.materializeProjectAssetDiscoveryNotebookDistribution.mockRejectedValue('409 notebook distribution preview expired');
        renderPage();

        await selectNotebookItem();
        fireEvent.mouseDown(screen.getByRole('combobox', { name: '追加到现有任务' }));
        await user.click(await screen.findByText(/持续扫描/));
        await user.click(screen.getByRole('button', { name: '预览分发' }));
        await screen.findByText('尚未执行');
        await user.click(screen.getByRole('button', { name: '确认追加并创建批次' }));

        expect(await screen.findByText('预览已过期或任务状态已变化，请重新预览后确认')).toBeInTheDocument();
        expect(screen.queryByText('尚未执行')).not.toBeInTheDocument();
        expect(apiMocks.materializeProjectAssetDiscoveryNotebookDistribution).toHaveBeenCalledTimes(1);
    });

    it('invalidates an idempotency conflict so a later preview receives a new key', async () => {
        setRole('operator');
        const user = userEvent.setup();
        apiMocks.materializeProjectAssetDiscoveryNotebookDistribution
            .mockRejectedValueOnce('notebook distribution idempotency conflict')
            .mockResolvedValueOnce(distributionResult);
        renderPage();

        await selectNotebookItem();
        fireEvent.mouseDown(screen.getByRole('combobox', { name: '追加到现有任务' }));
        await user.click(await screen.findByText(/持续扫描/));
        await user.click(screen.getByRole('button', { name: '预览分发' }));
        await screen.findByText('尚未执行');
        await user.click(screen.getByRole('button', { name: '确认追加并创建批次' }));
        const conflictKey = apiMocks.materializeProjectAssetDiscoveryNotebookDistribution.mock.calls[0][2];
        expect(await screen.findByText('确认请求冲突，请重新预览后确认')).toBeInTheDocument();

        await waitFor(() => expect(screen.getByRole('button', { name: /预览分发/ })).not.toBeDisabled());
        await user.click(screen.getByRole('button', { name: /预览分发/ }));
        await screen.findByText('尚未执行');
        await user.click(screen.getByRole('button', { name: '确认追加并创建批次' }));
        await waitFor(() => expect(apiMocks.materializeProjectAssetDiscoveryNotebookDistribution).toHaveBeenCalledTimes(2));
        expect(apiMocks.materializeProjectAssetDiscoveryNotebookDistribution.mock.calls[1][2]).not.toBe(conflictKey);
    });

    it('loads later task pages so older appendable tasks remain selectable', async () => {
        setRole('operator');
        const user = userEvent.setup();
        const unavailableFirstPage = Array.from({ length: 100 }, (_, index) => ({
            ...appendableTask,
            ID: `created-task-${index + 1}`,
            Name: `不可追加任务 ${index + 1}`,
            Status: 'CREATED',
        }));
        const olderTask = { ...appendableTask, ID: 'task-101', Name: '较早的可追加任务' };
        apiMocks.listTasks.mockImplementation(({ page }: { page: number }) => Promise.resolve(
            page === 1 ? taskPage(unavailableFirstPage, 1, 101, true) : taskPage([olderTask], 2, 101, false),
        ));
        renderPage();

        await waitFor(() => expect(apiMocks.listTasks).toHaveBeenCalledWith({ projectId: project.ID, page: 2, pageSize: 100, archived: 'active' }));
        fireEvent.mouseDown(screen.getByRole('combobox', { name: '追加到现有任务' }));
        expect(await screen.findByText(/较早的可追加任务 · RUNNING/)).toBeInTheDocument();
        await user.click(screen.getByText(/较早的可追加任务 · RUNNING/));
    });

    it('discards a stale notebook response after switching projects', async () => {
        setRole('operator');
        const user = userEvent.setup();
        let resolveNotebook: (value: API.AssetDiscoveryNotebookList) => void = () => undefined;
        apiMocks.listProjects.mockResolvedValue([project, secondProject]);
        apiMocks.listProjectAssetDiscoveryNotebookItems.mockImplementation((requestedProjectId: string) => {
            if (requestedProjectId === project.ID) return new Promise((resolve) => { resolveNotebook = resolve; });
            return Promise.resolve({ ...notebookResponse, project_id: secondProject.ID, items: [{
                id: 202, target: 'https://second.example.invalid', source_count: 1,
                first_archived_at: '2026-08-10T00:00:00Z', last_archived_at: '2026-08-10T00:00:00Z', created_by: '9',
            }] });
        });
        renderPage();

        await waitFor(() => expect(apiMocks.listProjectAssetDiscoveryNotebookItems).toHaveBeenCalledWith(project.ID, { page: 1, pageSize: 20 }));
        fireEvent.mouseDown(screen.getByRole('combobox', { name: '当前项目' }));
        await user.click(await screen.findByText(secondProject.Name));
        await screen.findByText('https://second.example.invalid');
        await act(async () => resolveNotebook({ ...notebookResponse, items: [{
            id: 101, target: 'https://stale.example.invalid', source_count: 1,
            first_archived_at: '2026-08-10T00:00:00Z', last_archived_at: '2026-08-10T00:00:00Z', created_by: '9',
        }] }));
        expect(screen.queryByText('https://stale.example.invalid')).not.toBeInTheDocument();
    });

    it('clears and discards a pending notebook distribution preview after switching projects', async () => {
        setRole('operator');
        const user = userEvent.setup();
        let resolvePreview: (value: API.AssetDiscoveryNotebookDistributionPreview) => void = () => undefined;
        apiMocks.listProjects.mockResolvedValue([project, secondProject]);
        apiMocks.previewProjectAssetDiscoveryNotebookDistribution.mockImplementation(() => new Promise((resolve) => { resolvePreview = resolve; }));
        renderPage();

        await selectNotebookItem();
        fireEvent.mouseDown(screen.getByRole('combobox', { name: '追加到现有任务' }));
        await user.click(await screen.findByText(/持续扫描/));
        await user.click(screen.getByRole('button', { name: '预览分发' }));
        await waitFor(() => expect(apiMocks.previewProjectAssetDiscoveryNotebookDistribution).toHaveBeenCalled());

        fireEvent.mouseDown(screen.getByRole('combobox', { name: '当前项目' }));
        await user.click(await screen.findByText(secondProject.Name));
        await act(async () => resolvePreview(distributionPreview));

        expect(screen.queryByText('尚未执行')).not.toBeInTheDocument();
        expect(screen.queryByText('plan-preview-1')).not.toBeInTheDocument();
    });

    it('discards an old materialize response without releasing the new project confirmation lock', async () => {
        setRole('operator');
        const user = userEvent.setup();
        const materializeResolvers: Array<(value: API.AssetDiscoveryNotebookDistributionMaterializeResult) => void> = [];
        apiMocks.listProjects.mockResolvedValue([project, secondProject]);
        apiMocks.materializeProjectAssetDiscoveryNotebookDistribution.mockImplementation(() => new Promise((resolve) => { materializeResolvers.push(resolve); }));
        renderPage();

        await selectNotebookItem();
        fireEvent.mouseDown(screen.getByRole('combobox', { name: '追加到现有任务' }));
        await user.click(await screen.findByText(/持续扫描/));
        await user.click(screen.getByRole('button', { name: '预览分发' }));
        await screen.findByText('尚未执行');
        await user.click(screen.getByRole('button', { name: '确认追加并创建批次' }));
        await waitFor(() => expect(apiMocks.materializeProjectAssetDiscoveryNotebookDistribution).toHaveBeenCalledTimes(1));

        fireEvent.mouseDown(screen.getByRole('combobox', { name: '当前项目' }));
        await user.click(await screen.findByText(secondProject.Name));
        await waitFor(() => expect(apiMocks.listProjectAssetDiscoveryNotebookItems).toHaveBeenCalledWith(secondProject.ID, { page: 1, pageSize: 20 }));

        await selectNotebookItem();
        fireEvent.mouseDown(screen.getByRole('combobox', { name: '追加到现有任务' }));
        await user.click(await screen.findByText(/持续扫描/));
        await user.click(screen.getByRole('button', { name: '预览分发' }));
        await screen.findByText('尚未执行');
        await user.click(screen.getByRole('button', { name: '确认追加并创建批次' }));
        await waitFor(() => expect(apiMocks.materializeProjectAssetDiscoveryNotebookDistribution).toHaveBeenCalledTimes(2));

        await act(async () => materializeResolvers[0](distributionResult));
        const activeConfirm = screen.getByRole('button', { name: /确认追加并创建批次/ });
        expect(activeConfirm).toBeDisabled();
        fireEvent.click(activeConfirm);
        expect(apiMocks.materializeProjectAssetDiscoveryNotebookDistribution).toHaveBeenCalledTimes(2);

        await act(async () => materializeResolvers[1]({ ...distributionResult, project_id: secondProject.ID }));

        expect(await screen.findByText(/已追加 1 个目标并创建 1 个批次/)).toBeInTheDocument();
        expect(screen.queryByText('尚未执行')).not.toBeInTheDocument();
    });

    it('lets operators run a minimal provider query and shows the immediate result', async () => {
        setRole('operator');
        const user = userEvent.setup();
        renderPage();

        const expressionInput = await screen.findByLabelText('查询表达式');
        await user.type(expressionInput, 'domain="new.example.invalid"');
        await user.click(screen.getByRole('button', { name: /开始测绘/ }));

        await waitFor(() => {
            expect(apiMocks.queryProjectAssetDiscovery).toHaveBeenCalledWith(
                project.ID,
                'fofa',
                'domain="new.example.invalid"',
                { page: 1 },
            );
        });
        expect(await screen.findByText('https://new.example.invalid:443')).toBeInTheDocument();
        expect(screen.queryByRole('button', { name: '归档到笔记本' })).not.toBeInTheDocument();
        await waitFor(() => expect(apiMocks.listProjectAssetDiscoveryQueries.mock.calls.length).toBeGreaterThanOrEqual(2));
    });

    it('pages through the fresh query result instead of capping at 100 assets', async () => {
        setRole('operator');
        const user = userEvent.setup();
        const pageTwo: API.AssetDiscoveryQueryPreview = {
            ...previewResponse,
            provider_total: 150,
            returned_count: 2,
            page: 2,
            has_more: false,
            assets: [{
                target: 'https://second.example.invalid:443',
                domain: 'second.example.invalid',
                port: 443,
                protocol: 'https',
                source: 'fofa',
            }],
        };
        apiMocks.queryProjectAssetDiscovery
            .mockResolvedValueOnce({ ...previewResponse, provider_total: 150, has_more: true })
            .mockResolvedValueOnce(pageTwo);
        renderPage();

        const expressionInput = await screen.findByLabelText('查询表达式');
        await user.type(expressionInput, 'domain="new.example.invalid"');
        await user.click(screen.getByRole('button', { name: /开始测绘/ }));
        expect(await screen.findByText('https://new.example.invalid:443')).toBeInTheDocument();

        await user.click(screen.getByRole('listitem', { name: '2' }));
        await waitFor(() => {
            expect(apiMocks.queryProjectAssetDiscovery).toHaveBeenCalledWith(
                project.ID,
                'fofa',
                '',
                { page: 2, limit: 100, snapshotId: 77 },
            );
        });
        expect(await screen.findByText('https://second.example.invalid:443')).toBeInTheDocument();
    });

    it('discards a pending query when the user switches projects', async () => {
        setRole('operator');
        const user = userEvent.setup();
        let resolveQuery: (value: API.AssetDiscoveryQueryPreview) => void = () => undefined;
        apiMocks.listProjects.mockResolvedValue([project, secondProject]);
        apiMocks.listProjectAssetDiscoveryQueries.mockImplementation(async (requestedProjectId: string) => ({
            ...historyResponse,
            project_id: requestedProjectId,
            items: requestedProjectId === project.ID ? [summary] : [],
            total: requestedProjectId === project.ID ? 1 : 0,
        }));
        apiMocks.queryProjectAssetDiscovery.mockImplementation(() => new Promise((resolve) => {
            resolveQuery = resolve;
        }));
        renderPage();

        const expressionInput = await screen.findByLabelText('查询表达式');
        await user.type(expressionInput, 'domain="new.example.invalid"');
        await user.click(screen.getByRole('button', { name: /开始测绘/ }));
        await waitFor(() => expect(apiMocks.queryProjectAssetDiscovery).toHaveBeenCalled());

        fireEvent.mouseDown(screen.getByRole('combobox', { name: '当前项目' }));
        await user.click(await screen.findByText(secondProject.Name));
        await waitFor(() => {
            expect(apiMocks.listProjectAssetDiscoveryQueries).toHaveBeenCalledWith(secondProject.ID, {
                page: 1,
                pageSize: 20,
                provider: undefined,
            });
        });
        const originalProjectHistoryCalls = apiMocks.listProjectAssetDiscoveryQueries.mock.calls
            .filter(([requestedProjectId]) => requestedProjectId === project.ID).length;

        await act(async () => resolveQuery(previewResponse));

        expect(screen.queryByText('https://new.example.invalid:443')).not.toBeInTheDocument();
        expect(apiMocks.listProjectAssetDiscoveryQueries.mock.calls
            .filter(([requestedProjectId]) => requestedProjectId === project.ID)).toHaveLength(originalProjectHistoryCalls);
    });

    it('shows provider-specific official syntax guidance and safe examples', async () => {
        setRole('operator');
        const user = userEvent.setup();
        renderPage();

        const syntaxGuide = await screen.findByLabelText('FOFA 语法速查');
        expect(syntaxGuide).toHaveTextContent('field="value"');
        expect(screen.getByRole('link', { name: /官方帮助/ })).toHaveAttribute('href', 'https://fofa.info/api');

        await user.click(screen.getByRole('button', { name: 'domain="example.invalid"' }));
        expect(screen.getByLabelText('查询表达式')).toHaveValue('domain="example.invalid"');
    });

    it('completes a field prefix with the keyboard without submitting a query', async () => {
        setRole('operator');
        const user = userEvent.setup();
        renderPage();

        const expressionInput = await screen.findByLabelText('查询表达式');
        await user.type(expressionInput, 'dom');
        expect(await screen.findByRole('option', { name: /domain/ })).toBeInTheDocument();
        await user.keyboard('{ArrowDown}{Enter}');

        expect(expressionInput).toHaveValue('domain=');
        expect(apiMocks.queryProjectAssetDiscovery).not.toHaveBeenCalled();
    });

    it('switches the syntax catalog with the selected provider', async () => {
        setRole('operator');
        const user = userEvent.setup();
        renderPage();

        await screen.findByLabelText('FOFA 语法速查');
        const providerSelect = screen.getAllByLabelText('测绘来源')[0];
        fireEvent.mouseDown(providerSelect.querySelector('[role="combobox"]') as HTMLElement);
        await user.click(await screen.findByText('Quake'));

        const syntaxGuide = await screen.findByLabelText('Quake 语法速查');
        expect(syntaxGuide).toHaveTextContent('field:"value"');
        expect(screen.getByRole('link', { name: /官方帮助/ })).toHaveAttribute('href', 'https://quake.360.net/quake/#/help');
        expect(screen.getByRole('button', { name: 'service.http.title' })).toBeInTheDocument();
    });

    it('loads one bounded history detail page on demand', async () => {
        setRole('viewer');
        const user = userEvent.setup();
        renderPage();

        await screen.findByText('domain="history.example.invalid"');
        await user.click(screen.getByRole('button', { name: /查看/ }));

        await waitFor(() => {
            expect(apiMocks.getProjectAssetDiscoveryQuery).toHaveBeenCalledWith(project.ID, summary.id, {
                page: 1,
                pageSize: 100,
            });
        });
        expect(await screen.findByText('https://history.example.invalid:443')).toBeInTheDocument();
    });

    it('downloads one persisted history snapshot with a fixed local filename', async () => {
        setRole('viewer');
        const user = userEvent.setup();
        const createObjectURL = vi.fn(() => 'blob:asset-discovery');
        const revokeObjectURL = vi.fn();
        Object.defineProperty(window.URL, 'createObjectURL', { configurable: true, value: createObjectURL });
        Object.defineProperty(window.URL, 'revokeObjectURL', { configurable: true, value: revokeObjectURL });
        const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
            expect(this.download).toBe(`argus-asset-discovery-${summary.id}.csv`);
            expect(this.href).toBe('blob:asset-discovery');
        });
        renderPage();

        await screen.findByText('domain="history.example.invalid"');
        await user.click(screen.getByRole('button', { name: /导出/ }));

        await waitFor(() => {
            expect(apiMocks.exportProjectAssetDiscoveryQuery).toHaveBeenCalledWith(project.ID, summary.id);
        });
        expect(createObjectURL).toHaveBeenCalledTimes(1);
        expect(click).toHaveBeenCalledTimes(1);
        expect(revokeObjectURL).toHaveBeenCalledWith('blob:asset-discovery');
        click.mockRestore();
    });

    it('discards a pending export when the user switches projects', async () => {
        setRole('viewer');
        const user = userEvent.setup();
        let resolveExport: (value: Blob) => void = () => undefined;
        const createObjectURL = vi.fn(() => 'blob:stale-export');
        Object.defineProperty(window.URL, 'createObjectURL', { configurable: true, value: createObjectURL });
        apiMocks.listProjects.mockResolvedValue([project, secondProject]);
        apiMocks.listProjectAssetDiscoveryQueries.mockImplementation(async (requestedProjectId: string) => ({
            ...historyResponse,
            project_id: requestedProjectId,
            items: requestedProjectId === project.ID ? [summary] : [],
            total: requestedProjectId === project.ID ? 1 : 0,
        }));
        apiMocks.exportProjectAssetDiscoveryQuery.mockImplementation(() => new Promise((resolve) => {
            resolveExport = resolve;
        }));
        renderPage();

        await screen.findByText('domain="history.example.invalid"');
        await user.click(screen.getByRole('button', { name: /导出/ }));
        await waitFor(() => expect(apiMocks.exportProjectAssetDiscoveryQuery).toHaveBeenCalledWith(project.ID, summary.id));
        fireEvent.mouseDown(screen.getByRole('combobox', { name: '当前项目' }));
        await user.click(await screen.findByText(secondProject.Name));

        await act(async () => resolveExport(new Blob(['stale'], { type: 'text/csv' })));

        expect(createObjectURL).not.toHaveBeenCalled();
    });

    it('keeps archived project history readable while disabling new queries', async () => {
        setRole('operator');
        apiMocks.listProjects.mockResolvedValue([{ ...project, Status: 'archived' }]);
        renderPage();

        expect(await screen.findByText('项目已归档')).toBeInTheDocument();
        expect(screen.queryByRole('button', { name: /开始测绘/ })).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: '归档到笔记本' })).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: '预览分发' })).not.toBeInTheDocument();
        await waitFor(() => expect(apiMocks.listProjectAssetDiscoveryQueries).toHaveBeenCalled());
    });

    it('hides notebook distribution selection and controls from viewers', async () => {
        setRole('viewer');
        renderPage();
        await screen.findByText('https://notebook.example.invalid:443');
        expect(screen.queryByRole('button', { name: '预览分发' })).not.toBeInTheDocument();
        expect(screen.queryByLabelText('追加到现有任务')).not.toBeInTheDocument();
        expect(screen.queryByRole('checkbox', { name: /Select row/ })).not.toBeInTheDocument();
    });
});
