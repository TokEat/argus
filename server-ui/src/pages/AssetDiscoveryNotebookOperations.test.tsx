import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
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
vi.mock('../features/assetDiscovery/api', () => apiMocks);

const project: API.Project = {
    ID: 'project-1', TenantID: 'default', Name: '互联网暴露面', Description: '', Status: 'active', CreatedAt: '2026-08-10T00:00:00Z',
};

const notebookResponse: API.AssetDiscoveryNotebookList = {
    schema_version: 'argus.asset-discovery-notebook/v1', project_id: project.ID, items: [{
        id: 301, target: 'https://notebook.example.invalid:443', source_count: 1,
        first_archived_at: '2026-08-10T00:00:00Z', last_archived_at: '2026-08-10T00:00:00Z', created_by: '9',
        tags: ['重点'], note: '待复核',
    }], total: 1, page: 1, page_size: 20, has_more: false, generated_at: '2026-08-10T00:06:00Z',
};

const historyResponse: API.AssetDiscoveryQueryHistory = {
    schema_version: 'argus.asset-discovery-query-history/v1', project_id: project.ID, items: [], total: 0,
    page: 1, page_size: 20, has_more: false, generated_at: '2026-08-10T00:06:00Z',
};

const setRole = (role: 'viewer' | 'operator') => {
    const payload = btoa(JSON.stringify({ role, tenant_id: 'default', user_id: '9' }));
    localStorage.setItem('token', `header.${payload}.signature`);
};

const renderPage = () => render(<App><AssetDiscovery /></App>);

describe('AssetDiscovery notebook operations', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        localStorage.clear();
        localStorage.setItem('active_project_id', project.ID);
        apiMocks.listProjects.mockResolvedValue([project]);
        apiMocks.listTasks.mockResolvedValue({ items: [], total: 0, page: 1, page_size: 100, has_more: false });
        apiMocks.listProjectAssetDiscoveryQueries.mockResolvedValue(historyResponse);
        apiMocks.listProjectAssetDiscoveryNotebookItems.mockResolvedValue(notebookResponse);
        apiMocks.listAccessibleAssetDiscoveryNotebookItems.mockResolvedValue({ ...notebookResponse, project_id: '' });
        apiMocks.updateProjectAssetDiscoveryNotebookItem.mockResolvedValue(undefined);
        apiMocks.setProjectAssetDiscoveryNotebookItemRemoved.mockResolvedValue(undefined);
    });

    it('filters and edits project notebook items for operators', async () => {
        setRole('operator');
        const user = userEvent.setup();
        renderPage();

        await screen.findByText('https://notebook.example.invalid:443');
        await user.type(screen.getByLabelText('搜索笔记本目标'), 'notebook.example');
        await user.type(screen.getByLabelText('筛选笔记本标签'), '重点');
        await user.click(screen.getByRole('button', { name: /筛选/ }));
        await waitFor(() => expect(apiMocks.listProjectAssetDiscoveryNotebookItems).toHaveBeenLastCalledWith(project.ID, {
            page: 1, pageSize: 20, q: 'notebook.example', tag: '重点',
        }));

        await user.click(screen.getByRole('button', { name: /编辑/ }));
        const tags = screen.getByLabelText('笔记本标签');
        const note = screen.getByLabelText('笔记本备注');
        await user.clear(tags);
        await user.type(tags, '重点, 待分发');
        await user.clear(note);
        await user.type(note, '已由运营复核');
        const saveButton = document.querySelector<HTMLButtonElement>('.ant-modal-footer .ant-btn-primary');
        expect(saveButton).not.toBeNull();
        fireEvent.click(saveButton as HTMLButtonElement);
        await waitFor(() => expect(apiMocks.updateProjectAssetDiscoveryNotebookItem).toHaveBeenCalledWith(project.ID, 301, {
            tags: ['重点', '待分发'], note: '已由运营复核',
        }));
    });

    it('softly removes project notebook items for operators', async () => {
        setRole('operator');
        const user = userEvent.setup();
        renderPage();

        await screen.findByText('https://notebook.example.invalid:443');
        await user.click(screen.getByRole('button', { name: /移除/ }));
        const removeDialog = await screen.findByRole('dialog', { name: '移除笔记本条目？' });
        await user.click(within(removeDialog).getByRole('button', { name: /移\s*除/ }));
        await waitFor(() => expect(apiMocks.setProjectAssetDiscoveryNotebookItemRemoved).toHaveBeenCalledWith(project.ID, 301, true));
    });

    it('shows a read-only aggregate of only accessible project notebook items', async () => {
        setRole('viewer');
        const user = userEvent.setup();
        apiMocks.listAccessibleAssetDiscoveryNotebookItems.mockResolvedValue({
            ...notebookResponse,
            project_id: '',
            items: [{ ...notebookResponse.items[0], project_id: project.ID, project_name: project.Name }],
        });
        renderPage();

        await screen.findByText('https://notebook.example.invalid:443');
        const accessibleScope = await screen.findByRole('button', { name: '可访问项目' });
        expect(accessibleScope).not.toBeDisabled();
        await user.click(accessibleScope);
        await waitFor(() => expect(screen.getByRole('button', { name: '可访问项目' })).toHaveAttribute('aria-pressed', 'true'));
        await waitFor(() => expect(apiMocks.listAccessibleAssetDiscoveryNotebookItems).toHaveBeenCalledWith({ page: 1, pageSize: 20 }));
        expect((await screen.findAllByText(project.Name)).length).toBeGreaterThanOrEqual(2);
        expect(screen.getByText('跨项目视图只聚合当前账号实际可访问的项目；编辑和分发请切回对应项目。')).toBeInTheDocument();
        expect(screen.queryByRole('button', { name: '编辑' })).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: '移除' })).not.toBeInTheDocument();
    });
});
