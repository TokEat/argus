import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ContentFindingsPanel from './ContentFindingsPanel';

const apiMocks = vi.hoisted(() => ({
    listCrawlSiteCandidates: vi.fn(),
    listSensitiveFindings: vi.fn(),
}));

vi.mock('../../services/api', () => apiMocks);

const paged = <T,>(items: T[], total: number, page: number, pageSize = 20) => ({
    items,
    total,
    page,
    page_size: pageSize,
});

describe('ContentFindingsPanel', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        localStorage.setItem('active_project_id', 'project-1');
        apiMocks.listCrawlSiteCandidates.mockResolvedValue(paged([
            {
                ID: 1,
                TenantID: 'default',
                ProjectID: 'project-1',
                TaskID: 'task-1',
                RootTaskID: 'task-1',
                SourceURL: 'https://example.com/',
                URL: 'https://example.com:8080/admin',
                Scheme: 'https',
                Host: 'example.com',
                Port: 8080,
                LinkContext: '<a href="https://example.com:8080/admin">admin</a>',
                AIControl: true,
                AIStatus: 'confirmed',
                AIConfidence: 0.9,
                AIReason: '同主机不同端口的站点，值得收录',
                AssetPromoted: true,
                CreatedAt: '2026-10-09T00:00:00Z',
                UpdatedAt: '2026-10-09T00:00:00Z',
            },
        ], 1, 1));
        apiMocks.listSensitiveFindings.mockResolvedValue(paged([
            {
                ID: 2,
                TenantID: 'default',
                ProjectID: 'project-1',
                TaskID: 'task-1',
                RootTaskID: 'task-1',
                SourceURL: 'https://example.com/contact',
                Host: 'example.com',
                Kind: 'email',
                Value: 'admin@example.com',
                Snippet: '联系邮箱 admin@example.com 获取支持',
                Context: '',
                AIControl: false,
                AIStatus: 'confirmed',
                AIConfidence: 0,
                AIReason: '',
                CreatedAt: '2026-10-09T00:00:00Z',
                UpdatedAt: '2026-10-09T00:00:00Z',
            },
        ], 1, 1));
    });

    it('fetches both candidate lists scoped to the task when active', async () => {
        render(<ContentFindingsPanel taskId="task-1" active />);

        await waitFor(() => {
            expect(apiMocks.listCrawlSiteCandidates).toHaveBeenCalledWith(expect.objectContaining({
                taskId: 'task-1',
                projectId: 'project-1',
                page: 1,
                pageSize: 20,
            }));
        });
        await waitFor(() => {
            expect(apiMocks.listSensitiveFindings).toHaveBeenCalledWith(expect.objectContaining({
                taskId: 'task-1',
                projectId: 'project-1',
                page: 1,
                pageSize: 20,
            }));
        });
        expect(await screen.findByText(/关联资产候选 \(1\)/)).toBeInTheDocument();
    });

    it('renders crawl site candidates with AI verdict and promoted tag', async () => {
        render(<ContentFindingsPanel taskId="task-1" active />);

        expect(await screen.findByText('https://example.com:8080/admin')).toBeInTheDocument();
        expect(screen.getByText('已确认')).toBeInTheDocument();
        expect(screen.getByText('已入库')).toBeInTheDocument();
    });

    it('does not fetch anything until the panel becomes active', () => {
        render(<ContentFindingsPanel taskId="task-1" active={false} />);

        expect(apiMocks.listCrawlSiteCandidates).not.toHaveBeenCalled();
        expect(apiMocks.listSensitiveFindings).not.toHaveBeenCalled();
    });

    it('lists sensitive findings with kind tag in the sensitive sub-tab', async () => {
        const user = userEvent.setup();
        render(<ContentFindingsPanel taskId="task-1" active />);

        await user.click(await screen.findByText(/敏感信息 \(1\)/));

        expect(await screen.findByText('admin@example.com')).toBeInTheDocument();
        expect(screen.getByText('邮箱')).toBeInTheDocument();
    });

    it('renders site_type tag for path_app/hidden_path crawl candidates', async () => {
        apiMocks.listCrawlSiteCandidates.mockResolvedValue(paged([
            {
                ID: 7,
                ProjectID: 'project-1',
                TaskID: 'task-1',
                RootTaskID: 'task-1',
                SourceURL: 'https://example.com/',
                URL: 'https://example.com:8080/app1',
                Scheme: 'https',
                Host: 'example.com',
                Port: 8080,
                SiteType: 'path_app',
                AIControl: true,
                AIStatus: 'confirmed',
                AssetPromoted: true,
                CreatedAt: '2026-10-09T00:00:00Z',
                UpdatedAt: '2026-10-09T00:00:00Z',
            },
            {
                ID: 8,
                ProjectID: 'project-1',
                TaskID: 'task-1',
                RootTaskID: 'task-1',
                SourceURL: 'https://example.com/',
                URL: 'https://example.com:8080/internal',
                Scheme: 'https',
                Host: 'example.com',
                Port: 8080,
                SiteType: 'hidden_path',
                AIControl: true,
                AIStatus: 'confirmed',
                AssetPromoted: false,
                CreatedAt: '2026-10-09T00:00:00Z',
                UpdatedAt: '2026-10-09T00:00:00Z',
            },
        ], 2, 1));

        render(<ContentFindingsPanel taskId="task-1" active />);

        expect(await screen.findByText('路径应用')).toBeInTheDocument();
        expect(screen.getByText('隐藏端点')).toBeInTheDocument();
    });

    it('renders new sensitive kind labels (username/apikey/token/secret)', async () => {
        const user = userEvent.setup();
        apiMocks.listSensitiveFindings.mockResolvedValue(paged([
            {
                ID: 3,
                ProjectID: 'project-1',
                TaskID: 'task-1',
                RootTaskID: 'task-1',
                SourceURL: 'https://example.com/',
                Host: 'example.com',
                Kind: 'apikey',
                Value: 'AKIAIOSFODNN7EXAMPLE',
                Snippet: 'awsAccessKey: "AKIAIOSFODNN7EXAMPLE"',
                Context: '',
                AIControl: true,
                AIStatus: 'confirmed',
                CreatedAt: '2026-10-09T00:00:00Z',
                UpdatedAt: '2026-10-09T00:00:00Z',
            },
            {
                ID: 4,
                ProjectID: 'project-1',
                TaskID: 'task-1',
                RootTaskID: 'task-1',
                SourceURL: 'https://example.com/',
                Host: 'example.com',
                Kind: 'username',
                Value: 'zhang.wei',
                Snippet: 'username: "zhang.wei"',
                Context: '{"username_convention":"firstname.lastname"}',
                AIControl: true,
                AIStatus: 'confirmed',
                CreatedAt: '2026-10-09T00:00:00Z',
                UpdatedAt: '2026-10-09T00:00:00Z',
            },
        ], 2, 1));

        render(<ContentFindingsPanel taskId="task-1" active />);

        await user.click(await screen.findByText(/敏感信息 \(2\)/));

        expect(await screen.findByText('AKIAIOSFODNN7EXAMPLE')).toBeInTheDocument();
        expect(screen.getByText('API 密钥')).toBeInTheDocument();
        expect(screen.getByText('zhang.wei')).toBeInTheDocument();
        expect(screen.getByText('用户名')).toBeInTheDocument();
    });
});
