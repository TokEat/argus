import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { App } from 'antd';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import TaskResults from './TaskResults';

const apiMocks = vi.hoisted(() => ({
    getVulns: vi.fn(),
    getAssets: vi.fn(),
    getFingerprints: vi.fn(),
    getFingerprintGroups: vi.fn(),
    exportVulns: vi.fn(),
    exportAssets: vi.fn(),
    exportFingerprints: vi.fn(),
}));

vi.mock('../contexts/GlobalAIContext', () => ({
    useAutoContext: vi.fn(),
}));

vi.mock('../services/api', () => apiMocks);

const paged = <T,>(items: T[], total: number, page: number, pageSize = 20, stats?: API.AssetKindStats) => ({
    items,
    total,
    page,
    page_size: pageSize,
    has_more: page * pageSize < total,
    generated_at: '2026-07-05T00:00:00Z',
    ...(stats ? { stats } : {}),
});

const assetStats = (partial: Partial<API.AssetKindStats>): API.AssetKindStats => ({
    total: 0,
    web: 0,
    host_port: 0,
    domain: 0,
    resolution: 0,
    other: 0,
    ...partial,
});

describe('TaskResults', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        localStorage.setItem('active_project_id', 'project-1');
        apiMocks.getVulns.mockImplementation(({ page }: { page: number }) => paged([
            {
                ID: page,
                TenantID: 'default',
                TaskID: 'task-1',
                Target: `https://target-${page}.example`,
                Plugin: `poc-${page}`,
                Severity: 'high',
                CreatedAt: '2026-07-05T00:00:00Z',
            },
        ], 25, page));
        apiMocks.getAssets.mockResolvedValue(paged([], 0, 1));
        apiMocks.getFingerprints.mockResolvedValue(paged([], 0, 1));
        apiMocks.getFingerprintGroups.mockResolvedValue(paged([], 0, 1));
        apiMocks.exportVulns.mockResolvedValue(new Blob(['vulns']));
        apiMocks.exportAssets.mockResolvedValue(new Blob(['assets']));
        apiMocks.exportFingerprints.mockResolvedValue(new Blob(['fingerprints']));
        vi.spyOn(window.URL, 'createObjectURL').mockReturnValue('blob:argus-test');
        vi.spyOn(window.URL, 'revokeObjectURL').mockImplementation(() => undefined);
    });

    it('requests the next vulnerability page from the server', async () => {
        const user = userEvent.setup();
        render(
            <MemoryRouter initialEntries={['/tasks/task-1/results']}>
                <App>
                    <Routes>
                        <Route path="/tasks/:taskId/results" element={<TaskResults />} />
                    </Routes>
                </App>
            </MemoryRouter>,
        );

        await waitFor(() => {
            expect(apiMocks.getVulns).toHaveBeenCalledWith({
                taskId: 'task-1',
                projectId: 'project-1',
                page: 1,
                pageSize: 20,
            });
        });
        expect(await screen.findByText(/漏洞 \(25\)/)).toBeInTheDocument();

        const nextButton = document.querySelector('.ant-pagination-next button');
        expect(nextButton).toBeTruthy();
        await user.click(nextButton as HTMLButtonElement);

        await waitFor(() => {
            expect(apiMocks.getVulns).toHaveBeenCalledWith({
                taskId: 'task-1',
                projectId: 'project-1',
                page: 2,
                pageSize: 20,
            });
        });
    });

    it('normalizes severity keys before counting current page stats', async () => {
        apiMocks.getVulns.mockResolvedValue(paged([
            {
                ID: 1,
                TenantID: 'default',
                TaskID: 'task-1',
                Target: 'https://target-1.example',
                Plugin: 'poc-info-lower',
                Severity: 'info',
                CreatedAt: '2026-07-05T00:00:00Z',
            },
            {
                ID: 2,
                TenantID: 'default',
                TaskID: 'task-1',
                Target: 'https://target-2.example',
                Plugin: 'poc-info-title',
                Severity: 'Info',
                CreatedAt: '2026-07-05T00:00:00Z',
            },
        ], 2, 1));

        render(
            <MemoryRouter initialEntries={['/tasks/task-1/results']}>
                <App>
                    <Routes>
                        <Route path="/tasks/:taskId/results" element={<TaskResults />} />
                    </Routes>
                </App>
            </MemoryRouter>,
        );

        expect(await screen.findByText('当前页 Info: 2')).toBeInTheDocument();
        expect(screen.queryAllByText('当前页 Info: 1')).toHaveLength(0);
    });

    it('groups fingerprint results by product and shows all matched urls', async () => {
        apiMocks.getFingerprintGroups.mockResolvedValue(paged([
            {
                ProductName: 'nginx',
                TargetCount: 2,
                Sources: ['passive'],
                SourceLabels: ['被动命中'],
                Targets: [
                    { Target: 'https://a.example', RuleName: 'rule-a', Source: 'passive', SourceLabel: '被动命中' },
                    { Target: 'https://b.example', RuleName: 'rule-b', Source: 'passive', SourceLabel: '被动命中' },
                ],
                FirstSeen: '2026-07-05T00:00:00Z',
                LastSeen: '2026-07-05T00:01:00Z',
            },
        ], 1, 1));

        const user = userEvent.setup();
        render(
            <MemoryRouter initialEntries={['/tasks/task-1/results']}>
                <App>
                    <Routes>
                        <Route path="/tasks/:taskId/results" element={<TaskResults />} />
                    </Routes>
                </App>
            </MemoryRouter>,
        );

        await user.click(await screen.findByText(/指纹 \(1\)/));

        await waitFor(() => {
            expect(apiMocks.getFingerprintGroups).toHaveBeenCalledWith({
                taskId: 'task-1',
                projectId: 'project-1',
                page: 1,
                pageSize: 20,
                search: undefined,
                source: undefined,
            });
        });
        expect(await screen.findByText('nginx')).toBeInTheDocument();
        expect(screen.getByText('https://a.example')).toBeInTheDocument();
        expect(screen.getByText('https://b.example')).toBeInTheDocument();
    });

    it('queries fingerprints and marks directory-scan active fingerprints', async () => {
        apiMocks.getVulns.mockResolvedValue(paged([], 0, 1));
        apiMocks.getAssets.mockResolvedValue(paged([], 0, 1));
        apiMocks.getFingerprintGroups.mockResolvedValue(paged([
            {
                ProductName: 'Jenkins',
                TargetCount: 1,
                Sources: ['directory'],
                SourceLabels: ['主动指纹（目录扫描）'],
                Targets: [{
                    Target: 'https://jenkins.example:443',
                    MatchedURL: 'https://jenkins.example/jenkins/login',
                    RuleName: 'Active-Finger',
                    Source: 'directory',
                    SourceLabel: '主动指纹（目录扫描）',
                }],
                FirstSeen: '2026-07-05T00:00:00Z',
                LastSeen: '2026-07-05T00:00:00Z',
            },
        ], 1, 1));

        const user = userEvent.setup();
        render(
            <MemoryRouter initialEntries={['/tasks/task-1/results']}>
                <App>
                    <Routes>
                        <Route path="/tasks/:taskId/results" element={<TaskResults />} />
                    </Routes>
                </App>
            </MemoryRouter>,
        );

        expect(await screen.findByText('Jenkins')).toBeInTheDocument();
        expect(screen.getAllByText('主动指纹（目录扫描）').length).toBeGreaterThan(0);
        expect(screen.getByText('https://jenkins.example/jenkins/login')).toBeInTheDocument();

        await user.type(screen.getByPlaceholderText('搜索产品名称或 URL'), 'jenkins');
        await user.keyboard('{Enter}');

        await waitFor(() => {
            expect(apiMocks.getFingerprintGroups).toHaveBeenCalledWith({
                taskId: 'task-1',
                projectId: 'project-1',
                page: 1,
                pageSize: 20,
                search: 'jenkins',
                source: undefined,
            });
        });
    });

    it('renders domain ↔ resolved-IP association badges from task-wide resolution stats', async () => {
        apiMocks.getVulns.mockResolvedValue(paged([], 0, 1));
        const stats = assetStats({
            total: 2,
            web: 1,
            resolution: 1,
            resolutions: [{ domain: 'assoc.test', ips: ['198.51.100.9'] }],
        });
        apiMocks.getAssets.mockImplementation((params: { kind?: string }) => {
            if (params.kind === 'resolution') {
                return paged([{
                    ID: 11,
                    TenantID: 'default',
                    TaskID: 'task-1',
                    Target: 'assoc.test',
                    Protocol: 'RealIP',
                    Port: 0,
                    Title: '',
                    Service: '',
                    Tags: JSON.stringify({ type: 'RealIP', domain: 'assoc.test', ips: ['198.51.100.9'] }),
                    CreatedAt: '2026-07-06T00:00:00Z',
                }], 1, 1, 20, stats);
            }
            return paged([{
                ID: 12,
                TenantID: 'default',
                TaskID: 'task-1',
                Target: 'http://198.51.100.9:8080',
                Protocol: 'Web',
                Port: 8080,
                Title: 'Origin page',
                Service: 'http/200',
                CreatedAt: '2026-07-06T00:00:00Z',
            }], 1, 1, 20, stats);
        });

        const user = userEvent.setup();
        render(
            <MemoryRouter initialEntries={['/tasks/task-1/results']}>
                <App>
                    <Routes>
                        <Route path="/tasks/:taskId/results" element={<TaskResults />} />
                    </Routes>
                </App>
            </MemoryRouter>,
        );

        expect(await screen.findByText('Origin page')).toBeInTheDocument();
        expect(screen.getByText('assoc.test')).toBeInTheDocument();
        expect(screen.getByText('198.51.100.9')).toBeInTheDocument();
        expect(screen.getByRole('tab', { name: /资产 \(2\)/ })).toBeInTheDocument();
        expect(screen.getByRole('tab', { name: /Web 站点 \(1\)/ })).toBeInTheDocument();

        await user.click(screen.getByRole('tab', { name: /解析关系 \(1\)/ }));
        expect(await screen.findAllByText('assoc.test')).not.toHaveLength(0);
        expect(screen.getAllByText('198.51.100.9').length).toBeGreaterThanOrEqual(1);
    });

    it('opens the first non-empty asset result instead of an empty vulnerability tab', async () => {
		apiMocks.getVulns.mockResolvedValue(paged([], 0, 1));
		apiMocks.getAssets.mockResolvedValue(paged([{
			ID: 7,
			TenantID: 'default',
			TaskID: 'task-1',
			Target: 'https://asset.example.invalid',
			Protocol: 'Web',
			Port: 443,
			Title: 'Asset result',
			Service: 'http/200',
			CreatedAt: '2026-07-05T00:00:00Z',
		}], 1, 1, 20, assetStats({ total: 1, web: 1 })));

		render(
			<MemoryRouter initialEntries={['/tasks/task-1/results']}>
				<App>
					<Routes>
						<Route path="/tasks/:taskId/results" element={<TaskResults />} />
					</Routes>
				</App>
			</MemoryRouter>,
		);

		expect(await screen.findByText('Asset result')).toBeInTheDocument();
		expect(screen.getByRole('tab', { name: /资产 \(1\)/ })).toHaveAttribute('aria-selected', 'true');
    });

	it('opens fingerprints when they are the only available result', async () => {
		apiMocks.getVulns.mockResolvedValue(paged([], 0, 1));
		apiMocks.getAssets.mockResolvedValue(paged([], 0, 1));
		apiMocks.getFingerprintGroups.mockResolvedValue(paged([{
			ProductName: 'Apache-Tomcat',
			TargetCount: 1,
			Targets: [{ Target: 'http://127.0.0.1:8082' }],
			FirstSeen: '2026-07-05T00:00:00Z',
			LastSeen: '2026-07-05T00:00:00Z',
		}], 1, 1));

		render(
			<MemoryRouter initialEntries={['/tasks/task-1/results']}>
				<App>
					<Routes>
						<Route path="/tasks/:taskId/results" element={<TaskResults />} />
					</Routes>
				</App>
			</MemoryRouter>,
		);

		expect(await screen.findByText('Apache-Tomcat')).toBeInTheDocument();
		expect(screen.getByRole('tab', { name: /指纹 \(1\)/ })).toHaveAttribute('aria-selected', 'true');
	});

    it('exports assets for the active assets tab with the current task scope', async () => {
        const user = userEvent.setup();
        render(
            <MemoryRouter initialEntries={['/tasks/task-1/results']}>
                <App>
                    <Routes>
                        <Route path="/tasks/:taskId/results" element={<TaskResults />} />
                    </Routes>
                </App>
            </MemoryRouter>,
        );

        await user.click(await screen.findByText(/资产 \(0\)/));
        await user.click(screen.getByRole('button', { name: /导出 CSV/ }));

        await waitFor(() => {
            expect(apiMocks.exportAssets).toHaveBeenCalledWith('project-1', 'task-1', 'web');
        });
        expect(apiMocks.exportVulns).not.toHaveBeenCalled();
        expect(apiMocks.exportFingerprints).not.toHaveBeenCalled();
    });

    it('exports fingerprints for the active fingerprints tab with the current task scope', async () => {
        const user = userEvent.setup();
        render(
            <MemoryRouter initialEntries={['/tasks/task-1/results']}>
                <App>
                    <Routes>
                        <Route path="/tasks/:taskId/results" element={<TaskResults />} />
                    </Routes>
                </App>
            </MemoryRouter>,
        );

        await user.click(await screen.findByText(/指纹 \(0\)/));
        await user.click(screen.getByRole('button', { name: /导出 CSV/ }));

        await waitFor(() => {
            expect(apiMocks.exportFingerprints).toHaveBeenCalledWith('project-1', 'task-1', '', '');
        });
        expect(apiMocks.exportVulns).not.toHaveBeenCalled();
        expect(apiMocks.exportAssets).not.toHaveBeenCalled();
    });

    it('keeps PortScan rows out of the Web 站点 group', async () => {
        apiMocks.getVulns.mockResolvedValue(paged([], 0, 1));
        apiMocks.getAssets.mockResolvedValue(paged([
            {
                ID: 1,
                TenantID: 'default',
                TaskID: 'task-1',
                Target: '61.155.21.117:161',
                Protocol: 'PortScan',
                Port: 161,
                CreatedAt: '2026-08-25T16:51:48Z',
            },
            {
                ID: 2,
                TenantID: 'default',
                TaskID: 'task-1',
                Target: 'https://jslgroup.cn',
                Protocol: 'Web',
                Port: 443,
                Title: '苏豪鼎创',
                Service: 'http/200',
                CreatedAt: '2026-08-25T16:51:22Z',
            },
        ], 2, 1, 20, assetStats({ total: 2, web: 1, host_port: 1 })));

        render(
            <MemoryRouter initialEntries={['/tasks/task-1/results']}>
                <App>
                    <Routes>
                        <Route path="/tasks/:taskId/results" element={<TaskResults />} />
                    </Routes>
                </App>
            </MemoryRouter>,
        );

        expect(await screen.findByText('苏豪鼎创')).toBeInTheDocument();
        expect(screen.queryByText('PortScan')).not.toBeInTheDocument();
        expect(screen.getByRole('tab', { name: /资产 \(2\)/ })).toBeInTheDocument();
        expect(screen.getByRole('tab', { name: /Web 站点 \(1\)/ })).toBeInTheDocument();
        expect(screen.getByRole('tab', { name: /主机与端口 \(1\)/ })).toBeInTheDocument();
    });

    it('shows matched fingerprints on Web 站点 rows and marks directory-scan hits', async () => {
        apiMocks.getVulns.mockResolvedValue(paged([], 0, 1));
        apiMocks.getAssets.mockResolvedValue(paged([{
            ID: 21,
            TenantID: 'default',
            TaskID: 'task-1',
            Target: 'https://web.example',
            Protocol: 'Web',
            Port: 443,
            Title: 'Portal',
            Service: 'http/200',
            CreatedAt: '2026-08-25T16:51:22Z',
            Fingerprints: [
                { ProductName: 'Jenkins', Source: 'directory', SourceLabel: '主动指纹（目录扫描）', MatchedURL: 'https://web.example/jenkins/login' },
                { ProductName: 'nginx', Source: 'passive', SourceLabel: '被动命中' },
            ],
        }], 1, 1, 20, assetStats({ total: 1, web: 1 })));

        render(
            <MemoryRouter initialEntries={['/tasks/task-1/results']}>
                <App>
                    <Routes>
                        <Route path="/tasks/:taskId/results" element={<TaskResults />} />
                    </Routes>
                </App>
            </MemoryRouter>,
        );

        expect(await screen.findByText('Portal')).toBeInTheDocument();
        expect(screen.getByText('匹配指纹')).toBeInTheDocument();
        expect(screen.getByText('nginx')).toBeInTheDocument();
        expect(screen.getByText('Jenkins · 主动指纹（目录扫描）')).toBeInTheDocument();
    });
});
