import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { App } from 'antd';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import TaskResults from './TaskResults';

const apiMocks = vi.hoisted(() => ({
    getVulns: vi.fn(),
    getVulnFacets: vi.fn(),
    getAssets: vi.fn(),
    getAssetFacets: vi.fn(),
    getFingerprints: vi.fn(),
    getFingerprintGroups: vi.fn(),
    getAssetLineage: vi.fn(),
    listCrawlSiteCandidates: vi.fn(),
    listSensitiveFindings: vi.fn(),
    exportVulns: vi.fn(),
    exportAssets: vi.fn(),
    exportFingerprints: vi.fn(),
    revealCredentialFinding: vi.fn(),
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

// 构造一个最小可用的 JWT（payload 为 base64url 编码的 claims），供 getCurrentUserRole 读取 role。
const makeToken = (claims: Record<string, unknown>): string => {
    const payload = btoa(JSON.stringify(claims)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    return `header.${payload}.sig`;
};

describe('TaskResults', () => {
    beforeEach(() => {
    apiMocks.listCrawlSiteCandidates.mockResolvedValue(paged([], 0, 1));
    apiMocks.listSensitiveFindings.mockResolvedValue(paged([], 0, 1));
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
        apiMocks.getAssetLineage.mockResolvedValue({ nodes: [] });
        apiMocks.getVulnFacets.mockResolvedValue({ plugins: [], statuses: [], ai_statuses: [], hosts: [], ports: [] });
        apiMocks.getAssetFacets.mockResolvedValue({ services: [], fingerprints: [] });
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
                severity: '!info',
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
                severity: '!info',
            });
        });
    });

    it('uses one compact filter and excludes a plugin from the vulnerability name', async () => {
        apiMocks.getVulnFacets.mockResolvedValue({
            plugins: [{ value: 'poc-1', count: 1 }],
            statuses: [], ai_statuses: [], hosts: [], ports: [],
        });
        apiMocks.getVulns.mockResolvedValue(paged([
            { ID: 1, TenantID: 'default', TaskID: 'task-1', Target: 'https://target-1.example', Plugin: 'poc-1', Severity: 'high', CreatedAt: '2026-07-05T00:00:00Z' },
        ], 1, 1));
        const user = userEvent.setup();
        render(<MemoryRouter initialEntries={['/tasks/task-1/results']}><App><Routes><Route path="/tasks/:taskId/results" element={<TaskResults />} /></Routes></App></MemoryRouter>);
        expect(await screen.findByText('poc-1')).toBeInTheDocument();
        await user.click(screen.getByRole('button', { name: '排除 poc-1' }));
        await waitFor(() => {
            expect(apiMocks.getVulns).toHaveBeenLastCalledWith(expect.objectContaining({ taskId: 'task-1', severity: '!info', plugin: '!poc-1', page: 1 }));
        });
        expect(screen.getByRole('combobox', { name: '漏洞筛选字段' })).toBeInTheDocument();
        expect(screen.getByRole('combobox', { name: '漏洞筛选值' })).toBeInTheDocument();
        await user.click(screen.getByRole('button', { name: '清除条件' }));
        await waitFor(() => {
            expect(apiMocks.getVulns).toHaveBeenLastCalledWith({ taskId: 'task-1', projectId: 'project-1', page: 1, pageSize: 20, severity: '!info' });
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
                SourceLabels: ['主动路径'],
                Targets: [{
                    Target: 'https://jenkins.example:443',
                    MatchedURL: 'https://jenkins.example/jenkins/login',
                    RuleName: 'Active-Finger',
                    Source: 'directory',
                    SourceLabel: '主动路径',
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
        expect(screen.getAllByText('主动路径').length).toBeGreaterThan(0);
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

    it('searches fingerprint products by name and resets to page 1', async () => {
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
        await user.type(screen.getByPlaceholderText('搜索产品名称或 URL'), 'nginx{Enter}');

        await waitFor(() => {
            expect(apiMocks.getFingerprintGroups).toHaveBeenCalledWith({
                taskId: 'task-1',
                projectId: 'project-1',
                page: 1,
                pageSize: 20,
                search: 'nginx',
            });
        }, { timeout: 3000 });
    });

    it('drills down from a fingerprint target to filtered assets and clears the filter', async () => {
        apiMocks.getVulns.mockResolvedValue(paged([], 0, 1));
        apiMocks.getAssets.mockResolvedValue(paged([], 0, 1));
        apiMocks.getFingerprintGroups.mockResolvedValue(paged([
            {
                ProductName: 'nginx',
                TargetCount: 1,
                Targets: [{ Target: 'https://a.example', RuleName: 'rule-a' }],
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

        expect(await screen.findByText('nginx')).toBeInTheDocument();
        expect(screen.getByRole('tab', { name: /指纹 \(1\)/ })).toHaveAttribute('aria-selected', 'true');

        await user.click(await screen.findByText('看资产'));

        await waitFor(() => {
            expect(apiMocks.getAssets).toHaveBeenCalledWith({
                taskId: 'task-1',
                projectId: 'project-1',
                page: 1,
                pageSize: 20,
                kind: 'web',
                search: 'a.example',
            });
        });
        expect(screen.getByRole('tab', { name: /资产 \(0\)/ })).toHaveAttribute('aria-selected', 'true');
        expect(await screen.findByRole('button', { name: '清除全部过滤' })).toBeInTheDocument();

        await user.click(screen.getByRole('button', { name: '清除全部过滤' }));
        await waitFor(() => {
            expect(apiMocks.getAssets).toHaveBeenCalledWith({
                taskId: 'task-1',
                projectId: 'project-1',
                page: 1,
                pageSize: 20,
                kind: 'web',
            });
        });
        expect(screen.queryByRole('button', { name: '清除全部过滤' })).toBeNull();
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

    it('opens the lineage drawer and renders the scan-chain steps for an asset', async () => {
        apiMocks.getAssets.mockImplementation(({ page }: { page: number }) => paged([
            {
                ID: 5,
                TenantID: 'default',
                TaskID: 'task-1',
                Target: 'http://1.2.3.4:80',
                Protocol: 'Web',
                Port: 80,
                URL: 'http://1.2.3.4:80',
                Title: '',
                Service: 'http/200',
                CreatedAt: '2026-07-05T00:00:00Z',
            },
        ], 1, page));
        apiMocks.getAssetLineage.mockResolvedValue({
            nodes: [
                { target: '1.2.3.0/24', stage: 'input', node_type: 'input' },
                { target: '1.2.3.4', stage: 'IPAlive', node_type: 'asset' },
                { target: '1.2.3.4:80', stage: 'PortScan', node_type: 'asset' },
                { target: 'http://1.2.3.4:80', stage: 'Web', node_type: 'asset' },
            ],
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
        await user.click(await screen.findByRole('tab', { name: /资产 \(1\)/ }));
        await user.click(await screen.getByRole('button', { name: /溯源/ }));

        await waitFor(() => {
            expect(apiMocks.getAssetLineage).toHaveBeenCalledWith('project-1', 5);
        });
        expect(await screen.findByText('扫描起点')).toBeInTheDocument();
        const drawerEl = document.querySelector('.ant-drawer-content');
        expect(drawerEl).toBeTruthy();
        const drawer = within(drawerEl as HTMLElement);
        expect(drawer.getByText('IPAlive')).toBeInTheDocument();
        expect(drawer.getByText('PortScan')).toBeInTheDocument();
        expect(drawer.getByText('Web')).toBeInTheDocument();
        // 起点必须是输入网段本身，而不是从网段扫出来的派生 IP。
        expect(drawer.getAllByText('1.2.3.0/24').length).toBeGreaterThan(0);
        expect(drawer.getAllByText('1.2.3.4:80').length).toBeGreaterThan(0);
        expect(drawer.getAllByText('1.2.3.4').length).toBeGreaterThan(0);
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
                { ProductName: 'Jenkins', Source: 'directory', SourceLabel: '主动路径', MatchedURL: 'https://web.example/jenkins/login' },
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
        expect(screen.getAllByText('匹配指纹').length).toBeGreaterThan(0);
        expect(screen.getByText('nginx')).toBeInTheDocument();
        expect(screen.getByText('Jenkins · 主动路径')).toBeInTheDocument();
    });

    it('lets an admin reveal the sealed credential from a credential vuln row', async () => {
        apiMocks.getVulns.mockImplementation(({ page }: { page: number }) => paged([
            {
                ID: page,
                TenantID: 'default',
                TaskID: 'task-1',
                Target: '10.3.130.95:22',
                Plugin: 'SSH-Crack',
                Severity: 'critical',
                Payload: JSON.stringify({
                    go_poc: {
                        credential_finding_id: 'finding-1',
                        info_left: 'credential evidence sealed',
                        show_msg: 'credential verified (masked)',
                    },
                }),
                CreatedAt: '2026-07-05T00:00:00Z',
            },
        ], 1, page));
        apiMocks.revealCredentialFinding.mockResolvedValue({ username: 'svc_ssh', password: 'P@ssw0rd!x' });
        localStorage.setItem('token', makeToken({ role: 'admin' }));

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

        await user.click(await screen.findByRole('button', { name: /审计揭示/ }));
        await waitFor(() => {
            expect(apiMocks.revealCredentialFinding).toHaveBeenCalledWith('finding-1');
        });
        // antd confirm 门户在动画期间可能渲染重复节点，用 findAllByText 断言脱敏值已展示。
        expect((await screen.findAllByText('svc_ssh')).length).toBeGreaterThan(0);
        expect((await screen.findAllByText('P@ssw0rd!x')).length).toBeGreaterThan(0);
    });

    it('shows a captured-credential tag without a reveal entry for non-admin rows', async () => {
        apiMocks.getVulns.mockImplementation(({ page }: { page: number }) => paged([
            {
                ID: page,
                TenantID: 'default',
                TaskID: 'task-1',
                Target: '10.3.130.95:22',
                Plugin: 'SSH-Crack',
                Severity: 'critical',
                Payload: JSON.stringify({ go_poc: { credential_finding_id: 'finding-1' } }),
                CreatedAt: '2026-07-05T00:00:00Z',
            },
        ], 1, page));
        localStorage.setItem('token', makeToken({ role: 'viewer' }));

        render(
            <MemoryRouter initialEntries={['/tasks/task-1/results']}>
                <App>
                    <Routes>
                        <Route path="/tasks/:taskId/results" element={<TaskResults />} />
                    </Routes>
                </App>
            </MemoryRouter>,
        );

        expect(await screen.findByText('已捕获')).toBeInTheDocument();
        expect(screen.queryByRole('button', { name: /审计揭示/ })).toBeNull();
        expect(apiMocks.revealCredentialFinding).not.toHaveBeenCalled();
    });

    it('renders no credential entry for vuln rows without a credential finding', async () => {
        apiMocks.getVulns.mockImplementation(({ page }: { page: number }) => paged([
            {
                ID: page,
                TenantID: 'default',
                TaskID: 'task-1',
                Target: 'https://plain.example',
                Plugin: 'XSS',
                Severity: 'high',
                CreatedAt: '2026-07-05T00:00:00Z',
            },
        ], 1, page));
        localStorage.setItem('token', makeToken({ role: 'admin' }));

        render(
            <MemoryRouter initialEntries={['/tasks/task-1/results']}>
                <App>
                    <Routes>
                        <Route path="/tasks/:taskId/results" element={<TaskResults />} />
                    </Routes>
                </App>
            </MemoryRouter>,
        );

        await screen.findByText(/漏洞 \(1\)/);
        expect(screen.queryByRole('button', { name: /审计揭示/ })).toBeNull();
        expect(screen.queryByText('已捕获')).toBeNull();
    });

});
