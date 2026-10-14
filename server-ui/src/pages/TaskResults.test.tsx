import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { App } from 'antd';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import TaskResults from './TaskResults';

const apiMocks = vi.hoisted(() => ({
    getVulns: vi.fn(),
    getAssets: vi.fn(),
    getFingerprints: vi.fn(),
    getFingerprintGroups: vi.fn(),
    getAssetLineage: vi.fn(),
    exportVulns: vi.fn(),
    exportAssets: vi.fn(),
    exportFingerprints: vi.fn(),
}));

vi.mock('../contexts/GlobalAIContext', () => ({
    useAutoContext: vi.fn(),
}));

vi.mock('../services/api', () => apiMocks);

const paged = <T,>(items: T[], total: number, page: number, pageSize = 20) => ({
    items,
    total,
    page,
    page_size: pageSize,
    has_more: page * pageSize < total,
    generated_at: '2026-07-05T00:00:00Z',
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
        apiMocks.getAssetLineage.mockResolvedValue({ nodes: [] });
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
                Targets: [
                    { Target: 'https://a.example', RuleName: 'rule-a' },
                    { Target: 'https://b.example', RuleName: 'rule-b' },
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
            });
        });
        expect(await screen.findByText('nginx')).toBeInTheDocument();
        expect(screen.getByText('https://a.example')).toBeInTheDocument();
        expect(screen.getByText('https://b.example')).toBeInTheDocument();
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
            expect(apiMocks.exportAssets).toHaveBeenCalledWith('project-1', 'task-1');
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
            expect(apiMocks.exportFingerprints).toHaveBeenCalledWith('project-1', 'task-1');
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
        await user.type(screen.getByPlaceholderText('按产品名称搜索'), 'nginx');

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

        await user.click(document.querySelector('.ant-table-row-expand-icon') as HTMLElement);
        await user.click(await screen.findByText('看资产'));

        await waitFor(() => {
            expect(apiMocks.getAssets).toHaveBeenCalledWith({
                taskId: 'task-1',
                projectId: 'project-1',
                page: 1,
                pageSize: 20,
                search: 'a.example',
            });
        });
        expect(screen.getByRole('tab', { name: /资产 \(0\)/ })).toHaveAttribute('aria-selected', 'true');
        expect(await screen.findByRole('button', { name: '清除过滤' })).toBeInTheDocument();

        await user.click(screen.getByRole('button', { name: '清除过滤' }));
        await waitFor(() => {
            expect(apiMocks.getAssets).toHaveBeenCalledWith({
                taskId: 'task-1',
                projectId: 'project-1',
                page: 1,
                pageSize: 20,
            });
        });
        expect(screen.queryByRole('button', { name: '清除过滤' })).toBeNull();
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
                { target: '1.2.3.4', stage: 'input', node_type: 'input' },
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

        await user.click(await screen.findByText(/资产 \(1\)/));
        await user.click(await screen.getByRole('button', { name: /溯源/ }));

        await waitFor(() => {
            expect(apiMocks.getAssetLineage).toHaveBeenCalledWith('project-1', 5);
        });
        expect(await screen.findByText('扫描起点')).toBeInTheDocument();
        const drawerEl = document.querySelector('.ant-drawer-content');
        expect(drawerEl).toBeTruthy();
        const drawer = within(drawerEl as HTMLElement);
        expect(drawer.getByText('PortScan')).toBeInTheDocument();
        expect(drawer.getByText('Web')).toBeInTheDocument();
        expect(drawer.getAllByText('1.2.3.4:80').length).toBeGreaterThan(0);
        // 起点节点必须具体到某个输入资产（IP/域名），而不是空描述。
        expect(drawer.getAllByText('1.2.3.4').length).toBeGreaterThan(0);
    });
});
