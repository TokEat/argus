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
    exportVulns: vi.fn(),
    getExploitCandidatesForVuln: vi.fn(),
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
});
