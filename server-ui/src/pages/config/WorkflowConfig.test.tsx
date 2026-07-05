import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import { App } from 'antd';
import WorkflowConfig from './WorkflowConfig';
import { getWorkflowDictPage } from '../../services/api';

vi.mock('../../contexts/GlobalAIContext', () => ({
    useAutoContext: vi.fn(),
}));

vi.mock('../../utils/auth', () => ({
    canAccessRole: () => true,
}));

vi.mock('../../services/api', () => ({
    getWorkflowDictPage: vi.fn(),
    deleteWorkflowDict: vi.fn(),
}));

vi.mock('./WorkflowEditDrawer', () => ({
    default: () => null,
}));

type WorkflowStats = {
    total: number;
    fp_missing: number;
    poc_missing: number;
    total_pocs: number;
    fingerprint_rules: number;
};

type WorkflowPageWithStats = API.PagedResponse<API.WorkflowSummary> & {
    stats: WorkflowStats;
};

const statisticValue = (title: string, value: string) => {
    const titleNode = screen.getAllByText(title).find((node) => node.classList.contains('ant-statistic-title'));
    expect(titleNode).toBeTruthy();
    const statistic = titleNode!.closest('.ant-statistic');
    expect(statistic).toBeTruthy();
    expect(within(statistic as HTMLElement).getByText(value)).toBeInTheDocument();
};

describe('WorkflowConfig', () => {
    beforeEach(() => {
        vi.mocked(getWorkflowDictPage).mockReset();
        vi.mocked(getWorkflowDictPage).mockResolvedValue({
            items: [
                {
                    product: 'Alpha',
                    type: ['root'],
                    pocs: ['alpha-a', 'alpha-b'],
                    poc_count: 2,
                    missing_pocs: [],
                    missing_poc_count: 0,
                    fingerprint_bound: true,
                    fingerprint_rule_count: 4,
                    is_general_poc: false,
                    state: 'Approved',
                    enabled: true,
                    content_hash: 'hash-alpha',
                    version: 1,
                    updated_at: '2026-07-05T08:00:00Z',
                },
            ],
            total: 3,
            page: 1,
            page_size: 1,
            has_more: true,
            stats: {
                total: 3,
                fp_missing: 2,
                poc_missing: 2,
                total_pocs: 6,
                fingerprint_rules: 4,
            },
        } as WorkflowPageWithStats);
    });

    it('uses server aggregate stats for the overview cards while keeping table pagination', async () => {
        render(
            <App>
                <WorkflowConfig />
            </App>,
        );

        expect(await screen.findByText('Alpha')).toBeInTheDocument();
        await waitFor(() => expect(getWorkflowDictPage).toHaveBeenCalledWith(expect.objectContaining({
            page: 1,
            page_size: 15,
            scope: 'specific',
        })));

        statisticValue('Workflow 总数', '3');
        statisticValue('指纹缺失', '2');
        statisticValue('POC 文件缺失', '2');
        statisticValue('挂载 POC 总数', '6');
        statisticValue('指纹规则总数', '4');
        expect(screen.getByText('当前页 1 / 匹配 3 条')).toBeInTheDocument();
    });
});
