import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { App } from 'antd';
import PocConfig from './PocConfig';
import {
    addWorkflowDict,
    getArsenal,
    getFingerprintDictPage,
    getWorkflowDictPage,
    listPocRulesPage,
    updateWorkflowDict,
} from '../../services/api';

vi.mock('@monaco-editor/react', () => ({
    default: ({ value }: { value?: string }) => <textarea aria-label="POC 编辑器" value={value || ''} readOnly />,
}));

vi.mock('../../contexts/GlobalAIContext', () => ({
    useAutoContext: vi.fn(),
    useGlobalAI: () => ({
        visible: false,
        openGlobalAI: vi.fn(),
        registerEditableTarget: vi.fn(() => vi.fn()),
    }),
}));

vi.mock('../../utils/auth', () => ({
    canAccessRole: () => true,
}));

vi.mock('./PocDebugPanel', () => ({
    default: () => <div data-testid="poc-debug-panel" />,
}));

vi.mock('../../services/api', () => ({
    listPocRulesPage: vi.fn(),
    getWorkflowDictPage: vi.fn(),
    getFingerprintDictPage: vi.fn(),
    getArsenal: vi.fn(),
    saveArsenal: vi.fn(),
    deleteArsenal: vi.fn(),
    approveArsenal: vi.fn(),
    addWorkflowDict: vi.fn(),
    updateWorkflowDict: vi.fn(),
}));

const orphanPoc: API.PocRuleMetadata = {
    id: 1,
    tenant_id: 'default',
    artifact_id: 'default:poc:orphan.yaml',
    source_file: 'orphan.yaml',
    name: 'Orphan POC',
    target_product: '',
    cve: '',
    compatibility_status: '',
    source_version: '',
    severity: 'medium',
    tags: '',
    author: '',
    description: '',
    content_hash: 'hash-orphan',
    version: 1,
    state: 'Approved',
    enabled: true,
    created_at: '2026-07-06T00:00:00Z',
    updated_at: '2026-07-06T00:00:00Z',
};

const makePoc = (sourceFile: string, id: number): API.PocRuleMetadata => ({
    ...orphanPoc,
    id,
    artifact_id: `default:poc:${sourceFile}`,
    source_file: sourceFile,
    name: sourceFile.replace(/\.ya?ml$/i, ''),
    content_hash: `hash-${id}`,
});

const linkedPocOne = makePoc('linked-one.yaml', 2);
const linkedPocTwo = makePoc('linked-two.yaml', 3);

const renderPocConfig = async () => {
    render(
        <App>
            <PocConfig />
        </App>,
    );
    expect(await screen.findByText('orphan.yaml')).toBeInTheDocument();
};

describe('PocConfig Workflow governance', () => {
    beforeEach(() => {
        vi.mocked(listPocRulesPage).mockReset();
        vi.mocked(getWorkflowDictPage).mockReset();
        vi.mocked(getFingerprintDictPage).mockReset();
        vi.mocked(getArsenal).mockReset();
        vi.mocked(addWorkflowDict).mockReset();
        vi.mocked(updateWorkflowDict).mockReset();

        vi.mocked(listPocRulesPage).mockImplementation(async (params) => {
            if (params?.page_size === 200) {
                return {
                    items: [orphanPoc, linkedPocOne, linkedPocTwo],
                    total: 3,
                    page: 1,
                    page_size: 200,
                    has_more: false,
                };
            }
            return {
                items: [orphanPoc],
                total: 3,
                page: 1,
                page_size: 15,
                has_more: false,
            };
        });
        vi.mocked(getWorkflowDictPage).mockImplementation(async (params) => {
            if (params?.q === 'Alpha') {
                return {
                    items: [{
                        product: 'Alpha',
                        type: ['root'],
                        pocs: ['alpha-existing', 'orphan.yaml'],
                        poc_count: 2,
                        missing_pocs: [],
                        missing_poc_count: 0,
                        fingerprint_bound: true,
                        fingerprint_rule_count: 2,
                        is_general_poc: false,
                        state: 'Approved',
                        enabled: true,
                        content_hash: 'wf-alpha',
                        version: 1,
                        updated_at: '2026-07-06T00:00:00Z',
                    }],
                    total: 1,
                    page: 1,
                    page_size: 50,
                    has_more: false,
                    stats: { total: 1, fp_missing: 0, poc_missing: 0, total_pocs: 1, fingerprint_rules: 2 },
                };
            }
            return {
                items: [{
                    product: 'LinkedProduct',
                    type: ['root', 'base'],
                    pocs: ['linked-one', 'linked-two.yaml'],
                    poc_count: 2,
                    missing_pocs: [],
                    missing_poc_count: 0,
                    fingerprint_bound: true,
                    fingerprint_rule_count: 1,
                    is_general_poc: false,
                    state: 'Approved',
                    enabled: true,
                    content_hash: 'wf-linked',
                    version: 1,
                    updated_at: '2026-07-06T00:00:00Z',
                }],
                total: 1,
                page: 1,
                page_size: 50,
                has_more: false,
                stats: { total: 1, fp_missing: 0, poc_missing: 0, total_pocs: 2, fingerprint_rules: 1 },
            };
        });
        vi.mocked(getFingerprintDictPage).mockImplementation(async (params) => {
            if (params?.q === 'Beta') {
                return {
                    items: [{
                        product: 'Beta',
                        rule_count: 1,
                        state: 'Approved',
                        enabled: true,
                        version: 1,
                        updated_at: '2026-07-06T00:00:00Z',
                    }],
                    total: 1,
                    page: 1,
                    page_size: 50,
                    has_more: false,
                };
            }
            return { items: [], total: 0, page: 1, page_size: 50, has_more: false };
        });
        vi.mocked(getArsenal).mockResolvedValue({
            ID: 'default:poc:orphan.yaml',
            TenantID: 'default',
            Type: 'poc',
            FileName: 'orphan.yaml',
            Content: 'id: orphan\ninfo:\n  name: Orphan\n',
            Hash: 'hash-orphan',
            PreviousHash: '',
            Version: 1,
            State: 'Approved',
            CreatedAt: '2026-07-06T00:00:00Z',
            UpdatedAt: '2026-07-06T00:00:00Z',
        });
    });

    it('shows a governance prompt when editing a POC that is not in Workflow', async () => {
        const user = userEvent.setup();
        await renderPocConfig();

        await user.click(screen.getByRole('button', { name: /编辑/ }));

        expect(await screen.findByText(/该 POC 不在 Workflow 中/)).toBeInTheDocument();
        expect(screen.getByText(/扫描不会主动触发/)).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /关联到 Workflow/ })).toBeInTheDocument();
    });

    it('shows all POC usage counts while the table keeps paginated rows', async () => {
        const user = userEvent.setup();
        await renderPocConfig();

        expect(await screen.findByText('全部 (3)')).toBeInTheDocument();
        expect(screen.getByText('在 Workflow 中 (2)')).toBeInTheDocument();
        expect(screen.getByText('不在 Workflow 中 (1)')).toBeInTheDocument();
        expect(screen.getByText('当前页 1 / 匹配 3 条')).toBeInTheDocument();
        expect(screen.queryByText('linked-one.yaml')).not.toBeInTheDocument();

        await user.click(screen.getByText('在 Workflow 中 (2)'));
        expect(await screen.findByText('当前页 2 / 匹配 2 条')).toBeInTheDocument();
        expect(screen.getByText('linked-one.yaml')).toBeInTheDocument();
        expect(screen.getByText('linked-two.yaml')).toBeInTheDocument();

        await user.click(screen.getByText('不在 Workflow 中 (1)'));
        expect(await screen.findByText('当前页 1 / 匹配 1 条')).toBeInTheDocument();
        expect(screen.getByText('orphan.yaml')).toBeInTheDocument();
    });

    it('appends the current POC to an existing Workflow without duplicating suffixes', async () => {
        const user = userEvent.setup();
        await renderPocConfig();

        await user.click(screen.getByRole('button', { name: /编辑/ }));
        await user.click(await screen.findByRole('button', { name: /关联到 Workflow/ }));
        await user.type(await screen.findByPlaceholderText('搜索 Workflow 或 Fingerprint product'), 'Alpha');
        await user.click(await screen.findByText('Alpha'));
        await user.click(screen.getByRole('button', { name: /保存关联/ }));

        await waitFor(() => expect(updateWorkflowDict).toHaveBeenCalledWith('Alpha', {
            product: 'Alpha',
            type: ['root'],
            pocs: ['alpha-existing', 'orphan'],
        }));
    });

    it('creates a Workflow with root and base triggers when only a Fingerprint product exists', async () => {
        const user = userEvent.setup();
        await renderPocConfig();

        await user.click(screen.getByRole('button', { name: /编辑/ }));
        await user.click(await screen.findByRole('button', { name: /关联到 Workflow/ }));
        await user.type(await screen.findByPlaceholderText('搜索 Workflow 或 Fingerprint product'), 'Beta');
        await user.click(await screen.findByText('Beta'));
        await user.click(screen.getByRole('button', { name: /保存关联/ }));

        await waitFor(() => expect(addWorkflowDict).toHaveBeenCalledWith({
            product: 'Beta',
            type: ['root', 'base'],
            pocs: ['orphan'],
        }));
    });
});
