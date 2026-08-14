import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { App } from 'antd';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import DirConfig from './DirConfig';
import { getDirDict, getFingerprintDict, getWorkflowDict, updateFingerprintDict } from '../../services/api';

vi.mock('../../contexts/GlobalAIContext', () => ({
    useAutoContext: vi.fn(),
}));

const authState = vi.hoisted(() => ({ allowed: true }));

vi.mock('../../utils/auth', () => ({
    canAccessRole: (role: string) => role === 'admin' && authState.allowed,
}));

vi.mock('../../services/api', () => ({
    getFingerprintDict: vi.fn(),
    getWorkflowDict: vi.fn(),
    getDirDict: vi.fn(),
    addFingerprintDict: vi.fn(),
    updateFingerprintDict: vi.fn(),
    deleteFingerprintDict: vi.fn(),
}));

const fingerprints = Array.from({ length: 20 }, (_, index) => ({
    product: `Product-${String(index + 1).padStart(2, '0')}`,
    rules: [`body="product-${index + 1}"`],
}));

describe('DirConfig', () => {
    beforeEach(() => {
        vi.mocked(getFingerprintDict).mockReset();
        vi.mocked(getWorkflowDict).mockReset();
        vi.mocked(getDirDict).mockReset();
        vi.mocked(getFingerprintDict).mockResolvedValue(fingerprints);
        vi.mocked(getWorkflowDict).mockResolvedValue([]);
        vi.mocked(getDirDict).mockResolvedValue([]);
        authState.allowed = true;
    });

    const renderPage = () => render(
        <MemoryRouter initialEntries={['/config/active-finger']}>
            <App>
                <Routes>
                    <Route path="/config/active-finger" element={<DirConfig />} />
                    <Route path="/config/dir" element={<div>路径探针目标页</div>} />
                </Routes>
            </App>
        </MemoryRouter>,
    );

    it('updates visible rows when the fingerprint page size changes', async () => {
        const user = userEvent.setup();
        renderPage();

        expect(await screen.findByText('Product-15')).toBeInTheDocument();
        expect(screen.queryByText('Product-16')).not.toBeInTheDocument();

        await user.click(document.querySelector('.ant-pagination-options-size-changer .ant-select-selector') as HTMLElement);
        await user.click(await screen.findByText(/20\s*\/\s*page|20\s*条\s*\/\s*页/));

        expect(await screen.findByText('Product-20')).toBeInTheDocument();
    });

    it('edits fingerprint rules in a multiline input and saves them as rule array', async () => {
        const user = userEvent.setup();
        renderPage();

        expect(await screen.findByText('Product-01')).toBeInTheDocument();

        const editButtons = await screen.findAllByRole('button', { name: /编辑/ });
        await user.click(editButtons[0]);

        const rulesInput = await screen.findByPlaceholderText('每行一条规则，规则之间按 OR 关系处理');
        expect(rulesInput).toHaveValue('body="product-1"');

        await user.clear(rulesInput);
        await user.type(rulesInput, 'body="alpha"{enter}header="beta" || cert="beta"');
        await user.click(screen.getByRole('button', { name: 'OK' }));

        expect(updateFingerprintDict).toHaveBeenCalledWith('Product-01', {
            product: 'Product-01',
            rules: ['body="alpha"', 'header="beta" || cert="beta"'],
        });
    }, 15000);

    it('opens the matching path-probe editor from the Dir association', async () => {
        const user = userEvent.setup();
        vi.mocked(getDirDict).mockResolvedValue([{ product: 'Product-01', paths: ['/admin'] }]);
        renderPage();

        await user.click(await screen.findByRole('button', { name: '编辑 Product-01 路径探针' }));
        expect(await screen.findByText('路径探针目标页')).toBeInTheDocument();
    });

    it('does not expose dictionary write controls without Admin permission', async () => {
        authState.allowed = false;
        renderPage();

        expect(await screen.findByText('Product-01')).toBeInTheDocument();
        expect(screen.queryByRole('button', { name: '新增特征指纹' })).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: /编辑/ })).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: /配置路径/ })).not.toBeInTheDocument();
    });
});
