import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { App } from 'antd';
import { MemoryRouter } from 'react-router-dom';
import userEvent from '@testing-library/user-event';
import DirProbeConfig from './DirProbeConfig';
import { getDirDict, getFingerprintDict } from '../../services/api';

vi.mock('../../contexts/GlobalAIContext', () => ({
    useAutoContext: vi.fn(),
}));

vi.mock('../../utils/auth', () => ({
    canAccessRole: (role: string) => role === 'admin',
}));

vi.mock('../../services/api', () => ({
    getDirDict: vi.fn(),
    getFingerprintDict: vi.fn(),
    addDirDict: vi.fn(),
    updateDirDict: vi.fn(),
    deleteDirDict: vi.fn(),
}));

const renderPage = (entry: string) => render(
    <MemoryRouter initialEntries={[entry]}>
        <App>
            <DirProbeConfig />
        </App>
    </MemoryRouter>,
);

describe('DirProbeConfig linked product editing', () => {
    beforeEach(() => {
        vi.mocked(getDirDict).mockReset();
        vi.mocked(getFingerprintDict).mockReset();
        vi.mocked(getFingerprintDict).mockResolvedValue([
            { product: 'Existing', rules: ['body="existing"'] },
            { product: 'NewProduct', rules: ['body="new"'] },
        ]);
    });

    it('opens the existing product path editor from the product query', async () => {
        vi.mocked(getDirDict).mockResolvedValue([{ product: 'Existing', paths: ['/admin'] }]);
        renderPage('/config/dir?product=Existing');

        expect(await screen.findByText('编辑 Dir 规则 — Existing')).toBeInTheDocument();
        expect(document.querySelector('#product')).toHaveValue('Existing');
        expect(screen.getAllByText('/admin').length).toBeGreaterThan(0);
    });

    it('prefills a new path rule when the product has no Dir association', async () => {
        vi.mocked(getDirDict).mockResolvedValue([]);
        renderPage('/config/dir?product=NewProduct');

        expect(await screen.findByText('添加 Dir 探测规则')).toBeInTheDocument();
        expect(document.querySelector('#product')).toHaveValue('NewProduct');
    });

    it('switches the items-per-page selector and re-renders the table', async () => {
        const user = userEvent.setup();
        const items = Array.from({ length: 35 }, (_, i) => ({
            product: `Product-${i + 1}`,
            paths: [`/path-${i + 1}`],
        }));
        vi.mocked(getDirDict).mockResolvedValue(items);
        renderPage('/config/dir');

        // The default page size is 15, so the last rows are on later pages.
        await waitFor(() => expect(screen.getByText('Product-1')).toBeInTheDocument());
        expect(screen.queryByText('Product-31')).not.toBeInTheDocument();

        await user.click(document.querySelector('.ant-pagination-options-size-changer .ant-select-selector') as HTMLElement);
        await user.click(await screen.findByText(/50\s*(条\s*\/\s*页|\/\s*page)/));

        // 50 items fit on one page, so the previously hidden rows must appear.
        await waitFor(() => expect(screen.getByText('Product-35')).toBeInTheDocument());
    });
});
