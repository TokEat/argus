import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { App } from 'antd';
import { MemoryRouter } from 'react-router-dom';
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
});
