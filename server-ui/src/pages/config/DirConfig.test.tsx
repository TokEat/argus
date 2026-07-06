import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { App } from 'antd';
import DirConfig from './DirConfig';
import { getDirDict, getFingerprintDict, getWorkflowDict } from '../../services/api';

vi.mock('../../contexts/GlobalAIContext', () => ({
    useAutoContext: vi.fn(),
}));

vi.mock('../../utils/auth', () => ({
    canAccessRole: () => true,
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
    });

    it('updates visible rows when the fingerprint page size changes', async () => {
        const user = userEvent.setup();
        render(
            <App>
                <DirConfig />
            </App>,
        );

        expect(await screen.findByText('Product-15')).toBeInTheDocument();
        expect(screen.queryByText('Product-16')).not.toBeInTheDocument();

        await user.click(document.querySelector('.ant-pagination-options-size-changer .ant-select-selector') as HTMLElement);
        await user.click(await screen.findByText(/20\s*\/\s*page|20\s*条\s*\/\s*页/));

        expect(await screen.findByText('Product-20')).toBeInTheDocument();
    });
});
