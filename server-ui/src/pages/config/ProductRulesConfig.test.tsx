import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import ProductRulesConfig from './ProductRulesConfig';

vi.mock('./DirConfig', () => ({ default: () => <div>被动规则内容</div> }));
vi.mock('./BehaviorProbeConfig', () => ({ default: () => <div>行为探针内容</div> }));
vi.mock('./DirProbeConfig', () => ({ default: () => <div>路径探针内容</div> }));
vi.mock('./WorkflowConfig', () => ({ default: () => <div>Workflow 内容</div> }));

describe('ProductRulesConfig', () => {
    it('shows concise product-rule tab labels without storage filenames', () => {
        render(
            <MemoryRouter initialEntries={['/config/active-finger']}>
                <ProductRulesConfig />
            </MemoryRouter>,
        );

        expect(screen.getByRole('tab', { name: '被动规则' })).toBeInTheDocument();
        expect(screen.getByRole('tab', { name: '行为探针' })).toBeInTheDocument();
        expect(screen.getByRole('tab', { name: '路径探针' })).toBeInTheDocument();
        expect(screen.getByRole('tab', { name: 'Workflow / POC 关联' })).toBeInTheDocument();
        expect(screen.queryByText(/finger\.yaml|active-fingerprints|dir\.yaml/)).not.toBeInTheDocument();
    });
});
