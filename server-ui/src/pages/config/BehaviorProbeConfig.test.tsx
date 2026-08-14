import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { App } from 'antd';
import BehaviorProbeConfig from './BehaviorProbeConfig';
import { listActiveFingerprintRules, listArsenalsPage } from '../../services/api';

vi.mock('@monaco-editor/react', () => ({
    default: () => <div data-testid="yaml-editor" />,
    DiffEditor: () => <div data-testid="yaml-diff" />,
}));

vi.mock('../../services/api', () => ({
    listArsenalsPage: vi.fn(),
    listActiveFingerprintRules: vi.fn(),
    getArsenal: vi.fn(),
    getArsenalHistory: vi.fn(),
    getNodes: vi.fn(),
    inspectActiveFingerprint: vi.fn(),
    saveArsenal: vi.fn(),
    approveArsenal: vi.fn(),
    deprecateArsenal: vi.fn(),
    rollbackArsenal: vi.fn(),
    debugBehaviorProbe: vi.fn(),
}));

describe('BehaviorProbeConfig', () => {
    beforeEach(() => {
        vi.mocked(listArsenalsPage).mockResolvedValue({
            items: [{ ID: 'active-1', TenantID: 'default', Type: 'active_fingerprint', FileName: 'shiro-detect.yaml', Content: '', Hash: 'hash', PreviousHash: '', Version: 1, State: 'Approved', CreatedAt: '', UpdatedAt: '' }],
            total: 1, page: 1, page_size: 200, has_more: false,
        });
        vi.mocked(listActiveFingerprintRules).mockResolvedValue([{
            ArtifactID: 'active-1', SourceFile: 'shiro-detect.yaml', Name: 'shiro-detect', ProductName: 'APACHE-Shiro', ContentHash: 'hash', Version: 1,
            State: 'Approved', Enabled: true, DeclaredAutoProfile: 'safe', ComputedAutoProfile: 'safe', AutoEligible: true, MaxRequests: 1, ClassificationReason: '[]', DownstreamValidations: ['Shiro-Key-Crack'], UpdatedAt: '',
        }]);
    });

    it('shows each Nuclei behavior probe as an independently governed artifact', async () => {
        render(<App><BehaviorProbeConfig /></App>);
        expect(await screen.findByText('shiro-detect.yaml')).toBeInTheDocument();
        expect(screen.getByText('APACHE-Shiro')).toBeInTheDocument();
        expect(screen.getByText('Shiro-Key-Crack')).toBeInTheDocument();
        expect(screen.getByText('一条探针一个完整 Nuclei YAML')).toBeInTheDocument();
    });
});
