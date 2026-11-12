import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { App } from 'antd';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import CredentialFindingsPanel from './CredentialFindingsPanel';
import { listTaskCredentialFindings, revealCredentialFinding } from '../../services/api';

vi.mock('../../services/api', () => ({
    listTaskCredentialFindings: vi.fn(),
    revealCredentialFinding: vi.fn(),
}));

vi.mock('../../utils/auth', () => ({ getCurrentUserRole: vi.fn(() => 'admin') }));

describe('CredentialFindingsPanel', () => {
    beforeEach(() => {
        vi.mocked(listTaskCredentialFindings).mockResolvedValue([{
            id: 'finding-1', endpoint: 'host.test:22', service: 'ssh', plugin: 'ssh-login',
            masked_username: 'ad***', created_at: '2026-08-13T00:00:00Z',
        }]);
        vi.mocked(revealCredentialFinding).mockResolvedValue({ username: 'admin', password: 'example-secret' });
    });

    it('keeps normal results useful while revealing plaintext only through the audited Admin action', async () => {
        const user = userEvent.setup();
        render(<App><CredentialFindingsPanel taskId="task-1" /></App>);

        expect(await screen.findByText('ad***')).toBeInTheDocument();
        expect(screen.getByText('••••••••')).toBeInTheDocument();
        expect(screen.queryByText('example-secret')).not.toBeInTheDocument();

        await user.click(screen.getByRole('button', { name: /审计揭示/ }));
        expect(await screen.findByText('example-secret')).toBeInTheDocument();
        expect(revealCredentialFinding).toHaveBeenCalledWith('finding-1');
    });
});
