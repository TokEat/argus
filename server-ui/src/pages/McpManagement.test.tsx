import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { App } from 'antd';
import { MemoryRouter } from 'react-router-dom';
import McpManagement from './McpManagement';

const apiMocks = vi.hoisted(() => ({
    getMcpAdminStatus: vi.fn(),
    listMcpAdminClients: vi.fn(),
    listMcpAdminSessions: vi.fn(),
    listMcpAdminInvocations: vi.fn(),
    updateMcpAdminStatus: vi.fn(),
    revokeMcpAdminClient: vi.fn(),
    disableMcpAdminClient: vi.fn(),
    enableMcpAdminClient: vi.fn(),
    deleteMcpAdminClient: vi.fn(),
    revokeMcpAdminSession: vi.fn(),
}));

vi.mock('../services/api', () => apiMocks);
vi.mock('../components/NetworkCanvas', () => ({ default: () => <div data-testid="network-canvas" /> }));

describe('McpManagement', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        apiMocks.getMcpAdminStatus.mockResolvedValue({
            enabled: true,
            mcp_url: 'http://127.0.0.1:8085/mcp',
            public_url: 'http://127.0.0.1:8085',
            transport: 'streamable-http-stateless-json',
            session_count: 1,
        });
        apiMocks.listMcpAdminClients.mockResolvedValue([
            { client_id: 'cursor', redirect_uris: ['http://127.0.0.1:8787/callback'], builtin: true, blocked: false, session_count: 1 },
        ]);
        apiMocks.listMcpAdminSessions.mockResolvedValue([]);
        apiMocks.listMcpAdminInvocations.mockResolvedValue({
            total: 1,
            items: [{
                id: 'inv-1',
                user_id: 'u1',
                role: 'operator',
                client_id: 'cursor',
                tool_name: 'argus_scan_create',
                action: '',
                args: { plan_hash: 'sealed-plan' },
                duration_ms: 12,
                status: 'ok',
                created_at: '2026-08-31T00:00:00Z',
            }],
        });
    });

    it('renders connect guide and client list', async () => {
        render(
            <MemoryRouter>
                <App>
                    <McpManagement />
                </App>
            </MemoryRouter>,
        );

        await waitFor(() => expect(apiMocks.getMcpAdminStatus).toHaveBeenCalled());
        expect(screen.getByText('MCP 管理')).toBeInTheDocument();
        expect(screen.getByText('http://127.0.0.1:8085/mcp')).toBeInTheDocument();
        expect(screen.getByText('cursor')).toBeInTheDocument();
        expect(screen.getByText('复制 mcp.json 示例')).toBeInTheDocument();
        expect(screen.getByText('接入治理')).toBeInTheDocument();
        expect(screen.getByText('调用审计')).toBeInTheDocument();
    });

    it('loads high-risk invocation audit rows', async () => {
        const { userEvent } = await import('@testing-library/user-event');
        const user = userEvent.setup();
        render(
            <MemoryRouter>
                <App>
                    <McpManagement />
                </App>
            </MemoryRouter>,
        );

        await waitFor(() => expect(apiMocks.listMcpAdminInvocations).toHaveBeenCalled());
        await user.click(screen.getByText('调用审计'));
        expect(await screen.findByText('argus_scan_create')).toBeInTheDocument();
    });
});
