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
    listMcpAdminEvents: vi.fn(),
    listMcpAdminTools: vi.fn(),
    updateMcpAdminStatus: vi.fn(),
    revokeMcpAdminClient: vi.fn(),
    disableMcpAdminClient: vi.fn(),
    enableMcpAdminClient: vi.fn(),
    deleteMcpAdminClient: vi.fn(),
    revokeMcpAdminSession: vi.fn(),
    revokeMcpAdminUserSessions: vi.fn(),
}));

vi.mock('../services/mcpAdmin', () => apiMocks);
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
        apiMocks.listMcpAdminSessions.mockResolvedValue([
            { session_id: 'sess-1', user_id: 'u1', client_id: 'cursor', created_at: '2026-08-31T00:00:00Z', expires_at: '2026-09-01T00:00:00Z' },
        ]);
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
        apiMocks.listMcpAdminEvents.mockResolvedValue({
            total: 1,
            items: [{
                id: 'evt-1',
                actor_id: '9',
                action: 'disable',
                client_id: '',
                details: { revoked_sessions: 1 },
                created_at: '2026-08-31T00:00:00Z',
            }],
        });
        apiMocks.listMcpAdminTools.mockResolvedValue([
            {
                name: 'argus_scan_create',
                title: '创建扫描',
                description: 'Create one authorized scan',
                category: 'scan',
                auditable: true,
                example_call: {
                    jsonrpc: '2.0',
                    id: 1,
                    method: 'tools/call',
                    params: { name: 'argus_scan_create', arguments: { plan_hash: '<plan_hash>' } },
                },
            },
            {
                name: 'argus_help',
                title: '入门手册',
                description: 'Playbook, resource catalog, required fields and lifecycle intents for a source-less client.',
                category: 'read',
                auditable: false,
                example_call: {
                    jsonrpc: '2.0',
                    id: 1,
                    method: 'tools/call',
                    params: { name: 'argus_help', arguments: {} },
                },
            },
        ]);
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
        expect(screen.getByText('通用 Streamable HTTP 接入')).toBeInTheDocument();
        expect(screen.getByRole('tab', { name: /接入治理/ })).toBeInTheDocument();
        expect(screen.getByRole('tab', { name: /会话/ })).toBeInTheDocument();
        expect(screen.getByRole('tab', { name: /调用审计/ })).toBeInTheDocument();
        expect(screen.getByRole('tab', { name: /治理事件/ })).toBeInTheDocument();
        expect(screen.getByRole('tab', { name: /工具目录/ })).toBeInTheDocument();
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

    it('opens sessions tab from the client row', async () => {
        const { userEvent } = await import('@testing-library/user-event');
        const user = userEvent.setup();
        render(
            <MemoryRouter>
                <App>
                    <McpManagement />
                </App>
            </MemoryRouter>,
        );

        await waitFor(() => expect(apiMocks.listMcpAdminSessions).toHaveBeenCalled());
        await user.click(screen.getByRole('button', { name: '会话' }));
        expect(await screen.findByText('撤销该用户')).toBeInTheDocument();
        expect(screen.getByText('u1')).toBeInTheDocument();
    });

    it('loads governance events and the read-only tool catalog', async () => {
        const { userEvent } = await import('@testing-library/user-event');
        const user = userEvent.setup();
        render(
            <MemoryRouter>
                <App>
                    <McpManagement />
                </App>
            </MemoryRouter>,
        );

        await waitFor(() => expect(apiMocks.listMcpAdminEvents).toHaveBeenCalled());
        await waitFor(() => expect(apiMocks.listMcpAdminTools).toHaveBeenCalled());
        await user.click(screen.getByText('治理事件'));
        expect(await screen.findByText('disable')).toBeInTheDocument();
        await user.click(screen.getByText('工具目录'));
        expect(await screen.findByText('argus_help')).toBeInTheDocument();
        expect(screen.getByText(/只读投影当前 MCP 工具定义/)).toBeInTheDocument();
        expect(screen.getByText('入门手册')).toBeInTheDocument();
        await user.click(screen.getAllByRole('button', { name: /详情/ })[0]);
        expect(await screen.findByText('调用示例')).toBeInTheDocument();
        expect(screen.getByText(/Create one authorized scan/)).toBeInTheDocument();
        expect(screen.getByText(/"method": "tools\/call"/)).toBeInTheDocument();
    });
});
