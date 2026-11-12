import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { App } from 'antd';
import { MemoryRouter } from 'react-router-dom';
import AgentLogs from './AgentLogs';

const apiMocks = vi.hoisted(() => ({
    archiveAgentLogs: vi.fn(),
    connectWebSocket: vi.fn(),
    createAgentLogAlertRule: vi.fn(),
    deleteAgentLogAlertRule: vi.fn(),
    getAgentLogRetention: vi.fn(),
    getAgentLogSummary: vi.fn(),
    getAgentLogs: vi.fn(),
    getNodes: vi.fn(),
    listAgentLogAlertRules: vi.fn(),
    listAgentLogAlerts: vi.fn(),
    updateAgentLogRetention: vi.fn(),
}));

vi.mock('../services/api', () => apiMocks);

describe('AgentLogs', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        localStorage.clear();
        apiMocks.connectWebSocket.mockReturnValue({ close: vi.fn() });
        apiMocks.getNodes.mockResolvedValue([{ AgentID: 'agent-1', Status: 'Alive' }]);
        apiMocks.getAgentLogs.mockResolvedValue(null);
        apiMocks.getAgentLogSummary.mockResolvedValue({
            level_counts: null,
            recent_errors: null,
            retention_days: 14,
        });
        apiMocks.getAgentLogRetention.mockResolvedValue({ retention_days: 14 });
        apiMocks.listAgentLogAlertRules.mockResolvedValue(null);
        apiMocks.listAgentLogAlerts.mockResolvedValue(null);
        apiMocks.archiveAgentLogs.mockResolvedValue({});
        apiMocks.updateAgentLogRetention.mockResolvedValue({ retention_days: 14, deleted: 0 });
        apiMocks.createAgentLogAlertRule.mockResolvedValue({});
        apiMocks.deleteAgentLogAlertRule.mockResolvedValue({});
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    it('renders when log APIs return null arrays', async () => {
        render(
            <MemoryRouter>
                <App>
                    <AgentLogs />
                </App>
            </MemoryRouter>,
        );

        await waitFor(() => expect(apiMocks.getAgentLogSummary).toHaveBeenCalled());
        expect(screen.getByText('Agent 日志')).toBeInTheDocument();
    });

    it('prefers agent_id from URL over cached filters', async () => {
        localStorage.setItem('argus_agent_log_filters', JSON.stringify({
            agent_id: 'agent-old',
            limit: 100,
        }));
        apiMocks.getNodes.mockResolvedValue([
            { AgentID: 'agent-old', Status: 'Alive' },
            { AgentID: 'agent-new', Status: 'Alive' },
        ]);
        apiMocks.getAgentLogs.mockResolvedValue([
            { ID: 1, AgentID: 'agent-new', Level: 'INFO', Message: 'fresh log', Timestamp: Date.now() },
        ]);

        render(
            <MemoryRouter initialEntries={['/agent-logs?agent_id=agent-new']}>
                <App>
                    <AgentLogs />
                </App>
            </MemoryRouter>,
        );

        await waitFor(() => expect(apiMocks.getAgentLogs).toHaveBeenCalledWith(
            'agent-new',
            expect.objectContaining({ limit: 100 }),
        ));
        expect(await screen.findByText('fresh log')).toBeInTheDocument();
    });

    it('shows historical logs when the selected agent is no longer in nodes', async () => {
        apiMocks.getNodes.mockResolvedValue([]);
        apiMocks.getAgentLogSummary.mockResolvedValue({
            agents: ['agent-history'],
            level_counts: [{ level: 'INFO', count: 1 }],
            recent_errors: [],
            retention_days: 14,
        });
        apiMocks.getAgentLogs.mockResolvedValue([
            { ID: 1, AgentID: 'agent-history', Level: 'INFO', Message: 'historical log without node', Timestamp: Date.now() },
        ]);

        render(
            <MemoryRouter initialEntries={['/agent-logs?agent_id=agent-history']}>
                <App>
                    <AgentLogs />
                </App>
            </MemoryRouter>,
        );

        await waitFor(() => expect(apiMocks.getAgentLogs).toHaveBeenCalledWith(
            'agent-history',
            expect.objectContaining({ limit: 100 }),
        ));
        expect(await screen.findByText('historical log without node')).toBeInTheDocument();
        expect(screen.queryByText('暂无 Agent 节点')).not.toBeInTheDocument();
    });

    it('uses a fresh rolling range instead of stale cached timestamps', async () => {
        const now = new Date('2026-07-06T04:46:00.000Z');
        vi.useFakeTimers();
        vi.setSystemTime(now);
        localStorage.setItem('argus_agent_log_filters', JSON.stringify({
            agent_id: 'agent-new',
            limit: 100,
            since: now.getTime() - 12 * 60 * 60 * 1000,
            until: now.getTime() - 10 * 60 * 1000,
        }));
        apiMocks.getNodes.mockResolvedValue([{ AgentID: 'agent-new', Status: 'Alive' }]);
        apiMocks.getAgentLogs.mockResolvedValue([
            { ID: 1, AgentID: 'agent-new', Level: 'INFO', Message: 'fresh runtime log', Timestamp: now.getTime() },
        ]);

        render(
            <MemoryRouter>
                <App>
                    <AgentLogs />
                </App>
            </MemoryRouter>,
        );
        vi.useRealTimers();

        await waitFor(() => expect(apiMocks.getAgentLogs).toHaveBeenCalledWith(
            'agent-new',
            expect.objectContaining({
                since: now.getTime() - 6 * 60 * 60 * 1000,
                until: now.getTime(),
            }),
        ));
        expect(await screen.findByText('fresh runtime log')).toBeInTheDocument();
    });
});
