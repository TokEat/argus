import { describe, expect, it, vi, beforeEach } from 'vitest';
import type React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import { App } from 'antd';
import { MemoryRouter } from 'react-router-dom';
import Login from '../pages/Login';
import Dashboard from '../pages/Dashboard';
import ClientBuild from '../pages/ClientBuild';
import AgentLogs from '../pages/AgentLogs';

vi.mock('echarts-for-react', () => ({
    default: () => <div data-testid="echarts" />,
}));

vi.mock('../components/NetworkCanvas', () => ({
    default: () => <div data-testid="network-canvas" />,
}));

vi.mock('../components/DispatchCanvas', () => ({
    default: () => <div data-testid="dispatch-canvas" />,
}));

vi.mock('../contexts/GlobalAIContext', () => ({
    useAutoContext: vi.fn(),
}));

vi.mock('../services/api', () => ({
    getDashboardStats: vi.fn().mockResolvedValue({
        nodes: 1,
        tasks: 2,
        assets: 3,
        fingerprints: 4,
        vulns: 5,
    }),
    listTasks: vi.fn().mockResolvedValue([]),
    getNodes: vi.fn().mockResolvedValue([
        {
            AgentID: 'agent-1',
            Status: 'Alive',
            Tags: '{"target_type":"all"}',
            Capacity: 2,
            RunningTasks: 0,
        },
    ]),
    getQueueDepth: vi.fn().mockResolvedValue({ depth: {}, pending: {}, mode: 'memory' }),
    getVulnTrends: vi.fn().mockResolvedValue([]),
    getSeverityDistribution: vi.fn().mockResolvedValue([]),
    getTaskResultStats: vi.fn().mockResolvedValue([]),
    getRecentHighVulns: vi.fn().mockResolvedValue([]),
    connectWebSocket: vi.fn((_onMessage, onStatus) => {
        onStatus?.(true);
        return { close: vi.fn() };
    }),
    listBuildArtifacts: vi.fn().mockResolvedValue([]),
    listBuildJobs: vi.fn().mockResolvedValue([]),
    triggerBuild: vi.fn().mockResolvedValue({ message: 'queued' }),
    getBuildJobLogs: vi.fn().mockResolvedValue(''),
    cancelBuildJob: vi.fn().mockResolvedValue({ status: 'canceled' }),
    retryBuildJob: vi.fn().mockResolvedValue({ status: 'queued' }),
    getAgentLogs: vi.fn().mockResolvedValue([]),
    getAgentLogSummary: vi.fn().mockResolvedValue({ level_counts: [], recent_errors: [], retention_days: 14 }),
    getAgentLogRetention: vi.fn().mockResolvedValue({ retention_days: 14 }),
    updateAgentLogRetention: vi.fn().mockResolvedValue({ retention_days: 14, deleted: 0 }),
    listAgentLogAlertRules: vi.fn().mockResolvedValue([]),
    listAgentLogAlerts: vi.fn().mockResolvedValue([]),
    createAgentLogAlertRule: vi.fn().mockResolvedValue({}),
    deleteAgentLogAlertRule: vi.fn().mockResolvedValue({}),
    archiveAgentLogs: vi.fn().mockResolvedValue({}),
}));

const renderPage = (page: React.ReactElement) => render(
    <MemoryRouter>
        <App>{page}</App>
    </MemoryRouter>
);

describe('server-ui smoke', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        localStorage.setItem('token', 'smoke-token');
        localStorage.setItem('role', 'admin');
        localStorage.setItem('active_project_id', 'project-1');
    });

    it('renders the login entrypoint', () => {
        renderPage(<Login />);

        expect(screen.getByPlaceholderText('租户 ID')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /登\s*录/i })).toBeInTheDocument();
    });

    it('renders the main operational pages with mocked APIs', async () => {
        renderPage(<Dashboard />);
        await waitFor(() => expect(screen.getByText('首页概览')).toBeInTheDocument());

        renderPage(<ClientBuild />);
        await waitFor(() => expect(screen.getByText('客户端生成')).toBeInTheDocument());

        renderPage(<AgentLogs />);
        await waitFor(() => expect(screen.getByText('Agent 日志')).toBeInTheDocument());
    });
});
