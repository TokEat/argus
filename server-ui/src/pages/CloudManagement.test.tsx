import { App, message } from 'antd';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import CloudManagement from './CloudManagement';

const apiMocks = vi.hoisted(() => ({
    listCloudInstances: vi.fn(),
    createCloudInstance: vi.fn(),
    deleteCloudInstance: vi.fn(),
    rebootCloudInstance: vi.fn(),
    cleanupCloudInstances: vi.fn(),
    listCloudAccounts: vi.fn(),
    createCloudAccount: vi.fn(),
    deleteCloudAccount: vi.fn(),
    testCloudAccount: vi.fn(),
    testOSSConnection: vi.fn(),
    listCloudPolicies: vi.fn(),
    createCloudPolicy: vi.fn(),
    updateCloudPolicy: vi.fn(),
    deleteCloudPolicy: vi.fn(),
    toggleCloudPolicy: vi.fn(),
    getCloudDashboard: vi.fn(),
    discoverCloudResources: vi.fn(),
    listCloudRecommendations: vi.fn(),
    autoConfigureCloudAccount: vi.fn(),
    oneClickSetup: vi.fn(),
    checkCloudPermissions: vi.fn(),
    queryCloudPrice: vi.fn(),
    listAvailableInstanceTypes: vi.fn(),
    listCloudRegions: vi.fn(),
    updateCloudAccountRegion: vi.fn(),
    listReleaseFiles: vi.fn(),
    uploadServerAgent: vi.fn(),
    uploadLocalAgent: vi.fn(),
    listOSSFiles: vi.fn(),
    deleteOSSFile: vi.fn(),
    listUsers: vi.fn(),
    getCloudAccountBindings: vi.fn(),
    updateCloudAccountBindings: vi.fn(),
}));

const authMocks = vi.hoisted(() => ({
    role: 'admin',
}));

vi.mock('../services/api', () => apiMocks);

vi.mock('../contexts/GlobalAIContext', () => ({
    useAutoContext: vi.fn(),
}));

vi.mock('../utils/auth', () => ({
    getCurrentUserRole: () => authMocks.role,
    canAccessRole: (required: string, current: string) => current === 'admin' || required === current,
}));

vi.mock('../components/NetworkCanvas', () => ({
    default: () => <div data-testid="network-canvas" />,
}));

vi.mock('@monaco-editor/react', () => ({
    default: () => <div data-testid="cloud-init-editor" />,
}));

const account = (overrides: Partial<API.CloudAccount> = {}): API.CloudAccount => ({
    id: 'account-1',
    tenant_id: 'tenant-1',
    name: 'Aliyun production',
    provider: 'aliyun',
    access_level: 'owner',
    status: 'active',
    region: 'cn-hangzhou',
    default_image_id: 'aliyun_3_x64_20G_alibase_20240528.vhd',
    default_instance_type: 'ecs.c7.large',
    default_security_group: 'sg-1',
    default_v_switch: 'vsw-1',
    oss_bucket: 'argus-agent',
    oss_endpoint: 'oss-cn-hangzhou.aliyuncs.com',
    created_at: '2026-07-13T00:00:00Z',
    updated_at: '2026-07-13T00:00:00Z',
    ...overrides,
});

const instance = (): API.CloudInstance => ({
    id: 'instance-1',
    tenant_id: 'tenant-1',
    cloud_account_id: 'account-1',
    policy_id: 'policy-1',
    provider_instance_id: 'i-test',
    agent_id: 'agent-1',
    ip: '192.0.2.10',
    region: 'cn-hangzhou',
    status: 'Running',
    spot: true,
    reboot_count: 0,
    created_at: '2026-07-13T00:00:00Z',
    updated_at: '2026-07-13T00:00:00Z',
});

const policy = (): API.CloudScalingPolicy => ({
    id: 'policy-1',
    tenant_id: 'tenant-1',
    cloud_account_id: 'account-1',
    name: 'Default policy',
    enabled: true,
    min_instances: 0,
    max_instances: 5,
    scale_up_threshold: 50,
    scale_down_threshold: 0,
    cooldown_seconds: 180,
    instance_ttl_minutes: 60,
    spot_strategy: 'SpotAsPriceGo',
    max_spot_price: 0,
    spot_duration_hours: 1,
    user_data_template: '',
    created_at: '2026-07-13T00:00:00Z',
    updated_at: '2026-07-13T00:00:00Z',
});

const renderPage = () => render(
    <App>
        <CloudManagement />
    </App>,
);

describe('CloudManagement', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        authMocks.role = 'admin';
        apiMocks.getCloudDashboard.mockResolvedValue({
            active_accounts: 1,
            enabled_policies: 1,
            running_instances: 1,
            total_instances: 1,
            recent_events: [],
        });
        apiMocks.listCloudInstances.mockResolvedValue([instance()]);
        apiMocks.listCloudAccounts.mockResolvedValue([account()]);
        apiMocks.listCloudPolicies.mockResolvedValue([policy()]);
        apiMocks.listUsers.mockResolvedValue([]);
        apiMocks.listCloudRegions.mockResolvedValue({ regions: [] });
        apiMocks.listCloudRecommendations.mockResolvedValue({ recommendations: [] });
        apiMocks.listAvailableInstanceTypes.mockResolvedValue({ instance_types: [] });
        apiMocks.queryCloudPrice.mockResolvedValue({ status: 'ok' });
        apiMocks.listReleaseFiles.mockResolvedValue({ files: [] });
        apiMocks.listOSSFiles.mockResolvedValue({ files: [] });
        apiMocks.toggleCloudPolicy.mockResolvedValue({ status: 'ok' });
        apiMocks.deleteCloudInstance.mockResolvedValue({ status: 'ok' });
    });

    it('loads each tab through its existing server request boundary', async () => {
        const user = userEvent.setup();
        renderPage();

        await waitFor(() => expect(apiMocks.listCloudInstances).toHaveBeenCalled());
        await user.click(screen.getByRole('tab', { name: /AutoScaler 策略/ }));
        await waitFor(() => expect(apiMocks.listCloudPolicies).toHaveBeenCalled());
        await user.click(screen.getByRole('tab', { name: /API 凭证管理/ }));
        await waitFor(() => expect(apiMocks.listCloudAccounts).toHaveBeenCalled());
        await user.click(screen.getByRole('tab', { name: /Agent 分发/ }));
        expect(await screen.findByText('Agent 二进制分发管理')).toBeInTheDocument();
    });

    it('disables account configuration for a bound user while keeping permission checks available', async () => {
        authMocks.role = 'operator';
        apiMocks.listCloudAccounts.mockResolvedValue([account({ access_level: 'bound' })]);
        const user = userEvent.setup();
        renderPage();

        await user.click(screen.getByRole('tab', { name: /API 凭证管理/ }));
        const configureButton = await screen.findByRole('button', { name: /一键配置/ });
        expect(configureButton).toBeDisabled();
        expect(screen.getByRole('button', { name: /权限检查/ })).toBeEnabled();
        expect(screen.queryByRole('button', { name: '绑定用户' })).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: '删除' })).not.toBeInTheDocument();
    });

    it('keeps policy toggle wired to the selected policy', async () => {
        const user = userEvent.setup();
        renderPage();

        await user.click(screen.getByRole('tab', { name: /AutoScaler 策略/ }));
        const toggle = await screen.findByRole('switch');
        await user.click(toggle);

        await waitFor(() => expect(apiMocks.toggleCloudPolicy).toHaveBeenCalledWith('policy-1'));
    });

    it('requires confirmation before destroying a running instance', async () => {
        const user = userEvent.setup();
        renderPage();

        await user.click(await screen.findByRole('button', { name: /销毁/ }));
        const confirmation = await screen.findByRole('tooltip');
        await user.click(within(confirmation).getByRole('button', { name: 'OK' }));

        await waitFor(() => expect(apiMocks.deleteCloudInstance).toHaveBeenCalledWith('instance-1'));
    });

    it('opens the Agent upload entry for a configured OSS account', async () => {
        const user = userEvent.setup();
        renderPage();

        await user.click(screen.getByRole('tab', { name: /Agent 分发/ }));
        await user.click(await screen.findByRole('button', { name: /上传 Agent/ }));

        expect(await screen.findByText('上传 Agent 到 OSS')).toBeInTheDocument();
        await waitFor(() => expect(apiMocks.listReleaseFiles).toHaveBeenCalledWith('account-1'));
    });

    it('shows the API error when credential connectivity testing fails', async () => {
        apiMocks.testCloudAccount.mockResolvedValue({ status: 'error', message: 'provider unavailable' });
        const errorSpy = vi.spyOn(message, 'error').mockImplementation(() => undefined as never);
        const user = userEvent.setup();
        renderPage();

        await user.click(screen.getByRole('tab', { name: /API 凭证管理/ }));
        await user.click(await screen.findByRole('button', { name: /连通性/ }));

        await waitFor(() => expect(errorSpy).toHaveBeenCalledWith('连通性测试失败: provider unavailable'));
    });
});
