import { App, ConfigProvider, message } from 'antd';
import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import CloudManagement from './CloudManagement';
import { APIRequestError } from '../services/request';

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
    <ConfigProvider theme={{ token: { motion: false } }}><App>
        <CloudManagement />
    </App></ConfigProvider>,
);

const blockedDeletion = (overrides: Partial<API.CloudAccountPolicyConflict> = {}) => new APIRequestError('still referenced', {
    code: 'cloud_account_has_policies',
    cloud_account_id: 'account-1',
    policy_count: 2,
    policies: [
        { id: 'enabled-policy', name: 'Enabled dependency', enabled: true },
        { id: 'disabled-policy', name: 'Disabled dependency', enabled: false },
    ],
    policies_truncated: false,
    ...overrides,
});

const confirmCredentialDeletion = async (user: ReturnType<typeof userEvent.setup>) => {
    await user.click(screen.getByRole('tab', { name: /API 凭证管理/ }));
    await user.click(await screen.findByRole('button', { name: '删除' }));
    const confirmation = await screen.findByRole('tooltip');
    await user.click(within(confirmation).getByRole('button', { name: 'OK' }));
};

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
        apiMocks.deleteCloudAccount.mockReset().mockResolvedValue({ status: 'ok' });
        apiMocks.deleteCloudPolicy.mockReset().mockResolvedValue({ status: 'ok' });
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

    it('explains enabled and disabled policy dependencies without mutating them', async () => {
        apiMocks.deleteCloudAccount.mockRejectedValue(blockedDeletion());
        const user = userEvent.setup();
        renderPage();
        await confirmCredentialDeletion(user);
        const dialog = await screen.findByRole('dialog');
        expect(within(dialog).getByText('凭证删除受阻')).toBeInTheDocument();
        expect(within(dialog).getByText(/仍关联 2 条伸缩策略/)).toBeInTheDocument();
        expect(within(dialog).getByText('Enabled dependency')).toBeInTheDocument();
        expect(within(dialog).getByText('Disabled dependency')).toBeInTheDocument();
        expect(within(dialog).getByText('已启用')).toBeInTheDocument();
        expect(within(dialog).getByText('已停用')).toBeInTheDocument();
        expect(within(dialog).getByText(/停用策略不等于解除凭证关联/)).toBeInTheDocument();
        await user.click(within(dialog).getByRole('button', { name: /关\s*闭/ }));
        expect(apiMocks.deleteCloudPolicy).not.toHaveBeenCalled();
        expect(apiMocks.toggleCloudPolicy).not.toHaveBeenCalled();
        expect(apiMocks.deleteCloudInstance).not.toHaveBeenCalled();
        expect(apiMocks.deleteCloudAccount).toHaveBeenCalledTimes(1);
    });

    it('refreshes dependencies and selects the requested policy instead of the first policy', async () => {
        apiMocks.deleteCloudAccount.mockRejectedValue(blockedDeletion());
        const refreshedPolicies = [
            { ...policy(), cloud_account_id: 'another-account', name: 'Unrelated first policy' },
            { ...policy(), id: 'disabled-policy', name: 'Disabled dependency', enabled: false },
        ];
        let finishRefresh!: (policies: API.CloudScalingPolicy[]) => void;
        const pendingRefresh = new Promise<API.CloudScalingPolicy[]>(resolve => { finishRefresh = resolve; });
        apiMocks.listCloudPolicies.mockImplementationOnce(() => pendingRefresh).mockResolvedValue(refreshedPolicies);
        const user = userEvent.setup();
        renderPage();
        await confirmCredentialDeletion(user);
        const dialog = await screen.findByRole('dialog');
        await user.click(within(dialog).getByRole('button', { name: '查看策略 Disabled dependency' }));
        expect(screen.getByRole('tab', { name: /API 凭证管理/ })).toHaveAttribute('aria-selected', 'true');
        expect(within(dialog).getByRole('button', { name: /关\s*闭/ })).toBeDisabled();
        expect(within(dialog).getByRole('button', { name: '查看策略页' })).toBeDisabled();
        expect(within(dialog).getByRole('button', { name: '查看策略 Enabled dependency' })).toBeDisabled();
        await act(async () => { finishRefresh(refreshedPolicies); });

        await waitFor(() => expect(screen.getByRole('tab', { name: /AutoScaler 策略/ })).toHaveAttribute('aria-selected', 'true'));
        await waitFor(() => expect(screen.getByLabelText('策略名称')).toHaveValue('Disabled dependency'));
        expect(screen.getByRole('switch')).not.toBeChecked();
        expect(apiMocks.listCloudPolicies).toHaveBeenCalled();
        expect(apiMocks.updateCloudPolicy).not.toHaveBeenCalled();
        expect(apiMocks.deleteCloudPolicy).not.toHaveBeenCalled();
    });

    it('keeps the dependency dialog usable when refreshing policies fails', async () => {
        apiMocks.deleteCloudAccount.mockRejectedValue(blockedDeletion());
        apiMocks.listCloudPolicies.mockRejectedValue(new Error('service unavailable'));
        const errorSpy = vi.spyOn(message, 'error').mockImplementation(() => undefined as never);
        const warning = vi.spyOn(message, 'warning').mockImplementation(() => undefined as never);
        const user = userEvent.setup();
        renderPage();
        await confirmCredentialDeletion(user);
        const dialog = await screen.findByRole('dialog');
        await user.click(within(dialog).getByRole('button', { name: '查看策略 Disabled dependency' }));
        await waitFor(() => expect(errorSpy).toHaveBeenCalledWith('读取关联策略失败：service unavailable'));
        expect(warning).not.toHaveBeenCalled();
        expect(screen.getByRole('tab', { name: /API 凭证管理/ })).toHaveAttribute('aria-selected', 'true');
        expect(within(dialog).getByRole('button', { name: /关\s*闭/ })).toBeEnabled();
        expect(within(dialog).getByRole('button', { name: '查看策略 Disabled dependency' })).toBeEnabled();
        expect(apiMocks.deleteCloudPolicy).not.toHaveBeenCalled();
        warning.mockRestore();
        errorSpy.mockRestore();
    });

    it.each(['removed', 'rebound'])('does not navigate to a %s dependency', async (change) => {
        apiMocks.deleteCloudAccount.mockRejectedValue(blockedDeletion());
        apiMocks.listCloudPolicies.mockResolvedValue(change === 'removed' ? [] : [
            { ...policy(), id: 'disabled-policy', cloud_account_id: 'another-account' },
        ]);
        const warning = vi.spyOn(message, 'warning').mockImplementation(() => undefined as never);
        const user = userEvent.setup();
        renderPage();
        await confirmCredentialDeletion(user);
        const dialog = await screen.findByRole('dialog');
        await user.click(within(dialog).getByRole('button', { name: '查看策略 Disabled dependency' }));
        await waitFor(() => expect(warning).toHaveBeenCalledWith('关联策略已变更或不可访问，请关闭提示后重新尝试删除。'));
        expect(screen.getByRole('tab', { name: /API 凭证管理/ })).toHaveAttribute('aria-selected', 'true');
        expect(dialog).toBeInTheDocument();
        expect(apiMocks.deleteCloudPolicy).not.toHaveBeenCalled();
        warning.mockRestore();
    });

    it('allows a fresh explicit deletion attempt after dependencies have been handled', async () => {
        apiMocks.deleteCloudAccount.mockRejectedValueOnce(blockedDeletion()).mockResolvedValue({ status: 'ok' });
        const user = userEvent.setup();
        renderPage();
        await confirmCredentialDeletion(user);
        const dialog = await screen.findByRole('dialog');
        await user.click(within(dialog).getByRole('button', { name: /关\s*闭/ }));
        apiMocks.listCloudAccounts.mockResolvedValue([]);
        await confirmCredentialDeletion(user);
        await waitFor(() => expect(apiMocks.deleteCloudAccount).toHaveBeenCalledTimes(2));
        await waitFor(() => expect(screen.queryByText('Aliyun production')).not.toBeInTheDocument());
        expect(apiMocks.deleteCloudPolicy).not.toHaveBeenCalled();
    });

    it.each([
        new APIRequestError('legacy error', { error: 'legacy error' }),
        blockedDeletion({ cloud_account_id: 'another-account' }),
    ])('falls back to the existing message for unrecognized or mismatched errors', async (error) => {
        apiMocks.deleteCloudAccount.mockRejectedValue(error);
        const errorSpy = vi.spyOn(message, 'error').mockImplementation(() => undefined as never);
        const user = userEvent.setup();
        renderPage();
        await confirmCredentialDeletion(user);
        await waitFor(() => expect(errorSpy).toHaveBeenCalledWith(error.message));
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });

    it('labels partial dependency details and provides the policy page entry', async () => {
        apiMocks.deleteCloudAccount.mockRejectedValue(blockedDeletion({ policy_count: 25, policies_truncated: true }));
        const user = userEvent.setup();
        renderPage();
        await confirmCredentialDeletion(user);
        const dialog = await screen.findByRole('dialog');
        expect(within(dialog).getByText(/仍关联 25 条伸缩策略/)).toBeInTheDocument();
        expect(within(dialog).getByText(/当前仅显示前 2 条/)).toBeInTheDocument();
        await user.click(within(dialog).getByRole('button', { name: '查看策略页' }));
        expect(screen.getByRole('tab', { name: /AutoScaler 策略/ })).toHaveAttribute('aria-selected', 'true');
    });
});
