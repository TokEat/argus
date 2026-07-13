import { Form, message } from 'antd';
import { useCallback, useState } from 'react';
import {
    autoConfigureCloudAccount,
    checkCloudPermissions,
    discoverCloudResources,
    listCloudRegions,
    oneClickSetup,
    updateCloudAccountRegion,
} from '../../services/api';
import { extractErrorMsg } from './utils';

interface UseCloudDiscoveryOptions {
    accounts: API.CloudAccount[];
    canManageAccount: (account?: API.CloudAccount | null) => boolean;
    onAccountsRefresh: () => Promise<unknown> | void;
    onPoliciesRefresh: () => Promise<unknown> | void;
    onDashboardRefresh: () => Promise<unknown> | void;
}

export const useCloudDiscovery = ({
    accounts,
    canManageAccount,
    onAccountsRefresh,
    onPoliciesRefresh,
    onDashboardRefresh,
}: UseCloudDiscoveryOptions) => {
    const [modalOpen, setModalOpen] = useState(false);
    const [loading, setLoading] = useState(false);
    const [data, setData] = useState<any>(null);
    const [accountId, setAccountId] = useState('');
    const [saving, setSaving] = useState(false);
    const [form] = Form.useForm();
    const [setupResultOpen, setSetupResultOpen] = useState(false);
    const [setupResult, setSetupResult] = useState<any>(null);
    const [permissionOpen, setPermissionOpen] = useState(false);
    const [permissionLoading, setPermissionLoading] = useState(false);
    const [permissionData, setPermissionData] = useState<any>(null);
    const [permissionError, setPermissionError] = useState<string | null>(null);
    const [regionOpen, setRegionOpen] = useState(false);
    const [regionLoading, setRegionLoading] = useState(false);
    const [regions, setRegions] = useState<API.RegionInfo[]>([]);
    const [regionAccountId, setRegionAccountId] = useState('');
    const [pendingAction, setPendingAction] = useState<'oneclick' | 'discover' | null>(null);

    const discover = useCallback(async (targetAccountId: string) => {
        setAccountId(targetAccountId);
        setLoading(true);
        setModalOpen(true);
        setData(null);
        form.resetFields();
        try {
            setData(await discoverCloudResources(targetAccountId));
        } catch (err) {
            const messageText = extractErrorMsg(err);
            if (messageText) message.error(`资源探测失败: ${messageText}`);
        } finally {
            setLoading(false);
        }
    }, [form]);

    const save = useCallback(async () => {
        try {
            const values = await form.validateFields();
            setSaving(true);
            await autoConfigureCloudAccount(accountId, values);
            message.success('云资源配置已自动保存到凭证');
            setModalOpen(false);
            onAccountsRefresh();
        } catch (err) {
            const messageText = extractErrorMsg(err);
            if (messageText) message.error(messageText);
        } finally {
            setSaving(false);
        }
    }, [accountId, form, onAccountsRefresh]);

    const runOneClick = useCallback(async (targetAccountId: string) => {
        const account = accounts.find(item => item.id === targetAccountId);
        message.loading({ content: `正在为「${account?.name || targetAccountId}」执行一键配置...`, key: 'one-click', duration: 0 });
        try {
            const result = await oneClickSetup(targetAccountId);
            message.destroy('one-click');
            setSetupResult(result);
            setSetupResultOpen(true);
            onAccountsRefresh();
            onPoliciesRefresh();
            onDashboardRefresh();
        } catch (err) {
            message.error({ content: `一键配置失败: ${extractErrorMsg(err)}`, key: 'one-click' });
        }
    }, [accounts, onAccountsRefresh, onDashboardRefresh, onPoliciesRefresh]);

    const ensureRegionThen = useCallback(async (targetAccountId: string, action: 'oneclick' | 'discover') => {
        const account = accounts.find(item => item.id === targetAccountId);
        if (!account) return;
        if (!account.region && !canManageAccount(account)) {
            message.warning('该凭证尚未配置地域，请联系凭证所有者或管理员先完成配置。');
            return;
        }
        if (account.region) {
            if (action === 'oneclick') return runOneClick(targetAccountId);
            return discover(targetAccountId);
        }
        setRegionAccountId(targetAccountId);
        setPendingAction(action);
        setRegionOpen(true);
        setRegionLoading(true);
        setRegions([]);
        try {
            const result = await listCloudRegions(targetAccountId);
            setRegions(result.regions || []);
        } catch (err) {
            message.error(`获取可用地域失败: ${extractErrorMsg(err)}`);
            setRegionOpen(false);
        } finally {
            setRegionLoading(false);
        }
    }, [accounts, canManageAccount, discover, runOneClick]);

    const selectRegion = useCallback(async (regionId: string) => {
        try {
            await updateCloudAccountRegion(regionAccountId, regionId);
            message.success(`已选择地域: ${regionId}`);
            setRegionOpen(false);
            await onAccountsRefresh();
            if (pendingAction === 'oneclick') runOneClick(regionAccountId);
            else if (pendingAction === 'discover') discover(regionAccountId);
        } catch (err) {
            message.error(`保存地域失败: ${extractErrorMsg(err)}`);
        }
    }, [discover, onAccountsRefresh, pendingAction, regionAccountId, runOneClick]);

    const checkPermissions = useCallback(async (targetAccountId: string) => {
        setPermissionOpen(true);
        setPermissionLoading(true);
        setPermissionData(null);
        setPermissionError(null);
        try {
            const result = await checkCloudPermissions(targetAccountId);
            if (result?.status === 'error') setPermissionError(result.message || '权限检查失败');
            else setPermissionData(result?.data || result);
        } catch (err) {
            setPermissionError(extractErrorMsg(err) || '权限检查请求失败');
        } finally {
            setPermissionLoading(false);
        }
    }, []);

    return {
        modalOpen,
        setModalOpen,
        loading,
        data,
        saving,
        form,
        setupResultOpen,
        setSetupResultOpen,
        setupResult,
        permissionOpen,
        setPermissionOpen,
        permissionLoading,
        permissionData,
        permissionError,
        regionOpen,
        setRegionOpen,
        regionLoading,
        regions,
        discover,
        save,
        ensureRegionThen,
        selectRegion,
        checkPermissions,
    };
};
