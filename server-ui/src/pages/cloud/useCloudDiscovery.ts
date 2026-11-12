import { Form, message } from 'antd';
import { useCallback, useRef, useState } from 'react';
import {
    autoConfigureCloudAccount,
    checkCloudPermissions,
    discoverCloudResources,
    listCloudRegions,
    listCloudRecommendations,
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
    const discoveryRequestRef = useRef(0);

    const discover = useCallback(async (targetAccountId: string, regionOverride?: string) => {
        const requestId = ++discoveryRequestRef.current;
        const account = accounts.find(item => item.id === targetAccountId);
        const currentRegion = regionOverride || account?.region || '';
        setAccountId(targetAccountId);
        setLoading(true);
        setModalOpen(true);
        setData(null);
        form.resetFields();
        if (currentRegion) form.setFieldValue('region', currentRegion);
        try {
            const [discovery, recommendations, regionResult] = await Promise.all([
                discoverCloudResources(targetAccountId, currentRegion ? { region: currentRegion } : undefined),
                listCloudRecommendations(targetAccountId, undefined, currentRegion || undefined).catch(() => ({ recommendations: [], cheapest: null, warnings: ['当前地域价格查询失败，已保留资源探测结果'] })),
                listCloudRegions(targetAccountId).catch(() => ({ regions: [] })),
            ]);
            const merged = {
                ...discovery,
                ...recommendations,
                regions: regionResult.regions || [],
                warnings: recommendations.warnings || [],
                region: currentRegion,
            };
            if (requestId !== discoveryRequestRef.current || form.getFieldValue('region') !== currentRegion) return;
            setData(merged);
            const initialRecommendation = merged.cheapest || merged.recommendations?.find((item: any) => item.region === currentRegion);
            form.setFieldsValue({ region: currentRegion });
            if (initialRecommendation && initialRecommendation.region === currentRegion) {
                form.setFieldsValue({
                    default_instance_type: initialRecommendation.instance_type,
                });
            }
        } catch (err) {
            if (requestId !== discoveryRequestRef.current) return;
            const messageText = extractErrorMsg(err);
            if (messageText) message.error(`资源探测失败: ${messageText}`);
        } finally {
            if (requestId === discoveryRequestRef.current) setLoading(false);
        }
    }, [accounts, form]);

    const save = useCallback(async () => {
        try {
            const values = await form.validateFields();
            const requiredFields = ['region', 'default_instance_type', 'default_image_id', 'default_security_group', 'default_v_switch'];
            const missingField = requiredFields.find(field => !values[field]);
            if (missingField) {
                message.warning('当前地域资源尚未探测完成，请等待完成后再保存配置');
                return;
            }
            setSaving(true);
            const selectedRecommendation = data?.recommendations?.find((item: any) => item.region === values.region && item.instance_type === values.default_instance_type);
            await autoConfigureCloudAccount(accountId, selectedRecommendation ? {
                ...values,
                region: selectedRecommendation.region,
                default_instance_type: selectedRecommendation.instance_type,
            } : values);
            message.success('云资源配置已自动保存到凭证');
            setModalOpen(false);
            onAccountsRefresh();
        } catch (err) {
            const messageText = extractErrorMsg(err);
            if (messageText) message.error(messageText);
        } finally {
            setSaving(false);
        }
    }, [accountId, data, form, onAccountsRefresh]);

    const changeRegion = useCallback(async (targetRegion: string) => {
        if (!targetRegion) return;
        const requestId = ++discoveryRequestRef.current;
        form.setFieldValue('region', targetRegion);
        form.setFieldsValue({
            default_instance_type: undefined,
            default_image_id: undefined,
            default_security_group: undefined,
            default_v_switch: undefined,
        });
        setData((previous: any) => ({
            ...previous,
            region: targetRegion,
            images: [],
            security_groups: [],
            v_switches: [],
            instance_types: [],
            recommendations: [],
            cheapest: null,
            warnings: [],
        }));
        setLoading(true);
        try {
            const [discovery, recommendations] = await Promise.all([
                discoverCloudResources(accountId, { region: targetRegion }),
                listCloudRecommendations(accountId, undefined, targetRegion).catch(() => ({ recommendations: [], cheapest: null, warnings: [`当前地域 ${targetRegion} 价格查询失败`] })),
            ]);
            if (requestId !== discoveryRequestRef.current || form.getFieldValue('region') !== targetRegion) return;
            setData((previous: any) => ({ ...previous, ...discovery, ...recommendations, region: targetRegion }));
            if (recommendations.cheapest?.region === targetRegion) {
                form.setFieldValue('default_instance_type', recommendations.cheapest.instance_type);
            }
        } catch (err) {
            if (requestId !== discoveryRequestRef.current || form.getFieldValue('region') !== targetRegion) return;
            message.warning(`地域 ${targetRegion} 的资源探测失败，请不要保存该地域配置: ${extractErrorMsg(err)}`);
        } finally {
            if (requestId === discoveryRequestRef.current) setLoading(false);
        }
    }, [accountId, form]);

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
            else if (pendingAction === 'discover') discover(regionAccountId, regionId);
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
        changeRegion,
        checkPermissions,
    };
};
