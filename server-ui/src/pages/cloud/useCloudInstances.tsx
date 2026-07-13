import { Alert, Descriptions, Form, message, Modal, Tag, Typography } from 'antd';
import { useCallback, useMemo, useRef, useState } from 'react';
import {
    cleanupCloudInstances,
    createCloudInstance,
    deleteCloudInstance,
    listAvailableInstanceTypes,
    listCloudInstances,
    listCloudRegions,
    queryCloudPrice,
    rebootCloudInstance,
} from '../../services/api';
import { extractErrorMsg } from './utils';

const { Text } = Typography;

interface InstanceType {
    id: string;
    cpu: number;
    memory_gb: number;
    family: string;
    status: string;
}

interface UseCloudInstancesOptions {
    accounts: API.CloudAccount[];
    policies: API.CloudScalingPolicy[];
    onAccountsRefresh: () => Promise<unknown> | void;
    onDashboardRefresh: () => Promise<unknown> | void;
}

export const useCloudInstances = ({ accounts, policies, onAccountsRefresh, onDashboardRefresh }: UseCloudInstancesOptions) => {
    const [instances, setInstances] = useState<API.CloudInstance[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [modalOpen, setModalOpen] = useState(false);
    const [form] = Form.useForm();
    const [priceData, setPriceData] = useState<any>(null);
    const [priceLoading, setPriceLoading] = useState(false);
    const priceSequence = useRef(0);
    const [availableTypes, setAvailableTypes] = useState<InstanceType[]>([]);
    const [typesLoading, setTypesLoading] = useState(false);
    const [selectedInstanceType, setSelectedInstanceType] = useState('');
    const [region, setRegion] = useState('');
    const [regions, setRegions] = useState<{ region_id: string; local_name: string; endpoint: string }[]>([]);
    const [regionsLoading, setRegionsLoading] = useState(false);
    const cleanupCandidateCount = useMemo(
        () => instances.filter(instance => ['Terminated', 'Error'].includes(instance.status)).length,
        [instances],
    );

    const fetchInstances = useCallback(async () => {
        setError(null);
        try {
            const result = await listCloudInstances();
            setInstances(result || []);
            return result || [];
        } catch (err) {
            setError(extractErrorMsg(err) || 'Failed to fetch instances');
            console.error('Failed to fetch instances:', err);
            return [];
        }
    }, []);

    const refreshModalData = useCallback((accountId: string, targetRegion: string) => {
        const sequence = ++priceSequence.current;
        setPriceData(null);
        setPriceLoading(true);
        setTypesLoading(true);
        setAvailableTypes([]);
        setSelectedInstanceType('');
        listAvailableInstanceTypes(accountId, { region: targetRegion }).then(result => {
            if (sequence !== priceSequence.current) return;
            if (!result?.instance_types) {
                setPriceLoading(false);
                return;
            }
            setAvailableTypes(result.instance_types);
            const account = accounts.find(item => item.id === accountId);
            const defaultType = account?.default_instance_type || '';
            const selected = result.instance_types.some(type => type.id === defaultType)
                ? defaultType
                : result.instance_types[0]?.id || '';
            setSelectedInstanceType(selected);
            if (!selected) {
                setPriceLoading(false);
                return;
            }
            queryCloudPrice(accountId, { region: targetRegion, instance_type: selected })
                .then(price => {
                    if (sequence === priceSequence.current && price?.status !== 'error') setPriceData(price);
                })
                .catch(() => {
                    if (sequence === priceSequence.current) setPriceData(null);
                })
                .finally(() => {
                    if (sequence === priceSequence.current) setPriceLoading(false);
                });
        }).catch(() => {
            if (sequence === priceSequence.current) setPriceLoading(false);
        }).finally(() => {
            if (sequence === priceSequence.current) setTypesLoading(false);
        });
    }, [accounts]);

    const openModal = useCallback(async () => {
        form.resetFields();
        if (accounts.length === 0) await onAccountsRefresh();
        setModalOpen(true);
    }, [accounts.length, form, onAccountsRefresh]);

    const changeAccount = useCallback((accountId?: string) => {
        if (!accountId) {
            setPriceData(null);
            setAvailableTypes([]);
            setSelectedInstanceType('');
            setRegion('');
            setRegions([]);
            return;
        }
        const account = accounts.find(item => item.id === accountId);
        const defaultRegion = account?.region || '';
        setRegion(defaultRegion);
        setRegionsLoading(true);
        listCloudRegions(accountId)
            .then(result => setRegions(result?.regions || []))
            .catch(() => undefined)
            .finally(() => setRegionsLoading(false));
        if (defaultRegion) refreshModalData(accountId, defaultRegion);
    }, [accounts, refreshModalData]);

    const changeRegion = useCallback((targetRegion: string) => {
        setRegion(targetRegion);
        const accountId = form.getFieldValue('account_id');
        if (accountId && targetRegion) refreshModalData(accountId, targetRegion);
    }, [form, refreshModalData]);

    const changeInstanceType = useCallback((instanceType: string) => {
        setSelectedInstanceType(instanceType);
        const accountId = form.getFieldValue('account_id');
        if (!accountId || !instanceType) return;
        setPriceLoading(true);
        const sequence = ++priceSequence.current;
        queryCloudPrice(accountId, { instance_type: instanceType, region })
            .then(result => {
                if (sequence === priceSequence.current && result?.status !== 'error') setPriceData(result);
            })
            .catch(() => undefined)
            .finally(() => {
                if (sequence === priceSequence.current) setPriceLoading(false);
            });
    }, [form, region]);

    const create = useCallback(async () => {
        try {
            const values = await form.validateFields();
            const account = accounts.find(item => item.id === values.account_id);
            if (selectedInstanceType) values.instance_type = selectedInstanceType;
            if (region) values.region = region;
            const previousCount = instances.length;
            await createCloudInstance(values);
            setModalOpen(false);
            let pollCount = 0;
            const pollTimer = window.setInterval(async () => {
                pollCount += 1;
                try {
                    const result = await listCloudInstances();
                    setInstances(result || []);
                    if ((result?.length || 0) > previousCount || pollCount >= 15) {
                        window.clearInterval(pollTimer);
                        onDashboardRefresh();
                    }
                } catch {
                    if (pollCount >= 15) window.clearInterval(pollTimer);
                }
            }, 2000);
            fetchInstances();
            onDashboardRefresh();
            Modal.success({
                title: '实例创建请求已提交',
                width: 480,
                content: (
                    <div style={{ marginTop: 12 }}>
                        <Descriptions bordered size="small" column={1} labelStyle={{ width: 100, fontWeight: 500, background: '#f8fafc' }} contentStyle={{ fontSize: 13 }}>
                            <Descriptions.Item label="云凭证"><Tag color="blue">{account?.name || values.account_id}</Tag></Descriptions.Item>
                            <Descriptions.Item label="创建数量"><Text strong style={{ color: '#0ea5e9' }}>{values.count || 1} 台</Text></Descriptions.Item>
                            <Descriptions.Item label="实例规格"><Text style={{ fontFamily: 'monospace', fontSize: 12 }}>{account?.default_instance_type || '默认'}</Text></Descriptions.Item>
                            <Descriptions.Item label="地域"><Text style={{ fontFamily: 'monospace', fontSize: 12 }}>{account?.region || '默认'}</Text></Descriptions.Item>
                        </Descriptions>
                        <Alert message="实例正在后台异步创建中，列表将自动刷新显示最新状态。" type="info" showIcon style={{ marginTop: 12, fontSize: 12 }} />
                    </div>
                ),
            });
        } catch (err) {
            const messageText = extractErrorMsg(err);
            if (messageText) Modal.error({ title: '实例创建失败', content: messageText });
        }
    }, [accounts, fetchInstances, form, instances.length, onDashboardRefresh, region, selectedInstanceType]);

    const remove = useCallback(async (id: string) => {
        try {
            await deleteCloudInstance(id);
            message.success('销毁指令已下发');
            fetchInstances();
            onDashboardRefresh();
        } catch (err) {
            const messageText = extractErrorMsg(err);
            if (messageText) message.error(messageText);
        }
    }, [fetchInstances, onDashboardRefresh]);

    const reboot = useCallback(async (id: string) => {
        try {
            await rebootCloudInstance(id);
            message.success('重启指令已下发');
            fetchInstances();
        } catch (err) {
            message.error(`重启失败: ${err}`);
        }
    }, [fetchInstances]);

    const cleanup = useCallback(async () => {
        try {
            const result = await cleanupCloudInstances({ confirm: true, reason: 'manual cleanup from cloud management' });
            message.success(`已清理 ${result.count} 个实例记录`);
            fetchInstances();
            onDashboardRefresh();
        } catch (err) {
            const messageText = extractErrorMsg(err);
            if (messageText) message.error(messageText);
        }
    }, [fetchInstances, onDashboardRefresh]);

    return {
        instances,
        loading,
        setLoading,
        error,
        modalOpen,
        setModalOpen,
        form,
        priceData,
        priceLoading,
        availableTypes,
        typesLoading,
        selectedInstanceType,
        region,
        regions,
        regionsLoading,
        cleanupCandidateCount,
        fetchInstances,
        openModal,
        changeAccount,
        changeRegion,
        changeInstanceType,
        create,
        remove,
        reboot,
        cleanup,
        policies,
    };
};
