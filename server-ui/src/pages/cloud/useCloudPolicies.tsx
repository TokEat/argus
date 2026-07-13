import { Descriptions, Form, message, Modal, Tag, Typography } from 'antd';
import { useCallback, useEffect, useMemo, useState } from 'react';
import {
    createCloudPolicy,
    deleteCloudPolicy,
    listCloudPolicies,
    toggleCloudPolicy,
    updateCloudPolicy,
} from '../../services/api';
import {
    buildDefaultPolicyFormValues,
    buildPolicyFormValues,
    DEFAULT_CLOUD_INIT_TEMPLATE,
    extractErrorMsg,
} from './utils';

const { Text } = Typography;

interface UseCloudPoliciesOptions {
    active: boolean;
    accounts: API.CloudAccount[];
    onDashboardRefresh: () => void;
}

export const useCloudPolicies = ({ active, accounts, onDashboardRefresh }: UseCloudPoliciesOptions) => {
    const [policies, setPolicies] = useState<API.CloudScalingPolicy[]>([]);
    const [currentPolicyId, setCurrentPolicyId] = useState<string | null>(null);
    const [userDataScript, setUserDataScript] = useState(DEFAULT_CLOUD_INIT_TEMPLATE);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [form] = Form.useForm();
    const defaultFormValues = useMemo(() => buildDefaultPolicyFormValues(accounts), [accounts]);

    const valuesFor = useCallback(
        (policy?: API.CloudScalingPolicy | null) => buildPolicyFormValues(defaultFormValues, policy),
        [defaultFormValues],
    );

    const fetchPolicies = useCallback(async () => {
        setLoading(true);
        setError(null);
        try {
            const result = await listCloudPolicies();
            setPolicies(result || []);
            if (result?.length) {
                const keepId = currentPolicyId && result.some(policy => policy.id === currentPolicyId)
                    ? currentPolicyId
                    : result[0].id;
                const selected = result.find(policy => policy.id === keepId) || result[0];
                setCurrentPolicyId(keepId);
                setUserDataScript(selected.user_data_template || DEFAULT_CLOUD_INIT_TEMPLATE);
            } else {
                setCurrentPolicyId(null);
                setUserDataScript(DEFAULT_CLOUD_INIT_TEMPLATE);
            }
            return result || [];
        } catch (err) {
            const messageText = extractErrorMsg(err) || 'Failed to fetch policies';
            setError(messageText);
            console.error('Failed to fetch policies:', err);
            return [];
        } finally {
            setLoading(false);
        }
    }, [currentPolicyId]);

    useEffect(() => {
        if (!active) return;
        const selected = policies.find(policy => policy.id === currentPolicyId) || policies[0] || null;
        const frame = window.requestAnimationFrame(() => form.setFieldsValue(valuesFor(selected)));
        return () => window.cancelAnimationFrame(frame);
    }, [active, currentPolicyId, form, policies, valuesFor]);

    const selectPolicy = useCallback((policyId: string | null) => {
        if (!policyId) {
            setCurrentPolicyId(null);
            form.setFieldsValue(valuesFor(null));
            setUserDataScript(DEFAULT_CLOUD_INIT_TEMPLATE);
            return;
        }
        const selected = policies.find(policy => policy.id === policyId) || null;
        setCurrentPolicyId(policyId);
        form.setFieldsValue(valuesFor(selected));
        setUserDataScript(selected?.user_data_template || DEFAULT_CLOUD_INIT_TEMPLATE);
    }, [form, policies, valuesFor]);

    const submit = useCallback(async () => {
        try {
            const values = await form.validateFields();
            const payload = { ...values, user_data_template: userDataScript };
            const isUpdate = Boolean(currentPolicyId);
            if (currentPolicyId) await updateCloudPolicy(currentPolicyId, payload);
            else await createCloudPolicy(payload);
            await fetchPolicies();
            await onDashboardRefresh();
            const linkedAccount = accounts.find(account => account.id === values.cloud_account_id);
            Modal.success({
                title: `策略${isUpdate ? '更新' : '创建'}成功`,
                width: 520,
                content: (
                    <Descriptions
                        bordered
                        size="small"
                        column={1}
                        style={{ marginTop: 12 }}
                        labelStyle={{ width: 110, fontWeight: 500, background: '#f8fafc' }}
                        contentStyle={{ fontSize: 13 }}
                    >
                        <Descriptions.Item label="策略名称"><Text strong>{values.name}</Text></Descriptions.Item>
                        <Descriptions.Item label="关联凭证"><Tag color="blue">{linkedAccount?.name || values.cloud_account_id}</Tag></Descriptions.Item>
                        <Descriptions.Item label="实例范围">{values.min_instances ?? 0} ~ {values.max_instances ?? 5} 台</Descriptions.Item>
                        <Descriptions.Item label="扩容阈值">队列堆积 &gt; {values.scale_up_threshold ?? 50} 任务时触发</Descriptions.Item>
                        <Descriptions.Item label="缩容阈值">队列堆积 ≤ {values.scale_down_threshold ?? 0} 任务时缩容</Descriptions.Item>
                        <Descriptions.Item label="实例 TTL">{values.instance_ttl_minutes ?? 120} 分钟</Descriptions.Item>
                        <Descriptions.Item label="竞价策略">
                            <Tag color={values.spot_strategy === 'SpotAsPriceGo' ? 'orange' : 'blue'}>
                                {values.spot_strategy === 'SpotAsPriceGo' ? '竞价实例（跟随市场价）' : values.spot_strategy === 'SpotWithPriceLimit' ? '竞价实例（限价）' : '按量付费'}
                            </Tag>
                        </Descriptions.Item>
                    </Descriptions>
                ),
            });
        } catch (err) {
            const messageText = extractErrorMsg(err);
            if (messageText) Modal.error({ title: '策略保存失败', content: messageText });
        }
    }, [accounts, currentPolicyId, fetchPolicies, form, onDashboardRefresh, userDataScript]);

    const toggle = useCallback(async (enabled: boolean) => {
        if (!currentPolicyId) {
            message.warning('请先选择或创建一个策略');
            return;
        }
        try {
            await toggleCloudPolicy(currentPolicyId);
            message.success(`策略已${enabled ? '启用' : '禁用'}`);
            fetchPolicies();
            onDashboardRefresh();
        } catch (err) {
            const messageText = extractErrorMsg(err);
            if (messageText) message.error(messageText);
        }
    }, [currentPolicyId, fetchPolicies, onDashboardRefresh]);

    const remove = useCallback(async () => {
        if (!currentPolicyId) {
            message.warning('请先选择一个要删除的策略');
            return;
        }
        try {
            await deleteCloudPolicy(currentPolicyId);
            message.success('策略已删除');
            setCurrentPolicyId(null);
            setUserDataScript(DEFAULT_CLOUD_INIT_TEMPLATE);
            form.setFieldsValue(valuesFor(null));
            fetchPolicies();
            onDashboardRefresh();
        } catch (err) {
            const messageText = extractErrorMsg(err);
            if (messageText) message.error(messageText);
        }
    }, [currentPolicyId, fetchPolicies, form, onDashboardRefresh, valuesFor]);

    return {
        policies,
        currentPolicyId,
        userDataScript,
        setUserDataScript,
        loading,
        error,
        form,
        defaultFormValues,
        fetchPolicies,
        selectPolicy,
        submit,
        toggle,
        remove,
    };
};
