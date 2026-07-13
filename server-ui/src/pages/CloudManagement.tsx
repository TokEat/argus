import React, { useEffect, useState, useMemo, useRef, useCallback } from 'react';
import { Typography, Tag, Space, Button, Form, message, Modal, Popconfirm, Badge, Tabs, Alert, Descriptions, Tooltip, Steps } from 'antd';
import { ProCard } from '@ant-design/pro-components';
import { CloudOutlined, ReloadOutlined, PlusOutlined, DeleteOutlined, WifiOutlined, KeyOutlined, SettingOutlined, AppstoreOutlined, PlayCircleOutlined, SyncOutlined, CloudUploadOutlined, SearchOutlined, CheckCircleOutlined, ThunderboltOutlined, SafetyCertificateOutlined, UserOutlined, LoadingOutlined, ExclamationCircleOutlined, ClockCircleOutlined, ApiOutlined, RocketOutlined, StopOutlined } from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import {
    listCloudInstances, createCloudInstance, deleteCloudInstance, rebootCloudInstance, cleanupCloudInstances,
    listCloudAccounts, createCloudAccount, deleteCloudAccount, testCloudAccount,
    testOSSConnection,
    listCloudPolicies, createCloudPolicy, updateCloudPolicy, deleteCloudPolicy, toggleCloudPolicy,
    getCloudDashboard,
    discoverCloudResources, autoConfigureCloudAccount, oneClickSetup,
    checkCloudPermissions, queryCloudPrice, listAvailableInstanceTypes,
    listCloudRegions, updateCloudAccountRegion,
    listReleaseFiles, uploadServerAgent, uploadLocalAgent,
    listUsers, getCloudAccountBindings, updateCloudAccountBindings
} from '../services/api';
import { useAutoContext } from '../contexts/GlobalAIContext';
import { canAccessRole, getCurrentUserRole } from '../utils/auth';
import gsap from 'gsap';
import NetworkCanvas from '../components/NetworkCanvas';
import { CloudAccountsPanel } from './cloud/CloudAccountsPanel';
import { AddCloudAccountModal, CloudAccountBindingModal, CloudDiscoveryModal } from './cloud/CloudAccountDialogs';
import { CloudOSSTestModal, CloudPermissionDrawer, CloudSetupResultModal } from './cloud/CloudAccountResultDialogs';
import { CloudAgentUploadModal, CloudRegionSelectModal } from './cloud/CloudAgentDialogs';
import { CloudAgentDistributionPanel } from './cloud/CloudAgentDistributionPanel';
import { CloudInstancesPanel } from './cloud/CloudInstancesPanel';
import { CloudInstanceCreateModal } from './cloud/CloudInstanceCreateModal';
import { CloudPolicyPanel } from './cloud/CloudPolicyPanel';
import { DEFAULT_CLOUD_INIT_TEMPLATE, extractErrorMsg } from './cloud/utils';

const { Title, Text } = Typography;

const CloudManagement: React.FC = () => {
    const [loading, setLoading] = useState(true);
    const [instances, setInstances] = useState<API.CloudInstance[]>([]);
    const [accounts, setAccounts] = useState<API.CloudAccount[]>([]);
    const [policies, setPolicies] = useState<API.CloudScalingPolicy[]>([]);
    const [tenantUsers, setTenantUsers] = useState<API.User[]>([]);
    const [dashboard, setDashboard] = useState<API.CloudDashboard | null>(null);

    const [instanceModalOpen, setInstanceModalOpen] = useState(false);
    const [akModalOpen, setAkModalOpen] = useState(false);
    const [bindingModalOpen, setBindingModalOpen] = useState(false);
    const [bindingAccount, setBindingAccount] = useState<API.CloudAccount | null>(null);
    const [bindingUserIds, setBindingUserIds] = useState<string[]>([]);
    const [bindingSaving, setBindingSaving] = useState(false);
    const [instanceForm] = Form.useForm();
    const [akForm] = Form.useForm();
    const [policyForm] = Form.useForm();
    const [activeTab, setActiveTab] = useState('instances');
    const [currentPolicyId, setCurrentPolicyId] = useState<string | null>(null);

    // 资源发现
    const [discoverModalOpen, setDiscoverModalOpen] = useState(false);
    const [discovering, setDiscovering] = useState(false);
    const [discoveryData, setDiscoveryData] = useState<any>(null);
    const [discoverAccountId, setDiscoverAccountId] = useState<string>('');
    const [discoverSaving, setDiscoverSaving] = useState(false);
    const [discoverForm] = Form.useForm();
    const [setupResultOpen, setSetupResultOpen] = useState(false);
    const [setupResult, setSetupResult] = useState<any>(null);

    // 权限检查
    const [permDrawerOpen, setPermDrawerOpen] = useState(false);
    const [permLoading, setPermLoading] = useState(false);
    const [permData, setPermData] = useState<any>(null);
    const [permError, setPermError] = useState<string | null>(null);

    // 地域选择
    const [regionModalOpen, setRegionModalOpen] = useState(false);
    const [regionLoading, setRegionLoading] = useState(false);
    const [regionList, setRegionList] = useState<API.RegionInfo[]>([]);
    const [regionSelectAccountId, setRegionSelectAccountId] = useState<string>('');
    const [regionPendingAction, setRegionPendingAction] = useState<'oneclick' | 'discover' | null>(null);

    // Agent 上传 Modal
    const [agentUploadOpen, setAgentUploadOpen] = useState(false);
    const [agentUploadAccountId, setAgentUploadAccountId] = useState<string>('');
    const [agentUploadMode, setAgentUploadMode] = useState<string>('服务器端制品');
    const [releaseFiles, setReleaseFiles] = useState<API.ReleaseFileInfo[]>([]);
    const [releaseFilesLoading, setReleaseFilesLoading] = useState(false);
    const [selectedReleaseFiles, setSelectedReleaseFiles] = useState<string[]>([]);
    const [serverUploading, setServerUploading] = useState(false);
    const [localFiles, setLocalFiles] = useState<File[]>([]);
    const [localUploading, setLocalUploading] = useState(false);
    const [localUploadProgress, setLocalUploadProgress] = useState(0);

    // OSS 测试结果 Modal
    const [ossTestResult, setOssTestResult] = useState<any>(null);
    const [ossTestModalOpen, setOssTestModalOpen] = useState(false);
    const [ossTestLoading, setOssTestLoading] = useState(false);

    // 实例价格查询
    const [priceData, setPriceData] = useState<any>(null);
    const [priceLoading, setPriceLoading] = useState(false);
    const priceAbortRef = useRef<number>(0);

    // 可用实例规格
    const [availableTypes, setAvailableTypes] = useState<{id: string; cpu: number; memory_gb: number; family: string; status: string}[]>([]);
    const [typesLoading, setTypesLoading] = useState(false);
    const [selectedInstanceType, setSelectedInstanceType] = useState<string>('');

    // 弹容地域选择
    const [modalRegion, setModalRegion] = useState<string>('');
    const [modalRegions, setModalRegions] = useState<{region_id: string; local_name: string; endpoint: string}[]>([]);
    const [modalRegionsLoading, setModalRegionsLoading] = useState(false);
    const currentRole = useMemo(() => getCurrentUserRole(), []);
    const isAdmin = canAccessRole('admin', currentRole);
    const cleanupCandidateCount = useMemo(
        () => instances.filter(i => ['Terminated', 'Error'].includes(i.status)).length,
        [instances],
    );

    const canManageAccount = useCallback((account?: API.CloudAccount | null) => {
        if (!account) return false;
        return account.access_level === 'admin' || account.access_level === 'owner';
    }, []);

    // 统一刷新规格+价格（凭证或地域变化时调用）
    // 先加载规格列表 → 确定选中规格 → 再查该规格的价格
    const refreshModalData = useCallback((accountId: string, region: string) => {
        const seq = ++priceAbortRef.current;
        setPriceData(null);
        setPriceLoading(true);
        setTypesLoading(true);
        setAvailableTypes([]);
        setSelectedInstanceType('');

        // 步骤1：先加载可用规格
        listAvailableInstanceTypes(accountId, { region }).then(res => {
            if (seq !== priceAbortRef.current) return;
            if (!res?.instance_types) {
                setPriceLoading(false);
                return;
            }

            setAvailableTypes(res.instance_types);
            const acct = accounts.find(a => a.id === accountId);
            const defaultType = acct?.default_instance_type || '';
            let chosenType = '';
            if (res.instance_types.some(t => t.id === defaultType)) {
                chosenType = defaultType;
            } else if (res.instance_types.length > 0) {
                chosenType = res.instance_types[0].id;
            }
            setSelectedInstanceType(chosenType);

            // 步骤2：用确定的规格查价格
            if (chosenType) {
                queryCloudPrice(accountId, { region, instance_type: chosenType }).then(priceRes => {
                    if (seq === priceAbortRef.current && priceRes?.status !== 'error') setPriceData(priceRes);
                }).catch(() => {
                    if (seq === priceAbortRef.current) setPriceData(null);
                }).finally(() => {
                    if (seq === priceAbortRef.current) setPriceLoading(false);
                });
            } else {
                setPriceLoading(false);
            }
        }).catch(() => {
            if (seq === priceAbortRef.current) setPriceLoading(false);
        }).finally(() => {
            if (seq === priceAbortRef.current) setTypesLoading(false);
        });
    }, [accounts]);

    const defaultPolicyFormValues = useMemo(() => ({
        name: '经济型弹性扫描策略',
        min_instances: 0,
        max_instances: 5,
        scale_up_threshold: 50,
        scale_down_threshold: 0,
        cooldown_seconds: 180,
        instance_ttl_minutes: 60,
        spot_strategy: 'SpotAsPriceGo',
        spot_duration_hours: 1,
        ...(accounts.length === 1 ? { cloud_account_id: accounts[0].id } : {}),
    }), [accounts]);

    const defaultCloudInitTemplate = DEFAULT_CLOUD_INIT_TEMPLATE;
    const [userDataScript, setUserDataScript] = useState(defaultCloudInitTemplate);

    const fetchDashboard = async () => {
        try {
            const data = await getCloudDashboard();
            setDashboard(data);
        } catch (error) {
            console.error('Failed to fetch dashboard:', error);
        }
    };

    const fetchInstances = async () => {
        try {
            const result = await listCloudInstances();
            setInstances(result || []);
        } catch (error) {
            console.error('Failed to fetch instances:', error);
        }
    };

    const fetchAccounts = async () => {
        try {
            const result = await listCloudAccounts();
            setAccounts(result || []);
        } catch (error) {
            console.error('Failed to fetch accounts:', error);
        }
    };

    const fetchTenantUsers = async () => {
        if (!isAdmin) return [];
        try {
            const result = await listUsers();
            const usable = (result || []).filter(u => u.status === 'active' && ['admin', 'operator'].includes(u.role));
            setTenantUsers(usable);
            return usable;
        } catch (error) {
            console.error('Failed to fetch tenant users:', error);
            return [];
        }
    };

    const fetchPolicies = async () => {
        try {
            const result = await listCloudPolicies();
            setPolicies(result || []);
            if (result && result.length > 0) {
                // 保留当前选中的策略（若仍存在），否则默认选第一个，支持多策略管理
                const keepId = (currentPolicyId && result.some((p: any) => p.id === currentPolicyId))
                    ? currentPolicyId
                    : result[0].id;
                const selected = result.find((p: any) => p.id === keepId) || result[0];
                setCurrentPolicyId(keepId);
                setUserDataScript(selected.user_data_template || defaultCloudInitTemplate);
            } else {
                setCurrentPolicyId(null);
                setUserDataScript(defaultCloudInitTemplate);
            }
        } catch (error) {
            console.error('Failed to fetch policies:', error);
        }
    };

    const buildPolicyFormValues = useCallback((policy?: API.CloudScalingPolicy | null) => {
        if (!policy) {
            return {
                ...defaultPolicyFormValues,
                max_spot_price: undefined,
            };
        }

        return {
            ...defaultPolicyFormValues,
            name: policy.name ?? defaultPolicyFormValues.name,
            cloud_account_id: policy.cloud_account_id ?? (defaultPolicyFormValues as any).cloud_account_id,
            min_instances: policy.min_instances ?? defaultPolicyFormValues.min_instances,
            max_instances: policy.max_instances ?? defaultPolicyFormValues.max_instances,
            scale_up_threshold: policy.scale_up_threshold ?? defaultPolicyFormValues.scale_up_threshold,
            scale_down_threshold: policy.scale_down_threshold ?? defaultPolicyFormValues.scale_down_threshold,
            cooldown_seconds: policy.cooldown_seconds ?? defaultPolicyFormValues.cooldown_seconds,
            instance_ttl_minutes: policy.instance_ttl_minutes ?? defaultPolicyFormValues.instance_ttl_minutes,
            spot_strategy: policy.spot_strategy ?? defaultPolicyFormValues.spot_strategy,
            spot_duration_hours: policy.spot_duration_hours ?? defaultPolicyFormValues.spot_duration_hours,
            max_spot_price: policy.max_spot_price ?? undefined,
        };
    }, [defaultPolicyFormValues]);

    const pageRef = useRef<HTMLDivElement>(null);

    /* GSAP entrance */
    useEffect(() => {
        if (!pageRef.current) return;
        const els = pageRef.current.querySelectorAll('.cloud-animate-in');
        if (els.length === 0) return;
        const ctx = gsap.context(() => {
            gsap.from(els, {
                y: 24, opacity: 0, duration: 0.45,
                stagger: 0.08, ease: 'power2.out', clearProps: 'transform,opacity',
            });
        }, pageRef);
        return () => ctx.revert();
    }, []);

    useEffect(() => {
        if (activeTab !== 'policy') return;

        const selected = policies.find((p: any) => p.id === currentPolicyId) || (policies.length > 0 ? policies[0] : null);
        const values = buildPolicyFormValues(selected);
        const raf = window.requestAnimationFrame(() => {
            policyForm.setFieldsValue(values);
        });

        return () => window.cancelAnimationFrame(raf);
    }, [activeTab, policies, currentPolicyId, policyForm, buildPolicyFormValues]);

    useEffect(() => {
        fetchDashboard();
        if (activeTab === 'instances') {
            setLoading(true);
            fetchInstances().finally(() => setLoading(false));
            if (accounts.length === 0) fetchAccounts();
            const timer = setInterval(() => {
                fetchInstances();
                fetchDashboard();
            }, 15000);
            return () => clearInterval(timer);
        } else if (activeTab === 'credentials' || activeTab === 'agent-dist') {
            setLoading(true);
            fetchAccounts().finally(() => setLoading(false));
            if (isAdmin && tenantUsers.length === 0) fetchTenantUsers();
        } else if (activeTab === 'policy') {
            fetchPolicies();
            if (accounts.length === 0) fetchAccounts();
        }
    }, [activeTab]);

    useAutoContext({
        cloud_dashboard: dashboard,
        cloud_active_tab: activeTab
    });

    const handleCreateInstance = async () => {
        try {
            const values = await instanceForm.validateFields();
            const account = accounts.find(a => a.id === values.account_id);
            // 注入用户选择的规格和地域
            if (selectedInstanceType) {
                values.instance_type = selectedInstanceType;
            }
            if (modalRegion) {
                values.region = modalRegion;
            }
            const prevCount = instances.length;
            await createCloudInstance(values);
            setInstanceModalOpen(false);

            // 启动短轮询：每 2 秒刷新实例列表，直到检测到新实例或超时 30 秒
            let pollCount = 0;
            const maxPolls = 15;
            const pollTimer = setInterval(async () => {
                pollCount++;
                try {
                    const result = await listCloudInstances();
                    setInstances(result || []);
                    // 检测到新实例或轮询超时则停止
                    if ((result?.length || 0) > prevCount || pollCount >= maxPolls) {
                        clearInterval(pollTimer);
                        fetchDashboard();
                    }
                } catch {
                    if (pollCount >= maxPolls) clearInterval(pollTimer);
                }
            }, 2000);

            // 同时立即刷新一次
            fetchInstances();
            fetchDashboard();

            Modal.success({
                title: '实例创建请求已提交',
                width: 480,
                content: (
                    <div style={{ marginTop: 12 }}>
                        <Descriptions bordered size="small" column={1}
                            labelStyle={{ width: 100, fontWeight: 500, background: '#f8fafc' }}
                            contentStyle={{ fontSize: 13 }}
                        >
                            <Descriptions.Item label="云凭证">
                                <Tag color="blue">{account?.name || values.account_id}</Tag>
                            </Descriptions.Item>
                            <Descriptions.Item label="创建数量">
                                <Text strong style={{ color: '#0ea5e9' }}>{values.count || 1} 台</Text>
                            </Descriptions.Item>
                            <Descriptions.Item label="实例规格">
                                <Text style={{ fontFamily: 'monospace', fontSize: 12 }}>{account?.default_instance_type || '默认'}</Text>
                            </Descriptions.Item>
                            <Descriptions.Item label="地域">
                                <Text style={{ fontFamily: 'monospace', fontSize: 12 }}>{account?.region || '默认'}</Text>
                            </Descriptions.Item>
                        </Descriptions>
                        <Alert
                            message="实例正在后台异步创建中，列表将自动刷新显示最新状态。"
                            type="info"
                            showIcon
                            style={{ marginTop: 12, fontSize: 12 }}
                        />
                    </div>
                ),
            });
        } catch (err) {
            const msg = extractErrorMsg(err);
            if (msg) {
                Modal.error({
                    title: '实例创建失败',
                    content: msg,
                });
            }
        }
    };

    const handleDeleteInstance = async (id: string) => {
        try {
            await deleteCloudInstance(id);
            message.success('销毁指令已下发');
            fetchInstances();
            fetchDashboard();
        } catch (err) {
            const msg = extractErrorMsg(err);
            if (msg) message.error(msg);
        }
    };

    const handleCleanupInstances = async () => {
        try {
            const result = await cleanupCloudInstances({
                confirm: true,
                reason: 'manual cleanup from cloud management',
            });
            message.success(`已清理 ${result.count} 个实例记录`);
            fetchInstances();
            fetchDashboard();
        } catch (err) {
            const msg = extractErrorMsg(err);
            if (msg) message.error(msg);
        }
    };

    const handleAddAk = async () => {
        try {
            const values = await akForm.validateFields();
            if (!isAdmin) {
                delete values.bound_user_ids;
            }
            await createCloudAccount(values);
            message.success('凭证已加密保存');
            setAkModalOpen(false);
            fetchAccounts();
            fetchDashboard();
        } catch (err) {
            const msg = extractErrorMsg(err);
            if (msg) message.error(msg);
        }
    };

    const handleOpenBindings = async (account: API.CloudAccount) => {
        setBindingAccount(account);
        setBindingUserIds(account.bound_user_ids || []);
        setBindingModalOpen(true);
        const users = tenantUsers.length > 0 ? tenantUsers : await fetchTenantUsers();
        try {
            const bindings = await getCloudAccountBindings(account.id);
            setBindingUserIds((bindings.user_ids || []).filter(id => users.some(u => String(u.id) === String(id))));
        } catch (err) {
            const msg = extractErrorMsg(err);
            if (msg) message.error(msg);
        }
    };

    const handleSaveBindings = async () => {
        if (!bindingAccount) return;
        setBindingSaving(true);
        try {
            await updateCloudAccountBindings(bindingAccount.id, bindingUserIds);
            message.success('凭证绑定已更新');
            setBindingModalOpen(false);
            await fetchAccounts();
        } catch (err) {
            const msg = extractErrorMsg(err);
            if (msg) message.error(msg);
        } finally {
            setBindingSaving(false);
        }
    };

    const handleDeleteAk = async (id: string) => {
        try {
            await deleteCloudAccount(id);
            message.success('凭证已删除');
            fetchAccounts();
            fetchDashboard();
        } catch (err) {
            const msg = extractErrorMsg(err);
            if (msg) message.error(msg);
        }
    };

    const handleTestAk = async (id: string) => {
        try {
            message.loading({ content: '正在连接云厂商测试凭证...', key: 'testAK', duration: 0 });
            const res = await testCloudAccount(id);
            message.destroy('testAK');
            if (res && (res as any).status === 'error') {
                message.error(`连通性测试失败: ${(res as any).message || '未知错误'}`);
            } else {
                message.success('凭证连通性测试通过');
            }
        } catch (err) {
            message.destroy('testAK');
            setTimeout(() => message.error(`连通性测试失败: ${extractErrorMsg(err)}`), 50);
        }
    };

    const handlePolicySubmit = async () => {
        try {
            const values = await policyForm.validateFields();
            const payload = { ...values, user_data_template: userDataScript };
            const isUpdate = !!currentPolicyId;
            if (isUpdate) {
                await updateCloudPolicy(currentPolicyId, payload);
            } else {
                await createCloudPolicy(payload);
            }
            await fetchPolicies();
            await fetchDashboard();

            // 查找关联凭证名称
            const linkedAccount = accounts.find(a => a.id === values.cloud_account_id);

            Modal.success({
                title: `策略${isUpdate ? '更新' : '创建'}成功`,
                width: 520,
                content: (
                    <Descriptions bordered size="small" column={1} style={{ marginTop: 12 }}
                        labelStyle={{ width: 110, fontWeight: 500, background: '#f8fafc' }}
                        contentStyle={{ fontSize: 13 }}
                    >
                        <Descriptions.Item label="策略名称">
                            <Text strong>{values.name}</Text>
                        </Descriptions.Item>
                        <Descriptions.Item label="关联凭证">
                            <Tag color="blue">{linkedAccount?.name || values.cloud_account_id}</Tag>
                        </Descriptions.Item>
                        <Descriptions.Item label="实例范围">
                            {values.min_instances ?? 0} ~ {values.max_instances ?? 5} 台
                        </Descriptions.Item>
                        <Descriptions.Item label="扩容阈值">
                            队列堆积 &gt; {values.scale_up_threshold ?? 50} 任务时触发
                        </Descriptions.Item>
                        <Descriptions.Item label="缩容阈值">
                            队列堆积 ≤ {values.scale_down_threshold ?? 0} 任务时缩容
                        </Descriptions.Item>
                        <Descriptions.Item label="实例 TTL">
                            {values.instance_ttl_minutes ?? 120} 分钟
                        </Descriptions.Item>
                        <Descriptions.Item label="竞价策略">
                            <Tag color={values.spot_strategy === 'SpotAsPriceGo' ? 'orange' : 'blue'}>
                                {values.spot_strategy === 'SpotAsPriceGo' ? '竞价实例（跟随市场价）' :
                                 values.spot_strategy === 'SpotWithPriceLimit' ? '竞价实例（限价）' : '按量付费'}
                            </Tag>
                        </Descriptions.Item>
                    </Descriptions>
                ),
            });
        } catch (err) {
            const msg = extractErrorMsg(err);
            if (msg) {
                Modal.error({
                    title: '策略保存失败',
                    content: msg,
                });
            }
        }
    };

    const handleTogglePolicy = async (checked: boolean) => {
        if (!currentPolicyId) { message.warning('请先选择或创建一个策略'); return; }
        try {
            await toggleCloudPolicy(currentPolicyId);
            message.success(`策略已${checked ? '启用' : '禁用'}`);
            fetchPolicies();
            fetchDashboard();
        } catch (err) {
            const msg = extractErrorMsg(err);
            if (msg) message.error(msg);
        }
    };

    const handleDeletePolicy = async () => {
        if (!currentPolicyId) { message.warning('请先选择一个要删除的策略'); return; }
        try {
            await deleteCloudPolicy(currentPolicyId);
            message.success('策略已删除');
            setCurrentPolicyId(null);
            setUserDataScript(defaultCloudInitTemplate);
            policyForm.setFieldsValue(buildPolicyFormValues(null));
            fetchPolicies();
            fetchDashboard();
        } catch (err) {
            const msg = extractErrorMsg(err);
            if (msg) message.error(msg);
        }
    };

    // 用 ref 持有最新的 handler 引用，供 useMemo 内部使用
    // 这样 useMemo 不需要依赖 handler 变化，同时避免 stale closure
    const handlePolicySubmitRef = useRef(handlePolicySubmit);
    handlePolicySubmitRef.current = handlePolicySubmit;
    const handleTogglePolicyRef = useRef(handleTogglePolicy);
    handleTogglePolicyRef.current = handleTogglePolicy;
    const handleDeletePolicyRef = useRef(handleDeletePolicy);
    handleDeletePolicyRef.current = handleDeletePolicy;

    // 资源自动探测
    const handleDiscover = async (accountId: string) => {
        setDiscoverAccountId(accountId);
        setDiscovering(true);
        setDiscoverModalOpen(true);
        setDiscoveryData(null);
        discoverForm.resetFields();
        try {
            const data = await discoverCloudResources(accountId);
            setDiscoveryData(data);
        } catch (err) {
            const msg = extractErrorMsg(err);
            if (msg) message.error(`资源探测失败: ${msg}`);
        } finally {
            setDiscovering(false);
        }
    };

    const handleSaveDiscovery = async () => {
        try {
            const values = await discoverForm.validateFields();
            setDiscoverSaving(true);
            await autoConfigureCloudAccount(discoverAccountId, values);
            message.success('云资源配置已自动保存到凭证');
            setDiscoverModalOpen(false);
            fetchAccounts();
        } catch (err) {
            const msg = extractErrorMsg(err);
            if (msg) message.error(msg);
        } finally {
            setDiscoverSaving(false);
        }
    };

    // 地域选择流程：当凭证未配置 Region 时，先弹出地域选择
    const ensureRegionThen = async (accountId: string, action: 'oneclick' | 'discover') => {
        const account = accounts.find(a => a.id === accountId);
        if (!account) return;
        if (!account.region && !canManageAccount(account)) {
            message.warning('该凭证尚未配置地域，请联系凭证所有者或管理员先完成配置。');
            return;
        }
        if (account?.region) {
            // 已有 Region，直接执行
            if (action === 'oneclick') return doOneClickSetup(accountId);
            if (action === 'discover') return handleDiscover(accountId);
        }
        // 需要先选择地域
        setRegionSelectAccountId(accountId);
        setRegionPendingAction(action);
        setRegionModalOpen(true);
        setRegionLoading(true);
        setRegionList([]);
        try {
            const res = await listCloudRegions(accountId);
            setRegionList(res.regions || []);
        } catch (err) {
            message.error(`获取可用地域失败: ${extractErrorMsg(err)}`);
            setRegionModalOpen(false);
        } finally {
            setRegionLoading(false);
        }
    };

    const handleRegionSelect = async (regionId: string) => {
        try {
            await updateCloudAccountRegion(regionSelectAccountId, regionId);
            message.success(`已选择地域: ${regionId}`);
            setRegionModalOpen(false);
            await fetchAccounts();
            // 执行待定操作
            if (regionPendingAction === 'oneclick') {
                doOneClickSetup(regionSelectAccountId);
            } else if (regionPendingAction === 'discover') {
                handleDiscover(regionSelectAccountId);
            }
        } catch (err) {
            message.error(`保存地域失败: ${extractErrorMsg(err)}`);
        }
    };

    const doOneClickSetup = async (accountId: string) => {
        const account = accounts.find(a => a.id === accountId);
        message.loading({ content: `正在为「${account?.name || accountId}」执行一键配置...`, key: 'one-click', duration: 0 });
        try {
            const res = await oneClickSetup(accountId);
            message.destroy('one-click');
            setSetupResult(res);
            setSetupResultOpen(true);
            fetchAccounts();
            fetchPolicies();
            fetchDashboard();
        } catch (err) {
            const msg = extractErrorMsg(err);
            message.error({ content: `一键配置失败: ${msg}`, key: 'one-click' });
        }
    };

    // 权限检查
    const handleCheckPermissions = async (accountId: string) => {
        setPermDrawerOpen(true);
        setPermLoading(true);
        setPermData(null);
        setPermError(null);
        try {
            const res = await checkCloudPermissions(accountId);
            if (res?.status === 'error') {
                setPermError(res.message || '权限检查失败');
            } else {
                setPermData(res?.data || res);
            }
        } catch (err) {
            setPermError(extractErrorMsg(err) || '权限检查请求失败');
        } finally {
            setPermLoading(false);
        }
    };

    // 实例生命周期流程图展开行
    const renderInstanceLifecycle = (record: API.CloudInstance) => {
        const status = record.status;

        // 定义生命周期阶段
        const stages = [
            { key: 'init', title: '参数准备', desc: '生成 AgentID、渲染 Cloud-Init' },
            { key: 'provision', title: '创建实例', desc: '调用云厂商 API 创建 ECS' },
            { key: 'waiting', title: 'OS 启动', desc: '等待操作系统就绪' },
            { key: 'agent', title: 'Agent 注册', desc: 'Cloud-Init 拉取并启动 Agent' },
            { key: 'running', title: '运行中', desc: '已就绪，等待任务调度' },
            { key: 'done', title: '已释放', desc: 'TTL 超时或手动销毁' },
        ];

        // 根据当前状态计算活动步骤和状态
        let currentStep = 0;
        let stepStatus: 'process' | 'error' | 'finish' | 'wait' = 'process';

        switch (status) {
            case 'Provisioning':
                currentStep = 1;
                stepStatus = 'process';
                break;
            case 'WaitingReady':
                currentStep = record.ip ? 3 : 2; // 有 IP 说明 OS 已就绪，等待 Agent
                stepStatus = 'process';
                break;
            case 'Running':
                currentStep = 4;
                stepStatus = 'finish';
                break;
            case 'Rebooting':
                currentStep = 3;
                stepStatus = 'process';
                break;
            case 'Terminating':
                currentStep = 5;
                stepStatus = 'process';
                break;
            case 'Terminated':
                currentStep = 5;
                stepStatus = 'finish';
                break;
            case 'Error':
                currentStep = record.provider_instance_id ? (record.ip ? 3 : 2) : 1;
                stepStatus = 'error';
                break;
            default:
                currentStep = 0;
                stepStatus = 'process';
        }

        // 计算运行时长
        const launchedAt = record.launched_at ? new Date(record.launched_at) : null;
        const terminatedAt = record.terminated_at ? new Date(record.terminated_at) : null;
        const now = new Date();
        const durationMs = launchedAt ? ((terminatedAt || now).getTime() - launchedAt.getTime()) : 0;
        const durationMin = Math.floor(durationMs / 60000);
        const durationSec = Math.floor((durationMs % 60000) / 1000);

        return (
            <div style={{ padding: '12px 16px' }}>
                <Steps
                    current={currentStep}
                    status={stepStatus}
                    size="small"
                    items={stages.map((stage, idx) => {
                        let icon;
                        if (idx < currentStep || (idx === currentStep && stepStatus === 'finish')) {
                            icon = <CheckCircleOutlined />;
                        } else if (idx === currentStep && stepStatus === 'error') {
                            icon = <ExclamationCircleOutlined />;
                        } else if (idx === currentStep && stepStatus === 'process') {
                            icon = <LoadingOutlined />;
                        }

                        // 根据阶段设置默认图标
                        if (!icon) {
                            const stageIcons = [<SettingOutlined />, <CloudOutlined />, <ClockCircleOutlined />, <ApiOutlined />, <RocketOutlined />, <StopOutlined />];
                            icon = stageIcons[idx];
                        }

                        return {
                            title: stage.title,
                            description: stage.desc,
                            icon,
                        };
                    })}
                />

                {/* 详细信息区域 */}
                <div style={{ marginTop: 16, display: 'flex', gap: 16, flexWrap: 'wrap' }}>
                    <div style={{
                        flex: 1, minWidth: 280,
                        background: '#f8fafc', borderRadius: 8, padding: '12px 16px', border: '1px solid #e2e8f0',
                    }}>
                        <div style={{ fontSize: 12, fontWeight: 600, color: '#475569', marginBottom: 8 }}>
                            <CloudOutlined style={{ marginRight: 4 }} />实例信息
                        </div>
                        <Descriptions size="small" column={2}
                            labelStyle={{ fontSize: 11, color: '#94a3b8', paddingBottom: 2 }}
                            contentStyle={{ fontSize: 12, fontFamily: 'monospace', paddingBottom: 2 }}
                        >
                            <Descriptions.Item label="内部 ID">
                                <Text copyable style={{ fontSize: 11 }}>{record.id}</Text>
                            </Descriptions.Item>
                            <Descriptions.Item label="云实例 ID">
                                <Text copyable style={{ fontSize: 11 }}>{record.provider_instance_id || '-'}</Text>
                            </Descriptions.Item>
                            <Descriptions.Item label="Agent ID">
                                <Text style={{ fontSize: 11, color: record.agent_id ? '#10b981' : '#94a3b8' }}>
                                    {record.agent_id || '待注册'}
                                </Text>
                            </Descriptions.Item>
                            <Descriptions.Item label="IP 地址">
                                <Text style={{ fontSize: 11 }}>{record.ip || '分配中'}</Text>
                            </Descriptions.Item>
                            <Descriptions.Item label="地域">
                                <Text style={{ fontSize: 11 }}>{record.region || '-'}</Text>
                            </Descriptions.Item>
                            <Descriptions.Item label="竞价实例">
                                {record.spot ? <Tag color="gold" style={{ fontSize: 10 }}>Spot</Tag> : <Tag style={{ fontSize: 10 }}>按量</Tag>}
                            </Descriptions.Item>
                        </Descriptions>
                    </div>

                    <div style={{
                        flex: 1, minWidth: 280,
                        background: '#f8fafc', borderRadius: 8, padding: '12px 16px', border: '1px solid #e2e8f0',
                    }}>
                        <div style={{ fontSize: 12, fontWeight: 600, color: '#475569', marginBottom: 8 }}>
                            <ClockCircleOutlined style={{ marginRight: 4 }} />时间线
                        </div>
                        <Descriptions size="small" column={1}
                            labelStyle={{ fontSize: 11, color: '#94a3b8', paddingBottom: 2 }}
                            contentStyle={{ fontSize: 12, paddingBottom: 2 }}
                        >
                            <Descriptions.Item label="创建时间">
                                {record.created_at ? new Date(record.created_at).toLocaleString('zh-CN') : '-'}
                            </Descriptions.Item>
                            <Descriptions.Item label="启动时间">
                                {record.launched_at ? new Date(record.launched_at).toLocaleString('zh-CN') : '-'}
                            </Descriptions.Item>
                            {record.terminated_at && (
                                <Descriptions.Item label="释放时间">
                                    {new Date(record.terminated_at).toLocaleString('zh-CN')}
                                </Descriptions.Item>
                            )}
                            <Descriptions.Item label="运行时长">
                                <Text style={{ color: '#0ea5e9', fontWeight: 600 }}>
                                    {durationMin > 0 ? `${durationMin} 分 ` : ''}{durationSec} 秒
                                </Text>
                                {status !== 'Terminated' && status !== 'Error' && (
                                    <Tag color="processing" style={{ fontSize: 10, marginLeft: 6 }}>计时中</Tag>
                                )}
                            </Descriptions.Item>
                        </Descriptions>
                    </div>
                </div>

                {/* 错误信息 */}
                {record.error_message && (
                    <Alert
                        type="error"
                        showIcon
                        message="错误详情"
                        description={<Text style={{ fontFamily: 'monospace', fontSize: 12 }}>{record.error_message}</Text>}
                        style={{ marginTop: 12, fontSize: 12 }}
                    />
                )}
            </div>
        );
    };

    const instanceColumns: ColumnsType<API.CloudInstance> = [
        {
            title: '状态', dataIndex: 'status', key: 'status', width: 100,
            render: (status: string) => {
                let color = 'default';
                if (status === 'Running') color = 'success';
                else if (status === 'Provisioning' || status === 'WaitingReady') color = 'processing';
                else if (status === 'Error') color = 'error';
                return <Badge status={color as any} text={<Tag color={color === 'success' ? '#10b981' : color === 'processing' ? '#0ea5e9' : '#94a3b8'}>{status}</Tag>} />;
            },
        },
        {
            title: '云实例 ID', dataIndex: 'provider_instance_id', key: 'provider_instance_id',
            render: (id: string, record) => (
                <Space direction="vertical" size="small">
                    <Text copyable={{ text: id }} style={{ fontFamily: 'monospace', fontSize: 12 }}>
                        {id || '分配中...'}
                    </Text>
                    {record.spot && <Tag color="gold" style={{ fontSize: 10, lineHeight: '14px' }}>Spot</Tag>}
                </Space>
            ),
        },
        {
            title: 'Agent 连接', dataIndex: 'agent_id', key: 'agent_id',
            render: (id: string) => id ? <Text style={{ color: '#10b981', fontSize: 12 }}><WifiOutlined /> 已绑定</Text> : <Text type="secondary" style={{ fontSize: 12 }}>待连接</Text>
        },
        {
            title: 'IP 地址', dataIndex: 'ip', key: 'ip', width: 140,
            render: (ip: string) => ip || <Text type="secondary">-</Text>,
        },
        {
            title: '创建时间', dataIndex: 'created_at', key: 'created_at', width: 160,
            render: (v: string) => <Text style={{ fontSize: 12, color: '#64748b' }}>{v ? new Date(v).toLocaleString('zh-CN') : '-'}</Text>,
        },
        {
            title: '操作', key: 'actions', width: 180,
            render: (_: any, record: API.CloudInstance) => (
                <Space>
                    <Popconfirm title="确认重启此云主机？Agent 将通过 systemd 自动恢复。" onConfirm={async () => {
                        try {
                            await rebootCloudInstance(record.id);
                            message.success('重启指令已下发');
                            fetchInstances();
                        } catch (err) {
                            message.error(`重启失败: ${err}`);
                        }
                    }}>
                        <Button type="link" size="small" icon={<SyncOutlined />}
                            disabled={!['Running', 'Error', 'WaitingReady'].includes(record.status)}>重启</Button>
                    </Popconfirm>
                    <Popconfirm
                        title={['Error', 'Terminated'].includes(record.status) ? '确认清理此失败/已终止的记录？' : '确认销毁此云主机？'}
                        onConfirm={() => handleDeleteInstance(record.id)}
                    >
                        <Button type="link" size="small" danger icon={<DeleteOutlined />}>
                            {['Error', 'Terminated'].includes(record.status) ? '清理' : '销毁'}
                        </Button>
                    </Popconfirm>
                </Space>
            ),
        },
    ];

    const credColumns = [
        {
            title: '凭证别名', dataIndex: 'name', key: 'name',
            render: (text: string) => <Text strong>{text}</Text>
        },
        {
            title: '提供商', dataIndex: 'provider', key: 'provider',
            render: (p: string) => <Tag color="blue">{p.toUpperCase()}</Tag>
        },
        {
            title: '归属', key: 'owner', width: 150,
            render: (_: any, record: API.CloudAccount) => (
                <Space direction="vertical" size={2}>
                    <Text style={{ fontSize: 12 }}>{record.owner_username || record.owner_user_id || '-'}</Text>
                    <Tag color={record.access_level === 'bound' ? 'cyan' : record.access_level === 'owner' ? 'green' : 'purple'} style={{ fontSize: 10, width: 'fit-content' }}>
                        {record.access_level === 'bound' ? '被授权使用' : record.access_level === 'owner' ? '我的凭证' : '管理员可管'}
                    </Tag>
                </Space>
            )
        },
        {
            title: '地域', dataIndex: 'region', key: 'region',
            render: (r: string) => r ? <Tag color="green">{r}</Tag> : <Tag color="orange">待选择</Tag>
        },
        {
            title: '配置状态', key: 'config_status',
            render: (_: any, record: API.CloudAccount) => {
                const ok = record.default_instance_type && record.default_image_id && record.default_security_group && record.default_v_switch;
                return ok ? <Tag color="success" icon={<CheckCircleOutlined />}>已就绪</Tag> : <Tag color="warning">待配置</Tag>;
            }
        },
        {
            title: '状态', dataIndex: 'status', key: 'status',
            render: (s: string) => <Tag color={s === 'active' ? 'success' : 'default'}>{s === 'active' ? '正常' : '已禁用'}</Tag>
        },
        {
            title: '操作', key: 'action', width: 320,
            render: (_: any, record: API.CloudAccount) => {
                const manageable = canManageAccount(record);
                return (
                    <Space wrap>
                        <Tooltip title={manageable ? '' : '被授权凭证只能使用，不能修改基础配置'}>
                            <Button type="link" size="small" icon={<ThunderboltOutlined />}
                                disabled={!manageable}
                                style={{ color: manageable ? '#0ea5e9' : undefined, fontWeight: 600 }}
                                onClick={() => ensureRegionThen(record.id, 'oneclick')}>一键配置</Button>
                        </Tooltip>
                        <Button type="link" size="small" icon={<SafetyCertificateOutlined />}
                            style={{ color: '#8b5cf6' }}
                            onClick={() => handleCheckPermissions(record.id)}>权限检查</Button>
                        <Button type="link" size="small" icon={<SearchOutlined />} onClick={() => ensureRegionThen(record.id, 'discover')}>自动探测</Button>
                        <Button type="link" size="small" icon={<PlayCircleOutlined />}
                            onClick={() => handleTestAk(record.id)}>连通性</Button>
                        {isAdmin && (
                            <Button type="link" size="small" icon={<UserOutlined />} onClick={() => handleOpenBindings(record)}>绑定用户</Button>
                        )}
                        {manageable && (
                            <Popconfirm title="确认删除此凭证？" onConfirm={() => handleDeleteAk(record.id)}>
                                <Button type="link" danger size="small">删除</Button>
                            </Popconfirm>
                        )}
                    </Space>
                );
            }
        }
    ];

    // 凭证展开行：显示详细配置
    const expandedAccountRow = (record: API.CloudAccount) => {
        const ossReady = !!(record.oss_bucket && record.oss_endpoint);
        const configReady = !!(record.default_instance_type && record.default_image_id && record.default_security_group && record.default_v_switch);
        return (
            <div style={{ padding: '8px 16px' }}>
                {/* 全链路状态概览 */}
                <div style={{ marginBottom: 12, display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                    <Tag color={configReady ? 'success' : 'warning'} style={{ fontSize: 12, padding: '2px 10px' }}>
                        {configReady ? '实例配置就绪' : '实例配置不完整'}
                    </Tag>
                    <Tag color={ossReady ? 'success' : 'default'} style={{ fontSize: 12, padding: '2px 10px' }}>
                        {ossReady ? 'OSS 分发就绪' : 'HTTP Fallback 分发'}
                    </Tag>
                </div>
                <Descriptions size="small" column={3} bordered
                    labelStyle={{ background: '#f8fafc', fontWeight: 500, width: 120 }}
                    contentStyle={{ fontFamily: 'monospace', fontSize: 12 }}
                >
                    <Descriptions.Item label="实例规格">{record.default_instance_type || <Text type="danger">未配置</Text>}</Descriptions.Item>
                    <Descriptions.Item label="系统镜像">{record.default_image_id || <Text type="danger">未配置</Text>}</Descriptions.Item>
                    <Descriptions.Item label="安全组">{record.default_security_group || <Text type="danger">未配置</Text>}</Descriptions.Item>
                    <Descriptions.Item label="交换机">{record.default_v_switch || <Text type="danger">未配置</Text>}</Descriptions.Item>
                    <Descriptions.Item label="OSS Bucket">{record.oss_bucket ? <Text style={{ color: '#10b981' }}>{record.oss_bucket}</Text> : <Text type="secondary">未配置</Text>}</Descriptions.Item>
                    <Descriptions.Item label="OSS Endpoint">{record.oss_endpoint ? <Text style={{ color: '#10b981' }}>{record.oss_endpoint}</Text> : <Text type="secondary">未配置</Text>}</Descriptions.Item>
                    <Descriptions.Item label="绑定用户">
                        {isAdmin && record.bound_user_ids?.length
                            ? <Text>{record.bound_user_ids.length} 个用户</Text>
                            : <Text type="secondary">{record.access_level === 'bound' ? '由管理员授权' : '仅自己可用'}</Text>}
                    </Descriptions.Item>
                </Descriptions>
            </div>
        );
    };

    const cardStyle = { background: 'transparent', border: 'none' };

    const handlePolicySelection = useCallback((policyId: string | null) => {
        if (!policyId) {
            setCurrentPolicyId(null);
            policyForm.setFieldsValue(buildPolicyFormValues(null));
            setUserDataScript(defaultCloudInitTemplate);
            return;
        }
        const selected = policies.find(policy => policy.id === policyId) || null;
        setCurrentPolicyId(policyId);
        policyForm.setFieldsValue(buildPolicyFormValues(selected));
        setUserDataScript(selected?.user_data_template || defaultCloudInitTemplate);
    }, [buildPolicyFormValues, defaultCloudInitTemplate, policies, policyForm]);

    const handleOpenAgentUpload = async (account: API.CloudAccount) => {
        setAgentUploadAccountId(account.id);
        setAgentUploadMode('服务器端制品');
        setSelectedReleaseFiles([]);
        setLocalFiles([]);
        setLocalUploadProgress(0);
        setAgentUploadOpen(true);
        setReleaseFilesLoading(true);
        try {
            const result = await listReleaseFiles(account.id);
            setReleaseFiles(result.files || []);
        } catch {
            setReleaseFiles([]);
        } finally {
            setReleaseFilesLoading(false);
        }
    };

    const handleTestOSS = async (account: API.CloudAccount) => {
        setOssTestLoading(true);
        setOssTestResult(null);
        setOssTestModalOpen(true);
        try {
            setOssTestResult(await testOSSConnection(account.id));
        } catch (err) {
            setOssTestResult({
                status: 'error',
                connection: false,
                connection_err: extractErrorMsg(err) || String(err),
                bucket: account.oss_bucket,
                endpoint: account.oss_endpoint,
            });
        } finally {
            setOssTestLoading(false);
        }
    };

    const handleInstanceAccountChange = (accountId?: string) => {
        if (!accountId) {
            setPriceData(null);
            setAvailableTypes([]);
            setSelectedInstanceType('');
            setModalRegion('');
            setModalRegions([]);
            return;
        }
        const account = accounts.find(item => item.id === accountId);
        const defaultRegion = account?.region || '';
        setModalRegion(defaultRegion);
        setModalRegionsLoading(true);
        listCloudRegions(accountId)
            .then(result => setModalRegions(result?.regions || []))
            .catch(() => undefined)
            .finally(() => setModalRegionsLoading(false));
        if (defaultRegion) refreshModalData(accountId, defaultRegion);
    };

    const handleInstanceRegionChange = (region: string) => {
        setModalRegion(region);
        const accountId = instanceForm.getFieldValue('account_id');
        if (accountId && region) refreshModalData(accountId, region);
    };

    const handleInstanceTypeChange = (instanceType: string) => {
        setSelectedInstanceType(instanceType);
        const accountId = instanceForm.getFieldValue('account_id');
        if (!accountId || !instanceType) return;
        setPriceLoading(true);
        const sequence = ++priceAbortRef.current;
        queryCloudPrice(accountId, { instance_type: instanceType, region: modalRegion })
            .then(result => {
                if (sequence === priceAbortRef.current && result?.status !== 'error') setPriceData(result);
            })
            .catch(() => undefined)
            .finally(() => {
                if (sequence === priceAbortRef.current) setPriceLoading(false);
            });
    };

    const handleAgentUploadModeChange = (mode: string) => {
        setAgentUploadMode(mode);
        if (mode !== '服务器端制品' || releaseFiles.length > 0 || releaseFilesLoading) return;
        setReleaseFilesLoading(true);
        listReleaseFiles(agentUploadAccountId)
            .then(result => setReleaseFiles(result.files || []))
            .catch(() => setReleaseFiles([]))
            .finally(() => setReleaseFilesLoading(false));
    };

    const handleServerAgentUpload = async () => {
        setServerUploading(true);
        try {
            const result = await uploadServerAgent(agentUploadAccountId, selectedReleaseFiles);
            if (result?.status === 'ok') {
                message.success(result.message || '上传成功');
                setAgentUploadOpen(false);
            } else {
                message.error(result?.message || '上传失败');
            }
        } catch (err) {
            message.error(`上传失败: ${extractErrorMsg(err) || String(err) || '未知错误'}`);
        } finally {
            setServerUploading(false);
        }
    };

    const handleLocalAgentUpload = async () => {
        setLocalUploading(true);
        setLocalUploadProgress(0);
        try {
            const result = await uploadLocalAgent(agentUploadAccountId, localFiles, setLocalUploadProgress);
            if (result?.status === 'ok') {
                message.success(result.message || '上传成功');
                setAgentUploadOpen(false);
                setLocalFiles([]);
                setLocalUploadProgress(0);
            } else {
                message.error(result?.message || '上传失败');
            }
        } catch (err) {
            message.error(`上传失败: ${extractErrorMsg(err) || String(err) || '未知错误'}`);
        } finally {
            setLocalUploading(false);
        }
    };

    const policyTabContent = useMemo(() => (
        <CloudPolicyPanel
            policies={policies}
            accounts={accounts}
            currentPolicyId={currentPolicyId}
            form={policyForm}
            initialValues={defaultPolicyFormValues}
            userDataScript={userDataScript}
            onPolicyChange={handlePolicySelection}
            onUserDataScriptChange={setUserDataScript}
            onToggle={(enabled) => handleTogglePolicyRef.current(enabled)}
            onSubmit={() => handlePolicySubmitRef.current()}
            onDelete={() => handleDeletePolicyRef.current()}
        />
    ), [accounts, currentPolicyId, defaultPolicyFormValues, handlePolicySelection, policies, policyForm, userDataScript]);

    return (
        <div ref={pageRef} style={{ position: 'relative', overflow: 'hidden' }}>
            <NetworkCanvas color="#0ea5e9" count={30} speed={0.15} linkDist={100} />
            <div className="cloud-animate-in" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20, position: 'relative', zIndex: 1 }}>
                <Title level={4} style={{ margin: 0, color: '#1e293b', fontWeight: 600 }}>
                    <CloudOutlined style={{ marginRight: 8, color: '#0ea5e9' }} />
                    云资源动态调度
                </Title>
                <Space>
                    <Tag color="#10b981" style={{ borderRadius: 20 }}>
                        <WifiOutlined /> 运行中云实例 {dashboard?.running_instances || 0}
                    </Tag>
                    {activeTab === 'instances' && (
                        <>
                            <Button type="primary" icon={<PlusOutlined />} onClick={async () => {
                                instanceForm.resetFields();
                                if (accounts.length === 0) await fetchAccounts();
                                setInstanceModalOpen(true);
                            }}>手动弹容</Button>
                            <Popconfirm
                                title="确认清理所有已终止/错误的实例记录？"
                                description="只会软删除当前可访问云账号下的终止或错误记录，不会销毁运行中的云实例。"
                                onConfirm={handleCleanupInstances}
                                okText="确认清理"
                                cancelText="取消"
                            >
                                <Button danger icon={<DeleteOutlined />} disabled={cleanupCandidateCount === 0}>
                                    一键清理 ({cleanupCandidateCount})
                                </Button>
                            </Popconfirm>
                            <Button icon={<ReloadOutlined />} onClick={fetchInstances} loading={loading}>刷新</Button>
                        </>
                    )}
                    {activeTab === 'credentials' && (
                        <Button type="primary" icon={<PlusOutlined />} onClick={() => { akForm.resetFields(); if (isAdmin && tenantUsers.length === 0) fetchTenantUsers(); setAkModalOpen(true); }}>添加凭证</Button>
                    )}
                </Space>
            </div>

            <ProCard className="glass-card cloud-animate-in" style={{ ...cardStyle, position: 'relative', zIndex: 1 }} bodyStyle={{ padding: 0 }}>
                <Tabs
                    activeKey={activeTab}
                    onChange={setActiveTab}
                    style={{ padding: '0 20px' }}
                    items={[
                        {
                            key: 'instances',
                            label: <span><AppstoreOutlined /> 实例状态追踪</span>,
                            children: <CloudInstancesPanel loading={loading} instances={instances} columns={instanceColumns} renderExpandedRow={renderInstanceLifecycle} />,
                        },
                        {
                            key: 'policy',
                            label: <span><SettingOutlined /> AutoScaler 策略</span>,
                            forceRender: true,
                            children: policyTabContent,
                        },
                        {
                            key: 'credentials',
                            label: <span><KeyOutlined /> API 凭证管理</span>,
                            children: <CloudAccountsPanel accounts={accounts} columns={credColumns} renderExpandedRow={expandedAccountRow} />,
                        },
                        {
                            key: 'agent-dist',
                            label: <span><CloudUploadOutlined /> Agent 分发</span>,
                            children: <CloudAgentDistributionPanel accounts={accounts} onUpload={handleOpenAgentUpload} onTest={handleTestOSS} />,
                        },
                    ]}
                />
            </ProCard>

            <CloudInstanceCreateModal
                open={instanceModalOpen}
                form={instanceForm}
                accounts={accounts}
                policies={policies}
                region={modalRegion}
                regions={modalRegions}
                regionsLoading={modalRegionsLoading}
                availableTypes={availableTypes}
                typesLoading={typesLoading}
                selectedInstanceType={selectedInstanceType}
                priceData={priceData}
                priceLoading={priceLoading}
                onSubmit={handleCreateInstance}
                onCancel={() => setInstanceModalOpen(false)}
                onAccountChange={handleInstanceAccountChange}
                onRegionChange={handleInstanceRegionChange}
                onInstanceTypeChange={handleInstanceTypeChange}
            />

            <AddCloudAccountModal
                open={akModalOpen}
                form={akForm}
                isAdmin={isAdmin}
                users={tenantUsers}
                onSubmit={handleAddAk}
                onCancel={() => setAkModalOpen(false)}
                onLoadUsers={fetchTenantUsers}
            />
            <CloudAccountBindingModal
                open={bindingModalOpen}
                account={bindingAccount}
                userIds={bindingUserIds}
                users={tenantUsers}
                saving={bindingSaving}
                onChange={setBindingUserIds}
                onSubmit={handleSaveBindings}
                onCancel={() => setBindingModalOpen(false)}
            />
            <CloudDiscoveryModal
                open={discoverModalOpen}
                loading={discovering}
                saving={discoverSaving}
                data={discoveryData}
                form={discoverForm}
                onSubmit={handleSaveDiscovery}
                onCancel={() => setDiscoverModalOpen(false)}
            />

            <CloudSetupResultModal open={setupResultOpen} result={setupResult} onClose={() => setSetupResultOpen(false)} />
            <CloudPermissionDrawer
                open={permDrawerOpen}
                loading={permLoading}
                error={permError}
                data={permData}
                onClose={() => setPermDrawerOpen(false)}
            />
            <CloudOSSTestModal
                open={ossTestModalOpen}
                loading={ossTestLoading}
                result={ossTestResult}
                onClose={() => setOssTestModalOpen(false)}
            />

            <CloudAgentUploadModal
                open={agentUploadOpen}
                mode={agentUploadMode}
                releaseFiles={releaseFiles}
                releaseFilesLoading={releaseFilesLoading}
                selectedReleaseFiles={selectedReleaseFiles}
                serverUploading={serverUploading}
                localFiles={localFiles}
                localUploading={localUploading}
                localUploadProgress={localUploadProgress}
                onClose={() => { setAgentUploadOpen(false); setLocalFiles([]); setLocalUploadProgress(0); }}
                onModeChange={handleAgentUploadModeChange}
                onSelectedReleaseFilesChange={setSelectedReleaseFiles}
                onServerUpload={handleServerAgentUpload}
                onLocalFilesChange={setLocalFiles}
                onLocalUpload={handleLocalAgentUpload}
                onClearLocalFiles={() => { setLocalFiles([]); setLocalUploadProgress(0); }}
            />
            <CloudRegionSelectModal
                open={regionModalOpen}
                loading={regionLoading}
                regions={regionList}
                onSelect={handleRegionSelect}
                onClose={() => setRegionModalOpen(false)}
            />
        </div>
    );
};

export default CloudManagement;
