import React, { useEffect, useState, useMemo, useRef, useCallback } from 'react';
import { Typography, Table, Tag, Space, Button, Spin, Empty, Modal, Form, Input, Select, message, Popconfirm, Badge, Tabs, Switch, InputNumber, Row, Col, Alert, Descriptions, Drawer, Collapse, Tooltip, Segmented, Upload, Progress, Steps } from 'antd';
import { ProCard } from '@ant-design/pro-components';
import { CloudOutlined, ReloadOutlined, PlusOutlined, DeleteOutlined, WifiOutlined, KeyOutlined, SettingOutlined, AppstoreOutlined, CodeOutlined, PlayCircleOutlined, SyncOutlined, CloudUploadOutlined, SearchOutlined, CheckCircleOutlined, ThunderboltOutlined, SafetyCertificateOutlined, CopyOutlined, CheckOutlined, CloseOutlined, UserOutlined, LockOutlined, InboxOutlined, FileOutlined, CloudServerOutlined, UploadOutlined, LoadingOutlined, ExclamationCircleOutlined, ClockCircleOutlined, ApiOutlined, RocketOutlined, StopOutlined } from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import Editor from '@monaco-editor/react';
import {
    listCloudInstances, createCloudInstance, deleteCloudInstance, rebootCloudInstance,
    listCloudAccounts, createCloudAccount, deleteCloudAccount, testCloudAccount,
    testOSSConnection,
    listCloudPolicies, createCloudPolicy, updateCloudPolicy, deleteCloudPolicy, toggleCloudPolicy,
    getCloudDashboard,
    discoverCloudResources, autoConfigureCloudAccount, oneClickSetup,
    checkCloudPermissions, queryCloudPrice, listAvailableInstanceTypes,
    listCloudRegions, updateCloudAccountRegion,
    listReleaseFiles, uploadServerAgent, uploadLocalAgent,
    listOSSFiles, deleteOSSFile
} from '../services/api';
import { useAutoContext } from '../contexts/GlobalAIContext';

const { Title, Text, Paragraph } = Typography;

// 统一错误提取：兼容 string / Error / Axios rejected / Antd ValidateErrorEntity
const extractErrorMsg = (err: unknown): string | null => {
    if (!err) return null;
    if (typeof err === 'string') return err;
    if (err instanceof Error) return err.message;
    if (typeof err === 'object') {
        const obj = err as Record<string, any>;
        // Ant Design 表单校验失败 (ValidateErrorEntity) 不弹后端错误
        if (obj.errorFields) return null;
        if (obj.error) return String(obj.error);
        if (obj.message) return String(obj.message);
    }
    return String(err);
};

// OSS 文件浏览器子组件
const OSSFileBrowser: React.FC<{ account: API.CloudAccount }> = ({ account }) => {
    const [ossFiles, setOssFiles] = useState<API.OSSFileInfo[]>([]);
    const [ossLoading, setOssLoading] = useState(false);
    const [loaded, setLoaded] = useState(false);

    const fetchOSSFiles = async () => {
        setOssLoading(true);
        try {
            const res = await listOSSFiles(account.id);
            setOssFiles(res.files || []);
        } catch {
            setOssFiles([]);
        } finally {
            setOssLoading(false);
            setLoaded(true);
        }
    };

    const handleDelete = async (objectKey: string) => {
        try {
            await deleteOSSFile(account.id, objectKey);
            message.success('文件已从 OSS 删除');
            fetchOSSFiles();
        } catch (err: any) {
            message.error(`删除失败: ${extractErrorMsg(err) || String(err)}`);
        }
    };

    return (
        <ProCard
            bordered
            size="small"
            style={{ marginBottom: 12 }}
            title={
                <Space>
                    <Tag color="blue" style={{ margin: 0 }}>{account.name}</Tag>
                    <Text type="secondary" style={{ fontSize: 12 }}>
                        {account.oss_bucket} / argus/agent/
                    </Text>
                </Space>
            }
            extra={
                <Button
                    size="small"
                    icon={<ReloadOutlined />}
                    onClick={fetchOSSFiles}
                    loading={ossLoading}
                >
                    {loaded ? '刷新' : '加载文件列表'}
                </Button>
            }
        >
            {!loaded ? (
                <div style={{ textAlign: 'center', padding: '24px 0', color: '#94a3b8' }}>
                    <InboxOutlined style={{ fontSize: 28, marginBottom: 8 }} />
                    <div style={{ fontSize: 13 }}>点击「加载文件列表」查看 OSS 中的 Agent 制品</div>
                </div>
            ) : ossLoading ? (
                <div style={{ display: 'flex', justifyContent: 'center', padding: '24px 0' }}><Spin /></div>
            ) : ossFiles.length === 0 ? (
                <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="OSS 中暂无 Agent 文件" style={{ padding: '16px 0' }} />
            ) : (
                <Table
                    dataSource={ossFiles}
                    rowKey="key"
                    pagination={false}
                    size="small"
                    columns={[
                        {
                            title: 'Object Key', dataIndex: 'key', key: 'key',
                            render: (key: string) => {
                                const name = key.split('/').pop() || key;
                                return (
                                    <Space>
                                        <FileOutlined style={{ color: '#64748b' }} />
                                        <div>
                                            <Text style={{ fontFamily: 'monospace', fontSize: 13 }}>{name}</Text>
                                            <br />
                                            <Text type="secondary" style={{ fontSize: 11 }}>{key}</Text>
                                        </div>
                                    </Space>
                                );
                            }
                        },
                        {
                            title: '大小', dataIndex: 'size', key: 'size', width: 110,
                            render: (size: number) => {
                                if (size > 1024 * 1024) return <Text type="secondary">{(size / 1024 / 1024).toFixed(1)} MB</Text>;
                                if (size > 1024) return <Text type="secondary">{(size / 1024).toFixed(1)} KB</Text>;
                                return <Text type="secondary">{size} B</Text>;
                            }
                        },
                        {
                            title: '最后修改', dataIndex: 'last_modified', key: 'last_modified', width: 180,
                            render: (v: string) => <Text style={{ fontSize: 12, color: '#64748b' }}>{v ? new Date(v).toLocaleString('zh-CN') : '-'}</Text>
                        },
                        {
                            title: '操作', key: 'actions', width: 80,
                            render: (_: any, record: API.OSSFileInfo) => (
                                <Popconfirm title="确认从 OSS 删除此文件？" onConfirm={() => handleDelete(record.key)}>
                                    <Button type="text" danger size="small" icon={<DeleteOutlined />} />
                                </Popconfirm>
                            )
                        }
                    ]}
                />
            )}
        </ProCard>
    );
};

const CloudManagement: React.FC = () => {
    const [loading, setLoading] = useState(true);
    const [instances, setInstances] = useState<API.CloudInstance[]>([]);
    const [accounts, setAccounts] = useState<API.CloudAccount[]>([]);
    const [policies, setPolicies] = useState<API.CloudScalingPolicy[]>([]);
    const [dashboard, setDashboard] = useState<API.CloudDashboard | null>(null);

    const [instanceModalOpen, setInstanceModalOpen] = useState(false);
    const [akModalOpen, setAkModalOpen] = useState(false);
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
        ...(accounts.length === 1 ? { cloud_account_id: accounts[0].id } : {}),
    }), [accounts]);

    // 默认 Cloud-Init 模板（与后端 DefaultCloudInitTemplate 保持一致）
    // 系统在下发实例时会自动替换 {{.DownloadURL}} {{.ServerAddr}} {{.AgentID}} {{.PSK}} 等变量
    const defaultCloudInitTemplate = `#!/bin/bash
set -ex

echo "[Argus] Starting agent provisioning..."

# 下载 Agent 二进制（优先使用 OSS 预签名 URL，fallback 到 Server HTTP）
DOWNLOAD_URL="{{.DownloadURL}}"
AGENT_BIN="/usr/local/bin/dddd-agent"

for i in 1 2 3 4 5; do
    if curl -fsSL "$DOWNLOAD_URL" -o "$AGENT_BIN"; then
        chmod +x "$AGENT_BIN"
        echo "[Argus] Agent binary downloaded successfully"
        break
    fi
    echo "[Argus] Download attempt $i failed, retrying in 10s..."
    sleep 10
done

if [ ! -x "$AGENT_BIN" ]; then
    echo "[Argus] FATAL: Failed to download agent binary after 5 attempts"
    exit 1
fi

mkdir -p /var/log/argus

cat > /etc/systemd/system/argus-agent.service <<EOF
[Unit]
Description=Argus Scanning Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$AGENT_BIN \\
    --server "{{.ServerAddr}}" \\
    --id "{{.AgentID}}" \\
    --api "{{.APIURL}}" \\
    --tags "cloud=true,auto_scaled=true,target_type=all"{{if .PSK}} \\
    --psk "{{.PSK}}"{{end}}
Restart=always
RestartSec=5
StandardOutput=append:/var/log/argus/agent.log
StandardError=append:/var/log/argus/agent.log
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable argus-agent
systemctl start argus-agent

echo "[Argus] Agent registered as systemd service and started"
`;
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

    const fetchPolicies = async () => {
        try {
            const result = await listCloudPolicies();
            setPolicies(result || []);
            if (result && result.length > 0) {
                const policy = result[0];
                setCurrentPolicyId(policy.id);
                if (policy.user_data_template) {
                    setUserDataScript(policy.user_data_template);
                }
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
            max_spot_price: policy.max_spot_price ?? undefined,
        };
    }, [defaultPolicyFormValues]);

    useEffect(() => {
        if (activeTab !== 'policy') return;

        const values = buildPolicyFormValues(policies.length > 0 ? policies[0] : null);
        const raf = window.requestAnimationFrame(() => {
            policyForm.setFieldsValue(values);
        });

        return () => window.cancelAnimationFrame(raf);
    }, [activeTab, policies, policyForm, buildPolicyFormValues]);

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

    const handleAddAk = async () => {
        try {
            const values = await akForm.validateFields();
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
                            队列堆积 ≥ {values.scale_up_threshold ?? 50} 任务时触发
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
        if (!currentPolicyId) return;
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
        if (!currentPolicyId) return;
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
            render: (_: any, record: API.CloudAccount) => (
                <Space wrap>
                    <Button type="link" size="small" icon={<ThunderboltOutlined />}
                        style={{ color: '#0ea5e9', fontWeight: 600 }}
                        onClick={() => ensureRegionThen(record.id, 'oneclick')}>一键配置</Button>
                    <Button type="link" size="small" icon={<SafetyCertificateOutlined />}
                        style={{ color: '#8b5cf6' }}
                        onClick={() => handleCheckPermissions(record.id)}>权限检查</Button>
                    <Button type="link" size="small" icon={<SearchOutlined />} onClick={() => ensureRegionThen(record.id, 'discover')}>自动探测</Button>
                    <Button type="link" size="small" icon={<PlayCircleOutlined />}
                        onClick={() => handleTestAk(record.id)}>连通性</Button>
                    <Popconfirm title="确认删除此凭证？" onConfirm={() => handleDeleteAk(record.id)}>
                        <Button type="link" danger size="small">删除</Button>
                    </Popconfirm>
                </Space>
            )
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
                </Descriptions>
            </div>
        );
    };

    const cardStyle = { background: 'transparent', border: 'none' };

    // 用 useMemo 稳定 policy tab 的 JSX 引用
    // 只有当 policies/accounts/currentPolicyId/userDataScript 变化时才重建
    // 避免 dashboard/loading/instances 等无关 state 更新导致 Form 被销毁重建
    const policyTabContent = useMemo(() => (
        <div style={{ padding: '20px 0', maxWidth: 800 }}>
            <ProCard bordered style={{ marginBottom: 24 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                    <Title level={5} style={{ margin: 0 }}>引擎调度开关</Title>
                    <Switch
                        checkedChildren="已启用" unCheckedChildren="已停用"
                        checked={policies.length > 0 ? policies[0].enabled : false}
                        onChange={(checked) => handleTogglePolicyRef.current(checked)}
                        disabled={!currentPolicyId}
                    />
                </div>
                <Paragraph type="secondary">
                    配置 AutoScaler (自动伸缩引擎) 的行为模式。系统将根据后台任务队列深度，向指定云厂商自动请求或销毁 Spot 竞价实例。
                </Paragraph>

                {!currentPolicyId && (
                    <Alert message="暂无伸缩策略，请填写下方表单创建一个新策略" type="info" showIcon style={{ marginBottom: 16 }} />
                )}

                <Form form={policyForm} layout="vertical" initialValues={defaultPolicyFormValues}>
                    <Form.Item name="name" label="策略名称" rules={[{ required: true }]}>
                        <Input placeholder="例: 默认全局扩容策略" />
                    </Form.Item>

                    <Form.Item name="cloud_account_id" label="绑定的云凭证" rules={[{ required: true }]}>
                        <Select placeholder="请选择凭证" options={accounts.map(a => ({ value: a.id, label: a.name + ' (' + a.provider + ')' }))} />
                    </Form.Item>

                    <Row gutter={16}>
                        <Col span={12}>
                            <Form.Item name="min_instances" label="最小实例数" extra="平时保持的最低机器数量">
                                <InputNumber min={0} max={100} style={{ width: '100%' }} />
                            </Form.Item>
                        </Col>
                        <Col span={12}>
                            <Form.Item name="max_instances" label="最大实例数" extra="硬性上限，防止账单爆炸">
                                <InputNumber min={1} max={500} style={{ width: '100%' }} />
                            </Form.Item>
                        </Col>
                    </Row>

                    <Row gutter={16}>
                        <Col span={8}>
                            <Form.Item name="scale_up_threshold" label="扩容阈值" extra="队列任务数 > 此值则扩容">
                                <InputNumber min={1} style={{ width: '100%' }} />
                            </Form.Item>
                        </Col>
                        <Col span={8}>
                            <Form.Item name="scale_down_threshold" label="缩容阈值" extra="队列任务数 <= 此值则缩容">
                                <InputNumber min={0} style={{ width: '100%' }} />
                            </Form.Item>
                        </Col>
                        <Col span={8}>
                            <Form.Item name="cooldown_seconds" label="冷却时间 (秒)" extra="两次伸缩操作间的最小间隔">
                                <InputNumber min={60} style={{ width: '100%' }} />
                            </Form.Item>
                        </Col>
                    </Row>

                    <Row gutter={16}>
                        <Col span={12}>
                            <Form.Item name="spot_strategy" label="竞价实例策略">
                                <Select options={[
                                    { value: 'NoSpot', label: '按量付费 (不使用竞价)' },
                                    { value: 'SpotAsPriceGo', label: '系统自动出价 (推荐)' },
                                    { value: 'SpotWithPriceLimit', label: '设置最高限价' }
                                ]} />
                            </Form.Item>
                        </Col>
                        <Col span={12}>
                            <Form.Item name="instance_ttl_minutes" label="TTL 强制回收 (分钟)" extra="实例最大存活时间，超时由后台强杀">
                                <InputNumber min={10} style={{ width: '100%' }} />
                            </Form.Item>
                        </Col>
                    </Row>

                    <Form.Item noStyle shouldUpdate={(prev: any, cur: any) => prev?.spot_strategy !== cur?.spot_strategy}>
                        {({ getFieldValue }: any) =>
                            getFieldValue('spot_strategy') === 'SpotWithPriceLimit' ? (
                                <Form.Item name="max_spot_price" label="最高竞价限价 (元/小时)" extra="仅在设置最高限价模式时生效">
                                    <InputNumber min={0.01} step={0.01} style={{ width: '100%' }} placeholder="例: 0.5" />
                                </Form.Item>
                            ) : null
                        }
                    </Form.Item>

                    <Form.Item label={<span><CodeOutlined /> Cloud-Init (UserData) 注入模板</span>} extra="系统在下发实例时会自动替换 {{.DownloadURL}} {{.ServerAddr}} {{.AgentID}} {{.PSK}} 等模板变量。留空则使用内置默认模板。">
                        <div style={{ height: 350, border: '1px solid #e2e8f0', borderRadius: 8, overflow: 'hidden' }}>
                            <Editor
                                height="100%"
                                language="shell"
                                theme="vs-dark"
                                value={userDataScript}
                                onChange={(val) => setUserDataScript(val || '')}
                                options={{ minimap: { enabled: false }, fontSize: 13 }}
                            />
                        </div>
                    </Form.Item>

                    <Space>
                        <Button type="primary" onClick={() => handlePolicySubmitRef.current()}>保存调度策略</Button>
                        {currentPolicyId && (
                            <Popconfirm title="确认删除当前 AutoScaler 策略？" onConfirm={() => handleDeletePolicyRef.current()}>
                                <Button danger icon={<DeleteOutlined />}>删除策略</Button>
                            </Popconfirm>
                        )}
                    </Space>
                </Form>
            </ProCard>
        </div>
    ), [policies, accounts, currentPolicyId, userDataScript, policyForm]);

    return (
        <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
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
                            <Button icon={<ReloadOutlined />} onClick={fetchInstances} loading={loading}>刷新</Button>
                        </>
                    )}
                    {activeTab === 'credentials' && (
                        <Button type="primary" icon={<PlusOutlined />} onClick={() => { akForm.resetFields(); setAkModalOpen(true); }}>添加凭证</Button>
                    )}
                </Space>
            </div>

            <ProCard className="glass-card" style={cardStyle} bodyStyle={{ padding: 0 }}>
                <Tabs
                    activeKey={activeTab}
                    onChange={setActiveTab}
                    style={{ padding: '0 20px' }}
                    items={[
                        {
                            key: 'instances',
                            label: <span><AppstoreOutlined /> 实例状态追踪</span>,
                            children: (
                                <div style={{ padding: '20px 0' }}>
                                    {loading && instances.length === 0 ? (
                                        <div style={{ display: 'flex', justifyContent: 'center', padding: '60px 0' }}><Spin size="large" /></div>
                                    ) : instances.length === 0 ? (
                                        <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="当前没有正在运行或被调度的云实例" style={{ padding: '60px 0' }} />
                                    ) : (
                                        <Table columns={instanceColumns} dataSource={instances} rowKey="id"
                                            pagination={{ pageSize: 20, showTotal: (total) => `共 ${total} 个实例` }} size="middle"
                                            expandable={{
                                                expandedRowRender: renderInstanceLifecycle,
                                                rowExpandable: () => true,
                                            }}
                                        />
                                    )}
                                </div>
                            ),
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
                            children: (
                                <div style={{ padding: '20px 0' }}>
                                    <Alert message="所有 AccessKey 和 Secret 均在入库前通过 AES-256-GCM 算法进行加密存储。点击「自动探测」可通过 AK/SK 自动发现云资源并配置。" type="success" showIcon style={{ marginBottom: 16 }} />
                                    <Table columns={credColumns} dataSource={accounts} rowKey="id" pagination={false} size="middle"
                                        expandable={{
                                            expandedRowRender: expandedAccountRow,
                                            rowExpandable: () => true,
                                        }}
                                    />
                                </div>
                            ),
                        },
                        {
                            key: 'agent-dist',
                            label: <span><CloudUploadOutlined /> Agent 分发</span>,
                            children: (
                                <div style={{ padding: '20px 0' }}>
                                    <Alert
                                        message="Agent 二进制分发管理"
                                        description="弹性扩缩创建的 ECS 实例需要下载 Agent 二进制。配置了 OSS 的凭证可通过内网高速分发，否则回退到 Server HTTP 下载。"
                                        type="info"
                                        showIcon
                                        style={{ marginBottom: 16 }}
                                    />
                                    {accounts.length === 0 ? (
                                        <Empty description="请先在「API 凭证管理」中添加云凭证" style={{ padding: '60px 0' }} />
                                    ) : (
                                        <Table
                                            dataSource={accounts}
                                            rowKey="id"
                                            pagination={false}
                                            size="middle"
                                            columns={[
                                                {
                                                    title: '凭证别名', dataIndex: 'name', key: 'name',
                                                    render: (text: string) => <Text strong>{text}</Text>
                                                },
                                                {
                                                    title: 'OSS Bucket', dataIndex: 'oss_bucket', key: 'oss_bucket',
                                                    render: (v: string) => v
                                                        ? <Text style={{ color: '#10b981', fontFamily: 'monospace', fontSize: 12 }}>{v}</Text>
                                                        : <Tag color="default">未配置</Tag>
                                                },
                                                {
                                                    title: 'OSS Endpoint', dataIndex: 'oss_endpoint', key: 'oss_endpoint',
                                                    render: (v: string) => v
                                                        ? <Text style={{ color: '#10b981', fontFamily: 'monospace', fontSize: 12 }}>{v}</Text>
                                                        : <Tag color="default">未配置</Tag>
                                                },
                                                {
                                                    title: '分发通道', key: 'channel',
                                                    render: (_: any, record: API.CloudAccount) => {
                                                        const ossReady = !!(record.oss_bucket && record.oss_endpoint);
                                                        return ossReady
                                                            ? <Tag color="blue">OSS 内网高速分发</Tag>
                                                            : <Tag color="orange">Server HTTP Fallback</Tag>;
                                                    }
                                                },
                                                {
                                                    title: '操作', key: 'actions', width: 260,
                                                    render: (_: any, record: API.CloudAccount) => (
                                                        <Space>
                                                            <Button
                                                                type="primary"
                                                                size="small"
                                                                icon={<CloudUploadOutlined />}
                                                                disabled={!record.oss_bucket || !record.oss_endpoint}
                                                                onClick={async () => {
                                                                    setAgentUploadAccountId(record.id);
                                                                    setAgentUploadMode('服务器端制品');
                                                                    setSelectedReleaseFiles([]);
                                                                    setLocalFiles([]);
                                                                    setLocalUploadProgress(0);
                                                                    setAgentUploadOpen(true);
                                                                    // 预加载服务器端文件列表
                                                                    setReleaseFilesLoading(true);
                                                                    try {
                                                                        const res = await listReleaseFiles(record.id);
                                                                        setReleaseFiles(res.files || []);
                                                                    } catch {
                                                                        setReleaseFiles([]);
                                                                    } finally {
                                                                        setReleaseFilesLoading(false);
                                                                    }
                                                                }}
                                                            >上传 Agent</Button>
                                                            <Button
                                                                size="small"
                                                                icon={<PlayCircleOutlined />}
                                                                disabled={!record.oss_bucket || !record.oss_endpoint}
                                                                onClick={async () => {
                                                                    setOssTestLoading(true);
                                                                    setOssTestResult(null);
                                                                    setOssTestModalOpen(true);
                                                                    try {
                                                                        const res = await testOSSConnection(record.id);
                                                                        setOssTestResult(res);
                                                                    } catch (err: any) {
                                                                        setOssTestResult({
                                                                            status: 'error',
                                                                            connection: false,
                                                                            connection_err: extractErrorMsg(err) || String(err),
                                                                            bucket: record.oss_bucket,
                                                                            endpoint: record.oss_endpoint,
                                                                        });
                                                                    } finally {
                                                                        setOssTestLoading(false);
                                                                    }
                                                                }}
                                                            >OSS 测试</Button>
                                                        </Space>
                                                    )
                                                }
                                            ]}
                                        />
                                    )}

                                    {/* OSS 文件浏览器 */}
                                    {accounts.filter(a => a.oss_bucket && a.oss_endpoint).length > 0 && (
                                        <div style={{ marginTop: 24 }}>
                                            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
                                                <InboxOutlined style={{ color: '#0ea5e9', fontSize: 16 }} />
                                                <Text strong style={{ fontSize: 15 }}>OSS 制品浏览器</Text>
                                                <Text type="secondary" style={{ fontSize: 12 }}>查看已上传到 OSS 的 Agent 文件</Text>
                                            </div>
                                            {accounts.filter(a => a.oss_bucket && a.oss_endpoint).map(account => (
                                                <OSSFileBrowser key={account.id} account={account} />
                                            ))}
                                        </div>
                                    )}
                                </div>
                            ),
                        }
                    ]}
                />
            </ProCard>

            <Modal
                title={<><ThunderboltOutlined style={{ marginRight: 8, color: '#f59e0b' }} />手动弹性扩容</>}
                open={instanceModalOpen}
                onOk={handleCreateInstance}
                onCancel={() => setInstanceModalOpen(false)}
                okText="确认创建"
                cancelText="取消"
                width={640}
                okButtonProps={{ disabled: accounts.length === 0 }}
            >
                <Form form={instanceForm} layout="vertical" style={{ marginTop: 8 }} initialValues={{ count: 1 }}>
                    <Alert
                        message="手动扩容将绕过 AutoScaler 冷却限制，直接向云厂商发起实例创建请求"
                        description="实例创建后将自动注入 Cloud-Init 脚本，下载并启动 Agent。请确保凭证已正确配置硬件规格和网络参数。"
                        type="warning"
                        showIcon
                        style={{ marginBottom: 16 }}
                    />

                    {accounts.length === 0 ? (
                        <Alert message="暂无可用云凭证，请先在「API 凭证管理」中添加并配置凭证。" type="info" showIcon style={{ marginBottom: 16 }} />
                    ) : (
                        <>
                            <Row gutter={16}>
                                <Col span={16}>
                                    <Form.Item name="account_id" label="云凭证" rules={[{ required: true, message: '请选择云凭证' }]}>
                                        <Select
                                            placeholder="选择调用凭证"
                                            options={accounts.map(a => {
                                                const ready = !!(a.region && a.default_instance_type && a.default_image_id);
                                                return {
                                                    value: a.id,
                                                    label: (
                                                        <Space>
                                                            <span>{a.name}</span>
                                                            {ready
                                                                ? <Tag color="success" style={{ fontSize: 10, lineHeight: '16px' }}>配置就绪</Tag>
                                                                : <Tag color="warning" style={{ fontSize: 10, lineHeight: '16px' }}>配置不完整</Tag>}
                                                        </Space>
                                                    ),
                                                };
                                            })}
                                            onChange={(val) => {
                                                instanceForm.validateFields(['account_id']);
                                                if (val) {
                                                    const acct = accounts.find(a => a.id === val);
                                                    const defaultRegion = acct?.region || '';
                                                    setModalRegion(defaultRegion);
                                                    // 加载地域列表
                                                    setModalRegionsLoading(true);
                                                    listCloudRegions(val).then(res => {
                                                        setModalRegions(res?.regions || []);
                                                    }).catch(() => {}).finally(() => setModalRegionsLoading(false));
                                                    // 加载规格+价格
                                                    if (defaultRegion) {
                                                        refreshModalData(val, defaultRegion);
                                                    }
                                                } else {
                                                    setPriceData(null);
                                                    setAvailableTypes([]);
                                                    setSelectedInstanceType('');
                                                    setModalRegion('');
                                                    setModalRegions([]);
                                                }
                                            }}
                                        />
                                    </Form.Item>
                                </Col>
                                <Col span={8}>
                                    <Form.Item name="count" label="创建数量" rules={[{ required: true, message: '请输入数量' }]}>
                                        <InputNumber min={1} max={10} style={{ width: '100%' }} addonAfter="台" />
                                    </Form.Item>
                                </Col>
                            </Row>

                            {/* 地域选择 */}
                            {instanceForm.getFieldValue('account_id') && (
                                <Form.Item label="地域" style={{ marginBottom: 12 }}>
                                    <Select
                                        loading={modalRegionsLoading}
                                        value={modalRegion || undefined}
                                        placeholder="选择目标地域"
                                        showSearch
                                        optionFilterProp="label"
                                        onChange={(val) => {
                                            setModalRegion(val);
                                            const acctId = instanceForm.getFieldValue('account_id');
                                            if (acctId && val) {
                                                refreshModalData(acctId, val);
                                            }
                                        }}
                                        options={modalRegions.map(r => ({
                                            value: r.region_id,
                                            label: `${r.region_id}  ${r.local_name ? '(' + r.local_name + ')' : ''}`,
                                        }))}
                                        style={{ width: '100%' }}
                                    />
                                </Form.Item>
                            )}

                            {/* 动态展示选中凭证的参数 */}
                            <Form.Item noStyle shouldUpdate={(prev, cur) => prev.account_id !== cur.account_id || prev.count !== cur.count}>
                                {({ getFieldValue }) => {
                                    const accountId = getFieldValue('account_id');
                                    const count = getFieldValue('count') || 1;
                                    const account = accounts.find(a => a.id === accountId);
                                    if (!account) return null;

                                    const configReady = !!(account.region && account.default_instance_type && account.default_image_id);
                                    const ossReady = !!(account.oss_bucket && account.oss_endpoint);

                                    // 找到关联策略
                                    const linkedPolicy = policies.find((p: any) => p.cloud_account_id === accountId);

                                    return (
                                        <div style={{
                                            background: '#f8fafc',
                                            borderRadius: 10,
                                            padding: '16px 20px',
                                            border: '1px solid #e2e8f0',
                                        }}>
                                            <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
                                                <SettingOutlined style={{ color: '#0ea5e9' }} />
                                                实例创建参数预览
                                                {!configReady && (
                                                    <Tag color="error" style={{ fontSize: 10 }}>配置不完整，请先完成一键配置</Tag>
                                                )}
                                            </div>

                                            <Descriptions size="small" column={2} bordered
                                                labelStyle={{ width: 100, fontWeight: 500, background: '#fff', fontSize: 12 }}
                                                contentStyle={{ fontSize: 12, fontFamily: 'monospace' }}
                                            >
                                                <Descriptions.Item label="地域">
                                                    {modalRegion
                                                        ? <Tag color="green">{modalRegion}</Tag>
                                                        : <Tag color="red">未选择</Tag>}
                                                </Descriptions.Item>
                                                <Descriptions.Item label="提供商">
                                                    <Tag color="blue">{account.provider === 'aliyun' ? '阿里云 ECS' : account.provider === 'aws' ? 'AWS EC2' : account.provider}</Tag>
                                                </Descriptions.Item>
                                                <Descriptions.Item label="实例规格" span={2}>
                                                    {typesLoading ? (
                                                        <Spin size="small" />
                                                    ) : availableTypes.length > 0 ? (
                                                        <Select
                                                            size="small"
                                                            style={{ width: '100%' }}
                                                            value={selectedInstanceType}
                                                            onChange={(val) => {
                                                                setSelectedInstanceType(val);
                                                                // 重新查询该规格的价格
                                                                const acctId = instanceForm.getFieldValue('account_id');
                                                                if (acctId && val) {
                                                                    setPriceLoading(true);
                                                                    const seq = ++priceAbortRef.current;
                                                                    queryCloudPrice(acctId, { instance_type: val, region: modalRegion }).then(res => {
                                                                        if (seq === priceAbortRef.current && res?.status !== 'error') setPriceData(res);
                                                                    }).catch(() => {}).finally(() => {
                                                                        if (seq === priceAbortRef.current) setPriceLoading(false);
                                                                    });
                                                                }
                                                            }}
                                                            showSearch
                                                            optionFilterProp="label"
                                                            options={availableTypes.map(t => ({
                                                                value: t.id,
                                                                label: `${t.id}  (${t.cpu}核 / ${t.memory_gb}G)${t.status === 'ClosedWithStock' ? ' · 限量' : ''}`,
                                                            }))}
                                                            optionRender={(option) => {
                                                                const t = availableTypes.find(x => x.id === option.value);
                                                                return (
                                                                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                                                        <span style={{ fontFamily: 'monospace', fontSize: 12 }}>{t?.id}</span>
                                                                        <span style={{ fontSize: 11, color: '#64748b' }}>
                                                                            {t?.cpu}核 / {t?.memory_gb}G
                                                                            {t?.status === 'ClosedWithStock' && <Tag color="orange" style={{ marginLeft: 4, fontSize: 10 }}>限量</Tag>}
                                                                        </span>
                                                                    </div>
                                                                );
                                                            }}
                                                        />
                                                    ) : (
                                                        <Text style={{ fontSize: 12 }}>
                                                            {account.default_instance_type || <Tag color="red">未配置</Tag>}
                                                        </Text>
                                                    )}
                                                </Descriptions.Item>
                                                <Descriptions.Item label="系统镜像">
                                                    {account.default_image_id
                                                        ? <Text style={{ fontSize: 12 }}>{account.default_image_id.length > 20 ? account.default_image_id.slice(0, 20) + '...' : account.default_image_id}</Text>
                                                        : <Tag color="red">未配置</Tag>}
                                                </Descriptions.Item>
                                                <Descriptions.Item label="安全组">
                                                    {account.default_security_group
                                                        ? <Text style={{ fontSize: 12 }}>{account.default_security_group}</Text>
                                                        : <Tag color="orange">未配置</Tag>}
                                                </Descriptions.Item>
                                                <Descriptions.Item label="交换机">
                                                    {account.default_v_switch
                                                        ? <Text style={{ fontSize: 12 }}>{account.default_v_switch}</Text>
                                                        : <Tag color="orange">未配置</Tag>}
                                                </Descriptions.Item>
                                            </Descriptions>

                                            {/* 费用与策略预估 */}
                                            <div style={{
                                                marginTop: 12,
                                                display: 'flex',
                                                gap: 12,
                                                flexWrap: 'wrap',
                                            }}>
                                                {/* 单价卡片 */}
                                                <div style={{
                                                    flex: 1,
                                                    minWidth: 160,
                                                    background: priceData ? 'linear-gradient(135deg, #f0fdf4 0%, #ecfdf5 100%)' : '#fff',
                                                    borderRadius: 8,
                                                    padding: '12px 16px',
                                                    border: '1px solid #e2e8f0',
                                                }}>
                                                    <div style={{ fontSize: 11, color: '#64748b', marginBottom: 4 }}>单台小时价</div>
                                                    {priceLoading ? (
                                                        <Spin size="small" />
                                                    ) : priceData ? (
                                                        <div>
                                                            <div style={{ fontSize: 20, fontWeight: 700, color: '#059669' }}>
                                                                ¥{(priceData.spot_price > 0 ? priceData.spot_price : priceData.total_hourly).toFixed(3)}
                                                                <span style={{ fontSize: 11, fontWeight: 400, color: '#94a3b8' }}>/h</span>
                                                            </div>
                                                            {priceData.spot_price > 0 && priceData.spot_discount > 0 && (
                                                                <div style={{ fontSize: 11, color: '#f59e0b', marginTop: 2 }}>
                                                                    原价 ¥{priceData.instance_price.toFixed(3)}/h · 节省 {priceData.spot_discount.toFixed(0)}%
                                                                </div>
                                                            )}
                                                        </div>
                                                    ) : (
                                                        <div style={{ fontSize: 13, color: '#94a3b8' }}>选择凭证后加载</div>
                                                    )}
                                                </div>

                                                {/* 总费用预估 */}
                                                <div style={{
                                                    flex: 1,
                                                    minWidth: 160,
                                                    background: priceData ? 'linear-gradient(135deg, #eff6ff 0%, #eef2ff 100%)' : '#fff',
                                                    borderRadius: 8,
                                                    padding: '12px 16px',
                                                    border: '1px solid #e2e8f0',
                                                }}>
                                                    <div style={{ fontSize: 11, color: '#64748b', marginBottom: 4 }}>
                                                        {count} 台 · {linkedPolicy ? `${linkedPolicy.instance_ttl_minutes} 分钟` : '1 小时'} 预估
                                                    </div>
                                                    {priceLoading ? (
                                                        <Spin size="small" />
                                                    ) : priceData ? (
                                                        <div style={{ fontSize: 20, fontWeight: 700, color: '#2563eb' }}>
                                                            ¥{((priceData.spot_price > 0 ? priceData.spot_price : priceData.total_hourly) * count * (linkedPolicy ? linkedPolicy.instance_ttl_minutes / 60 : 1)).toFixed(2)}
                                                        </div>
                                                    ) : (
                                                        <div style={{ fontSize: 13, color: '#94a3b8' }}>--</div>
                                                    )}
                                                </div>

                                                {/* 竞价策略 */}
                                                <div style={{
                                                    flex: 1,
                                                    minWidth: 160,
                                                    background: '#fff',
                                                    borderRadius: 8,
                                                    padding: '12px 16px',
                                                    border: '1px solid #e2e8f0',
                                                }}>
                                                    <div style={{ fontSize: 11, color: '#64748b', marginBottom: 4 }}>竞价策略</div>
                                                    <div style={{ fontSize: 14, fontWeight: 600 }}>
                                                        {linkedPolicy ? (
                                                            <Tag color={linkedPolicy.spot_strategy === 'SpotAsPriceGo' ? 'orange' : linkedPolicy.spot_strategy === 'SpotWithPriceLimit' ? 'volcano' : 'blue'}>
                                                                {linkedPolicy.spot_strategy === 'SpotAsPriceGo' ? '竞价（跟随市价）' :
                                                                 linkedPolicy.spot_strategy === 'SpotWithPriceLimit' ? `竞价限价 ¥${linkedPolicy.max_spot_price}/h` : '按量付费'}
                                                            </Tag>
                                                        ) : (
                                                            <Tag color="orange">抢占式（默认）</Tag>
                                                        )}
                                                    </div>
                                                </div>

                                                {/* Agent 分发 */}
                                                <div style={{
                                                    flex: 1,
                                                    minWidth: 160,
                                                    background: '#fff',
                                                    borderRadius: 8,
                                                    padding: '12px 16px',
                                                    border: '1px solid #e2e8f0',
                                                }}>
                                                    <div style={{ fontSize: 11, color: '#64748b', marginBottom: 4 }}>Agent 分发</div>
                                                    <div style={{ fontSize: 14, fontWeight: 600 }}>
                                                        {ossReady
                                                            ? <Tag color="success">OSS 内网高速</Tag>
                                                            : <Tag color="warning">HTTP Fallback</Tag>}
                                                    </div>
                                                </div>
                                            </div>

                                            {/* 实例 TTL 提示 */}
                                            {linkedPolicy && (
                                                <div style={{ marginTop: 10, padding: '6px 12px', background: '#eff6ff', borderRadius: 6, fontSize: 12, color: '#3b82f6' }}>
                                                    <CheckCircleOutlined style={{ marginRight: 4 }} />
                                                    实例将在 {linkedPolicy.instance_ttl_minutes} 分钟后自动释放（策略: {linkedPolicy.name}）
                                                </div>
                                            )}

                                            {!linkedPolicy && (
                                                <Alert
                                                    message="该凭证尚未绑定调度策略，创建实例可能失败。请先在「引擎调度 & 开关」中配置策略。"
                                                    type="error"
                                                    showIcon
                                                    style={{ marginTop: 10, fontSize: 12 }}
                                                />
                                            )}
                                        </div>
                                    );
                                }}
                            </Form.Item>
                        </>
                    )}
                </Form>
            </Modal>

            <Modal title="添加云服务凭证 (AK/SK)" open={akModalOpen} onOk={handleAddAk} onCancel={() => setAkModalOpen(false)}
                okText="安全保存" cancelText="取消">
                <Form form={akForm} layout="vertical" style={{ marginTop: 16 }}>
                    <Form.Item name="provider" label="提供商" initialValue="aliyun" rules={[{ required: true }]}>
                        <Select options={[
                            { value: 'aliyun', label: '阿里云 ECS' },
                            { value: 'aws', label: 'AWS EC2' },
                            { value: 'tencent', label: '腾讯云 CVM' },
                        ]} />
                    </Form.Item>
                    <Form.Item name="name" label="凭证别名" rules={[{ required: true }]}>
                        <Input placeholder="例如：阿里云生产环境主账号" />
                    </Form.Item>
                    <Form.Item name="access_key_id" label="Access Key ID" rules={[{ required: true }]}>
                        <Input placeholder="输入 AK" />
                    </Form.Item>
                    <Form.Item name="access_key_secret" label="Access Key Secret" rules={[{ required: true }]}>
                        <Input.Password placeholder="输入 SK" />
                    </Form.Item>

                    <Form.Item name="region" label="地域 (Region)" extra="可选，弹性扩缩时需要指定。不填则在一键配置时自动选择。">
                        <Input placeholder="可选，如 cn-shanghai、cn-hangzhou" />
                    </Form.Item>

                    <Form.Item label="默认云主机硬件配置" style={{ marginBottom: 4 }} extra="选填，如果留空将使用云厂商 API 的默认值">
                        <Input.Group compact style={{ display: 'flex', gap: 8 }}>
                            <Form.Item name="default_instance_type" noStyle>
                                <Input placeholder="实例规格 (如 ecs.c6.large)" style={{ flex: 1 }} />
                            </Form.Item>
                            <Form.Item name="default_image_id" noStyle>
                                <Input placeholder="系统镜像 ID (如 ubuntu_22_04)" style={{ flex: 1 }} />
                            </Form.Item>
                        </Input.Group>
                    </Form.Item>

                    <Form.Item label="网络与安全配置" style={{ marginBottom: 4 }}>
                        <Input.Group compact style={{ display: 'flex', gap: 8 }}>
                            <Form.Item name="default_security_group" noStyle>
                                <Input placeholder="安全组 ID" style={{ flex: 1 }} />
                            </Form.Item>
                            <Form.Item name="default_v_switch" noStyle>
                                <Input placeholder="虚拟交换机 ID" style={{ flex: 1 }} />
                            </Form.Item>
                        </Input.Group>
                    </Form.Item>
                    <Form.Item label="OSS 配置（可选，用于 Agent 二进制分发）" style={{ marginBottom: 4 }}>
                        <Input.Group compact style={{ display: 'flex', gap: 8 }}>
                            <Form.Item name="oss_bucket" noStyle>
                                <Input placeholder="Bucket 名称，如 argus-release" style={{ flex: 1 }} />
                            </Form.Item>
                            <Form.Item name="oss_endpoint" noStyle>
                                <Input placeholder="Endpoint，如 oss-cn-shanghai-internal.aliyuncs.com" style={{ flex: 2 }} />
                            </Form.Item>
                        </Input.Group>
                    </Form.Item>
                </Form>
            </Modal>

            {/* 资源自动探测弹窗 */}
            <Modal
                title={<><SearchOutlined /> 云资源自动探测</>}
                open={discoverModalOpen}
                onCancel={() => setDiscoverModalOpen(false)}
                footer={discoveryData ? [
                    <Button key="cancel" onClick={() => setDiscoverModalOpen(false)}>取消</Button>,
                    <Button key="save" type="primary" loading={discoverSaving} onClick={handleSaveDiscovery} icon={<CheckCircleOutlined />}>
                        保存配置
                    </Button>,
                ] : null}
                width={720}
                destroyOnClose
            >
                {discovering ? (
                    <div style={{ textAlign: 'center', padding: '60px 0' }}>
                        <Spin size="large" />
                        <div style={{ marginTop: 16 }}><Text type="secondary">正在通过 AK/SK 查询云资源...</Text></div>
                    </div>
                ) : discoveryData ? (
                    <Form form={discoverForm} layout="vertical">
                        <Alert
                            message="以下资源已通过你的 AK/SK 从云厂商 API 自动获取，请在每一项中选择合适的值后保存。"
                            type="info" showIcon style={{ marginBottom: 20 }}
                        />
                        <Form.Item name="default_instance_type" label={`实例规格 (发现 ${discoveryData.instance_types?.length || 0} 个)`}
                            rules={[{ required: true, message: '请选择实例规格' }]}>
                            <Select placeholder="选择实例规格" showSearch optionFilterProp="label"
                                options={(discoveryData.instance_types || []).map((it: any) => ({
                                    value: it.id,
                                    label: `${it.id}  —  ${it.cpu}核 ${it.memory_gb}GB  (${it.family})`,
                                }))}
                            />
                        </Form.Item>
                        <Form.Item name="default_image_id" label={`系统镜像 (发现 ${discoveryData.images?.length || 0} 个)`}
                            rules={[{ required: true, message: '请选择系统镜像' }]}>
                            <Select placeholder="选择系统镜像" showSearch optionFilterProp="label"
                                options={(discoveryData.images || []).map((img: any) => ({
                                    value: img.id,
                                    label: `${img.name}  —  ${img.desc}`,
                                }))}
                            />
                        </Form.Item>
                        <Form.Item name="default_security_group" label={`安全组 (发现 ${discoveryData.security_groups?.length || 0} 个)`}
                            rules={[{ required: true, message: '请选择安全组' }]}>
                            <Select placeholder="选择安全组" showSearch optionFilterProp="label"
                                options={(discoveryData.security_groups || []).map((sg: any) => ({
                                    value: sg.id,
                                    label: `${sg.id}  —  ${sg.name || '(无名称)'}  ${sg.desc}`,
                                }))}
                            />
                        </Form.Item>
                        <Form.Item name="default_v_switch" label={`虚拟交换机 (发现 ${discoveryData.v_switches?.length || 0} 个)`}
                            rules={[{ required: true, message: '请选择交换机' }]}>
                            <Select placeholder="选择交换机" showSearch optionFilterProp="label"
                                options={(discoveryData.v_switches || []).map((vsw: any) => ({
                                    value: vsw.id,
                                    label: `${vsw.id}  —  ${vsw.name || '(无名称)'}  ${vsw.desc}`,
                                }))}
                            />
                        </Form.Item>
                    </Form>
                ) : (
                    <div style={{ textAlign: 'center', padding: '40px 0', color: '#94a3b8' }}>
                        <Text type="secondary">探测失败，请检查 AK/SK 权限是否包含 ECS 读取权限。</Text>
                    </div>
                )}
            </Modal>

            {/* 一键配置结果弹窗 */}
            <Modal
                title={<><ThunderboltOutlined style={{ color: '#0ea5e9' }} /> 一键配置结果</>}
                open={setupResultOpen}
                onCancel={() => setSetupResultOpen(false)}
                footer={[<Button key="ok" type="primary" onClick={() => setSetupResultOpen(false)}>知道了</Button>]}
                width={640}
            >
                {setupResult && (
                    <div>
                        {/* 警告信息 */}
                        {setupResult.warnings && setupResult.warnings.length > 0 && (
                            <Alert
                                type="warning" showIcon
                                style={{ marginBottom: 16 }}
                                message="部分资源发现失败"
                                description={
                                    <ul style={{ margin: 0, paddingLeft: 16 }}>
                                        {setupResult.warnings.map((w: string, i: number) => (
                                            <li key={i} style={{ marginBottom: 4 }}>{w}</li>
                                        ))}
                                    </ul>
                                }
                            />
                        )}

                        {/* 策略信息 */}
                        {setupResult.policy_created && (
                            <Alert type="success" showIcon message="已自动创建调度策略（默认关闭），请在「引擎调度 & 开关」标签页中查看和启用。" style={{ marginBottom: 16 }} />
                        )}

                        {/* 当前配置 */}
                        <Descriptions title="当前凭证配置" bordered size="small" column={1}
                            labelStyle={{ width: 120, fontWeight: 500, background: '#f8fafc' }}
                            contentStyle={{ fontFamily: 'monospace', fontSize: 13 }}
                        >
                            <Descriptions.Item label="地域">
                                {setupResult.current_config?.region ?
                                    <Tag color="green">{setupResult.current_config.region}</Tag> :
                                    <Tag color="red">未配置</Tag>}
                            </Descriptions.Item>
                            <Descriptions.Item label="实例规格">
                                {setupResult.current_config?.instance_type ?
                                    <><Tag color="blue">{setupResult.current_config.instance_type}</Tag>
                                        {setupResult.chosen?.instance_type && <Tag color="cyan">本次更新</Tag>}</> :
                                    <Tag color="red">未配置</Tag>}
                            </Descriptions.Item>
                            <Descriptions.Item label="系统镜像">
                                {setupResult.current_config?.image_id ?
                                    <><Text code style={{ fontSize: 12 }}>{setupResult.current_config.image_id}</Text>
                                        {setupResult.chosen?.image_name && <Text type="secondary" style={{ marginLeft: 8, fontSize: 11 }}>({setupResult.chosen.image_name})</Text>}
                                        {setupResult.chosen?.image_id && <Tag color="cyan" style={{ marginLeft: 4 }}>本次更新</Tag>}</> :
                                    <Tag color="red">未配置</Tag>}
                            </Descriptions.Item>
                            <Descriptions.Item label="安全组">
                                {setupResult.current_config?.security_group ?
                                    <><Text code style={{ fontSize: 12 }}>{setupResult.current_config.security_group}</Text>
                                        {setupResult.chosen?.security_group && <Tag color="cyan" style={{ marginLeft: 4 }}>本次更新</Tag>}</> :
                                    <Tag color="red">未配置 — 需在阿里云控制台创建安全组</Tag>}
                            </Descriptions.Item>
                            <Descriptions.Item label="交换机">
                                {setupResult.current_config?.v_switch ?
                                    <><Text code style={{ fontSize: 12 }}>{setupResult.current_config.v_switch}</Text>
                                        {setupResult.chosen?.v_switch && <Tag color="cyan" style={{ marginLeft: 4 }}>本次更新</Tag>}</> :
                                    <Tag color="red">未配置 — 需在阿里云控制台创建 VPC 和交换机</Tag>}
                            </Descriptions.Item>
                            <Descriptions.Item label="OSS 存储桶">
                                {setupResult.current_config?.oss_bucket ?
                                    <><Text code style={{ fontSize: 12 }}>{setupResult.current_config.oss_bucket}</Text>
                                        {setupResult.chosen?.oss_bucket && <Tag color="cyan" style={{ marginLeft: 4 }}>自动创建</Tag>}</> :
                                    <Tag color="red">未配置</Tag>}
                            </Descriptions.Item>
                            <Descriptions.Item label="OSS 访问节点">
                                {setupResult.current_config?.oss_endpoint ?
                                    <><Text code style={{ fontSize: 12 }}>{setupResult.current_config.oss_endpoint}</Text>
                                        {setupResult.chosen?.oss_endpoint && <Tag color="cyan" style={{ marginLeft: 4 }}>自动配置</Tag>}</> :
                                    <Tag color="red">未配置</Tag>}
                            </Descriptions.Item>
                        </Descriptions>

                        {/* 发现统计 */}
                        <div style={{ marginTop: 16, padding: '8px 12px', background: '#f1f5f9', borderRadius: 6, fontSize: 12, color: '#64748b' }}>
                            资源发现统计：实例规格 {setupResult.discovery?.instance_types || 0} 个 | 镜像 {setupResult.discovery?.images || 0} 个 | 安全组 {setupResult.discovery?.security_groups || 0} 个 | 交换机 {setupResult.discovery?.v_switches || 0} 个
                        </div>
                    </div>
                )}
            </Modal>

            {/* 权限检查 Drawer */}
            <Drawer
                title={<span><SafetyCertificateOutlined style={{ marginRight: 8, color: '#8b5cf6' }} />AK/SK 权限检查</span>}
                open={permDrawerOpen}
                onClose={() => setPermDrawerOpen(false)}
                width={720}
                destroyOnClose
            >
                {permLoading ? (
                    <div style={{ textAlign: 'center', padding: '80px 0' }}>
                        <Spin size="large" />
                        <div style={{ marginTop: 16 }}><Text type="secondary">正在通过 STS/RAM API 检查凭证权限...</Text></div>
                        <div style={{ marginTop: 8, fontSize: 12, color: '#94a3b8' }}>首次检查可能需要 10-20 秒</div>
                    </div>
                ) : permError ? (
                    <Alert
                        type="error" showIcon
                        message="权限检查失败"
                        description={<>
                            <div style={{ marginBottom: 8 }}>{permError}</div>
                            <Text type="secondary" style={{ fontSize: 12 }}>可能原因：AK/SK 无效、网络不通、或缺少 sts:GetCallerIdentity / ram:ListPoliciesForUser 权限。</Text>
                        </>}
                    />
                ) : permData ? (
                    <div>
                        {/* 一键配置就绪状态 */}
                        <Alert
                            type={permData.can_one_click_setup ? 'success' : 'warning'}
                            showIcon
                            icon={permData.can_one_click_setup ? <CheckCircleOutlined /> : <CloseOutlined />}
                            message={permData.can_one_click_setup
                                ? '权限充足，可以执行一键配置'
                                : `缺少 ${permData.missing_permissions?.length || 0} 项权限，无法完成一键配置`}
                            description={!permData.can_one_click_setup && permData.missing_permissions?.length > 0 && (
                                <div style={{ marginTop: 8 }}>
                                    <Text type="secondary">缺失权限：</Text>
                                    <div style={{ marginTop: 4, display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                                        {permData.missing_permissions.map((p: string) => (
                                            <Tag key={p} color="error" style={{ fontSize: 11 }}>{p}</Tag>
                                        ))}
                                    </div>
                                </div>
                            )}
                            style={{ marginBottom: 20 }}
                        />

                        {/* 身份信息卡片 */}
                        <div style={{
                            background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                            borderRadius: 12,
                            padding: '20px 24px',
                            marginBottom: 20,
                            color: '#fff',
                        }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 12 }}>
                                <UserOutlined style={{ fontSize: 24 }} />
                                <div>
                                    <div style={{ fontWeight: 600, fontSize: 16 }}>
                                        {permData.identity_type === 'Root' ? '主账号 (Root)' :
                                         permData.identity_type === 'RAMUser' ? `RAM 用户: ${permData.user_name}` :
                                         permData.identity_type === 'RAMRole' ? `RAM 角色: ${permData.user_name}` :
                                         `STS 临时凭证: ${permData.user_name || '未知'}`}
                                    </div>
                                    <div style={{ opacity: 0.8, fontSize: 12, marginTop: 2 }}>
                                        Account ID: {permData.account_id}
                                    </div>
                                </div>
                            </div>
                            <div style={{ fontSize: 11, opacity: 0.7, fontFamily: 'monospace', wordBreak: 'break-all' }}>
                                ARN: {permData.identity_arn}
                            </div>
                        </div>

                        {/* 绑定策略列表 */}
                        <div style={{ marginBottom: 20 }}>
                            <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
                                <LockOutlined style={{ color: '#8b5cf6' }} />
                                绑定的权限策略 ({permData.policies?.length || 0})
                            </div>
                            {permData.policies?.length > 0 ? (
                                <Table
                                    size="small"
                                    dataSource={permData.policies}
                                    rowKey={(r: any) => `${r.policy_name}-${r.attach_source}`}
                                    pagination={false}
                                    columns={[
                                        {
                                            title: '策略名称', dataIndex: 'policy_name', key: 'policy_name',
                                            render: (name: string) => <Text strong style={{ fontSize: 12, fontFamily: 'monospace' }}>{name}</Text>
                                        },
                                        {
                                            title: '类型', dataIndex: 'policy_type', key: 'policy_type', width: 80,
                                            render: (type: string) => <Tag color={type === 'System' ? 'blue' : 'orange'}>{type === 'System' ? '系统' : '自定义'}</Tag>
                                        },
                                        {
                                            title: '来源', dataIndex: 'attach_source', key: 'attach_source', width: 120,
                                            render: (src: string) => {
                                                if (src === 'User') return <Tag color="green">用户直绑</Tag>;
                                                if (src === 'Role') return <Tag color="purple">角色绑定</Tag>;
                                                if (src === 'RootAccount') return <Tag color="gold">主账号</Tag>;
                                                if (src?.startsWith('Group:')) return <Tag color="cyan">组: {src.slice(6)}</Tag>;
                                                return <Tag>{src}</Tag>;
                                            }
                                        },
                                        {
                                            title: '描述', dataIndex: 'description', key: 'description',
                                            render: (desc: string) => <Text type="secondary" style={{ fontSize: 11 }}>{desc || '-'}</Text>
                                        },
                                    ]}
                                    expandable={{
                                        expandedRowRender: (record: any) => record.policy_document ? (
                                            <pre style={{
                                                background: '#1e1e1e', color: '#d4d4d4',
                                                padding: 16, borderRadius: 8,
                                                fontSize: 11, maxHeight: 300, overflow: 'auto',
                                                margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all'
                                            }}>
                                                {(() => { try { return JSON.stringify(JSON.parse(record.policy_document), null, 2); } catch { return record.policy_document; } })()}
                                            </pre>
                                        ) : <Text type="secondary">系统策略不展示 Policy Document</Text>,
                                        rowExpandable: () => true,
                                    }}
                                />
                            ) : (
                                <Empty description="未查询到绑定的权限策略" image={Empty.PRESENTED_IMAGE_SIMPLE} />
                            )}
                        </div>

                        {/* 所需权限比对表 */}
                        <div>
                            <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
                                <SafetyCertificateOutlined style={{ color: '#0ea5e9' }} />
                                一键配置所需权限检查 ({permData.required_permissions?.filter((p: any) => p.satisfied).length || 0}/{permData.required_permissions?.length || 0})
                            </div>
                            <Collapse
                                defaultActiveKey={['ECS', 'VPC', 'OSS']}
                                style={{ background: '#fafafa' }}
                                items={['ECS', 'VPC', 'OSS'].map(category => {
                                    const items = (permData.required_permissions || []).filter((p: any) => p.category === category);
                                    const satisfiedCount = items.filter((p: any) => p.satisfied).length;
                                    const allSatisfied = satisfiedCount === items.length;
                                    return {
                                        key: category,
                                        label: (
                                            <Space>
                                                <Tag color={allSatisfied ? 'success' : 'error'} style={{ fontWeight: 600 }}>
                                                    {category}
                                                </Tag>
                                                <Text type={allSatisfied ? undefined : 'danger'} style={{ fontSize: 13 }}>
                                                    {satisfiedCount}/{items.length} 项已授权
                                                </Text>
                                                {allSatisfied && <CheckOutlined style={{ color: '#10b981', fontSize: 12 }} />}
                                            </Space>
                                        ),
                                        children: (
                                            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                                                {items.map((perm: any) => (
                                                    <div key={perm.action_pattern} style={{
                                                        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                                                        padding: '8px 12px', background: '#fff', borderRadius: 6,
                                                        border: `1px solid ${perm.satisfied ? '#d1fae5' : '#fecaca'}`,
                                                    }}>
                                                        <div>
                                                            <Text style={{ fontFamily: 'monospace', fontSize: 12, fontWeight: 500 }}>
                                                                {perm.action_pattern}
                                                            </Text>
                                                            <br />
                                                            <Text type="secondary" style={{ fontSize: 11 }}>{perm.description}</Text>
                                                        </div>
                                                        {perm.satisfied
                                                            ? <Tag icon={<CheckOutlined />} color="success">已授权</Tag>
                                                            : <Tag icon={<CloseOutlined />} color="error">未授权</Tag>
                                                        }
                                                    </div>
                                                ))}
                                            </div>
                                        ),
                                    };
                                })}
                            />

                            {/* 快速复制最小权限策略 */}
                            {!permData.can_one_click_setup && (
                                <div style={{ marginTop: 20 }}>
                                    <Alert
                                        type="info" showIcon
                                        message="快速修复"
                                        description={
                                            <div>
                                                <div style={{ marginBottom: 8 }}>在阿里云 RAM 控制台创建自定义策略，粘贴以下 JSON 即可授予一键配置所需的最小权限：</div>
                                                <Tooltip title="点击复制最小权限策略 JSON">
                                                    <Button
                                                        size="small"
                                                        icon={<CopyOutlined />}
                                                        onClick={() => {
                                                            const actions = (permData.required_permissions || []).map((p: any) => p.action_pattern);
                                                            const ecsActions = actions.filter((a: string) => a.startsWith('ecs:'));
                                                            const ossActions = actions.filter((a: string) => a.startsWith('oss:'));
                                                            const policy = JSON.stringify({
                                                                Version: '1',
                                                                Statement: [
                                                                    { Effect: 'Allow', Action: ecsActions, Resource: '*' },
                                                                    { Effect: 'Allow', Action: ossActions, Resource: '*' },
                                                                ],
                                                            }, null, 2);
                                                            navigator.clipboard.writeText(policy);
                                                            message.success('最小权限策略 JSON 已复制到剪贴板');
                                                        }}
                                                    >
                                                        复制最小权限策略 JSON
                                                    </Button>
                                                </Tooltip>
                                            </div>
                                        }
                                    />
                                </div>
                            )}
                        </div>
                    </div>
                ) : null}
            </Drawer>

            {/* OSS 测试结果 Modal */}
            <Modal
                title={<><PlayCircleOutlined style={{ marginRight: 8, color: '#8b5cf6' }} />OSS 连通性测试报告</>}
                open={ossTestModalOpen}
                onCancel={() => setOssTestModalOpen(false)}
                footer={[<Button key="ok" type="primary" onClick={() => setOssTestModalOpen(false)}>知道了</Button>]}
                width={600}
            >
                {ossTestLoading ? (
                    <div style={{ textAlign: 'center', padding: '40px 0' }}>
                        <Spin size="large" />
                        <div style={{ marginTop: 16 }}><Text type="secondary">正在测试 OSS 连通性...</Text></div>
                    </div>
                ) : ossTestResult ? (
                    <div>
                        {/* 总体结果 */}
                        <Alert
                            type={ossTestResult.connection ? 'success' : 'error'}
                            showIcon
                            message={ossTestResult.connection ? 'OSS 连通性测试通过' : 'OSS 连接失败'}
                            description={ossTestResult.connection_err || undefined}
                            style={{ marginBottom: 20 }}
                        />

                        {/* 详细信息 */}
                        <Descriptions bordered size="small" column={1}
                            labelStyle={{ width: 130, fontWeight: 500, background: '#f8fafc' }}
                            contentStyle={{ fontFamily: 'monospace', fontSize: 13 }}
                        >
                            <Descriptions.Item label="Bucket">
                                <Text copyable style={{ fontSize: 13 }}>{ossTestResult.bucket || '-'}</Text>
                            </Descriptions.Item>
                            <Descriptions.Item label="Endpoint">
                                <Text copyable style={{ fontSize: 13 }}>{ossTestResult.endpoint || '-'}</Text>
                            </Descriptions.Item>
                            <Descriptions.Item label="连接状态">
                                {ossTestResult.connection
                                    ? <Tag icon={<CheckCircleOutlined />} color="success">已连通</Tag>
                                    : <Tag icon={<CloseOutlined />} color="error">连接失败</Tag>}
                            </Descriptions.Item>
                            {ossTestResult.connection && (
                                <>
                                    <Descriptions.Item label="Agent 文件数">
                                        <Badge
                                            count={ossTestResult.file_count || 0}
                                            showZero
                                            style={{ backgroundColor: ossTestResult.file_count > 0 ? '#10b981' : '#94a3b8' }}
                                        />
                                        <Text type="secondary" style={{ marginLeft: 8, fontSize: 12 }}>
                                            (共 {((ossTestResult.total_size || 0) / 1024 / 1024).toFixed(1)} MB)
                                        </Text>
                                    </Descriptions.Item>
                                    <Descriptions.Item label="核心制品">
                                        {ossTestResult.agent_ready
                                            ? <><Tag color="success">已就绪</Tag><Text type="secondary" style={{ fontSize: 11 }}>{ossTestResult.required_agent}</Text></>
                                            : <><Tag color="warning">未上传</Tag><Text type="secondary" style={{ fontSize: 11 }}>需要上传 {ossTestResult.required_agent}</Text></>}
                                    </Descriptions.Item>
                                </>
                            )}
                        </Descriptions>

                        {/* 文件列表 */}
                        {ossTestResult.connection && ossTestResult.files?.length > 0 && (
                            <div style={{ marginTop: 16 }}>
                                <Text strong style={{ fontSize: 13, marginBottom: 8, display: 'block' }}>
                                    <FileOutlined style={{ marginRight: 4 }} />OSS 中的 Agent 文件
                                </Text>
                                {ossTestResult.files.map((f: any) => {
                                    const name = f.key?.split('/').pop() || f.key;
                                    const sizeMB = (f.size / 1024 / 1024).toFixed(1);
                                    const isRequired = f.key === ossTestResult.required_agent;
                                    return (
                                        <div key={f.key} style={{
                                            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                                            padding: '6px 12px', borderRadius: 4,
                                            background: isRequired ? '#f0fdf4' : '#f8fafc',
                                            border: isRequired ? '1px solid #bbf7d0' : '1px solid #f1f5f9',
                                            marginBottom: 4,
                                        }}>
                                            <Space>
                                                <FileOutlined style={{ color: isRequired ? '#10b981' : '#64748b' }} />
                                                <Text style={{ fontFamily: 'monospace', fontSize: 12 }}>{name}</Text>
                                                {isRequired && <Tag color="green" style={{ fontSize: 10 }}>核心制品</Tag>}
                                            </Space>
                                            <Text type="secondary" style={{ fontSize: 12 }}>{sizeMB} MB</Text>
                                        </div>
                                    );
                                })}
                            </div>
                        )}
                    </div>
                ) : null}
            </Modal>

            {/* Agent 上传 Modal */}
            <Modal
                title={<><CloudUploadOutlined style={{ marginRight: 8, color: '#0ea5e9' }} />上传 Agent 到 OSS</>}
                open={agentUploadOpen}
                onCancel={() => { setAgentUploadOpen(false); setLocalFiles([]); setLocalUploadProgress(0); }}
                footer={null}
                width={680}
                destroyOnClose
            >
                <Segmented
                    block
                    value={agentUploadMode}
                    onChange={(v) => {
                        setAgentUploadMode(v as string);
                        if (v === '服务器端制品' && releaseFiles.length === 0 && !releaseFilesLoading) {
                            setReleaseFilesLoading(true);
                            listReleaseFiles(agentUploadAccountId)
                                .then(res => setReleaseFiles(res.files || []))
                                .catch(() => setReleaseFiles([]))
                                .finally(() => setReleaseFilesLoading(false));
                        }
                    }}
                    options={[
                        { label: <span><CloudServerOutlined style={{ marginRight: 4 }} />服务器端制品</span>, value: '服务器端制品' },
                        { label: <span><UploadOutlined style={{ marginRight: 4 }} />本地上传</span>, value: '本地上传' },
                    ]}
                    style={{ marginBottom: 20 }}
                />

                {agentUploadMode === '服务器端制品' ? (
                    <div>
                        <Alert
                            message="选择服务器 ./release 目录下的 Agent 二进制文件上传到 OSS"
                            type="info"
                            showIcon
                            style={{ marginBottom: 16 }}
                        />
                        {releaseFilesLoading ? (
                            <div style={{ display: 'flex', justifyContent: 'center', padding: '40px 0' }}><Spin /></div>
                        ) : releaseFiles.length === 0 ? (
                            <Empty
                                image={Empty.PRESENTED_IMAGE_SIMPLE}
                                description={<span>服务器 <Text code>./release</Text> 目录为空或不存在<br /><Text type="secondary" style={{ fontSize: 12 }}>请先构建 Agent 二进制或切换到「本地上传」</Text></span>}
                                style={{ padding: '40px 0' }}
                            />
                        ) : (
                            <>
                                <Table
                                    dataSource={releaseFiles}
                                    rowKey="name"
                                    pagination={false}
                                    size="small"
                                    rowSelection={{
                                        selectedRowKeys: selectedReleaseFiles,
                                        onChange: (keys) => setSelectedReleaseFiles(keys as string[]),
                                    }}
                                    columns={[
                                        {
                                            title: '文件名', dataIndex: 'name', key: 'name',
                                            render: (name: string) => (
                                                <Space>
                                                    <FileOutlined style={{ color: '#64748b' }} />
                                                    <Text style={{ fontFamily: 'monospace', fontSize: 13 }}>{name}</Text>
                                                </Space>
                                            )
                                        },
                                        {
                                            title: '大小', dataIndex: 'size', key: 'size', width: 120,
                                            render: (size: number) => <Text type="secondary">{(size / 1024 / 1024).toFixed(1)} MB</Text>
                                        },
                                        {
                                            title: '修改时间', dataIndex: 'modified', key: 'modified', width: 180,
                                            render: (v: string) => <Text style={{ fontSize: 12, color: '#64748b' }}>{v ? new Date(v).toLocaleString('zh-CN') : '-'}</Text>
                                        },
                                    ]}
                                />
                                <div style={{ marginTop: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                    <Text type="secondary" style={{ fontSize: 12 }}>
                                        已选 {selectedReleaseFiles.length}/{releaseFiles.length} 个文件
                                    </Text>
                                    <Space>
                                        <Button onClick={() => setSelectedReleaseFiles(releaseFiles.map(f => f.name))}>全选</Button>
                                        <Button
                                            type="primary"
                                            icon={<CloudUploadOutlined />}
                                            disabled={selectedReleaseFiles.length === 0}
                                            loading={serverUploading}
                                            onClick={async () => {
                                                setServerUploading(true);
                                                try {
                                                    const res = await uploadServerAgent(agentUploadAccountId, selectedReleaseFiles);
                                                    if (res?.status === 'ok') {
                                                        message.success(res.message || '上传成功');
                                                        setAgentUploadOpen(false);
                                                    } else {
                                                        message.error(res?.message || '上传失败');
                                                    }
                                                } catch (err: any) {
                                                    const errMsg = extractErrorMsg(err) || String(err) || '未知错误';
                                                    message.error(`上传失败: ${errMsg}`);
                                                } finally {
                                                    setServerUploading(false);
                                                }
                                            }}
                                        >
                                            上传选中文件到 OSS
                                        </Button>
                                    </Space>
                                </div>
                            </>
                        )}
                    </div>
                ) : (
                    <div>
                        <Alert
                            message="从本地选择 Agent 二进制文件，上传到服务器并自动推送到 OSS"
                            type="info"
                            showIcon
                            style={{ marginBottom: 16 }}
                        />
                        <Upload.Dragger
                            multiple
                            beforeUpload={(file, fileList) => {
                                // 只在第一个文件触发时收集全部文件
                                if (file === fileList[0]) {
                                    setLocalFiles(prev => {
                                        const existNames = new Set(prev.map(f => f.name));
                                        const newFiles = fileList.filter(f => !existNames.has(f.name));
                                        return [...prev, ...newFiles];
                                    });
                                }
                                return false; // 阻止自动上传
                            }}
                            showUploadList={false}
                            accept="*"
                            disabled={localUploading}
                        >
                            <p className="ant-upload-drag-icon">
                                <InboxOutlined style={{ color: '#0ea5e9', fontSize: 48 }} />
                            </p>
                            <p className="ant-upload-text">点击或拖拽文件到此区域</p>
                            <p className="ant-upload-hint">支持多文件选择，支持 Linux/ARM 等多架构 Agent 二进制</p>
                        </Upload.Dragger>

                        {localFiles.length > 0 && (
                            <div style={{ marginTop: 16 }}>
                                <div style={{ marginBottom: 8, fontWeight: 500 }}>待上传文件 ({localFiles.length})</div>
                                {localFiles.map((f, i) => (
                                    <div key={f.name} style={{
                                        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                                        padding: '6px 12px', background: i % 2 === 0 ? '#f8fafc' : '#fff',
                                        borderRadius: 4, marginBottom: 2,
                                    }}>
                                        <Space>
                                            <FileOutlined style={{ color: '#64748b' }} />
                                            <Text style={{ fontFamily: 'monospace', fontSize: 13 }}>{f.name}</Text>
                                            <Text type="secondary" style={{ fontSize: 12 }}>({(f.size / 1024 / 1024).toFixed(1)} MB)</Text>
                                        </Space>
                                        <Button
                                            type="text" size="small" danger
                                            icon={<DeleteOutlined />}
                                            onClick={() => setLocalFiles(prev => prev.filter((_, idx) => idx !== i))}
                                            disabled={localUploading}
                                        />
                                    </div>
                                ))}

                                {localUploading && (
                                    <Progress
                                        percent={localUploadProgress}
                                        status="active"
                                        strokeColor={{ '0%': '#0ea5e9', '100%': '#10b981' }}
                                        style={{ marginTop: 12 }}
                                    />
                                )}

                                <div style={{ marginTop: 16, display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
                                    <Button onClick={() => { setLocalFiles([]); setLocalUploadProgress(0); }} disabled={localUploading}>
                                        清空
                                    </Button>
                                    <Button
                                        type="primary"
                                        icon={<CloudUploadOutlined />}
                                        loading={localUploading}
                                        onClick={async () => {
                                            setLocalUploading(true);
                                            setLocalUploadProgress(0);
                                            try {
                                                const res = await uploadLocalAgent(
                                                    agentUploadAccountId,
                                                    localFiles,
                                                    (percent) => setLocalUploadProgress(percent)
                                                );
                                                if (res?.status === 'ok') {
                                                    message.success(res.message || '上传成功');
                                                    setAgentUploadOpen(false);
                                                    setLocalFiles([]);
                                                    setLocalUploadProgress(0);
                                                } else {
                                                    message.error(res?.message || '上传失败');
                                                }
                                            } catch (err: any) {
                                                const errMsg = extractErrorMsg(err) || String(err) || '未知错误';
                                                message.error(`上传失败: ${errMsg}`);
                                            } finally {
                                                setLocalUploading(false);
                                            }
                                        }}
                                    >
                                        上传到服务器 & OSS
                                    </Button>
                                </div>
                            </div>
                        )}
                    </div>
                )}
            </Modal>

            {/* 地域选择 Modal */}
            <Modal
                title="选择云资源地域"
                open={regionModalOpen}
                onCancel={() => setRegionModalOpen(false)}
                footer={null}
                width={600}
            >
                <Alert
                    message="该凭证尚未指定地域，请选择一个地域以继续操作。地域决定了弹性扩缩时 ECS 实例的创建位置。"
                    type="info"
                    showIcon
                    style={{ marginBottom: 16 }}
                />
                {regionLoading ? (
                    <div style={{ display: 'flex', justifyContent: 'center', padding: '40px 0' }}><Spin size="large" /></div>
                ) : (
                    <div style={{ maxHeight: 400, overflow: 'auto' }}>
                        {regionList.map(r => {
                            const isChinaMainland = r.region_id.startsWith('cn-');
                            return (
                                <div
                                    key={r.region_id}
                                    style={{
                                        display: 'flex',
                                        justifyContent: 'space-between',
                                        alignItems: 'center',
                                        padding: '10px 16px',
                                        borderBottom: '1px solid #f0f0f0',
                                        cursor: 'pointer',
                                        borderRadius: 6,
                                        transition: 'background 0.2s',
                                    }}
                                    onMouseEnter={e => (e.currentTarget.style.background = '#f0f9ff')}
                                    onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                                    onClick={() => handleRegionSelect(r.region_id)}
                                >
                                    <div>
                                        <Text strong style={{ fontSize: 14 }}>{r.local_name}</Text>
                                        <Text type="secondary" style={{ marginLeft: 8, fontSize: 12 }}>{r.region_id}</Text>
                                        {isChinaMainland && <Tag color="blue" style={{ marginLeft: 8, fontSize: 10 }}>推荐</Tag>}
                                    </div>
                                    <Button type="link" size="small">选择</Button>
                                </div>
                            );
                        })}
                        {regionList.length === 0 && !regionLoading && (
                            <Empty description="未获取到可用地域" style={{ padding: '40px 0' }} />
                        )}
                    </div>
                )}
            </Modal>
        </div>
    );
};

export default CloudManagement;
