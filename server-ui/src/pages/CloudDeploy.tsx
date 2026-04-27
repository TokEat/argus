import React, { useEffect, useState, useRef } from 'react';
import { Typography, Button, Select, InputNumber, Form, message, Tag, Space, Card, Timeline, Badge, Descriptions, Alert, Spin, Empty, Popconfirm, Tooltip, Modal } from 'antd';
import { ProCard } from '@ant-design/pro-components';
import {
    ThunderboltOutlined, CloudServerOutlined, CheckCircleOutlined, CloseCircleOutlined,
    LoadingOutlined, SyncOutlined, DeleteOutlined, ReloadOutlined, RocketOutlined,
    ClockCircleOutlined, ApiOutlined, WifiOutlined, WarningOutlined, SearchOutlined,
    SettingOutlined
} from '@ant-design/icons';
import {
    listCloudAccounts, listCloudPolicies, listCloudInstances,
    createCloudInstance, deleteCloudInstance, rebootCloudInstance,
    testCloudAccount, discoverCloudResources, autoConfigureCloudAccount
} from '../services/api';

const { Title, Text, Paragraph } = Typography;

const extractErr = (err: unknown): string => {
    if (!err) return '未知错误';
    if (typeof err === 'string') return err;
    if (err instanceof Error) return err.message;
    if (typeof err === 'object') {
        const o = err as Record<string, any>;
        if (o.errorFields) return '表单校验失败';
        return o.error || o.message || JSON.stringify(err);
    }
    return String(err);
};

const statusConfig: Record<string, { color: string; icon: React.ReactNode; label: string }> = {
    Provisioning: { color: '#0ea5e9', icon: <LoadingOutlined spin />, label: '创建中' },
    WaitingReady: { color: '#f59e0b', icon: <ClockCircleOutlined />, label: '等待就绪' },
    Running: { color: '#10b981', icon: <CheckCircleOutlined />, label: '运行中' },
    Error: { color: '#ef4444', icon: <CloseCircleOutlined />, label: '异常' },
    Terminating: { color: '#f97316', icon: <SyncOutlined spin />, label: '销毁中' },
    Terminated: { color: '#94a3b8', icon: <DeleteOutlined />, label: '已销毁' },
};

const CloudDeploy: React.FC = () => {
    const [accounts, setAccounts] = useState<API.CloudAccount[]>([]);
    const [policies, setPolicies] = useState<API.CloudScalingPolicy[]>([]);
    const [instances, setInstances] = useState<API.CloudInstance[]>([]);
    const [loading, setLoading] = useState(false);
    const [deploying, setDeploying] = useState(false);
    const [logs, setLogs] = useState<{ time: string; msg: string; type: 'info' | 'success' | 'error' | 'warning' }[]>([]);
    const [form] = Form.useForm();
    const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

    // 资源发现状态
    const [discoverModalOpen, setDiscoverModalOpen] = useState(false);
    const [discovering, setDiscovering] = useState(false);
    const [discoveryData, setDiscoveryData] = useState<any>(null);
    const [configForm] = Form.useForm();
    const [discoverAccountId, setDiscoverAccountId] = useState<string>('');
    const [saving, setSaving] = useState(false);

    const addLog = (msg: string, type: 'info' | 'success' | 'error' | 'warning' = 'info') => {
        const time = new Date().toLocaleTimeString('zh-CN', { hour12: false });
        setLogs(prev => [{ time, msg, type }, ...prev]);
    };

    const fetchAll = async () => {
        setLoading(true);
        try {
            const [accs, pols, insts] = await Promise.all([
                listCloudAccounts(),
                listCloudPolicies(),
                listCloudInstances(),
            ]);
            setAccounts(accs || []);
            setPolicies(pols || []);
            setInstances((insts || []).filter(i => i.status !== 'Terminated'));
        } catch (err) {
            addLog(`加载数据失败: ${extractErr(err)}`, 'error');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchAll();
        return () => { if (pollRef.current) clearInterval(pollRef.current); };
    }, []);

    const startPolling = () => {
        if (pollRef.current) clearInterval(pollRef.current);
        pollRef.current = setInterval(async () => {
            try {
                const insts = await listCloudInstances();
                setInstances((insts || []).filter(i => i.status !== 'Terminated'));
            } catch { /* ignore */ }
        }, 5000);
    };

    const stopPolling = () => {
        if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
    };

    // 资源发现
    const handleDiscover = async (accountId: string) => {
        setDiscoverAccountId(accountId);
        setDiscovering(true);
        setDiscoverModalOpen(true);
        setDiscoveryData(null);
        configForm.resetFields();
        addLog(`🔍 正在探测凭证的云资源...`);

        try {
            const data = await discoverCloudResources(accountId);
            setDiscoveryData(data);
            addLog(`  ✓ 发现 ${data.security_groups?.length || 0} 个安全组, ${data.v_switches?.length || 0} 个交换机, ${data.images?.length || 0} 个镜像, ${data.instance_types?.length || 0} 个规格`, 'success');
        } catch (err) {
            addLog(`  ✗ 资源探测失败: ${extractErr(err)}`, 'error');
            message.error(`资源探测失败: ${extractErr(err)}`);
        } finally {
            setDiscovering(false);
        }
    };

    const handleSaveConfig = async () => {
        try {
            const values = await configForm.validateFields();
            setSaving(true);
            await autoConfigureCloudAccount(discoverAccountId, values);
            message.success('配置已保存');
            addLog(`  ✓ 云资源配置已自动写入凭证`, 'success');
            setDiscoverModalOpen(false);
            fetchAll(); // 刷新凭证数据
        } catch (err) {
            const msg = extractErr(err);
            if (msg !== '表单校验失败') message.error(msg);
        } finally {
            setSaving(false);
        }
    };

    const handleDeploy = async () => {
        try {
            const values = await form.validateFields();
            const account = accounts.find(a => a.id === values.account_id);
            const policy = policies.find(p => p.cloud_account_id === values.account_id);

            if (!account) { message.error('凭证不存在'); return; }

            const missing: string[] = [];
            if (!account.region) missing.push('地域');
            if (!account.default_instance_type) missing.push('实例规格');
            if (!account.default_image_id) missing.push('镜像');
            if (!account.default_security_group) missing.push('安全组');
            if (!account.default_v_switch) missing.push('交换机');
            if (missing.length > 0) {
                message.error(`缺少配置: ${missing.join(', ')}，请先点击「自动配置」按钮`);
                return;
            }
            if (!policy) {
                message.error('该凭证尚未配置 AutoScaler 策略');
                return;
            }

            setDeploying(true);
            addLog(`🚀 开始部署 ${values.count} 台实例，使用凭证「${account.name}」...`);
            addLog(`  → 地域: ${account.region}，规格: ${account.default_instance_type}`, 'info');
            addLog(`  → 竞价策略: ${policy.spot_strategy}`, 'info');

            addLog('  → 正在测试连通性...');
            try {
                await testCloudAccount(account.id);
                addLog('  ✓ 凭证连通性正常', 'success');
            } catch (err) {
                addLog(`  ✗ 连通性失败: ${extractErr(err)}`, 'error');
                setDeploying(false);
                return;
            }

            addLog(`  → 正在向云厂商发起 RunInstances...`);
            try {
                const res = await createCloudInstance({ account_id: values.account_id, count: values.count });
                addLog(`  ✓ ${(res as any)?.message || '请求已接受'}`, 'success');
                addLog('  → 轮询实例状态中...', 'info');
                startPolling();
            } catch (err) {
                addLog(`  ✗ 创建失败: ${extractErr(err)}`, 'error');
            } finally {
                setDeploying(false);
            }
        } catch (err) {
            const msg = extractErr(err);
            if (msg !== '表单校验失败') message.error(msg);
        }
    };

    const handleDestroy = async (inst: API.CloudInstance) => {
        addLog(`🗑️ 正在销毁 ${inst.provider_instance_id || inst.id}...`, 'warning');
        try {
            await deleteCloudInstance(inst.id);
            addLog(`  ✓ 销毁指令已下发`, 'success');
            startPolling();
        } catch (err) {
            addLog(`  ✗ 销毁失败: ${extractErr(err)}`, 'error');
        }
    };

    const handleReboot = async (inst: API.CloudInstance) => {
        addLog(`🔄 正在重启 ${inst.provider_instance_id || inst.id}...`);
        try {
            await rebootCloudInstance(inst.id);
            addLog(`  ✓ 重启指令已下发`, 'success');
            startPolling();
        } catch (err) {
            addLog(`  ✗ 重启失败: ${extractErr(err)}`, 'error');
        }
    };

    const selectedAccountId = Form.useWatch('account_id', form);
    const selectedAccount = accounts.find(a => a.id === selectedAccountId);
    const selectedPolicy = policies.find(p => p.cloud_account_id === selectedAccountId);
    const hasFullConfig = selectedAccount &&
        selectedAccount.region &&
        selectedAccount.default_instance_type &&
        selectedAccount.default_image_id &&
        selectedAccount.default_security_group &&
        selectedAccount.default_v_switch;

    return (
        <div style={{ padding: '24px', maxWidth: 1200, margin: '0 auto' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
                <div>
                    <Title level={3} style={{ margin: 0 }}>
                        <ThunderboltOutlined style={{ color: '#0ea5e9', marginRight: 8 }} />
                        Agent 部署测试台
                    </Title>
                    <Paragraph type="secondary" style={{ margin: '4px 0 0' }}>
                        一站式测试：自动配置 → 创建实例 → Agent 上线 → 销毁
                    </Paragraph>
                </div>
                <Button icon={<ReloadOutlined />} onClick={() => { fetchAll(); addLog('手动刷新数据'); }}>
                    刷新
                </Button>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
                {/* 左侧：部署控制面板 */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
                    <ProCard bordered title={<><RocketOutlined /> 创建实例</>} headerBordered>
                        <Form form={form} layout="vertical" initialValues={{ count: 1 }}>
                            <Form.Item name="account_id" label="云凭证" rules={[{ required: true, message: '请选择凭证' }]}>
                                <Select
                                    placeholder="选择云凭证"
                                    loading={loading}
                                    options={accounts.map(a => ({
                                        value: a.id,
                                        label: (
                                            <Space>
                                                <Tag color="blue">{a.provider.toUpperCase()}</Tag>
                                                {a.name}
                                                <Text type="secondary" style={{ fontSize: 12 }}>{a.region || '未配置地域'}</Text>
                                            </Space>
                                        ),
                                    }))}
                                />
                            </Form.Item>

                            {/* 选中凭证后的操作区 */}
                            {selectedAccount && (
                                <>
                                    {/* 自动配置按钮 */}
                                    {!hasFullConfig && (
                                        <Alert
                                            message="该凭证尚未完成云资源配置"
                                            description="点击下方按钮，系统将通过 AK/SK 自动探测你的安全组、交换机、镜像等资源，一键填入配置。"
                                            type="warning" showIcon
                                            style={{ marginBottom: 16 }}
                                            action={
                                                <Button
                                                    type="primary" size="small"
                                                    icon={<SearchOutlined />}
                                                    onClick={() => handleDiscover(selectedAccount.id)}
                                                >
                                                    自动探测并配置
                                                </Button>
                                            }
                                        />
                                    )}

                                    {/* 配置预览 */}
                                    <div style={{
                                        background: '#f8fafc', borderRadius: 8, padding: '12px 16px',
                                        marginBottom: 16, border: '1px solid #e2e8f0'
                                    }}>
                                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                                            <Text strong style={{ fontSize: 12, color: '#475569' }}>配置预览</Text>
                                            <Button size="small" type="link" icon={<SettingOutlined />}
                                                onClick={() => handleDiscover(selectedAccount.id)}>
                                                重新配置
                                            </Button>
                                        </div>
                                        <Descriptions column={1} size="small"
                                            labelStyle={{ fontSize: 12, color: '#94a3b8', width: 80 }}
                                            contentStyle={{ fontSize: 12 }}
                                        >
                                            <Descriptions.Item label="地域">
                                                {selectedAccount.region ?
                                                    <Tag color="green">{selectedAccount.region}</Tag> :
                                                    <Tag color="red">未配置</Tag>}
                                            </Descriptions.Item>
                                            <Descriptions.Item label="实例规格">
                                                {selectedAccount.default_instance_type ?
                                                    <Tag>{selectedAccount.default_instance_type}</Tag> :
                                                    <Tag color="red">未配置</Tag>}
                                            </Descriptions.Item>
                                            <Descriptions.Item label="镜像">
                                                {selectedAccount.default_image_id ?
                                                    <Text code style={{ fontSize: 11 }}>{selectedAccount.default_image_id}</Text> :
                                                    <Tag color="red">未配置</Tag>}
                                            </Descriptions.Item>
                                            <Descriptions.Item label="安全组">
                                                {selectedAccount.default_security_group ?
                                                    <Text code style={{ fontSize: 11 }}>{selectedAccount.default_security_group}</Text> :
                                                    <Tag color="red">未配置</Tag>}
                                            </Descriptions.Item>
                                            <Descriptions.Item label="交换机">
                                                {selectedAccount.default_v_switch ?
                                                    <Text code style={{ fontSize: 11 }}>{selectedAccount.default_v_switch}</Text> :
                                                    <Tag color="red">未配置</Tag>}
                                            </Descriptions.Item>
                                            <Descriptions.Item label="策略">
                                                {selectedPolicy ?
                                                    <Space size={4}>
                                                        <Tag color="cyan">{selectedPolicy.name}</Tag>
                                                        <Tag>{selectedPolicy.spot_strategy}</Tag>
                                                    </Space> :
                                                    <Tag color="red">无策略</Tag>}
                                            </Descriptions.Item>
                                        </Descriptions>
                                    </div>
                                </>
                            )}

                            <Form.Item name="count" label="创建数量" rules={[{ required: true }]}>
                                <InputNumber min={1} max={10} style={{ width: '100%' }} />
                            </Form.Item>

                            <Button
                                type="primary" block size="large"
                                icon={<ThunderboltOutlined />}
                                loading={deploying}
                                onClick={handleDeploy}
                                disabled={!hasFullConfig}
                                style={{ height: 48, fontWeight: 600, fontSize: 16 }}
                            >
                                {deploying ? '部署中...' : '一键部署 Agent'}
                            </Button>
                        </Form>
                    </ProCard>

                    {/* 实例状态 */}
                    <ProCard
                        bordered
                        title={<><CloudServerOutlined /> 实例状态 <Badge count={instances.length} style={{ backgroundColor: '#0ea5e9', marginLeft: 8 }} /></>}
                        headerBordered
                        extra={<Button size="small" type="text" icon={<SyncOutlined />} onClick={() => { fetchAll(); }}>刷新</Button>}
                    >
                        {loading && instances.length === 0 ? (
                            <div style={{ textAlign: 'center', padding: 40 }}><Spin /></div>
                        ) : instances.length === 0 ? (
                            <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无在线实例" />
                        ) : (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                                {instances.map(inst => {
                                    const cfg = statusConfig[inst.status] || statusConfig.Error;
                                    return (
                                        <Card key={inst.id} size="small" style={{ borderLeft: `3px solid ${cfg.color}` }}>
                                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                                <div>
                                                    <Space style={{ marginBottom: 4 }}>
                                                        <Tag icon={cfg.icon} color={cfg.color} style={{ borderRadius: 4 }}>{cfg.label}</Tag>
                                                        {inst.spot && <Tag color="gold" style={{ fontSize: 10 }}>Spot</Tag>}
                                                    </Space>
                                                    <div>
                                                        <Text style={{ fontFamily: 'monospace', fontSize: 12 }}>
                                                            {inst.provider_instance_id || '分配中...'}
                                                        </Text>
                                                    </div>
                                                    <Space style={{ marginTop: 4 }} size={12}>
                                                        {inst.ip && <Text type="secondary" style={{ fontSize: 11 }}><ApiOutlined /> {inst.ip}</Text>}
                                                        {inst.agent_id && <Text style={{ fontSize: 11, color: '#10b981' }}><WifiOutlined /> Agent 已连接</Text>}
                                                        {inst.error_message && (
                                                            <Tooltip title={inst.error_message}>
                                                                <Text type="danger" style={{ fontSize: 11 }}><WarningOutlined /> {inst.error_message.substring(0, 40)}...</Text>
                                                            </Tooltip>
                                                        )}
                                                    </Space>
                                                </div>
                                                <Space>
                                                    <Popconfirm title="确认重启？" onConfirm={() => handleReboot(inst)}>
                                                        <Button size="small" type="text" icon={<SyncOutlined />}
                                                            disabled={!['Running', 'Error', 'WaitingReady'].includes(inst.status)}>重启</Button>
                                                    </Popconfirm>
                                                    <Popconfirm title="确认销毁？" onConfirm={() => handleDestroy(inst)}>
                                                        <Button size="small" type="text" danger icon={<DeleteOutlined />}>销毁</Button>
                                                    </Popconfirm>
                                                </Space>
                                            </div>
                                        </Card>
                                    );
                                })}
                            </div>
                        )}
                    </ProCard>
                </div>

                {/* 右侧：操作日志 */}
                <ProCard
                    bordered title={<><ClockCircleOutlined /> 操作日志</>} headerBordered
                    extra={
                        <Space>
                            {pollRef.current && <Tag color="processing" icon={<SyncOutlined spin />}>轮询中</Tag>}
                            <Button size="small" type="text" danger onClick={() => { setLogs([]); stopPolling(); }}>清空</Button>
                        </Space>
                    }
                    style={{ height: 'fit-content', maxHeight: 'calc(100vh - 160px)', position: 'sticky', top: 24 }}
                    bodyStyle={{ overflow: 'auto', maxHeight: 'calc(100vh - 260px)' }}
                >
                    {logs.length === 0 ? (
                        <div style={{ textAlign: 'center', padding: '60px 0', color: '#94a3b8' }}>
                            <CloudServerOutlined style={{ fontSize: 40, marginBottom: 12 }} /><br />
                            <Text type="secondary">等待操作...</Text><br />
                            <Text type="secondary" style={{ fontSize: 12 }}>选择凭证 → 自动配置 → 一键部署</Text>
                        </div>
                    ) : (
                        <Timeline
                            items={logs.map((log, idx) => ({
                                key: idx,
                                color: log.type === 'success' ? 'green' : log.type === 'error' ? 'red' : log.type === 'warning' ? 'orange' : 'blue',
                                children: (
                                    <div>
                                        <Text type="secondary" style={{ fontSize: 10, fontFamily: 'monospace' }}>{log.time}</Text><br />
                                        <Text style={{
                                            fontSize: 13,
                                            color: log.type === 'error' ? '#ef4444' : log.type === 'success' ? '#10b981' : log.type === 'warning' ? '#f59e0b' : '#334155',
                                        }}>{log.msg}</Text>
                                    </div>
                                ),
                            }))}
                        />
                    )}
                </ProCard>
            </div>

            {/* 资源发现弹窗 */}
            <Modal
                title={<><SearchOutlined /> 云资源自动探测</>}
                open={discoverModalOpen}
                onCancel={() => setDiscoverModalOpen(false)}
                footer={discoveryData ? [
                    <Button key="cancel" onClick={() => setDiscoverModalOpen(false)}>取消</Button>,
                    <Button key="save" type="primary" loading={saving} onClick={handleSaveConfig} icon={<CheckCircleOutlined />}>
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
                    <Form form={configForm} layout="vertical">
                        <Alert
                            message="以下资源已通过你的 AK/SK 从阿里云 API 自动获取，请在每一项中选择合适的值。"
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
                        <WarningOutlined style={{ fontSize: 32, marginBottom: 8 }} /><br />
                        <Text type="secondary">探测失败或未开始，请检查日志。</Text>
                    </div>
                )}
            </Modal>

            {accounts.length === 0 && !loading && (
                <Alert
                    message="未检测到云凭证"
                    description="请先到「实例配置」页面添加云厂商凭证 (AK/SK)，然后回到此页面使用自动配置功能。"
                    type="warning" showIcon style={{ marginTop: 20 }}
                />
            )}
        </div>
    );
};

export default CloudDeploy;
