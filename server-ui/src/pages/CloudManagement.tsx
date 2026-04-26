import React, { useEffect, useState } from 'react';
import { Typography, Table, Tag, Space, Button, Spin, Empty, Modal, Form, Input, Select, message, Popconfirm, Badge, Tabs, Switch, InputNumber, Row, Col, Alert } from 'antd';
import { ProCard } from '@ant-design/pro-components';
import { CloudOutlined, ReloadOutlined, PlusOutlined, DeleteOutlined, WifiOutlined, KeyOutlined, SettingOutlined, AppstoreOutlined, CodeOutlined, PlayCircleOutlined } from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import Editor from '@monaco-editor/react';
import { 
    listCloudInstances, createCloudInstance, deleteCloudInstance, 
    listCloudAccounts, createCloudAccount, deleteCloudAccount, testCloudAccount,
    listCloudPolicies, createCloudPolicy, updateCloudPolicy, toggleCloudPolicy,
    getCloudDashboard 
} from '../services/api';
import { useAutoContext } from '../contexts/GlobalAIContext';

const { Title, Text, Paragraph } = Typography;

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
    
    const [userDataScript, setUserDataScript] = useState(`#!/bin/bash
systemctl stop firewalld
systemctl disable firewalld

# 下载 Agent (SERVER_URL 将被动态替换)
curl -o /usr/local/bin/argus-agent {{SERVER_URL}}/release/dddd-agent-linux-amd64
chmod +x /usr/local/bin/argus-agent

# 配置 Systemd 守护进程
cat <<EOF > /etc/systemd/system/argus-agent.service
[Unit]
Description=Argus Distributed Scanner Agent
After=network.target

[Service]
Type=simple
# DYNAMIC_TOKEN 将被动态替换
ExecStart=/usr/local/bin/argus-agent --server {{SERVER_IP}}:50051 --token {{DYNAMIC_TOKEN}} --tags "cloud"
Restart=always
RestartSec=5
LimitNOFILE=65536
Environment="ARGUS_SPOT=1"

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable argus-agent
systemctl start argus-agent
`);

    const fetchDashboard = async () => {
        try {
            const data = await getCloudDashboard();
            setDashboard(data);
        } catch (error) {
            console.error('Failed to fetch dashboard:', error);
        }
    };

    const fetchInstances = async () => {
        setLoading(true);
        try {
            const result = await listCloudInstances();
            setInstances(result || []);
        } catch (error) {
            console.error('Failed to fetch instances:', error);
        } finally {
            setLoading(false);
        }
    };

    const fetchAccounts = async () => {
        setLoading(true);
        try {
            const result = await listCloudAccounts();
            setAccounts(result || []);
        } catch (error) {
            console.error('Failed to fetch accounts:', error);
        } finally {
            setLoading(false);
        }
    };

    const fetchPolicies = async () => {
        try {
            const result = await listCloudPolicies();
            setPolicies(result || []);
            if (result && result.length > 0) {
                const policy = result[0];
                setCurrentPolicyId(policy.id);
                policyForm.setFieldsValue({
                    name: policy.name,
                    enabled: policy.enabled,
                    cloud_account_id: policy.cloud_account_id,
                    min_instances: policy.min_instances,
                    max_instances: policy.max_instances,
                    scale_up_threshold: policy.scale_up_threshold,
                    scale_down_threshold: policy.scale_down_threshold,
                    cooldown_seconds: policy.cooldown_seconds,
                    instance_ttl_minutes: policy.instance_ttl_minutes,
                    spot_strategy: policy.spot_strategy,
                    max_spot_price: policy.max_spot_price,
                });
                if (policy.user_data_template) {
                    setUserDataScript(policy.user_data_template);
                }
            }
        } catch (error) {
            console.error('Failed to fetch policies:', error);
        }
    };

    useEffect(() => {
        fetchDashboard();
        if (activeTab === 'instances') {
            fetchInstances();
            const timer = setInterval(() => {
                fetchInstances();
                fetchDashboard();
            }, 15000);
            return () => clearInterval(timer);
        } else if (activeTab === 'credentials') {
            fetchAccounts();
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
            await createCloudInstance(values);
            message.success('已发起创建实例请求');
            setInstanceModalOpen(false);
            fetchInstances();
            fetchDashboard();
        } catch (err) {
            if (typeof err === 'string') message.error(err);
        }
    };

    const handleDeleteInstance = async (id: string) => {
        try {
            await deleteCloudInstance(id);
            message.success('销毁指令已下发');
            fetchInstances();
            fetchDashboard();
        } catch (err) {
            if (typeof err === 'string') message.error(err);
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
            if (typeof err === 'string') message.error(err);
        }
    };

    const handleDeleteAk = async (id: string) => {
        try {
            await deleteCloudAccount(id);
            message.success('凭证已删除');
            fetchAccounts();
            fetchDashboard();
        } catch (err) {
            if (typeof err === 'string') message.error(err);
        }
    };

    const handleTestAk = async (id: string) => {
        try {
            message.loading({ content: '正在连接云厂商测试凭证...', key: 'testAK' });
            await testCloudAccount(id);
            message.success({ content: '凭证连通性测试通过', key: 'testAK' });
        } catch (err) {
            message.error({ content: `连通性测试失败: ${err}`, key: 'testAK' });
        }
    };

    const handlePolicySubmit = async () => {
        try {
            const values = await policyForm.validateFields();
            const payload = { ...values, user_data_template: userDataScript };
            if (currentPolicyId) {
                await updateCloudPolicy(currentPolicyId, payload);
                message.success('策略已更新');
            } else {
                await createCloudPolicy(payload);
                message.success('策略已创建');
                fetchPolicies();
            }
            fetchDashboard();
        } catch (err) {
            if (typeof err === 'string') message.error(err);
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
            if (typeof err === 'string') message.error(err);
        }
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
            title: '操作', key: 'actions', width: 100,
            render: (_, record) => (
                <Popconfirm title="确认销毁此云主机？" onConfirm={() => handleDeleteInstance(record.id)}>
                    <Button type="link" size="small" danger icon={<DeleteOutlined />}>销毁</Button>
                </Popconfirm>
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
            title: '状态', dataIndex: 'status', key: 'status',
            render: (s: string) => <Tag color={s === 'active' ? 'success' : 'default'}>{s === 'active' ? '正常' : '已禁用'}</Tag>
        },
        {
            title: '更新时间', dataIndex: 'updated_at', key: 'updated_at',
            render: (v: string) => <Text style={{ fontSize: 12 }}>{new Date(v).toLocaleString('zh-CN')}</Text>
        },
        {
            title: '操作', key: 'action',
            render: (_: any, record: API.CloudAccount) => (
                <Space>
                    <Button type="link" size="small" icon={<PlayCircleOutlined />} onClick={() => handleTestAk(record.id)}>连通性测试</Button>
                    <Popconfirm title="确认删除此凭证？" onConfirm={() => handleDeleteAk(record.id)}>
                        <Button type="link" danger size="small">删除</Button>
                    </Popconfirm>
                </Space>
            )
        }
    ];

    const cardStyle = { background: 'transparent', border: 'none' };

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
                            <Button type="primary" icon={<PlusOutlined />} onClick={() => { instanceForm.resetFields(); setInstanceModalOpen(true); }}>手动弹容</Button>
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
                                            pagination={{ pageSize: 20, showTotal: (total) => `共 ${total} 个实例` }} size="middle" />
                                    )}
                                </div>
                            ),
                        },
                        {
                            key: 'policy',
                            label: <span><SettingOutlined /> AutoScaler 策略</span>,
                            children: (
                                <div style={{ padding: '20px 0', maxWidth: 800 }}>
                                    <ProCard bordered style={{ marginBottom: 24 }}>
                                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                                            <Title level={5} style={{ margin: 0 }}>引擎调度开关</Title>
                                            <Switch 
                                                checkedChildren="已启用" unCheckedChildren="已停用" 
                                                checked={policies.length > 0 ? policies[0].enabled : false} 
                                                onChange={handleTogglePolicy}
                                                disabled={!currentPolicyId}
                                            />
                                        </div>
                                        <Paragraph type="secondary">
                                            配置 AutoScaler (自动伸缩引擎) 的行为模式。系统将根据后台任务队列深度，向指定云厂商自动请求或销毁 Spot 竞价实例。
                                        </Paragraph>

                                        {!currentPolicyId && (
                                            <Alert message="暂无伸缩策略，请填写下方表单创建一个新策略" type="info" showIcon style={{ marginBottom: 16 }} />
                                        )}

                                        <Form form={policyForm} layout="vertical" initialValues={{ min_instances: 0, max_instances: 5, scale_up_threshold: 50, scale_down_threshold: 3, cooldown_seconds: 300, instance_ttl_minutes: 120, spot_strategy: 'SpotAsPriceGo' }}>
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
                                            
                                            <Form.Item label={<span><CodeOutlined /> Cloud-Init (UserData) 注入模板</span>} extra="AgentID, Token 和 Server 地址将在下发前由系统动态注入。">
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

                                            <Button type="primary" onClick={handlePolicySubmit}>保存调度策略</Button>
                                        </Form>
                                    </ProCard>
                                </div>
                            ),
                        },
                        {
                            key: 'credentials',
                            label: <span><KeyOutlined /> API 凭证管理</span>,
                            children: (
                                <div style={{ padding: '20px 0' }}>
                                    <Alert message="所有 AccessKey 和 Secret 均在入库前通过 AES-256-GCM 算法进行加密存储，保护您的云资产安全。" type="success" showIcon style={{ marginBottom: 16 }} />
                                    <Table columns={credColumns} dataSource={accounts} rowKey="id" pagination={false} size="middle" />
                                </div>
                            ),
                        }
                    ]}
                />
            </ProCard>

            <Modal title="手动创建实例" open={instanceModalOpen} onOk={handleCreateInstance} onCancel={() => setInstanceModalOpen(false)}
                okText="立即创建" cancelText="取消">
                <Form form={instanceForm} layout="vertical" style={{ marginTop: 16 }} initialValues={{ count: 1 }}>
                    <Alert message="提示：通常不需要手动创建实例，AutoScaler 会根据队列堆积自动拉起。手动创建将绕过冷却限制。" type="warning" showIcon style={{ marginBottom: 16 }} />
                    <Form.Item name="account_id" label="使用的云凭证" rules={[{ required: true }]}>
                        <Select placeholder="选择调用凭证" options={accounts.map(a => ({ value: a.id, label: a.name }))} />
                    </Form.Item>
                    <Form.Item name="count" label="创建数量" rules={[{ required: true }]}>
                        <InputNumber min={1} max={10} style={{ width: '100%' }} />
                    </Form.Item>
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
                </Form>
            </Modal>
        </div>
    );
};

export default CloudManagement;
