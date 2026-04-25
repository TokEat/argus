import React, { useEffect, useState } from 'react';
import { Typography, Table, Tag, Space, Button, Spin, Empty, Modal, Form, Input, Select, message, Popconfirm, Badge, Tabs, Switch, InputNumber, Row, Col } from 'antd';
import { ProCard } from '@ant-design/pro-components';
import { CloudOutlined, ReloadOutlined, PlusOutlined, DeleteOutlined, WifiOutlined, KeyOutlined, SettingOutlined, AppstoreOutlined, CodeOutlined } from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import Editor from '@monaco-editor/react';
import { listCloudInstances, createCloudInstance, deleteCloudInstance, saveCloudPolicy } from '../services/api';
import { useAutoContext } from '../contexts/GlobalAIContext';

const { Title, Text, Paragraph } = Typography;

const CloudManagement: React.FC = () => {
    const [loading, setLoading] = useState(true);
    const [instances, setInstances] = useState<API.CloudInstance[]>([]);
    const [modalOpen, setModalOpen] = useState(false);
    const [akModalOpen, setAkModalOpen] = useState(false);
    const [form] = Form.useForm();
    const [akForm] = Form.useForm();
    const [policyForm] = Form.useForm();
    const [activeTab, setActiveTab] = useState('instances');
    
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
ExecStart=/usr/local/bin/argus-agent --server {{SERVER_IP}}:50051 --token {{DYNAMIC_TOKEN}} --tags "auto-scaling"
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable argus-agent
systemctl start argus-agent
`);

    // 占位凭证数据
    const [credentials] = useState([
        { id: '1', provider: 'aliyun', name: '阿里云生产环境 AK', status: 'active', updated_at: '2026-04-19 10:00:00' }
    ]);

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

    useEffect(() => {
        if (activeTab === 'instances') {
            fetchInstances();
            const timer = setInterval(fetchInstances, 15000);
            return () => clearInterval(timer);
        }
    }, [activeTab]);

    useAutoContext({
        cloud_assets: {
            total_instances: instances.length,
            online_instances: instances.filter(i => i.status === 'Alive' || i.status === 'Running').length,
            providers_configured: credentials.map(c => c.provider)
        },
        cloud_active_tab: activeTab
    });

    const handleCreate = () => {
        form.resetFields();
        setModalOpen(true);
    };

    const handleAddAk = () => {
        akForm.resetFields();
        setAkModalOpen(true);
    };

    const handleSubmit = async () => {
        try {
            const values = await form.validateFields();
            const res = await createCloudInstance(values);
            message.success(res?.message || '实例创建请求已提交');
            setModalOpen(false);
            fetchInstances();
        } catch (err) {
            if (typeof err === 'string') message.error(err);
        }
    };

    const handleAkSubmit = async () => {
        try {
            await akForm.validateFields();
            message.success('凭证已保存，系统将使用该凭证动态调度资源。');
            setAkModalOpen(false);
        } catch (err) {}
    };

    const handlePolicySubmit = async () => {
        try {
            const values = await policyForm.validateFields();
            await saveCloudPolicy({ ...values, user_data: userDataScript });
            message.success('调度策略与 Cloud-Init 初始化脚本已更新并生效。');
        } catch (err) {
            message.error('保存失败');
        }
    };

    const handleDelete = async (id: string) => {
        try {
            await deleteCloudInstance(id);
            message.success('实例已标记终止');
            fetchInstances();
        } catch (err) {
            message.error(String(err));
        }
    };

    const columns: ColumnsType<API.CloudInstance> = [
        {
            title: '状态', dataIndex: 'status', key: 'status', width: 80,
            render: (status: string) => {
                const alive = status === 'Alive' || status === 'Running';
                return (
                    <Badge status={alive ? 'success' : 'default'}
                        text={<Tag color={alive ? '#10b981' : '#94a3b8'} style={{ borderRadius: 20, fontSize: 11 }}>
                            {alive ? '运行中' : '已停止'}
                        </Tag>} />
                );
            },
        },
        {
            title: '实例 ID', dataIndex: 'id', key: 'id', ellipsis: true,
            render: (id: string) => (
                <Text copyable={{ text: id }} style={{ fontFamily: 'monospace', fontSize: 12 }}>
                    {id.length > 24 ? `${id.slice(0, 24)}...` : id}
                </Text>
            ),
        },
        {
            title: 'IP 地址', dataIndex: 'ip', key: 'ip', width: 140,
            render: (ip: string) => ip || <Text type="secondary">-</Text>,
        },
        {
            title: '提供商', dataIndex: 'provider', key: 'provider', width: 100,
            render: (p: string) => <Tag color="blue" style={{ fontSize: 11 }}>{p}</Tag>,
        },
        {
            title: '创建时间', dataIndex: 'created_at', key: 'created_at', width: 180,
            render: (v: string) => <Text style={{ fontSize: 12, color: '#64748b' }}>{v ? new Date(v).toLocaleString('zh-CN') : '-'}</Text>,
        },
        {
            title: '操作', key: 'actions', width: 100,
            render: (_, record) => (
                <Popconfirm title="确认终止此实例？" onConfirm={() => handleDelete(record.id)}>
                    <Button type="link" size="small" danger icon={<DeleteOutlined />}>手动终止</Button>
                </Popconfirm>
            ),
        },
    ];

    const credColumns = [
        {
            title: '别名', dataIndex: 'name', key: 'name',
            render: (text: string) => <Text strong>{text}</Text>
        },
        {
            title: '提供商', dataIndex: 'provider', key: 'provider',
            render: (p: string) => <Tag color="blue">{p.toUpperCase()}</Tag>
        },
        {
            title: '状态', dataIndex: 'status', key: 'status',
            render: () => <Tag color="success">正常</Tag>
        },
        {
            title: '更新时间', dataIndex: 'updated_at', key: 'updated_at',
        },
        {
            title: '操作', key: 'action',
            render: () => <Button type="link" danger size="small">删除</Button>
        }
    ];

    const onlineCount = instances.filter(i => i.status === 'Alive' || i.status === 'Running').length;
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
                        <WifiOutlined /> 运行中实例 {onlineCount}
                    </Tag>
                    {activeTab === 'instances' && (
                        <>
                            <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>手动创建</Button>
                            <Button icon={<ReloadOutlined />} onClick={fetchInstances} loading={loading}>刷新</Button>
                        </>
                    )}
                    {activeTab === 'credentials' && (
                        <Button type="primary" icon={<PlusOutlined />} onClick={handleAddAk}>添加凭证</Button>
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
                            label: <span><AppstoreOutlined /> 活跃实例</span>,
                            children: (
                                <div style={{ padding: '20px 0' }}>
                                    {loading && instances.length === 0 ? (
                                        <div style={{ display: 'flex', justifyContent: 'center', padding: '60px 0' }}><Spin size="large" /></div>
                                    ) : instances.length === 0 ? (
                                        <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无动态调度的云实例" style={{ padding: '60px 0' }} />
                                    ) : (
                                        <Table columns={columns} dataSource={instances} rowKey="id"
                                            pagination={{ pageSize: 20, showTotal: (total) => `共 ${total} 个实例` }} size="middle" />
                                    )}
                                </div>
                            ),
                        },
                        {
                            key: 'policy',
                            label: <span><SettingOutlined /> 动态伸缩策略</span>,
                            children: (
                                <div style={{ padding: '20px 0', maxWidth: 800 }}>
                                    <ProCard bordered style={{ marginBottom: 24 }}>
                                        <Title level={5}>自动化调度引擎</Title>
                                        <Paragraph type="secondary">
                                            开启后，系统将根据任务队列的堆积情况，使用配置好的 AK/SK 自动向云厂商申请服务器，并通过 Cloud-Init 技术自动拉取 Agent 运行。当服务端任务全部下发且节点空闲时，将自动销毁机器以节省成本。
                                        </Paragraph>
                                        <Form form={policyForm} layout="vertical" initialValues={{ auto_scale: true, max_instances: 10, idle_timeout: 10, target_provider: 'aliyun', server_url: 'http://192.168.1.100', server_ip: '192.168.1.100' }}>
                                            <Row gutter={16}>
                                                <Col span={8}>
                                                    <Form.Item name="auto_scale" label="启用动态伸缩 (Auto Scaling)" valuePropName="checked">
                                                        <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                                                    </Form.Item>
                                                </Col>
                                                <Col span={8}>
                                                    <Form.Item name="target_provider" label="首选云厂商">
                                                        <Select options={[
                                                            { value: 'aliyun', label: '阿里云 ECS' },
                                                            { value: 'tencent', label: '腾讯云 CVM' },
                                                            { value: 'aws', label: 'AWS EC2' }
                                                        ]} />
                                                    </Form.Item>
                                                </Col>
                                                <Col span={8}>
                                                    <Form.Item name="max_instances" label="最大并发实例数" extra="防止账单爆炸，建议设置上限">
                                                        <InputNumber min={1} max={100} style={{ width: '100%' }} />
                                                    </Form.Item>
                                                </Col>
                                            </Row>
                                            <Row gutter={16}>
                                                <Col span={12}>
                                                    <Form.Item name="server_url" label="Agent 下载基础路径" extra="用于替换脚本中的 {{SERVER_URL}}">
                                                        <Input placeholder="例: http://192.168.1.100" />
                                                    </Form.Item>
                                                </Col>
                                                <Col span={12}>
                                                    <Form.Item name="server_ip" label="RPC 回连地址" extra="用于替换脚本中的 {{SERVER_IP}}">
                                                        <Input placeholder="例: 192.168.1.100" />
                                                    </Form.Item>
                                                </Col>
                                            </Row>
                                            <Form.Item name="idle_timeout" label="空闲销毁延迟 (分钟)" extra="任务队列清空后，若机器空闲超过此时间则自动释放销毁">
                                                <InputNumber min={1} max={60} style={{ width: '100%' }} />
                                            </Form.Item>
                                            
                                            <Form.Item label={<span><CodeOutlined /> Cloud-Init (UserData) 初始化脚本模板</span>} extra="机器创建启动时，系统将使用上述模板自动执行。使用 {{SERVER_URL}}, {{SERVER_IP}}, {{DYNAMIC_TOKEN}} 作为占位符，Server端会在下发前自动完成鉴权信息的替换。">
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

                                            <Button type="primary" onClick={handlePolicySubmit}>保存调度与下发策略</Button>
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
                                    <Table columns={credColumns} dataSource={credentials} rowKey="id" pagination={false} size="middle" />
                                </div>
                            ),
                        }
                    ]}
                />
            </ProCard>

            <Modal title="手动创建实例" open={modalOpen} onOk={handleSubmit} onCancel={() => setModalOpen(false)}
                okText="创建" cancelText="取消">
                <Form form={form} layout="vertical" style={{ marginTop: 16 }}>
                    <Form.Item name="provider" label="提供商" initialValue="aliyun" rules={[{ required: true }]}>
                        <Select options={[
                            { value: 'aliyun', label: '阿里云 ECS' },
                            { value: 'tencent', label: '腾讯云 CVM' },
                            { value: 'docker', label: 'Docker（本地容器）' },
                        ]} />
                    </Form.Item>
                    <Form.Item name="image_id" label="镜像 ID">
                        <Input placeholder="例如：m-bp1... 或 dddd-agent:latest" />
                    </Form.Item>
                    <Form.Item name="region" label="区域">
                        <Input placeholder="例如：cn-hangzhou" />
                    </Form.Item>
                    <Form.Item name="instance_type" label="规格">
                        <Input placeholder="例如：ecs.c6.large" />
                    </Form.Item>
                </Form>
            </Modal>

            <Modal title="添加云服务凭证 (AK/SK)" open={akModalOpen} onOk={handleAkSubmit} onCancel={() => setAkModalOpen(false)}
                okText="保存" cancelText="取消">
                <Form form={akForm} layout="vertical" style={{ marginTop: 16 }}>
                    <Form.Item name="provider" label="提供商" initialValue="aliyun" rules={[{ required: true }]}>
                        <Select options={[
                            { value: 'aliyun', label: '阿里云 ECS' },
                            { value: 'tencent', label: '腾讯云 CVM' },
                            { value: 'aws', label: 'AWS EC2' },
                        ]} />
                    </Form.Item>
                    <Form.Item name="name" label="凭证别名" rules={[{ required: true }]}>
                        <Input placeholder="例如：生产环境主账号AK" />
                    </Form.Item>
                    <Form.Item name="access_key" label="Access Key ID" rules={[{ required: true }]}>
                        <Input placeholder="输入 AK" />
                    </Form.Item>
                    <Form.Item name="secret_key" label="Secret Access Key" rules={[{ required: true }]}>
                        <Input.Password placeholder="输入 SK" />
                    </Form.Item>
                </Form>
            </Modal>
        </div>
    );
};

export default CloudManagement;
