import React, { useEffect, useState } from 'react';
import { Typography, Table, Tag, Space, Button, Spin, Empty, Modal, Form, Input, Select, message, Popconfirm, Badge } from 'antd';
import { ProCard } from '@ant-design/pro-components';
import { CloudOutlined, ReloadOutlined, PlusOutlined, DeleteOutlined, WifiOutlined, DisconnectOutlined } from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import { listCloudInstances, createCloudInstance, deleteCloudInstance } from '../services/api';

const { Title, Text } = Typography;

const CloudManagement: React.FC = () => {
    const [loading, setLoading] = useState(true);
    const [instances, setInstances] = useState<API.CloudInstance[]>([]);
    const [modalOpen, setModalOpen] = useState(false);
    const [form] = Form.useForm();

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
        fetchInstances();
        const timer = setInterval(fetchInstances, 15000);
        return () => clearInterval(timer);
    }, []);

    const handleCreate = () => {
        form.resetFields();
        setModalOpen(true);
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
                    <Button type="link" size="small" danger icon={<DeleteOutlined />}>终止</Button>
                </Popconfirm>
            ),
        },
    ];

    const onlineCount = instances.filter(i => i.status === 'Alive' || i.status === 'Running').length;
    const cardStyle = {
        background: '#ffffff', borderRadius: 12,
        border: '1px solid #e2e8f0',
        boxShadow: '0 1px 3px 0 rgba(0, 0, 0, 0.04)',
    };

    return (
        <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
                <Title level={4} style={{ margin: 0, color: '#1e293b', fontWeight: 600 }}>
                    <CloudOutlined style={{ marginRight: 8, color: '#0ea5e9' }} />
                    云实例管理
                </Title>
                <Space>
                    <Tag color="#10b981" style={{ borderRadius: 20 }}>
                        <WifiOutlined /> 运行中 {onlineCount}
                    </Tag>
                    <Tag color="#94a3b8" style={{ borderRadius: 20 }}>
                        <DisconnectOutlined /> 已停止 {instances.length - onlineCount}
                    </Tag>
                    <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>创建实例</Button>
                    <Button icon={<ReloadOutlined />} onClick={fetchInstances} loading={loading}>刷新</Button>
                </Space>
            </div>

            <ProCard style={cardStyle}>
                {loading && instances.length === 0 ? (
                    <div style={{ display: 'flex', justifyContent: 'center', padding: '60px 0' }}><Spin size="large" /></div>
                ) : instances.length === 0 ? (
                    <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无云实例，可通过「创建实例」启动 Agent 节点" style={{ padding: '60px 0' }} />
                ) : (
                    <Table columns={columns} dataSource={instances} rowKey="id"
                        pagination={{ pageSize: 20, showTotal: (total) => `共 ${total} 个实例` }} size="middle" />
                )}
            </ProCard>

            <Modal title="创建云实例" open={modalOpen} onOk={handleSubmit} onCancel={() => setModalOpen(false)}
                okText="创建" cancelText="取消">
                <Form form={form} layout="vertical" style={{ marginTop: 16 }}>
                    <Form.Item name="provider" label="提供商" initialValue="docker" rules={[{ required: true }]}>
                        <Select options={[
                            { value: 'docker', label: 'Docker（本地容器）' },
                            { value: 'aliyun', label: '阿里云 ECS' },
                        ]} />
                    </Form.Item>
                    <Form.Item name="image_id" label="镜像 ID">
                        <Input placeholder="例如：dddd-agent:latest" />
                    </Form.Item>
                    <Form.Item name="region" label="区域">
                        <Input placeholder="例如：cn-hangzhou" />
                    </Form.Item>
                    <Form.Item name="instance_type" label="规格">
                        <Input placeholder="例如：ecs.c6.large" />
                    </Form.Item>
                    <Form.Item name="server_addr" label="Server 地址">
                        <Input placeholder="Agent 回连地址，例如：192.168.1.100:50051" />
                    </Form.Item>
                </Form>
            </Modal>
        </div>
    );
};

export default CloudManagement;
