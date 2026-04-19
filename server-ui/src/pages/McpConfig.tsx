import React, { useEffect, useState } from 'react';
import { Typography, Table, Tag, Space, Button, Spin, Empty, Modal, Form, Input, Select, message, Popconfirm } from 'antd';
import { ProCard } from '@ant-design/pro-components';
import { ApiOutlined, ReloadOutlined, PlusOutlined, DeleteOutlined, KeyOutlined } from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import { listMcpKeys, saveMcpKey, deleteMcpKey } from '../services/api';

const { Title, Text } = Typography;

const providerLabels: Record<string, { name: string; color: string }> = {
    fofa: { name: 'FOFA', color: '#0ea5e9' },
    hunter: { name: 'Hunter', color: '#10b981' },
    quake: { name: '360 Quake', color: '#f59e0b' },
    openai: { name: 'OpenAI', color: '#6366f1' },
    deepseek: { name: 'DeepSeek', color: '#8b5cf6' },
    shodan: { name: 'Shodan', color: '#ef4444' },
    censys: { name: 'Censys', color: '#ec4899' },
};

const McpConfig: React.FC = () => {
    const [loading, setLoading] = useState(true);
    const [keys, setKeys] = useState<API.McpKey[]>([]);
    const [modalOpen, setModalOpen] = useState(false);
    const [form] = Form.useForm();

    const fetchKeys = async () => {
        setLoading(true);
        try {
            const result = await listMcpKeys();
            setKeys(result || []);
        } catch (error) {
            console.error('Failed to fetch MCP keys:', error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => { fetchKeys(); }, []);

    const handleAdd = () => {
        form.resetFields();
        setModalOpen(true);
    };

    const handleSubmit = async () => {
        try {
            const values = await form.validateFields();
            await saveMcpKey(values.provider, values.key);
            message.success('密钥已保存');
            setModalOpen(false);
            fetchKeys();
        } catch (err) {
            if (typeof err === 'string') message.error(err);
        }
    };

    const handleDelete = async (id: string) => {
        try {
            await deleteMcpKey(id);
            message.success('密钥已删除');
            fetchKeys();
        } catch (err) {
            message.error(String(err));
        }
    };

    const columns: ColumnsType<API.McpKey> = [
        {
            title: '服务商', dataIndex: 'provider', key: 'provider', width: 150,
            render: (p: string) => {
                const info = providerLabels[p] || { name: p, color: '#94a3b8' };
                return <Tag color={info.color} style={{ borderRadius: 20, fontSize: 11 }}>{info.name}</Tag>;
            },
        },
        {
            title: 'API Key', dataIndex: 'key', key: 'key',
            render: (key: string) => (
                <Space>
                    <KeyOutlined style={{ color: '#64748b' }} />
                    <Text style={{ fontFamily: 'monospace', fontSize: 12, color: '#64748b' }}>{key}</Text>
                </Space>
            ),
        },
        {
            title: '状态', dataIndex: 'status', key: 'status', width: 80,
            render: (s: string) => <Tag color={s === 'active' ? '#10b981' : '#94a3b8'} style={{ borderRadius: 20, fontSize: 11 }}>{s === 'active' ? '生效' : '停用'}</Tag>,
        },
        {
            title: '操作', key: 'actions', width: 100,
            render: (_, record) => (
                <Popconfirm title="确认删除此密钥？" onConfirm={() => handleDelete(record.id)}>
                    <Button type="link" size="small" danger icon={<DeleteOutlined />}>删除</Button>
                </Popconfirm>
            ),
        },
    ];

    const cardStyle = {
        background: '#ffffff', borderRadius: 12,
        border: '1px solid #e2e8f0',
        boxShadow: '0 1px 3px 0 rgba(0, 0, 0, 0.04)',
    };

    return (
        <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
                <Title level={4} style={{ margin: 0, color: '#1e293b', fontWeight: 600 }}>
                    <ApiOutlined style={{ marginRight: 8, color: '#8b5cf6' }} />
                    MCP 配置 / API Key 管理
                </Title>
                <Space>
                    <Tag color="blue">{keys.length} 个密钥</Tag>
                    <Button type="primary" icon={<PlusOutlined />} onClick={handleAdd}>添加密钥</Button>
                    <Button icon={<ReloadOutlined />} onClick={fetchKeys} loading={loading}>刷新</Button>
                </Space>
            </div>

            {/* 说明卡片 */}
            <ProCard style={{ ...cardStyle, marginBottom: 16, background: 'linear-gradient(135deg, #f8fafc, #f1f5f9)' }}
                bodyStyle={{ padding: '16px 20px' }}>
                <Text style={{ fontSize: 13, color: '#475569' }}>
                    在此管理各外部服务的 API Key。
                    <strong>空间搜索引擎</strong>（Fofa / Hunter / Quake）的 Key 用于资产发现，
                    <strong>LLM</strong>（OpenAI / DeepSeek）的 Key 用于 AI 辅助规则审查。
                    密钥以加密形式存储在 PostgreSQL 中。
                </Text>
            </ProCard>

            <ProCard style={cardStyle}>
                {loading && keys.length === 0 ? (
                    <div style={{ display: 'flex', justifyContent: 'center', padding: '60px 0' }}><Spin size="large" /></div>
                ) : keys.length === 0 ? (
                    <Empty image={Empty.PRESENTED_IMAGE_SIMPLE}
                        description="暂无 API Key，点击「添加密钥」配置" style={{ padding: '60px 0' }} />
                ) : (
                    <Table columns={columns} dataSource={keys} rowKey="id"
                        pagination={false} size="middle" />
                )}
            </ProCard>

            <Modal title="添加 API Key" open={modalOpen} onOk={handleSubmit} onCancel={() => setModalOpen(false)}
                okText="保存" cancelText="取消">
                <Form form={form} layout="vertical" style={{ marginTop: 16 }}>
                    <Form.Item name="provider" label="服务商" rules={[{ required: true, message: '请选择服务商' }]}>
                        <Select placeholder="选择 API 服务商" options={[
                            { value: 'fofa', label: '🔍 FOFA（空间搜索引擎）' },
                            { value: 'hunter', label: '🎯 Hunter（空间搜索引擎）' },
                            { value: 'quake', label: '🌐 360 Quake（空间搜索引擎）' },
                            { value: 'shodan', label: '🌍 Shodan（空间搜索引擎）' },
                            { value: 'censys', label: '📡 Censys（空间搜索引擎）' },
                            { value: 'openai', label: '🤖 OpenAI（AI 规则审查）' },
                            { value: 'deepseek', label: '🧠 DeepSeek（AI 规则审查）' },
                        ]} />
                    </Form.Item>
                    <Form.Item name="key" label="API Key" rules={[{ required: true, message: '请输入 API Key' }]}>
                        <Input.Password placeholder="请输入 API Key" />
                    </Form.Item>
                </Form>
            </Modal>
        </div>
    );
};

export default McpConfig;
