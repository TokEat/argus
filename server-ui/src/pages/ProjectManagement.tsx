import React, { useEffect, useState } from 'react';
import { App, Button, Form, Input, Modal, Space, Table, Tag, Typography, Spin, Empty } from 'antd';
import { ProCard } from '@ant-design/pro-components';
import { PlusOutlined, ProjectOutlined, ReloadOutlined } from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import { listProjects, createProject } from '../services/api';
import { canAccessRole } from '../utils/auth';

const { Title, Text } = Typography;

const ProjectManagement: React.FC = () => {
    const [loading, setLoading] = useState(true);
    const [projects, setProjects] = useState<API.Project[]>([]);
    const [createOpen, setCreateOpen] = useState(false);
    const [creating, setCreating] = useState(false);
    const [form] = Form.useForm();
    const { message } = App.useApp();
    const canManageProjects = canAccessRole('operator');

    const fetchProjects = async () => {
        setLoading(true);
        try {
            const result = await listProjects();
            setProjects(result || []);
        } catch (error) {
            console.error('Failed to fetch projects:', error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchProjects();
    }, []);

    const handleCreate = async () => {
        if (!canManageProjects) return;
        try {
            const values = await form.validateFields();
            setCreating(true);

            await createProject({
                name: values.name,
                description: values.description,
            });

            message.success('项目创建成功');
            setCreateOpen(false);
            form.resetFields();
            fetchProjects();
        } catch (error: unknown) {
            if (typeof error === 'string') {
                message.error(error);
            } else if (error instanceof Error) {
                message.error(error.message);
            }
        } finally {
            setCreating(false);
        }
    };

    const columns: ColumnsType<API.Project> = [
        {
            title: '项目名称',
            dataIndex: 'Name',
            key: 'name',
            render: (name: string, record) => (
                <Space direction="vertical" size={0}>
                    <Text strong style={{ fontSize: 14 }}>{name}</Text>
                    <Text style={{ fontSize: 11, color: '#94a3b8', fontFamily: 'monospace' }}>
                        {record.ID}
                    </Text>
                </Space>
            ),
        },
        {
            title: '描述',
            dataIndex: 'Description',
            key: 'description',
            render: (desc: string) => <Text style={{ color: '#64748b' }}>{desc || '-'}</Text>,
        },
        {
            title: '状态',
            dataIndex: 'Status',
            key: 'status',
            render: (status: string) => (
                <Tag color={status === 'active' ? 'success' : 'default'}>
                    {status === 'active' ? '活跃' : status}
                </Tag>
            ),
        },
        {
            title: '创建时间',
            dataIndex: 'CreatedAt',
            key: 'created_at',
            render: (val: string) => <Text style={{ fontSize: 12, color: '#64748b' }}>{new Date(val).toLocaleString()}</Text>,
        },
    ];

    return (
        <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
                <Title level={4} style={{ margin: 0, color: '#1e293b', fontWeight: 600 }}>
                    <ProjectOutlined style={{ marginRight: 8, color: '#0ea5e9' }} />
                    项目管理
                </Title>
                <Space>
                    <Button icon={<ReloadOutlined />} onClick={fetchProjects} loading={loading}>
                        刷新
                    </Button>
                    {canManageProjects && (
                        <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>
                            新建项目
                        </Button>
                    )}
                </Space>
            </div>

            <ProCard className="glass-card" style={{ background: 'transparent', border: 'none' }}>
                {loading && projects.length === 0 ? (
                    <div style={{ display: 'flex', justifyContent: 'center', padding: '60px 0' }}>
                        <Spin size="large" />
                    </div>
                ) : projects.length === 0 ? (
                    <Empty
                        image={Empty.PRESENTED_IMAGE_SIMPLE}
                        description="暂无项目"
                        style={{ padding: '60px 0' }}
                    >
                        {canManageProjects && (
                            <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>
                                创建第一个项目
                            </Button>
                        )}
                    </Empty>
                ) : (
                    <Table
                        columns={columns}
                        dataSource={projects}
                        rowKey="ID"
                        pagination={{ pageSize: 15 }}
                        size="middle"
                    />
                )}
            </ProCard>

            {canManageProjects && (
                <Modal
                    title="新建项目"
                    open={createOpen}
                    onCancel={() => setCreateOpen(false)}
                    onOk={handleCreate}
                    okText="创建"
                    confirmLoading={creating}
                >
                    <Form form={form} layout="vertical" style={{ marginTop: 16 }}>
                        <Form.Item label="项目名称" name="name" rules={[{ required: true, message: '请输入项目名称' }]}>
                            <Input placeholder="例如：2026 护网行动 - 某某局" />
                        </Form.Item>
                        <Form.Item label="项目描述" name="description">
                            <Input.TextArea rows={4} placeholder="项目的目标范围或备注说明" />
                        </Form.Item>
                    </Form>
                </Modal>
            )}
        </div>
    );
};

export default ProjectManagement;
