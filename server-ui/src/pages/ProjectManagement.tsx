import React, { useEffect, useState } from 'react';
import { App, Button, Form, Input, Modal, Space, Table, Tag, Typography, Spin, Empty, Popconfirm, Statistic, Tooltip } from 'antd';
import { ProCard } from '@ant-design/pro-components';
import {
    PlusOutlined, ProjectOutlined, ReloadOutlined,
    DeleteOutlined, InboxOutlined, UndoOutlined,
    ExclamationCircleOutlined, BugOutlined, ScanOutlined,
    ApiOutlined, RocketOutlined, WarningOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import { listProjects, createProject, updateProject, deleteProject, getProjectStats } from '../services/api';
import { canAccessRole } from '../utils/auth';
import dayjs from 'dayjs';

const { Title, Text, Paragraph } = Typography;

interface ProjectStats {
    project_id: string;
    project_name: string;
    tasks: number;
    assets: number;
    fingerprints: number;
    vulns: number;
}

const ProjectManagement: React.FC = () => {
    const [loading, setLoading] = useState(true);
    const [projects, setProjects] = useState<API.Project[]>([]);
    const [createOpen, setCreateOpen] = useState(false);
    const [creating, setCreating] = useState(false);
    const [form] = Form.useForm();
    const { message, modal } = App.useApp();
    const canManageProjects = canAccessRole('operator');

    // Delete confirmation state
    const [deleteModalOpen, setDeleteModalOpen] = useState(false);
    const [deleteTarget, setDeleteTarget] = useState<API.Project | null>(null);
    const [deleteStats, setDeleteStats] = useState<ProjectStats | null>(null);
    const [loadingStats, setLoadingStats] = useState(false);
    const [deleteConfirmText, setDeleteConfirmText] = useState('');
    const [deleting, setDeleting] = useState(false);

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

    // ── Archive / Restore ──
    const handleToggleArchive = async (project: API.Project) => {
        const newStatus = project.Status === 'archived' ? 'active' : 'archived';
        const actionLabel = newStatus === 'archived' ? '归档' : '恢复';
        try {
            await updateProject(project.ID, { status: newStatus });
            message.success(`项目已${actionLabel}`);
            // 如果当前活动项目被归档，清除选择
            if (newStatus === 'archived') {
                const activeProjectId = localStorage.getItem('active_project_id');
                if (activeProjectId === project.ID) {
                    localStorage.removeItem('active_project_id');
                }
            }
            fetchProjects();
        } catch (error) {
            message.error(`${actionLabel}失败`);
        }
    };

    // ── Delete with impact assessment ──
    const openDeleteModal = async (project: API.Project) => {
        setDeleteTarget(project);
        setDeleteConfirmText('');
        setDeleteStats(null);
        setDeleteModalOpen(true);

        // Fetch stats
        setLoadingStats(true);
        try {
            const stats = await getProjectStats(project.ID);
            setDeleteStats(stats);
        } catch {
            setDeleteStats({ project_id: project.ID, project_name: project.Name, tasks: 0, assets: 0, fingerprints: 0, vulns: 0 });
        } finally {
            setLoadingStats(false);
        }
    };

    const handleDelete = async () => {
        if (!deleteTarget) return;
        setDeleting(true);
        try {
            await deleteProject(deleteTarget.ID);
            message.success('项目已软删除');
            // 清除活动项目
            const activeProjectId = localStorage.getItem('active_project_id');
            if (activeProjectId === deleteTarget.ID) {
                localStorage.removeItem('active_project_id');
            }
            setDeleteModalOpen(false);
            setDeleteTarget(null);
            fetchProjects();
        } catch (error) {
            message.error('删除失败');
        } finally {
            setDeleting(false);
        }
    };

    const hasImpact = deleteStats && (deleteStats.tasks > 0 || deleteStats.assets > 0 || deleteStats.vulns > 0);

    const columns: ColumnsType<API.Project> = [
        {
            title: '项目名称',
            dataIndex: 'Name',
            key: 'name',
            render: (name: string, record) => (
                <Space direction="vertical" size={0}>
                    <Space size={6}>
                        <Text strong style={{ fontSize: 14 }}>{name}</Text>
                        {record.Status === 'archived' && (
                            <Tag color="default" style={{ margin: 0, fontSize: 10, lineHeight: '16px', borderRadius: 3 }}>
                                <InboxOutlined style={{ marginRight: 2 }} />已归档
                            </Tag>
                        )}
                    </Space>
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
            width: 100,
            render: (status: string) => {
                const map: Record<string, { color: string; label: string }> = {
                    active: { color: 'success', label: '活跃' },
                    archived: { color: 'default', label: '已归档' },
                };
                const info = map[status] || { color: 'default', label: status };
                return <Tag color={info.color}>{info.label}</Tag>;
            },
            filters: [
                { text: '活跃', value: 'active' },
                { text: '已归档', value: 'archived' },
            ],
            onFilter: (value, record) => record.Status === value,
        },
        {
            title: '创建时间',
            dataIndex: 'CreatedAt',
            key: 'created_at',
            width: 170,
            render: (val: string) => <Text style={{ fontSize: 12, color: '#64748b' }}>{dayjs(val).format('YYYY-MM-DD HH:mm:ss')}</Text>,
        },
        ...(canManageProjects ? [{
            title: '操作',
            key: 'actions',
            width: 160,
            render: (_: unknown, record: API.Project) => (
                <Space size={4}>
                    {record.Status === 'active' ? (
                        <Tooltip title="归档项目">
                            <Button
                                type="text" size="small"
                                icon={<InboxOutlined style={{ color: '#f59e0b' }} />}
                                onClick={() => handleToggleArchive(record)}
                            />
                        </Tooltip>
                    ) : (
                        <Tooltip title="恢复项目">
                            <Button
                                type="text" size="small"
                                icon={<UndoOutlined style={{ color: '#10b981' }} />}
                                onClick={() => handleToggleArchive(record)}
                            />
                        </Tooltip>
                    )}
                    <Tooltip title="删除项目">
                        <Button
                            type="text" size="small" danger
                            icon={<DeleteOutlined />}
                            onClick={() => openDeleteModal(record)}
                        />
                    </Tooltip>
                </Space>
            ),
        } as ColumnsType<API.Project>[number]] : []),
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
                        rowClassName={(record) => record.Status === 'archived' ? 'archived-row' : ''}
                    />
                )}
            </ProCard>

            {/* ── 新建项目 Modal ── */}
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

            {/* ── 删除确认 Modal (带影响评估) ── */}
            <Modal
                title={
                    <Space>
                        <ExclamationCircleOutlined style={{ color: '#ef4444', fontSize: 18 }} />
                        <span>确认删除项目</span>
                    </Space>
                }
                open={deleteModalOpen}
                onCancel={() => { setDeleteModalOpen(false); setDeleteTarget(null); }}
                footer={[
                    <Button key="cancel" onClick={() => { setDeleteModalOpen(false); setDeleteTarget(null); }}>
                        取消
                    </Button>,
                    <Button
                        key="delete"
                        danger
                        type="primary"
                        loading={deleting}
                        disabled={hasImpact ? deleteConfirmText !== deleteTarget?.Name : false}
                        onClick={handleDelete}
                        icon={<DeleteOutlined />}
                    >
                        确认软删除
                    </Button>,
                ]}
                width={520}
            >
                {deleteTarget && (
                    <div>
                        {/* 项目基本信息 */}
                        <div style={{
                            padding: '12px 16px', borderRadius: 8, marginBottom: 16,
                            background: '#f8fafc', border: '1px solid #e2e8f0',
                        }}>
                            <Text strong style={{ fontSize: 15 }}>{deleteTarget.Name}</Text>
                            <div><Text style={{ fontSize: 11, color: '#94a3b8', fontFamily: 'monospace' }}>{deleteTarget.ID}</Text></div>
                        </div>

                        {/* 影响范围统计 */}
                        {loadingStats ? (
                            <div style={{ textAlign: 'center', padding: '24px 0' }}><Spin /></div>
                        ) : deleteStats && (
                            <>
                                <div style={{
                                    padding: '12px 16px', borderRadius: 8, marginBottom: 16,
                                    background: hasImpact ? '#fef2f2' : '#f0fdf4',
                                    border: `1px solid ${hasImpact ? '#fecaca' : '#bbf7d0'}`,
                                }}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 12 }}>
                                        {hasImpact ? (
                                            <WarningOutlined style={{ color: '#ef4444' }} />
                                        ) : null}
                                        <Text strong style={{ color: hasImpact ? '#991b1b' : '#166534', fontSize: 13 }}>
                                            {hasImpact ? '⚠️ 该项目包含以下关联数据' : '✅ 该项目无关联数据，可安全删除'}
                                        </Text>
                                    </div>
                                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
                                        <Statistic
                                            title={<span style={{ fontSize: 11 }}><RocketOutlined /> 任务</span>}
                                            value={deleteStats.tasks}
                                            valueStyle={{ fontSize: 20, fontWeight: 700, color: deleteStats.tasks > 0 ? '#ef4444' : '#94a3b8' }}
                                        />
                                        <Statistic
                                            title={<span style={{ fontSize: 11 }}><ApiOutlined /> 资产</span>}
                                            value={deleteStats.assets}
                                            valueStyle={{ fontSize: 20, fontWeight: 700, color: deleteStats.assets > 0 ? '#f97316' : '#94a3b8' }}
                                        />
                                        <Statistic
                                            title={<span style={{ fontSize: 11 }}><ScanOutlined /> 指纹</span>}
                                            value={deleteStats.fingerprints}
                                            valueStyle={{ fontSize: 20, fontWeight: 700, color: deleteStats.fingerprints > 0 ? '#f59e0b' : '#94a3b8' }}
                                        />
                                        <Statistic
                                            title={<span style={{ fontSize: 11 }}><BugOutlined /> 漏洞</span>}
                                            value={deleteStats.vulns}
                                            valueStyle={{ fontSize: 20, fontWeight: 700, color: deleteStats.vulns > 0 ? '#ef4444' : '#94a3b8' }}
                                        />
                                    </div>
                                </div>

                                {/* 软删除说明 */}
                                <div style={{
                                    padding: '10px 14px', borderRadius: 8, marginBottom: 16,
                                    background: '#eff6ff', border: '1px solid #bfdbfe',
                                }}>
                                    <Text style={{ fontSize: 12, color: '#1e40af' }}>
                                        💡 <strong>软删除说明：</strong>项目数据不会被物理删除，仅标记为已删除状态。
                                        项目的关联数据（任务、资产、漏洞等）不受影响。如需恢复，可通过数据库操作还原。
                                    </Text>
                                </div>

                                {/* 高风险确认输入 */}
                                {hasImpact && (
                                    <div>
                                        <Text style={{ fontSize: 12, color: '#64748b' }}>
                                            请输入项目名称 <Text strong code>{deleteTarget.Name}</Text> 以确认删除：
                                        </Text>
                                        <Input
                                            style={{ marginTop: 8 }}
                                            placeholder={deleteTarget.Name}
                                            value={deleteConfirmText}
                                            onChange={(e) => setDeleteConfirmText(e.target.value)}
                                            status={deleteConfirmText && deleteConfirmText !== deleteTarget.Name ? 'error' : undefined}
                                        />
                                    </div>
                                )}
                            </>
                        )}
                    </div>
                )}
            </Modal>

            <style>{`
                .archived-row td {
                    opacity: 0.55;
                }
                .archived-row:hover td {
                    opacity: 0.85;
                }
            `}</style>
        </div>
    );
};

export default ProjectManagement;
