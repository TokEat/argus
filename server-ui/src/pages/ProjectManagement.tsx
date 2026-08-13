import React, { useEffect, useState } from 'react';
import { App, Button, Form, Input, Modal, Space, Table, Tag, Typography, Spin, Empty, Statistic, Tooltip, Select } from 'antd';
import { ProCard } from '@ant-design/pro-components';
import {
    PlusOutlined, ProjectOutlined, ReloadOutlined,
    DeleteOutlined, InboxOutlined, UndoOutlined,
    ExclamationCircleOutlined, BugOutlined, ScanOutlined,
    ApiOutlined, RocketOutlined, WarningOutlined,
    TeamOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import {
    listProjects,
    createProject,
    updateProject,
    deleteProject,
    getProjectStats,
    listUsers,
    getProjectMembers,
    updateProjectMembers,
} from '../services/api';
import { canAccessRole, getCurrentUserRole } from '../utils/auth';
import dayjs from 'dayjs';
import NetworkCanvas from '../components/NetworkCanvas';
import { notifyProjectsChanged } from '../utils/projectSelection';

const { Title, Text } = Typography;

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
    const { message } = App.useApp();
    const currentRole = getCurrentUserRole();
    const isAdmin = currentRole === 'admin';
    const canCreateProjects = canAccessRole('operator');
    const canManageProject = (project: API.Project) => isAdmin || project.access_level === 'owner';
    // Delete confirmation state
    const [deleteModalOpen, setDeleteModalOpen] = useState(false);
    const [deleteTarget, setDeleteTarget] = useState<API.Project | null>(null);
    const [deleteStats, setDeleteStats] = useState<ProjectStats | null>(null);
    const [loadingStats, setLoadingStats] = useState(false);
    const [deleteConfirmText, setDeleteConfirmText] = useState('');
    const [deleting, setDeleting] = useState(false);
    const [tenantUsers, setTenantUsers] = useState<API.User[]>([]);
    const [memberModalOpen, setMemberModalOpen] = useState(false);
    const [memberProject, setMemberProject] = useState<API.Project | null>(null);
    const [memberUserIds, setMemberUserIds] = useState<string[]>([]);
    const [memberKeys, setMemberKeys] = useState<string[]>([]);
    const [memberSaving, setMemberSaving] = useState(false);

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

    const fetchTenantUsers = async () => {
        try {
            const users = await listUsers();
            const activeUsers = (users || []).filter((u) => u.status === 'active');
            setTenantUsers(activeUsers);
            return activeUsers;
        } catch (error) {
            console.error('Failed to fetch tenant users:', error);
            return [];
        }
    };

    useEffect(() => {
        fetchProjects();
        if (isAdmin) fetchTenantUsers();
    }, []);

    const handleCreate = async () => {
        if (!canCreateProjects) return;
        try {
            const values = await form.validateFields();
            setCreating(true);

            const created = await createProject({
                name: values.name,
                description: values.description,
                member_user_ids: isAdmin ? values.member_user_ids : undefined,
            });

            message.success('项目创建成功');
            localStorage.setItem('active_project_id', created.ID);
            notifyProjectsChanged(created.ID);
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
        if (!canManageProject(project)) return;
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
            notifyProjectsChanged();
            fetchProjects();
        } catch (error) {
            message.error(`${actionLabel}失败`);
        }
    };

    // ── Delete with impact assessment ──
    const openDeleteModal = async (project: API.Project) => {
        if (!canManageProject(project)) return;
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
        if (!canManageProject(deleteTarget)) return;
        setDeleting(true);
        try {
            await deleteProject(deleteTarget.ID);
            message.success('项目已软删除');
            // 清除活动项目
            const activeProjectId = localStorage.getItem('active_project_id');
            if (activeProjectId === deleteTarget.ID) {
                localStorage.removeItem('active_project_id');
            }
            notifyProjectsChanged();
            setDeleteModalOpen(false);
            setDeleteTarget(null);
            fetchProjects();
        } catch (error) {
            message.error('删除失败');
        } finally {
            setDeleting(false);
        }
    };

    const handleOpenMembers = async (project: API.Project) => {
        if (!canManageProject(project)) return;
        setMemberProject(project);
        setMemberUserIds(project.member_user_ids || []);
        setMemberKeys((project.members || []).filter((m) => m.role !== 'owner').map((m) => `${m.user_id}:${m.role}`));
        setMemberModalOpen(true);
        if (tenantUsers.length === 0) fetchTenantUsers();
        try {
            const res = await getProjectMembers(project.ID);
            setMemberUserIds((res.user_ids || []).map(String));
            setMemberKeys(((res as { members?: API.ProjectMember[] }).members || [])
                .filter((m) => m.role !== 'owner')
                .map((m) => `${m.user_id}:${m.role}`));
        } catch (error) {
            message.error(typeof error === 'string' ? error : '加载项目成员失败');
        }
    };

    const handleSaveMembers = async () => {
        if (!memberProject) return;
        setMemberSaving(true);
        try {
            const members = memberKeys.map((key) => {
                const [user_id, role] = key.split(':') as [string, API.ProjectMember['role']];
                return { user_id, role };
            });
            await updateProjectMembers(memberProject.ID, members.length > 0 ? members : memberUserIds);
            message.success('项目分发已更新');
            setMemberModalOpen(false);
            setMemberProject(null);
            fetchProjects();
        } catch (error) {
            message.error(typeof error === 'string' ? error : '保存项目成员失败');
        } finally {
            setMemberSaving(false);
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
            title: '归属',
            key: 'owner',
            width: 150,
            render: (_: unknown, record: API.Project) => (
                <Space direction="vertical" size={2}>
                    <Text style={{ fontSize: 12 }}>{record.owner_username || record.OwnerUserID || '-'}</Text>
                    <Tag
                        color={record.access_level === 'member' ? 'cyan' : record.access_level === 'owner' ? 'green' : 'purple'}
                        style={{ margin: 0, width: 'fit-content' }}
                    >
                        {record.access_level === 'member' ? '被分发' : record.access_level === 'owner' ? '我的项目' : '管理员可管'}
                    </Tag>
                </Space>
            ),
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
        ...(canCreateProjects ? [{
            title: '操作',
            key: 'actions',
            width: 210,
            render: (_: unknown, record: API.Project) => {
                const manageable = canManageProject(record);
                return (
                    <Space size={4}>
                        {manageable && (record.Status === 'active' ? (
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
                        ))}
                        {isAdmin && (
                            <Tooltip title="项目分发">
                                <Button
                                    type="text" size="small"
                                    icon={<TeamOutlined style={{ color: '#0ea5e9' }} />}
                                    onClick={() => handleOpenMembers(record)}
                                />
                            </Tooltip>
                        )}
                        {manageable && (
                            <Tooltip title="删除项目">
                                <Button
                                    type="text" size="small" danger
                                    icon={<DeleteOutlined />}
                                    onClick={() => openDeleteModal(record)}
                                />
                            </Tooltip>
                        )}
                        {!manageable && !isAdmin && <Text type="secondary" style={{ fontSize: 12 }}>仅参与</Text>}
                    </Space>
                );
            },
        } as ColumnsType<API.Project>[number]] : []),
    ];

    return (
        <div style={{ position: 'relative', overflow: 'hidden' }}>
            <NetworkCanvas color="#0ea5e9" count={30} speed={0.15} linkDist={100} />
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20, position: 'relative', zIndex: 1 }}>
                <Title level={4} style={{ margin: 0, color: '#1e293b', fontWeight: 600 }}>
                    <ProjectOutlined style={{ marginRight: 8, color: '#0ea5e9' }} />
                    项目管理
                </Title>
                <Space>
                    <Button icon={<ReloadOutlined />} onClick={fetchProjects} loading={loading}>
                        刷新
                    </Button>
                    {canCreateProjects && (
                        <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>
                            新建项目
                        </Button>
                    )}
                </Space>
            </div>

            <ProCard className="glass-card" style={{ background: 'transparent', border: 'none', position: 'relative', zIndex: 1 }}>
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
                        {canCreateProjects && (
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
            {canCreateProjects && (
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
                        {isAdmin && (
                        <Form.Item name="member_user_ids" label="分发给操作员">
                                <Select
                                    mode="multiple"
                                    placeholder="选择可参与该项目的用户"
                                    options={tenantUsers.map((u) => ({ label: u.username, value: String(u.id) }))}
                                />
                            </Form.Item>
                        )}
                    </Form>
                </Modal>
            )}

            {(isAdmin || memberProject?.access_level === 'owner') && (
                <Modal
                    title={`项目分发${memberProject ? ` - ${memberProject.Name}` : ''}`}
                    open={memberModalOpen}
                    onCancel={() => setMemberModalOpen(false)}
                    onOk={handleSaveMembers}
                    okText="保存"
                    confirmLoading={memberSaving}
                >
                    <Select
                        mode="multiple"
                        style={{ width: '100%', marginTop: 12 }}
                        placeholder="选择项目成员及权限"
                        value={memberKeys}
                        onChange={setMemberKeys}
                        options={tenantUsers.flatMap((u) => [
                            { label: `${u.username} - viewer`, value: `${u.id}:viewer` },
                            { label: `${u.username} - operator`, value: `${u.id}:operator` },
                            { label: `${u.username} - owner`, value: `${u.id}:owner` },
                        ])}
                    />
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
