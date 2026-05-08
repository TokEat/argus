import React, { useRef, useEffect, useState, useMemo, useCallback } from 'react';
import { Typography, Tag, Space, Row, Col, List, Table, Divider, Button, Modal, Form, Input, Select, message, Popconfirm, Spin, Empty, InputNumber, Alert } from 'antd';
import { ProCard } from '@ant-design/pro-components';
import { SafetyOutlined, CrownOutlined, ToolOutlined, EyeOutlined, PlusOutlined, EditOutlined, DeleteOutlined, ReloadOutlined } from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import gsap from 'gsap';
import NetworkCanvas from '../components/NetworkCanvas';
import { createRoleApi, deleteRoleApi, getTenantQuota, listRoles, updateRoleApi, updateTenantQuota } from '../services/api';

const { Title, Text, Paragraph } = Typography;

const roleMeta: Record<string, { name: string; color: string; gradient: string; icon: React.ReactNode }> = {
    admin: {
        name: '管理员',
        color: '#ef4444',
        gradient: 'linear-gradient(135deg, #ef4444, #f87171)',
        icon: <CrownOutlined style={{ fontSize: 28, color: '#fff' }} />,
    },
    operator: {
        name: '操作员',
        color: '#f59e0b',
        gradient: 'linear-gradient(135deg, #f59e0b, #fbbf24)',
        icon: <ToolOutlined style={{ fontSize: 28, color: '#fff' }} />,
    },
    viewer: {
        name: '观察者',
        color: '#10b981',
        gradient: 'linear-gradient(135deg, #10b981, #34d399)',
        icon: <EyeOutlined style={{ fontSize: 28, color: '#fff' }} />,
    },
};

const matrix = [
    { module: '租户隔离', viewer: '仅本租户', operator: '仅本租户', admin: '仅本租户' },
    { module: '仪表盘 / 项目 / 任务 / 结果', viewer: '查看', operator: '查看 + 任务操作', admin: '全部' },
    { module: '项目创建', viewer: '-', operator: '允许', admin: '允许' },
    { module: '任务下发 / 追加 / 取消 / 删除', viewer: '-', operator: '允许', admin: '允许' },
    { module: '节点状态 / 队列 / Agent 日志', viewer: '查看节点', operator: '查看 + 运维', admin: '全部' },
    { module: '弹药库规则 / 字典', viewer: '查看', operator: '草稿维护', admin: '维护 + 审批 + 回滚' },
    { module: 'EXP 功能', viewer: '需授权后只读', operator: '需授权后执行', admin: '授权管理 + 需授权后使用' },
    { module: '漏洞报表', viewer: '导出', operator: '导出', admin: '导出' },
    { module: 'AI 分析 / 全局问答', viewer: '-', operator: '允许', admin: '允许' },
    { module: '用户与角色管理', viewer: '-', operator: '-', admin: '允许' },
    { module: '云资源与 OSS 分发', viewer: '-', operator: '自有/被绑定 AK/SK', admin: '全租户 + 绑定管理' },
    { module: 'MCP / API Key / AI 配置', viewer: '-', operator: '-', admin: '允许' },
    { module: '客户端构建', viewer: '-', operator: '-', admin: '允许' },
];

const columns: ColumnsType<(typeof matrix)[number]> = [
    { title: '功能域', dataIndex: 'module', key: 'module', width: 220 },
    { title: '观察者 viewer', dataIndex: 'viewer', key: 'viewer' },
    { title: '操作员 operator', dataIndex: 'operator', key: 'operator' },
    { title: '管理员 admin', dataIndex: 'admin', key: 'admin' },
];

const cardStyle = {
    background: '#ffffff', borderRadius: 12,
    border: '1px solid #e2e8f0',
    boxShadow: '0 1px 3px 0 rgba(0, 0, 0, 0.04)',
};

const baseRoleOptions = [
    { value: 'viewer', label: '观察者 viewer' },
    { value: 'operator', label: '操作员 operator' },
    { value: 'admin', label: '管理员 admin' },
];

const RoleManagement: React.FC = () => {
    const pageRef = useRef<HTMLDivElement>(null);
    const [loading, setLoading] = useState(true);
    const [roles, setRoles] = useState<API.RoleDefinition[]>([]);
    const [modalOpen, setModalOpen] = useState(false);
    const [editingRole, setEditingRole] = useState<API.RoleDefinition | null>(null);
    const [quota, setQuota] = useState<API.TenantQuota | null>(null);
    const [form] = Form.useForm();
    const [quotaForm] = Form.useForm();

    useEffect(() => {
        if (!pageRef.current) return;
        const els = pageRef.current.querySelectorAll('.sys-animate-in');
        if (els.length === 0) return;
        const ctx = gsap.context(() => {
            gsap.from(els, {
                y: 24, opacity: 0, duration: 0.45,
                stagger: 0.08, ease: 'power2.out', clearProps: 'transform,opacity',
            });
        }, pageRef);
        return () => ctx.revert();
    }, [roles.length]);

    const fetchRoles = useCallback(async () => {
        setLoading(true);
        try {
            const result = await listRoles();
            setRoles(result.roles || []);
        } catch (err) {
            message.error(String(err));
        } finally {
            setLoading(false);
        }
    }, []);

    const fetchQuota = useCallback(async () => {
        try {
            const result = await getTenantQuota('current');
            setQuota(result);
            quotaForm.setFieldsValue({
                max_concurrent_tasks: result.max_concurrent_tasks,
                max_running_sub_tasks: result.max_running_sub_tasks,
                daily_task_limit: result.daily_task_limit,
            });
        } catch (err) {
            message.error(String(err));
        }
    }, [quotaForm]);

    useEffect(() => { fetchRoles(); fetchQuota(); }, [fetchRoles, fetchQuota]);

    const customRoleCount = useMemo(() => roles.filter((role) => !role.builtin).length, [roles]);

    const openCreateModal = () => {
        setEditingRole(null);
        form.resetFields();
        form.setFieldsValue({ base_role: 'viewer' });
        setModalOpen(true);
    };

    const openEditModal = (role: API.RoleDefinition) => {
        setEditingRole(role);
        form.setFieldsValue({
            name: role.name,
            label: role.label,
            description: role.description,
            base_role: role.base_role || 'viewer',
        });
        setModalOpen(true);
    };

    const submitRole = async () => {
        try {
            const values = await form.validateFields();
            if (editingRole) {
                await updateRoleApi(editingRole.name, values);
                message.success('角色已更新');
            } else {
                await createRoleApi(values);
                message.success('角色已创建');
            }
            setModalOpen(false);
            fetchRoles();
        } catch (err) {
            if (typeof err === 'string') message.error(err);
        }
    };

    const removeRole = async (name: string) => {
        try {
            await deleteRoleApi(name);
            message.success('角色已删除');
            fetchRoles();
        } catch (err) {
            message.error(String(err));
        }
    };

    const submitQuota = async () => {
        try {
            const values = await quotaForm.validateFields();
            const result = await updateTenantQuota('current', {
                max_concurrent_tasks: Number(values.max_concurrent_tasks || 0),
                max_running_sub_tasks: Number(values.max_running_sub_tasks || 0),
                daily_task_limit: Number(values.daily_task_limit || 0),
            });
            setQuota(result);
            message.success('租户配额已更新');
        } catch (err) {
            if (typeof err === 'string') message.error(err);
        }
    };

    const renderRoleCard = (role: API.RoleDefinition) => {
        const meta = roleMeta[role.base_role] || roleMeta.viewer;
        const permissionPreview = (role.permissions || []).slice(0, 7);
        return (
            <Col xs={24} md={12} xl={8} key={role.name}>
                <ProCard style={{ ...cardStyle, height: '100%' }} bodyStyle={{ padding: 0 }}>
                    <div style={{
                        background: meta.gradient, padding: '24px 20px',
                        borderRadius: '12px 12px 0 0',
                        display: 'flex', alignItems: 'center', gap: 12,
                    }}>
                        <div style={{
                            width: 48, height: 48, borderRadius: 12,
                            background: 'rgba(255,255,255,0.2)',
                            display: 'flex', alignItems: 'center', justifyContent: 'center',
                        }}>
                            {meta.icon}
                        </div>
                        <div style={{ minWidth: 0, flex: 1 }}>
                            <Text style={{ color: '#fff', fontSize: 18, fontWeight: 600 }}>{role.label || role.name}</Text>
                            <div>
                                <Tag style={{ background: 'rgba(255,255,255,0.2)', border: 'none', color: '#fff', borderRadius: 20, fontSize: 10 }}>
                                    {role.name}
                                </Tag>
                                <Tag style={{ background: 'rgba(255,255,255,0.2)', border: 'none', color: '#fff', borderRadius: 20, fontSize: 10 }}>
                                    基线 {meta.name}
                                </Tag>
                            </div>
                        </div>
                    </div>
                    <div style={{ padding: '16px 20px' }}>
                        <Space style={{ marginBottom: 10 }}>
                            <Tag color={role.builtin ? 'blue' : 'purple'}>{role.builtin ? '内置角色' : '自定义角色'}</Tag>
                            <Tag color={meta.color}>{role.permissions?.length || 0} 项接口权限</Tag>
                        </Space>
                        <Paragraph style={{ color: '#64748b', fontSize: 13, marginBottom: 16, minHeight: 44 }}>
                            {role.description || '未填写描述'}
                        </Paragraph>
                        <Text strong style={{ fontSize: 12, color: '#1e293b', marginBottom: 8, display: 'block' }}>
                            权限预览
                        </Text>
                        <List
                            size="small"
                            dataSource={permissionPreview}
                            locale={{ emptyText: '暂无权限' }}
                            renderItem={(item) => (
                                <List.Item style={{ padding: '4px 0', border: 'none' }}>
                                    <Space size={6}>
                                        <div style={{ width: 5, height: 5, borderRadius: '50%', background: meta.color }} />
                                        <Text style={{ fontSize: 12, color: '#475569' }}>{item}</Text>
                                    </Space>
                                </List.Item>
                            )}
                        />
                        {!role.builtin && (
                            <Space style={{ marginTop: 12 }}>
                                <Button size="small" icon={<EditOutlined />} onClick={() => openEditModal(role)}>编辑</Button>
                                <Popconfirm title="确认删除此角色？" onConfirm={() => removeRole(role.name)}>
                                    <Button size="small" danger icon={<DeleteOutlined />}>删除</Button>
                                </Popconfirm>
                            </Space>
                        )}
                    </div>
                </ProCard>
            </Col>
        );
    };

    return (
        <div ref={pageRef} style={{ position: 'relative', overflow: 'hidden' }}>
            <NetworkCanvas color="#6366f1" count={25} speed={0.12} linkDist={90} />
            <div className="sys-animate-in" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20, position: 'relative', zIndex: 1 }}>
                <Title level={4} style={{ margin: 0, color: '#1e293b', fontWeight: 600 }}>
                    <SafetyOutlined style={{ marginRight: 8, color: '#6366f1' }} />
                    角色权限管理
                </Title>
                <Space>
                    <Tag color="blue">{roles.length} 个角色</Tag>
                    <Tag color="purple">{customRoleCount} 个自定义</Tag>
                    <Button type="primary" icon={<PlusOutlined />} onClick={openCreateModal}>新建角色</Button>
                    <Button icon={<ReloadOutlined />} onClick={fetchRoles} loading={loading}>刷新</Button>
                </Space>
            </div>

            {loading && roles.length === 0 ? (
                <div style={{ display: 'flex', justifyContent: 'center', padding: '60px 0', position: 'relative', zIndex: 1 }}><Spin size="large" /></div>
            ) : roles.length === 0 ? (
                <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无角色" style={{ padding: '60px 0', position: 'relative', zIndex: 1 }} />
            ) : (
                <Row gutter={[16, 16]} className="sys-animate-in" style={{ position: 'relative', zIndex: 1 }}>
                    {roles.map(renderRoleCard)}
                </Row>
            )}

            <Divider />

            <ProCard style={{ ...cardStyle }} bodyStyle={{ padding: 16 }}>
                <Title level={5} style={{ marginTop: 0, marginBottom: 12, color: '#1e293b' }}>功能权限矩阵</Title>
                <Table
                    columns={columns}
                    dataSource={matrix}
                    rowKey="module"
                    pagination={false}
                    size="small"
                />
                <Paragraph style={{ marginTop: 12, marginBottom: 0, color: '#64748b', fontSize: 12 }}>
                    自定义角色通过基线角色继承后端权限，接口级权限矩阵用于展示和审计；未显式声明的新接口默认要求管理员权限。
                </Paragraph>
            </ProCard>

            <ProCard style={{ ...cardStyle, marginTop: 16 }} bodyStyle={{ padding: 16 }}>
                <Title level={5} style={{ marginTop: 0, marginBottom: 12, color: '#1e293b' }}>租户任务配额</Title>
                <Alert
                    type="info"
                    showIcon
                    style={{ marginBottom: 16 }}
                    message={`当前使用：活跃任务 ${quota?.usage?.active_tasks ?? 0}，运行批次 ${quota?.usage?.running_subtasks ?? 0}，今日任务 ${quota?.usage?.tasks_today ?? 0}`}
                />
                <Form form={quotaForm} layout="inline">
                    <Form.Item name="max_concurrent_tasks" label="活跃任务上限" rules={[{ type: 'number', min: 0, message: '不能小于 0' }]}>
                        <InputNumber min={0} precision={0} />
                    </Form.Item>
                    <Form.Item name="max_running_sub_tasks" label="运行批次上限" rules={[{ type: 'number', min: 0, message: '不能小于 0' }]}>
                        <InputNumber min={0} precision={0} />
                    </Form.Item>
                    <Form.Item name="daily_task_limit" label="每日任务上限" rules={[{ type: 'number', min: 0, message: '不能小于 0' }]}>
                        <InputNumber min={0} precision={0} />
                    </Form.Item>
                    <Form.Item>
                        <Space>
                            <Button type="primary" onClick={submitQuota}>保存配额</Button>
                            <Button onClick={fetchQuota}>刷新使用量</Button>
                        </Space>
                    </Form.Item>
                </Form>
                <Paragraph style={{ marginTop: 12, marginBottom: 0, color: '#64748b', fontSize: 12 }}>
                    配额值为 0 表示不限制；创建任务会校验活跃任务与每日任务数，Agent 认领会校验运行中批次数。
                </Paragraph>
            </ProCard>

            <Modal title={editingRole ? '编辑角色' : '新建角色'} open={modalOpen}
                onOk={submitRole} onCancel={() => setModalOpen(false)} okText="确定" cancelText="取消">
                <Form form={form} layout="vertical" style={{ marginTop: 16 }}>
                    {!editingRole && (
                        <Form.Item name="name" label="角色标识" rules={[
                            { required: true, message: '请输入角色标识' },
                            { pattern: /^[a-z][a-z0-9_-]{1,31}$/, message: '使用小写字母开头，可含数字、-、_，长度 2-32' },
                        ]}>
                            <Input placeholder="例如 security-reviewer" />
                        </Form.Item>
                    )}
                    <Form.Item name="label" label="显示名称" rules={[{ required: true, message: '请输入显示名称' }]}>
                        <Input placeholder="例如 安全观察员" />
                    </Form.Item>
                    <Form.Item name="base_role" label="权限基线" rules={[{ required: true, message: '请选择权限基线' }]}>
                        <Select options={baseRoleOptions} />
                    </Form.Item>
                    <Form.Item name="description" label="描述">
                        <Input.TextArea rows={3} placeholder="说明此角色的使用边界" />
                    </Form.Item>
                </Form>
            </Modal>
        </div>
    );
};

export default RoleManagement;
