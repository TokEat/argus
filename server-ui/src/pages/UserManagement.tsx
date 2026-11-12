import React, { useEffect, useState } from 'react';
import { Typography, Table, Tag, Space, Button, Spin, Empty, Modal, Form, Input, Select, Switch, message, Popconfirm } from 'antd';
import { ProCard } from '@ant-design/pro-components';
import { TeamOutlined, ReloadOutlined, PlusOutlined, EditOutlined, DeleteOutlined } from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import { listUsers, createUserApi, updateUserApi, deleteUserApi, listRoles } from '../services/api';
import NetworkCanvas from '../components/NetworkCanvas';

const { Title, Text } = Typography;

const roleColors: Record<string, string> = {
    admin: '#ef4444',
    operator: '#f59e0b',
    viewer: '#10b981',
};

const UserManagement: React.FC = () => {
    const [loading, setLoading] = useState(true);
    const [users, setUsers] = useState<API.User[]>([]);
    const [roles, setRoles] = useState<API.RoleDefinition[]>([]);
    const [modalOpen, setModalOpen] = useState(false);
    const [editingUser, setEditingUser] = useState<API.User | null>(null);
    const [form] = Form.useForm();
    const fetchUsers = async () => {
        setLoading(true);
        try {
            const result = await listUsers();
            setUsers(result || []);
        } catch (error) {
            console.error('Failed to fetch users:', error);
        } finally {
            setLoading(false);
        }
    };

    const fetchRoles = async () => {
        try {
            const result = await listRoles();
            setRoles(result.roles || []);
        } catch (error) {
            console.error('Failed to fetch roles:', error);
        }
    };

    useEffect(() => { fetchUsers(); fetchRoles(); }, []);

    const handleCreate = () => {
        setEditingUser(null);
        form.resetFields();
        setModalOpen(true);
    };

    const handleEdit = (user: API.User) => {
        setEditingUser(user);
        form.setFieldsValue({ username: user.username, role: user.role, status: user.status, exp_authorized: user.exp_authorized });
        setModalOpen(true);
    };

    const handleDelete = async (id: number) => {
        try {
            await deleteUserApi(id);
            message.success('用户已删除');
            fetchUsers();
        } catch (err) {
            message.error(String(err));
        }
    };

    const handleSubmit = async () => {
        try {
            const values = await form.validateFields();
            if (editingUser) {
                await updateUserApi(editingUser.id, {
                    role: values.role,
                    status: values.status,
                    password: values.password || undefined,
                    exp_authorized: !!values.exp_authorized,
                });
                message.success('用户已更新');
            } else {
                await createUserApi({
                    username: values.username,
                    password: values.password,
                    role: values.role || 'viewer',
                    exp_authorized: !!values.exp_authorized,
                });
                message.success('用户已创建');
            }
            setModalOpen(false);
            fetchUsers();
        } catch (err) {
            if (typeof err === 'string') message.error(err);
        }
    };

    const roleOptions = (roles.length > 0 ? roles : [
        { name: 'admin', label: '管理员', base_role: 'admin' },
        { name: 'operator', label: '操作员', base_role: 'operator' },
        { name: 'viewer', label: '观察者', base_role: 'viewer' },
    ] as API.RoleDefinition[]).map((role) => ({
        value: role.name,
        label: `${role.label || role.name} - ${role.name}`,
        baseRole: role.base_role,
    }));

    const roleLabelMap = Object.fromEntries(roleOptions.map((role) => [role.value, role.label.split(' - ')[0]]));
    const roleBaseMap = Object.fromEntries(roleOptions.map((role) => [role.value, role.baseRole]));

    const columns: ColumnsType<API.User> = [
        {
            title: 'ID', dataIndex: 'id', key: 'id', width: 60,
        },
        {
            title: '用户名', dataIndex: 'username', key: 'username',
            render: (v: string) => <Text style={{ fontWeight: 500 }}>{v}</Text>,
        },
        {
            title: '角色', dataIndex: 'role', key: 'role', width: 120,
            render: (role: string) => (
                <Tag color={roleColors[roleBaseMap[role] || role] || '#94a3b8'} style={{ borderRadius: 20, fontSize: 11 }}>
                    {roleLabelMap[role] || role}
                </Tag>
            ),
            filters: roleOptions.map((role) => ({ text: role.label, value: role.value })),
            onFilter: (value, record) => record.role === value,
        },
        {
            title: '状态', dataIndex: 'status', key: 'status', width: 100,
            render: (s: string) => (
                <Tag color={s === 'active' ? '#10b981' : '#94a3b8'} style={{ borderRadius: 20, fontSize: 11 }}>
                    {s === 'active' ? '正常' : '禁用'}
                </Tag>
            ),
        },
        {
            title: 'EXP 授权', dataIndex: 'exp_authorized', key: 'exp_authorized', width: 110,
            render: (enabled: boolean) => (
                <Tag color={enabled ? '#2563eb' : '#94a3b8'} style={{ borderRadius: 20, fontSize: 11 }}>
                    {enabled ? '已授权' : '未授权'}
                </Tag>
            ),
            filters: [
                { text: '已授权', value: 'true' },
                { text: '未授权', value: 'false' },
            ],
            onFilter: (value, record) => String(record.exp_authorized) === value,
        },
        {
            title: '租户', dataIndex: 'tenant_id', key: 'tenant_id', width: 100,
            render: (v: string) => <Text style={{ fontSize: 12, color: '#64748b' }}>{v}</Text>,
        },
        {
            title: '创建时间', dataIndex: 'created_at', key: 'created_at', width: 180,
            render: (v: string) => <Text style={{ fontSize: 12, color: '#64748b' }}>{v ? new Date(v).toLocaleString('zh-CN') : '-'}</Text>,
        },
        {
            title: '操作', key: 'actions', width: 140,
            render: (_, record) => (
                <Space size={4}>
                    <Button type="link" size="small" icon={<EditOutlined />} onClick={() => handleEdit(record)}>编辑</Button>
                    <Popconfirm title="确认删除此用户？" onConfirm={() => handleDelete(record.id)}>
                        <Button type="link" size="small" danger icon={<DeleteOutlined />}>删除</Button>
                    </Popconfirm>
                </Space>
            ),
        },
    ];

    const cardStyle = {
        background: 'transparent', border: 'none'
    };

    return (
        <div style={{ position: 'relative', overflow: 'hidden' }}>
            <NetworkCanvas color="#6366f1" count={25} speed={0.12} linkDist={90} />
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20, position: 'relative', zIndex: 1 }}>
                <Title level={4} style={{ margin: 0, color: '#1e293b', fontWeight: 600 }}>
                    <TeamOutlined style={{ marginRight: 8, color: '#6366f1' }} />
                    用户管理
                </Title>
                <Space>
                    <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>新建用户</Button>
                    <Button icon={<ReloadOutlined />} onClick={fetchUsers} loading={loading}>刷新</Button>
                </Space>
            </div>

            <ProCard className="glass-card" style={{ ...cardStyle, position: 'relative', zIndex: 1 }}>
                {loading && users.length === 0 ? (
                    <div style={{ display: 'flex', justifyContent: 'center', padding: '60px 0' }}><Spin size="large" /></div>
                ) : users.length === 0 ? (
                    <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无用户，点击上方「新建用户」创建" style={{ padding: '60px 0' }} />
                ) : (
                    <Table columns={columns} dataSource={users} rowKey="id"
                        pagination={{ pageSize: 20, showTotal: (total) => `共 ${total} 个用户` }} size="middle" />
                )}
            </ProCard>

            <Modal title={editingUser ? '编辑用户' : '新建用户'} open={modalOpen}
                onOk={handleSubmit} onCancel={() => setModalOpen(false)} okText="确定" cancelText="取消">
                <Form form={form} layout="vertical" style={{ marginTop: 16 }}>
                    {!editingUser && (
                        <Form.Item name="username" label="用户名" rules={[{ required: true, message: '请输入用户名' }]}>
                            <Input placeholder="请输入用户名" />
                        </Form.Item>
                    )}
                    <Form.Item name="password" label={editingUser ? '新密码（留空则不修改）' : '密码'}
                        rules={editingUser ? [] : [{ required: true, message: '请输入密码' }]}>
                        <Input.Password placeholder="请输入密码" />
                    </Form.Item>
                    <Form.Item name="role" label="角色" initialValue="viewer">
                        <Select options={roleOptions.map((role) => ({ value: role.value, label: role.label }))} />
                    </Form.Item>
                    <Form.Item name="exp_authorized" label="EXP 授权" valuePropName="checked" initialValue={false}>
                        <Switch checkedChildren="已授权" unCheckedChildren="未授权" />
                    </Form.Item>
                    {editingUser && (
                        <Form.Item name="status" label="状态">
                            <Select options={[
                                { value: 'active', label: '正常' },
                                { value: 'disabled', label: '禁用' },
                            ]} />
                        </Form.Item>
                    )}
                </Form>
            </Modal>
        </div>
    );
};

export default UserManagement;
