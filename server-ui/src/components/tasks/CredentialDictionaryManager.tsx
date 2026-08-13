import { useCallback, useEffect, useMemo, useState } from 'react';
import { App, Button, Empty, Form, Input, Modal, Popconfirm, Segmented, Space, Table, Tag, Typography } from 'antd';
import { DeleteOutlined, PlusOutlined, ReloadOutlined } from '@ant-design/icons';
import { createCredentialDictionary, deleteCredentialDictionary, listCredentialDictionaries } from '../../services/api';

const { Text } = Typography;

interface Props {
    open: boolean;
    projectId: string;
    onClose: () => void;
    onChanged?: (items: API.CredentialDictionary[]) => void;
}

export default function CredentialDictionaryManager({ open, projectId, onClose, onChanged }: Props) {
    const { message } = App.useApp();
    const [items, setItems] = useState<API.CredentialDictionary[]>([]);
    const [loading, setLoading] = useState(false);
    const [saving, setSaving] = useState(false);
    const [createOpen, setCreateOpen] = useState(false);
    const [kind, setKind] = useState<'username' | 'password'>('username');
    const [form] = Form.useForm();

    const refresh = useCallback(async () => {
        if (!projectId) return;
        setLoading(true);
        try {
            const result = await listCredentialDictionaries(projectId);
            setItems(result);
            onChanged?.(result);
        } catch (error) {
            message.error(typeof error === 'string' ? error : '加载项目字典失败');
        } finally {
            setLoading(false);
        }
    }, [message, onChanged, projectId]);

    useEffect(() => {
        if (open && projectId) void refresh();
    }, [open, projectId, refresh]);

    const create = async () => {
        try {
            const values = await form.validateFields();
            const dictionaryValues = String(values.values || '').split(/\r?\n/).map((value) => value.trim()).filter(Boolean);
            setSaving(true);
            await createCredentialDictionary(projectId, { name: values.name.trim(), kind, values: dictionaryValues });
            message.success('字典 Revision 已创建');
            form.resetFields();
            setCreateOpen(false);
            await refresh();
        } catch (error) {
            if (typeof error === 'string') message.error(error);
        } finally {
            setSaving(false);
        }
    };

    const remove = async (dictionaryId: string) => {
        try {
            await deleteCredentialDictionary(projectId, dictionaryId);
            message.success('字典已软删除');
            await refresh();
        } catch (error) {
            message.error(typeof error === 'string' ? error : '删除字典失败');
        }
    };

    const summary = useMemo(() => ({
        usernames: items.filter((item) => item.kind === 'username').reduce((sum, item) => sum + item.count, 0),
        passwords: items.filter((item) => item.kind === 'password').reduce((sum, item) => sum + item.count, 0),
    }), [items]);

    return (
        <>
            <Modal title="项目增量凭据字典" open={open} onCancel={onClose} footer={<Button onClick={onClose}>完成</Button>} width={820}>
                <Space direction="vertical" size={12} style={{ width: '100%' }}>
                    <Text type="secondary">内置服务字典始终保留；这里维护的用户名本和密码本只作为增量补充，并按不可变 Revision 绑定任务。</Text>
                    <Space wrap>
                        <Tag color="blue">用户名 {summary.usernames}</Tag>
                        <Tag color="purple">密码 {summary.passwords}</Tag>
                        <Button icon={<ReloadOutlined />} onClick={refresh} loading={loading}>刷新</Button>
                        <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>新增字典</Button>
                    </Space>
                    <Table
                        size="small"
                        loading={loading}
                        rowKey="id"
                        dataSource={items}
                        locale={{ emptyText: <Empty description="尚未添加增量字典" image={Empty.PRESENTED_IMAGE_SIMPLE} /> }}
                        pagination={false}
                        columns={[
                            { title: '名称', dataIndex: 'name' },
                            { title: '类型', dataIndex: 'kind', width: 100, render: (value: string) => <Tag color={value === 'username' ? 'blue' : 'purple'}>{value === 'username' ? '用户名本' : '密码本'}</Tag> },
                            { title: 'Revision', dataIndex: 'revision', width: 100, render: (value: number) => <Tag>r{value}</Tag> },
                            { title: '条目', dataIndex: 'count', width: 80 },
                            { title: 'SHA-256', dataIndex: 'sha256', ellipsis: true, render: (value: string) => <Text code>{value.slice(0, 12)}…</Text> },
                            { title: '操作', width: 80, render: (_, row) => <Popconfirm title="仅未被任务 Revision 引用的字典可删除" onConfirm={() => remove(row.id)}><Button danger type="text" aria-label={`删除字典 ${row.name}`} icon={<DeleteOutlined />} /></Popconfirm> },
                        ]}
                    />
                </Space>
            </Modal>
            <Modal title="新增增量字典" open={createOpen} onCancel={() => setCreateOpen(false)} onOk={create} confirmLoading={saving} okText="创建 Revision">
                <Form form={form} layout="vertical">
                    <Form.Item label="类型">
                        <Segmented block value={kind} onChange={(value) => setKind(value as 'username' | 'password')} options={[{ label: '用户名本', value: 'username' }, { label: '密码本', value: 'password' }]} />
                    </Form.Item>
                    <Form.Item label="字典名称" name="name" rules={[{ required: true, whitespace: true, message: '请输入字典名称' }]}>
                        <Input placeholder={kind === 'username' ? '例如：运维账号补充' : '例如：项目默认口令补充'} />
                    </Form.Item>
                    <Form.Item label="条目" name="values" extra="每行一项；Server 去重、加密并创建不可变 Revision。" rules={[{ required: true, whitespace: true, message: '请输入至少一项' }]}>
                        <Input.TextArea rows={8} autoComplete="off" placeholder={kind === 'username' ? 'ops\nbackup\nmonitor' : '每行一个增量密码'} />
                    </Form.Item>
                </Form>
            </Modal>
        </>
    );
}
