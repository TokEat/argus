import { useCallback, useEffect, useState } from 'react';
import { App, Button, Empty, Form, Input, Modal, Popconfirm, Space, Table, Tag, Typography } from 'antd';
import { DeleteOutlined, EditOutlined, PlusOutlined, ReloadOutlined } from '@ant-design/icons';
import { addSubdomainDictionaryRevision, createSubdomainDictionary, deleteSubdomainDictionary, listSubdomainDictionaries } from '../../services/api';

const { Text } = Typography;

interface Props {
	open: boolean;
	projectId: string;
	onClose: () => void;
	onChanged?: (items: API.SubdomainDictionary[]) => void;
}

export default function SubdomainDictionaryManager({ open, projectId, onClose, onChanged }: Props) {
	const { message } = App.useApp();
	const [items, setItems] = useState<API.SubdomainDictionary[]>([]);
	const [loading, setLoading] = useState(false);
	const [saving, setSaving] = useState(false);
	const [editorOpen, setEditorOpen] = useState(false);
	const [editing, setEditing] = useState<API.SubdomainDictionary | null>(null);
	const [form] = Form.useForm();

	const refresh = useCallback(async () => {
		if (!projectId) return;
		setLoading(true);
		try {
			const result = await listSubdomainDictionaries(projectId);
			setItems(result);
			onChanged?.(result);
		} catch (error) {
			message.error(typeof error === 'string' ? error : '加载子域字典失败');
		} finally {
			setLoading(false);
		}
	}, [message, onChanged, projectId]);

	useEffect(() => { if (open && projectId) void refresh(); }, [open, projectId, refresh]);

	const showEditor = (item?: API.SubdomainDictionary) => {
		setEditing(item || null);
		form.resetFields();
		setEditorOpen(true);
	};

	const save = async () => {
		try {
			const values = await form.validateFields();
			const words = String(values.values || '').split(/\r?\n/).map((value) => value.trim()).filter(Boolean);
			setSaving(true);
			if (editing) await addSubdomainDictionaryRevision(projectId, editing.id, words);
			else await createSubdomainDictionary(projectId, { name: values.name.trim(), values: words });
			message.success(editing ? '新 Revision 已创建' : '增量子域字典已创建');
			setEditorOpen(false);
			await refresh();
		} catch (error) {
			if (typeof error === 'string') message.error(error);
		} finally {
			setSaving(false);
		}
	};

	const remove = async (id: string) => {
		try {
			await deleteSubdomainDictionary(projectId, id);
			message.success('字典已软删除');
			await refresh();
		} catch (error) {
			message.error(typeof error === 'string' ? error : '删除字典失败');
		}
	};

	return <>
		<Modal title="项目增量子域字典" open={open} onCancel={onClose} footer={<Button onClick={onClose}>完成</Button>} width={820}>
			<Space direction="vertical" size={12} style={{ width: '100%' }}>
				<Text type="secondary">内置子域字典始终保留；项目字典只增量补充，并按不可变 Revision 与哈希绑定任务。</Text>
				<Space wrap><Tag color="blue">{items.reduce((sum, item) => sum + item.count, 0)} 个增量词</Tag><Button icon={<ReloadOutlined />} onClick={refresh}>刷新</Button><Button type="primary" icon={<PlusOutlined />} onClick={() => showEditor()}>新增字典</Button></Space>
				<Table size="small" rowKey="id" loading={loading} dataSource={items} pagination={false} locale={{ emptyText: <Empty description="尚未添加增量子域字典" image={Empty.PRESENTED_IMAGE_SIMPLE} /> }} columns={[
					{ title: '名称', dataIndex: 'name' },
					{ title: 'Revision', dataIndex: 'revision', width: 100, render: (value: number) => <Tag>r{value}</Tag> },
					{ title: '条目', dataIndex: 'count', width: 80 },
					{ title: 'SHA-256', dataIndex: 'sha256', ellipsis: true, render: (value: string) => <Text code>{value.slice(0, 12)}…</Text> },
					{ title: '操作', width: 120, render: (_, row) => <Space><Button type="text" aria-label={`新增 Revision ${row.name}`} icon={<EditOutlined />} onClick={() => showEditor(row)} /><Popconfirm title="软删除后历史任务仍保留已绑定 Revision" onConfirm={() => remove(row.id)}><Button danger type="text" aria-label={`删除字典 ${row.name}`} icon={<DeleteOutlined />} /></Popconfirm></Space> },
				]} />
			</Space>
		</Modal>
		<Modal title={editing ? `新增 Revision · ${editing.name}` : '新增增量子域字典'} open={editorOpen} onCancel={() => setEditorOpen(false)} onOk={save} okText="创建 Revision" confirmLoading={saving}>
			<Form form={form} layout="vertical">
				{!editing && <Form.Item name="name" label="字典名称" rules={[{ required: true, whitespace: true, message: '请输入字典名称' }]}><Input placeholder="例如：项目环境前缀" /></Form.Item>}
				<Form.Item name="values" label="子域标签" extra="每行一个单层标签，例如 dev、staging、api；Server 规范化、去重并创建不可变 Revision。" rules={[{ required: true, whitespace: true, message: '请输入至少一项' }]}><Input.TextArea rows={9} placeholder={'dev\nstaging\napi'} /></Form.Item>
			</Form>
		</Modal>
	</>;
}
