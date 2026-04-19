import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Typography, Table, Tag, Space, Button, Modal, Input, Form, App, Spin, Empty, Popconfirm, Progress, InputNumber } from 'antd';
import { ProCard } from '@ant-design/pro-components';
import {
    PlusOutlined,
    ReloadOutlined,
    RocketOutlined,
    DeleteOutlined,
    StopOutlined,
    EyeOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import { listTasks, createTask, deleteTask, cancelTask } from '../services/api';

const { Title, Text } = Typography;
const { TextArea } = Input;

const TaskManagement: React.FC = () => {
    const [loading, setLoading] = useState(true);
    const [tasks, setTasks] = useState<API.RootTask[]>([]);
    const [createOpen, setCreateOpen] = useState(false);
    const [creating, setCreating] = useState(false);
    const [form] = Form.useForm();
    const { message } = App.useApp();
    const navigate = useNavigate();

    const fetchTasks = async () => {
        setLoading(true);
        try {
            const result = await listTasks();
            setTasks(result || []);
        } catch (error) {
            console.error('Failed to fetch tasks:', error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchTasks();
        const timer = setInterval(fetchTasks, 10000);
        return () => clearInterval(timer);
    }, []);

    const handleCreate = async () => {
        try {
            const values = await form.validateFields();
            setCreating(true);
            await createTask({
                name: values.name,
                targets: values.targets,
                config: values.config || '{}',
                priority: values.priority || 0,
                timeout_sec: values.timeout_sec || 3600,
            });
            message.success('任务创建成功');
            setCreateOpen(false);
            form.resetFields();
            fetchTasks();
        } catch (error: unknown) {
            if (typeof error === 'string') message.error(error);
        } finally {
            setCreating(false);
        }
    };

    const handleDelete = async (taskId: string) => {
        try {
            await deleteTask(taskId);
            message.success('任务已删除');
            fetchTasks();
        } catch {
            message.error('删除失败');
        }
    };

    const handleCancel = async (taskId: string) => {
        try {
            await cancelTask(taskId);
            message.success('取消指令已下发');
            fetchTasks();
        } catch {
            message.error('取消失败');
        }
    };

    const getStatusTag = (status: string) => {
        const map: Record<string, { color: string; text: string }> = {
            Pending: { color: 'orange', text: '等待中' },
            Running: { color: 'processing', text: '运行中' },
            FINISHED: { color: 'success', text: '已完成' },
            Cancelled: { color: 'default', text: '已取消' },
            CancelPending: { color: 'warning', text: '取消中' },
        };
        const { color, text } = map[status] || { color: 'default', text: status };
        return <Tag color={color}>{text}</Tag>;
    };

    const columns: ColumnsType<API.RootTask> = [
        {
            title: '任务名称',
            dataIndex: 'Name',
            key: 'name',
            ellipsis: true,
            render: (name: string, record) => (
                <Space direction="vertical" size={0}>
                    <Text strong style={{ fontSize: 13 }}>{name}</Text>
                    <Text style={{ fontSize: 11, color: '#94a3b8', fontFamily: 'monospace' }}>
                        {record.ID}
                    </Text>
                </Space>
            ),
        },
        {
            title: '状态',
            dataIndex: 'Status',
            key: 'status',
            width: 100,
            render: (status: string) => getStatusTag(status),
            filters: [
                { text: '等待中', value: 'Pending' },
                { text: '运行中', value: 'Running' },
                { text: '已完成', value: 'FINISHED' },
                { text: '已取消', value: 'Cancelled' },
            ],
            onFilter: (value, record) => record.Status === value,
        },
        {
            title: '进度',
            key: 'progress',
            width: 160,
            render: (_, record) => {
                if (record.TotalChunks === 0) return <Text type="secondary">-</Text>;
                const pct = Math.round(record.CompletedChunks / record.TotalChunks * 100);
                return (
                    <Space direction="vertical" size={0} style={{ width: '100%' }}>
                        <Progress
                            percent={pct}
                            size="small"
                            status={pct >= 100 ? 'success' : 'active'}
                            strokeColor={pct >= 100 ? '#10b981' : '#0ea5e9'}
                            style={{ marginBottom: 0 }}
                        />
                        <Text style={{ fontSize: 11, color: '#94a3b8' }}>
                            {record.CompletedChunks}/{record.TotalChunks} 分片
                        </Text>
                    </Space>
                );
            },
        },
        {
            title: '优先级',
            dataIndex: 'Priority',
            key: 'priority',
            width: 80,
            render: (v: number) => v || <Text type="secondary">0</Text>,
        },
        {
            title: '创建时间',
            dataIndex: 'CreatedAt',
            key: 'created_at',
            width: 170,
            render: (v: string) => <Text style={{ fontSize: 12, color: '#64748b' }}>{v}</Text>,
        },
        {
            title: '操作',
            key: 'actions',
            width: 200,
            render: (_, record) => (
                <Space size={4}>
                    <Button type="link" size="small" icon={<EyeOutlined />}
                        onClick={() => navigate(`/tasks/${record.ID}/results`)}>
                        结果
                    </Button>
                    {(record.Status === 'Pending' || record.Status === 'Running') && (
                        <Popconfirm title="确认取消此任务？" onConfirm={() => handleCancel(record.ID)}>
                            <Button type="text" size="small" danger icon={<StopOutlined />}>
                                取消
                            </Button>
                        </Popconfirm>
                    )}
                    <Popconfirm title="确认删除此任务？" onConfirm={() => handleDelete(record.ID)}>
                        <Button type="text" size="small" danger icon={<DeleteOutlined />}>
                            删除
                        </Button>
                    </Popconfirm>
                </Space>
            ),
        },
    ];

    return (
        <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
                <Title level={4} style={{ margin: 0, color: '#1e293b', fontWeight: 600 }}>
                    <RocketOutlined style={{ marginRight: 8, color: '#10b981' }} />
                    任务管理
                </Title>
                <Space>
                    <Button icon={<ReloadOutlined />} onClick={fetchTasks} loading={loading}>
                        刷新
                    </Button>
                    <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>
                        创建任务
                    </Button>
                </Space>
            </div>

            <ProCard className="glass-card" style={{ background: 'transparent', border: 'none' }}>
                {loading && tasks.length === 0 ? (
                    <div style={{ display: 'flex', justifyContent: 'center', padding: '60px 0' }}>
                        <Spin size="large" />
                    </div>
                ) : tasks.length === 0 ? (
                    <Empty
                        image={Empty.PRESENTED_IMAGE_SIMPLE}
                        description="暂无扫描任务"
                        style={{ padding: '60px 0' }}
                    >
                        <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>
                            创建第一个任务
                        </Button>
                    </Empty>
                ) : (
                    <Table
                        columns={columns}
                        dataSource={tasks}
                        rowKey="ID"
                        pagination={{ pageSize: 15, showSizeChanger: true, showTotal: (total) => `共 ${total} 个任务` }}
                        size="middle"
                    />
                )}
            </ProCard>

            {/* Create Task Modal */}
            <Modal
                title="创建扫描任务"
                open={createOpen}
                onCancel={() => setCreateOpen(false)}
                onOk={handleCreate}
                okText="创建"
                confirmLoading={creating}
                width={600}
            >
                <Form form={form} layout="vertical" style={{ marginTop: 16 }}>
                    <Form.Item label="任务名称" name="name" rules={[{ required: true, message: '请输入任务名称' }]}>
                        <Input placeholder="输入任务名称" />
                    </Form.Item>
                    <Form.Item
                        label="扫描目标"
                        name="targets"
                        rules={[{ required: true, message: '请输入扫描目标' }]}
                        extra="每行一个目标，支持 IP、域名、CIDR"
                    >
                        <TextArea rows={6} placeholder={"192.168.1.0/24\nexample.com\n10.0.0.1"} />
                    </Form.Item>
                    <Form.Item
                        label="扫描配置（JSON）"
                        name="config"
                        extra="可选，JSON 格式的额外配置参数"
                    >
                        <TextArea rows={3} placeholder='{"threads": 10, "timeout": 300}' />
                    </Form.Item>
                    <Space style={{ display: 'flex', width: '100%' }}>
                        <Form.Item label="任务优先级" name="priority" initialValue={0} extra="数值越高越优先">
                            <InputNumber min={0} max={100} style={{ width: '100%' }} />
                        </Form.Item>
                        <Form.Item label="任务超时(秒)" name="timeout_sec" initialValue={3600} extra="默认3600秒">
                            <InputNumber min={60} step={60} style={{ width: '100%' }} />
                        </Form.Item>
                    </Space>
                </Form>
            </Modal>
        </div>
    );
};

export default TaskManagement;
