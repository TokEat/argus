import React, { useEffect, useState } from 'react';
import { Typography, Table, Tag, Space, Button, Spin, Empty, Modal, Form, Select, Switch, message, Row, Col, Alert } from 'antd';
import { ProCard } from '@ant-design/pro-components';
import {
    BuildOutlined, ReloadOutlined, ThunderboltOutlined,
    AppleOutlined, WindowsOutlined, CloudOutlined, DownloadOutlined,
    StopOutlined, RedoOutlined, FileTextOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import { cancelBuildJob, getBuildJobLogs, listBuildArtifacts, listBuildJobs, retryBuildJob, triggerBuild } from '../services/api';

const { Title, Text } = Typography;

const platformIcons: Record<string, React.ReactNode> = {
    darwin: <AppleOutlined style={{ color: '#64748b' }} />,
    windows: <WindowsOutlined style={{ color: '#0ea5e9' }} />,
    linux: <CloudOutlined style={{ color: '#f59e0b' }} />,
};

const platformNames: Record<string, string> = {
    darwin: 'macOS', windows: 'Windows', linux: 'Linux', unknown: '未知',
};

const formatSize = (bytes: number) => {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1024 / 1024).toFixed(1) + ' MB';
};

const ClientBuild: React.FC = () => {
    const [loading, setLoading] = useState(true);
    const [artifacts, setArtifacts] = useState<API.BuildArtifact[]>([]);
    const [jobs, setJobs] = useState<API.BuildJob[]>([]);
    const [buildModalOpen, setBuildModalOpen] = useState(false);
    const [building, setBuilding] = useState(false);
    const [jobActionLoading, setJobActionLoading] = useState<Record<number, string>>({});
    const [logModalOpen, setLogModalOpen] = useState(false);
    const [logLoading, setLogLoading] = useState(false);
    const [selectedJob, setSelectedJob] = useState<API.BuildJob | null>(null);
    const [jobLog, setJobLog] = useState('');
    const [form] = Form.useForm();

    const fetchArtifacts = async () => {
        setLoading(true);
        try {
            const [result, jobResult] = await Promise.all([listBuildArtifacts(), listBuildJobs(20)]);
            setArtifacts(result || []);
            setJobs(jobResult || []);
        } catch (error) {
            console.error('Failed to fetch artifacts:', error);
        } finally {
            setLoading(false);
        }
    };

    const withJobAction = async (job: API.BuildJob, action: string, runner: () => Promise<API.MessageResponse>) => {
        setJobActionLoading((prev) => ({ ...prev, [job.id]: action }));
        try {
            const res = await runner();
            message.success(res?.message || '操作已提交');
            fetchArtifacts();
        } catch (err) {
            if (typeof err === 'string') message.error(err);
        } finally {
            setJobActionLoading((prev) => {
                const next = { ...prev };
                delete next[job.id];
                return next;
            });
        }
    };

    const handleCancelJob = (job: API.BuildJob) => {
        Modal.confirm({
            title: '取消构建任务',
            content: `确认取消 ${job.platform}/${job.arch} 构建吗？`,
            okText: '取消构建',
            okButtonProps: { danger: true },
            cancelText: '关闭',
            onOk: () => withJobAction(job, 'cancel', () => cancelBuildJob(job.id)),
        });
    };

    const handleRetryJob = (job: API.BuildJob) => {
        withJobAction(job, 'retry', () => retryBuildJob(job.id));
    };

    const handleViewLog = async (job: API.BuildJob) => {
        setSelectedJob(job);
        setLogModalOpen(true);
        setLogLoading(true);
        setJobLog('');
        try {
            const logText = await getBuildJobLogs(job.id);
            setJobLog(logText || '');
        } catch (err) {
            setJobLog('');
            if (typeof err === 'string') message.error(err);
        } finally {
            setLogLoading(false);
        }
    };

    useEffect(() => {
        fetchArtifacts();
        const timer = setInterval(fetchArtifacts, 5000);
        return () => clearInterval(timer);
    }, []);

    const handleBuild = async () => {
        try {
            const values = await form.validateFields();
            setBuilding(true);
            const res = await triggerBuild({ platform: values.platform, arch: values.arch, pack: values.pack });
            message.success(res?.message || '构建请求已提交');
            setBuildModalOpen(false);
            fetchArtifacts();
        } catch (err) {
            if (typeof err === 'string') message.error(err);
        } finally {
            setBuilding(false);
        }
    };

    const columns: ColumnsType<API.BuildArtifact> = [
        {
            title: '文件名', dataIndex: 'name', key: 'name',
            render: (name: string) => (
                <Space>
                    {platformIcons[artifacts.find(a => a.name === name)?.platform || ''] || <BuildOutlined />}
                    <Text style={{ fontFamily: 'monospace', fontSize: 12, fontWeight: 500 }}>{name}</Text>
                </Space>
            ),
        },
        {
            title: '平台', dataIndex: 'platform', key: 'platform', width: 100,
            render: (p: string) => <Tag color="blue" style={{ borderRadius: 20, fontSize: 11 }}>{platformNames[p] || p}</Tag>,
        },
        {
            title: '架构', dataIndex: 'arch', key: 'arch', width: 80,
            render: (a: string) => <Tag style={{ fontSize: 11 }}>{a}</Tag>,
        },
        {
            title: '大小', dataIndex: 'size', key: 'size', width: 100,
            render: (s: number) => <Text style={{ fontSize: 12, color: '#64748b' }}>{formatSize(s)}</Text>,
            sorter: (a, b) => a.size - b.size,
        },
        {
            title: '修改时间', dataIndex: 'mod_time', key: 'mod_time', width: 180,
            render: (v: string) => <Text style={{ fontSize: 12, color: '#64748b' }}>{v ? new Date(v).toLocaleString('zh-CN') : '-'}</Text>,
        },
        {
            title: '操作', key: 'actions', width: 80,
            render: (_, record) => (
                <Button type="link" size="small" icon={<DownloadOutlined />}
                    href={`/release/${record.name}`} target="_blank">下载</Button>
            ),
        },
    ];

    const jobColumns: ColumnsType<API.BuildJob> = [
        {
            title: '构建目标',
            key: 'target',
            render: (_, record) => <Text code>{record.platform}/{record.arch}</Text>,
        },
        {
            title: '状态',
            dataIndex: 'status',
            width: 110,
            render: (status: API.BuildJob['status']) => {
                const color = status === 'success' ? 'success' : status === 'failed' ? 'error' : status === 'running' ? 'processing' : status === 'canceled' ? 'warning' : 'default';
                return <Tag color={color}>{status}</Tag>;
            },
        },
        {
            title: '产物',
            dataIndex: 'artifact',
            render: (artifact: string) => artifact ? <Button type="link" href={`/release/${artifact}`} target="_blank">{artifact}</Button> : '-',
        },
        {
            title: '日志尾部',
            dataIndex: 'log_tail',
            ellipsis: true,
            render: (logTail: string, record) => (
                <Text type={record.error ? 'danger' : 'secondary'} style={{ fontSize: 12 }}>
                    {record.error || logTail?.split('\n').filter(Boolean).slice(-1)[0] || '-'}
                </Text>
            ),
        },
        {
            title: '操作',
            key: 'actions',
            width: 210,
            render: (_, record) => {
                const active = record.status === 'queued' || record.status === 'running';
                const terminal = !active;
                return (
                    <Space size={4}>
                        <Button type="link" size="small" icon={<FileTextOutlined />} onClick={() => handleViewLog(record)}>
                            日志
                        </Button>
                        {active && (
                            <Button danger type="link" size="small" icon={<StopOutlined />}
                                loading={jobActionLoading[record.id] === 'cancel'} onClick={() => handleCancelJob(record)}>
                                取消
                            </Button>
                        )}
                        {terminal && (
                            <Button type="link" size="small" icon={<RedoOutlined />}
                                loading={jobActionLoading[record.id] === 'retry'} onClick={() => handleRetryJob(record)}>
                                重试
                            </Button>
                        )}
                    </Space>
                );
            },
        },
        {
            title: '创建时间',
            dataIndex: 'created_at',
            width: 180,
            render: (value: string) => <Text style={{ fontSize: 12 }}>{value ? new Date(value).toLocaleString('zh-CN') : '-'}</Text>,
        },
    ];

    const cardStyle = {
        background: 'transparent', border: 'none'
    };

    // 按平台统计
    const platformCount = artifacts.reduce((acc, a) => {
        acc[a.platform] = (acc[a.platform] || 0) + 1;
        return acc;
    }, {} as Record<string, number>);

    return (
        <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
                <Title level={4} style={{ margin: 0, color: '#1e293b', fontWeight: 600 }}>
                    <BuildOutlined style={{ marginRight: 8, color: '#f59e0b' }} />
                    客户端生成
                </Title>
                <Space>
                    {Object.entries(platformCount).map(([p, count]) => (
                        <Tag key={p} color="blue" style={{ borderRadius: 20 }}>
                            {platformNames[p] || p}: {count}
                        </Tag>
                    ))}
                    <Button type="primary" icon={<ThunderboltOutlined />} onClick={() => setBuildModalOpen(true)}>
                        触发构建
                    </Button>
                    <Button icon={<ReloadOutlined />} onClick={fetchArtifacts} loading={loading}>刷新</Button>
                </Space>
            </div>

            <ProCard className="glass-card" style={cardStyle}>
                {loading && artifacts.length === 0 ? (
                    <div style={{ display: 'flex', justifyContent: 'center', padding: '60px 0' }}><Spin size="large" /></div>
                ) : artifacts.length === 0 ? (
                    <Empty image={Empty.PRESENTED_IMAGE_SIMPLE}
                        description="尚无构建产物。请先运行 build.sh 或点击「触发构建」" style={{ padding: '60px 0' }} />
                ) : (
                    <Table columns={columns} dataSource={artifacts} rowKey="name"
                        pagination={false} size="middle" />
                )}
            </ProCard>

            <ProCard title="构建任务" className="glass-card" style={{ ...cardStyle, marginTop: 16 }}>
                {jobs.some((job) => job.status === 'queued' || job.status === 'running') && (
                    <Alert type="info" showIcon style={{ marginBottom: 12 }} message="构建进行中，页面会自动刷新状态" />
                )}
                <Table columns={jobColumns} dataSource={jobs} rowKey="id" pagination={false} size="small" />
            </ProCard>

            <Modal title="触发客户端构建" open={buildModalOpen} onOk={handleBuild}
                onCancel={() => setBuildModalOpen(false)} okText="开始构建" cancelText="取消"
                confirmLoading={building}>
                <Form form={form} layout="vertical" style={{ marginTop: 16 }}>
                    <Row gutter={16}>
                        <Col span={12}>
                            <Form.Item name="platform" label="目标平台" initialValue="linux" rules={[{ required: true }]}>
                                <Select options={[
                                    { value: 'linux', label: 'Linux' },
                                    { value: 'darwin', label: 'macOS' },
                                    { value: 'windows', label: 'Windows' },
                                ]} />
                            </Form.Item>
                        </Col>
                        <Col span={12}>
                            <Form.Item name="arch" label="架构" initialValue="amd64" rules={[{ required: true }]}>
                                <Select options={[
                                    { value: 'amd64', label: 'x86_64 (amd64)' },
                                    { value: 'arm64', label: 'ARM64 (aarch64)' },
                                ]} />
                            </Form.Item>
                        </Col>
                    </Row>
                    <Form.Item name="pack" label="UPX 压缩" valuePropName="checked">
                        <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                    </Form.Item>
                </Form>
            </Modal>

            <Modal title={selectedJob ? `构建日志 #${selectedJob.id}` : '构建日志'} open={logModalOpen}
                onCancel={() => setLogModalOpen(false)} footer={null} width={880}>
                <Spin spinning={logLoading}>
                    <pre style={{
                        minHeight: 260,
                        maxHeight: 520,
                        overflow: 'auto',
                        margin: 0,
                        padding: 16,
                        background: '#0f172a',
                        color: '#e2e8f0',
                        borderRadius: 6,
                        fontSize: 12,
                        lineHeight: 1.6,
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-word',
                    }}>{jobLog || '暂无日志'}</pre>
                </Spin>
            </Modal>
        </div>
    );
};

export default ClientBuild;
