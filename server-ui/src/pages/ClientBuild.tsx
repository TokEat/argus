import React, { useEffect, useState } from 'react';
import { Typography, Table, Tag, Space, Button, Spin, Empty, Modal, Form, Select, Switch, message, Row, Col } from 'antd';
import { ProCard } from '@ant-design/pro-components';
import {
    BuildOutlined, ReloadOutlined, ThunderboltOutlined,
    AppleOutlined, WindowsOutlined, CloudOutlined, DownloadOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import { listBuildArtifacts, triggerBuild } from '../services/api';

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
    const [buildModalOpen, setBuildModalOpen] = useState(false);
    const [building, setBuilding] = useState(false);
    const [form] = Form.useForm();

    const fetchArtifacts = async () => {
        setLoading(true);
        try {
            const result = await listBuildArtifacts();
            setArtifacts(result || []);
        } catch (error) {
            console.error('Failed to fetch artifacts:', error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => { fetchArtifacts(); }, []);

    const handleBuild = async () => {
        try {
            const values = await form.validateFields();
            setBuilding(true);
            const res = await triggerBuild({ platform: values.platform, arch: values.arch, pack: values.pack });
            message.success(res?.message || '构建请求已提交');
            setBuildModalOpen(false);
            setTimeout(fetchArtifacts, 2000);
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
        </div>
    );
};

export default ClientBuild;
