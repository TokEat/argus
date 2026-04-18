import React, { useEffect, useState } from 'react';
import { Typography, Table, Tag, Tabs, Space, Spin, Button, Tooltip, Empty } from 'antd';
import { ProCard } from '@ant-design/pro-components';
import {
    BugOutlined,
    GlobalOutlined,
    ScanOutlined,
    DownloadOutlined,
    ArrowLeftOutlined,
    ReloadOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import { useNavigate, useParams } from 'react-router-dom';
import { getVulns, getAssets, getFingerprints, exportVulns } from '../services/api';

const { Title, Text } = Typography;

const TaskResults: React.FC = () => {
    const { taskId } = useParams<{ taskId: string }>();
    const [loading, setLoading] = useState(true);
    const [vulns, setVulns] = useState<API.Vulnerability[]>([]);
    const [assets, setAssets] = useState<API.Asset[]>([]);
    const [fingerprints, setFingerprints] = useState<API.FingerprintHit[]>([]);
    const [activeTab, setActiveTab] = useState('vulns');
    const navigate = useNavigate();

    const fetchData = async () => {
        setLoading(true);
        try {
            const [vulnRes, assetRes, fpRes] = await Promise.all([
                getVulns(taskId),
                getAssets(taskId),
                getFingerprints(taskId),
            ]);
            setVulns(vulnRes || []);
            setAssets(assetRes || []);
            setFingerprints(fpRes || []);
        } catch (error) {
            console.error('Failed to fetch results:', error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchData();
    }, [taskId]);

    const handleExport = async () => {
        try {
            const blob = await exportVulns();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `vulns-${taskId || 'all'}.csv`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
        } catch {
            console.error('Export failed');
        }
    };

    const getSeverityColor = (severity: string) => {
        const map: Record<string, string> = {
            Critical: '#ef4444', High: '#f97316', Medium: '#f59e0b',
            Low: '#3b82f6', Info: '#6b7280', Unknown: '#94a3b8',
        };
        return map[severity] || '#94a3b8';
    };

    const getSeverityWeight = (severity: string) => {
        const map: Record<string, number> = {
            Critical: 5, High: 4, Medium: 3, Low: 2, Info: 1, Unknown: 0,
        };
        return map[severity] || 0;
    };

    const vulnColumns: ColumnsType<API.Vulnerability> = [
        {
            title: '目标',
            dataIndex: 'Target',
            key: 'target',
            ellipsis: true,
            render: (v: string) => <Text style={{ fontFamily: 'monospace', fontSize: 12 }}>{v}</Text>,
        },
        {
            title: '插件',
            dataIndex: 'Plugin',
            key: 'plugin',
            ellipsis: true,
            render: (v: string) => <Text strong style={{ fontSize: 13 }}>{v}</Text>,
        },
        {
            title: '危害等级',
            dataIndex: 'Severity',
            key: 'severity',
            width: 100,
            render: (v: string) => <Tag color={getSeverityColor(v)}>{v}</Tag>,
            filters: ['Critical', 'High', 'Medium', 'Low', 'Info', 'Unknown'].map(s => ({ text: s, value: s })),
            onFilter: (value, record) => record.Severity === value,
            sorter: (a, b) => getSeverityWeight(b.Severity) - getSeverityWeight(a.Severity),
            defaultSortOrder: 'ascend',
        },
        {
            title: 'Payload',
            dataIndex: 'Payload',
            key: 'payload',
            ellipsis: true,
            render: (v: string) => (
                <Tooltip title={v}>
                    <Text copyable={{ text: v }} style={{ fontSize: 12, color: '#64748b' }}>{v?.slice(0, 80)}</Text>
                </Tooltip>
            ),
        },
        {
            title: '发现时间',
            dataIndex: 'CreatedAt',
            key: 'created_at',
            width: 170,
            sorter: (a, b) => new Date(a.CreatedAt).getTime() - new Date(b.CreatedAt).getTime(),
            render: (v: string) => <Text style={{ fontSize: 12, color: '#64748b' }}>{v}</Text>,
        },
    ];

    const assetColumns: ColumnsType<API.Asset> = [
        {
            title: '目标',
            dataIndex: 'Target',
            key: 'target',
            ellipsis: true,
            render: (v: string) => <Text style={{ fontFamily: 'monospace', fontSize: 12 }}>{v}</Text>,
        },
        {
            title: '协议',
            dataIndex: 'Protocol',
            key: 'protocol',
            width: 100,
            render: (v: string) => <Tag color="blue">{v}</Tag>,
        },
        {
            title: '端口',
            dataIndex: 'Port',
            key: 'port',
            width: 80,
            sorter: (a, b) => a.Port - b.Port,
        },
        {
            title: '标题',
            dataIndex: 'Title',
            key: 'title',
            ellipsis: true,
        },
        {
            title: '服务',
            dataIndex: 'Service',
            key: 'service',
            width: 120,
            render: (v: string) => v ? <Tag>{v}</Tag> : <Text type="secondary">-</Text>,
        },
        {
            title: 'URL',
            dataIndex: 'URL',
            key: 'url',
            ellipsis: true,
            render: (v: string) => (
                v ? (
                    <Tooltip title={v}>
                        <a href={v} target="_blank" rel="noopener" style={{ fontSize: 12 }}>{v?.slice(0, 60)}</a>
                    </Tooltip>
                ) : <Text type="secondary">-</Text>
            ),
        },
        {
            title: '发现时间',
            dataIndex: 'CreatedAt',
            key: 'created_at',
            width: 170,
            render: (v: string) => <Text style={{ fontSize: 12, color: '#64748b' }}>{v}</Text>,
        },
    ];

    const fpColumns: ColumnsType<API.FingerprintHit> = [
        {
            title: '目标',
            dataIndex: 'Target',
            key: 'target',
            ellipsis: true,
            render: (v: string) => <Text style={{ fontFamily: 'monospace', fontSize: 12 }}>{v}</Text>,
        },
        {
            title: '产品名称',
            dataIndex: 'ProductName',
            key: 'product_name',
            render: (v: string) => <Tag color="cyan">{v}</Tag>,
        },
        {
            title: '规则',
            dataIndex: 'RuleName',
            key: 'rule_name',
            ellipsis: true,
        },
        {
            title: '证据',
            dataIndex: 'Evidence',
            key: 'evidence',
            ellipsis: true,
            render: (v: string) => (
                <Tooltip title={v}>
                    <Text style={{ fontSize: 12, color: '#64748b' }}>{v?.slice(0, 80)}</Text>
                </Tooltip>
            ),
        },
        {
            title: '发现时间',
            dataIndex: 'CreatedAt',
            key: 'created_at',
            width: 170,
            render: (v: string) => <Text style={{ fontSize: 12, color: '#64748b' }}>{v}</Text>,
        },
    ];

    const cardStyle = {
        background: '#ffffff', borderRadius: 12,
        border: '1px solid #e2e8f0',
        boxShadow: '0 1px 3px 0 rgba(0, 0, 0, 0.04)',
    };

    // Severity statistics
    const severityStats = vulns.reduce((acc, v) => {
        acc[v.Severity] = (acc[v.Severity] || 0) + 1;
        return acc;
    }, {} as Record<string, number>);

    return (
        <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
                <Space>
                    <Button icon={<ArrowLeftOutlined />} onClick={() => navigate('/tasks')}>返回</Button>
                    <Title level={4} style={{ margin: 0, color: '#1e293b', fontWeight: 600 }}>
                        扫描结果
                    </Title>
                    {taskId && (
                        <Tag color="blue" style={{ fontFamily: 'monospace', fontSize: 11 }}>
                            {taskId}
                        </Tag>
                    )}
                </Space>
                <Space>
                    {/* Severity breakdown */}
                    {Object.entries(severityStats).map(([severity, count]) => (
                        <Tag key={severity} color={getSeverityColor(severity)}>
                            {severity}: {count}
                        </Tag>
                    ))}
                    <Tag color="blue"><GlobalOutlined /> 资产 {assets.length}</Tag>
                    <Tag color="cyan"><ScanOutlined /> 指纹 {fingerprints.length}</Tag>
                    <Button icon={<ReloadOutlined />} onClick={fetchData} loading={loading}>刷新</Button>
                    <Button icon={<DownloadOutlined />} onClick={handleExport}>导出 CSV</Button>
                </Space>
            </div>

            <ProCard style={cardStyle}>
                {loading ? (
                    <div style={{ display: 'flex', justifyContent: 'center', padding: '60px 0' }}>
                        <Spin size="large" />
                    </div>
                ) : vulns.length === 0 && assets.length === 0 && fingerprints.length === 0 ? (
                    <Empty description="暂无扫描结果" style={{ padding: '60px 0' }} />
                ) : (
                    <Tabs
                        activeKey={activeTab}
                        onChange={setActiveTab}
                        items={[
                            {
                                key: 'vulns',
                                label: <span><BugOutlined /> 漏洞 ({vulns.length})</span>,
                                children: (
                                    <Table
                                        columns={vulnColumns}
                                        dataSource={vulns}
                                        rowKey="ID"
                                        pagination={{ pageSize: 20, showTotal: (t) => `共 ${t} 条` }}
                                        size="middle"
                                    />
                                ),
                            },
                            {
                                key: 'assets',
                                label: <span><GlobalOutlined /> 资产 ({assets.length})</span>,
                                children: (
                                    <Table
                                        columns={assetColumns}
                                        dataSource={assets}
                                        rowKey="ID"
                                        pagination={{ pageSize: 20, showTotal: (t) => `共 ${t} 条` }}
                                        size="middle"
                                    />
                                ),
                            },
                            {
                                key: 'fingerprints',
                                label: <span><ScanOutlined /> 指纹 ({fingerprints.length})</span>,
                                children: (
                                    <Table
                                        columns={fpColumns}
                                        dataSource={fingerprints}
                                        rowKey="ID"
                                        pagination={{ pageSize: 20, showTotal: (t) => `共 ${t} 条` }}
                                        size="middle"
                                    />
                                ),
                            },
                        ]}
                    />
                )}
            </ProCard>
        </div>
    );
};

export default TaskResults;
