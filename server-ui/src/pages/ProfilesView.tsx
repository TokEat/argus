import React, { useEffect, useState } from 'react';
import { Typography, Table, Tag, Space, Spin, Input, Badge, Collapse, Empty, Tooltip } from 'antd';
import { ProCard } from '@ant-design/pro-components';
import {
    ProfileOutlined,
    SearchOutlined,
    BugOutlined,
    GlobalOutlined,
    ScanOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import { getProfiles } from '../services/api';

const { Title, Text } = Typography;

const ProfilesView: React.FC = () => {
    const [loading, setLoading] = useState(true);
    const [profiles, setProfiles] = useState<API.Profile[]>([]);
    const [filtered, setFiltered] = useState<API.Profile[]>([]);
    const [searchKeyword, setSearchKeyword] = useState('');

    useEffect(() => {
        fetchData();
    }, []);

    const fetchData = async () => {
        setLoading(true);
        try {
            const result = await getProfiles();
            setProfiles(result || []);
            setFiltered(result || []);
        } catch (error) {
            console.error('Failed to fetch profiles:', error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        if (!searchKeyword) {
            setFiltered(profiles);
        } else {
            const lower = searchKeyword.toLowerCase();
            setFiltered(profiles.filter(p => p.target.toLowerCase().includes(lower)));
        }
    }, [searchKeyword, profiles]);

    const getSeverityColor = (severity: string) => {
        const map: Record<string, string> = {
            Critical: '#ef4444', High: '#f97316', Medium: '#f59e0b',
            Low: '#3b82f6', Info: '#6b7280', Unknown: '#94a3b8',
        };
        return map[severity] || '#94a3b8';
    };

    const columns: ColumnsType<API.Profile> = [
        {
            title: '目标',
            dataIndex: 'target',
            key: 'target',
            width: 300,
            render: (target: string) => (
                <Text strong style={{ fontFamily: 'monospace', fontSize: 13 }}>{target}</Text>
            ),
        },
        {
            title: '资产',
            key: 'assets',
            width: 80,
            render: (_, record) => (
                <Badge count={record.assets?.length || 0} style={{ backgroundColor: '#0ea5e9' }}>
                    <GlobalOutlined style={{ fontSize: 18, color: '#0ea5e9' }} />
                </Badge>
            ),
            sorter: (a, b) => (a.assets?.length || 0) - (b.assets?.length || 0),
        },
        {
            title: '指纹',
            key: 'fingerprints',
            width: 80,
            render: (_, record) => (
                <Badge count={record.fingerprints?.length || 0} style={{ backgroundColor: '#f59e0b' }}>
                    <ScanOutlined style={{ fontSize: 18, color: '#f59e0b' }} />
                </Badge>
            ),
            sorter: (a, b) => (a.fingerprints?.length || 0) - (b.fingerprints?.length || 0),
        },
        {
            title: '漏洞',
            key: 'vulns',
            width: 80,
            render: (_, record) => (
                <Badge count={record.vulns?.length || 0} style={{ backgroundColor: '#ef4444' }}>
                    <BugOutlined style={{ fontSize: 18, color: '#ef4444' }} />
                </Badge>
            ),
            sorter: (a, b) => (a.vulns?.length || 0) - (b.vulns?.length || 0),
        },
        {
            title: '指纹产品',
            key: 'products',
            render: (_, record) => {
                const fps = record.fingerprints || [];
                if (fps.length === 0) return <Text type="secondary">-</Text>;
                const products = [...new Set(fps.map(f => f.ProductName))];
                return (
                    <Space wrap size={2}>
                        {products.slice(0, 5).map((p, i) => (
                            <Tag key={i} color="cyan" style={{ fontSize: 11, margin: 0 }}>{p}</Tag>
                        ))}
                        {products.length > 5 && <Tag style={{ fontSize: 11, margin: 0 }}>+{products.length - 5}</Tag>}
                    </Space>
                );
            },
        },
        {
            title: '漏洞详情',
            key: 'vuln_detail',
            render: (_, record) => {
                const vulns = record.vulns || [];
                if (vulns.length === 0) return <Text type="secondary">-</Text>;
                return (
                    <Space wrap size={2}>
                        {vulns.slice(0, 3).map((v, i) => (
                            <Tooltip key={i} title={v.Payload?.slice(0, 200)}>
                                <Tag color={getSeverityColor(v.Severity)} style={{ fontSize: 11, margin: 0 }}>
                                    {v.Plugin}
                                </Tag>
                            </Tooltip>
                        ))}
                        {vulns.length > 3 && <Tag style={{ fontSize: 11, margin: 0 }}>+{vulns.length - 3}</Tag>}
                    </Space>
                );
            },
        },
    ];

    const cardStyle = {
        background: 'transparent',
        border: 'none',
    };

    return (
        <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
                <Title level={4} style={{ margin: 0, color: '#1e293b', fontWeight: 600 }}>
                    <ProfileOutlined style={{ marginRight: 8, color: '#8b5cf6' }} />
                    融合画像
                </Title>
                <Space>
                    <Input
                        placeholder="搜索目标..."
                        prefix={<SearchOutlined style={{ color: '#94a3b8' }} />}
                        value={searchKeyword}
                        onChange={(e) => setSearchKeyword(e.target.value)}
                        style={{ width: 260 }}
                        allowClear
                    />
                    <Tag color="default">{filtered.length} 个目标</Tag>
                </Space>
            </div>

            <ProCard className="glass-card" style={cardStyle}>
                {loading ? (
                    <div style={{ display: 'flex', justifyContent: 'center', padding: '60px 0' }}>
                        <Spin size="large" />
                    </div>
                ) : filtered.length === 0 ? (
                    <Empty description="暂无画像数据" style={{ padding: '60px 0' }} />
                ) : (
                    <Table
                        columns={columns}
                        dataSource={filtered}
                        rowKey="target"
                        pagination={{ pageSize: 20, showTotal: (t) => `共 ${t} 个目标` }}
                        size="middle"
                        expandable={{
                            expandedRowRender: (record) => (
                                <div style={{ padding: '8px 0' }}>
                                    <Collapse
                                        size="small"
                                        items={[
                                            record.assets?.length ? {
                                                key: 'assets',
                                                label: <span><GlobalOutlined /> 资产 ({record.assets.length})</span>,
                                                children: (
                                                    <div style={{ maxHeight: 200, overflow: 'auto' }}>
                                                        {record.assets.map((a, i) => (
                                                            <div key={i} style={{ padding: '4px 0', borderBottom: '1px solid #f1f5f9', fontSize: 12 }}>
                                                                <Tag color="blue">{a.Protocol}</Tag>
                                                                <Text>{a.Target}:{a.Port}</Text>
                                                                {a.Title && <Text type="secondary"> — {a.Title}</Text>}
                                                            </div>
                                                        ))}
                                                    </div>
                                                ),
                                            } : null,
                                            record.fingerprints?.length ? {
                                                key: 'fps',
                                                label: <span><ScanOutlined /> 指纹 ({record.fingerprints.length})</span>,
                                                children: (
                                                    <div style={{ maxHeight: 200, overflow: 'auto' }}>
                                                        {record.fingerprints.map((f, i) => (
                                                            <div key={i} style={{ padding: '4px 0', borderBottom: '1px solid #f1f5f9', fontSize: 12 }}>
                                                                <Tag color="cyan">{f.ProductName}</Tag>
                                                                <Text type="secondary">{f.RuleName}</Text>
                                                            </div>
                                                        ))}
                                                    </div>
                                                ),
                                            } : null,
                                            record.vulns?.length ? {
                                                key: 'vulns',
                                                label: <span><BugOutlined /> 漏洞 ({record.vulns.length})</span>,
                                                children: (
                                                    <div style={{ maxHeight: 200, overflow: 'auto' }}>
                                                        {record.vulns.map((v, i) => (
                                                            <div key={i} style={{ padding: '4px 0', borderBottom: '1px solid #f1f5f9', fontSize: 12 }}>
                                                                <Tag color={getSeverityColor(v.Severity)}>{v.Severity}</Tag>
                                                                <Text>{v.Plugin}</Text>
                                                            </div>
                                                        ))}
                                                    </div>
                                                ),
                                            } : null,
                                        ].filter(Boolean) as any[]}
                                    />
                                </div>
                            ),
                        }}
                    />
                )}
            </ProCard>
        </div>
    );
};

export default ProfilesView;
