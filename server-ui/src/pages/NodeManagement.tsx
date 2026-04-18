import React, { useEffect, useState } from 'react';
import { Typography, Table, Tag, Space, Button, Spin, Tooltip, Badge, Empty } from 'antd';
import { ProCard } from '@ant-design/pro-components';
import {
    ReloadOutlined,
    ClusterOutlined,
    WifiOutlined,
    DisconnectOutlined,
    FieldTimeOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import { getNodes } from '../services/api';

const { Title, Text } = Typography;

const NodeManagement: React.FC = () => {
    const [loading, setLoading] = useState(true);
    const [nodes, setNodes] = useState<API.AgentNode[]>([]);

    const fetchNodes = async () => {
        setLoading(true);
        try {
            const result = await getNodes();
            setNodes(result || []);
        } catch (error) {
            console.error('Failed to fetch nodes:', error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchNodes();
        const timer = setInterval(fetchNodes, 10000);
        return () => clearInterval(timer);
    }, []);

    const formatLastBeat = (ts: number) => {
        if (!ts) return '-';
        const d = new Date(ts);
        return d.toLocaleString('zh-CN');
    };

    const getTimeSince = (ts: number) => {
        if (!ts) return '';
        const diff = Date.now() - ts;
        if (diff < 60000) return `${Math.floor(diff / 1000)}秒前`;
        if (diff < 3600000) return `${Math.floor(diff / 60000)}分钟前`;
        return `${Math.floor(diff / 3600000)}小时前`;
    };

    const columns: ColumnsType<API.AgentNode> = [
        {
            title: '状态',
            dataIndex: 'Status',
            key: 'status',
            width: 80,
            render: (status: string) => {
                const isAlive = status === 'Alive';
                return (
                    <Badge
                        status={isAlive ? 'success' : 'default'}
                        text={
                            <Tag
                                color={isAlive ? '#10b981' : '#94a3b8'}
                                style={{ borderRadius: 20, fontSize: 11 }}
                            >
                                {isAlive ? '在线' : '离线'}
                            </Tag>
                        }
                    />
                );
            },
            filters: [
                { text: '在线', value: 'Alive' },
                { text: '离线', value: 'Offline' },
            ],
            onFilter: (value, record) => record.Status === value,
        },
        {
            title: 'Agent ID',
            dataIndex: 'AgentID',
            key: 'agent_id',
            ellipsis: true,
            render: (id: string) => (
                <Tooltip title={id}>
                    <Text copyable={{ text: id }} style={{ fontFamily: 'monospace', fontSize: 12 }}>
                        {id.length > 20 ? `${id.slice(0, 20)}...` : id}
                    </Text>
                </Tooltip>
            ),
        },
        {
            title: 'IP 地址',
            dataIndex: 'IP',
            key: 'ip',
            width: 140,
            render: (ip: string) => ip || <Text type="secondary">-</Text>,
        },
        {
            title: '最后心跳',
            dataIndex: 'LastBeat',
            key: 'last_beat',
            width: 200,
            sorter: (a, b) => a.LastBeat - b.LastBeat,
            render: (ts: number) => (
                <Tooltip title={formatLastBeat(ts)}>
                    <Space size={4}>
                        <FieldTimeOutlined style={{ color: '#64748b' }} />
                        <Text style={{ fontSize: 12, color: '#64748b' }}>
                            {getTimeSince(ts)}
                        </Text>
                    </Space>
                </Tooltip>
            ),
        },
        {
            title: '标签',
            dataIndex: 'Tags',
            key: 'tags',
            render: (tags: string) => {
                if (!tags) return <Text type="secondary">-</Text>;
                return tags.split(',').map((t, i) => (
                    <Tag key={i} color="blue" style={{ fontSize: 11 }}>{t.trim()}</Tag>
                ));
            },
        },
        {
            title: '注册时间',
            dataIndex: 'CreatedAt',
            key: 'created_at',
            width: 170,
            render: (v: string) => <Text style={{ fontSize: 12, color: '#64748b' }}>{v}</Text>,
        },
    ];

    const onlineCount = nodes.filter(n => n.Status === 'Alive').length;
    const offlineCount = nodes.length - onlineCount;

    return (
        <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
                <Title level={4} style={{ margin: 0, color: '#1e293b', fontWeight: 600 }}>
                    <ClusterOutlined style={{ marginRight: 8, color: '#0ea5e9' }} />
                    节点管理
                </Title>
                <Space>
                    <Tag color="#10b981" style={{ borderRadius: 20 }}>
                        <WifiOutlined /> 在线 {onlineCount}
                    </Tag>
                    <Tag color="#94a3b8" style={{ borderRadius: 20 }}>
                        <DisconnectOutlined /> 离线 {offlineCount}
                    </Tag>
                    <Button icon={<ReloadOutlined />} onClick={fetchNodes} loading={loading}>
                        刷新
                    </Button>
                </Space>
            </div>

            <ProCard style={{
                background: '#ffffff', borderRadius: 12,
                border: '1px solid #e2e8f0',
                boxShadow: '0 1px 3px 0 rgba(0, 0, 0, 0.04)',
            }}>
                {loading && nodes.length === 0 ? (
                    <div style={{ display: 'flex', justifyContent: 'center', padding: '60px 0' }}>
                        <Spin size="large" />
                    </div>
                ) : nodes.length === 0 ? (
                    <Empty
                        image={Empty.PRESENTED_IMAGE_SIMPLE}
                        description="暂无已注册的 Agent 节点"
                        style={{ padding: '60px 0' }}
                    />
                ) : (
                    <Table
                        columns={columns}
                        dataSource={nodes}
                        rowKey="AgentID"
                        pagination={{ pageSize: 20, showSizeChanger: true, showTotal: (total) => `共 ${total} 个节点` }}
                        size="middle"
                    />
                )}
            </ProCard>
        </div>
    );
};

export default NodeManagement;
