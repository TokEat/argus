import React, { useEffect, useState } from 'react';
import { Typography, Table, Tag, Space, Button, Spin, Tooltip, Popover, Badge, Empty, Progress, List } from 'antd';
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
            title: '当前负载',
            key: 'workload',
            width: 150,
            render: (_, record) => {
                if (record.Status !== 'Alive') return <Text type="secondary">-</Text>;
                const running = record.RunningTasks || 0;
                const capacity = record.Capacity || 10; // Default capacity if not set
                const percent = Math.min(100, Math.round((running / capacity) * 100));
                
                let color = '#10b981'; // Green
                if (percent > 70) color = '#f59e0b'; // Yellow
                if (percent > 90) color = '#ef4444'; // Red

                const content = (
                    <div style={{ maxWidth: 300, maxHeight: 400, overflow: 'auto' }}>
                        <div style={{ marginBottom: 8, fontWeight: 'bold' }}>运行中任务 ({running}/{capacity})</div>
                        {record.RunningTaskDetails && record.RunningTaskDetails.length > 0 ? (
                            <List
                                size="small"
                                dataSource={record.RunningTaskDetails}
                                renderItem={(task) => (
                                    <List.Item>
                                        <div style={{ wordBreak: 'break-all' }}>
                                            <Tag color="blue">{task.task_id.split('-')[0]}</Tag>
                                            <Text style={{ fontSize: 12 }}>
                                                {task.targets?.join(', ')}
                                            </Text>
                                        </div>
                                    </List.Item>
                                )}
                            />
                        ) : (
                            <Text type="secondary">暂无详细任务数据</Text>
                        )}
                    </div>
                );

                return (
                    <Popover content={content} trigger="hover" placement="left">
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                            <Progress 
                                percent={percent} 
                                showInfo={false} 
                                size="small" 
                                strokeColor={color} 
                                style={{ margin: 0, flex: 1 }} 
                            />
                            <Text style={{ fontSize: 11, color: '#64748b', minWidth: 35 }}>{percent}%</Text>
                        </div>
                    </Popover>
                );
            }
        },
        {
            title: '标签',
            dataIndex: 'Tags',
            key: 'tags',
            render: (tags: string) => {
                if (!tags) return <Text type="secondary">-</Text>;
                const colors = ['blue', 'cyan', 'geekblue', 'purple'];
                return tags.split(',').map((t, i) => (
                    <Tag key={i} color={colors[i % colors.length]} style={{ fontSize: 11, borderRadius: 10 }}>{t.trim()}</Tag>
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

            <ProCard className="glass-card" style={{ background: 'transparent', border: 'none' }}>
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
