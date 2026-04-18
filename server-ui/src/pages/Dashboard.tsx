import React, { useEffect, useState, useRef, useCallback } from 'react';
import { Row, Col, Typography, List, Tag, Space, Spin, Badge, Button, Tooltip, Table } from 'antd';
import { ProCard } from '@ant-design/pro-components';
import {
    ClusterOutlined,
    RocketOutlined,
    BugOutlined,
    ScanOutlined,
    CheckCircleOutlined,
    ClockCircleOutlined,
    ExclamationCircleOutlined,
    NodeIndexOutlined,
    DatabaseOutlined,
    ThunderboltOutlined,
    WifiOutlined,
    DisconnectOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import { getDashboardStats, listTasks, getNodes, connectWebSocket } from '../services/api';

const { Text, Title } = Typography;

const Dashboard: React.FC = () => {
    const [loading, setLoading] = useState(true);
    const [stats, setStats] = useState<API.DashboardStats | null>(null);
    const [recentTasks, setRecentTasks] = useState<API.RootTask[]>([]);
    const [nodes, setNodes] = useState<API.AgentNode[]>([]);
    const [wsConnected, setWsConnected] = useState(false);
    const [wsMessages, setWsMessages] = useState<{ time: string; type: string; data: string }[]>([]);
    const wsRef = useRef<WebSocket | null>(null);

    const fetchData = useCallback(async () => {
        try {
            const [statsRes, tasksRes, nodesRes] = await Promise.all([
                getDashboardStats(),
                listTasks(),
                getNodes(),
            ]);
            setStats(statsRes);
            setRecentTasks((tasksRes || []).slice(0, 8));
            setNodes(nodesRes || []);
        } catch (error) {
            console.error('Failed to fetch dashboard data:', error);
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        fetchData();
        const timer = setInterval(fetchData, 15000);
        return () => clearInterval(timer);
    }, [fetchData]);

    // WebSocket
    useEffect(() => {
        const ws = connectWebSocket((data: unknown) => {
            setWsConnected(true);
            const msg = data as Record<string, unknown>;
            setWsMessages((prev) => [
                {
                    time: new Date().toLocaleTimeString('zh-CN'),
                    type: String(msg.type || msg.event || 'data'),
                    data: JSON.stringify(msg).slice(0, 200),
                },
                ...prev.slice(0, 49),
            ]);
            // Auto-refresh stats when we receive a WS message
            fetchData();
        });
        ws.onopen = () => setWsConnected(true);
        ws.onclose = () => setWsConnected(false);
        ws.onerror = () => setWsConnected(false);
        wsRef.current = ws;

        return () => {
            ws.close();
        };
    }, [fetchData]);

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

    const getStatusIcon = (status: string) => {
        switch (status) {
            case 'FINISHED': return <CheckCircleOutlined style={{ color: '#10b981' }} />;
            case 'Running': return <ClockCircleOutlined style={{ color: '#0ea5e9' }} spin />;
            case 'Cancelled': return <ExclamationCircleOutlined style={{ color: '#ef4444' }} />;
            default: return <ClockCircleOutlined style={{ color: '#f59e0b' }} />;
        }
    };

    const getNodeStatusText = (status: string) => {
        switch (status) {
            case 'Alive': return '在线';
            case 'Offline': return '离线';
            default: return '未知';
        }
    };

    if (loading) {
        return (
            <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '60vh' }}>
                <Spin size="large" />
            </div>
        );
    }

    const statCards = [
        {
            title: '节点总数', value: stats?.nodes ?? 0, icon: <ClusterOutlined />,
            iconBg: 'linear-gradient(135deg, #6366f1, #8b5cf6)', color: '#6366f1'
        },
        {
            title: '任务总数', value: stats?.tasks ?? 0, icon: <RocketOutlined />,
            iconBg: 'linear-gradient(135deg, #10b981, #34d399)', color: '#10b981'
        },
        {
            title: '发现资产', value: stats?.assets ?? 0, icon: <DatabaseOutlined />,
            iconBg: 'linear-gradient(135deg, #0ea5e9, #06b6d4)', color: '#0ea5e9'
        },
        {
            title: '指纹命中', value: stats?.fingerprints ?? 0, icon: <ScanOutlined />,
            iconBg: 'linear-gradient(135deg, #f59e0b, #fbbf24)', color: '#f59e0b'
        },
        {
            title: '累计漏洞', value: stats?.vulns ?? 0, icon: <BugOutlined />,
            iconBg: 'linear-gradient(135deg, #ef4444, #f87171)', color: '#ef4444'
        },
    ];

    const cardStyle = {
        background: '#ffffff', borderRadius: 12,
        border: '1px solid #e2e8f0',
        boxShadow: '0 1px 3px 0 rgba(0, 0, 0, 0.04)',
    };

    const onlineCount = nodes.filter(n => n.Status === 'Alive').length;

    const wsColumns: ColumnsType<{ time: string; type: string; data: string }> = [
        { title: '时间', dataIndex: 'time', key: 'time', width: 90, render: (v) => <Text style={{ fontSize: 11, color: '#94a3b8' }}>{v}</Text> },
        { title: '类型', dataIndex: 'type', key: 'type', width: 100, render: (v) => <Tag color="blue" style={{ fontSize: 10 }}>{v}</Tag> },
        { title: '数据', dataIndex: 'data', key: 'data', ellipsis: true, render: (v) => <Text style={{ fontSize: 11, fontFamily: 'monospace', color: '#64748b' }}>{v}</Text> },
    ];

    return (
        <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
                <Title level={4} style={{ margin: 0, color: '#1e293b', fontWeight: 600 }}>
                    首页概览
                </Title>
                <Space>
                    <Tooltip title={wsConnected ? 'WebSocket 已连接' : 'WebSocket 未连接'}>
                        <Tag
                            color={wsConnected ? 'success' : 'default'}
                            icon={wsConnected ? <WifiOutlined /> : <DisconnectOutlined />}
                        >
                            {wsConnected ? '实时连接' : '离线'}
                        </Tag>
                    </Tooltip>
                    <Tag color="blue">
                        <ClusterOutlined /> {onlineCount}/{nodes.length} 在线
                    </Tag>
                </Space>
            </div>

            {/* Stat Cards - 5 columns */}
            <Row gutter={[12, 12]} style={{ marginBottom: 20 }}>
                {statCards.map((card, i) => (
                    <Col key={i} xs={12} sm={8} md={6} lg={4} xl={4}>
                        <ProCard hoverable style={cardStyle} bodyStyle={{ padding: 18 }}>
                            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                                <div>
                                    <Text style={{ color: '#64748b', fontSize: 12 }}>{card.title}</Text>
                                    <div style={{ fontSize: 26, fontWeight: 700, color: card.color, marginTop: 2 }}>
                                        {card.value}
                                    </div>
                                </div>
                                <div style={{
                                    width: 44, height: 44, borderRadius: 10,
                                    background: card.iconBg,
                                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                                    fontSize: 20, color: '#fff',
                                }}>
                                    {card.icon}
                                </div>
                            </div>
                        </ProCard>
                    </Col>
                ))}
            </Row>

            {/* Node Status + Recent Tasks */}
            <Row gutter={[12, 12]} style={{ marginBottom: 20 }}>
                <Col xs={24} lg={10}>
                    <ProCard
                        title={
                            <Space>
                                <NodeIndexOutlined style={{ color: '#0ea5e9' }} />
                                <Text strong style={{ color: '#1e293b', fontSize: 15 }}>节点状态</Text>
                                <Tag color="blue">{nodes.length} 个</Tag>
                            </Space>
                        }
                        style={{ ...cardStyle, height: '100%' }}
                        bodyStyle={{ padding: '4px 16px', maxHeight: 340, overflow: 'auto' }}
                    >
                        {nodes.length > 0 ? (
                            <List
                                dataSource={nodes}
                                renderItem={(node) => (
                                    <List.Item style={{ padding: '8px 0', borderBottom: '1px solid #f1f5f9' }}>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: 10, width: '100%' }}>
                                            <Badge status={node.Status === 'Alive' ? 'success' : 'default'} />
                                            <div style={{ flex: 1, minWidth: 0 }}>
                                                <Text style={{ fontSize: 13, fontWeight: 500 }}>
                                                    {node.AgentID.length > 16 ? node.AgentID.slice(0, 16) + '…' : node.AgentID}
                                                </Text>
                                                <div style={{ fontSize: 11, color: '#94a3b8' }}>{node.IP || '-'}</div>
                                            </div>
                                            <Tag color={node.Status === 'Alive' ? '#10b981' : '#94a3b8'}
                                                style={{ borderRadius: 20, padding: '0 8px', fontSize: 11, margin: 0 }}>
                                                {getNodeStatusText(node.Status)}
                                            </Tag>
                                        </div>
                                    </List.Item>
                                )}
                            />
                        ) : (
                            <div style={{ textAlign: 'center', padding: '50px 0', color: '#94a3b8' }}>暂无节点</div>
                        )}
                    </ProCard>
                </Col>
                <Col xs={24} lg={14}>
                    <ProCard
                        title={
                            <Space>
                                <RocketOutlined style={{ color: '#10b981' }} />
                                <Text strong style={{ color: '#1e293b', fontSize: 15 }}>最近任务</Text>
                            </Space>
                        }
                        style={{ ...cardStyle, height: '100%' }}
                        bodyStyle={{ padding: '4px 16px', maxHeight: 340, overflow: 'auto' }}
                    >
                        {recentTasks.length > 0 ? (
                            <List
                                dataSource={recentTasks}
                                renderItem={(task) => (
                                    <List.Item style={{ padding: '10px 0', borderBottom: '1px solid #f1f5f9' }}>
                                        <List.Item.Meta
                                            avatar={getStatusIcon(task.Status)}
                                            title={
                                                <Space>
                                                    <Text style={{ fontWeight: 500 }}>{task.Name}</Text>
                                                    {getStatusTag(task.Status)}
                                                </Space>
                                            }
                                            description={
                                                <Space>
                                                    <Text style={{ color: '#94a3b8', fontSize: 12 }}>{task.CreatedAt}</Text>
                                                    {task.TotalChunks > 0 && (
                                                        <Text style={{ color: '#0ea5e9', fontSize: 12 }}>
                                                            {task.CompletedChunks}/{task.TotalChunks} 分片
                                                        </Text>
                                                    )}
                                                </Space>
                                            }
                                        />
                                    </List.Item>
                                )}
                            />
                        ) : (
                            <div style={{ textAlign: 'center', padding: '50px 0', color: '#94a3b8' }}>暂无任务</div>
                        )}
                    </ProCard>
                </Col>
            </Row>

            {/* Real-time WebSocket Feed */}
            <Row gutter={[12, 12]}>
                <Col span={24}>
                    <ProCard
                        title={
                            <Space>
                                <ThunderboltOutlined style={{ color: wsConnected ? '#10b981' : '#94a3b8' }} />
                                <Text strong style={{ color: '#1e293b', fontSize: 15 }}>实时推送</Text>
                                <Badge status={wsConnected ? 'success' : 'default'} text={wsConnected ? '在线' : '离线'} />
                            </Space>
                        }
                        style={cardStyle}
                        bodyStyle={{ padding: '4px 16px' }}
                    >
                        {wsMessages.length > 0 ? (
                            <Table
                                columns={wsColumns}
                                dataSource={wsMessages.map((m, i) => ({ ...m, key: i }))}
                                pagination={false}
                                size="small"
                                scroll={{ y: 200 }}
                                showHeader={false}
                            />
                        ) : (
                            <div style={{ textAlign: 'center', padding: '30px 0', color: '#94a3b8' }}>
                                等待实时扫描数据推送…
                            </div>
                        )}
                    </ProCard>
                </Col>
            </Row>
        </div>
    );
};

export default Dashboard;
