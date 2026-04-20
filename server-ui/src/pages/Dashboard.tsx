import React, { useEffect, useState, useCallback } from 'react';
import { Row, Col, Typography, List, Tag, Space, Spin, Badge, Tooltip, Table, Empty } from 'antd';
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
    BarChartOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import ReactECharts from 'echarts-for-react';
import { getDashboardStats, listTasks, getNodes, connectWebSocket, getQueueDepth } from '../services/api';
import { getTaskStatusMeta, normalizeTaskStatus } from '../utils/taskStatus';

const { Text, Title } = Typography;

type QueueDepthInfo = {
    depth: Record<string, number>;
    pending: Record<string, number>;
    mode: string;
    ready_batches?: number;
    pending_batches?: number;
    ready_targets?: number;
    pending_targets?: number;
};

const Dashboard: React.FC = () => {
    const [loading, setLoading] = useState(true);
    const [stats, setStats] = useState<API.DashboardStats | null>(null);
    const [recentTasks, setRecentTasks] = useState<API.RootTask[]>([]);
    const [nodes, setNodes] = useState<API.AgentNode[]>([]);
    const [queueDepth, setQueueDepth] = useState<QueueDepthInfo | null>(null);
    const [wsConnected, setWsConnected] = useState(false);
    const [wsMessages, setWsMessages] = useState<{ time: string; type: string; data: string }[]>([]);

    const fetchData = useCallback(async () => {
        try {
            const [statsRes, tasksRes, nodesRes, queueRes] = await Promise.all([
                getDashboardStats(),
                listTasks(),
                getNodes(),
                getQueueDepth().catch(() => null),
            ]);
            setStats(statsRes);
            setRecentTasks((tasksRes || []).slice(0, 8));
            setNodes(nodesRes || []);
            if (queueRes) setQueueDepth(queueRes);
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
                    data: JSON.stringify(msg),
                },
                ...prev.slice(0, 49),
            ]);
            // Auto-refresh stats when we receive a WS message
            fetchData();
        });
        ws.onopen = () => setWsConnected(true);
        ws.onclose = () => setWsConnected(false);
        ws.onerror = () => setWsConnected(false);
        return () => {
            ws.close();
        };
    }, [fetchData]);

    const getStatusTag = (status: string) => {
        const { color, text } = getTaskStatusMeta(status);
        return <Tag color={color}>{text}</Tag>;
    };

    const getStatusIcon = (status: string) => {
        switch (normalizeTaskStatus(status)) {
            case 'FINISHED':
            case 'DONE':
                return <CheckCircleOutlined style={{ color: '#10b981' }} />;
            case 'PARTIALDONE':
                return <CheckCircleOutlined style={{ color: '#0ea5e9' }} />;
            case 'RUNNING':
                return <ClockCircleOutlined style={{ color: '#0ea5e9' }} spin />;
            case 'FAILED':
            case 'TIMEOUT':
                return <ExclamationCircleOutlined style={{ color: '#ef4444' }} />;
            case 'CANCELLED':
            case 'CANCELPENDING':
                return <ExclamationCircleOutlined style={{ color: '#94a3b8' }} />;
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

    const DispatchVisualizer: React.FC<{
        nodes: API.AgentNode[];
        wsMessages: { time: string; type: string; data: string }[];
        queueDepth: QueueDepthInfo | null;
    }> = ({ nodes, wsMessages, queueDepth }) => {
        const [animations, setAnimations] = useState<{ id: string; agentIndex: number; taskId: string }[]>([]);
        
        const activeNodes = nodes.filter(n => n.Status === 'Alive');
    
        useEffect(() => {
            const latestMsg = wsMessages[0];
            if (latestMsg && latestMsg.type === 'task_claimed') {
                try {
                    const data = JSON.parse(latestMsg.data);
                    if (data.agent_id) {
                        const agentIndex = activeNodes.findIndex(n => n.AgentID === data.agent_id);
                        if (agentIndex !== -1) {
                            const animId = Math.random().toString(36).substring(7);
                            setAnimations(prev => [...prev, { id: animId, agentIndex, taskId: data.task_id }]);
                            setTimeout(() => {
                                setAnimations(prev => prev.filter(a => a.id !== animId));
                            }, 800);
                        }
                    }
                } catch {}
            }
        }, [wsMessages, activeNodes]);
    
        const sumValues = (items?: Record<string, number>) =>
            Object.values(items || {}).reduce((acc, v) => acc + v, 0);
        const queueMode = queueDepth?.mode || 'unknown';
        const queueTitle = queueMode === 'rabbitmq'
            ? 'RabbitMQ 队列'
            : queueMode === 'memory'
                ? '内存队列'
                : '任务队列';
        const totalQueued = sumValues(queueDepth?.depth);
        const totalPending = sumValues(queueDepth?.pending);
        const urgentReady = queueDepth?.depth?.['dddd.tasks.urgent'] || 0;
        const normalReady = queueDepth?.depth?.['dddd.tasks.normal'] || 0;
        const lowReady = queueDepth?.depth?.['dddd.tasks.low'] || 0;
        const urgentPending = queueDepth?.pending?.['dddd.tasks.urgent'] || 0;
        const normalPending = queueDepth?.pending?.['dddd.tasks.normal'] || 0;
        const lowPending = queueDepth?.pending?.['dddd.tasks.low'] || 0;

        const queueTooltip = (
            <div>
                <div><strong>模式:</strong> {queueMode}</div>
                <div><strong>可领取批次:</strong> {queueDepth?.ready_batches ?? totalQueued}</div>
                <div><strong>处理中批次:</strong> {queueDepth?.pending_batches ?? totalPending}</div>
                {(queueDepth?.ready_targets !== undefined) && (
                    <>
                        <div><strong>可领取目标:</strong> {queueDepth.ready_targets}</div>
                        <div><strong>处理中目标:</strong> {queueDepth.pending_targets}</div>
                    </>
                )}
                {queueMode === 'rabbitmq' ? (
                    <>
                        <div><strong>Urgent 紧急:</strong> {urgentReady} / pending {urgentPending}</div>
                        <div><strong>Normal 普通:</strong> {normalReady} / pending {normalPending}</div>
                        <div><strong>Low 低级:</strong> {lowReady} / pending {lowPending}</div>
                    </>
                ) : (
                    <div><strong>Memory:</strong> {queueDepth?.depth?.memory || 0}</div>
                )}
            </div>
        );
    
        return (
            <div style={{ display: 'flex', alignItems: 'stretch', height: 280 }}>
                {/* Queue Block */}
                <div style={{ width: 120, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <Tooltip title={queueTooltip} placement="right">
                        <div className="glass-card" style={{ padding: 20, textAlign: 'center', borderRadius: 12, border: '1px solid #e2e8f0', background: '#f8fafc', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)', cursor: 'pointer' }}>
                            <DatabaseOutlined style={{ fontSize: 32, color: '#ef4444' }} />
                            <div style={{ marginTop: 8, fontWeight: 'bold' }}>{queueTitle}</div>
                            <Tag color="error" style={{ marginTop: 8 }}>{totalQueued as React.ReactNode} 积压</Tag>
                            <Tag color="processing" style={{ marginTop: 4 }}>{totalPending as React.ReactNode} 处理中</Tag>
                        </div>
                    </Tooltip>
                </div>
    
                {/* Animation Flow Area */}
                <div style={{ flex: 1, position: 'relative', overflow: 'hidden', borderTop: '1px dashed #e2e8f0', borderBottom: '1px dashed #e2e8f0', margin: '0 20px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <div style={{ color: '#94a3b8', fontSize: 12, letterSpacing: 2, opacity: 0.5 }}>TASK FLOW</div>
                    {animations.map(anim => {
                        const topPercent = activeNodes.length > 1 
                            ? (anim.agentIndex / (activeNodes.length - 1)) * 80 + 10 
                            : 50;
                        return (
                            <div key={anim.id} style={{
                                position: 'absolute',
                                left: 0,
                                top: '50%',
                                width: 90,
                                padding: '4px 8px',
                                background: 'linear-gradient(90deg, #10b981, #0ea5e9)',
                                color: '#fff',
                                fontSize: 10,
                                borderRadius: 12,
                                whiteSpace: 'nowrap',
                                boxShadow: '0 0 10px rgba(16, 185, 129, 0.5)',
                                transition: 'all 0.8s cubic-bezier(0.4, 0, 0.2, 1)',
                                transform: 'translate(0, -50%)',
                            }}
                            ref={el => {
                                if (el) {
                                    setTimeout(() => {
                                        el.style.left = 'calc(100% - 100px)';
                                        el.style.top = `${topPercent}%`;
                                    }, 10);
                                }
                            }}
                            >
                                <RocketOutlined /> {anim.taskId.slice(0,6)}
                            </div>
                        );
                    })}
                </div>
    
                {/* Agents Block */}
                <div style={{ width: 220, display: 'flex', flexDirection: 'column', gap: 10, overflowY: 'auto', paddingRight: 10 }}>
                    {activeNodes.length > 0 ? activeNodes.map(node => {
                        let taskIds: string[] = [];
                        try {
                            const runningIdsRaw = node.RunningTaskIDs || node.RunningTaskIds || '[]';
                            taskIds = JSON.parse(runningIdsRaw);
                        } catch {}
    
                        const tooltip = (
                            <div style={{ maxWidth: 200 }}>
                                <div>运行中: {node.RunningTasks}/{node.Capacity}</div>
                                {taskIds.map((id: string) => <div key={id} style={{ fontSize: 10, color: '#94a3b8' }}>{id}</div>)}
                            </div>
                        );
    
                        return (
                            <Tooltip title={tooltip} placement="left" key={node.AgentID}>
                                <div style={{ 
                                    padding: 10, 
                                    borderRadius: 8, 
                                    border: '1px solid #e2e8f0', 
                                    background: '#fff',
                                    display: 'flex',
                                    alignItems: 'center',
                                    gap: 10,
                                    boxShadow: '0 1px 3px 0 rgb(0 0 0 / 0.1)',
                                    cursor: 'pointer',
                                    transition: 'all 0.2s'
                                }}
                                onMouseEnter={(e) => e.currentTarget.style.transform = 'scale(1.02)'}
                                onMouseLeave={(e) => e.currentTarget.style.transform = 'scale(1)'}
                                >
                                    <Badge status="processing" color={taskIds.length > 0 ? '#10b981' : '#94a3b8'} />
                                    <div style={{ flex: 1, minWidth: 0 }}>
                                        <div style={{ fontWeight: 500, fontSize: 12, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                                            {node.AgentID}
                                        </div>
                                    </div>
                                    <Tag color={taskIds.length > 0 ? "processing" : "default"} style={{ margin: 0 }}>
                                        {node.RunningTasks}
                                    </Tag>
                                </div>
                            </Tooltip>
                        );
                    }) : (
                        <div style={{ color: '#94a3b8', fontSize: 12, textAlign: 'center', marginTop: 50 }}>无可用节点</div>
                    )}
                </div>
            </div>
        );
    };

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



    const onlineCount = nodes.filter(n => n.Status === 'Alive').length;

    const wsColumns: ColumnsType<{ time: string; type: string; data: string }> = [
        { title: '时间', dataIndex: 'time', key: 'time', width: 90, render: (v) => <Text style={{ fontSize: 11, color: '#94a3b8' }}>{v}</Text> },
        { title: '类型', dataIndex: 'type', key: 'type', width: 100, render: (v) => <Tag color="blue" style={{ fontSize: 10 }}>{v}</Tag> },
        { title: '数据', dataIndex: 'data', key: 'data', ellipsis: true, render: (v) => <Text style={{ fontSize: 11, fontFamily: 'monospace', color: '#64748b' }}>{v}</Text> },
    ];

    const vulnPieOptions = {
        tooltip: { trigger: 'item' },
        series: [
            {
                name: '漏洞分布',
                type: 'pie',
                radius: ['40%', '70%'],
                avoidLabelOverlap: false,
                itemStyle: { borderRadius: 10, borderColor: '#fff', borderWidth: 2 },
                label: { show: false, position: 'center' },
                emphasis: { label: { show: true, fontSize: '18', fontWeight: 'bold' } },
                labelLine: { show: false },
                data: [
                    { value: Math.floor((stats?.vulns || 0) * 0.1), name: '严重', itemStyle: { color: '#ef4444' } },
                    { value: Math.floor((stats?.vulns || 0) * 0.2), name: '高危', itemStyle: { color: '#f97316' } },
                    { value: Math.floor((stats?.vulns || 0) * 0.4), name: '中危', itemStyle: { color: '#f59e0b' } },
                    { value: Math.floor((stats?.vulns || 0) * 0.3), name: '低危', itemStyle: { color: '#10b981' } },
                ]
            }
        ]
    };


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
                        <ProCard hoverable className="glass-card" bodyStyle={{ padding: 18 }} style={{ height: '100%', background: 'transparent', border: 'none' }}>
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
                <Col xs={24} lg={8}>
                    <ProCard
                        title={
                            <Space>
                                <BugOutlined style={{ color: '#ef4444' }} />
                                <Text strong style={{ color: '#1e293b', fontSize: 15 }}>漏洞统计</Text>
                            </Space>
                        }
                        className="glass-card"
                        style={{ height: '100%', background: 'transparent', border: 'none' }}
                        bodyStyle={{ padding: '0 16px', height: 340, display: 'flex', alignItems: 'center', justifyContent: 'center' }}
                    >
                        {(stats?.vulns || 0) > 0 ? (
                            <ReactECharts option={vulnPieOptions} style={{ height: '100%', width: '100%' }} />
                        ) : (
                            <div style={{ textAlign: 'center', color: '#94a3b8' }}>暂无漏洞数据</div>
                        )}
                    </ProCard>
                </Col>
                <Col xs={24} lg={8}>
                    <ProCard
                        title={
                            <Space>
                                <NodeIndexOutlined style={{ color: '#0ea5e9' }} />
                                <Text strong style={{ color: '#1e293b', fontSize: 15 }}>节点状态</Text>
                                <Tag color="blue">{nodes.length} 个</Tag>
                            </Space>
                        }
                        className="glass-card"
                        style={{ height: '100%', background: 'transparent', border: 'none' }}
                        bodyStyle={{ padding: '4px 16px', maxHeight: 340, overflow: 'auto' }}
                    >
                        {nodes.length > 0 ? (
                            <List
                                dataSource={nodes}
                                renderItem={(node) => (
                                    <List.Item style={{ padding: '8px 0', borderBottom: '1px solid rgba(241, 245, 249, 0.5)' }}>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: 10, width: '100%' }}>
                                            <div className="pulse-dot" style={{ width: 8, height: 8, borderRadius: '50%', background: node.Status === 'Alive' ? '#10b981' : '#94a3b8' }} />
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
                <Col xs={24} lg={8}>
                    <ProCard
                        title={
                            <Space>
                                <RocketOutlined style={{ color: '#10b981' }} />
                                <Text strong style={{ color: '#1e293b', fontSize: 15 }}>最近任务</Text>
                            </Space>
                        }
                        className="glass-card"
                        style={{ height: '100%', background: 'transparent', border: 'none' }}
                        bodyStyle={{ padding: '4px 16px', maxHeight: 340, overflow: 'auto' }}
                    >
                        {recentTasks.length > 0 ? (
                            <List
                                dataSource={recentTasks}
                                renderItem={(task) => (
                                    <List.Item style={{ padding: '10px 0', borderBottom: '1px solid rgba(241, 245, 249, 0.5)' }}>
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
                                                    {task.TotalTargets > 0 ? (
                                                        <Text style={{ color: '#0ea5e9', fontSize: 12 }}>
                                                            {task.CompletedTargets}/{task.TotalTargets} 目标 · {task.CompletedChunks}/{task.TotalChunks} 批次
                                                        </Text>
                                                    ) : task.TotalChunks > 0 ? (
                                                        <Text style={{ color: '#0ea5e9', fontSize: 12 }}>
                                                            {task.CompletedChunks}/{task.TotalChunks} 分片
                                                        </Text>
                                                    ) : null}
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

            {/* Agent Workload Dashboard */}
            <Row gutter={[12, 12]} style={{ marginBottom: 20 }}>
                <Col span={24}>
                    <ProCard
                        title={
                            <Space>
                                <BarChartOutlined style={{ color: '#8b5cf6' }} />
                                <Text strong style={{ color: '#1e293b', fontSize: 15 }}>任务队列与算力分布 (Multi-Agent Dispatch)</Text>
                                {onlineCount > 0 && <Tag color="purple">动态调度中</Tag>}
                            </Space>
                        }
                        className="glass-card"
                        style={{ background: 'transparent', border: 'none' }}
                        bodyStyle={{ padding: '16px', height: 280 }}
                    >
                        {onlineCount > 0 ? (
                            <DispatchVisualizer nodes={nodes} wsMessages={wsMessages} queueDepth={queueDepth} />
                        ) : (
                            <div style={{ height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#94a3b8' }}>
                                <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无在线计算节点，无法展示调度流" />
                            </div>
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
                        className="glass-card"
                        style={{ background: 'transparent', border: 'none' }}
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
