import React, { useEffect, useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { Typography, Tag, Space, Button, Spin, Tooltip, Popover, Badge, Empty, Progress, List, Row, Col, Divider, message, Popconfirm } from 'antd';
import { ProCard } from '@ant-design/pro-components';
import {
    ReloadOutlined,
    ClusterOutlined,
    WifiOutlined,
    DisconnectOutlined,
    FieldTimeOutlined,
    DesktopOutlined,
    TagsOutlined,
    AppstoreOutlined,
    DashboardOutlined,
    HddOutlined,
    DeleteOutlined,
    ClearOutlined
} from '@ant-design/icons';
import { getNodes, deleteNode, cleanOfflineNodes } from '../services/api';
import { useAutoContext } from '../contexts/GlobalAIContext';
import { canAccessRole } from '../utils/auth';
import gsap from 'gsap';
import NetworkCanvas from '../components/NetworkCanvas';

const { Title, Text } = Typography;

function parseNodeTags(tags?: string): Record<string, string> {
    if (!tags) return {};
    try {
        const parsed = JSON.parse(tags);
        if (parsed && !Array.isArray(parsed) && typeof parsed === 'object') {
            return Object.fromEntries(
                Object.entries(parsed as Record<string, unknown>)
                    .filter(([, value]) => typeof value === 'string')
                    .map(([key, value]) => [key, String(value)])
            );
        }
    } catch {
        return {};
    }
    return {};
}

const NodeManagement: React.FC = () => {
    const [loading, setLoading] = useState(true);
    const [nodes, setNodes] = useState<API.AgentNode[]>([]);
    const canManageNodes = canAccessRole('operator');
    const navigate = useNavigate();
    const cardsRef = useRef<HTMLDivElement>(null);

    /* GSAP card entrance */
    useEffect(() => {
        if (!cardsRef.current || nodes.length === 0) return;
        const cards = cardsRef.current.querySelectorAll('.node-card');
        if (cards.length === 0) return;
        const ctx = gsap.context(() => {
            gsap.from(cards, {
                y: 30, opacity: 0, duration: 0.45,
                stagger: 0.06, ease: 'power2.out', clearProps: 'transform,opacity',
            });
        }, cardsRef);
        return () => ctx.revert();
    }, [nodes]);

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

    const onlineCount = nodes.filter(n => n.Status === 'Alive').length;
    const offlineCount = nodes.length - onlineCount;

    useAutoContext({
        node_stats: {
            total: nodes.length,
            online: onlineCount,
            offline: offlineCount,
        },
        agents: nodes.map(n => ({
            agent_id: n.AgentID,
            ip: n.IP,
            status: n.Status,
            version: n.Version,
            os: n.OS,
            capacity: n.Capacity,
            running_tasks: n.RunningTasks,
            cpu: Math.round(n.CPUUsage || 0),
            mem: Math.round(n.MemUsage || 0),
        })),
    });

    const handleCleanOffline = async () => {
        if (!canManageNodes) return;
        try {
            const res = await cleanOfflineNodes();
            message.success(`成功清理 ${res.count} 个离线节点`);
            fetchNodes();
        } catch (e: any) {
            message.error(e || '清理失败');
        }
    };

    const handleDeleteNode = async (agentId: string) => {
        if (!canManageNodes) return;
        try {
            await deleteNode(agentId);
            message.success('删除成功');
            fetchNodes();
        } catch (e: any) {
            message.error(e || '删除失败');
        }
    };

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

    const renderTags = (tagsStr: string) => {
        const tags = parseNodeTags(tagsStr);
        if (Object.keys(tags).length === 0) return <Text type="secondary" style={{ fontSize: 12 }}>无标签</Text>;
        const colors = ['blue', 'cyan', 'geekblue', 'purple'];
        return Object.entries(tags).map(([key, value], i) => (
            <Tag key={key} color={colors[i % colors.length]} style={{ fontSize: 11, borderRadius: 10, border: 'none' }}>
                {key}={value}
            </Tag>
        ));
    };

    const renderNodeCard = (record: API.AgentNode) => {
        const isAlive = record.Status === 'Alive';
        const running = record.RunningTasks || 0;
        const capacity = record.Capacity || 10;
        const freeSlots = Math.max(capacity - running, 0);
        const percent = Math.min(100, Math.round((running / capacity) * 100));
        
        let color = '#10b981'; // Green
        if (percent > 70) color = '#f59e0b'; // Yellow
        if (percent > 90) color = '#ef4444'; // Red

        const cpuPercent = record.CPUUsage ? Math.round(record.CPUUsage) : 0;
        const memPercent = record.MemUsage ? Math.round(record.MemUsage) : 0;
        
        let cpuColor = '#10b981';
        if (cpuPercent > 60) cpuColor = '#f59e0b';
        if (cpuPercent > 85) cpuColor = '#ef4444';

        let memColor = '#10b981';
        if (memPercent > 60) memColor = '#f59e0b';
        if (memPercent > 85) memColor = '#ef4444';

        const taskContent = (
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
            <Col xs={24} sm={12} md={12} lg={8} xl={6} key={record.AgentID}>
                <ProCard 
                    className="glass-card node-card hover-lift"
                    style={{ 
                        borderRadius: 16, 
                        border: '1px solid rgba(255, 255, 255, 0.4)',
                        overflow: 'hidden',
                        height: '100%'
                    }}
                    bodyStyle={{ padding: 20 }}
                >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                            <div style={{ 
                                width: 40, 
                                height: 40, 
                                borderRadius: 12, 
                                background: isAlive ? 'rgba(16, 185, 129, 0.1)' : 'rgba(148, 163, 184, 0.1)',
                                display: 'flex', 
                                alignItems: 'center', 
                                justifyContent: 'center',
                                color: isAlive ? '#10b981' : '#94a3b8'
                            }}>
                                <DesktopOutlined style={{ fontSize: 20 }} />
                            </div>
                            <div>
                                <Tooltip title={record.AgentID}>
                                    <Text copyable={{ text: record.AgentID }} style={{ fontWeight: 600, fontSize: 15, color: '#1e293b' }}>
                                        {record.AgentID.substring(0, 8)}...
                                    </Text>
                                </Tooltip>
                                <div style={{ fontSize: 12, color: '#64748b', marginTop: 2 }}>
                                    {record.IP || '未知 IP'}
                                </div>
                            </div>
                        </div>
                        <Space>
                            <Badge
                                status={isAlive ? 'success' : 'default'}
                                text={
                                    <span style={{ color: isAlive ? '#10b981' : '#94a3b8', fontSize: 12, fontWeight: 500 }}>
                                        {isAlive ? '在线' : '离线'}
                                    </span>
                                }
                            />
                            {canManageNodes && !isAlive && (
                                <Popconfirm
                                    title="删除节点"
                                    description="确定要删除该离线节点吗？"
                                    onConfirm={() => handleDeleteNode(record.AgentID)}
                                    okText="删除"
                                    cancelText="取消"
                                >
                                    <Button type="text" danger icon={<DeleteOutlined />} size="small" />
                                </Popconfirm>
                            )}
                        </Space>
                    </div>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                        <div>
                            <Text type="secondary" style={{ fontSize: 12, display: 'block', marginBottom: 4 }}>
                                <TagsOutlined style={{ marginRight: 6 }} />能力标签
                            </Text>
                            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                                {record.OS && <Tag color="default" style={{ fontSize: 11, borderRadius: 10, border: '1px solid #e2e8f0' }}>{record.OS}</Tag>}
                                {record.Arch && <Tag color="default" style={{ fontSize: 11, borderRadius: 10, border: '1px solid #e2e8f0' }}>{record.Arch}</Tag>}
                                {renderTags(record.Tags)}
                            </div>
                        </div>

                        <div>
                            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                                <Text type="secondary" style={{ fontSize: 12 }}>
                                    <AppstoreOutlined style={{ marginRight: 6 }} />当前负载 ({running}/{capacity})
                                </Text>
                            </div>
                            {isAlive ? (
                                <Popover content={taskContent} trigger="hover" placement="top">
                                    <div style={{ cursor: 'pointer' }}>
                                        <Progress 
                                            percent={percent} 
                                            showInfo={false} 
                                            size="small" 
                                            strokeColor={color} 
                                            trailColor="rgba(0,0,0,0.04)"
                                            style={{ margin: 0 }} 
                                        />
                                    </div>
                                </Popover>
                            ) : (
                                <Progress percent={0} showInfo={false} size="small" style={{ margin: 0 }} />
                            )}
                        </div>

                        {/* 硬件负载指标 */}
                        <div style={{ display: 'flex', gap: 16, marginTop: 4 }}>
                            <div style={{ flex: 1 }}>
                                <Text type="secondary" style={{ fontSize: 11, display: 'block', marginBottom: 2 }}>
                                    <DashboardOutlined style={{ marginRight: 4 }} />CPU
                                </Text>
                                <Progress percent={isAlive ? cpuPercent : 0} size="small" strokeColor={cpuColor} format={(p) => <span style={{fontSize: 10}}>{p}%</span>} />
                            </div>
                            <div style={{ flex: 1 }}>
                                <Text type="secondary" style={{ fontSize: 11, display: 'block', marginBottom: 2 }}>
                                    <HddOutlined style={{ marginRight: 4 }} />内存
                                </Text>
                                <Progress percent={isAlive ? memPercent : 0} size="small" strokeColor={memColor} format={(p) => <span style={{fontSize: 10}}>{p}%</span>} />
                            </div>
                        </div>

                        <Divider style={{ margin: '8px 0' }} />

                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12 }}>
                            <Text type="secondary">规则版本: <Text strong>{record.RuleVersion || '未知'}</Text></Text>
                            <Text type="secondary">引擎: <Text strong>{record.Version || '-'}</Text></Text>
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12 }}>
                            <Text type="secondary">空闲槽位: <Text strong>{freeSlots}</Text></Text>
                            <Button type="link" size="small" onClick={() => navigate(`/agent-logs?agent_id=${encodeURIComponent(record.AgentID)}`)}>
                                查看日志
                            </Button>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: 12 }}>
                            <Tooltip title={formatLastBeat(record.LastBeat)}>
                                <Space size={4}>
                                    <FieldTimeOutlined style={{ color: '#64748b' }} />
                                    <Text style={{ color: '#64748b' }}>心跳: {getTimeSince(record.LastBeat)}</Text>
                                </Space>
                            </Tooltip>
                        </div>
                    </div>
                </ProCard>
            </Col>
        );
    };

    return (
        <div style={{ paddingBottom: 40, position: 'relative', overflow: 'hidden' }}>
            <NetworkCanvas color="#0ea5e9" count={35} speed={0.15} linkDist={100} />
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24, position: 'relative', zIndex: 1 }}>
                <div>
                    <Title level={3} style={{ margin: 0, color: '#1e293b', fontWeight: 600 }}>
                        <ClusterOutlined style={{ marginRight: 12, color: '#0ea5e9' }} />
                        分布式节点大屏
                    </Title>
                    <Text type="secondary" style={{ marginTop: 4, display: 'block' }}>实时监控与管理全局扫描算力池</Text>
                </div>
                <Space>
                    <Tag color="success" style={{ borderRadius: 20, padding: '4px 12px', border: 'none', background: 'rgba(16, 185, 129, 0.1)', color: '#10b981' }}>
                        <WifiOutlined /> 在线 {onlineCount}
                    </Tag>
                    <Tag color="default" style={{ borderRadius: 20, padding: '4px 12px', border: 'none', background: 'rgba(148, 163, 184, 0.1)', color: '#64748b' }}>
                        <DisconnectOutlined /> 离线 {offlineCount}
                    </Tag>
                    {canManageNodes && offlineCount > 0 && (
                        <Popconfirm
                            title="清理离线节点"
                            description="确定要清理所有离线的节点吗？"
                            onConfirm={handleCleanOffline}
                            okText="清理"
                            cancelText="取消"
                        >
                            <Button danger icon={<ClearOutlined />} style={{ borderRadius: 8 }}>
                                清理离线
                            </Button>
                        </Popconfirm>
                    )}
                    <Button type="primary" icon={<ReloadOutlined />} onClick={fetchNodes} loading={loading} style={{ borderRadius: 8 }}>
                        实时刷新
                    </Button>
                </Space>
            </div>

            {loading && nodes.length === 0 ? (
                <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: 400 }}>
                    <Spin size="large" />
                </div>
            ) : nodes.length === 0 ? (
                <Empty
                    image={Empty.PRESENTED_IMAGE_SIMPLE}
                    description="当前集群暂无计算节点接入"
                    style={{ padding: '100px 0', background: 'rgba(255,255,255,0.4)', borderRadius: 16 }}
                />
            ) : (
                <div ref={cardsRef} style={{ position: 'relative', zIndex: 1 }}>
                    <Row gutter={[20, 20]}>
                        {nodes.map(node => renderNodeCard(node))}
                    </Row>
                </div>
            )}
            
            <style>{`
                .node-card {
                    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                }
                .hover-lift:hover {
                    transform: translateY(-4px);
                    box-shadow: 0 12px 24px -8px rgba(0, 0, 0, 0.08), 0 4px 12px -4px rgba(0, 0, 0, 0.04);
                }
            `}</style>
        </div>
    );
};

export default NodeManagement;
