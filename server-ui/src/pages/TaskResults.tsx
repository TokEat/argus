import React, { useEffect, useState } from 'react';
import { Typography, Table, Tag, Tabs, Space, Spin, Button, Tooltip, Empty, Drawer, Descriptions, Divider, Popover } from 'antd';
import { ProCard } from '@ant-design/pro-components';
import {
    BugOutlined,
    GlobalOutlined,
    ScanOutlined,
    DownloadOutlined,
    ArrowLeftOutlined,
    ReloadOutlined,
    SendOutlined,
    CloudDownloadOutlined,
    LinkOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import { useNavigate, useParams } from 'react-router-dom';
import { getVulns, getAssets, getFingerprints, exportVulns } from '../services/api';
import { useAutoContext } from '../contexts/GlobalAIContext';
import dayjs from 'dayjs';

const { Title, Text } = Typography;

const TaskResults: React.FC = () => {
    const { taskId } = useParams<{ taskId: string }>();
    const [loading, setLoading] = useState(true);
    const [vulns, setVulns] = useState<API.Vulnerability[]>([]);
    const [assets, setAssets] = useState<API.Asset[]>([]);
    const [fingerprints, setFingerprints] = useState<API.FingerprintHit[]>([]);
    const [activeTab, setActiveTab] = useState('vulns');
    const [selectedVuln, setSelectedVuln] = useState<API.Vulnerability | null>(null);
    const [drawerOpen, setDrawerOpen] = useState(false);
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

    useAutoContext({
        task_id: taskId,
        active_tab: activeTab,
        stats: {
            vulns: vulns.length,
            assets: assets.length,
            fingerprints: fingerprints.length,
        },
        viewing_vuln: drawerOpen ? selectedVuln : null,
    });

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

    const handleVulnClick = (record: API.Vulnerability) => {
        setSelectedVuln(record);
        setDrawerOpen(true);
    };

    const parseReferences = (ref: string): string[] => {
        if (!ref) return [];
        try {
            const parsed = JSON.parse(ref);
            return Array.isArray(parsed) ? parsed : [ref];
        } catch {
            return ref ? [ref] : [];
        }
    };

    const getSeverityColor = (severity: string) => {
        const normalized = severity ? severity.charAt(0).toUpperCase() + severity.slice(1).toLowerCase() : 'Unknown';
        const map: Record<string, string> = {
            Critical: '#ef4444', High: '#f97316', Medium: '#f59e0b',
            Low: '#3b82f6', Info: '#14b8a6', Unknown: '#94a3b8',
        };
        return map[normalized] || '#94a3b8';
    };

    const getSeverityWeight = (severity: string) => {
        const normalized = severity ? severity.charAt(0).toUpperCase() + severity.slice(1).toLowerCase() : 'Unknown';
        const map: Record<string, number> = {
            Critical: 5, High: 4, Medium: 3, Low: 2, Info: 1, Unknown: 0,
        };
        return map[normalized] || 0;
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
            render: (v: string) => {
                const normalized = v ? v.charAt(0).toUpperCase() + v.slice(1).toLowerCase() : 'Unknown';
                return <Tag color={getSeverityColor(normalized)}>{normalized}</Tag>;
            },
            filters: ['Critical', 'High', 'Medium', 'Low', 'Info', 'Unknown'].map(s => ({ text: s, value: s })),
            onFilter: (value, record) => {
                const normalized = record.Severity ? record.Severity.charAt(0).toUpperCase() + record.Severity.slice(1).toLowerCase() : 'Unknown';
                return normalized === value;
            },
            sorter: (a, b) => getSeverityWeight(b.Severity) - getSeverityWeight(a.Severity),
            defaultSortOrder: 'ascend',
        },
        {
            title: '匹配位置',
            dataIndex: 'MatchedAt',
            key: 'matched_at',
            ellipsis: true,
            render: (v: string) => v ? (
                <Text style={{ fontSize: 12, fontFamily: 'monospace', color: '#0ea5e9' }}>{v}</Text>
            ) : <Text type="secondary">-</Text>,
        },
        {
            title: '请求/响应',
            key: 'has_packet',
            width: 90,
            align: 'center',
            render: (_: unknown, record: API.Vulnerability) => {
                const hasData = record.Request || record.Response;
                return hasData
                    ? <Tag color="green" style={{ cursor: 'pointer' }}><SendOutlined /> 有</Tag>
                    : <Text type="secondary" style={{ fontSize: 12 }}>-</Text>;
            },
        },
        {
            title: '发现时间',
            dataIndex: 'CreatedAt',
            key: 'created_at',
            width: 170,
            sorter: (a, b) => new Date(a.CreatedAt).getTime() - new Date(b.CreatedAt).getTime(),
            render: (v: string) => {
                if (!v) return '-';
                return <Text style={{ fontSize: 12, color: '#64748b' }}>{dayjs(v).format('YYYY-MM-DD HH:mm:ss')}</Text>;
            },
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
            render: (v: string) => {
                if (!v) return '-';
                return <Text style={{ fontSize: 12, color: '#64748b' }}>{dayjs(v).format('YYYY-MM-DD HH:mm:ss')}</Text>;
            },
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
            title: '证据',
            dataIndex: 'Evidence',
            key: 'evidence',
            render: (v: string) => {
                if (!v) return <Text type="secondary">-</Text>;
                try {
                    const parsed = JSON.parse(v);
                    const web = parsed.web;
                    return (
                        <Popover
                            content={<pre style={{ maxWidth: 500, maxHeight: 400, overflow: 'auto', fontSize: 12, margin: 0 }}>{JSON.stringify(parsed, null, 2)}</pre>}
                            title={<span style={{ fontSize: 13 }}>完整证据 (JSON)</span>}
                            trigger="hover"
                            placement="left"
                        >
                            <Space size={4} style={{ cursor: 'pointer' }}>
                                {web?.status && (
                                    <Tag color={String(web.status) === '200' ? 'green' : (String(web.status).startsWith('3') ? 'blue' : 'orange')} style={{ margin: 0 }}>
                                        {web.status}
                                    </Tag>
                                )}
                                {web?.title ? (
                                    <Text style={{ fontSize: 12, color: '#64748b', maxWidth: 250 }} ellipsis={{ tooltip: web.title }}>
                                        {web.title}
                                    </Text>
                                ) : (
                                    <Text style={{ fontSize: 12, color: '#64748b', maxWidth: 250 }} ellipsis>
                                        {v}
                                    </Text>
                                )}
                            </Space>
                        </Popover>
                    );
                } catch {
                    return (
                        <Tooltip title={v}>
                            <Text style={{ fontSize: 12, color: '#64748b', maxWidth: 260 }} ellipsis>{v}</Text>
                        </Tooltip>
                    );
                }
            },
        },
        {
            title: '发现时间',
            dataIndex: 'CreatedAt',
            key: 'created_at',
            width: 170,
            render: (v: string) => {
                if (!v) return '-';
                return <Text style={{ fontSize: 12, color: '#64748b' }}>{dayjs(v).format('YYYY-MM-DD HH:mm:ss')}</Text>;
            },
        },
    ];

    const cardStyle = {
        background: 'transparent',
        border: 'none'
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
                    {Object.entries(severityStats).map(([severity, count]) => {
                        const normalized = severity ? severity.charAt(0).toUpperCase() + severity.slice(1).toLowerCase() : 'Unknown';
                        return (
                            <Tag key={severity} color={getSeverityColor(normalized)}>
                                {normalized}: {count}
                            </Tag>
                        );
                    })}
                    <Tag color="blue"><GlobalOutlined /> 资产 {assets.length}</Tag>
                    <Tag color="cyan"><ScanOutlined /> 指纹 {fingerprints.length}</Tag>
                    <Button icon={<ReloadOutlined />} onClick={fetchData} loading={loading}>刷新</Button>
                    <Button icon={<DownloadOutlined />} onClick={handleExport}>导出 CSV</Button>
                </Space>
            </div>

            <ProCard className="glass-card" style={cardStyle}>
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
                                        bordered
                                        columns={vulnColumns}
                                        dataSource={vulns}
                                        rowKey="ID"
                                        pagination={{ pageSize: 20, showTotal: (t) => `共 ${t} 条` }}
                                        size="middle"
                                        onRow={(record) => ({
                                            onClick: () => handleVulnClick(record),
                                            style: { cursor: 'pointer' },
                                        })}
                                        rowClassName={(_, index) => index % 2 === 1 ? 'table-row-light' : 'table-row-dark'}
                                    />
                                ),
                            },
                            {
                                key: 'assets',
                                label: <span><GlobalOutlined /> 资产 ({assets.length})</span>,
                                children: (
                                    <Table
                                        bordered
                                        columns={assetColumns}
                                        dataSource={assets}
                                        rowKey="ID"
                                        pagination={{ pageSize: 20, showTotal: (t) => `共 ${t} 条` }}
                                        size="middle"
                                        rowClassName={(_, index) => index % 2 === 1 ? 'table-row-light' : 'table-row-dark'}
                                    />
                                ),
                            },
                            {
                                key: 'fingerprints',
                                label: <span><ScanOutlined /> 指纹 ({fingerprints.length})</span>,
                                children: (
                                    <Table
                                        bordered
                                        columns={fpColumns}
                                        dataSource={fingerprints}
                                        rowKey="ID"
                                        pagination={{ pageSize: 20, showTotal: (t) => `共 ${t} 条` }}
                                        size="middle"
                                        rowClassName={(_, index) => index % 2 === 1 ? 'table-row-light' : 'table-row-dark'}
                                    />
                                ),
                            },
                        ]}
                    />
                )}
            </ProCard>

            {/* 漏洞详情 Drawer */}
            <Drawer
                title={
                    <Space>
                        <BugOutlined style={{ color: getSeverityColor(selectedVuln?.Severity || '') }} />
                        <span>漏洞详情</span>
                        {selectedVuln && <Tag color={getSeverityColor(selectedVuln.Severity)}>{selectedVuln.Severity}</Tag>}
                    </Space>
                }
                open={drawerOpen}
                onClose={() => setDrawerOpen(false)}
                width={860}
                destroyOnClose
            >
                {selectedVuln && (
                    <div>
                        <Descriptions column={2} bordered size="small">
                            <Descriptions.Item label="插件 / 模板" span={2}>
                                <Text strong copyable>{selectedVuln.Plugin}</Text>
                            </Descriptions.Item>
                            <Descriptions.Item label="目标">
                                <Text copyable style={{ fontFamily: 'monospace' }}>{selectedVuln.Target}</Text>
                            </Descriptions.Item>
                            <Descriptions.Item label="危害等级">
                                <Tag color={getSeverityColor(selectedVuln.Severity ? selectedVuln.Severity.charAt(0).toUpperCase() + selectedVuln.Severity.slice(1).toLowerCase() : 'Unknown')}>
                                    {selectedVuln.Severity ? selectedVuln.Severity.charAt(0).toUpperCase() + selectedVuln.Severity.slice(1).toLowerCase() : 'Unknown'}
                                </Tag>
                            </Descriptions.Item>
                            {selectedVuln.MatchedAt && (
                                <Descriptions.Item label="匹配位置" span={2}>
                                    <a href={selectedVuln.MatchedAt} target="_blank" rel="noopener noreferrer">
                                        <LinkOutlined /> {selectedVuln.MatchedAt}
                                    </a>
                                </Descriptions.Item>
                            )}
                            <Descriptions.Item label="发现时间" span={2}>
                                {selectedVuln.CreatedAt ? dayjs(selectedVuln.CreatedAt).format('YYYY-MM-DD HH:mm:ss') : '-'}
                            </Descriptions.Item>
                        </Descriptions>

                        {selectedVuln.Description && (
                            <>
                                <Divider orientation="left" style={{ fontSize: 13 }}>漏洞描述</Divider>
                                <div style={{
                                    background: '#f8fafc', border: '1px solid #e2e8f0',
                                    borderRadius: 8, padding: '12px 16px', whiteSpace: 'pre-wrap',
                                    fontSize: 13, lineHeight: 1.6, color: '#334155',
                                }}>
                                    {selectedVuln.Description}
                                </div>
                            </>
                        )}

                        {parseReferences(selectedVuln.Reference).length > 0 && (
                            <>
                                <Divider orientation="left" style={{ fontSize: 13 }}>参考链接</Divider>
                                <ul style={{ paddingLeft: 20 }}>
                                    {parseReferences(selectedVuln.Reference).map((ref, i) => (
                                        <li key={i} style={{ marginBottom: 4 }}>
                                            <a href={ref} target="_blank" rel="noopener noreferrer" style={{ fontSize: 13 }}>
                                                {ref}
                                            </a>
                                        </li>
                                    ))}
                                </ul>
                            </>
                        )}

                        {(selectedVuln.Request || selectedVuln.Response) && (
                            <>
                                <Divider orientation="left" style={{ fontSize: 13 }}>
                                    <SendOutlined /> 请求 / <CloudDownloadOutlined /> 响应
                                </Divider>
                                <div style={{ display: 'flex', gap: 12 }}>
                                    {/* 请求包 */}
                                    <div style={{ flex: 1, minWidth: 0 }}>
                                        <div style={{
                                            background: '#0f172a', color: '#4ade80',
                                            borderRadius: '8px 8px 0 0', padding: '8px 12px',
                                            fontSize: 12, fontWeight: 600, display: 'flex',
                                            alignItems: 'center', gap: 6,
                                        }}>
                                            <SendOutlined /> Request
                                        </div>
                                        <pre style={{
                                            background: '#1e293b', color: '#e2e8f0',
                                            margin: 0, padding: 12, borderRadius: '0 0 8px 8px',
                                            fontSize: 12, lineHeight: 1.5, fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
                                            whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                                            maxHeight: 400, overflow: 'auto',
                                            border: '1px solid #334155', borderTop: 'none',
                                        }}>
                                            {selectedVuln.Request || '(无请求数据)'}
                                        </pre>
                                    </div>
                                    {/* 响应包 */}
                                    <div style={{ flex: 1, minWidth: 0 }}>
                                        <div style={{
                                            background: '#0f172a', color: '#fb923c',
                                            borderRadius: '8px 8px 0 0', padding: '8px 12px',
                                            fontSize: 12, fontWeight: 600, display: 'flex',
                                            alignItems: 'center', gap: 6,
                                        }}>
                                            <CloudDownloadOutlined /> Response
                                        </div>
                                        <pre style={{
                                            background: '#1e293b', color: '#e2e8f0',
                                            margin: 0, padding: 12, borderRadius: '0 0 8px 8px',
                                            fontSize: 12, lineHeight: 1.5, fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
                                            whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                                            maxHeight: 400, overflow: 'auto',
                                            border: '1px solid #334155', borderTop: 'none',
                                        }}>
                                            {selectedVuln.Response || '(无响应数据)'}
                                        </pre>
                                    </div>
                                </div>
                            </>
                        )}

                        {selectedVuln.Payload && (
                            <>
                                <Divider orientation="left" style={{ fontSize: 13 }}>原始 Payload</Divider>
                                <pre style={{
                                    background: '#f1f5f9', border: '1px solid #e2e8f0',
                                    borderRadius: 8, padding: 12, fontSize: 11, maxHeight: 200,
                                    overflow: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                                }}>
                                    {(() => {
                                        try { return JSON.stringify(JSON.parse(selectedVuln.Payload), null, 2); }
                                        catch { return selectedVuln.Payload; }
                                    })()}
                                </pre>
                            </>
                        )}
                    </div>
                )}
            </Drawer>
        </div>
    );
};

export default TaskResults;
