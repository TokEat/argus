import React, { useCallback, useEffect, useMemo, useState } from 'react';
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
import { getVulns, getAssets, getFingerprintGroups, exportVulns, exportAssets, exportFingerprints } from '../services/api';
import { useAutoContext } from '../contexts/GlobalAIContext';
import { DEFAULT_RESULT_PAGE_SIZE, firstNonEmptyResultTab, initialResultPageState, type ResultPageState, type ResultTabKey } from './taskResultTabs';
import dayjs from 'dayjs';

const { Title, Text } = Typography;

const TaskResults: React.FC = () => {
    const { taskId } = useParams<{ taskId: string }>();
    const [loading, setLoading] = useState(true);
    const [tabLoading, setTabLoading] = useState<Record<ResultTabKey, boolean>>({
        vulns: false,
        assets: false,
        fingerprints: false,
    });
    const [vulns, setVulns] = useState<API.Vulnerability[]>([]);
    const [assets, setAssets] = useState<API.Asset[]>([]);
    const [fingerprints, setFingerprints] = useState<API.FingerprintGroup[]>([]);
    const [vulnPagination, setVulnPagination] = useState<ResultPageState>(initialResultPageState);
    const [assetPagination, setAssetPagination] = useState<ResultPageState>(initialResultPageState);
    const [fingerprintPagination, setFingerprintPagination] = useState<ResultPageState>(initialResultPageState);
    const [activeTab, setActiveTab] = useState<ResultTabKey>('vulns');
    const [selectedVuln, setSelectedVuln] = useState<API.Vulnerability | null>(null);
    const [drawerOpen, setDrawerOpen] = useState(false);
    const navigate = useNavigate();

    const setTabBusy = useCallback((key: ResultTabKey, value: boolean) => {
        setTabLoading((cur) => ({ ...cur, [key]: value }));
    }, []);

    const fetchVulnsPage = useCallback(async (page: number, pageSize: number) => {
        setTabBusy('vulns', true);
        try {
            const projectId = localStorage.getItem('active_project_id') || undefined;
            const res = await getVulns({ taskId, projectId, page, pageSize });
            setVulns(res.items || []);
            setVulnPagination({
                current: res.page || page,
                pageSize: res.page_size || pageSize,
                total: res.total || 0,
            });
            return res.total || 0;
        } catch (error) {
            console.error('Failed to fetch vulnerabilities:', error);
            setVulns([]);
            return 0;
        } finally {
            setTabBusy('vulns', false);
        }
    }, [setTabBusy, taskId]);

    const fetchAssetsPage = useCallback(async (page: number, pageSize: number) => {
        setTabBusy('assets', true);
        try {
            const projectId = localStorage.getItem('active_project_id') || undefined;
            const res = await getAssets({ taskId, projectId, page, pageSize });
            setAssets(res.items || []);
            setAssetPagination({
                current: res.page || page,
                pageSize: res.page_size || pageSize,
                total: res.total || 0,
            });
            return res.total || 0;
        } catch (error) {
            console.error('Failed to fetch assets:', error);
            setAssets([]);
            return 0;
        } finally {
            setTabBusy('assets', false);
        }
    }, [setTabBusy, taskId]);

    const fetchFingerprintsPage = useCallback(async (page: number, pageSize: number) => {
        setTabBusy('fingerprints', true);
        try {
            const projectId = localStorage.getItem('active_project_id') || undefined;
            const res = await getFingerprintGroups({ taskId, projectId, page, pageSize });
            setFingerprints(res.items || []);
            setFingerprintPagination({
                current: res.page || page,
                pageSize: res.page_size || pageSize,
                total: res.total || 0,
            });
            return res.total || 0;
        } catch (error) {
            console.error('Failed to fetch fingerprints:', error);
            setFingerprints([]);
            return 0;
        } finally {
            setTabBusy('fingerprints', false);
        }
    }, [setTabBusy, taskId]);

    const fetchFirstPages = useCallback(async () => {
        setLoading(true);
        try {
            const [vulnerabilityTotal, assetTotal, fingerprintTotal] = await Promise.all([
                fetchVulnsPage(1, DEFAULT_RESULT_PAGE_SIZE),
                fetchAssetsPage(1, DEFAULT_RESULT_PAGE_SIZE),
                fetchFingerprintsPage(1, DEFAULT_RESULT_PAGE_SIZE),
            ]);
            setActiveTab(firstNonEmptyResultTab(vulnerabilityTotal, assetTotal, fingerprintTotal));
        } finally {
            setLoading(false);
        }
    }, [fetchAssetsPage, fetchFingerprintsPage, fetchVulnsPage]);

    const fetchCurrentPages = useCallback(async () => {
        setLoading(true);
        try {
            await Promise.all([
                fetchVulnsPage(vulnPagination.current, vulnPagination.pageSize),
                fetchAssetsPage(assetPagination.current, assetPagination.pageSize),
                fetchFingerprintsPage(fingerprintPagination.current, fingerprintPagination.pageSize),
            ]);
        } finally {
            setLoading(false);
        }
    }, [
        assetPagination,
        fetchAssetsPage,
        fetchFingerprintsPage,
        fetchVulnsPage,
        fingerprintPagination,
        vulnPagination,
    ]);

    useEffect(() => {
        fetchFirstPages();
    }, [fetchFirstPages]);

    useAutoContext({
        task_id: taskId,
        active_tab: activeTab,
        stats: {
            vulns: vulnPagination.total,
            assets: assetPagination.total,
            fingerprints: fingerprintPagination.total,
        },
        vulns_summary: vulns.slice(0, 10).map(v => ({
            id: v.ID,
            target: v.Target,
            severity: v.Severity,
            plugin: v.Plugin,
        })),
        assets_summary: assets.slice(0, 10).map(a => ({
            id: a.ID,
            target: a.Target,
            protocol: a.Protocol,
            port: a.Port,
            title: a.Title,
            service: a.Service,
        })),
        fingerprints_summary: fingerprints.slice(0, 10).map(f => ({
            product_name: f.ProductName,
            target_count: f.TargetCount,
            targets: f.Targets?.slice(0, 5).map(target => target.Target) || [],
        })),
        viewing_vuln: drawerOpen ? selectedVuln : null,
    });

    const handleExport = async () => {
        try {
            const projectId = localStorage.getItem('active_project_id') || undefined;
            let blob: Blob;
            let filename: string;
            if (activeTab === 'assets') {
                blob = await exportAssets(projectId, taskId);
                filename = `assets-${taskId || 'all'}.csv`;
            } else if (activeTab === 'fingerprints') {
                blob = await exportFingerprints(projectId, taskId);
                filename = `fingerprints-${taskId || 'all'}.csv`;
            } else {
                blob = await exportVulns(projectId, taskId);
                filename = `vulns-${taskId || 'all'}.csv`;
            }
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
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

    const normalizeSeverity = (severity?: string) => {
        if (!severity) return 'Unknown';
        const normalized = severity.charAt(0).toUpperCase() + severity.slice(1).toLowerCase();
        return ['Critical', 'High', 'Medium', 'Low', 'Info'].includes(normalized) ? normalized : 'Unknown';
    };

    const getSeverityColor = (severity: string) => {
        const normalized = normalizeSeverity(severity);
        const map: Record<string, string> = {
            Critical: '#ef4444', High: '#f97316', Medium: '#f59e0b',
            Low: '#3b82f6', Info: '#14b8a6', Unknown: '#94a3b8',
        };
        return map[normalized] || '#94a3b8';
    };

    const getSeverityWeight = (severity: string) => {
        const normalized = normalizeSeverity(severity);
        const map: Record<string, number> = {
            Critical: 5, High: 4, Medium: 3, Low: 2, Info: 1, Unknown: 0,
        };
        return map[normalized] || 0;
    };

    // ── Target helpers ──
    const extractHostFromTarget = (target: string): string => {
        if (!target) return '-';
        try {
            if (target.includes('://')) {
                const u = new URL(target);
                return u.hostname;
            }
        } catch { /* ignore */ }
        const parts = target.split(':');
        return parts[0] || target;
    };

    const extractPortFromTarget = (target: string, port: number): number => {
        if (port > 0) return port;
        if (!target) return 0;
        try {
            if (target.includes('://')) {
                const u = new URL(target);
                if (u.port) return parseInt(u.port);
                if (u.protocol === 'https:') return 443;
                if (u.protocol === 'http:') return 80;
            }
        } catch { /* ignore */ }
        const parts = target.split(':');
        if (parts.length >= 2) {
            const p = parseInt(parts[parts.length - 1]);
            if (!isNaN(p) && p > 0 && p <= 65535) return p;
        }
        return 0;
    };

    // ── 域名 ↔ 解析 IP 关联（来源：RealIP 资产行 Tags 中的 domain/ips）──
    const { ipToDomains, domainToIPs } = useMemo(() => {
        const ipMap = new Map<string, string[]>();
        const domainMap = new Map<string, string[]>();
        assets.forEach((asset) => {
            if (asset.Protocol !== 'RealIP' || !asset.Tags) return;
            try {
                const payload = JSON.parse(asset.Tags) as { domain?: unknown; ips?: unknown };
                const domain = typeof payload.domain === 'string' ? payload.domain : '';
                const ips = Array.isArray(payload.ips)
                    ? payload.ips.filter((item): item is string => typeof item === 'string')
                    : [];
                if (!domain || ips.length === 0) return;
                ips.forEach((ip) => {
                    const domains = ipMap.get(ip) || [];
                    if (!domains.includes(domain)) domains.push(domain);
                    ipMap.set(ip, domains);
                    const resolved = domainMap.get(domain) || [];
                    if (!resolved.includes(ip)) resolved.push(ip);
                    domainMap.set(domain, resolved);
                });
            } catch { /* ignore malformed tags */ }
        });
        return { ipToDomains: ipMap, domainToIPs: domainMap };
    }, [assets]);

    const ipv4Pattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
    const relatedHostsFor = (host: string): string[] => {
        if (ipv4Pattern.test(host)) return ipToDomains.get(host) || [];
        return domainToIPs.get(host) || [];
    };


    const isJsonString = (s: string): boolean => {
        if (!s) return false;
        return (s.startsWith('{') && s.endsWith('}')) || (s.startsWith('[') && s.endsWith(']'));
    };

    const protocolColors: Record<string, string> = {
        'Web': 'green', 'Nmap': 'purple', 'PortScan': 'blue',
        'Protocol': 'geekblue', 'Domain': 'cyan', 'Domain-Bind': 'cyan',
        'IPAlive': 'default',
    };

    const vulnColumns: ColumnsType<API.Vulnerability> = [
        {
            title: '主机',
            key: 'host',
            width: 160,
            render: (_, record) => {
                const host = extractHostFromTarget(record.Target);
                return (
                    <Text copyable={{ text: host }} style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, fontWeight: 500 }}>
                        {host}
                    </Text>
                );
            },
            filters: (() => {
                const hosts = [...new Set(vulns.map(v => extractHostFromTarget(v.Target)))];
                return hosts.slice(0, 20).map(h => ({ text: h, value: h }));
            })(),
            onFilter: (value, record) => extractHostFromTarget(record.Target) === value,
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
                const normalized = normalizeSeverity(v);
                return <Tag color={getSeverityColor(normalized)}>{normalized}</Tag>;
            },
            filters: ['Critical', 'High', 'Medium', 'Low', 'Info', 'Unknown'].map(s => ({ text: s, value: s })),
            onFilter: (value, record) => {
                return normalizeSeverity(record.Severity) === value;
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
            title: '主机',
            key: 'host',
            width: 220,
            render: (_, record) => {
                const host = extractHostFromTarget(record.Target);
                const related = relatedHostsFor(host).filter((item) => item !== host);
                const shown = related.slice(0, 2);
                return (
                    <Space size={4} wrap>
                        <Text copyable={{ text: host }} style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, fontWeight: 500 }}>
                            {host}
                        </Text>
                        {record.CDN && <Tag color="orange" style={{ margin: 0, fontSize: 10 }}>CDN</Tag>}
                        {shown.length > 0 && (
                            <Tooltip title={`关联 ${related.length === 1 ? '主机' : '主机'}：${related.join('、')}`}>
                                <span style={{ display: 'inline-flex', gap: 2 }}>
                                    <Text type="secondary" style={{ fontSize: 10 }}>↔</Text>
                                    {shown.map((item) => (
                                        <Tag key={item} color="default" style={{ margin: 0, fontSize: 10, fontFamily: "'JetBrains Mono', monospace" }}>
                                            {item}
                                        </Tag>
                                    ))}
                                    {related.length > shown.length && (
                                        <Tag style={{ margin: 0, fontSize: 10 }}>+{related.length - shown.length}</Tag>
                                    )}
                                </span>
                            </Tooltip>
                        )}
                    </Space>
                );
            },
            filters: (() => {
                const hosts = [...new Set(assets.map(a => extractHostFromTarget(a.Target)))];
                return hosts.slice(0, 20).map(h => ({ text: h, value: h }));
            })(),
            onFilter: (value, record) => extractHostFromTarget(record.Target) === value,
        },
        {
            title: 'CDN',
            key: 'cdn',
            width: 70,
            render: (_, record) => record.CDN
                ? <Tag color="orange" style={{ margin: 0 }}>疑似 CDN</Tag>
                : <Text type="secondary">-</Text>,
            filters: [{ text: '疑似 CDN', value: true }],
            onFilter: (value, record) => Boolean(record.CDN) === value,
        },
        {
            title: '端口',
            key: 'port',
            width: 90,
            render: (_, record) => {
                const port = extractPortFromTarget(record.Target, record.Port);
                return port > 0
                    ? <Tag color="blue" style={{ margin: 0, fontFamily: 'monospace', fontWeight: 600 }}>{port}</Tag>
                    : <Text type="secondary">-</Text>;
            },
            sorter: (a, b) => extractPortFromTarget(a.Target, a.Port) - extractPortFromTarget(b.Target, b.Port),
        },
        {
            title: '来源',
            dataIndex: 'Protocol',
            key: 'protocol',
            width: 100,
            render: (v: string) => <Tag color={protocolColors[v] || 'default'} style={{ margin: 0, fontSize: 11 }}>{v}</Tag>,
            filters: [...new Set(assets.map(a => a.Protocol))].map(p => ({ text: p, value: p })),
            onFilter: (value, record) => record.Protocol === value,
        },
        {
            title: '服务',
            dataIndex: 'Service',
            key: 'service',
            width: 120,
            render: (v: string) => v ? <Tag color="geekblue" style={{ margin: 0 }}>{v}</Tag> : <Text type="secondary">-</Text>,
        },
        {
            title: '标题',
            dataIndex: 'Title',
            key: 'title',
            ellipsis: { showTitle: false },
            render: (v: string) => v
                ? <Tooltip title={v}><Text style={{ fontSize: 12 }}>{v}</Text></Tooltip>
                : <Text type="secondary">-</Text>,
        },
        {
            title: 'URL',
            key: 'url',
            width: 180,
            ellipsis: true,
            render: (_, record) => {
                const url = record.URL;
                if (!url) return <Text type="secondary">-</Text>;
                // 如果是真实 URL（非 JSON）
                if (url.startsWith('http://') || url.startsWith('https://')) {
                    return (
                        <Tooltip title={url}>
                            <a href={url} target="_blank" rel="noopener noreferrer" style={{ fontSize: 12, fontFamily: 'monospace' }}>
                                <LinkOutlined style={{ marginRight: 4 }} />{url.replace(/^https?:\/\//, '').slice(0, 40)}
                            </a>
                        </Tooltip>
                    );
                }
                // JSON evidence — show as popover
                if (isJsonString(url)) {
                    let preview = '';
                    try {
                        const parsed = JSON.parse(url);
                        preview = parsed.ip || parsed.type || 'evidence';
                    } catch {
                        preview = 'data';
                    }
                    return (
                        <Popover
                            content={<pre style={{ maxWidth: 500, maxHeight: 300, overflow: 'auto', fontSize: 11, margin: 0 }}>{JSON.stringify(JSON.parse(url), null, 2)}</pre>}
                            title="原始数据"
                            trigger="hover"
                        >
                            <Tag color="default" style={{ cursor: 'pointer', fontSize: 10, margin: 0 }}>📋 {preview}</Tag>
                        </Popover>
                    );
                }
                return <Text style={{ fontSize: 12, color: '#64748b' }} ellipsis={{ tooltip: url }}>{url}</Text>;
            },
        },
        {
            title: '发现时间',
            dataIndex: 'CreatedAt',
            key: 'created_at',
            width: 160,
            sorter: (a, b) => new Date(a.CreatedAt).getTime() - new Date(b.CreatedAt).getTime(),
            render: (v: string) => {
                if (!v) return '-';
                return <Text style={{ fontSize: 12, color: '#64748b' }}>{dayjs(v).format('YYYY-MM-DD HH:mm:ss')}</Text>;
            },
        },
    ];

    const fpColumns: ColumnsType<API.FingerprintGroup> = [
        {
            title: '产品名称',
            dataIndex: 'ProductName',
            key: 'product_name',
            width: 220,
            render: (v: string) => <Tag color="cyan">{v}</Tag>,
        },
        {
            title: 'URL 数',
            dataIndex: 'TargetCount',
            key: 'target_count',
            width: 100,
            sorter: (a, b) => (a.TargetCount || 0) - (b.TargetCount || 0),
            render: (v: number) => <Tag color="blue">{v || 0}</Tag>,
        },
        {
            title: '匹配 URL',
            key: 'targets',
            render: (_, record) => {
                const targets = record.Targets || [];
                if (targets.length === 0) return <Text type="secondary">-</Text>;
                return (
                    <div style={{ maxHeight: 180, overflow: 'auto', display: 'grid', gap: 6 }}>
                        {targets.map((target, index) => (
                            <Space key={`${target.Target}-${index}`} size={6} wrap={false}>
                                <Text
                                    copyable={{ text: target.Target }}
                                    style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12 }}
                                >
                                    {target.Target}
                                </Text>
                                {target.RuleName && <Tag color="default">{target.RuleName}</Tag>}
                            </Space>
                        ))}
                    </div>
                );
            },
        },
        {
            title: '最近发现',
            dataIndex: 'LastSeen',
            key: 'last_seen',
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
        const severity = normalizeSeverity(v.Severity);
        acc[severity] = (acc[severity] || 0) + 1;
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
                        return (
                            <Tag key={severity} color={getSeverityColor(severity)}>
                                当前页 {severity}: {count}
                            </Tag>
                        );
                    })}
                    <Tag color="blue"><GlobalOutlined /> 资产 {assetPagination.total}</Tag>
                    <Tag color="cyan"><ScanOutlined /> 指纹 {fingerprintPagination.total}</Tag>
                    <Button icon={<ReloadOutlined />} onClick={fetchCurrentPages} loading={loading}>刷新</Button>
                    <Button icon={<DownloadOutlined />} onClick={handleExport}>导出 CSV</Button>
                </Space>
            </div>

            <ProCard className="glass-card" style={cardStyle}>
                {loading ? (
                    <div style={{ display: 'flex', justifyContent: 'center', padding: '60px 0' }}>
                        <Spin size="large" />
                    </div>
                ) : vulnPagination.total === 0 && assetPagination.total === 0 && fingerprintPagination.total === 0 ? (
                    <Empty description="暂无扫描结果" style={{ padding: '60px 0' }} />
                ) : (
                    <Tabs
                        activeKey={activeTab}
                        onChange={(key) => setActiveTab(key as ResultTabKey)}
                        items={[
                            {
                                key: 'vulns',
                                label: <span><BugOutlined /> 漏洞 ({vulnPagination.total})</span>,
                                children: (
                                    <Table
                                        bordered
                                        columns={vulnColumns}
                                        dataSource={vulns}
                                        rowKey="ID"
                                        loading={tabLoading.vulns}
                                        pagination={{
                                            current: vulnPagination.current,
                                            pageSize: vulnPagination.pageSize,
                                            total: vulnPagination.total,
                                            showSizeChanger: true,
                                            pageSizeOptions: ['10', '20', '50', '100', '200'],
                                            showTotal: (t) => `共 ${t} 条`,
                                            onChange: (page, pageSize) => fetchVulnsPage(page, pageSize),
                                        }}
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
                                label: <span><GlobalOutlined /> 资产 ({assetPagination.total})</span>,
                                children: (
                                    <Table
                                        bordered
                                        columns={assetColumns}
                                        dataSource={assets}
                                        rowKey="ID"
                                        loading={tabLoading.assets}
                                        pagination={{
                                            current: assetPagination.current,
                                            pageSize: assetPagination.pageSize,
                                            total: assetPagination.total,
                                            showSizeChanger: true,
                                            pageSizeOptions: ['10', '20', '50', '100', '200'],
                                            showTotal: (t) => `共 ${t} 条`,
                                            onChange: (page, pageSize) => fetchAssetsPage(page, pageSize),
                                        }}
                                        size="middle"
                                        rowClassName={(_, index) => index % 2 === 1 ? 'table-row-light' : 'table-row-dark'}
                                    />
                                ),
                            },
                            {
                                key: 'fingerprints',
                                label: <span><ScanOutlined /> 指纹 ({fingerprintPagination.total})</span>,
                                children: (
                                    <Table
                                        bordered
                                        columns={fpColumns}
                                        dataSource={fingerprints}
                                        rowKey="ProductName"
                                        loading={tabLoading.fingerprints}
                                        pagination={{
                                            current: fingerprintPagination.current,
                                            pageSize: fingerprintPagination.pageSize,
                                            total: fingerprintPagination.total,
                                            showSizeChanger: true,
                                            pageSizeOptions: ['10', '20', '50', '100', '200'],
                                            showTotal: (t) => `共 ${t} 条`,
                                            onChange: (page, pageSize) => fetchFingerprintsPage(page, pageSize),
                                        }}
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
                        {selectedVuln && <Tag color={getSeverityColor(selectedVuln.Severity)}>{normalizeSeverity(selectedVuln.Severity)}</Tag>}
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
                                <Tag color={getSeverityColor(selectedVuln.Severity)}>
                                    {normalizeSeverity(selectedVuln.Severity)}
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
