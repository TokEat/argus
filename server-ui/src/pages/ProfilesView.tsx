import React, { useEffect, useState, useMemo, useRef, useCallback } from 'react';
import { Typography, Tag, Space, Spin, Input, Empty, Tooltip, Pagination, Popover, Badge } from 'antd';
import { ProCard } from '@ant-design/pro-components';
import gsap from 'gsap';
import {
    ProfileOutlined,
    SearchOutlined,
    BugOutlined,
    GlobalOutlined,
    ScanOutlined,
    CloudServerOutlined,
    LinkOutlined,
    ApiOutlined,
    SafetyCertificateOutlined,
    ExclamationCircleOutlined,
    DesktopOutlined,
    RightOutlined,
    DownOutlined,
} from '@ant-design/icons';
import { getProfiles } from '../services/api';
import dayjs from 'dayjs';
import NetworkCanvas from '../components/NetworkCanvas';

const { Title, Text } = Typography;

const SEVERITY_COLOR: Record<string, string> = {
    Critical: '#ef4444', High: '#f97316', Medium: '#f59e0b',
    Low: '#3b82f6', Info: '#14b8a6', Unknown: '#94a3b8',
};

const SEVERITY_ORDER: Record<string, number> = {
    Critical: 5, High: 4, Medium: 3, Low: 2, Info: 1, Unknown: 0,
};

const normSeverity = (s: string) => s ? s.charAt(0).toUpperCase() + s.slice(1).toLowerCase() : 'Unknown';

// ─── Host Card Component ───────────────────────────────────

const HostCard: React.FC<{ profile: API.Profile }> = ({ profile }) => {
    const [expanded, setExpanded] = useState<string | null>(null);
    const ports = profile.ports || [];
    const fps = profile.fingerprints || [];
    const vulns = profile.vulns || [];

    // Severity summary
    const sevSummary = useMemo(() => {
        const map: Record<string, number> = {};
        vulns.forEach(v => {
            const key = normSeverity(v.Severity);
            map[key] = (map[key] || 0) + 1;
        });
        return Object.entries(map).sort((a, b) => (SEVERITY_ORDER[b[0]] || 0) - (SEVERITY_ORDER[a[0]] || 0));
    }, [vulns]);

    // Unique fingerprint products
    const products = useMemo(() => [...new Set(fps.map(f => f.ProductName))], [fps]);

    const toggle = (key: string) => setExpanded(prev => prev === key ? null : key);

    const hasVulns = vulns.length > 0;
    const maxSev = sevSummary.length > 0 ? sevSummary[0][0] : null;
    const borderColor = hasVulns ? (SEVERITY_COLOR[maxSev || 'Unknown'] || '#e2e8f0') : '#e2e8f0';

    return (
        <div style={{
            background: '#fff',
            borderRadius: 12,
            border: `1px solid ${hasVulns ? borderColor + '40' : '#e2e8f0'}`,
            borderLeft: `3px solid ${borderColor}`,
            boxShadow: '0 1px 3px rgba(0,0,0,0.04), 0 1px 2px rgba(0,0,0,0.03)',
            transition: 'all 0.2s ease',
            overflow: 'hidden',
        }}
            onMouseEnter={e => {
                e.currentTarget.style.boxShadow = '0 4px 12px rgba(0,0,0,0.08), 0 2px 4px rgba(0,0,0,0.04)';
                e.currentTarget.style.transform = 'translateY(-1px)';
            }}
            onMouseLeave={e => {
                e.currentTarget.style.boxShadow = '0 1px 3px rgba(0,0,0,0.04), 0 1px 2px rgba(0,0,0,0.03)';
                e.currentTarget.style.transform = 'translateY(0)';
            }}
        >
            {/* ── Header ── */}
            <div style={{ padding: '16px 20px', display: 'flex', alignItems: 'center', gap: 16, borderBottom: '1px solid #f1f5f9' }}>
                <div style={{
                    width: 42, height: 42, borderRadius: 10,
                    background: hasVulns
                        ? `linear-gradient(135deg, ${borderColor}18, ${borderColor}30)`
                        : 'linear-gradient(135deg, #f0f9ff, #e0f2fe)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    flexShrink: 0,
                }}>
                    <CloudServerOutlined style={{ fontSize: 20, color: hasVulns ? borderColor : '#0ea5e9' }} />
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                    <Text strong copyable style={{ fontSize: 15, fontFamily: "'JetBrains Mono', monospace", letterSpacing: -0.3 }}>
                        {profile.host}
                    </Text>
                    <div style={{ marginTop: 2, display: 'flex', flexWrap: 'wrap', gap: 6, alignItems: 'center' }}>
                        <Tag style={{ margin: 0, fontSize: 11, borderRadius: 4, background: '#f0f9ff', border: '1px solid #bae6fd', color: '#0369a1' }}>
                            <ApiOutlined style={{ marginRight: 3 }} />{ports.length} 端口
                        </Tag>
                        {fps.length > 0 && (
                            <Tag style={{ margin: 0, fontSize: 11, borderRadius: 4, background: '#fffbeb', border: '1px solid #fde68a', color: '#92400e' }}>
                                <ScanOutlined style={{ marginRight: 3 }} />{products.length} 指纹
                            </Tag>
                        )}
                        {vulns.length > 0 && (
                            <Tag style={{ margin: 0, fontSize: 11, borderRadius: 4, background: '#fef2f2', border: '1px solid #fecaca', color: '#991b1b' }}>
                                <BugOutlined style={{ marginRight: 3 }} />{vulns.length} 漏洞
                            </Tag>
                        )}
                    </div>
                </div>

                {/* Severity Pills */}
                <div style={{ display: 'flex', gap: 4, flexShrink: 0, flexWrap: 'wrap', justifyContent: 'flex-end', maxWidth: 220 }}>
                    {sevSummary.map(([sev, cnt]) => (
                        <Tag key={sev} color={SEVERITY_COLOR[sev]} style={{ margin: 0, fontSize: 11, borderRadius: 10, padding: '0 8px', fontWeight: 600 }}>
                            {sev} {cnt}
                        </Tag>
                    ))}
                </div>
            </div>

            {/* ── Ports Section ── */}
            {ports.length > 0 && (
                <div>
                    <div
                        onClick={() => toggle('ports')}
                        style={{
                            padding: '10px 20px', display: 'flex', alignItems: 'center', gap: 8,
                            cursor: 'pointer', background: expanded === 'ports' ? '#f8fafc' : 'transparent',
                            transition: 'background 0.15s',
                            userSelect: 'none',
                        }}
                        onMouseEnter={e => { if (expanded !== 'ports') e.currentTarget.style.background = '#fafbfc'; }}
                        onMouseLeave={e => { if (expanded !== 'ports') e.currentTarget.style.background = 'transparent'; }}
                    >
                        {expanded === 'ports' ? <DownOutlined style={{ fontSize: 10, color: '#94a3b8' }} /> : <RightOutlined style={{ fontSize: 10, color: '#94a3b8' }} />}
                        <DesktopOutlined style={{ color: '#0ea5e9' }} />
                        <Text style={{ fontSize: 13, fontWeight: 500, color: '#334155' }}>端口与服务</Text>
                        <Text style={{ fontSize: 12, color: '#94a3b8' }}>({ports.length})</Text>
                        {expanded !== 'ports' && (
                            <div style={{ flex: 1, display: 'flex', gap: 4, flexWrap: 'wrap', marginLeft: 8, overflow: 'hidden', maxHeight: 22 }}>
                                {ports.slice(0, 12).map(p => (
                                    <Tag key={`${p.port}:${p.protocol}`} style={{ margin: 0, fontSize: 10, padding: '0 4px', lineHeight: '18px', borderRadius: 3, background: '#f1f5f9', border: '1px solid #e2e8f0', color: '#475569' }}>
                                        {p.port}
                                    </Tag>
                                ))}
                                {ports.length > 12 && <Text style={{ fontSize: 10, color: '#94a3b8' }}>+{ports.length - 12}</Text>}
                            </div>
                        )}
                    </div>
                    {expanded === 'ports' && (
                        <div style={{ padding: '0 20px 12px', display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 8 }}>
                            {ports.map(p => (
                                <div key={`${p.port}:${p.protocol}`} style={{
                                    padding: '8px 12px', borderRadius: 8,
                                    background: '#f8fafc', border: '1px solid #f1f5f9',
                                    display: 'flex', alignItems: 'center', gap: 10,
                                }}>
                                    <Tag color="blue" style={{ margin: 0, fontWeight: 600, fontFamily: 'monospace', minWidth: 52, textAlign: 'center' }}>
                                        {p.port}
                                    </Tag>
                                    <div style={{ flex: 1, minWidth: 0 }}>
                                        <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                                            <Tag style={{ margin: 0, fontSize: 10, padding: '0 4px', borderRadius: 3 }}>
                                                {p.protocol || 'tcp'}
                                            </Tag>
                                            {p.service && (
                                                <Tag color="geekblue" style={{ margin: 0, fontSize: 10, padding: '0 4px', borderRadius: 3 }}>
                                                    {p.service}
                                                </Tag>
                                            )}
                                        </div>
                                        {p.title && (
                                            <Text style={{ fontSize: 11, color: '#64748b', marginTop: 2, display: 'block' }} ellipsis={{ tooltip: p.title }}>
                                                {p.title}
                                            </Text>
                                        )}
                                    </div>
                                    {p.url && (
                                        <Tooltip title={p.url}>
                                            <a href={p.url} target="_blank" rel="noopener noreferrer" style={{ flexShrink: 0 }}>
                                                <LinkOutlined style={{ color: '#0ea5e9', fontSize: 13 }} />
                                            </a>
                                        </Tooltip>
                                    )}
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            )}

            {/* ── Fingerprints Section ── */}
            {fps.length > 0 && (
                <div style={{ borderTop: '1px solid #f1f5f9' }}>
                    <div
                        onClick={() => toggle('fps')}
                        style={{
                            padding: '10px 20px', display: 'flex', alignItems: 'center', gap: 8,
                            cursor: 'pointer', background: expanded === 'fps' ? '#f8fafc' : 'transparent',
                            transition: 'background 0.15s',
                            userSelect: 'none',
                        }}
                        onMouseEnter={e => { if (expanded !== 'fps') e.currentTarget.style.background = '#fafbfc'; }}
                        onMouseLeave={e => { if (expanded !== 'fps') e.currentTarget.style.background = 'transparent'; }}
                    >
                        {expanded === 'fps' ? <DownOutlined style={{ fontSize: 10, color: '#94a3b8' }} /> : <RightOutlined style={{ fontSize: 10, color: '#94a3b8' }} />}
                        <SafetyCertificateOutlined style={{ color: '#f59e0b' }} />
                        <Text style={{ fontSize: 13, fontWeight: 500, color: '#334155' }}>指纹识别</Text>
                        <Text style={{ fontSize: 12, color: '#94a3b8' }}>({products.length} 产品)</Text>
                        {expanded !== 'fps' && (
                            <div style={{ flex: 1, display: 'flex', gap: 4, flexWrap: 'wrap', marginLeft: 8, overflow: 'hidden', maxHeight: 22 }}>
                                {products.slice(0, 8).map(p => (
                                    <Tag key={p} color="gold" style={{ margin: 0, fontSize: 10, padding: '0 5px', lineHeight: '18px', borderRadius: 3 }}>
                                        {p}
                                    </Tag>
                                ))}
                                {products.length > 8 && <Text style={{ fontSize: 10, color: '#94a3b8' }}>+{products.length - 8}</Text>}
                            </div>
                        )}
                    </div>
                    {expanded === 'fps' && (
                        <div style={{ padding: '0 20px 12px' }}>
                            {products.map(prod => {
                                const hits = fps.filter(f => f.ProductName === prod);
                                return (
                                    <div key={prod} style={{ marginBottom: 8, padding: '8px 12px', borderRadius: 8, background: '#fffbeb', border: '1px solid #fef3c7' }}>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                                            <Tag color="gold" style={{ margin: 0, fontWeight: 600 }}>{prod}</Tag>
                                            <Text style={{ fontSize: 11, color: '#92400e' }}>{hits.length} 匹配</Text>
                                        </div>
                                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                                            {hits.map((h, i) => {
                                                let evidencePreview = '';
                                                try {
                                                    const ev = JSON.parse(h.Evidence);
                                                    evidencePreview = ev?.web?.title || ev?.web?.status || h.RuleName;
                                                } catch {
                                                    evidencePreview = h.RuleName;
                                                }
                                                return (
                                                    <Popover
                                                        key={i}
                                                        content={
                                                            <pre style={{ maxWidth: 400, maxHeight: 300, overflow: 'auto', fontSize: 11, margin: 0 }}>
                                                                {(() => { try { return JSON.stringify(JSON.parse(h.Evidence), null, 2); } catch { return h.Evidence; } })()}
                                                            </pre>
                                                        }
                                                        title={<span style={{ fontSize: 12 }}>{h.RuleName}</span>}
                                                        trigger="hover"
                                                    >
                                                        <Tag style={{ margin: 0, fontSize: 10, cursor: 'pointer', borderRadius: 3, background: '#fef9c3', border: '1px solid #fde68a', color: '#78350f' }}>
                                                            {evidencePreview}
                                                        </Tag>
                                                    </Popover>
                                                );
                                            })}
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    )}
                </div>
            )}

            {/* ── Vulnerabilities Section ── */}
            {vulns.length > 0 && (
                <div style={{ borderTop: '1px solid #f1f5f9' }}>
                    <div
                        onClick={() => toggle('vulns')}
                        style={{
                            padding: '10px 20px', display: 'flex', alignItems: 'center', gap: 8,
                            cursor: 'pointer', background: expanded === 'vulns' ? '#fef2f2' : 'transparent',
                            transition: 'background 0.15s',
                            userSelect: 'none',
                        }}
                        onMouseEnter={e => { if (expanded !== 'vulns') e.currentTarget.style.background = '#fff5f5'; }}
                        onMouseLeave={e => { if (expanded !== 'vulns') e.currentTarget.style.background = 'transparent'; }}
                    >
                        {expanded === 'vulns' ? <DownOutlined style={{ fontSize: 10, color: '#94a3b8' }} /> : <RightOutlined style={{ fontSize: 10, color: '#94a3b8' }} />}
                        <ExclamationCircleOutlined style={{ color: '#ef4444' }} />
                        <Text style={{ fontSize: 13, fontWeight: 500, color: '#334155' }}>漏洞</Text>
                        <Text style={{ fontSize: 12, color: '#94a3b8' }}>({vulns.length})</Text>
                        {expanded !== 'vulns' && (
                            <div style={{ flex: 1, display: 'flex', gap: 4, flexWrap: 'wrap', marginLeft: 8, overflow: 'hidden', maxHeight: 22 }}>
                                {vulns.slice(0, 5).map((v, i) => (
                                    <Tag key={i} color={SEVERITY_COLOR[normSeverity(v.Severity)]} style={{ margin: 0, fontSize: 10, lineHeight: '18px', borderRadius: 3 }}>
                                        {v.Plugin}
                                    </Tag>
                                ))}
                                {vulns.length > 5 && <Text style={{ fontSize: 10, color: '#94a3b8' }}>+{vulns.length - 5}</Text>}
                            </div>
                        )}
                    </div>
                    {expanded === 'vulns' && (
                        <div style={{ padding: '0 20px 12px' }}>
                            {[...vulns].sort((a, b) => (SEVERITY_ORDER[normSeverity(b.Severity)] || 0) - (SEVERITY_ORDER[normSeverity(a.Severity)] || 0)).map((v, i) => (
                                <Popover
                                    key={i}
                                    placement="left"
                                    trigger="hover"
                                    title={
                                        <Space>
                                            <Tag color={SEVERITY_COLOR[normSeverity(v.Severity)]} style={{ margin: 0 }}>{normSeverity(v.Severity)}</Tag>
                                            <Text strong style={{ fontSize: 13 }}>{v.Plugin}</Text>
                                        </Space>
                                    }
                                    content={
                                        <div style={{ maxWidth: 500, maxHeight: 400, overflow: 'auto' }}>
                                            {v.Description && <div style={{ marginBottom: 8, fontSize: 12, color: '#475569' }}>{v.Description}</div>}
                                            {v.MatchedAt && <div style={{ fontSize: 11, marginBottom: 4 }}><Text type="secondary">匹配:</Text> <a href={v.MatchedAt} target="_blank" rel="noopener">{v.MatchedAt}</a></div>}
                                            {v.Request && (
                                                <div style={{ marginTop: 8 }}>
                                                    <Text style={{ fontSize: 11, fontWeight: 600 }}>Request:</Text>
                                                    <pre style={{ background: '#1e293b', color: '#e2e8f0', padding: 8, borderRadius: 6, fontSize: 10, maxHeight: 150, overflow: 'auto', margin: '4px 0' }}>{v.Request}</pre>
                                                </div>
                                            )}
                                            {v.Response && (
                                                <div style={{ marginTop: 4 }}>
                                                    <Text style={{ fontSize: 11, fontWeight: 600 }}>Response:</Text>
                                                    <pre style={{ background: '#1e293b', color: '#e2e8f0', padding: 8, borderRadius: 6, fontSize: 10, maxHeight: 150, overflow: 'auto', margin: '4px 0' }}>{v.Response}</pre>
                                                </div>
                                            )}
                                        </div>
                                    }
                                >
                                    <div style={{
                                        padding: '8px 12px', marginBottom: 6, borderRadius: 8, cursor: 'pointer',
                                        background: '#fef2f2', border: '1px solid #fecaca',
                                        display: 'flex', alignItems: 'center', gap: 10,
                                        transition: 'all 0.15s',
                                    }}
                                        onMouseEnter={e => { e.currentTarget.style.background = '#fee2e2'; }}
                                        onMouseLeave={e => { e.currentTarget.style.background = '#fef2f2'; }}
                                    >
                                        <Tag color={SEVERITY_COLOR[normSeverity(v.Severity)]} style={{ margin: 0, fontSize: 10, minWidth: 56, textAlign: 'center', borderRadius: 4 }}>
                                            {normSeverity(v.Severity)}
                                        </Tag>
                                        <div style={{ flex: 1, minWidth: 0 }}>
                                            <Text strong style={{ fontSize: 12 }} ellipsis={{ tooltip: v.Plugin }}>{v.Plugin}</Text>
                                            {v.MatchedAt && (
                                                <div>
                                                    <Text style={{ fontSize: 10, color: '#64748b', fontFamily: 'monospace' }} ellipsis={{ tooltip: v.MatchedAt }}>
                                                        {v.MatchedAt}
                                                    </Text>
                                                </div>
                                            )}
                                        </div>
                                        <Text style={{ fontSize: 10, color: '#94a3b8', flexShrink: 0 }}>
                                            {v.CreatedAt ? dayjs(v.CreatedAt).format('MM-DD HH:mm') : ''}
                                        </Text>
                                        {(v.Request || v.Response) && (
                                            <Badge dot color="#10b981" style={{ marginLeft: 2 }} />
                                        )}
                                    </div>
                                </Popover>
                            ))}
                        </div>
                    )}
                </div>
            )}
        </div>
    );
};

// ─── Main ProfilesView ────────────────────────────────────

const ProfilesView: React.FC = () => {
    const [loading, setLoading] = useState(true);
    const [profiles, setProfiles] = useState<API.Profile[]>([]);
    const [total, setTotal] = useState(0);
    const [page, setPage] = useState(1);
    const [pageSize, setPageSize] = useState(20);
    const [searchKeyword, setSearchKeyword] = useState('');
    const cardsRef = useRef<HTMLDivElement>(null);

    const fetchData = useCallback(async () => {
        setLoading(true);
        try {
            const projectId = localStorage.getItem('active_project_id') || undefined;
            const result = await getProfiles(page, pageSize, searchKeyword, projectId);
            setProfiles(result.data || []);
            setTotal(result.total || 0);
        } catch (error) {
            console.error('Failed to fetch profiles:', error);
        } finally {
            setLoading(false);
        }
    }, [page, pageSize, searchKeyword]);

    // GSAP stagger entrance for host cards
    useEffect(() => {
        if (loading || !cardsRef.current) return;
        const cards = cardsRef.current.querySelectorAll('.host-card-item');
        if (cards.length === 0) return;

        const ctx = gsap.context(() => {
            gsap.from(cards, {
                y: 20,
                opacity: 0,
                duration: 0.4,
                stagger: 0.05,
                ease: 'power2.out',
                clearProps: 'transform,opacity',
            });
        }, cardsRef);

        return () => ctx.revert();
    }, [loading, profiles]);

    useEffect(() => {
        const timer = setTimeout(() => {
            fetchData();
        }, 300);
        return () => clearTimeout(timer);
    }, [fetchData]);

    // Compute aggregates
    const totalPorts = profiles.reduce((acc, p) => acc + (p.ports?.length || 0), 0);
    const totalFps = profiles.reduce((acc, p) => acc + (p.fingerprints?.length || 0), 0);
    const totalVulns = profiles.reduce((acc, p) => acc + (p.vulns?.length || 0), 0);

    return (
        <div style={{ position: 'relative', overflow: 'hidden' }}>
            <NetworkCanvas color="#8b5cf6" count={30} speed={0.15} linkDist={100} />
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20, position: 'relative', zIndex: 1 }}>
                <div>
                    <Title level={4} style={{ margin: 0, color: '#1e293b', fontWeight: 600 }}>
                        <ProfileOutlined style={{ marginRight: 8, color: '#8b5cf6' }} />
                        融合画像
                    </Title>
                    <Text style={{ fontSize: 12, color: '#94a3b8', marginTop: 2, display: 'block' }}>
                        以主机为维度聚合资产、指纹、漏洞信息
                    </Text>
                </div>
                <Space size={12}>
                    <Input
                        placeholder="搜索 IP / 域名..."
                        prefix={<SearchOutlined style={{ color: '#94a3b8' }} />}
                        value={searchKeyword}
                        onChange={(e) => { setSearchKeyword(e.target.value); setPage(1); }}
                        style={{ width: 260, borderRadius: 8 }}
                        allowClear
                    />
                    <Space size={4}>
                        <Tag style={{ margin: 0, background: '#f0f9ff', border: '1px solid #bae6fd', color: '#0369a1', borderRadius: 6 }}>
                            <GlobalOutlined style={{ marginRight: 3 }} />{total} 主机
                        </Tag>
                        <Tag style={{ margin: 0, background: '#f0fdf4', border: '1px solid #bbf7d0', color: '#166534', borderRadius: 6 }}>
                            <ApiOutlined style={{ marginRight: 3 }} />{totalPorts} 端口
                        </Tag>
                        <Tag style={{ margin: 0, background: '#fffbeb', border: '1px solid #fde68a', color: '#92400e', borderRadius: 6 }}>
                            <ScanOutlined style={{ marginRight: 3 }} />{totalFps} 指纹
                        </Tag>
                        {totalVulns > 0 && (
                            <Tag style={{ margin: 0, background: '#fef2f2', border: '1px solid #fecaca', color: '#991b1b', borderRadius: 6 }}>
                                <BugOutlined style={{ marginRight: 3 }} />{totalVulns} 漏洞
                            </Tag>
                        )}
                    </Space>
                </Space>
            </div>

            {loading ? (
                <div style={{ display: 'flex', justifyContent: 'center', padding: '80px 0' }}>
                    <Spin size="large" />
                </div>
            ) : profiles.length === 0 ? (
                <ProCard className="glass-card" style={{ background: 'transparent', border: 'none' }}>
                    <Empty description="暂无画像数据" style={{ padding: '80px 0' }} />
                </ProCard>
            ) : (
                <>
                    <div ref={cardsRef} style={{ display: 'flex', flexDirection: 'column', gap: 12, position: 'relative', zIndex: 1 }}>
                        {profiles.map(p => (
                            <div key={p.host} className="host-card-item">
                                <HostCard profile={p} />
                            </div>
                        ))}
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 20 }}>
                        <Pagination
                            current={page}
                            pageSize={pageSize}
                            total={total}
                            showTotal={(t) => `共 ${t} 个主机`}
                            showSizeChanger
                            pageSizeOptions={['10', '20', '50']}
                            onChange={(p, ps) => { setPage(p); setPageSize(ps); }}
                        />
                    </div>
                </>
            )}
        </div>
    );
};

export default ProfilesView;
