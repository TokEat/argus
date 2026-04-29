import React, { useState, useEffect, useRef } from 'react';
import { Button, Space, Tag, Input, Table, Empty, App, Switch, Typography } from 'antd';
import { ProCard } from '@ant-design/pro-components';
import {
    SaveOutlined,
    ReloadOutlined,
    EyeOutlined,
    EyeInvisibleOutlined,
    KeyOutlined,
    SearchOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import { getApiKeysConfig, saveApiKeysConfig } from '../services/api';
import gsap from 'gsap';
import NetworkCanvas from '../components/NetworkCanvas';

const { Text } = Typography;

// 引擎元数据：描述 + 密钥格式
interface ProviderMeta {
    desc: string;
    format: string;
    placeholder: string;
}

const providerMeta: Record<string, ProviderMeta> = {
    fofa:            { desc: 'FOFA 网络空间搜索',            format: 'email:key',  placeholder: 'user@example.com:xxxxxxxxxxxxxxxx' },
    hunter:          { desc: '鹰图（奇安信）资产搜索',        format: 'api-key',    placeholder: 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' },
    quake:           { desc: '360 Quake 网络空间搜索',       format: 'token',      placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' },
    shodan:          { desc: 'Shodan 物联网搜索引擎',         format: 'api-key',    placeholder: 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' },
    censys:          { desc: 'Censys 互联网设备搜索',         format: 'id:secret',  placeholder: 'api-id:api-secret' },
    zoomeye:         { desc: 'ZoomEye 钟馗之眼',             format: 'api-key',    placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' },
    zoomeyeapi:      { desc: 'ZoomEye API v2',              format: 'api-key',    placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' },
    virustotal:      { desc: 'VirusTotal 威胁情报',           format: 'api-key',    placeholder: 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' },
    github:          { desc: 'GitHub Token（子域名搜索）',     format: 'token',      placeholder: 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' },
    securitytrails:  { desc: 'SecurityTrails DNS 情报',      format: 'api-key',    placeholder: 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' },
    intelx:          { desc: 'Intelligence X 搜索引擎',       format: 'api-key',    placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' },
    chaos:           { desc: 'ProjectDiscovery Chaos',       format: 'api-key',    placeholder: 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' },
    bevigil:         { desc: 'BeVigil 移动应用情报',           format: 'api-key',    placeholder: 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' },
    binaryedge:      { desc: 'BinaryEdge 网络扫描数据',        format: 'api-key',    placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' },
    fullhunt:        { desc: 'FullHunt 攻击面管理',            format: 'api-key',    placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' },
    threatbook:      { desc: '微步在线威胁情报',               format: 'api-key',    placeholder: 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' },
    chinaz:          { desc: '站长之家 Chinaz',               format: 'api-key',    placeholder: 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' },
    leakix:          { desc: 'LeakIX 泄露信息搜索',            format: 'api-key',    placeholder: 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' },
    passivetotal:    { desc: 'PassiveTotal / RiskIQ',        format: 'user:key',   placeholder: 'user@example.com:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' },
    bufferover:      { desc: 'BufferOver DNS 数据',           format: 'api-key',    placeholder: 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' },
    c99:             { desc: 'C99 子域名枚举',                format: 'api-key',    placeholder: 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' },
    certspotter:     { desc: 'CertSpotter 证书透明度',         format: 'api-key',    placeholder: 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' },
    dnsdb:           { desc: 'DNSDB 被动 DNS 数据库',          format: 'api-key',    placeholder: 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' },
    dnsrepo:         { desc: 'DNSRepo DNS 记录',              format: 'api-key',    placeholder: 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' },
    robtex:          { desc: 'Robtex DNS/IP 分析',            format: 'api-key',    placeholder: 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' },
    whoisxmlapi:     { desc: 'WhoisXML API',                 format: 'api-key',    placeholder: 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' },
};

const ApiKeysConfig: React.FC = () => {
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [entries, setEntries] = useState<API.ApiKeyEntry[]>([]);
    const [filtered, setFiltered] = useState<API.ApiKeyEntry[]>([]);
    const [searchKeyword, setSearchKeyword] = useState('');
    const [showKeys, setShowKeys] = useState(false);
    const [modified, setModified] = useState(false);
    const { message } = App.useApp();
    const pageRef = useRef<HTMLDivElement>(null);

    /* GSAP entrance */
    useEffect(() => {
        if (!pageRef.current) return;
        const els = pageRef.current.querySelectorAll('.sys-animate-in');
        if (els.length === 0) return;
        const ctx = gsap.context(() => {
            gsap.from(els, {
                y: 24, opacity: 0, duration: 0.45,
                stagger: 0.08, ease: 'power2.out', clearProps: 'transform,opacity',
            });
        }, pageRef);
        return () => ctx.revert();
    }, []);

    const fetchData = async () => {
        setLoading(true);
        try {
            const result = await getApiKeysConfig();
            // 按是否有密钥排序：有密钥的排前面
            const sorted = (result || []).sort((a, b) => {
                const aHas = a.keys?.some(k => k.length > 0) ? 0 : 1;
                const bHas = b.keys?.some(k => k.length > 0) ? 0 : 1;
                return aHas - bHas || a.provider.localeCompare(b.provider);
            });
            setEntries(sorted);
            setModified(false);
        } catch {
            message.error('加载 API 密钥配置失败');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => { fetchData(); }, []);

    useEffect(() => {
        if (!searchKeyword) {
            setFiltered(entries);
        } else {
            const lower = searchKeyword.toLowerCase();
            setFiltered(entries.filter(e => e.provider.toLowerCase().includes(lower)));
        }
    }, [searchKeyword, entries]);

    // keys 数组序列化：多个 key 用换行分隔显示/编辑
    const keysToString = (keys: string[]): string => {
        return (keys || []).filter(k => k.length > 0).join('\n');
    };

    const stringToKeys = (value: string): string[] => {
        if (!value) return [];
        return value.split('\n').map(k => k.trim()).filter(k => k.length > 0);
    };

    const handleKeyChange = (provider: string, value: string) => {
        setEntries(prev => prev.map(e => {
            if (e.provider !== provider) return e;
            return { ...e, keys: stringToKeys(value) };
        }));
        setModified(true);
    };

    const handleSave = async () => {
        setSaving(true);
        try {
            await saveApiKeysConfig(entries);
            message.success('API 密钥已保存，已触发全网 Agent 配置重载');
            setModified(false);
        } catch {
            message.error('保存失败');
        } finally {
            setSaving(false);
        }
    };

    const configuredCount = entries.filter(e => e.keys?.some(k => k.length > 0)).length;

    const columns: ColumnsType<API.ApiKeyEntry> = [
        {
            title: '引擎 (Provider)',
            dataIndex: 'provider',
            key: 'provider',
            width: 200,
            render: (provider: string) => {
                const meta = providerMeta[provider];
                return (
                    <Space direction="vertical" size={0}>
                        <Space>
                            <KeyOutlined style={{ color: '#f59e0b' }} />
                            <Text strong style={{ textTransform: 'capitalize' }}>{provider}</Text>
                        </Space>
                        {meta && (
                            <Text style={{ fontSize: 11, color: '#64748b' }}>{meta.desc}</Text>
                        )}
                    </Space>
                );
            },
        },
        {
            title: '格式',
            key: 'format',
            width: 100,
            align: 'center',
            render: (_, record) => {
                const meta = providerMeta[record.provider];
                return <Tag color="geekblue" style={{ fontFamily: 'monospace', fontSize: 11 }}>{meta?.format || 'key'}</Tag>;
            },
        },
        {
            title: '状态',
            key: 'status',
            width: 80,
            align: 'center',
            render: (_, record) => {
                const configured = record.keys?.some(k => k.length > 0);
                return configured
                    ? <Tag color="green">已配置</Tag>
                    : <Tag color="default">未配置</Tag>;
            },
        },
        {
            title: '密钥 (API Key)',
            key: 'keys',
            render: (_, record) => {
                const meta = providerMeta[record.provider];
                const currentValue = keysToString(record.keys);
                const hasMultipleKeys = (record.keys?.filter(k => k.length > 0).length || 0) > 1;

                if (hasMultipleKeys) {
                    // 多个 key 用 TextArea 显示
                    if (showKeys) {
                        return (
                            <Input.TextArea
                                value={currentValue}
                                onChange={(e) => handleKeyChange(record.provider, e.target.value)}
                                placeholder={meta?.placeholder || '输入 API Key'}
                                style={{ fontFamily: 'monospace', fontSize: 12 }}
                                autoSize={{ minRows: 1, maxRows: 4 }}
                            />
                        );
                    }
                    return (
                        <Input.TextArea
                            value={currentValue}
                            onChange={(e) => handleKeyChange(record.provider, e.target.value)}
                            placeholder={meta?.placeholder || '输入 API Key'}
                            style={{ fontFamily: 'monospace', fontSize: 12, color: 'transparent', textShadow: '0 0 5px rgba(255,255,255,0.5)' }}
                            autoSize={{ minRows: 1, maxRows: 4 }}
                        />
                    );
                }

                if (showKeys) {
                    return (
                        <Input
                            value={currentValue}
                            onChange={(e) => handleKeyChange(record.provider, e.target.value)}
                            placeholder={meta?.placeholder || '输入 API Key'}
                            style={{ fontFamily: 'monospace', fontSize: 12 }}
                        />
                    );
                }
                return (
                    <Input.Password
                        value={currentValue}
                        onChange={(e) => handleKeyChange(record.provider, e.target.value)}
                        placeholder={meta?.placeholder || '输入 API Key'}
                        style={{ fontFamily: 'monospace', fontSize: 12 }}
                        visibilityToggle={false}
                    />
                );
            },
        },
        {
            title: 'Keys',
            key: 'count',
            width: 60,
            align: 'center',
            render: (_, record) => {
                const count = record.keys?.filter(k => k.length > 0).length || 0;
                return count > 0 ? <Tag>{count}</Tag> : <Text style={{ color: '#475569' }}>-</Text>;
            },
        },
    ];

    return (
        <div ref={pageRef} style={{ position: 'relative', overflow: 'hidden' }}>
            <NetworkCanvas color="#6366f1" count={25} speed={0.12} linkDist={90} />
            <div className="sys-animate-in" style={{
                background: 'rgba(15, 23, 42, 0.6)',
                borderRadius: 8,
                padding: '12px 16px',
                marginBottom: 16,
                fontSize: 12,
                color: '#94a3b8',
                border: '1px solid rgba(51, 65, 85, 0.5)',
            }}>
                💡 配置搜索引擎 API 密钥后，Agent 会自动同步。不同引擎格式不同：
                <code style={{ color: '#4ade80', margin: '0 4px' }}>fofa</code> 格式为 <code style={{ color: '#fb923c' }}>email:key</code>，
                <code style={{ color: '#4ade80', margin: '0 4px' }}>hunter</code> 为纯 API Key，
                <code style={{ color: '#4ade80', margin: '0 4px' }}>quake</code> 为 Token。
                多个密钥可换行分隔（轮转使用）。
            </div>

            <div className="sys-animate-in" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16, position: 'relative', zIndex: 1 }}>
                <Space>
                    <Input
                        placeholder="搜索引擎名..."
                        prefix={<SearchOutlined style={{ color: '#94a3b8' }} />}
                        value={searchKeyword}
                        onChange={(e) => setSearchKeyword(e.target.value)}
                        style={{ width: 220 }}
                        allowClear
                    />
                    <Tag color="blue">{configuredCount} / {entries.length} 已配置</Tag>
                </Space>
                <Space>
                    <Switch
                        checkedChildren={<><EyeOutlined /> 显示密钥</>}
                        unCheckedChildren={<><EyeInvisibleOutlined /> 隐藏密钥</>}
                        checked={showKeys}
                        onChange={setShowKeys}
                    />
                    <Button icon={<ReloadOutlined />} onClick={fetchData} loading={loading}>
                        刷新
                    </Button>
                    <Button
                        type="primary"
                        icon={<SaveOutlined />}
                        onClick={handleSave}
                        loading={saving}
                        disabled={!modified}
                    >
                        {modified ? '保存并分发' : '已保存'}
                    </Button>
                </Space>
            </div>

            <ProCard className="glass-card sys-animate-in" style={{ background: 'transparent', border: 'none', padding: 0, position: 'relative', zIndex: 1 }}>
                {filtered.length === 0 && !loading ? (
                    <Empty description="暂无 API 密钥配置" style={{ padding: '60px 0' }} />
                ) : (
                    <Table
                        columns={columns}
                        dataSource={filtered}
                        rowKey="provider"
                        loading={loading}
                        pagination={false}
                        size="middle"
                    />
                )}
            </ProCard>
        </div>
    );
};

export default ApiKeysConfig;
