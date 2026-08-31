import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Typography, Table, Tag, Space, Button, Spin, Empty, Switch, message, Popconfirm, Drawer, Alert } from 'antd';
import { ProCard } from '@ant-design/pro-components';
import { ApiOutlined, CopyOutlined, ReloadOutlined } from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import {
    deleteMcpAdminClient,
    disableMcpAdminClient,
    enableMcpAdminClient,
    getMcpAdminStatus,
    listMcpAdminClients,
    listMcpAdminSessions,
    revokeMcpAdminClient,
    revokeMcpAdminSession,
    updateMcpAdminStatus,
} from '../services/api';
import NetworkCanvas from '../components/NetworkCanvas';

const { Title, Text, Paragraph } = Typography;

const cursorConfigSnippet = (mcpUrl: string) => `{
  "mcpServers": {
    "argus": {
      "url": ${JSON.stringify(mcpUrl || 'http://127.0.0.1:8085/mcp')}
    }
  }
}`;

const McpManagement: React.FC = () => {
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [status, setStatus] = useState<API.McpAdminStatus | null>(null);
    const [clients, setClients] = useState<API.McpAdminClient[]>([]);
    const [sessions, setSessions] = useState<API.McpAdminSession[]>([]);
    const [sessionClient, setSessionClient] = useState<string | null>(null);

    const load = useCallback(async () => {
        setLoading(true);
        try {
            const [nextStatus, nextClients, nextSessions] = await Promise.all([
                getMcpAdminStatus(),
                listMcpAdminClients(),
                listMcpAdminSessions(),
            ]);
            setStatus(nextStatus);
            setClients(nextClients || []);
            setSessions(nextSessions || []);
        } catch (error) {
            message.error(String(error));
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => { load(); }, [load]);

    const copyText = async (value: string, ok: string) => {
        try {
            await navigator.clipboard.writeText(value);
            message.success(ok);
        } catch {
            message.error('复制失败');
        }
    };

    const handleToggle = async (enabled: boolean) => {
        setSaving(true);
        try {
            await updateMcpAdminStatus(enabled, !enabled);
            message.success(enabled ? '已为本租户打开 MCP' : '已关闭本租户 MCP，并撤销全部刷新令牌');
            await load();
        } catch (error) {
            message.error(String(error));
        } finally {
            setSaving(false);
        }
    };

    const visibleSessions = useMemo(
        () => sessions.filter((item) => !sessionClient || item.client_id === sessionClient),
        [sessions, sessionClient],
    );

    const columns: ColumnsType<API.McpAdminClient> = [
        {
            title: '客户端',
            dataIndex: 'client_id',
            key: 'client_id',
            render: (id: string, record) => (
                <Space>
                    <Text style={{ fontWeight: 500 }}>{id}</Text>
                    {record.builtin ? <Tag color="blue">内置</Tag> : <Tag>DCR</Tag>}
                    {record.blocked ? <Tag color="red">已禁用</Tag> : <Tag color="green">可用</Tag>}
                </Space>
            ),
        },
        {
            title: '回调',
            dataIndex: 'redirect_uris',
            key: 'redirect_uris',
            render: (uris: string[]) => (
                <Text style={{ fontSize: 12, color: '#64748b' }}>
                    {(uris || []).slice(0, 2).join(' · ') || '-'}
                    {(uris || []).length > 2 ? ` 等 ${uris.length} 条` : ''}
                </Text>
            ),
        },
        {
            title: '会话',
            dataIndex: 'session_count',
            key: 'session_count',
            width: 80,
        },
        {
            title: '最近使用',
            dataIndex: 'last_used_at',
            key: 'last_used_at',
            width: 180,
            render: (value?: string) => (
                <Text style={{ fontSize: 12, color: '#64748b' }}>
                    {value ? new Date(value).toLocaleString('zh-CN') : '-'}
                </Text>
            ),
        },
        {
            title: '操作',
            key: 'actions',
            width: 280,
            render: (_, record) => (
                <Space size={4} wrap>
                    <Button type="link" size="small" onClick={() => setSessionClient(record.client_id)}>
                        会话
                    </Button>
                    <Popconfirm title="撤销本租户该客户端的全部刷新令牌？" onConfirm={() => revokeMcpAdminClient(record.client_id).then(load).catch((err) => message.error(String(err)))}>
                        <Button type="link" size="small">撤销会话</Button>
                    </Popconfirm>
                    {record.blocked ? (
                        <Button type="link" size="small" onClick={() => enableMcpAdminClient(record.client_id).then(() => { message.success('已对本租户重新启用'); return load(); }).catch((err) => message.error(String(err)))}>
                            启用
                        </Button>
                    ) : (
                        <Popconfirm title="对本租户禁用该客户端并撤销其会话？" onConfirm={() => disableMcpAdminClient(record.client_id).then(load).catch((err) => message.error(String(err)))}>
                            <Button type="link" size="small">禁用</Button>
                        </Popconfirm>
                    )}
                    {record.builtin ? null : (
                        <Popconfirm title="对本租户拉黑该客户端。若无其他租户使用，将删除全局注册行。" onConfirm={() => deleteMcpAdminClient(record.client_id).then((result) => { message.success(result.row_deleted ? '客户端已删除' : '已对本租户禁用，全局行仍在'); return load(); }).catch((err) => message.error(String(err)))}>
                            <Button type="link" size="small" danger>删除</Button>
                        </Popconfirm>
                    )}
                </Space>
            ),
        },
    ];

    const sessionColumns: ColumnsType<API.McpAdminSession> = [
        { title: '用户', dataIndex: 'user_id', key: 'user_id' },
        { title: '客户端', dataIndex: 'client_id', key: 'client_id' },
        {
            title: '签发',
            dataIndex: 'created_at',
            key: 'created_at',
            render: (value: string) => new Date(value).toLocaleString('zh-CN'),
        },
        {
            title: '过期',
            dataIndex: 'expires_at',
            key: 'expires_at',
            render: (value: string) => new Date(value).toLocaleString('zh-CN'),
        },
        {
            title: '操作',
            key: 'actions',
            render: (_, record) => (
                <Popconfirm title="撤销该刷新令牌？" onConfirm={() => revokeMcpAdminSession(record.session_id).then(load).catch((err) => message.error(String(err)))}>
                    <Button type="link" size="small" danger>撤销</Button>
                </Popconfirm>
            ),
        },
    ];

    return (
        <div style={{ position: 'relative', overflow: 'hidden' }}>
            <NetworkCanvas color="#0ea5e9" count={25} speed={0.12} linkDist={90} />
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20, position: 'relative', zIndex: 1 }}>
                <Title level={4} style={{ margin: 0, color: '#1e293b', fontWeight: 600 }}>
                    <ApiOutlined style={{ marginRight: 8, color: '#0ea5e9' }} />
                    MCP 管理
                </Title>
                <Button icon={<ReloadOutlined />} onClick={load} loading={loading}>刷新</Button>
            </div>

            <Space direction="vertical" size={16} style={{ width: '100%', position: 'relative', zIndex: 1 }}>
                <ProCard className="glass-card" style={{ background: 'transparent', border: 'none' }}>
                    {loading && !status ? (
                        <div style={{ display: 'flex', justifyContent: 'center', padding: '40px 0' }}><Spin /></div>
                    ) : (
                        <Space direction="vertical" size={12} style={{ width: '100%' }}>
                            <Space align="center">
                                <Text>本租户 MCP</Text>
                                <Switch
                                    checked={!!status?.enabled}
                                    loading={saving}
                                    onChange={(checked) => {
                                        if (!checked) {
                                            return;
                                        }
                                        handleToggle(true);
                                    }}
                                />
                                {!status?.enabled ? null : (
                                    <Popconfirm title="关闭后本租户无法授权或调用 /mcp，并立刻撤销全部刷新令牌。" onConfirm={() => handleToggle(false)}>
                                        <Button size="small">关闭</Button>
                                    </Popconfirm>
                                )}
                                <Tag color={status?.enabled ? 'green' : 'red'}>{status?.enabled ? '已启用' : '已关闭'}</Tag>
                                <Text type="secondary">活跃会话 {status?.session_count ?? 0}</Text>
                            </Space>
                            <Alert
                                type="info"
                                showIcon
                                message="Cursor 用 url 连接 Server /mcp，不要把 JWT 写进 mcp.json。"
                            />
                            <Space wrap>
                                <Text>接入地址</Text>
                                <Text code>{status?.mcp_url || '-'}</Text>
                                <Button size="small" icon={<CopyOutlined />} onClick={() => copyText(status?.mcp_url || '', '已复制 MCP 地址')}>复制</Button>
                            </Space>
                            <Text type="secondary">对外 public URL（只读，错了会导致 OAuth aud 对不上）：{status?.public_url || '-'}</Text>
                            <Paragraph style={{ marginBottom: 0 }}>
                                <pre style={{ margin: 0, padding: 12, background: '#0f172a', color: '#e2e8f0', borderRadius: 8, fontSize: 12 }}>
                                    {cursorConfigSnippet(status?.mcp_url || '')}
                                </pre>
                            </Paragraph>
                            <Button size="small" icon={<CopyOutlined />} onClick={() => copyText(cursorConfigSnippet(status?.mcp_url || ''), '已复制 Cursor 配置')}>
                                复制 mcp.json 示例
                            </Button>
                        </Space>
                    )}
                </ProCard>

                <ProCard className="glass-card" style={{ background: 'transparent', border: 'none' }} title="OAuth 客户端">
                    {loading && clients.length === 0 ? (
                        <div style={{ display: 'flex', justifyContent: 'center', padding: '40px 0' }}><Spin /></div>
                    ) : clients.length === 0 ? (
                        <Empty description="暂无客户端" />
                    ) : (
                        <Table rowKey="client_id" columns={columns} dataSource={clients} pagination={false} size="middle" />
                    )}
                </ProCard>
            </Space>

            <Drawer title={sessionClient ? `会话 · ${sessionClient}` : '会话'} open={!!sessionClient} width={640} onClose={() => setSessionClient(null)}>
                <Table
                    rowKey="session_id"
                    columns={sessionColumns}
                    dataSource={visibleSessions}
                    pagination={false}
                    size="small"
                    locale={{ emptyText: '没有未过期的刷新令牌' }}
                />
            </Drawer>
        </div>
    );
};

export default McpManagement;
