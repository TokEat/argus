import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Typography, Table, Tag, Space, Button, Spin, Empty, Switch, message, Popconfirm, Drawer, Alert, Tabs, Form, Input, Select } from 'antd';
import { ProCard } from '@ant-design/pro-components';
import { ApiOutlined, AppstoreOutlined, AuditOutlined, CopyOutlined, EyeOutlined, HistoryOutlined, ReloadOutlined, TeamOutlined } from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import {
    deleteMcpAdminClient,
    disableMcpAdminClient,
    enableMcpAdminClient,
    getMcpAdminStatus,
    listMcpAdminClients,
    listMcpAdminEvents,
    listMcpAdminInvocations,
    listMcpAdminSessions,
    listMcpAdminTools,
    revokeMcpAdminClient,
    revokeMcpAdminSession,
    revokeMcpAdminUserSessions,
    updateMcpAdminStatus,
    type McpAdminClient,
    type McpAdminEvent,
    type McpAdminInvocation,
    type McpAdminSession,
    type McpAdminStatus,
    type McpAdminTool,
} from '../services/mcpAdmin';
import NetworkCanvas from '../components/NetworkCanvas';
import { cursorConfigSnippet, formatMcpTime } from './mcpManagementShared';
import McpToolCatalog from './McpToolCatalog';

const { Title, Text, Paragraph } = Typography;

const McpManagement: React.FC = () => {
    const [activeTab, setActiveTab] = useState('governance');
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [status, setStatus] = useState<McpAdminStatus | null>(null);
    const [clients, setClients] = useState<McpAdminClient[]>([]);
    const [sessions, setSessions] = useState<McpAdminSession[]>([]);
    const [sessionClient, setSessionClient] = useState<string | null>(null);
    const [sessionUser, setSessionUser] = useState('');
    const [tools, setTools] = useState<McpAdminTool[]>([]);
    const [auditForm] = Form.useForm<{ tool_name?: string; user_id?: string; client_id?: string; status?: string }>();
    const [auditLoading, setAuditLoading] = useState(false);
    const [auditItems, setAuditItems] = useState<McpAdminInvocation[]>([]);
    const [auditTotal, setAuditTotal] = useState(0);
    const [auditPage, setAuditPage] = useState(1);
    const [auditPageSize, setAuditPageSize] = useState(50);
    const [auditFilters, setAuditFilters] = useState<{ tool_name?: string; user_id?: string; client_id?: string; status?: string }>({});
    const [selectedAudit, setSelectedAudit] = useState<McpAdminInvocation | null>(null);
    const [eventForm] = Form.useForm<{ action?: string; actor_id?: string; client_id?: string }>();
    const [eventLoading, setEventLoading] = useState(false);
    const [eventItems, setEventItems] = useState<McpAdminEvent[]>([]);
    const [eventTotal, setEventTotal] = useState(0);
    const [eventPage, setEventPage] = useState(1);
    const [eventPageSize, setEventPageSize] = useState(50);
    const [eventFilters, setEventFilters] = useState<{ action?: string; actor_id?: string; client_id?: string }>({});
    const [selectedEvent, setSelectedEvent] = useState<McpAdminEvent | null>(null);

    const load = useCallback(async () => {
        setLoading(true);
        try {
            const [nextStatus, nextClients, nextSessions, nextTools] = await Promise.all([
                getMcpAdminStatus(),
                listMcpAdminClients(),
                listMcpAdminSessions(),
                listMcpAdminTools(),
            ]);
            setStatus(nextStatus);
            setClients(nextClients || []);
            setSessions(nextSessions || []);
            setTools(nextTools || []);
        } catch (error) {
            message.error(String(error));
        } finally {
            setLoading(false);
        }
    }, []);

    const fetchAudit = useCallback(async (
        page: number,
        pageSize: number,
        filters: { tool_name?: string; user_id?: string; client_id?: string; status?: string },
    ) => {
        setAuditLoading(true);
        try {
            const normalized = Object.fromEntries(
                Object.entries(filters).filter(([, value]) => typeof value === 'string' && value.trim() !== ''),
            ) as { tool_name?: string; user_id?: string; client_id?: string; status?: string };
            const resp = await listMcpAdminInvocations({
                ...normalized,
                limit: pageSize,
                offset: (page - 1) * pageSize,
            });
            setAuditItems(resp.items || []);
            setAuditTotal(resp.total || 0);
            setAuditPage(page);
            setAuditPageSize(pageSize);
            setAuditFilters(normalized);
        } catch (error) {
            message.error(String(error));
        } finally {
            setAuditLoading(false);
        }
    }, []);

    const fetchEvents = useCallback(async (
        page: number,
        pageSize: number,
        filters: { action?: string; actor_id?: string; client_id?: string },
    ) => {
        setEventLoading(true);
        try {
            const normalized = Object.fromEntries(
                Object.entries(filters).filter(([, value]) => typeof value === 'string' && value.trim() !== ''),
            ) as { action?: string; actor_id?: string; client_id?: string };
            const resp = await listMcpAdminEvents({
                ...normalized,
                limit: pageSize,
                offset: (page - 1) * pageSize,
            });
            setEventItems(resp.items || []);
            setEventTotal(resp.total || 0);
            setEventPage(page);
            setEventPageSize(pageSize);
            setEventFilters(normalized);
        } catch (error) {
            message.error(String(error));
        } finally {
            setEventLoading(false);
        }
    }, []);

    useEffect(() => { load(); }, [load]);
    useEffect(() => { fetchAudit(1, 50, {}); }, [fetchAudit]);
    useEffect(() => { fetchEvents(1, 50, {}); }, [fetchEvents]);

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

    const openClientSessions = (clientId: string) => {
        setSessionClient(clientId);
        setActiveTab('sessions');
    };

    const handleRevokeSession = async (sessionId: string) => {
        try {
            await revokeMcpAdminSession(sessionId);
            message.success('已撤销该刷新令牌');
            await load();
        } catch (error) {
            message.error(String(error));
        }
    };

    const handleRevokeUserSessions = async (userId: string) => {
        try {
            const result = await revokeMcpAdminUserSessions(userId);
            message.success(`已撤销 ${result.revoked_sessions ?? 0} 条会话`);
            await load();
        } catch (error) {
            message.error(String(error));
        }
    };

    const visibleSessions = useMemo(
        () => sessions.filter((item) => {
            if (sessionClient && item.client_id !== sessionClient) return false;
            if (sessionUser.trim() && item.user_id !== sessionUser.trim()) return false;
            return true;
        }),
        [sessions, sessionClient, sessionUser],
    );

    const columns: ColumnsType<McpAdminClient> = [
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
                    <Button type="link" size="small" onClick={() => openClientSessions(record.client_id)}>
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

    const sessionColumns: ColumnsType<McpAdminSession> = [
        { title: '用户', dataIndex: 'user_id', key: 'user_id' },
        { title: '客户端', dataIndex: 'client_id', key: 'client_id' },
        {
            title: '签发',
            dataIndex: 'created_at',
            key: 'created_at',
            render: (value: string) => formatMcpTime(value),
        },
        {
            title: '过期',
            dataIndex: 'expires_at',
            key: 'expires_at',
            render: (value: string) => formatMcpTime(value),
        },
        {
            title: '操作',
            key: 'actions',
            width: 220,
            render: (_, record) => (
                <Space size={4} wrap>
                    <Popconfirm title="撤销该刷新令牌？" onConfirm={() => handleRevokeSession(record.session_id)}>
                        <Button type="link" size="small" danger>撤销</Button>
                    </Popconfirm>
                    <Popconfirm title={`撤销用户 ${record.user_id} 在本租户的全部 MCP 刷新令牌？`} onConfirm={() => handleRevokeUserSessions(record.user_id)}>
                        <Button type="link" size="small" danger>撤销该用户</Button>
                    </Popconfirm>
                </Space>
            ),
        },
    ];

    const renderGovernance = () => (
        <Space direction="vertical" size={16} style={{ width: '100%' }}>
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
                            message="通用 Streamable HTTP 接入"
                            description={(
                                <Space direction="vertical" size={4}>
                                    <Text>传输为 Streamable HTTP（stateless JSON）。接入地址即下方 MCP URL。</Text>
                                    <Text>浏览器 / IDE 走 Server OAuth。配置里只写 url，不要写 JWT。</Text>
                                    <Text>关闭本租户或拉黑 client_id 后，未过期的 access token 也会被拒绝。</Text>
                                </Space>
                            )}
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
    );

    const renderSessions = () => (
        <ProCard className="glass-card" style={{ background: 'transparent', border: 'none' }}>
            <Space wrap style={{ marginBottom: 16 }}>
                <Select
                    allowClear
                    placeholder="全部客户端"
                    value={sessionClient || undefined}
                    onChange={(value) => setSessionClient(value || null)}
                    style={{ width: 220 }}
                    options={clients.map((item) => ({ value: item.client_id, label: item.client_id }))}
                />
                <Input
                    allowClear
                    placeholder="按 user_id 筛选"
                    value={sessionUser}
                    onChange={(event) => setSessionUser(event.target.value)}
                    style={{ width: 180 }}
                />
                <Button icon={<ReloadOutlined />} onClick={load} loading={loading}>刷新</Button>
            </Space>
            <Table
                rowKey="session_id"
                columns={sessionColumns}
                dataSource={visibleSessions}
                loading={loading}
                pagination={false}
                size="middle"
                locale={{ emptyText: '没有未过期的刷新令牌' }}
            />
        </ProCard>
    );

    const renderAudit = () => (
        <ProCard className="glass-card" style={{ background: 'transparent', border: 'none', padding: 0 }}>
            <Form
                form={auditForm}
                layout="inline"
                onFinish={(values) => fetchAudit(1, auditPageSize, values)}
                style={{ marginBottom: 16, rowGap: 8 }}
            >
                <Form.Item name="tool_name" label="工具">
                    <Input allowClear placeholder="如 argus_scan_create" style={{ width: 210 }} />
                </Form.Item>
                <Form.Item name="user_id" label="用户">
                    <Input allowClear placeholder="user_id" style={{ width: 140 }} />
                </Form.Item>
                <Form.Item name="client_id" label="客户端">
                    <Input allowClear placeholder="cursor" style={{ width: 140 }} />
                </Form.Item>
                <Form.Item name="status" label="状态">
                    <Select
                        allowClear
                        placeholder="全部"
                        style={{ width: 120 }}
                        options={[
                            { value: 'ok', label: 'ok' },
                            { value: 'error', label: 'error' },
                        ]}
                    />
                </Form.Item>
                <Form.Item>
                    <Space>
                        <Button type="primary" htmlType="submit">筛选</Button>
                        <Button onClick={() => { auditForm.resetFields(); fetchAudit(1, auditPageSize, {}); }}>重置</Button>
                        <Button icon={<ReloadOutlined />} onClick={() => fetchAudit(auditPage, auditPageSize, auditFilters)} loading={auditLoading}>刷新</Button>
                    </Space>
                </Form.Item>
            </Form>
            <Alert
                type="info"
                showIcon
                style={{ marginBottom: 16 }}
                message="记录 argus_debug_*、argus_save_*、scan create、rule publish、yaksha debug/run。参数已剥离密钥类字段。"
            />
            <Table
                rowKey="id"
                loading={auditLoading}
                dataSource={auditItems}
                pagination={{
                    current: auditPage,
                    pageSize: auditPageSize,
                    total: auditTotal,
                    showSizeChanger: true,
                    pageSizeOptions: [20, 50, 100, 200],
                    showTotal: (total) => `共 ${total} 条`,
                    onChange: (page, pageSize) => fetchAudit(page, pageSize, auditFilters),
                }}
                locale={{ emptyText: '暂无高风险调用' }}
                columns={[
                    { title: '时间', dataIndex: 'created_at', width: 180, render: formatMcpTime },
                    { title: '用户', dataIndex: 'user_id', width: 100, render: (value: string) => value || '-' },
                    { title: '客户端', dataIndex: 'client_id', width: 120, render: (value: string) => value || '-' },
                    { title: '工具', dataIndex: 'tool_name', render: (value: string) => <Text code>{value}</Text> },
                    { title: '动作', dataIndex: 'action', width: 90, render: (value: string) => value || '-' },
                    {
                        title: '状态',
                        dataIndex: 'status',
                        width: 90,
                        render: (value: string) => <Tag color={value === 'ok' ? 'green' : 'red'}>{value || '-'}</Tag>,
                    },
                    { title: '耗时', dataIndex: 'duration_ms', width: 90, render: (value: number) => `${value || 0}ms` },
                    {
                        title: '操作',
                        width: 110,
                        render: (_: unknown, row: McpAdminInvocation) => (
                            <Button size="small" icon={<EyeOutlined />} onClick={() => setSelectedAudit(row)}>详情</Button>
                        ),
                    },
                ]}
            />
        </ProCard>
    );

    const renderEvents = () => (
        <ProCard className="glass-card" style={{ background: 'transparent', border: 'none', padding: 0 }}>
            <Form
                form={eventForm}
                layout="inline"
                onFinish={(values) => fetchEvents(1, eventPageSize, values)}
                style={{ marginBottom: 16, rowGap: 8 }}
            >
                <Form.Item name="action" label="动作">
                    <Select
                        allowClear
                        placeholder="全部"
                        style={{ width: 180 }}
                        options={[
                            { value: 'enable', label: 'enable' },
                            { value: 'disable', label: 'disable' },
                            { value: 'revoke_client', label: 'revoke_client' },
                            { value: 'disable_client', label: 'disable_client' },
                            { value: 'enable_client', label: 'enable_client' },
                            { value: 'delete_client', label: 'delete_client' },
                            { value: 'revoke_session', label: 'revoke_session' },
                            { value: 'revoke_sessions', label: 'revoke_sessions' },
                        ]}
                    />
                </Form.Item>
                <Form.Item name="actor_id" label="操作人">
                    <Input allowClear placeholder="user_id" style={{ width: 140 }} />
                </Form.Item>
                <Form.Item name="client_id" label="客户端">
                    <Input allowClear placeholder="cursor" style={{ width: 140 }} />
                </Form.Item>
                <Form.Item>
                    <Space>
                        <Button type="primary" htmlType="submit">筛选</Button>
                        <Button onClick={() => { eventForm.resetFields(); fetchEvents(1, eventPageSize, {}); }}>重置</Button>
                        <Button icon={<ReloadOutlined />} onClick={() => fetchEvents(eventPage, eventPageSize, eventFilters)} loading={eventLoading}>刷新</Button>
                    </Space>
                </Form.Item>
            </Form>
            <Alert
                type="info"
                showIcon
                style={{ marginBottom: 16 }}
                message="记录本租户 admin 对 MCP 开关、客户端和会话的治理操作，不是 tools/call 流水。"
            />
            <Table
                rowKey="id"
                loading={eventLoading}
                dataSource={eventItems}
                pagination={{
                    current: eventPage,
                    pageSize: eventPageSize,
                    total: eventTotal,
                    showSizeChanger: true,
                    pageSizeOptions: [20, 50, 100, 200],
                    showTotal: (total) => `共 ${total} 条`,
                    onChange: (page, pageSize) => fetchEvents(page, pageSize, eventFilters),
                }}
                locale={{ emptyText: '暂无治理操作' }}
                columns={[
                    { title: '时间', dataIndex: 'created_at', width: 180, render: formatMcpTime },
                    { title: '操作人', dataIndex: 'actor_id', width: 120, render: (value: string) => value || '-' },
                    { title: '动作', dataIndex: 'action', width: 160, render: (value: string) => <Tag>{value || '-'}</Tag> },
                    { title: '客户端', dataIndex: 'client_id', width: 140, render: (value: string) => value || '-' },
                    {
                        title: '操作',
                        width: 110,
                        render: (_: unknown, row: McpAdminEvent) => (
                            <Button size="small" icon={<EyeOutlined />} onClick={() => setSelectedEvent(row)}>详情</Button>
                        ),
                    },
                ]}
            />
        </ProCard>
    );

    return (
        <div style={{ position: 'relative', overflow: 'hidden' }}>
            <NetworkCanvas color="#0ea5e9" count={25} speed={0.12} linkDist={90} />
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20, position: 'relative', zIndex: 1 }}>
                <Title level={4} style={{ margin: 0, color: '#1e293b', fontWeight: 600 }}>
                    <ApiOutlined style={{ marginRight: 8, color: '#0ea5e9' }} />
                    MCP 管理
                </Title>
                <Button
                    icon={<ReloadOutlined />}
                    onClick={() => {
                        load();
                        fetchAudit(auditPage, auditPageSize, auditFilters);
                        fetchEvents(eventPage, eventPageSize, eventFilters);
                    }}
                    loading={loading || auditLoading || eventLoading}
                >
                    刷新
                </Button>
            </div>

            <div style={{ position: 'relative', zIndex: 1 }}>
                <Tabs
                    activeKey={activeTab}
                    onChange={setActiveTab}
                    destroyOnHidden
                    items={[
                        { key: 'governance', label: <span><ApiOutlined /> 接入治理</span>, children: renderGovernance() },
                        { key: 'sessions', label: <span><TeamOutlined /> 会话</span>, children: renderSessions() },
                        { key: 'audit', label: <span><AuditOutlined /> 调用审计</span>, children: renderAudit() },
                        { key: 'events', label: <span><HistoryOutlined /> 治理事件</span>, children: renderEvents() },
                        { key: 'catalog', label: <span><AppstoreOutlined /> 工具目录</span>, children: <McpToolCatalog tools={tools} loading={loading} /> },
                    ]}
                />
            </div>

            <Drawer title="调用详情" width={760} open={!!selectedAudit} onClose={() => setSelectedAudit(null)}>
                {selectedAudit && (
                    <Space direction="vertical" size={16} style={{ width: '100%' }}>
                        <Space>
                            <Text code>{selectedAudit.tool_name}</Text>
                            <Tag color={selectedAudit.status === 'ok' ? 'green' : 'red'}>{selectedAudit.status}</Tag>
                        </Space>
                        <Text type="secondary">{formatMcpTime(selectedAudit.created_at)} · {selectedAudit.user_id || '-'} · {selectedAudit.client_id || '-'}</Text>
                        {selectedAudit.error_summary ? <Alert type="error" showIcon message={selectedAudit.error_summary} /> : null}
                        <Paragraph style={{ marginBottom: 0 }}>
                            <pre style={{ margin: 0, padding: 12, background: '#0f172a', color: '#e2e8f0', borderRadius: 8, fontSize: 12, whiteSpace: 'pre-wrap' }}>
                                {JSON.stringify(selectedAudit.args || {}, null, 2)}
                            </pre>
                        </Paragraph>
                    </Space>
                )}
            </Drawer>
            <Drawer title="治理事件详情" width={640} open={!!selectedEvent} onClose={() => setSelectedEvent(null)}>
                {selectedEvent && (
                    <Space direction="vertical" size={16} style={{ width: '100%' }}>
                        <Space>
                            <Tag>{selectedEvent.action}</Tag>
                            <Text type="secondary">{formatMcpTime(selectedEvent.created_at)}</Text>
                        </Space>
                        <Text>操作人 {selectedEvent.actor_id || '-'} · 客户端 {selectedEvent.client_id || '-'}</Text>
                        <Paragraph style={{ marginBottom: 0 }}>
                            <pre style={{ margin: 0, padding: 12, background: '#0f172a', color: '#e2e8f0', borderRadius: 8, fontSize: 12, whiteSpace: 'pre-wrap' }}>
                                {JSON.stringify(selectedEvent.details || {}, null, 2)}
                            </pre>
                        </Paragraph>
                    </Space>
                )}
            </Drawer>
        </div>
    );
};

export default McpManagement;
