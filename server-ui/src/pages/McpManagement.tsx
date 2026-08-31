import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Typography, Table, Tag, Space, Button, Spin, Empty, Switch, message, Popconfirm, Drawer, Alert, Tabs, Form, Input, Select } from 'antd';
import { ProCard } from '@ant-design/pro-components';
import { ApiOutlined, AuditOutlined, CopyOutlined, EyeOutlined, ReloadOutlined } from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import {
    deleteMcpAdminClient,
    disableMcpAdminClient,
    enableMcpAdminClient,
    getMcpAdminStatus,
    listMcpAdminClients,
    listMcpAdminInvocations,
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

const formatTime = (value?: string) => {
    if (!value) return '-';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return date.toLocaleString('zh-CN');
};

const McpManagement: React.FC = () => {
    const [activeTab, setActiveTab] = useState('governance');
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [status, setStatus] = useState<API.McpAdminStatus | null>(null);
    const [clients, setClients] = useState<API.McpAdminClient[]>([]);
    const [sessions, setSessions] = useState<API.McpAdminSession[]>([]);
    const [sessionClient, setSessionClient] = useState<string | null>(null);
    const [auditForm] = Form.useForm<{ tool_name?: string; user_id?: string; client_id?: string; status?: string }>();
    const [auditLoading, setAuditLoading] = useState(false);
    const [auditItems, setAuditItems] = useState<API.McpAdminInvocation[]>([]);
    const [auditTotal, setAuditTotal] = useState(0);
    const [auditPage, setAuditPage] = useState(1);
    const [auditPageSize, setAuditPageSize] = useState(50);
    const [auditFilters, setAuditFilters] = useState<{ tool_name?: string; user_id?: string; client_id?: string; status?: string }>({});
    const [selectedAudit, setSelectedAudit] = useState<API.McpAdminInvocation | null>(null);

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

    useEffect(() => { load(); }, [load]);
    useEffect(() => { fetchAudit(1, 50, {}); }, [fetchAudit]);

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
                message="只记录高风险 tools/call：behavior probe debug、scan create、rule publish、yaksha debug/run。参数已剥离密钥类字段。"
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
                    { title: '时间', dataIndex: 'created_at', width: 180, render: formatTime },
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
                        render: (_: unknown, row: API.McpAdminInvocation) => (
                            <Button size="small" icon={<EyeOutlined />} onClick={() => setSelectedAudit(row)}>详情</Button>
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
                <Button icon={<ReloadOutlined />} onClick={() => { load(); fetchAudit(auditPage, auditPageSize, auditFilters); }} loading={loading || auditLoading}>刷新</Button>
            </div>

            <div style={{ position: 'relative', zIndex: 1 }}>
                <Tabs
                    activeKey={activeTab}
                    onChange={setActiveTab}
                    items={[
                        { key: 'governance', label: <span><ApiOutlined /> 接入治理</span>, children: renderGovernance() },
                        { key: 'audit', label: <span><AuditOutlined /> 调用审计</span>, children: renderAudit() },
                    ]}
                />
            </div>

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
            <Drawer title="调用详情" width={760} open={!!selectedAudit} onClose={() => setSelectedAudit(null)}>
                {selectedAudit && (
                    <Space direction="vertical" size={16} style={{ width: '100%' }}>
                        <Space>
                            <Text code>{selectedAudit.tool_name}</Text>
                            <Tag color={selectedAudit.status === 'ok' ? 'green' : 'red'}>{selectedAudit.status}</Tag>
                        </Space>
                        <Text type="secondary">{formatTime(selectedAudit.created_at)} · {selectedAudit.user_id || '-'} · {selectedAudit.client_id || '-'}</Text>
                        {selectedAudit.error_summary ? <Alert type="error" showIcon message={selectedAudit.error_summary} /> : null}
                        <Paragraph style={{ marginBottom: 0 }}>
                            <pre style={{ margin: 0, padding: 12, background: '#0f172a', color: '#e2e8f0', borderRadius: 8, fontSize: 12, whiteSpace: 'pre-wrap' }}>
                                {JSON.stringify(selectedAudit.args || {}, null, 2)}
                            </pre>
                        </Paragraph>
                    </Space>
                )}
            </Drawer>
        </div>
    );
};

export default McpManagement;
