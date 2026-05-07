import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
    Alert,
    App,
    AutoComplete,
    Button,
    Collapse,
    Descriptions,
    Drawer,
    Form,
    Input,
    Select,
    Space,
    Spin,
    Table,
    Tabs,
    Tag,
    Typography,
} from 'antd';
import { ProCard } from '@ant-design/pro-components';
import {
    AuditOutlined,
    CloudSyncOutlined,
    EyeOutlined,
    FileTextOutlined,
    ReloadOutlined,
    RobotOutlined,
    SaveOutlined,
    ThunderboltOutlined,
} from '@ant-design/icons';
import {
    getAIConfig,
    getCopilotPromptProfiles,
    listAIToolInvocations,
    listAIModels,
    saveAIConfig,
    testAIConnection,
} from '../services/api';
import { canAccessRole, getCurrentUserRole } from '../utils/auth';
import gsap from 'gsap';
import NetworkCanvas from '../components/NetworkCanvas';

const { Paragraph, Text } = Typography;

const baseURLHints = [
    { label: 'OpenAI', value: 'https://api.openai.com/v1' },
    { label: 'DeepSeek', value: 'https://api.deepseek.com' },
    { label: '阿里通义千问', value: 'https://dashscope.aliyuncs.com/compatible-mode/v1' },
    { label: '月之暗面 Kimi', value: 'https://api.moonshot.cn/v1' },
    { label: '智谱 GLM', value: 'https://open.bigmodel.cn/api/paas/v4' },
    { label: 'Ollama 本地', value: 'http://localhost:11434/v1' },
];

const formatTime = (value?: string) => {
    if (!value) return '-';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return date.toLocaleString();
};

const statusColor = (status?: string) => {
    if (status === 'success') return 'green';
    if (status === 'error') return 'red';
    return 'default';
};

const AIConfig: React.FC = () => {
    const [form] = Form.useForm<API.AIConfig>();
    const [auditForm] = Form.useForm<{ module?: string; tool_name?: string; status?: string }>();
    const currentRole = getCurrentUserRole();
    const isAdmin = canAccessRole('admin', currentRole);
    const defaultTab = isAdmin ? 'model' : 'audit';
    const [activeTab, setActiveTab] = useState(defaultTab);

    const [loading, setLoading] = useState(false);
    const [saving, setSaving] = useState(false);
    const [hasKey, setHasKey] = useState(false);
    const [maskedKey, setMaskedKey] = useState('');
    const [models, setModels] = useState<API.AIModelInfo[]>([]);
    const [modelsLoading, setModelsLoading] = useState(false);
    const [modelsError, setModelsError] = useState('');
    const [testing, setTesting] = useState(false);
    const [testResult, setTestResult] = useState<{ success: boolean; response?: string; error?: string; elapsed_ms: number; base_url: string; model: string } | null>(null);

    const [promptLoading, setPromptLoading] = useState(false);
    const [promptRegistry, setPromptRegistry] = useState<API.CopilotPromptRegistry | null>(null);
    const [selectedPrompt, setSelectedPrompt] = useState<API.CopilotPromptProfile | null>(null);

    const [auditLoading, setAuditLoading] = useState(false);
    const [auditItems, setAuditItems] = useState<API.AIToolInvocation[]>([]);
    const [auditTotal, setAuditTotal] = useState(0);
    const [auditPage, setAuditPage] = useState(1);
    const [auditPageSize, setAuditPageSize] = useState(50);
    const [auditFilters, setAuditFilters] = useState<{ module?: string; tool_name?: string; status?: string }>({});
    const [selectedAudit, setSelectedAudit] = useState<API.AIToolInvocation | null>(null);

    const { message } = App.useApp();
    const pageRef = useRef<HTMLDivElement>(null);

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

    const fetchModels = useCallback(async (overrideBaseURL?: string, overrideAPIKey?: string) => {
        setModelsLoading(true);
        setModelsError('');
        try {
            const params: { base_url?: string; api_key?: string } = {};
            if (overrideBaseURL) params.base_url = overrideBaseURL;
            if (overrideAPIKey) params.api_key = overrideAPIKey;
            const resp = await listAIModels(Object.keys(params).length > 0 ? params : undefined);
            setModels(resp.models || []);
        } catch (err: unknown) {
            const errMsg = typeof err === 'string' ? err : '获取模型列表失败';
            setModelsError(errMsg);
            setModels([]);
        } finally {
            setModelsLoading(false);
        }
    }, []);

    const fetchConfig = useCallback(async () => {
        if (!isAdmin) return;
        setLoading(true);
        try {
            const cfg = await getAIConfig();
            const baseURL = cfg.base_url || 'https://api.openai.com/v1';
            form.setFieldsValue({
                base_url: baseURL,
                model: cfg.model,
                api_key: '',
            });
            setHasKey(!!cfg.has_api_key);
            setMaskedKey(cfg.api_key_masked || '');
            if (cfg.has_api_key) {
                fetchModels();
            }
        } catch (err: unknown) {
            message.error(typeof err === 'string' ? err : '加载 AI 配置失败');
        } finally {
            setLoading(false);
        }
    }, [fetchModels, form, isAdmin, message]);

    const fetchPromptRegistry = useCallback(async () => {
        setPromptLoading(true);
        try {
            setPromptRegistry(await getCopilotPromptProfiles());
        } catch (err: unknown) {
            message.error(typeof err === 'string' ? err : '加载 Copilot Prompt 失败');
        } finally {
            setPromptLoading(false);
        }
    }, [message]);

    const fetchAudit = useCallback(async (
        page: number,
        pageSize: number,
        filters: { module?: string; tool_name?: string; status?: string },
    ) => {
        setAuditLoading(true);
        try {
            const normalized = Object.fromEntries(
                Object.entries(filters).filter(([, value]) => typeof value === 'string' && value.trim() !== ''),
            ) as { module?: string; tool_name?: string; status?: string };
            const resp = await listAIToolInvocations({
                ...normalized,
                limit: pageSize,
                offset: (page - 1) * pageSize,
            });
            setAuditItems(resp.items || []);
            setAuditTotal(resp.total || 0);
            setAuditPage(page);
            setAuditPageSize(pageSize);
            setAuditFilters(normalized);
        } catch (err: unknown) {
            message.error(typeof err === 'string' ? err : '加载 Copilot 审计失败');
        } finally {
            setAuditLoading(false);
        }
    }, [message]);

    useEffect(() => {
        if (isAdmin) {
            fetchConfig();
        }
        fetchPromptRegistry();
        fetchAudit(1, 50, {});
    }, [fetchAudit, fetchConfig, fetchPromptRegistry, isAdmin]);

    const handleFetchModels = () => {
        const baseURL = form.getFieldValue('base_url');
        const apiKey = form.getFieldValue('api_key');
        fetchModels(baseURL || undefined, apiKey || undefined);
    };

    const handleSave = async () => {
        const values = await form.validateFields();
        const payload: API.AIConfig = {
            base_url: values.base_url,
            model: values.model,
        };
        if (values.api_key?.trim()) {
            payload.api_key = values.api_key.trim();
        }
        setSaving(true);
        try {
            const cfg = await saveAIConfig(payload);
            form.setFieldsValue({
                base_url: cfg.base_url,
                model: cfg.model,
                api_key: '',
            });
            setHasKey(!!cfg.has_api_key);
            setMaskedKey(cfg.api_key_masked || '');
            message.success('AI 配置已保存');
            if (cfg.has_api_key) {
                fetchModels();
            }
        } catch (err: unknown) {
            message.error(typeof err === 'string' ? err : '保存 AI 配置失败');
        } finally {
            setSaving(false);
        }
    };

    const handleTest = async () => {
        setTesting(true);
        setTestResult(null);
        try {
            const result = await testAIConnection();
            setTestResult(result);
        } catch (err: unknown) {
            setTestResult({
                success: false,
                error: typeof err === 'string' ? err : '连接测试失败',
                elapsed_ms: 0,
                base_url: form.getFieldValue('base_url') || '',
                model: form.getFieldValue('model') || '',
            });
        } finally {
            setTesting(false);
        }
    };

    const modelOptions = models.map((m) => ({
        value: m.id,
        label: (
            <span>
                {m.id}
                {m.owned_by && <Text type="secondary" style={{ fontSize: 11, marginLeft: 8 }}>({m.owned_by})</Text>}
            </span>
        ),
    }));

    const promptProfiles = useMemo(() => {
        if (!promptRegistry) return [];
        return [promptRegistry.default, ...promptRegistry.profiles];
    }, [promptRegistry]);

    const renderModelTab = () => (
        <ProCard className="glass-card" style={{ background: 'transparent', border: 'none', padding: 0 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, marginBottom: 16, flexWrap: 'wrap' }}>
                <Space>
                    <Tag color={hasKey ? 'green' : 'default'}>{hasKey ? '已配置 Key' : '未配置 Key'}</Tag>
                    <Text type="secondary">模型配置仅管理员可操作</Text>
                </Space>
                <Space>
                    <Button icon={<ReloadOutlined />} onClick={fetchConfig} loading={loading}>
                        刷新
                    </Button>
                    <Button icon={<ThunderboltOutlined />} onClick={handleTest} loading={testing}>
                        测试连接
                    </Button>
                    <Button type="primary" icon={<SaveOutlined />} onClick={handleSave} loading={saving}>
                        保存
                    </Button>
                </Space>
            </div>

            <Form form={form} layout="vertical" style={{ maxWidth: 760 }}>
                <Form.Item
                    label="Base URL"
                    name="base_url"
                    rules={[{ required: true, message: '请输入 Base URL' }]}
                >
                    <AutoComplete
                        options={baseURLHints.map((h) => ({
                            value: h.value,
                            label: <span>{h.label} <Text type="secondary" style={{ fontSize: 11 }}>{h.value}</Text></span>,
                        }))}
                        placeholder="https://api.openai.com/v1"
                        filterOption={(input, option) =>
                            (option?.value as string)?.toLowerCase().includes(input.toLowerCase())
                        }
                    />
                </Form.Item>
                <Form.Item label="API Key" name="api_key" extra={maskedKey ? `当前：${maskedKey}` : undefined}>
                    <Input.Password placeholder={hasKey ? '留空则保留当前 Key' : '输入 API Key'} autoComplete="new-password" />
                </Form.Item>
                <Form.Item
                    label={
                        <Space>
                            <span>模型</span>
                            <Button
                                type="link"
                                size="small"
                                icon={<CloudSyncOutlined />}
                                loading={modelsLoading}
                                onClick={handleFetchModels}
                                style={{ padding: 0, height: 'auto' }}
                            >
                                获取模型列表
                            </Button>
                            {modelsLoading && <Spin size="small" />}
                        </Space>
                    }
                    name="model"
                    rules={[{ required: true, message: '请选择或输入模型名' }]}
                    extra={
                        modelsError
                            ? <Text type="danger" style={{ fontSize: 12 }}>{modelsError}，可手动输入模型名</Text>
                            : models.length > 0
                                ? <Text type="secondary" style={{ fontSize: 12 }}>已加载 {models.length} 个可用模型</Text>
                                : <Text type="secondary" style={{ fontSize: 12 }}>点击「获取模型列表」从 API 加载，或直接手动输入</Text>
                    }
                >
                    <AutoComplete
                        options={modelOptions}
                        placeholder={modelsLoading ? '加载中...' : '选择或输入模型名'}
                        filterOption={(input, option) =>
                            (option?.value as string)?.toLowerCase().includes(input.toLowerCase())
                        }
                    />
                </Form.Item>
            </Form>

            {testResult && (
                <div style={{ marginTop: 16 }}>
                    <Alert
                        type={testResult.success ? 'success' : 'error'}
                        showIcon
                        message={testResult.success ? '连接测试成功' : '连接测试失败'}
                        description={
                            <div style={{ marginTop: 8 }}>
                                <p><strong>Base URL：</strong>{testResult.base_url}</p>
                                <p><strong>模型：</strong>{testResult.model}</p>
                                <p><strong>耗时：</strong>{testResult.elapsed_ms}ms</p>
                                {testResult.success && testResult.response && (
                                    <p><strong>模型响应：</strong><Text code>{testResult.response}</Text></p>
                                )}
                                {testResult.error && (
                                    <p><strong>错误信息：</strong><Text type="danger">{testResult.error}</Text></p>
                                )}
                            </div>
                        }
                    />
                </div>
            )}
        </ProCard>
    );

    const renderPromptTab = () => (
        <ProCard className="glass-card" style={{ background: 'transparent', border: 'none', padding: 0 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, marginBottom: 16, flexWrap: 'wrap' }}>
                <Space>
                    <Tag color="blue">Registry v{promptRegistry?.version || '-'}</Tag>
                    {promptRegistry?.source && <Text type="secondary">{promptRegistry.source}</Text>}
                </Space>
                <Button icon={<ReloadOutlined />} onClick={fetchPromptRegistry} loading={promptLoading}>
                    刷新
                </Button>
            </div>

            <Collapse
                style={{ marginBottom: 16 }}
                items={[
                    {
                        key: 'base',
                        label: 'Base Prompt',
                        children: (
                            <Paragraph style={{ whiteSpace: 'pre-wrap', marginBottom: 0 }}>
                                {promptRegistry?.base_prompt || '暂无数据'}
                            </Paragraph>
                        ),
                    },
                ]}
            />

            <Table
                rowKey="module"
                loading={promptLoading}
                dataSource={promptProfiles}
                pagination={false}
                columns={[
                    {
                        title: '模块',
                        dataIndex: 'module',
                        width: 180,
                        render: (value: string, row: API.CopilotPromptProfile) => (
                            <Space direction="vertical" size={2}>
                                <Text strong>{value}</Text>
                                <Text type="secondary" style={{ fontSize: 12 }}>{row.label}</Text>
                            </Space>
                        ),
                    },
                    {
                        title: '工具白名单',
                        dataIndex: 'tools',
                        render: (tools: string[]) => (
                            <Space wrap>
                                {(tools || []).map((tool) => <Tag key={tool}>{tool}</Tag>)}
                            </Space>
                        ),
                    },
                    {
                        title: 'Aliases',
                        dataIndex: 'aliases',
                        width: 180,
                        render: (aliases?: string[]) => aliases?.length ? (
                            <Space wrap>{aliases.map((alias) => <Tag key={alias} color="geekblue">{alias}</Tag>)}</Space>
                        ) : <Text type="secondary">-</Text>,
                    },
                    {
                        title: '轮次',
                        dataIndex: 'max_turns',
                        width: 90,
                        render: (value: number) => <Tag color="purple">{value}</Tag>,
                    },
                    {
                        title: '操作',
                        width: 110,
                        render: (_: unknown, row: API.CopilotPromptProfile) => (
                            <Button size="small" icon={<EyeOutlined />} onClick={() => setSelectedPrompt(row)}>
                                详情
                            </Button>
                        ),
                    },
                ]}
            />

            {promptRegistry?.actions?.length ? (
                <div style={{ marginTop: 24 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, marginBottom: 12, flexWrap: 'wrap' }}>
                        <Space>
                            <Text strong>待确认动作白名单</Text>
                            <Tag color="green">{promptRegistry.actions.length} 个动作</Tag>
                        </Space>
                        <Text type="secondary">所有动作都需要用户确认、RBAC 校验和审计记录。</Text>
                    </div>
                    <Table
                        rowKey="action_type"
                        size="small"
                        pagination={false}
                        dataSource={promptRegistry.actions}
                        columns={[
                            {
                                title: '动作',
                                dataIndex: 'action_type',
                                width: 220,
                                render: (value: string) => <Text code>{value}</Text>,
                            },
                            {
                                title: '风险',
                                dataIndex: 'risk_level',
                                width: 90,
                                render: (value: string) => <Tag color={value === 'medium' ? 'orange' : value === 'high' ? 'red' : 'green'}>{value || '-'}</Tag>,
                            },
                            {
                                title: '权限',
                                dataIndex: 'required_role',
                                width: 100,
                                render: (value: string) => <Tag>{value || '-'}</Tag>,
                            },
                            {
                                title: '参数',
                                dataIndex: 'params',
                                render: (params: string[]) => (
                                    <Space wrap>
                                        {(params || []).map((param) => <Tag key={param}>{param}</Tag>)}
                                    </Space>
                                ),
                            },
                            {
                                title: '语义',
                                dataIndex: 'description',
                                render: (value: string) => value || '-',
                            },
                        ]}
                    />
                </div>
            ) : null}
        </ProCard>
    );

    const renderAuditTab = () => (
        <ProCard className="glass-card" style={{ background: 'transparent', border: 'none', padding: 0 }}>
            <Form
                form={auditForm}
                layout="inline"
                onFinish={(values) => fetchAudit(1, auditPageSize, values)}
                style={{ marginBottom: 16, rowGap: 8 }}
            >
                <Form.Item name="module" label="模块">
                    <Input allowClear placeholder="如 poc_inline" style={{ width: 170 }} />
                </Form.Item>
                <Form.Item name="tool_name" label="工具/动作">
                    <Input allowClear placeholder="如 node_capacity" style={{ width: 210 }} />
                </Form.Item>
                <Form.Item name="status" label="状态">
                    <Select
                        allowClear
                        placeholder="全部"
                        style={{ width: 130 }}
                        options={[
                            { value: 'success', label: 'success' },
                            { value: 'error', label: 'error' },
                        ]}
                    />
                </Form.Item>
                <Form.Item>
                    <Space>
                        <Button type="primary" htmlType="submit">筛选</Button>
                        <Button
                            onClick={() => {
                                auditForm.resetFields();
                                fetchAudit(1, auditPageSize, {});
                            }}
                        >
                            重置
                        </Button>
                        <Button icon={<ReloadOutlined />} onClick={() => fetchAudit(auditPage, auditPageSize, auditFilters)} loading={auditLoading}>
                            刷新
                        </Button>
                    </Space>
                </Form.Item>
            </Form>

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
                columns={[
                    {
                        title: '时间',
                        dataIndex: 'created_at',
                        width: 180,
                        render: formatTime,
                    },
                    {
                        title: '模块',
                        dataIndex: 'module',
                        width: 150,
                        render: (value: string) => value || '-',
                    },
                    {
                        title: '工具/动作',
                        dataIndex: 'tool_name',
                        render: (value: string) => <Text code>{value}</Text>,
                    },
                    {
                        title: '状态',
                        dataIndex: 'status',
                        width: 100,
                        render: (value: string) => <Tag color={statusColor(value)}>{value || '-'}</Tag>,
                    },
                    {
                        title: '耗时',
                        dataIndex: 'duration_ms',
                        width: 100,
                        render: (value: number) => `${value || 0}ms`,
                    },
                    {
                        title: '操作',
                        width: 110,
                        render: (_: unknown, row: API.AIToolInvocation) => (
                            <Button size="small" icon={<EyeOutlined />} onClick={() => setSelectedAudit(row)}>
                                详情
                            </Button>
                        ),
                    },
                ]}
            />
        </ProCard>
    );

    const tabItems = [
        ...(isAdmin ? [{
            key: 'model',
            label: <span><RobotOutlined /> 模型配置</span>,
            children: renderModelTab(),
        }] : []),
        {
            key: 'prompt',
            label: <span><FileTextOutlined /> Copilot Prompt</span>,
            children: renderPromptTab(),
        },
        {
            key: 'audit',
            label: <span><AuditOutlined /> 工具审计</span>,
            children: renderAuditTab(),
        },
    ];

    return (
        <div ref={pageRef} style={{ position: 'relative', overflow: 'hidden' }}>
            <NetworkCanvas color="#6366f1" count={25} speed={0.12} linkDist={90} />
            <div className="sys-animate-in" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16, position: 'relative', zIndex: 1 }}>
                <Space>
                    <RobotOutlined style={{ color: '#6366f1' }} />
                    <Text strong>AI Copilot 管理</Text>
                    <Tag color={isAdmin ? 'gold' : 'blue'}>{isAdmin ? 'admin' : 'operator'}</Tag>
                </Space>
                {!isAdmin && <Text type="secondary">模型连接配置仅管理员可见；当前可管理 Prompt 与自己的审计记录。</Text>}
            </div>

            <div className="sys-animate-in" style={{ position: 'relative', zIndex: 1 }}>
                <Tabs activeKey={activeTab} onChange={setActiveTab} items={tabItems} />
            </div>

            <Drawer
                title={selectedPrompt?.label || selectedPrompt?.module || 'Prompt 详情'}
                width={760}
                open={!!selectedPrompt}
                onClose={() => setSelectedPrompt(null)}
            >
                {selectedPrompt && (
                    <Space direction="vertical" size={16} style={{ width: '100%' }}>
                        <Descriptions column={1} bordered size="small" items={[
                            { key: 'module', label: '模块', children: selectedPrompt.module },
                            { key: 'description', label: '描述', children: selectedPrompt.description || '-' },
                            { key: 'max_turns', label: '最大轮次', children: selectedPrompt.max_turns },
                            { key: 'aliases', label: 'Aliases', children: selectedPrompt.aliases?.length ? selectedPrompt.aliases.join(', ') : '-' },
                            { key: 'tools', label: '工具白名单', children: selectedPrompt.tools?.join(', ') || '-' },
                        ]} />
                        <div>
                            <Text strong>模块 Prompt</Text>
                            <Paragraph style={{ whiteSpace: 'pre-wrap', marginTop: 8 }}>{selectedPrompt.prompt || '-'}</Paragraph>
                        </div>
                        <div>
                            <Text strong>最终 System Prompt</Text>
                            <Paragraph style={{ whiteSpace: 'pre-wrap', marginTop: 8 }}>{selectedPrompt.system_prompt}</Paragraph>
                        </div>
                    </Space>
                )}
            </Drawer>

            <Drawer
                title="审计详情"
                width={720}
                open={!!selectedAudit}
                onClose={() => setSelectedAudit(null)}
            >
                {selectedAudit && (
                    <Space direction="vertical" size={16} style={{ width: '100%' }}>
                        <Descriptions column={1} bordered size="small" items={[
                            { key: 'id', label: 'ID', children: selectedAudit.id },
                            { key: 'created_at', label: '时间', children: formatTime(selectedAudit.created_at) },
                            { key: 'user_id', label: '用户', children: selectedAudit.user_id || '-' },
                            { key: 'module', label: '模块', children: selectedAudit.module || '-' },
                            { key: 'tool_name', label: '工具/动作', children: selectedAudit.tool_name || '-' },
                            { key: 'status', label: '状态', children: <Tag color={statusColor(selectedAudit.status)}>{selectedAudit.status}</Tag> },
                            { key: 'duration', label: '耗时', children: `${selectedAudit.duration_ms || 0}ms` },
                            { key: 'agent', label: 'Agent', children: selectedAudit.agent_id || '-' },
                            { key: 'target', label: 'Target URL', children: selectedAudit.target_url || '-' },
                        ]} />
                        <div>
                            <Text strong>参数摘要</Text>
                            <Paragraph style={{ whiteSpace: 'pre-wrap', marginTop: 8 }}>{selectedAudit.args_summary || '-'}</Paragraph>
                        </div>
                        {selectedAudit.error_summary && (
                            <Alert type="error" showIcon message="错误摘要" description={selectedAudit.error_summary} />
                        )}
                    </Space>
                )}
            </Drawer>
        </div>
    );
};

export default AIConfig;
