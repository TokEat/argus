import React, { useCallback, useEffect, useMemo, useState } from 'react';
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
    InputNumber,
    Popconfirm,
    Select,
    Space,
    Spin,
    Switch,
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
    SafetyCertificateOutlined,
    SaveOutlined,
    SecurityScanOutlined,
    ThunderboltOutlined,
} from '@ant-design/icons';
import {
    dismissSentinelEvent,
    executeSentinelEvent,
    getAIConfig,
    getAITriageConfig,
    getContentAnalysisConfig,
    getCopilotPromptProfiles,
    getSentinelConfig,
    listAIToolInvocations,
    listAIModels,
    listSentinelEvents,
    saveAIConfig,
    testAIConnection,
    updateAITriageConfig,
    updateContentAnalysisConfig,
    updateSentinelConfig,
} from '../services/api';
import { canAccessRole, getCurrentUserRole } from '../utils/auth';
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

const sentinelClassificationColor = (value?: string) => {
    switch (value) {
        case 'banned': return 'red';
        case 'rate_limited': return 'orange';
        case 'waf_challenge': return 'volcano';
        case 'target_down': return 'geekblue';
        case 'scanner_bug': return 'purple';
        case 'false_positive': return 'default';
        default: return 'gold'; // pending
    }
};

const sentinelClassificationLabel = (value?: string) => {
    switch (value) {
        case 'banned': return '已封禁';
        case 'rate_limited': return '被限速';
        case 'waf_challenge': return 'WAF 拦截';
        case 'target_down': return '目标宕机';
        case 'scanner_bug': return '扫描器故障';
        case 'false_positive': return '规则误报';
        case 'pending': return '待研判';
        default: return value || '-';
    }
};

const sentinelActionLabel = (value?: string) => {
    switch (value) {
        case 'backoff': return '退避冷却';
        case 'rescan_other_node': return '换节点重扫';
        case 'flag_findings': return '标记 finding 污点';
        case 'halt': return '建议暂停';
        case 'none': return '无需处理';
        default: return value || '-';
    }
};

const sentinelEventStatusColor = (value?: string) => {
    switch (value) {
        case 'open': return 'gold';
        case 'executed': return 'green';
        case 'dismissed': return 'default';
        case 'expired': return 'cyan';
        default: return 'default';
    }
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

    const [triageConfig, setTriageConfig] = useState<API.AITriageConfig | null>(null);
    const [triageSaving, setTriageSaving] = useState(false);
    const [contentConfig, setContentConfig] = useState<API.ContentAnalysisConfig | null>(null);
    const [contentSaving, setContentSaving] = useState(false);
    const [sentinelConfig, setSentinelConfig] = useState<API.SentinelConfig | null>(null);
    const [sentinelSaving, setSentinelSaving] = useState(false);
    const [sentinelEvents, setSentinelEvents] = useState<API.SentinelEvent[]>([]);
    const [sentinelTotal, setSentinelTotal] = useState(0);
    const [sentinelPage, setSentinelPage] = useState(1);
    const [sentinelLoading, setSentinelLoading] = useState(false);
    const [sentinelStatusFilter, setSentinelStatusFilter] = useState<string>('open');
    const [sentinelActing, setSentinelActing] = useState<number | null>(null);

    const { message } = App.useApp();
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

    const fetchTriageConfig = useCallback(async () => {
        if (!isAdmin) return;
        try {
            setTriageConfig(await getAITriageConfig());
        } catch (err: unknown) {
            message.error(typeof err === 'string' ? err : '加载研判开关失败');
        }
    }, [isAdmin, message]);

    const handleTriageChange = async (patch: Partial<API.AITriageConfig>) => {
        const next = { ...triageConfig, ...patch } as API.AITriageConfig;
        setTriageConfig(next);
        setTriageSaving(true);
        try {
            const saved = await updateAITriageConfig(patch);
            setTriageConfig(saved);
            message.success('研判开关已保存');
        } catch (err: unknown) {
            message.error(typeof err === 'string' ? err : '保存研判开关失败');
            fetchTriageConfig();
        } finally {
            setTriageSaving(false);
        }
    };

    const fetchContentConfig = useCallback(async () => {
        if (!isAdmin) return;
        try {
            setContentConfig(await getContentAnalysisConfig());
        } catch (err: unknown) {
            message.error(typeof err === 'string' ? err : '加载内容分析开关失败');
        }
    }, [isAdmin, message]);

    const handleContentChange = async (patch: Partial<API.ContentAnalysisConfig>) => {
        const next = { ...contentConfig, ...patch } as API.ContentAnalysisConfig;
        setContentConfig(next);
        setContentSaving(true);
        try {
            const saved = await updateContentAnalysisConfig(patch);
            setContentConfig(saved);
            message.success('内容分析开关已保存');
        } catch (err: unknown) {
            message.error(typeof err === 'string' ? err : '保存内容分析开关失败');
            fetchContentConfig();
        } finally {
            setContentSaving(false);
        }
    };

    const fetchSentinelConfig = useCallback(async () => {
        if (!isAdmin) return;
        try {
            setSentinelConfig(await getSentinelConfig());
        } catch (err: unknown) {
            message.error(typeof err === 'string' ? err : '加载哨兵配置失败');
        }
    }, [isAdmin, message]);

    const handleSentinelChange = async (patch: Partial<API.SentinelConfig>) => {
        const next = { ...sentinelConfig, ...patch } as API.SentinelConfig;
        setSentinelConfig(next);
        setSentinelSaving(true);
        try {
            const saved = await updateSentinelConfig(patch);
            setSentinelConfig(saved);
            message.success('哨兵配置已保存');
        } catch (err: unknown) {
            message.error(typeof err === 'string' ? err : '保存哨兵配置失败');
            fetchSentinelConfig();
        } finally {
            setSentinelSaving(false);
        }
    };

    const fetchSentinelEvents = useCallback(async (page: number, status: string) => {
        setSentinelLoading(true);
        try {
            const resp = await listSentinelEvents({
                page,
                page_size: 20,
                ...(status ? { status } : {}),
            });
            setSentinelEvents(resp.items || []);
            setSentinelTotal(resp.total || 0);
            setSentinelPage(page);
        } catch (err: unknown) {
            message.error(typeof err === 'string' ? err : '加载哨兵事件失败');
        } finally {
            setSentinelLoading(false);
        }
    }, [message]);

    const handleSentinelExecute = async (row: API.SentinelEvent) => {
        setSentinelActing(row.ID);
        try {
            await executeSentinelEvent(row.ID);
            message.success('已执行建议动作');
            fetchSentinelEvents(sentinelPage, sentinelStatusFilter);
        } catch (err: unknown) {
            message.error(typeof err === 'string' ? err : '执行失败');
        } finally {
            setSentinelActing(null);
        }
    };

    const handleSentinelDismiss = async (row: API.SentinelEvent) => {
        setSentinelActing(row.ID);
        try {
            await dismissSentinelEvent(row.ID);
            message.success('已忽略该事件');
            fetchSentinelEvents(sentinelPage, sentinelStatusFilter);
        } catch (err: unknown) {
            message.error(typeof err === 'string' ? err : '忽略失败');
        } finally {
            setSentinelActing(null);
        }
    };

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
            fetchSentinelConfig();
            fetchSentinelEvents(1, 'open');
        }
        fetchPromptRegistry();
        fetchAudit(1, 50, {});
        fetchTriageConfig();
        fetchContentConfig();
    }, [fetchAudit, fetchConfig, fetchPromptRegistry, fetchTriageConfig, fetchSentinelConfig, fetchContentConfig, isAdmin]);

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

            <div style={{ marginTop: 24, borderTop: '1px solid #eef2f7', paddingTop: 16 }}>
                <div style={{ marginBottom: 12 }}>
                    <Text strong><SafetyCertificateOutlined /> 误报研判开关</Text>
                    <div style={{ marginTop: 4 }}>
                        <Text type="secondary" style={{ fontSize: 12 }}>
                            漏洞落库后由后台 worker 异步调用模型复核误报，结果写入 ai_status / 置信度 / 理由，人工可覆写。
                        </Text>
                    </div>
                </div>
                {triageConfig ? (
                    <Space direction="vertical" size={12} style={{ width: '100%', maxWidth: 520 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <Space direction="vertical" size={0}>
                                <Text>启用 AI 误报研判</Text>
                                <Text type="secondary" style={{ fontSize: 12 }}>关闭后后台 worker 停止自动研判</Text>
                            </Space>
                            <Switch
                                checked={triageConfig.enabled}
                                loading={triageSaving}
                                onChange={(v) => handleTriageChange({ enabled: v })}
                            />
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <Space direction="vertical" size={0}>
                                <Text>高置信误报自动抑制</Text>
                                <Text type="secondary" style={{ fontSize: 12 }}>
                                    研判为疑似误报且置信度 ≥ 阈值时，自动将漏洞置为 false_positive
                                </Text>
                            </Space>
                            <Switch
                                checked={triageConfig.auto_suppress}
                                loading={triageSaving}
                                onChange={(v) => handleTriageChange({ auto_suppress: v })}
                            />
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <Space direction="vertical" size={0}>
                                <Text>抑制置信度阈值</Text>
                                <Text type="secondary" style={{ fontSize: 12 }}>范围 (0, 1]，默认 0.85</Text>
                            </Space>
                            <InputNumber
                                min={0.01}
                                max={1}
                                step={0.05}
                                value={triageConfig.confidence_threshold}
                                disabled={triageSaving}
                                onChange={(v) => {
                                    if (v != null) setTriageConfig({ ...triageConfig, confidence_threshold: v });
                                }}
                                onBlur={() => {
                                    if (triageConfig.confidence_threshold > 0 && triageConfig.confidence_threshold <= 1) {
                                        handleTriageChange({ confidence_threshold: triageConfig.confidence_threshold });
                                    }
                                }}
                            />
                        </div>
                    </Space>
                ) : (
                    <Spin size="small" />
                )}
            </div>

            <div style={{ marginTop: 24, borderTop: '1px solid #eef2f7', paddingTop: 16 }}>
                <div style={{ marginBottom: 12 }}>
                    <Text strong><FileTextOutlined /> AI 内容分析（爬取 / 敏感信息）</Text>
                    <div style={{ marginTop: 4 }}>
                        <Text type="secondary" style={{ fontSize: 12 }}>
                            主动爬取发现的"同主机不同站点"关联资产候选、页面/JS 敏感信息候选，由后台 worker 异步调用模型做价值研判 / 判重 / 结构化提取。
                            需任务开启对应能力及 AI 子开关；全局关闭后 worker 停止研判。
                        </Text>
                    </div>
                </div>
                {contentConfig ? (
                    <Space direction="vertical" size={12} style={{ width: '100%', maxWidth: 520 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <Space direction="vertical" size={0}>
                                <Text>启用 AI 内容分析</Text>
                                <Text type="secondary" style={{ fontSize: 12 }}>关闭后关联资产研判与敏感信息提取全部停止</Text>
                            </Space>
                            <Switch
                                checked={contentConfig.enabled}
                                loading={contentSaving}
                                onChange={(v) => handleContentChange({ enabled: v })}
                            />
                        </div>
                    </Space>
                ) : (
                    <Spin size="small" />
                )}
            </div>
        </ProCard>
    );

    const renderSentinelTab = () => (
        <ProCard className="glass-card" style={{ background: 'transparent', border: 'none', padding: 0 }}>
            <div style={{ marginBottom: 16 }}>
                <Text strong><SecurityScanOutlined /> 扫描对抗哨兵</Text>
                <div style={{ marginTop: 4 }}>
                    <Text type="secondary" style={{ fontSize: 12 }}>
                        规则实时检测（同主机多端口同响应页 / 成功率突降）→ AI 研判分类与建议 → 策略门控执行。
                        AI 只收敛不扩大：退避/打污点自动执行，换节点重扫需开启自动执行或人工确认。
                    </Text>
                </div>
            </div>

            {sentinelConfig ? (
                <Space direction="vertical" size={12} style={{ width: '100%', maxWidth: 560, marginBottom: 24 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <Space direction="vertical" size={0}>
                            <Text>启用哨兵检测</Text>
                            <Text type="secondary" style={{ fontSize: 12 }}>关闭后规则检测 / AI 研判 / 自动执行全部停止</Text>
                        </Space>
                        <Switch
                            checked={sentinelConfig.enabled}
                            loading={sentinelSaving}
                            onChange={(v) => handleSentinelChange({ enabled: v })}
                        />
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <Space direction="vertical" size={0}>
                            <Text>自动执行换节点重扫</Text>
                            <Text type="secondary" style={{ fontSize: 12 }}>
                                关闭时换节点/暂停类动作保持待处理，需人工在事件列表确认执行
                            </Text>
                        </Space>
                        <Switch
                            checked={sentinelConfig.auto_execute}
                            loading={sentinelSaving}
                            onChange={(v) => handleSentinelChange({ auto_execute: v })}
                        />
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <Space direction="vertical" size={0}>
                            <Text>封禁冷却基数（分钟）</Text>
                            <Text type="secondary" style={{ fontSize: 12 }}>已封禁出口按此冷却，封禁×3、WAF×2，默认 10</Text>
                        </Space>
                        <InputNumber
                            min={1}
                            max={1440}
                            value={sentinelConfig.cooldown_minutes}
                            disabled={sentinelSaving}
                            onChange={(v) => {
                                if (v != null) setSentinelConfig({ ...sentinelConfig, cooldown_minutes: v });
                            }}
                            onBlur={() => {
                                if (sentinelConfig.cooldown_minutes >= 1) {
                                    handleSentinelChange({ cooldown_minutes: sentinelConfig.cooldown_minutes });
                                }
                            }}
                        />
                    </div>
                </Space>
            ) : (
                <Spin size="small" />
            )}

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                <Space>
                    <Text strong>对抗事件</Text>
                    <Select
                        size="small"
                        value={sentinelStatusFilter}
                        style={{ width: 130 }}
                        onChange={(v) => {
                            setSentinelStatusFilter(v);
                            fetchSentinelEvents(1, v);
                        }}
                        options={[
                            { value: 'open', label: '待处理' },
                            { value: 'executed', label: '已执行' },
                            { value: 'dismissed', label: '已忽略' },
                            { value: '', label: '全部' },
                        ]}
                    />
                </Space>
                <Button size="small" icon={<ReloadOutlined />} onClick={() => fetchSentinelEvents(sentinelPage, sentinelStatusFilter)} loading={sentinelLoading}>
                    刷新
                </Button>
            </div>

            <Table<API.SentinelEvent>
                rowKey="ID"
                size="small"
                loading={sentinelLoading}
                dataSource={sentinelEvents}
                pagination={{
                    current: sentinelPage,
                    pageSize: 20,
                    total: sentinelTotal,
                    showSizeChanger: false,
                    onChange: (page) => fetchSentinelEvents(page, sentinelStatusFilter),
                }}
                expandable={{
                    expandedRowRender: (row: API.SentinelEvent) => (
                        <Space direction="vertical" size={6} style={{ width: '100%' }}>
                            {row.ActionReason && (
                                <div><Text type="secondary">研判理由：</Text><Text>{row.ActionReason}</Text></div>
                            )}
                            <div>
                                <Text type="secondary">证据：</Text>
                                <Paragraph copyable code style={{ whiteSpace: 'pre-wrap', marginBottom: 0, fontSize: 12 }}>
                                    {row.Evidence || '-'}
                                </Paragraph>
                            </div>
                        </Space>
                    ),
                }}
                columns={[
                    {
                        title: 'ID',
                        dataIndex: 'ID',
                        width: 70,
                    },
                    {
                        title: '信号',
                        dataIndex: 'SignalType',
                        width: 130,
                        render: (value: string) => (
                            <Tag color={value === 'homogeneity' ? 'volcano' : 'geekblue'}>{value}</Tag>
                        ),
                    },
                    {
                        title: '目标 / 主机',
                        dataIndex: 'Target',
                        render: (_: string, row: API.SentinelEvent) => (
                            <Space direction="vertical" size={0}>
                                <Text code>{row.Host || row.Target || '-'}</Text>
                                {row.AgentID && <Text type="secondary" style={{ fontSize: 12 }}>节点 {row.AgentID}</Text>}
                            </Space>
                        ),
                    },
                    {
                        title: 'AI 分类',
                        dataIndex: 'Classification',
                        width: 120,
                        render: (value: string) => (
                            <Tag color={sentinelClassificationColor(value)}>{sentinelClassificationLabel(value)}</Tag>
                        ),
                    },
                    {
                        title: '置信度',
                        dataIndex: 'Confidence',
                        width: 80,
                        render: (value: number) => (value > 0 ? `${(value * 100).toFixed(0)}%` : '-'),
                    },
                    {
                        title: '建议动作',
                        dataIndex: 'RecommendedAction',
                        width: 130,
                        render: (value: string) => sentinelActionLabel(value),
                    },
                    {
                        title: '状态',
                        dataIndex: 'Status',
                        width: 90,
                        render: (value: string) => (
                            <Tag color={sentinelEventStatusColor(value)}>{value}</Tag>
                        ),
                    },
                    {
                        title: '时间',
                        dataIndex: 'CreatedAt',
                        width: 150,
                        render: formatTime,
                    },
                    {
                        title: '操作',
                        width: 150,
                        render: (_: unknown, row: API.SentinelEvent) => (
                            row.Status === 'open' ? (
                                <Space>
                                    <Popconfirm
                                        title="执行建议动作？"
                                        description={sentinelActionLabel(row.RecommendedAction)}
                                        okText="执行"
                                        cancelText="取消"
                                        onConfirm={() => handleSentinelExecute(row)}
                                    >
                                        <Button size="small" type="primary" loading={sentinelActing === row.ID}>
                                            执行
                                        </Button>
                                    </Popconfirm>
                                    <Popconfirm
                                        title="忽略该事件？"
                                        okText="忽略"
                                        cancelText="取消"
                                        onConfirm={() => handleSentinelDismiss(row)}
                                    >
                                        <Button size="small" loading={sentinelActing === row.ID}>
                                            忽略
                                        </Button>
                                    </Popconfirm>
                                </Space>
                            ) : (
                                <Text type="secondary" style={{ fontSize: 12 }}>
                                    {row.ExecutedBy ? `${row.Status} by ${row.ExecutedBy}` : row.Status}
                                </Text>
                            )
                        ),
                    },
                ]}
            />
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
        ...(isAdmin ? [{
            key: 'sentinel',
            label: <span><SecurityScanOutlined /> 扫描对抗哨兵</span>,
            children: renderSentinelTab(),
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
        <div style={{ position: 'relative', overflow: 'hidden' }}>
            <NetworkCanvas color="#6366f1" count={25} speed={0.12} linkDist={90} />
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16, position: 'relative', zIndex: 1 }}>
                <Space>
                    <RobotOutlined style={{ color: '#6366f1' }} />
                    <Text strong>AI Copilot 管理</Text>
                    <Tag color={isAdmin ? 'gold' : 'blue'}>{isAdmin ? 'admin' : 'operator'}</Tag>
                </Space>
                {!isAdmin && <Text type="secondary">模型连接配置仅管理员可见；当前可管理 Prompt 与自己的审计记录。</Text>}
            </div>

            <div style={{ position: 'relative', zIndex: 1 }}>
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
