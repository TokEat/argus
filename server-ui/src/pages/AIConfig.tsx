import React, { useCallback, useEffect, useState } from 'react';
import { Alert, App, AutoComplete, Button, Form, Input, Space, Spin, Tag, Typography } from 'antd';
import { ProCard } from '@ant-design/pro-components';
import { ReloadOutlined, RobotOutlined, SaveOutlined, CloudSyncOutlined, ThunderboltOutlined } from '@ant-design/icons';
import { getAIConfig, saveAIConfig, listAIModels, testAIConnection } from '../services/api';

const { Text } = Typography;

/** Base URL 快捷提示（仅 URL 提示，不硬编码模型） */
const baseURLHints = [
    { label: 'OpenAI', value: 'https://api.openai.com/v1' },
    { label: 'DeepSeek', value: 'https://api.deepseek.com' },
    { label: '阿里通义千问', value: 'https://dashscope.aliyuncs.com/compatible-mode/v1' },
    { label: '月之暗面 Kimi', value: 'https://api.moonshot.cn/v1' },
    { label: '智谱 GLM', value: 'https://open.bigmodel.cn/api/paas/v4' },
    { label: 'Ollama 本地', value: 'http://localhost:11434/v1' },
];

const AIConfig: React.FC = () => {
    const [form] = Form.useForm<API.AIConfig>();
    const [loading, setLoading] = useState(false);
    const [saving, setSaving] = useState(false);
    const [hasKey, setHasKey] = useState(false);
    const [maskedKey, setMaskedKey] = useState('');
    const [models, setModels] = useState<API.AIModelInfo[]>([]);
    const [modelsLoading, setModelsLoading] = useState(false);
    const [modelsError, setModelsError] = useState('');
    const [testing, setTesting] = useState(false);
    const [testResult, setTestResult] = useState<{ success: boolean; response?: string; error?: string; elapsed_ms: number; base_url: string; model: string } | null>(null);
    const { message } = App.useApp();

    const fetchConfig = async () => {
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
            // 有已保存的 key 时自动拉取模型列表
            if (cfg.has_api_key) {
                fetchModels();
            }
        } catch (err: unknown) {
            message.error(typeof err === 'string' ? err : '加载 AI 配置失败');
        } finally {
            setLoading(false);
        }
    };

    /** 从已保存配置（或当前表单值）拉取可用模型 */
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

    useEffect(() => {
        fetchConfig();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    /** 手动触发拉取模型列表（使用表单中当前填写的值） */
    const handleFetchModels = () => {
        const baseURL = form.getFieldValue('base_url');
        const apiKey = form.getFieldValue('api_key');
        // 如果表单里有新输入的 key，用它探测；否则用已保存的
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
            // 保存后刷新模型列表
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

    return (
        <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                <Space>
                    <RobotOutlined style={{ color: '#6366f1' }} />
                    <Text strong>AI 模型配置</Text>
                    {hasKey ? <Tag color="green">已配置 Key</Tag> : <Tag>未配置 Key</Tag>}
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

            <ProCard className="glass-card" style={{ background: 'transparent', border: 'none', padding: 0 }}>
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
        </div>
    );
};

export default AIConfig;
