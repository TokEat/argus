import React, { useEffect, useState } from 'react';
import { App, Button, Form, Input, Space, Tag, Typography } from 'antd';
import { ProCard } from '@ant-design/pro-components';
import { ReloadOutlined, RobotOutlined, SaveOutlined } from '@ant-design/icons';
import { getAIConfig, saveAIConfig } from '../services/api';

const { Text } = Typography;

const AIConfig: React.FC = () => {
    const [form] = Form.useForm<API.AIConfig>();
    const [loading, setLoading] = useState(false);
    const [saving, setSaving] = useState(false);
    const [hasKey, setHasKey] = useState(false);
    const [maskedKey, setMaskedKey] = useState('');
    const { message } = App.useApp();

    const fetchConfig = async () => {
        setLoading(true);
        try {
            const cfg = await getAIConfig();
            form.setFieldsValue({
                base_url: cfg.base_url || 'https://api.openai.com/v1',
                model: cfg.model,
                api_key: '',
            });
            setHasKey(!!cfg.has_api_key);
            setMaskedKey(cfg.api_key_masked || '');
        } catch (err: unknown) {
            message.error(typeof err === 'string' ? err : '加载 AI 配置失败');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchConfig();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

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
        } catch (err: unknown) {
            message.error(typeof err === 'string' ? err : '保存 AI 配置失败');
        } finally {
            setSaving(false);
        }
    };

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
                        <Input placeholder="https://api.openai.com/v1" />
                    </Form.Item>
                    <Form.Item
                        label="模型"
                        name="model"
                        rules={[{ required: true, message: '请输入模型名' }]}
                    >
                        <Input placeholder="gpt-4o-mini / deepseek-chat / your-model" />
                    </Form.Item>
                    <Form.Item label="API Key" name="api_key" extra={maskedKey ? `当前：${maskedKey}` : undefined}>
                        <Input.Password placeholder={hasKey ? '留空则保留当前 Key' : '输入 API Key'} autoComplete="new-password" />
                    </Form.Item>
                </Form>
            </ProCard>
        </div>
    );
};

export default AIConfig;

