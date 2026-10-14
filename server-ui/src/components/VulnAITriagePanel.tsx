import React, { useCallback, useEffect, useState } from 'react';
import { App, Button, Divider, Empty, Popconfirm, Space, Spin, Tag, Typography } from 'antd';
import {
    CheckCircleOutlined,
    CloseCircleOutlined,
    QuestionCircleOutlined,
    ReloadOutlined,
    RobotOutlined,
} from '@ant-design/icons';
import dayjs from 'dayjs';
import { getVulnAIReview, overrideVulnAIReview, retriggerVulnAIReview } from '../services/api';

const { Text, Paragraph } = Typography;

interface TriageDetail {
    ai_status: string;
    ai_confidence: number;
    ai_reason: string;
    ai_triaged_at?: string;
    reviews: API.AIFindingReview[];
}

const VERDICT_META: Record<string, { color: string; label: string; icon: React.ReactNode }> = {
    confirmed: { color: 'green', label: '确认真实', icon: <CheckCircleOutlined /> },
    likely_false_positive: { color: 'orange', label: '疑似误报', icon: <CloseCircleOutlined /> },
    uncertain: { color: 'default', label: '不确定', icon: <QuestionCircleOutlined /> },
};

export const aiVerdictMeta = (verdict?: string) => {
    if (!verdict) return undefined;
    return VERDICT_META[verdict];
};

export const AIVerdictTag: React.FC<{ verdict?: string }> = ({ verdict }) => {
    if (!verdict) return <Text type="secondary" style={{ fontSize: 12 }}>未研判</Text>;
    const meta = VERDICT_META[verdict];
    if (!meta) return <Tag>{verdict}</Tag>;
    return <Tag color={meta.color} icon={meta.icon}>{meta.label}</Tag>;
};

interface VulnAITriagePanelProps {
    vuln: API.Vulnerability;
    onChanged?: () => void;
}

const VulnAITriagePanel: React.FC<VulnAITriagePanelProps> = ({ vuln, onChanged }) => {
    const { message } = App.useApp();
    const [loading, setLoading] = useState(false);
    const [busy, setBusy] = useState('');
    const [detail, setDetail] = useState<TriageDetail | null>(null);

    const fetchDetail = useCallback(async () => {
        if (!vuln?.ID) return;
        setLoading(true);
        try {
            setDetail(await getVulnAIReview(vuln.ID));
        } catch (err: unknown) {
            message.error(typeof err === 'string' ? err : '加载 AI 研判失败');
        } finally {
            setLoading(false);
        }
    }, [vuln?.ID, message]);

    useEffect(() => {
        fetchDetail();
    }, [fetchDetail]);

    const handleRetrigger = async () => {
        setBusy('retrigger');
        try {
            await retriggerVulnAIReview(vuln.ID);
            message.success('已重新研判');
            await fetchDetail();
            onChanged?.();
        } catch (err: unknown) {
            message.error(typeof err === 'string' ? err : '重新研判失败');
        } finally {
            setBusy('');
        }
    };

    const handleOverride = async (verdict: string) => {
        setBusy(verdict);
        try {
            await overrideVulnAIReview(vuln.ID, { verdict });
            message.success('已记录人工判定');
            await fetchDetail();
            onChanged?.();
        } catch (err: unknown) {
            message.error(typeof err === 'string' ? err : '人工覆写失败');
        } finally {
            setBusy('');
        }
    };

    const current = detail?.ai_status || vuln.AIStatus;
    const confidence = detail?.ai_confidence ?? vuln.AIConfidence;
    const reason = detail?.ai_reason || vuln.AIReason;
    const triagedAt = detail?.ai_triaged_at || vuln.AITriagedAt;
    const reviews = detail?.reviews || [];

    return (
        <div>
            <Divider orientation="left" style={{ fontSize: 13 }}>
                <RobotOutlined /> AI 误报研判
            </Divider>
            <Spin spinning={loading}>
                <div style={{
                    background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 8,
                    padding: '12px 16px',
                }}>
                    <Space direction="vertical" size={10} style={{ width: '100%' }}>
                        <Space wrap size={8}>
                            <AIVerdictTag verdict={current} />
                            {current && confidence != null && confidence > 0 && (
                                <Tag color="blue">置信度 {(confidence * 100).toFixed(0)}%</Tag>
                            )}
                            {triagedAt && (
                                <Text type="secondary" style={{ fontSize: 12 }}>
                                    {dayjs(triagedAt).format('YYYY-MM-DD HH:mm:ss')}
                                </Text>
                            )}
                        </Space>

                        {reason && (
                            <Paragraph style={{ marginBottom: 0, fontSize: 13, color: '#334155', whiteSpace: 'pre-wrap' }}>
                                {reason}
                            </Paragraph>
                        )}

                        {!current && !loading && (
                            <Text type="secondary" style={{ fontSize: 12 }}>
                                尚未研判。等待后台研判 worker 处理，或手动触发。
                            </Text>
                        )}

                        <Space wrap>
                            <Button
                                size="small"
                                icon={<ReloadOutlined />}
                                loading={busy === 'retrigger'}
                                disabled={!!busy}
                                onClick={handleRetrigger}
                            >
                                重新研判
                            </Button>
                            <Popconfirm
                                title="确认为真实漏洞？"
                                description="将覆写 AI 判定，误报抑制状态会恢复为 open"
                                onConfirm={() => handleOverride('confirmed')}
                            >
                                <Button
                                    size="small"
                                    type="primary"
                                    ghost
                                    icon={<CheckCircleOutlined />}
                                    loading={busy === 'confirmed'}
                                    disabled={!!busy}
                                >
                                    确认真实
                                </Button>
                            </Popconfirm>
                            <Popconfirm
                                title="标记为误报？"
                                description="将覆写 AI 判定为疑似误报"
                                onConfirm={() => handleOverride('likely_false_positive')}
                            >
                                <Button
                                    size="small"
                                    danger
                                    icon={<CloseCircleOutlined />}
                                    loading={busy === 'likely_false_positive'}
                                    disabled={!!busy}
                                >
                                    标记误报
                                </Button>
                            </Popconfirm>
                        </Space>
                    </Space>
                </div>

                {reviews.length > 0 && (
                    <div style={{ marginTop: 12 }}>
                        <Text strong style={{ fontSize: 12 }}>研判历史</Text>
                        <Space direction="vertical" size={6} style={{ width: '100%', marginTop: 8 }}>
                            {reviews.map((rev) => (
                                <div key={rev.ID} style={{
                                    border: '1px solid #eef2f7', borderRadius: 6, padding: '8px 12px',
                                    background: rev.OverrideVerdict ? '#fffbe6' : '#fff',
                                }}>
                                    <Space wrap size={8}>
                                        <AIVerdictTag verdict={rev.OverrideVerdict || rev.Verdict} />
                                        {rev.Confidence > 0 && (
                                            <Text type="secondary" style={{ fontSize: 12 }}>
                                                {(rev.Confidence * 100).toFixed(0)}%
                                            </Text>
                                        )}
                                        {rev.Provider && <Tag style={{ fontSize: 11 }}>{rev.Provider}</Tag>}
                                        <Text type="secondary" style={{ fontSize: 12 }}>
                                            {rev.CreatedAt ? dayjs(rev.CreatedAt).format('YYYY-MM-DD HH:mm:ss') : ''}
                                        </Text>
                                    </Space>
                                    {rev.Reason && (
                                        <div style={{ fontSize: 12, color: '#475569', marginTop: 4 }}>{rev.Reason}</div>
                                    )}
                                    {rev.OverrideVerdict && (
                                        <div style={{ fontSize: 12, color: '#b45309', marginTop: 4 }}>
                                            人工覆写为「{VERDICT_META[rev.OverrideVerdict]?.label || rev.OverrideVerdict}」
                                            {rev.OverriddenBy ? `（${rev.OverriddenBy}）` : ''}
                                        </div>
                                    )}
                                </div>
                            ))}
                        </Space>
                    </div>
                )}

                {!loading && reviews.length === 0 && !current && (
                    <Empty description="暂无研判记录" image={Empty.PRESENTED_IMAGE_SIMPLE} style={{ margin: '12px 0' }} />
                )}
            </Spin>
        </div>
    );
};

export default VulnAITriagePanel;
