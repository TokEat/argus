import React, { useEffect, useRef, useState } from 'react';
import { Alert, Button, Card, Space, Spin, Tag, Typography, App } from 'antd';
import { RobotOutlined, CheckCircleOutlined, CloseCircleOutlined, EditOutlined, StopOutlined, SyncOutlined } from '@ant-design/icons';
import { aiAnalyzeArsenalStream } from '../../services/api';

const { Text, Paragraph } = Typography;

interface PocAiPanelProps {
    pocContent: string;
    fileName: string;
    visible: boolean;
}

const PocAiPanel: React.FC<PocAiPanelProps> = ({ pocContent, fileName, visible }) => {
    const { message } = App.useApp();
    const [loading, setLoading] = useState(false);
    const [statusText, setStatusText] = useState('准备就绪');
    const [streamText, setStreamText] = useState('');
    const [result, setResult] = useState<API.AIAnalysisResult | null>(null);
    const [error, setError] = useState<string>('');
    const streamAbortRef = useRef<{ abort: () => void } | null>(null);
    const streamAreaRef = useRef<HTMLDivElement>(null);

    // Auto scroll stream text
    useEffect(() => {
        if (streamAreaRef.current) {
            streamAreaRef.current.scrollTop = streamAreaRef.current.scrollHeight;
        }
    }, [streamText]);

    const startAnalysis = () => {
        if (!pocContent.trim()) {
            message.warning('POC 内容为空，无法分析');
            return;
        }

        setLoading(true);
        setStatusText('正在连接分析引擎...');
        setStreamText('');
        setResult(null);
        setError('');

        const handle = aiAnalyzeArsenalStream(
            { type: 'poc', file_name: fileName || 'untitled.yaml', content: pocContent },
            {
                onStatus: (_phase, msg) => {
                    setStatusText(`⏳ ${msg}`);
                },
                onToken: (content) => {
                    setStreamText((prev) => prev + content);
                },
                onResult: (res) => {
                    setResult(res);
                    setStatusText('✅ 分析完成');
                    setLoading(false);
                    streamAbortRef.current = null;
                },
                onError: (err) => {
                    setError(err);
                    setStatusText('❌ 分析出错');
                    setLoading(false);
                    streamAbortRef.current = null;
                },
            }
        );
        streamAbortRef.current = handle;
    };

    const stopAnalysis = () => {
        if (streamAbortRef.current) {
            streamAbortRef.current.abort();
            streamAbortRef.current = null;
            setStatusText('⏹️ 分析已手动终止');
            setLoading(false);
        }
    };

    // When the panel is hidden, we no longer stop the stream so analysis continues in background.
    // (Removed useEffect that calls stopAnalysis on !visible)

    const renderResult = () => {
        if (!result) return null;
        let color = 'orange';
        let icon = <EditOutlined />;
        let title = '建议修改';
        
        if (result.suggestion === 'Approve') {
            color = 'green';
            icon = <CheckCircleOutlined />;
            title = '建议通过';
        } else if (result.suggestion === 'Reject') {
            color = 'red';
            icon = <CloseCircleOutlined />;
            title = '建议拒绝';
        }

        return (
            <Card size="small" style={{ marginTop: 16, borderColor: color }}>
                <Space style={{ marginBottom: 8 }}>
                    <Tag color={color} icon={icon}>{title}</Tag>
                    <Text type="secondary">置信度: {(result.confidence * 100).toFixed(0)}%</Text>
                </Space>
                <Paragraph style={{ marginBottom: 8 }}>
                    <strong>核心原因：</strong> {result.reason}
                </Paragraph>
                <Paragraph style={{ marginBottom: 8 }}>
                    <strong>总结：</strong> {result.summary}
                </Paragraph>
                {result.issues && result.issues.length > 0 && (
                    <div style={{ marginTop: 12 }}>
                        <Text strong>具体问题发现：</Text>
                        <ul style={{ paddingLeft: 20, margin: '8px 0 0 0' }}>
                            {result.issues.map((issue, idx) => (
                                <li key={idx} style={{ marginBottom: 6 }}>
                                    <Tag color={issue.severity === 'high' || issue.severity === 'critical' ? 'red' : 'orange'} style={{ marginRight: 4 }}>
                                        {issue.severity}
                                    </Tag>
                                    <Text>{issue.message}</Text>
                                    <br />
                                    <Text type="secondary" style={{ fontSize: 12 }}>👉 {issue.suggestion}</Text>
                                </li>
                            ))}
                        </ul>
                    </div>
                )}
            </Card>
        );
    };

    return (
        <div style={{ display: visible ? 'flex' : 'none', flexDirection: 'column', height: '100%', paddingLeft: 16 }}>
            <div style={{ marginBottom: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Space>
                    <RobotOutlined style={{ fontSize: 18, color: '#1677ff' }} />
                    <Text strong style={{ fontSize: 16 }}>AI 智能分析</Text>
                </Space>
                <Space>
                    {loading ? (
                        <Button danger icon={<StopOutlined />} onClick={stopAnalysis} size="small">
                            终止
                        </Button>
                    ) : (
                        <Button type="primary" icon={<SyncOutlined />} onClick={startAnalysis} size="small">
                            {result || streamText || error ? '重新分析' : '开始分析'}
                        </Button>
                    )}
                </Space>
            </div>

            <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column' }}>
                <div style={{ marginBottom: 12 }}>
                    {loading && <Spin size="small" style={{ marginRight: 8 }} />}
                    <Text type="secondary">{statusText}</Text>
                </div>

                {error && (
                    <Alert type="error" showIcon message="分析失败" description={error} style={{ marginBottom: 16 }} />
                )}

                {streamText && (
                    <div 
                        ref={streamAreaRef}
                        style={{
                            flex: result ? 'none' : 1,
                            maxHeight: result ? 200 : 'none',
                            backgroundColor: '#1e1e1e',
                            color: '#d4d4d4',
                            padding: 12,
                            borderRadius: 6,
                            fontFamily: 'monospace',
                            fontSize: 13,
                            whiteSpace: 'pre-wrap',
                            overflowY: 'auto',
                            lineHeight: 1.6,
                        }}
                    >
                        {streamText}
                    </div>
                )}

                {renderResult()}

                {!loading && !streamText && !result && !error && (
                    <div style={{ textAlign: 'center', marginTop: 60, color: '#8c8c8c' }}>
                        <RobotOutlined style={{ fontSize: 48, marginBottom: 16, opacity: 0.5 }} />
                        <p>点击“开始分析”让 AI 助手帮你审查 POC 代码</p>
                    </div>
                )}
            </div>
        </div>
    );
};

export default PocAiPanel;
