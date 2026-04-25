import React, { useEffect, useMemo, useState } from 'react';
import { Alert, App, Button, Card, Col, Empty, Form, Input, InputNumber, Row, Select, Space, Tag, Typography } from 'antd';
import { BugOutlined, CloseCircleOutlined, PlayCircleOutlined, ReloadOutlined, RobotOutlined } from '@ant-design/icons';
import Editor from '@monaco-editor/react';
import { cancelDebugSession, connectWebSocket, debugPoc, getNodes } from '../../services/api';

const { Text } = Typography;

interface PocDebugPanelProps {
    pocContent: string;
    visible: boolean;
    onDiagnose?: (context: any) => void;
}

const supportsDebug = (version?: string): boolean => {
    const normalized = (version || '').trim().toLowerCase().replace(/^v/, '');
    const [majorRaw, minorRaw] = normalized.split('.');
    const major = Number.parseInt(majorRaw, 10);
    const minor = Number.parseInt(minorRaw, 10);
    return Number.isFinite(major) && Number.isFinite(minor) && (major > 2 || (major === 2 && minor >= 2));
};

const PocDebugPanel: React.FC<PocDebugPanelProps> = ({ pocContent, onDiagnose }) => {
    const { message } = App.useApp();
    const [form] = Form.useForm<API.DebugPocRequest>();
    const [nodes, setNodes] = useState<API.AgentNode[]>([]);
    const [loadingNodes, setLoadingNodes] = useState(false);
    const [running, setRunning] = useState(false);
    const [sessionId, setSessionId] = useState('');
    const [logs, setLogs] = useState<API.DebugEvent[]>([]);
    const [results, setResults] = useState<API.DebugEvent[]>([]);
    const [complete, setComplete] = useState<API.DebugEvent | null>(null);

    const onlineDebugNodes = useMemo(
        () => nodes.filter((n) => n.Status === 'Alive' && supportsDebug(n.Version)),
        [nodes],
    );

    const fetchNodes = async () => {
        setLoadingNodes(true);
        try {
            const res = await getNodes();
            setNodes(res || []);
            const first = (res || []).find((n) => n.Status === 'Alive' && supportsDebug(n.Version));
            if (first && !form.getFieldValue('agent_id')) {
                form.setFieldValue('agent_id', first.AgentID);
            }
        } catch {
            message.error('加载 Agent 节点失败');
        } finally {
            setLoadingNodes(false);
        }
    };

    useEffect(() => {
        fetchNodes();
        const ws = connectWebSocket((data) => {
            const event = data as API.DebugEvent;
            if (!event || !event.type || !event.session_id) return;
            setSessionId((current) => {
                if (!current || current !== event.session_id) return current;
                if (event.type === 'debug_log') {
                    setLogs((prev) => [...prev, event]);
                } else if (event.type === 'debug_result') {
                    setResults((prev) => [...prev, event]);
                } else if (event.type === 'debug_complete') {
                    setComplete(event);
                    setRunning(false);
                }
                return current;
            });
        });
        return () => ws.close();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    const resetOutput = () => {
        setLogs([]);
        setResults([]);
        setComplete(null);
    };

    const startDebug = async () => {
        const values = await form.validateFields();
        resetOutput();
        setRunning(true);
        try {
            const res = await debugPoc({
                ...values,
                poc_content: pocContent,
                timeout_sec: values.timeout_sec || 60,
            });
            setSessionId(res.session_id);
            setLogs([{
                type: 'debug_log',
                session_id: res.session_id,
                timestamp: Date.now(),
                level: 'INFO',
                message: 'debug session started',
            }]);
        } catch (err) {
            setRunning(false);
            message.error(typeof err === 'string' ? err : '启动调试失败');
        }
    };

    const cancelDebug = async () => {
        if (!sessionId) return;
        try {
            await cancelDebugSession(sessionId);
            setLogs((prev) => [...prev, {
                type: 'debug_log',
                session_id: sessionId,
                timestamp: Date.now(),
                level: 'WARN',
                message: 'cancel requested',
            }]);
        } catch (err) {
            message.error(typeof err === 'string' ? err : '取消调试失败');
        }
    };

    return (
        <Card
            size="small"
            title={<Space><BugOutlined />POC 沙箱调试</Space>}
            style={{ marginTop: 14, borderRadius: 10 }}
            extra={<Button size="small" icon={<ReloadOutlined />} onClick={fetchNodes} loading={loadingNodes}>刷新节点</Button>}
        >
            <Form form={form} layout="vertical" initialValues={{ timeout_sec: 60 }}>
                <Row gutter={12}>
                    <Col span={24}>
                        <Form.Item name="agent_id" label="执行 Agent" rules={[{ required: true, message: '请选择 Agent' }]}>
                            <Select
                                placeholder="选择在线 Agent"
                                loading={loadingNodes}
                                options={onlineDebugNodes.map((n) => ({
                                    value: n.AgentID,
                                    label: `${n.AgentID} (${n.Version})`,
                                }))}
                            />
                        </Form.Item>
                    </Col>
                    <Col span={24}>
                        <Form.Item name="target_url" label="目标 URL" rules={[{ required: true, message: '请输入目标 URL' }]}>
                            <Input placeholder="https://example.com" />
                        </Form.Item>
                    </Col>
                    <Col span={16}>
                        <Form.Item name="proxy" label="代理（可选）">
                            <Input placeholder="socks5://127.0.0.1:1080" />
                        </Form.Item>
                    </Col>
                    <Col span={8}>
                        <Form.Item name="timeout_sec" label="超时">
                            <InputNumber min={1} max={60} style={{ width: '100%' }} />
                        </Form.Item>
                    </Col>
                </Row>
                <Space wrap>
                    <Button type="primary" icon={<PlayCircleOutlined />} onClick={startDebug} loading={running}>
                        开始调试
                    </Button>
                    <Button danger icon={<CloseCircleOutlined />} onClick={cancelDebug} disabled={!running || !sessionId}>
                        取消
                    </Button>
                    {sessionId && <Text type="secondary">Session: <Text code>{sessionId}</Text></Text>}
                </Space>
            </Form>

            {onlineDebugNodes.length === 0 && (
                <Alert
                    style={{ marginTop: 12 }}
                    type="warning"
                    showIcon
                    message="没有可用的调试 Agent"
                    description="需要在线且版本不低于 v2.2.0 的 Agent。"
                />
            )}

            <div style={{ marginTop: 14 }}>
                <Card size="small" title="实时日志" styles={{ body: { height: 180, overflow: 'auto', background: '#0f172a' } }}>
                    {logs.length === 0 ? (
                        <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无日志" />
                    ) : logs.map((log, idx) => (
                        <div key={`${log.timestamp}-${idx}`} style={{ color: '#cbd5e1', fontFamily: 'monospace', fontSize: 12, marginBottom: 6 }}>
                            <Tag color={log.level === 'ERROR' ? 'red' : log.level === 'WARN' ? 'gold' : 'blue'}>{log.level || 'INFO'}</Tag>
                            {new Date(log.timestamp).toLocaleTimeString()} {log.message}
                        </div>
                    ))}
                </Card>
            </div>

            <div style={{ marginTop: 14 }}>
                <Card size="small" title="匹配结果" styles={{ body: { minHeight: 240 } }}>
                    {complete && (
                        <Alert
                            style={{ marginBottom: 12 }}
                            type={complete.error ? 'error' : results.some((r) => r.matched) ? 'success' : 'info'}
                            showIcon
                            message={complete.error ? complete.error : results.some((r) => r.matched) ? 'POC 命中' : '未命中'}
                            description={complete.duration_ms ? `耗时 ${complete.duration_ms}ms` : undefined}
                            action={
                                <Button
                                    size="small"
                                    type="dashed"
                                    icon={<RobotOutlined />}
                                    onClick={() => onDiagnose?.({ logs, results, complete, config: form.getFieldsValue() })}
                                >
                                    召唤智能体诊断
                                </Button>
                            }
                        />
                    )}
                    {results.length === 0 && !complete ? (
                        <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无命中结果" />
                    ) : (
                        <Space direction="vertical" style={{ width: '100%' }} size={12}>
                            {results.map((item, idx) => (
                                <Card
                                    key={idx}
                                    size="small"
                                    type="inner"
                                    title={
                                        <Space wrap>
                                            {item.matched ? (
                                                <>
                                                    <Tag color="green">命中</Tag>
                                                    <Tag>{item.template_id}</Tag>
                                                    <Tag color="red">{item.severity || 'unknown'}</Tag>
                                                    <Text copyable>{item.matched_at}</Text>
                                                </>
                                            ) : (
                                                <Tag color="orange">未命中 — 请求/响应记录</Tag>
                                            )}
                                        </Space>
                                    }
                                >
                                    {item.matched && item.extracted && item.extracted.length > 0 && (
                                        <Text type="secondary" style={{ display: 'block', marginBottom: 8 }}>
                                            Extracted: {item.extracted.join(', ')}
                                        </Text>
                                    )}
                                    {(item.request || item.response) ? (
                                        <>
                                            <Text strong style={{ fontSize: 12, display: 'block', marginBottom: 4 }}>
                                                Request
                                            </Text>
                                            <div style={{ height: 180, border: '1px solid #e2e8f0', borderRadius: 6, overflow: 'hidden' }}>
                                                <Editor
                                                    height="100%"
                                                    language="http"
                                                    theme="vs-dark"
                                                    value={item.request || '(empty)'}
                                                    options={{ readOnly: true, minimap: { enabled: false }, fontSize: 12 }}
                                                />
                                            </div>
                                            <Text strong style={{ fontSize: 12, display: 'block', margin: '8px 0 4px' }}>
                                                Response
                                            </Text>
                                            <div style={{ height: 220, border: '1px solid #e2e8f0', borderRadius: 6, overflow: 'hidden' }}>
                                                <Editor
                                                    height="100%"
                                                    language="http"
                                                    theme="vs-dark"
                                                    value={item.response || '(empty)'}
                                                    options={{ readOnly: true, minimap: { enabled: false }, fontSize: 12 }}
                                                />
                                            </div>
                                        </>
                                    ) : (
                                        <Text type="secondary">无请求/响应数据</Text>
                                    )}
                                </Card>
                            ))}
                            {results.length === 0 && complete && !complete.error && (
                                <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="未捕获到请求记录" />
                            )}
                        </Space>
                    )}
                </Card>
            </div>
        </Card>
    );
};

export default PocDebugPanel;
