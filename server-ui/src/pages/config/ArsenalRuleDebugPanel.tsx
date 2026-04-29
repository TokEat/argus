import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Alert, App, Button, Card, Checkbox, Empty, Form, Input, InputNumber, Radio, Select, Space, Statistic, Tag, Tooltip, Typography } from 'antd';
import {
    ApartmentOutlined,
    BugOutlined,
    CheckCircleOutlined,
    CloseCircleOutlined,
    CodeOutlined,
    ExperimentOutlined,
    FileSearchOutlined,
    PlayCircleOutlined,
    ReloadOutlined,
    ScanOutlined,
    ThunderboltOutlined,
    WarningOutlined,
} from '@ant-design/icons';
import Editor from '@monaco-editor/react';
import { cancelDebugSession, connectWebSocket, debugFingerprint, getNodes } from '../../services/api';

const { Text } = Typography;

const GENERAL_POC_PREFIX = 'General-Poc-';

interface ArsenalRuleDebugPanelProps {
    fingerprints: API.FingerprintItem[];
    workflows: API.WorkflowItem[];
    dirs?: API.DirItem[];
    pocFiles?: Set<string>;
    focusProduct?: string;
    title?: string;
}

interface DebugFormValues {
    agent_id: string;
    target_url: string;
    proxy?: string;
    timeout_sec?: number;
    include_dir?: boolean;
    include_poc?: boolean;
    custom_product?: string;
    custom_rule?: string;
    custom_wf_types?: string[];
    custom_wf_pocs?: string;
}

const sectionStyle: React.CSSProperties = {
    border: '1px solid #e2e8f0',
    borderRadius: 8,
    padding: 12,
    background: '#fff',
};

const sectionTitleStyle: React.CSSProperties = {
    fontWeight: 600,
    marginBottom: 10,
    display: 'flex',
    alignItems: 'center',
    gap: 6,
};

const customRuleBoxStyle: React.CSSProperties = {
    padding: '10px 14px',
    marginBottom: 12,
    background: '#f8fafc',
    borderRadius: 8,
    border: '1px solid #e2e8f0',
};

const customRuleLabelStyle: React.CSSProperties = {
    fontSize: 13,
    fontWeight: 600,
    color: '#334155',
    marginBottom: 10,
    display: 'flex',
    alignItems: 'center',
    gap: 6,
};

const supportsFingerprintDebug = (version?: string): boolean => {
    const normalized = (version || '').trim().toLowerCase().replace(/^v/, '');
    const [majorRaw, minorRaw] = normalized.split('.');
    const major = Number.parseInt(majorRaw, 10);
    const minor = Number.parseInt(minorRaw, 10);
    return Number.isFinite(major) && Number.isFinite(minor) && (major > 2 || (major === 2 && minor >= 3));
};

const stripYamlExt = (name: string) => name.replace(/\.(ya?ml)$/i, '');

const DEFAULT_CUSTOM_POC = `id: custom-poc

info:
  name: Custom POC
  author: argus
  severity: medium
  description: ""
  tags: ""

http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - "keyword"
`;

const pocExists = (pocFiles: Set<string> | undefined, poc: string) => {
    if (!pocFiles) return true;
    return pocFiles.has(poc) || pocFiles.has(stripYamlExt(poc));
};

const ArsenalRuleDebugPanel: React.FC<ArsenalRuleDebugPanelProps> = ({
    fingerprints,
    workflows,
    dirs = [],
    pocFiles,
    focusProduct,
    title = 'Workflow 规则调试',
}) => {
    const { message } = App.useApp();
    const [form] = Form.useForm<DebugFormValues>();
    const [nodes, setNodes] = useState<API.AgentNode[]>([]);
    const [loadingNodes, setLoadingNodes] = useState(false);
    const [running, setRunning] = useState(false);
    const [sessionId, setSessionId] = useState('');
    const [logs, setLogs] = useState<API.DebugEvent[]>([]);
    const [results, setResults] = useState<API.DebugEvent[]>([]);
    const [complete, setComplete] = useState<API.DebugEvent | null>(null);
    const [pocMode, setPocMode] = useState<'select' | 'custom'>('select');
    const [customPocContent, setCustomPocContent] = useState('');

    const extractPocId = useCallback((yaml: string): string => {
        const m = yaml.match(/^id:\s*(.+)$/m);
        return m ? m[1].trim() : '';
    }, []);

    const onlineDebugNodes = useMemo(
        () => nodes.filter((n) => n.Status === 'Alive' && supportsFingerprintDebug(n.Version)),
        [nodes],
    );

    const fetchNodes = async () => {
        setLoadingNodes(true);
        try {
            const res = await getNodes();
            setNodes(res || []);
            const first = (res || []).find((n) => n.Status === 'Alive' && supportsFingerprintDebug(n.Version));
            if (first && !form.getFieldValue('agent_id')) {
                form.setFieldValue('agent_id', first.AgentID);
            }
        } catch {
            message.error('加载 Agent 节点失败');
        } finally {
            setLoadingNodes(false);
        }
    };

    const wsRef = useRef<{ close: () => void } | null>(null);
    const activeSessionRef = useRef('');

    useEffect(() => {
        fetchNodes();
        if (wsRef.current) return;
        const ws = connectWebSocket((data) => {
            const event = data as API.DebugEvent;
            if (!event || !event.type || !event.session_id) return;
            const active = activeSessionRef.current;
            if (!active || active !== event.session_id) return;
            if (event.type === 'debug_log') {
                setLogs((prev) => [...prev, event]);
            } else if (event.type === 'debug_result') {
                setResults((prev) => [...prev, event]);
            } else if (event.type === 'debug_complete') {
                setComplete(event);
                setRunning(false);
            }
        });
        wsRef.current = ws;
        return () => {
            ws.close();
            wsRef.current = null;
        };
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    // 指纹命中的产品名（去掉 [custom] 前缀）
    const products = useMemo(() => {
        const found = results.flatMap((item) => (item.extracted || []).map((e) => e.replace(/^\[custom]/, '')));
        if (focusProduct) found.push(focusProduct);
        return Array.from(new Set(found.filter(Boolean)));
    }, [results, focusProduct]);

    const workflowHits = useMemo(
        () => workflows.filter((wf) => products.includes(wf.product)),
        [workflows, products],
    );

    const generalHits = useMemo(
        () => workflows.filter((wf) => wf.product.startsWith(GENERAL_POC_PREFIX)),
        [workflows],
    );

    const dirHits = useMemo(
        () => dirs.filter((dir) => products.includes(dir.product)),
        [dirs, products],
    );

    const missingPocs = useMemo(
        () => Array.from(new Set([...workflowHits, ...generalHits]
            .flatMap((wf) => wf.pocs || [])
            .filter((poc) => !pocExists(pocFiles, poc)))),
        [workflowHits, generalHits, pocFiles],
    );

    const vulnResults = useMemo(
        () => results.filter((r) => r.template_id && (r.template_id.startsWith('Nuclei') || r.template_id.startsWith('GoPoc'))),
        [results],
    );

    const fingerResults = useMemo(
        () => results.filter((r) => !r.template_id || (!r.template_id.startsWith('Nuclei') && !r.template_id.startsWith('GoPoc'))),
        [results],
    );

    const resetOutput = () => {
        setLogs([]);
        setResults([]);
        setComplete(null);
    };

    const startDebug = async () => {
        const values = await form.validateFields();
        if (pocMode === 'custom' && !customPocContent.trim()) {
            message.error('自定义 POC 内容不能为空');
            return;
        }
        resetOutput();
        setRunning(true);
        try {
            const payload: API.DebugFingerprintRequest = {
                agent_id: values.agent_id,
                target_url: values.target_url,
                proxy: values.proxy || undefined,
                timeout_sec: values.timeout_sec || 60,
                include_dir: values.include_dir || false,
                include_poc: values.include_poc || false,
            };
            if (values.custom_product && values.custom_rule) {
                payload.custom_product = values.custom_product;
                payload.custom_rule = values.custom_rule;
            }
            if (values.custom_product && values.custom_wf_pocs) {
                payload.custom_wf_product = values.custom_product;
                payload.custom_wf_types = values.custom_wf_types?.join(',') || undefined;
                payload.custom_wf_pocs = values.custom_wf_pocs;
            }
            if (pocMode === 'custom' && customPocContent.trim()) {
                payload.custom_poc_content = customPocContent.trim();
            }
            const res = await debugFingerprint(payload);
            activeSessionRef.current = res.session_id;
            setSessionId(res.session_id);
            setLogs([{
                type: 'debug_log',
                session_id: res.session_id,
                timestamp: Date.now(),
                level: 'INFO',
                message: 'workflow debug session started',
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
            title={<Space><ExperimentOutlined />{title}</Space>}
            extra={<Button size="small" icon={<ReloadOutlined />} onClick={fetchNodes} loading={loadingNodes}>刷新节点</Button>}
            style={{ height: '100%' }}
            styles={{ body: { maxHeight: 'calc(100vh - 196px)', overflow: 'auto' } }}
        >
            <Form
                form={form}
                layout="vertical"
                initialValues={{ target_url: 'https://example.com/', timeout_sec: 60, include_dir: false, include_poc: false }}
            >
                {/* ── 基础配置 ── */}
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
                <Form.Item name="target_url" label="目标 URL" rules={[{ required: true, message: '请输入目标 URL' }]}>
                    <Input placeholder="https://example.com/" />
                </Form.Item>
                <Space.Compact style={{ width: '100%' }}>
                    <Form.Item name="proxy" label="代理" style={{ width: '70%' }}>
                        <Input placeholder="socks5://127.0.0.1:1080" />
                    </Form.Item>
                    <Form.Item name="timeout_sec" label="超时" style={{ width: '30%' }}>
                        <InputNumber min={1} max={300} style={{ width: '100%' }} />
                    </Form.Item>
                </Space.Compact>

                {/* ── 自定义 Workflow 规则 = 产品名 + 指纹 + 触发阶段 + POC ── */}
                <div style={customRuleBoxStyle}>
                    <div style={customRuleLabelStyle}>
                        <ApartmentOutlined />自定义 Workflow 规则（可选）
                    </div>

                    <Form.Item name="custom_product" label="产品名" style={{ marginBottom: 8 }}
                        tooltip="统一标识：指纹命中后以此名称关联 Workflow 和 POC"
                    >
                        <Input placeholder="如 Nacos、SpringBoot" />
                    </Form.Item>

                    <Form.Item name="custom_rule" label="① 指纹规则" style={{ marginBottom: 8 }}
                        tooltip="产品识别表达式，支持 body/header/title/cert/server/status 等关键字"
                    >
                        <Input placeholder='如 body="nacos" && title="Nacos"' style={{ fontFamily: 'monospace' }} />
                    </Form.Item>

                    <Form.Item name="custom_wf_types" label="② 触发阶段" style={{ marginBottom: 8 }}
                        tooltip="指纹命中后，在哪些 Pipeline 阶段触发 POC 执行"
                    >
                        <Checkbox.Group
                            options={[
                                { label: 'Root', value: 'root' },
                                { label: 'Base', value: 'base' },
                                { label: 'Dir', value: 'dir' },
                                { label: 'Dir-Fallback', value: 'dir-fallback' },
                            ]}
                        />
                    </Form.Item>

                    <div style={{ marginBottom: 8 }}>
                        <div style={{ ...customRuleLabelStyle, marginBottom: 6 }}>
                            <CodeOutlined />③ 关联 POC
                        </div>
                        <Radio.Group
                            size="small"
                            optionType="button"
                            value={pocMode}
                            onChange={(e) => {
                                const mode = e.target.value;
                                setPocMode(mode);
                                if (mode === 'custom' && !customPocContent) {
                                    const tpl = DEFAULT_CUSTOM_POC;
                                    setCustomPocContent(tpl);
                                    form.setFieldValue('custom_wf_pocs', extractPocId(tpl));
                                }
                            }}
                            style={{ marginBottom: 8 }}
                        >
                            <Radio.Button value="select">选择已有</Radio.Button>
                            <Radio.Button value="custom">自定义编辑</Radio.Button>
                        </Radio.Group>

                        {pocMode === 'select' ? (
                            <Form.Item name="custom_wf_pocs" noStyle
                                tooltip="指纹命中后要执行的 POC 模板名，多个用逗号分隔"
                            >
                                <Input placeholder="如 nacos-auth-bypass,nacos-default-login" style={{ fontFamily: 'monospace' }} />
                            </Form.Item>
                        ) : (
                            <div>
                                <Form.Item name="custom_wf_pocs" noStyle>
                                    <Input type="hidden" />
                                </Form.Item>
                                <div style={{ fontSize: 12, color: '#64748b', marginBottom: 4 }}>
                                    POC ID 自动同步：<Tag size="small">{form.getFieldValue('custom_wf_pocs') || '-'}</Tag>
                                </div>
                                <div style={{ border: '1px solid #e2e8f0', borderRadius: 6, overflow: 'hidden' }}>
                                    <Editor
                                        height="260px"
                                        language="yaml"
                                        theme="vs-dark"
                                        value={customPocContent}
                                        onChange={(v) => {
                                            const content = v || '';
                                            setCustomPocContent(content);
                                            const id = extractPocId(content);
                                            if (id) {
                                                form.setFieldValue('custom_wf_pocs', id);
                                            }
                                        }}
                                        options={{ minimap: { enabled: false }, fontSize: 13, scrollBeyondLastLine: false }}
                                    />
                                </div>
                            </div>
                        )}
                    </div>
                </div>

                {/* ── 调试选项 ── */}
                <Form.Item name="include_dir" valuePropName="checked" style={{ marginBottom: 4 }}>
                    <Checkbox>同时运行 Dir 主动指纹探测</Checkbox>
                </Form.Item>
                <Form.Item name="include_poc" valuePropName="checked">
                    <Checkbox>执行 Workflow 关联 POC（漏洞检测）</Checkbox>
                </Form.Item>

                <Space wrap>
                    <Button type="primary" icon={<PlayCircleOutlined />} onClick={startDebug} loading={running}>
                        开始调试
                    </Button>
                    <Button danger icon={<CloseCircleOutlined />} onClick={cancelDebug} disabled={!running || !sessionId}>
                        取消
                    </Button>
                </Space>
            </Form>

            {onlineDebugNodes.length === 0 && (
                <Alert
                    style={{ marginTop: 12 }}
                    type="warning"
                    showIcon
                    message="没有可用的调试 Agent"
                    description="需要在线且版本不低于 v2.3.0 的 Agent。"
                />
            )}

            {/* ── 统计面板 ── */}
            <div style={{ marginTop: 14 }}>
                <Space wrap style={{ width: '100%', justifyContent: 'space-between' }}>
                    <Statistic title="命中指纹" value={products.length} prefix={<ScanOutlined />} />
                    <Statistic title="Workflow" value={workflowHits.length + generalHits.length} prefix={<ApartmentOutlined />} />
                    <Statistic title="漏洞命中" value={vulnResults.length} valueStyle={{ color: vulnResults.length ? '#ef4444' : undefined }} prefix={<ThunderboltOutlined />} />
                    <Statistic title="POC 缺失" value={missingPocs.length} valueStyle={{ color: missingPocs.length ? '#ef4444' : '#10b981' }} prefix={<BugOutlined />} />
                </Space>
            </div>

            {/* ── 结果展示 ── */}
            <Space direction="vertical" size={12} style={{ width: '100%', marginTop: 14 }}>
                {/* 1️⃣ 指纹识别 */}
                <div style={sectionStyle}>
                    <div style={sectionTitleStyle}><ScanOutlined />指纹识别</div>
                    {logs.length === 0 && fingerResults.length === 0 && !complete ? (
                        <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="等待 Agent 实测结果" />
                    ) : (
                        <Space direction="vertical" size={8} style={{ width: '100%' }}>
                            {logs.slice(-8).map((log, idx) => (
                                <div key={`${log.timestamp}-${idx}`} style={{ fontSize: 12, color: '#64748b' }}>
                                    <Tag color={log.level === 'ERROR' ? 'red' : log.level === 'WARN' ? 'gold' : log.level === 'DEBUG' ? 'default' : 'blue'}>
                                        {log.level || 'INFO'}
                                    </Tag>
                                    {new Date(log.timestamp).toLocaleTimeString()} {log.message}
                                </div>
                            ))}
                            {fingerResults.map((item, idx) => (
                                <div key={`fp-${item.matched_at}-${idx}`}>
                                    <Space wrap>
                                        <Tag color="green" icon={<CheckCircleOutlined />}>{item.template_id || 'Finger'}</Tag>
                                        <Text copyable style={{ maxWidth: 260 }}>{item.matched_at}</Text>
                                    </Space>
                                    <div style={{ marginTop: 6 }}>
                                        <Space wrap>
                                            {(item.extracted || []).map((fp) => (
                                                <Tag key={fp} color={fp.startsWith('[custom]') ? 'gold' : 'cyan'}>
                                                    {fp.startsWith('[custom]') ? `✦ ${fp.slice(8)}` : fp}
                                                </Tag>
                                            ))}
                                        </Space>
                                    </div>
                                    {item.message && <Text type="secondary" style={{ fontSize: 12 }}>{item.message}</Text>}
                                </div>
                            ))}
                        </Space>
                    )}
                </div>

                {/* 2️⃣ 漏洞检测 */}
                {vulnResults.length > 0 && (
                    <div style={{ ...sectionStyle, borderColor: '#fecaca', background: '#fffbfb' }}>
                        <div style={sectionTitleStyle}><ThunderboltOutlined style={{ color: '#ef4444' }} />漏洞检测</div>
                        <Space direction="vertical" size={8} style={{ width: '100%' }}>
                            {vulnResults.map((item, idx) => (
                                <div key={`vuln-${item.matched_at}-${idx}`} style={{ padding: '6px 8px', background: '#fef2f2', borderRadius: 6, border: '1px solid #fecaca' }}>
                                    <Space wrap>
                                        <Tag color={item.severity === 'critical' ? '#dc2626' : item.severity === 'high' ? '#ea580c' : item.severity === 'medium' ? '#d97706' : 'blue'}>
                                            {(item.severity || 'info').toUpperCase()}
                                        </Tag>
                                        <Tag color="volcano" icon={<ThunderboltOutlined />}>{item.template_id}</Tag>
                                        <Text copyable style={{ maxWidth: 300 }}>{item.matched_at}</Text>
                                    </Space>
                                    {item.extracted && item.extracted.length > 0 && (
                                        <div style={{ marginTop: 4 }}>
                                            <Space wrap>
                                                {item.extracted.map((e) => <Tag key={e} color="purple">{e}</Tag>)}
                                            </Space>
                                        </div>
                                    )}
                                </div>
                            ))}
                        </Space>
                    </div>
                )}

                {/* 3️⃣ Workflow / POC 联动 */}
                <div style={sectionStyle}>
                    <div style={sectionTitleStyle}><ApartmentOutlined />Workflow / POC 联动</div>
                    {workflowHits.length === 0 && generalHits.length === 0 ? (
                        <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无可触发 Workflow" />
                    ) : (
                        <Space direction="vertical" style={{ width: '100%' }}>
                            {[...workflowHits, ...generalHits].map((wf) => (
                                <div key={wf.product}>
                                    <Space wrap>
                                        <Tag color={wf.product.startsWith(GENERAL_POC_PREFIX) ? 'orange' : 'blue'}>
                                            {wf.product.startsWith(GENERAL_POC_PREFIX) ? wf.product.replace(GENERAL_POC_PREFIX, '') : wf.product}
                                        </Tag>
                                        {(wf.type || []).map((t) => <Tag key={t}>{t}</Tag>)}
                                    </Space>
                                    <div style={{ marginTop: 6 }}>
                                        <Space wrap>
                                            {(wf.pocs || []).map((poc) => {
                                                const missing = !pocExists(pocFiles, poc);
                                                return (
                                                    <Tooltip key={poc} title={missing ? '弹药库中未找到该 POC' : 'POC 已存在'}>
                                                        <Tag color={missing ? 'red' : 'purple'} icon={missing ? <WarningOutlined /> : <BugOutlined />}>{poc}</Tag>
                                                    </Tooltip>
                                                );
                                            })}
                                        </Space>
                                    </div>
                                </div>
                            ))}
                        </Space>
                    )}
                </div>

                {/* 4️⃣ Dir 联动 */}
                {dirs.length > 0 && (
                    <div style={sectionStyle}>
                        <div style={sectionTitleStyle}><FileSearchOutlined />Dir 联动</div>
                        {dirHits.length === 0 ? (
                            <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无命中指纹对应的 Dir 规则" />
                        ) : (
                            <Space direction="vertical" style={{ width: '100%' }}>
                                {dirHits.map((dir) => (
                                    <div key={dir.product}>
                                        <Tag color="cyan">{dir.product}</Tag>
                                        <div style={{ marginTop: 6 }}>
                                            <Space wrap>{(dir.paths || []).map((path) => <Tag key={path}>{path}</Tag>)}</Space>
                                        </div>
                                    </div>
                                ))}
                            </Space>
                        )}
                    </div>
                )}

                {/* 5️⃣ 完成状态 */}
                {complete && (
                    <Alert
                        type={complete.error ? 'error' : (vulnResults.length ? 'warning' : products.length ? 'success' : 'info')}
                        showIcon
                        message={complete.error ? complete.error : vulnResults.length ? `调试完成，发现 ${vulnResults.length} 个漏洞` : products.length ? '调试完成，指纹命中' : '调试完成，未命中指纹'}
                        description={complete.duration_ms ? `耗时 ${complete.duration_ms}ms` : undefined}
                    />
                )}
            </Space>

            <div style={{ marginTop: 12, fontSize: 12, color: '#94a3b8' }}>
                指纹规则共 {fingerprints.length} 个 product。自定义规则命中将以 <span style={{ color: '#d97706' }}>✦ 金色</span> 标记显示。
            </div>
        </Card>
    );
};

export default ArsenalRuleDebugPanel;
