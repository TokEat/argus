import type React from 'react';
import { Alert, Card, Collapse, Descriptions, Empty, Space, Tabs, Tag, Typography } from 'antd';

const { Text } = Typography;

type ValueRecord = Record<string, unknown>;

const fieldLabels: Record<string, string> = {
    vulnerable: '利用结论',
    verdict: '判定方式',
    reason: '人工判断原因',
    cve: '漏洞编号',
    service: '服务',
    target: '目标',
    remote_address: '远端地址',
    gadget: '利用链',
    exploit_status: '利用响应状态',
    probe_status: '探测响应状态',
    output: '命令输出',
    message: '说明',
    username: '用户名',
    password: '密码',
    behavior_detected: 'Shiro 行为特征',
    canary_hit: 'Canary 回证',
    crypto_roundtrip: '加解密回验',
    default_key_valid: '默认密钥有效',
    identity_found: '身份输出',
    marker_found: '随机标记回显',
    command_executed: '命令执行回证',
};

const asRecord = (value: unknown): ValueRecord => value && typeof value === 'object' && !Array.isArray(value)
    ? value as ValueRecord
    : {};

const isPresent = (value: unknown): boolean => {
    if (value == null || value === '') return false;
    if (Array.isArray(value)) return value.some(isPresent);
    if (typeof value === 'object') return Object.values(value as ValueRecord).some(isPresent);
    return true;
};

const labelFor = (key: string) => fieldLabels[key] || key.replaceAll('_', ' ');

const isKeyResultValue = (value: unknown) => {
    if (value == null || typeof value !== 'object') return isPresent(value);
    return Array.isArray(value) && value.every((item) => item == null || typeof item !== 'object');
};

const statusMeta = (status: string) => {
    switch (status) {
    case 'Succeeded': return { color: 'success', text: '执行成功' };
    case 'Failed': return { color: 'error', text: '执行失败' };
    case 'Timeout': return { color: 'warning', text: '执行超时' };
    case 'Canceled': return { color: 'default', text: '已取消' };
    case 'Rejected': return { color: 'error', text: '已拒绝' };
    default: return { color: 'processing', text: status || '等待执行' };
    }
};

const conciseRuntimeError = (value: string) => {
    if (value.includes('Yaksha egress is disabled')) {
        return '当前运行出口为 disabled；此 EXP 需要网络访问，请选择 direct、SOCKS5 或 Agent 出口，并添加精确网络目标。';
    }
    const panic = value.match(/YakVM Panic:\s*([^\r\n]+)/);
    return panic?.[1]?.trim() || value;
};

const contentStyle: React.CSSProperties = {
    margin: 0,
    maxHeight: 360,
    overflow: 'auto',
    padding: 12,
    whiteSpace: 'pre-wrap',
    overflowWrap: 'anywhere',
    background: '#f5f5f5',
    borderRadius: 6,
};

const ReadableValue: React.FC<{ value: unknown }> = ({ value }) => {
    if (typeof value === 'boolean') return value ? <Tag color="success">是</Tag> : <Tag>否</Tag>;
    if (typeof value === 'string' && (value.includes('\n') || value.length > 160)) return <pre style={contentStyle}>{value}</pre>;
    if (Array.isArray(value)) {
        return <Space direction="vertical" size={6} style={{ width: '100%' }}>{value.map((item, index) => <div key={index}><ReadableValue value={item} /></div>)}</Space>;
    }
    if (value && typeof value === 'object') {
        const entries = Object.entries(value as ValueRecord).filter(([, item]) => isPresent(item));
        if (!entries.length) return <Text type="secondary">—</Text>;
        return <Descriptions size="small" column={1} bordered items={entries.map(([key, item]) => ({ key, label: labelFor(key), children: <ReadableValue value={item} /> }))} />;
    }
    return <Text copyable={typeof value === 'string'}>{value == null || value === '' ? '—' : String(value)}</Text>;
};

const headerLines = (headers: unknown): string[] => Object.entries(asRecord(headers)).map(([name, value]) => {
    const text = Array.isArray(value) ? value.join(', ') : String(value ?? '');
    return `${name}: ${text}`;
});

const httpRequestText = (event: ValueRecord) => {
    const request = asRecord(event.request);
    const method = String(request.method || event.operation || 'GET').toUpperCase();
    const url = String(request.url || event.target || '');
    const lines = [`${method} ${url}`];
    lines.push(...headerLines(request.headers));
    if (request.body_encoding) lines.push(`Content-Encoding: ${String(request.body_encoding)}`);
    if (isPresent(request.body)) lines.push('', String(request.body));
    return lines.join('\n');
};

const httpResponseText = (event: ValueRecord) => {
    const response = asRecord(event.response);
    const status = response.status_code || event.status_code;
    const lines = [`HTTP ${status || '响应'}`];
    if (response.final_url) lines.push(`Final-URL: ${String(response.final_url)}`);
    if (response.remote_address) lines.push(`Remote-Address: ${String(response.remote_address)}`);
    lines.push(...headerLines(response.headers));
    if (response.body_encoding) lines.push(`Content-Encoding: ${String(response.body_encoding)}`);
    if (isPresent(response.body)) lines.push('', String(response.body));
    return lines.join('\n');
};

const tcpRequestText = (event: ValueRecord) => {
    const request = asRecord(event.request);
    const steps = Array.isArray(request.steps) ? request.steps.map(asRecord) : [];
    const writes = steps.filter((step) => step.operation === 'write').map((step, index) => {
        const encoding = step.encoding ? ` (${String(step.encoding)})` : '';
        return `发送 ${index + 1}${encoding}\n${String(step.data || '')}`;
    });
    return writes.join('\n\n') || `连接 ${String(request.address || event.target || '')}`;
};

const tcpResponseText = (event: ValueRecord) => {
    const response = asRecord(event.response);
    const responses = Array.isArray(response.responses) ? response.responses : [];
    const encodings = Array.isArray(response.encodings) ? response.encodings : [];
    const chunks = responses.map((item, index) => `接收 ${index + 1}${encodings[index] ? ` (${String(encodings[index])})` : ''}\n${String(item ?? '')}`);
    if (response.remote_address) chunks.unshift(`Remote-Address: ${String(response.remote_address)}`);
    return chunks.join('\n\n') || '无响应内容';
};

const TraceEvents: React.FC<{ events: ValueRecord[] }> = ({ events }) => <Collapse
    size="small"
    items={events.map((event, index) => {
        const kind = String(event.kind || '').toLowerCase();
        const failed = String(event.error || '');
        const status = event.status_code ? ` · ${String(event.status_code)}` : '';
        const duration = event.duration_ms == null ? '' : ` · ${String(event.duration_ms)} ms`;
        return {
            key: String(index),
            label: `${kind === 'http' ? 'HTTP' : 'TCP'} ${String(event.operation || '')} · ${String(event.target || '')}${status}${duration}`,
            children: <Space direction="vertical" size={12} style={{ width: '100%' }}>
                {failed && <Alert type="error" showIcon message={failed} />}
                <Card size="small" title={kind === 'http' ? 'HTTP 请求包' : 'TCP 发送内容'}><pre style={contentStyle}>{kind === 'http' ? httpRequestText(event) : tcpRequestText(event)}</pre></Card>
                {isPresent(event.response) && <Card size="small" title={kind === 'http' ? 'HTTP 响应包' : 'TCP 接收内容'}><pre style={contentStyle}>{kind === 'http' ? httpResponseText(event) : tcpResponseText(event)}</pre></Card>}
            </Space>,
        };
    })}
/>
;

export const ExpRunResult: React.FC<{ value: unknown }> = ({ value }) => {
    const root = asRecord(value);
    const runtime = asRecord(root.runtime || root.artifact || root.response || root);
    const run = asRecord(root.run);
    const testCases = Array.isArray(asRecord(runtime.test).cases) ? (asRecord(runtime.test).cases as unknown[]).map(asRecord) : [];
    const status = String(runtime.status || root.status || run.status || '');
    const error = conciseRuntimeError(String(runtime.error || root.error || run.error_code || ''));
    const result = runtime.result ?? (testCases.length ? testCases.map((item) => item.result).filter(isPresent) : undefined);
    const evidence = runtime.evidence ?? (testCases.length ? testCases.map((item) => item.evidence).filter(isPresent) : undefined);
    const logs = Array.isArray(runtime.logs) ? runtime.logs : [];
    const debug = asRecord(runtime.debug || runtime.trace);
    const events = Array.isArray(debug.events)
        ? debug.events.map(asRecord)
        : testCases.flatMap((item) => Array.isArray(item.events) ? item.events.map(asRecord) : []);
    const calls = Array.isArray(runtime.calls) ? runtime.calls : [];

    if (!status && !error && !isPresent(result) && !isPresent(evidence) && !events.length && !logs.length && !calls.length) {
        return <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="尚未执行" />;
    }

    const meta = statusMeta(status);
    const resultRecord = asRecord(result);
    const vulnerable = typeof resultRecord.vulnerable === 'boolean' ? resultRecord.vulnerable : undefined;
    const manualReview = resultRecord.verdict === 'manual_review';
    const resultWithoutConclusion = Object.fromEntries(Object.entries(resultRecord).filter(([key, item]) => key !== 'vulnerable' && key !== 'verdict' && isKeyResultValue(item)));
    const displayResult = Object.keys(resultRecord).length ? resultWithoutConclusion : result;
    const detailTabs = [
        events.length ? { key: 'trace', label: `请求 / 响应 (${events.length})`, children: <TraceEvents events={events} /> } : null,
        logs.length ? { key: 'logs', label: `日志 (${logs.length})`, children: <Space direction="vertical" style={{ width: '100%' }}>{logs.map((line, index) => <pre key={index} style={contentStyle}>{String(line)}</pre>)}</Space> } : null,
        calls.length ? { key: 'calls', label: `子 EXP (${calls.length})`, children: <ReadableValue value={calls} /> } : null,
    ].filter(Boolean) as Array<{ key: string; label: string; children: React.ReactNode }>;

    return <Space direction="vertical" size={12} style={{ width: '100%' }}>
        <Space wrap>
            <Tag color={meta.color}>{meta.text}</Tag>
            {run.action || runtime.action ? <Tag>{String(run.action || runtime.action)}</Tag> : null}
            {run.revision || asRecord(runtime.context).revision ? <Text type="secondary">Revision {String(run.revision || asRecord(runtime.context).revision)}</Text> : null}
        </Space>
        {error && <Alert type="error" showIcon message="错误原因" description={error} />}
        {vulnerable !== undefined && <Alert
            type={vulnerable ? 'error' : 'success'}
            showIcon
            message={vulnerable ? '已确认目标存在漏洞' : '本次执行未确认漏洞'}
        />}
        {manualReview && <Alert type="warning" showIcon message="EXP 无可靠自动判据，需要人工判断" description={typeof resultRecord.reason === 'string' ? resultRecord.reason : undefined} />}
        {isPresent(displayResult) && <Card size="small" title="关键结果">
            <ReadableValue value={displayResult} />
        </Card>}
        {isPresent(evidence) && <Card size="small" title="关键证据"><ReadableValue value={evidence} /></Card>}
        {detailTabs.length > 0 && <Tabs size="small" items={detailTabs} />}
    </Space>;
};

export const expRunSummaryText = (summary: unknown, status?: string) => {
    const record = asRecord(summary);
    const summaryStatus = String(status || record.status || '');
    if (status && status !== 'Succeeded') return statusMeta(status).text;
    if (record.has_error === true) return '执行失败';
    if (summaryStatus === 'Succeeded') return '执行成功';
    return statusMeta(summaryStatus).text;
};
