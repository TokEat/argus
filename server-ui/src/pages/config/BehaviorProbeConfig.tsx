import { useCallback, useEffect, useState } from 'react';
import { Alert, App, Button, Checkbox, Descriptions, Drawer, Empty, Form, Input, Modal, Popconfirm, Select, Space, Table, Tabs, Tag, Timeline, Typography } from 'antd';
import { DiffEditor } from '@monaco-editor/react';
import Editor from '@monaco-editor/react';
import type { ColumnsType } from 'antd/es/table';
import {
    approveArsenal, debugBehaviorProbe, deprecateArsenal, getArsenal, getArsenalHistory,
    getNodes, inspectActiveFingerprint, listActiveFingerprintRules, listArsenalsPage,
    rollbackArsenal, saveArsenal,
} from '../../services/api';

const { Text, Paragraph } = Typography;
const ruleType = 'active_fingerprint';
const starter = `id: product-detect
info:
  name: Detect Product
  severity: info
  metadata:
    argus-rule-kind: active-fingerprint
    argus-product: ProductName
    argus-auto-profile: safe
    max-request: 1
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        part: header
        words:
          - "Product-Marker"
`;

function agentSupportsBehaviorProbe(node: API.AgentNode) {
    try { return JSON.parse(node.Tags || '{}').behavior_probe === 'v1'; } catch { return false; }
}

export default function BehaviorProbeConfig() {
    const { message } = App.useApp();
    const [loading, setLoading] = useState(false);
    const [rows, setRows] = useState<API.Arsenal[]>([]);
    const [catalog, setCatalog] = useState<Record<string, API.ActiveFingerprintRule>>({});
    const [editorOpen, setEditorOpen] = useState(false);
    const [fileName, setFileName] = useState('');
    const [content, setContent] = useState(starter);
    const [current, setCurrent] = useState<API.Arsenal | null>(null);
    const [classification, setClassification] = useState<API.ActiveFingerprintClassification | null>(null);
    const [classificationError, setClassificationError] = useState('');
    const [history, setHistory] = useState<API.ArsenalEvent[]>([]);
    const [diffEvent, setDiffEvent] = useState<API.ArsenalEvent | null>(null);
    const [debugOpen, setDebugOpen] = useState(false);
    const [debugging, setDebugging] = useState(false);
    const [debugResult, setDebugResult] = useState<API.BehaviorProbeDebugResponse | null>(null);
    const [agents, setAgents] = useState<API.AgentNode[]>([]);
    const [debugForm] = Form.useForm();

    const load = useCallback(async () => {
        setLoading(true);
        try {
            const [artifacts, rules] = await Promise.all([
                listArsenalsPage(ruleType, { all: '1', lite: '1', page_size: 200 }),
                listActiveFingerprintRules(),
            ]);
            setRows(artifacts.items || []);
            setCatalog(Object.fromEntries((rules || []).map((rule) => [rule.SourceFile, rule])));
        } catch (error) { message.error(typeof error === 'string' ? error : '加载行为探针失败'); }
        finally { setLoading(false); }
    }, [message]);

    useEffect(() => { void load(); }, [load]);

    const classify = useCallback(async (name = fileName, source = content) => {
        if (!name.trim() || !source.trim()) return;
        try {
            setClassification(await inspectActiveFingerprint(name.trim(), source));
            setClassificationError('');
        } catch (error) {
            setClassification(null);
            setClassificationError(typeof error === 'string' ? error : '模板分类失败');
        }
    }, [fileName, content]);

    const openCreate = () => {
        setCurrent(null); setFileName(''); setContent(starter); setClassification(null);
        setClassificationError(''); setHistory([]); setDiffEvent(null); setEditorOpen(true);
    };

    const openEdit = async (row: API.Arsenal) => {
        try {
            const [artifact, events] = await Promise.all([getArsenal(ruleType, row.FileName), getArsenalHistory(ruleType, row.FileName)]);
            setCurrent(artifact); setFileName(artifact.FileName); setContent(artifact.Content || '');
            setHistory(events.items || []); setDiffEvent((events.items || []).find((item) => item.Content) || null);
            setEditorOpen(true);
            await classify(artifact.FileName, artifact.Content || '');
        } catch (error) { message.error(typeof error === 'string' ? error : '读取探针失败'); }
    };

    const save = async () => {
        try {
            await classify();
            await saveArsenal(ruleType, fileName.trim(), content);
            message.success('已保存为 Draft，并重新计算安全分类');
            setEditorOpen(false); await load();
        } catch (error) { message.error(typeof error === 'string' ? error : '保存失败'); }
    };

    const lifecycle = async (action: 'publish' | 'deprecate' | 'rollback', row: API.Arsenal) => {
        try {
            const guard = { hash: row.Hash, version: row.Version };
            if (action === 'publish') await approveArsenal(ruleType, row.FileName, guard);
            else if (action === 'deprecate') await deprecateArsenal(ruleType, row.FileName, guard);
            else await rollbackArsenal(ruleType, row.FileName, guard);
            message.success(action === 'publish' ? '已发布' : action === 'deprecate' ? '已废弃' : '已回滚为新 Draft');
            await load();
        } catch (error) { message.error(typeof error === 'string' ? error : '操作失败'); }
    };

    const openDebug = async () => {
        try {
            const list = (await getNodes()).filter((node) => node.Status === 'Alive' && agentSupportsBehaviorProbe(node));
            setAgents(list); setDebugResult(null); setDebugOpen(true);
        } catch { message.error('加载 Agent 失败'); }
    };

    const runDebug = async () => {
        try {
            const values = await debugForm.validateFields();
            setDebugging(true);
            setDebugResult(await debugBehaviorProbe({ ...values, file_name: fileName, content }));
        } catch (error) {
            if (typeof error === 'string') message.error(error);
        } finally { setDebugging(false); }
    };

    const columns: ColumnsType<API.Arsenal> = [
        { title: '文件', dataIndex: 'FileName', render: (value: string) => <Text code>{value}</Text> },
        { title: '产品 / 模板', render: (_, row) => <Space direction="vertical" size={0}><Text strong>{catalog[row.FileName]?.ProductName || '待分类'}</Text><Text type="secondary">{catalog[row.FileName]?.Name || '-'}</Text></Space> },
        { title: '安全分类', render: (_, row) => { const rule = catalog[row.FileName]; return <Tag color={rule?.AutoEligible ? 'green' : 'orange'}>{rule?.ComputedAutoProfile || 'unknown'}</Tag>; } },
        { title: '版本', render: (_, row) => <Space><Tag>v{row.Version}</Tag><Text type="secondary">{row.Hash?.slice(0, 10)}</Text></Space> },
        { title: '状态', dataIndex: 'State', render: (value: string) => <Tag color={value === 'Approved' ? 'green' : value === 'Deprecated' ? 'default' : 'gold'}>{value}</Tag> },
        { title: '操作', width: 300, render: (_, row) => <Space wrap>
            <Button size="small" onClick={() => void openEdit(row)}>编辑 / 历史</Button>
            {row.State !== 'Approved' && <Popconfirm title="确认发布该精确版本？" onConfirm={() => void lifecycle('publish', row)}><Button size="small" type="primary">发布</Button></Popconfirm>}
            {row.State === 'Approved' && <Popconfirm title="废弃后将停止自动下发" onConfirm={() => void lifecycle('deprecate', row)}><Button size="small">废弃</Button></Popconfirm>}
            {row.PreviousHash && <Popconfirm title="回滚会创建新的 Draft 版本" onConfirm={() => void lifecycle('rollback', row)}><Button size="small">回滚</Button></Popconfirm>}
        </Space> },
    ];

    const profile = classification?.auto_eligible ? '自动安全' : '受控模板';
    return <>
        <Alert type="info" showIcon style={{ marginBottom: 16 }} message="一条探针一个完整 Nuclei YAML" description="自动扫描仅执行 Server 重新分类为安全的 HTTP/HTTPS 单请求模板；受控模板只能在授权目标上单独调试。每租户最多启用 8 条自动安全探针。" />
        <Space style={{ marginBottom: 16 }}><Button type="primary" onClick={openCreate}>新增行为探针</Button><Text type="secondary">{rows.length} 个独立 Artifact</Text></Space>
        <Table loading={loading} rowKey="ID" dataSource={rows} columns={columns} pagination={{ pageSize: 12 }} />

        <Drawer width="86vw" open={editorOpen} onClose={() => setEditorOpen(false)} title={current ? `编辑 ${current.FileName}` : '新增行为探针'} extra={<Space><Button onClick={() => void classify()}>重新分类</Button><Button onClick={() => void openDebug()} disabled={!fileName || !content}>Agent 调试</Button><Button type="primary" onClick={() => void save()}>保存 Draft</Button></Space>}>
            <Tabs items={[
                { key: 'source', label: 'YAML 与元数据', children: <Space direction="vertical" style={{ width: '100%' }}>
                    <Input value={fileName} disabled={Boolean(current)} onChange={(event) => setFileName(event.target.value)} placeholder="product-detect.yaml" />
                    {classification && <Alert type={classification.auto_eligible ? 'success' : 'warning'} showIcon message={`${profile} · ${classification.product} · ${classification.id}`} description={classification.reasons?.length ? classification.reasons.join('；') : '符合标准任务自动执行边界'} />}
                    {classificationError && <Alert type="error" showIcon message="模板无效" description={classificationError} />}
                    <Editor height="62vh" language="yaml" value={content} onChange={(value) => setContent(value || '')} options={{ minimap: { enabled: false }, wordWrap: 'on' }} />
                </Space> },
                { key: 'history', label: `历史与审计 (${history.length})`, children: history.length === 0 ? <Empty description="保存后生成不可变历史" /> : <Space direction="vertical" style={{ width: '100%' }}>
                    <Timeline items={history.map((event) => ({ children: <Button type="link" onClick={() => event.Content && setDiffEvent(event)}>{event.Action} · v{event.Version} · {new Date(event.CreatedAt).toLocaleString()}</Button> }))} />
                    {diffEvent?.Content && <><Paragraph type="secondary">当前编辑内容与 v{diffEvent.Version} 快照差异</Paragraph><DiffEditor height="42vh" language="yaml" original={diffEvent.Content} modified={content} options={{ readOnly: true, minimap: { enabled: false } }} /></>}
                </Space> },
            ]} />
        </Drawer>

        <Modal width={900} open={debugOpen} onCancel={() => setDebugOpen(false)} onOk={() => void runDebug()} okText="执行一次" confirmLoading={debugging} title="授权目标上的行为探针调试">
            <Form form={debugForm} layout="vertical">
                <Form.Item name="agent_id" label="Agent" rules={[{ required: true }]}><Select options={agents.map((node) => ({ value: node.AgentID, label: `${node.AgentID} · ${node.IP}` }))} placeholder={agents.length ? '选择具备 behavior_probe=v1 的在线 Agent' : '无兼容在线 Agent'} /></Form.Item>
                <Form.Item name="target_url" label="授权目标 URL" rules={[{ required: true }, { type: 'url' }]}><Input placeholder="https://authorized-target.example" /></Form.Item>
                <Form.Item name="proxy" label="代理（可选，write-only）"><Input.Password autoComplete="off" /></Form.Item>
                {!classification?.auto_eligible && <Form.Item name="risk_confirmed" valuePropName="checked" rules={[{ validator: (_, value) => value ? Promise.resolve() : Promise.reject(new Error('受控模板必须确认风险')) }]}><Checkbox>我确认该受控模板只针对已授权目标执行一次</Checkbox></Form.Item>}
            </Form>
            {debugResult && <Descriptions bordered size="small" column={1}>
                <Descriptions.Item label="分类">{debugResult.classification.computed_profile}</Descriptions.Item>
                <Descriptions.Item label="命中产品">{debugResult.transcript.matched_products?.join(', ') || '未命中'}</Descriptions.Item>
                <Descriptions.Item label="结果"><pre style={{ maxHeight: 300, overflow: 'auto', whiteSpace: 'pre-wrap' }}>{JSON.stringify(debugResult.transcript, null, 2)}</pre></Descriptions.Item>
            </Descriptions>}
        </Modal>
    </>;
}
