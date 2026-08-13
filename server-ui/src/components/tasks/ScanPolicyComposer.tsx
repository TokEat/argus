import { useCallback, useEffect, useState } from 'react';
import { Alert, Button, Card, Checkbox, Col, Collapse, Descriptions, Divider, Form, Input, InputNumber, Radio, Row, Select, Space, Spin, Statistic, Steps, Switch, Tag, Typography } from 'antd';
import { DatabaseOutlined, ExperimentOutlined, SafetyCertificateOutlined } from '@ant-design/icons';
import type { FormInstance } from 'antd';
import { listCredentialDictionaries, previewScanPlan } from '../../services/api';
import CredentialDictionaryManager from './CredentialDictionaryManager';

const { Text } = Typography;

export interface ScanPolicyFormValues {
    project_id?: string;
    name?: string;
    targets?: string;
    preset?: API.ScanPreset;
    priority?: number;
    timeout_sec?: number;
    port_profile?: API.ScanPortProfile;
    custom_ports?: string;
    scan_method?: API.ScanMethod;
    intensity?: API.ScanIntensity;
    subdomain_discovery?: boolean;
    subdomain_bruteforce?: boolean;
    allow_cdn_assets?: boolean;
    allow_private_resolved_domains?: boolean;
    host_binding?: boolean;
    directory_probe?: boolean;
    risk_validation?: boolean;
    credential_validation?: boolean;
    username_books?: string[];
    password_books?: string[];
    credential_pair_limit?: number;
    validation_confirmed?: boolean;
}

export const presetDefaults: Record<Exclude<API.ScanPreset, 'custom'>, Partial<ScanPolicyFormValues>> = {
    quick: { port_profile: 'common-100', scan_method: 'tcp', intensity: 'low', subdomain_discovery: true, subdomain_bruteforce: false, host_binding: false, directory_probe: false, risk_validation: false },
    standard: { port_profile: 'top-1000', scan_method: 'tcp', intensity: 'balanced', subdomain_discovery: true, subdomain_bruteforce: false, host_binding: false, directory_probe: false, risk_validation: true },
    deep: { port_profile: 'all', scan_method: 'tcp', intensity: 'high', subdomain_discovery: true, subdomain_bruteforce: true, host_binding: true, directory_probe: true, risk_validation: true },
};

export const scanPolicyInitialValues: ScanPolicyFormValues = {
    preset: 'standard', priority: 1, timeout_sec: 3600,
    ...presetDefaults.standard,
    allow_cdn_assets: false, allow_private_resolved_domains: false,
    credential_validation: false, credential_pair_limit: 50000,
    username_books: [], password_books: [], validation_confirmed: false,
};

export function buildScanPolicy(values: ScanPolicyFormValues, dictionaries: API.CredentialDictionary[]): API.ScanPolicy {
    const preset = values.preset || 'standard';
    const presetValues = preset === 'custom' ? {} : presetDefaults[preset];
    const merged = { ...presetValues, ...values };
    const refs = (ids: string[] | undefined, kind: 'username' | 'password') => (ids || []).map((id) => dictionaries.find((item) => item.id === id && item.kind === kind)).filter(Boolean).map((item) => ({
        id: item!.id, revision: item!.revision, sha256: item!.sha256, count: item!.count,
    }));
    return {
        schema_version: 'argus.scan-policy/v1', preset,
        port_profile: merged.port_profile || 'top-1000',
        ...(merged.port_profile === 'custom' ? { custom_ports: String(merged.custom_ports || '') } : {}),
        scan_method: merged.scan_method || 'tcp', intensity: merged.intensity || 'balanced',
        capabilities: {
            subdomain_discovery: Boolean(merged.subdomain_discovery),
            subdomain_bruteforce: Boolean(merged.subdomain_bruteforce),
            allow_cdn_assets: Boolean(merged.allow_cdn_assets),
            allow_private_resolved_domains: Boolean(merged.allow_private_resolved_domains),
            host_binding: Boolean(merged.host_binding), directory_probe: Boolean(merged.directory_probe),
            risk_validation: Boolean(merged.risk_validation), credential_validation: Boolean(merged.credential_validation),
        },
        credentials: {
            username_books: refs(values.username_books, 'username'), password_books: refs(values.password_books, 'password'),
            pair_limit: values.credential_pair_limit || 50000,
        },
        authorization: { validation_confirmed: Boolean(values.validation_confirmed) },
    };
}

const stageNames: Record<string, string> = {
    host_discovery: '资产发现', port_scan: '端口扫描', protocol_identification: '协议识别',
    http_probe: 'HTTP 探测', fingerprint: '指纹识别', risk_validation: 'POC 验证', credential_validation: '弱口令验证',
};

interface Props {
    form: FormInstance<ScanPolicyFormValues>;
    projects: API.Project[];
    onPlanChange: (plan: API.ScanPlanPreview | null) => void;
}

export default function ScanPolicyComposer({ form, projects, onPlanChange }: Props) {
    const values = Form.useWatch([], form) as ScanPolicyFormValues | undefined;
    const projectId = values?.project_id || '';
    const [dictionaries, setDictionaries] = useState<API.CredentialDictionary[]>([]);
    const [dictionaryOpen, setDictionaryOpen] = useState(false);
    const [preview, setPreview] = useState<API.ScanPlanPreview | null>(null);
    const [previewError, setPreviewError] = useState('');
    const [previewing, setPreviewing] = useState(false);

    const loadDictionaries = useCallback(async () => {
        if (!projectId) {
            setDictionaries([]);
            return;
        }
        try { setDictionaries(await listCredentialDictionaries(projectId)); } catch { setDictionaries([]); }
    }, [projectId]);

    useEffect(() => { void loadDictionaries(); }, [loadDictionaries]);

    const previewKey = JSON.stringify({
        project_id: projectId, targets: values?.targets, preset: values?.preset,
        priority: values?.priority, timeout_sec: values?.timeout_sec,
        port_profile: values?.port_profile, custom_ports: values?.custom_ports,
        scan_method: values?.scan_method, intensity: values?.intensity,
        capabilities: [values?.subdomain_discovery, values?.subdomain_bruteforce, values?.allow_cdn_assets, values?.allow_private_resolved_domains, values?.host_binding, values?.directory_probe, values?.risk_validation, values?.credential_validation],
        books: [values?.username_books, values?.password_books], pair_limit: values?.credential_pair_limit,
        confirmed: values?.validation_confirmed, dictionaries: dictionaries.map((item) => [item.id, item.revision, item.sha256]),
    });

    useEffect(() => {
        const currentValues = form.getFieldsValue(true) as ScanPolicyFormValues;
        if (!projectId || !currentValues.targets?.trim()) {
            setPreview(null); setPreviewError('填写项目和目标后生成执行计划'); onPlanChange(null); return;
        }
        let cancelled = false;
        const timer = window.setTimeout(async () => {
            setPreviewing(true); setPreviewError('');
            try {
                const policy = buildScanPolicy(currentValues, dictionaries);
                const result = await previewScanPlan({ project_id: projectId, targets: currentValues.targets!, policy, priority: currentValues.priority, timeout_sec: currentValues.timeout_sec });
                if (cancelled) return;
                setPreview(result); onPlanChange(result);
            } catch (error) {
                if (cancelled) return;
                setPreview(null); onPlanChange(null);
                setPreviewError(typeof error === 'string' ? error : '计划预览失败');
            } finally { if (!cancelled) setPreviewing(false); }
        }, 350);
        return () => { cancelled = true; window.clearTimeout(timer); };
    }, [previewKey, projectId, form, dictionaries, onPlanChange]);

    const applyPreset = (preset: API.ScanPreset) => {
        if (preset !== 'custom') form.setFieldsValue({ ...presetDefaults[preset], preset });
        else form.setFieldValue('preset', preset);
    };

    const validationEnabled = Boolean(values?.risk_validation || values?.credential_validation);
    const usernameOptions = dictionaries.filter((item) => item.kind === 'username').map((item) => ({ label: `${item.name} · r${item.revision} · ${item.count} 项`, value: item.id }));
    const passwordOptions = dictionaries.filter((item) => item.kind === 'password').map((item) => ({ label: `${item.name} · r${item.revision} · ${item.count} 项`, value: item.id }));

    return (
        <>
            <Row gutter={20} align="top">
                <Col xs={24} xl={13}>
                    <Space direction="vertical" size={12} style={{ width: '100%' }}>
                        <Card size="small" title="项目与目标">
                            <Form.Item name="project_id" label="所属项目" rules={[{ required: true, message: '请选择所属项目' }]}>
                                <Select showSearch optionFilterProp="label" options={projects.map((project) => ({ label: project.Name, value: project.ID }))} placeholder="选择项目" />
                            </Form.Item>
                            <Form.Item name="name" label="任务名称（可选）"><Input placeholder="自动生成任务名称" /></Form.Item>
                            <Form.Item name="targets" label="扫描目标" rules={[{ required: true, whitespace: true, message: '请输入扫描目标' }]} extra="每行一个 IP、域名、CIDR、IP 段或 URL。">
                                <Input.TextArea rows={6} placeholder={'192.168.1.10\nexample.com\nhttps://example.com'} />
                            </Form.Item>
                        </Card>

                        <Card size="small" title="扫描预设">
                            <Form.Item name="preset" noStyle>
                                <Radio.Group buttonStyle="solid" onChange={(event) => applyPreset(event.target.value)}>
                                    <Radio.Button value="quick">快速 · 常用100</Radio.Button>
                                    <Radio.Button value="standard">标准 · Top1000</Radio.Button>
                                    <Radio.Button value="deep">深度 · 全端口</Radio.Button>
                                    <Radio.Button value="custom">自定义</Radio.Button>
                                </Radio.Group>
                            </Form.Item>
                            <Divider style={{ margin: '14px 0' }} />
                            <Row gutter={[12, 8]}>
                                <Col span={12}><Form.Item name="subdomain_discovery" valuePropName="checked" label="被动子域"><Switch /></Form.Item></Col>
                                <Col span={12}><Form.Item name="subdomain_bruteforce" valuePropName="checked" label="子域爆破"><Switch disabled={!values?.subdomain_discovery} /></Form.Item></Col>
                                <Col span={12}><Form.Item name="host_binding" valuePropName="checked" label="Host Binding"><Switch /></Form.Item></Col>
                                <Col span={12}><Form.Item name="directory_probe" valuePropName="checked" label="目录探测"><Switch /></Form.Item></Col>
                                <Col span={12}><Form.Item name="risk_validation" valuePropName="checked" label="自动 POC 验证"><Switch /></Form.Item></Col>
                                <Col span={12}><Form.Item name="credential_validation" valuePropName="checked" label="弱口令验证"><Switch /></Form.Item></Col>
                            </Row>
                        </Card>

                        {values?.credential_validation && (
                            <Card size="small" title={<Space><DatabaseOutlined />增量凭据字典</Space>} extra={<Button size="small" onClick={() => setDictionaryOpen(true)}>管理字典</Button>}>
                                <Alert type="info" showIcon message="内置服务字典始终参与验证" description="所选项目用户名本 × 密码本只做增量补充；任务锁定当前 Revision 与哈希。" style={{ marginBottom: 12 }} />
                                <Form.Item name="username_books" label="用户名本"><Select mode="multiple" options={usernameOptions} placeholder="可选；不影响内置用户名" /></Form.Item>
                                <Form.Item name="password_books" label="密码本"><Select mode="multiple" options={passwordOptions} placeholder="可选；不影响内置密码" /></Form.Item>
                                <Form.Item name="credential_pair_limit" label="每服务目标组合上限"><InputNumber min={1} max={100000} step={1000} style={{ width: '100%' }} /></Form.Item>
                            </Card>
                        )}

                        <Collapse items={[{ key: 'expert', label: <Space><ExperimentOutlined />结构化专家配置</Space>, children: (
                            <Row gutter={12}>
                                <Col span={8}><Form.Item name="scan_method" label="扫描方式"><Select options={[{ value: 'tcp', label: 'TCP' }, { value: 'syn', label: 'SYN（需兼容 Agent）' }]} /></Form.Item></Col>
                                <Col span={8}><Form.Item name="port_profile" label="端口范围"><Select disabled={values?.preset !== 'custom'} options={[{ value: 'common-100', label: '常用100' }, { value: 'top-1000', label: 'Top1000' }, { value: 'all', label: '1-65535' }, { value: 'custom', label: '自定义' }]} /></Form.Item></Col>
                                <Col span={8}><Form.Item name="intensity" label="强度"><Select options={[{ value: 'low', label: '低' }, { value: 'balanced', label: '均衡' }, { value: 'high', label: '高' }]} /></Form.Item></Col>
                                {values?.port_profile === 'custom' && <Col span={24}><Form.Item name="custom_ports" label="自定义端口" rules={[{ required: true, message: '请输入端口范围' }]}><Input placeholder="22,80,443,8000-9000" /></Form.Item></Col>}
                                <Col span={8}><Form.Item name="priority" label="优先级"><Select options={[{ value: 0, label: 'P0 紧急' }, { value: 1, label: 'P1 普通' }, { value: 2, label: 'P2 低' }]} /></Form.Item></Col>
                                <Col span={8}><Form.Item name="timeout_sec" label="任务超时（秒）"><InputNumber min={0} step={60} style={{ width: '100%' }} /></Form.Item></Col>
                                <Col span={8}><Form.Item name="allow_cdn_assets" valuePropName="checked" label="允许 CDN 资产"><Switch /></Form.Item></Col>
                                <Col span={8}><Form.Item name="allow_private_resolved_domains" valuePropName="checked" label="允许解析到私网"><Switch /></Form.Item></Col>
                            </Row>
                        ) }]} />

                        {validationEnabled && <Form.Item name="validation_confirmed" valuePropName="checked" rules={[{ validator: (_, checked) => checked ? Promise.resolve() : Promise.reject(new Error('请确认授权范围')) }]}>
                            <Checkbox><SafetyCertificateOutlined /> 我确认全部目标均在当前项目授权范围内，同意自动执行匹配的已审核 POC 与所选弱口令阶段</Checkbox>
                        </Form.Item>}
                    </Space>
                </Col>

                <Col xs={24} xl={11}>
                    <Card title="实时执行计划" style={{ position: 'sticky', top: 8 }}>
                        {previewing && <div style={{ textAlign: 'center', padding: 24 }}><Spin tip="Server 正在编译策略" /></div>}
                        {!previewing && previewError && <Alert type={validationEnabled && !values?.validation_confirmed ? 'warning' : 'info'} showIcon message={previewError} />}
                        {!previewing && preview && <Space direction="vertical" size={16} style={{ width: '100%' }}>
                            <Row gutter={8}>
                                <Col span={8}><Statistic title="端口" value={preview.port_count} /></Col>
                                <Col span={8}><Statistic title="匹配 Agent" value={preview.matched_agents} /></Col>
                                <Col span={8}><Statistic title="可用槽位" value={preview.available_slots} /></Col>
                            </Row>
                            <Steps direction="vertical" size="small" items={preview.stages.filter((stage) => stage.enabled).map((stage) => ({ title: stageNames[stage.id] || stage.id, description: stage.reason }))} />
                            <Descriptions size="small" column={1} bordered>
                                <Descriptions.Item label="规则版本"><Tag color="blue">{preview.rule_version || 'unknown'}</Tag></Descriptions.Item>
                                <Descriptions.Item label="预计基础请求">{preview.estimated_requests.toLocaleString()}</Descriptions.Item>
                                <Descriptions.Item label="弱口令增量组合">{preview.custom_credential_pairs.toLocaleString()} / {preview.credential_pair_limit.toLocaleString()}</Descriptions.Item>
                                <Descriptions.Item label="验证预算">并发 {preview.validation_budget.target_concurrency} · {preview.validation_budget.rate_limit}/s</Descriptions.Item>
                                <Descriptions.Item label="计划哈希"><Text code>{preview.plan_hash.slice(0, 16)}…</Text></Descriptions.Item>
                            </Descriptions>
                            {preview.agent_reasons?.map((reason) => <Alert key={reason} type="warning" showIcon message={reason} />)}
                        </Space>}
                    </Card>
                </Col>
            </Row>
            <CredentialDictionaryManager open={dictionaryOpen} projectId={projectId} onClose={() => setDictionaryOpen(false)} onChanged={setDictionaries} />
        </>
    );
}
