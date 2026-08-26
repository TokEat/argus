import { useCallback, useEffect, useState } from 'react';
import { Alert, Button, Card, Checkbox, Col, Collapse, Descriptions, Form, Input, InputNumber, Radio, Row, Select, Space, Spin, Statistic, Steps, Switch, Tag, Typography } from 'antd';
import { DatabaseOutlined, ExperimentOutlined, InfoCircleOutlined, SafetyCertificateOutlined } from '@ant-design/icons';
import type { FormInstance } from 'antd';
import { listCredentialDictionaries, listSubdomainDictionaries, previewScanPlan } from '../../services/api';
import CredentialDictionaryManager from './CredentialDictionaryManager';
import SubdomainDictionaryManager from './SubdomainDictionaryManager';

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
	subdomain_bruteforce_depth?: number;
	subdomain_books?: string[];
    allow_cdn_assets?: boolean;
    allow_private_resolved_domains?: boolean;
    host_binding?: boolean;
    directory_probe?: boolean;
	behavior_probe?: boolean;
    risk_validation?: boolean;
    credential_validation?: boolean;
    username_books?: string[];
    password_books?: string[];
    credential_pair_limit?: number;
    validation_confirmed?: boolean;
    high_risk_auto_execution?: boolean;
}

export const presetDefaults: Record<Exclude<API.ScanPreset, 'custom'>, Partial<ScanPolicyFormValues>> = {
    quick: { port_profile: 'common-100', scan_method: 'tcp', intensity: 'low', subdomain_discovery: true, subdomain_bruteforce: false, subdomain_bruteforce_depth: 1, host_binding: false, behavior_probe: false, directory_probe: false, risk_validation: false },
    standard: { port_profile: 'top-1000', scan_method: 'tcp', intensity: 'balanced', subdomain_discovery: true, subdomain_bruteforce: false, subdomain_bruteforce_depth: 1, host_binding: false, behavior_probe: true, directory_probe: false, risk_validation: true },
    deep: { port_profile: 'all', scan_method: 'tcp', intensity: 'high', subdomain_discovery: true, subdomain_bruteforce: true, subdomain_bruteforce_depth: 2, host_binding: true, behavior_probe: true, directory_probe: true, risk_validation: true },
};

export const scanPolicyInitialValues: ScanPolicyFormValues = {
    preset: 'standard', priority: 1, timeout_sec: 3600,
    ...presetDefaults.standard,
    allow_cdn_assets: false, allow_private_resolved_domains: false,
    credential_validation: false, credential_pair_limit: 50000,
    username_books: [], password_books: [], validation_confirmed: false,
	subdomain_books: [],
};

export function buildScanPolicy(values: ScanPolicyFormValues, dictionaries: API.CredentialDictionary[], subdomainDictionaries: API.SubdomainDictionary[] = []): API.ScanPolicy {
    const preset = values.preset || 'standard';
    const presetValues = preset === 'custom' ? {} : presetDefaults[preset];
    const merged = { ...presetValues, ...values };
    const refs = (ids: string[] | undefined, kind: 'username' | 'password') => (ids || []).map((id) => dictionaries.find((item) => item.id === id && item.kind === kind)).filter(Boolean).map((item) => ({
        id: item!.id, revision: item!.revision, sha256: item!.sha256, count: item!.count,
    }));
	const subdomainRefs = Boolean(merged.subdomain_bruteforce)
		? (values.subdomain_books || []).map((id) => subdomainDictionaries.find((item) => item.id === id)).filter(Boolean).map((item) => ({
			id: item!.id, revision: item!.revision, sha256: item!.sha256, count: item!.count,
		}))
		: [];
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
            host_binding: Boolean(merged.host_binding), behavior_probe: Boolean(merged.behavior_probe), directory_probe: Boolean(merged.directory_probe),
            risk_validation: Boolean(merged.risk_validation), credential_validation: Boolean(merged.credential_validation),
        },
		subdomains: {
			wordlists: subdomainRefs,
			bruteforce_depth: merged.subdomain_bruteforce ? (merged.subdomain_bruteforce_depth || 1) : 0,
		},
        credentials: {
            username_books: refs(values.username_books, 'username'), password_books: refs(values.password_books, 'password'),
            pair_limit: values.credential_pair_limit || 50000,
        },
        authorization: { validation_confirmed: Boolean(values.validation_confirmed), allow_high_risk_auto_execution: Boolean(merged.risk_validation) && Boolean(values.high_risk_auto_execution) },
    };
}

const stageNames: Record<string, string> = {
    host_discovery: '资产发现', port_scan: '端口扫描', protocol_identification: '协议识别',
	subdomain_discovery: '子域发现', http_probe: 'HTTP 探测', behavior_probe: '安全行为探针', directory_probe: '主动路径指纹',
	fingerprint: '响应指纹识别', risk_validation: 'POC 验证', credential_validation: '弱口令验证',
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
	const [subdomainDictionaries, setSubdomainDictionaries] = useState<API.SubdomainDictionary[]>([]);
    const [dictionaryOpen, setDictionaryOpen] = useState(false);
	const [subdomainDictionaryOpen, setSubdomainDictionaryOpen] = useState(false);
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

	const loadSubdomainDictionaries = useCallback(async () => {
		if (!projectId) { setSubdomainDictionaries([]); return; }
		try { setSubdomainDictionaries(await listSubdomainDictionaries(projectId)); } catch { setSubdomainDictionaries([]); }
	}, [projectId]);

	useEffect(() => { void loadSubdomainDictionaries(); }, [loadSubdomainDictionaries]);

    const previewKey = JSON.stringify({
        project_id: projectId, targets: values?.targets, preset: values?.preset,
        priority: values?.priority, timeout_sec: values?.timeout_sec,
        port_profile: values?.port_profile, custom_ports: values?.custom_ports,
        scan_method: values?.scan_method, intensity: values?.intensity,
        capabilities: [values?.subdomain_discovery, values?.subdomain_bruteforce, values?.subdomain_bruteforce_depth, values?.allow_cdn_assets, values?.allow_private_resolved_domains, values?.host_binding, values?.behavior_probe, values?.directory_probe, values?.risk_validation, values?.credential_validation, values?.high_risk_auto_execution],
        books: [values?.subdomain_books, values?.username_books, values?.password_books], pair_limit: values?.credential_pair_limit,
        confirmed: values?.validation_confirmed, dictionaries: dictionaries.map((item) => [item.id, item.revision, item.sha256]),
		subdomain_dictionaries: subdomainDictionaries.map((item) => [item.id, item.revision, item.sha256]),
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
				const policy = buildScanPolicy(currentValues, dictionaries, subdomainDictionaries);
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
    }, [previewKey, projectId, form, dictionaries, subdomainDictionaries, onPlanChange]);

    const applyPreset = (preset: API.ScanPreset) => {
        if (preset !== 'custom') form.setFieldsValue({ ...presetDefaults[preset], preset });
        else form.setFieldValue('preset', preset);
    };

    const validationEnabled = Boolean(values?.risk_validation || values?.credential_validation);
    const usernameOptions = dictionaries.filter((item) => item.kind === 'username').map((item) => ({ label: `${item.name} · r${item.revision} · ${item.count} 项`, value: item.id }));
    const passwordOptions = dictionaries.filter((item) => item.kind === 'password').map((item) => ({ label: `${item.name} · r${item.revision} · ${item.count} 项`, value: item.id }));
	const subdomainOptions = subdomainDictionaries.map((item) => ({ label: `${item.name} · r${item.revision} · ${item.count} 项`, value: item.id }));

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
                                    <Radio.Button value="quick">快速 · 常用协议</Radio.Button>
                                    <Radio.Button value="standard">标准 · Top1000</Radio.Button>
                                    <Radio.Button value="deep">深度 · 全端口</Radio.Button>
                                    <Radio.Button value="custom">自定义</Radio.Button>
                                </Radio.Group>
                            </Form.Item>
                        </Card>

						<Card size="small" title="子域发现">
							<Form.Item name="subdomain_discovery" valuePropName="checked" label="被动来源收集" tooltip={{ title: '任务下发前由 Server 从 crt.sh、certspotter、crt.name 等证书透明度公开数据源被动收集候选子域，经 DNS 解析验证去重后密封进任务配置；结果跨任务缓存并共享给所有 Agent，无需任何 API 凭据。默认开启，三种预设均生效。', icon: <InfoCircleOutlined /> }} extra="默认开启；从证书透明度与公共 DNS 数据源收集候选子域。"><Switch /></Form.Item>
							<Form.Item name="subdomain_bruteforce" valuePropName="checked" label="字典爆破" tooltip={{ title: '以并发 DNS 解析方式，用「Scanner 内置子域词典 ∪ 所选项目增量词典」猜测子域，命中者进入后续端口扫描与 HTTP 探测。快速与标准预设默认关闭；深度预设默认开启且为 2 层。始终保留内置词典，项目词典只做增量补充。', icon: <InfoCircleOutlined /> }} extra="深度模式默认开启；始终保留 Scanner 内置字典。"><Switch disabled={!values?.subdomain_discovery} /></Form.Item>
							{values?.subdomain_bruteforce && <>
								<Alert type="info" showIcon message="内置字典 ∪ 项目增量字典" description="Server 去重后将选中的不可变 Revision 密封到本次任务；不接受 Agent 文件路径。" style={{ marginBottom: 12 }} />
				<Form.Item name="subdomain_books" label="项目增量字典" tooltip={{ title: '从项目字典库中选择要叠加的子域词典；Server 会把所选不可变 Revision 的内容与哈希密封进本次任务，保证各 Agent 使用完全一致的词典，不接受 Agent 侧本地文件路径。', icon: <InfoCircleOutlined /> }}><Select mode="multiple" options={subdomainOptions} placeholder="可选；不会替换内置字典" /></Form.Item>
				<Form.Item name="subdomain_bruteforce_depth" label="爆破深度" tooltip={{ title: '控制字典爆破的递归层数：第 1 层对主域做词典拼接猜测，只有上一层真实解析成功的子域才会作为下一层的展开基础，最大支持 4 层。层数越高请求量增长越快；深度预设默认 2 层。', icon: <InfoCircleOutlined /> }} extra="仅对上一层真实解析成功的子域继续展开；层数越高，请求量增长越快。">
					<Select options={[1, 2, 3, 4].map((value) => ({ value, label: `${value} 层` }))} />
				</Form.Item>
				<Button size="small" onClick={() => setSubdomainDictionaryOpen(true)}>管理子域字典</Button>
							</>}
						</Card>

						<Card size="small" title="Web 指纹识别">
							<Alert type="success" showIcon message="响应指纹识别（默认）" description="复用 HTTP 探测响应完成基础指纹识别，作为后续 Workflow 与 POC 匹配依据。" style={{ marginBottom: 12 }} />
							<Form.Item name="behavior_probe" valuePropName="checked" label="安全行为探针" tooltip={{ title: 'HTTP 探测完成后对存活 Web 服务执行一批经安全审核的 Nuclei 行为探针：Server 仅保留重新分类为「自动安全」的单请求探针，每个 HTTP 服务每探针最多发送一次请求，用于补充行为特征并作为指纹与 POC 匹配依据。标准与深度预设默认开启。', icon: <InfoCircleOutlined /> }} extra="标准、深度默认开启；仅执行 Server 重新分类为自动安全的单请求 Nuclei 探针。"><Switch /></Form.Item>
							<Form.Item name="directory_probe" valuePropName="checked" label="主动路径指纹" tooltip={{ title: '对已识别出产品的资产请求其规则定义的特征路径（如 Spring Actuator、Druid 控制台等），命中即产出 Active-Finger 指纹供后续 Workflow 匹配；只请求规则内路径，不执行通用目录爆破。仅深度预设默认开启，开启会增加少量请求。', icon: <InfoCircleOutlined /> }} extra="可选；请求产品特征路径并产出 Active-Finger，不执行通用目录扫描。"><Switch /></Form.Item>
						</Card>

						<Card size="small" title="自动验证">
							<Alert
								type="info"
								showIcon
								message="GoPoc 是内部执行框架，不是第三个扫描开关"
								description="协议类 GoPoc 随协议识别形成资产证据；漏洞类 GoPoc 与 Nuclei 统一归入自动 POC；凭据类 GoPoc 只在弱口令阶段执行。"
								style={{ marginBottom: 12 }}
							/>
							<Row gutter={[12, 8]}>
								<Col span={12}><Form.Item name="risk_validation" valuePropName="checked" label="自动 POC 验证" tooltip={{ title: '指纹识别完成后自动匹配并执行漏洞验证：Workflow 规则命中的资产运行对应 Nuclei 模板，服务精确命中的执行受审核 GoPoc 漏洞检查。默认仅自动执行 info/low/medium 风险的已审批 POC；高风险与未分类 POC 默认跳过，可开启下方预授权或事后经手动风险验证二次确认执行。需勾选页面底部的授权范围确认。标准与深度预设默认开启。', icon: <InfoCircleOutlined /> }}><Switch /></Form.Item></Col>
									<Col span={12}><Form.Item name="credential_validation" valuePropName="checked" label="弱口令验证" tooltip={{ title: '对协议识别确认的服务（SSH、数据库、中间件等）使用「内置服务凭据字典 ∪ 所选项目用户名本×密码本」尝试登录验证，组合数受「每服务目标组合上限」约束防止请求爆炸；同样需要授权确认后才执行。默认关闭，开启后在下方配置增量字典。', icon: <InfoCircleOutlined /> }}><Switch /></Form.Item></Col>
								</Row>
								{values?.risk_validation && (
									<Form.Item name="high_risk_auto_execution" valuePropName="checked" label="高风险 POC 预授权" extra="默认关闭；开启后自动阶段将直接执行已审批的高风险/未分类 POC。" tooltip={{ title: '任务级显式预授权开关：关闭时自动阶段跳过 high 与未分类（unknown）风险的已审批 POC 并记录原因，这些 POC 需在任务完成后通过手动「风险验证」入口经二次确认执行；开启后资产发现结束将直接自动执行它们。该选择会密封进不可变任务快照并写入审计，请确认目标均在授权范围内后再开启。', icon: <InfoCircleOutlined /> }}><Switch /></Form.Item>
								)}
						</Card>

                        {values?.credential_validation && (
                            <Card size="small" title={<Space><DatabaseOutlined />增量凭据字典</Space>} extra={<Button size="small" onClick={() => setDictionaryOpen(true)}>管理字典</Button>}>
                                <Alert type="info" showIcon message="内置服务字典始终参与验证" description="所选项目用户名本 × 密码本只做增量补充；任务锁定当前 Revision 与哈希。" style={{ marginBottom: 12 }} />
                                <Form.Item name="username_books" label="用户名本" tooltip={{ title: '从项目凭据字典库中选择用户名词典作为增量来源；与下方密码本做笛卡尔积生成本次任务的增量弱口令组合。内容按所选不可变 Revision 加密存储并密封进一次性凭据包（带哈希校验）下发给 Agent，不影响 Scanner 内置服务字典。', icon: <InfoCircleOutlined /> }}><Select mode="multiple" options={usernameOptions} placeholder="可选；不影响内置用户名" /></Form.Item>
                                <Form.Item name="password_books" label="密码本" tooltip={{ title: '从项目凭据字典库中选择密码词典作为增量来源；与上方用户名本做笛卡尔积生成增量弱口令组合，同样按不可变 Revision 密封下发。两者都未选择时不产生增量组合，仅使用内置服务字典。', icon: <InfoCircleOutlined /> }}><Select mode="multiple" options={passwordOptions} placeholder="可选；不影响内置密码" /></Form.Item>
                                <Form.Item name="credential_pair_limit" label="每服务目标组合上限" tooltip={{ title: '限制「所选用户名本×密码本」笛卡尔积的最大组合数：默认 50000，最大 100000，超出会直接拒绝生成验证计划；Server 同时按 目标数×该上限 预估请求预算并密封进任务，防止弱口令阶段对目标产生过量登录尝试。内置服务字典不受此上限约束。', icon: <InfoCircleOutlined /> }}><InputNumber min={1} max={100000} step={1000} style={{ width: '100%' }} /></Form.Item>
                            </Card>
                        )}

                        <Collapse items={[{ key: 'expert', label: <Space><ExperimentOutlined />结构化专家配置</Space>, children: (
                            <Row gutter={12}>
                                <Col span={8}><Form.Item name="scan_method" label="扫描方式" tooltip={{ title: 'TCP：全连接扫描，兼容性最好，无需特殊权限；SYN：Agent 内置半开扫描（Linux raw socket + SYN cookie），速度更快，仅调度已上报 scan_syn=v1 的 Agent（通常需 CAP_NET_RAW/root）。不具备能力的 Agent 不会领取 SYN 任务；已领取后运行时失败会降级 TCP。', icon: <InfoCircleOutlined /> }}><Select options={[{ value: 'tcp', label: 'TCP' }, { value: 'syn', label: 'SYN（内置，需 Linux Agent）' }]} /></Form.Item></Col>
                                <Col span={8}><Form.Item name="port_profile" label="端口范围" tooltip={{ title: '常用协议端口：134 个精选常见协议与中间件端口，速度最快；Top1000：Nmap 频率统计前 1000 端口，覆盖均衡；1-65535：全端口最完整但耗时显著增加；自定义：如 22,80,443,8000-9000。该端口集同时决定 CDN 域名盲探的范围。', icon: <InfoCircleOutlined /> }}><Select disabled={values?.preset !== 'custom'} options={[{ value: 'common-100', label: '常用协议端口' }, { value: 'top-1000', label: 'Top1000' }, { value: 'all', label: '1-65535' }, { value: 'custom', label: '自定义' }]} /></Form.Item></Col>
                                <Col span={8}><Form.Item name="intensity" label="强度" tooltip={{ title: '控制存活探测、端口扫描、Web 探测等各阶段的并发线程数与发包速率。低：对目标压力最小，适合脆弱生产环境；均衡：默认推荐；高：覆盖最快，但对目标压力大、网络丢包引起的误判风险升高。', icon: <InfoCircleOutlined /> }}><Select options={[{ value: 'low', label: '低' }, { value: 'balanced', label: '均衡' }, { value: 'high', label: '高' }]} /></Form.Item></Col>
                                {values?.port_profile === 'custom' && <Col span={24}><Form.Item name="custom_ports" label="自定义端口" tooltip={{ title: '逗号分隔的单个端口或区间，例如 22,80,443,8000-9000。最多 65535 个端口。', icon: <InfoCircleOutlined /> }} rules={[{ required: true, message: '请输入端口范围' }]}><Input placeholder="22,80,443,8000-9000" /></Form.Item></Col>}
                                <Col span={8}><Form.Item name="priority" label="优先级" tooltip={{ title: '任务在调度队列中的执行顺序：P0 紧急最先被 Agent 领取，P1 普通为默认，P2 低适合非紧急的例行扫描。', icon: <InfoCircleOutlined /> }}><Select options={[{ value: 0, label: 'P0 紧急' }, { value: 1, label: 'P1 普通' }, { value: 2, label: 'P2 低' }]} /></Form.Item></Col>
                                <Col span={8}><Form.Item name="timeout_sec" label="任务超时（秒）" tooltip={{ title: '单个扫描批次允许执行的最长时间，超过后该批次会被判定失败并按策略重试或拆分重跑。默认 3600 秒（1 小时）；全端口大网段建议适当调大。', icon: <InfoCircleOutlined /> }}><InputNumber min={0} step={60} style={{ width: '100%' }} /></Form.Item></Col>
                                <Col span={8}><Form.Item name="allow_cdn_assets" valuePropName="checked" label="允许 CDN 资产" tooltip={{ title: '开启后：判定为 CDN 的域名不扫描其解析 IP（避免触达厂商基础设施），而是按上方端口范围对域名本身以 域名:端口 形式做 Web 盲探，产出的资产带「疑似 CDN」标记。关闭时仅记录 CDN 判定结果，不做探测。', icon: <InfoCircleOutlined /> }}><Switch /></Form.Item></Col>
                                <Col span={8}><Form.Item name="allow_private_resolved_domains" valuePropName="checked" label="允许解析到私网" tooltip={{ title: '域名解析到私网/回环地址（如 10.x、192.168.x、127.x）时是否纳入扫描。默认关闭=跳过这些解析结果，防止误扫内网；开启后才会对私网 IP 做存活探测与端口扫描。请确认私网目标在授权范围内再开启。', icon: <InfoCircleOutlined /> }}><Switch /></Form.Item></Col>
								<Col span={8}><Form.Item name="host_binding" valuePropName="checked" label="Host Binding" tooltip={{ title: '基于本任务已建立的 DNS 解析记录，对发现的存活 IP 站点反查绑定域名，再以 域名:端口 形式补充探测，可发现仅靠 IP 访问看不到的虚拟主机资产。开启会增加请求量。', icon: <InfoCircleOutlined /> }}><Switch /></Form.Item></Col>
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
								<Descriptions.Item label="增量子域词">{(preview.custom_subdomain_words || 0).toLocaleString()}（另含内置字典）</Descriptions.Item>
								{preview.policy.capabilities.subdomain_bruteforce && <Descriptions.Item label="子域爆破深度">{preview.policy.subdomains.bruteforce_depth} 层（逐层命中后扩展）</Descriptions.Item>}
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
			<SubdomainDictionaryManager open={subdomainDictionaryOpen} projectId={projectId} onClose={() => setSubdomainDictionaryOpen(false)} onChanged={setSubdomainDictionaries} />
        </>
    );
}
