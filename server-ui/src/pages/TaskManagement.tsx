import React, { useEffect, useMemo, useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
    Alert,
    App,
    Badge,
    Button,
    Col,
    Collapse,
    Descriptions,
    Divider,
    Drawer,
    Empty,
    Form,
    Input,
    InputNumber,
    Modal,
    Popconfirm,
    Progress,
    Row,
    Select,
    Space,
    Spin,
    Statistic,
    Switch,
    Table,
    Tag,
    Tooltip,
    Typography,
} from 'antd';
import { ProCard } from '@ant-design/pro-components';
import {
    AimOutlined,
    ApiOutlined,
    AuditOutlined,
    BugOutlined,
    CloudServerOutlined,
    DeleteOutlined,
    ExperimentOutlined,
    EyeOutlined,
    GlobalOutlined,
    InfoCircleOutlined,
    KeyOutlined,
    PlusOutlined,
    RadarChartOutlined,
    ReloadOutlined,
    RocketOutlined,
    SearchOutlined,
    StopOutlined,
    WifiOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import { cancelTask, connectWebSocket, createTask, deleteTask, listTasks, listProjects, getTaskDetail, getNodes, previewTaskSelector } from '../services/api';
import { getTaskStatusMeta, isTaskCancellable, isTaskFailedLike, isTaskFinished, normalizeTaskStatus } from '../utils/taskStatus';
import { canAccessRole } from '../utils/auth';
import { useAutoContext } from '../contexts/GlobalAIContext';
import gsap from 'gsap';
import NetworkCanvas from '../components/NetworkCanvas';

const { Title, Text } = Typography;
const { TextArea } = Input;

type TaskSourceMode = 'direct' | 'hunter' | 'fofa' | 'hunter_fofa' | 'quake';

const sourceModeOptions = [
    { value: 'direct', label: '直接目标' },
    { value: 'hunter', label: 'Hunter' },
    { value: 'fofa', label: 'Fofa' },
    { value: 'hunter_fofa', label: 'Hunter + Fofa' },
    { value: 'quake', label: 'Quake' },
];

const sourceModeHints: Record<TaskSourceMode, string> = {
    direct: '每行一个目标，支持 IP、IP:Port、CIDR、IP 段、域名、域名:Port、URL。',
    hunter: '每行一个 Hunter 查询语句，需使用 field=value 形式，例如 icp.name="xxx有限公司"。',
    fofa: '每行一个 Fofa 查询语句，需使用 field=value 形式，例如 title="nginx"。',
    hunter_fofa: '每行一个通用查询语句，将同时交给 Hunter 与 Fofa，需使用 field=value 形式。',
    quake: '每行一个 Quake 查询语句，需使用 field:value 形式，例如 service:http。',
};

const targetTypeLabels: Record<string, string> = {
    url: 'URL',
    domain: '域名',
    domain_port: '域名端口',
    ip: 'IP',
    cidr: 'CIDR',
    ip_range: 'IP 段',
    ip_port: 'IP 端口',
    osint: '空间搜索',
    unknown: '未知',
};

const createInitialValues = {
    source_mode: 'direct' as TaskSourceMode,
    priority: 1,
    timeout_sec: 3600,
    agent_selector_pairs: [],
    agent_selector_rules_json: '',
    PortScanType: 'tcp',
    TCPPortScanThreads: 1000,
    SYNPortScanThreads: 10000,
    PortsThreshold: 300,
    TCPPortScanTimeout: 6,
    GetBannerThreads: 500,
    GetBannerTimeout: 5,
    WebThreads: 200,
    WebTimeout: 10,
    GoPocThreads: 50,
    HunterPageSize: 100,
    HunterMaxPageCount: 10,
    FofaMaxCount: 100,
    QuakeSize: 100,
};

function compactObject(input: Record<string, unknown>) {
    return Object.fromEntries(
        Object.entries(input).filter(([, value]) => value !== undefined && value !== null && value !== '')
    );
}

function parseNodeTags(tags?: string): Record<string, string> {
    if (!tags) return {};
    try {
        const parsed = JSON.parse(tags);
        if (parsed && !Array.isArray(parsed) && typeof parsed === 'object') {
            return Object.fromEntries(
                Object.entries(parsed as Record<string, unknown>)
                    .filter(([, value]) => typeof value === 'string')
                    .map(([key, value]) => [key, String(value)])
            );
        }
    } catch {
        return {};
    }
    return {};
}

function selectorFromPairs(pairs?: { key?: string; value?: string }[]): Record<string, string> | undefined {
    const selector: Record<string, string> = {};
    (pairs || []).forEach((pair) => {
        const key = pair?.key?.trim();
        const value = pair?.value?.trim();
        if (key && value) {
            selector[key] = value;
        }
    });
    return Object.keys(selector).length > 0 ? selector : undefined;
}

function selectorRulesFromJSON(raw?: string): API.AgentSelectorRules | undefined {
    const trimmed = raw?.trim();
    if (!trimmed) return undefined;
    return JSON.parse(trimmed) as API.AgentSelectorRules;
}

function parseAdvancedConfig(raw?: string) {
    const trimmed = raw?.trim();
    if (!trimmed) {
        return {};
    }

    const parsed = JSON.parse(trimmed);
    if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
        throw new Error('高级配置必须是 JSON 对象');
    }
    return parsed as Record<string, unknown>;
}

function buildTaskConfig(values: Record<string, unknown>) {
    const sourceMode = (values.source_mode as TaskSourceMode) || 'direct';
    const config: Record<string, unknown> = {
        Ports: values.Ports,
        PortScanType: values.PortScanType,
        SkipHostDiscovery: values.SkipHostDiscovery,
        NoICMPPing: values.NoICMPPing,
        TCPPing: values.TCPPing,
        TCPPortScanThreads: values.TCPPortScanThreads,
        SYNPortScanThreads: values.SYNPortScanThreads,
        PortsThreshold: values.PortsThreshold,
        TCPPortScanTimeout: values.TCPPortScanTimeout,
        GetBannerThreads: values.GetBannerThreads,
        GetBannerTimeout: values.GetBannerTimeout,
        Subdomain: values.Subdomain,
        NoSubdomainBruteForce: values.NoSubdomainBruteForce,
        NoSubFinder: values.NoSubFinder,
        AllowCDNAssets: values.AllowCDNAssets,
        AllowLocalAreaDomain: values.AllowLocalAreaDomain,
        NoHostBind: values.NoHostBind,
        WebThreads: values.WebThreads,
        WebTimeout: values.WebTimeout,
        NoDirSearch: values.NoDirSearch,
        NoPoc: values.NoPoc,
        GolangPoc: values.GolangPoc,
        DisableGeneralPoc: values.DisableGeneralPoc,
        GoPocThreads: values.GoPocThreads,
        ExcludeTags: values.ExcludeTags,
        Severities: values.Severities,
        PocNameForSearch: values.PocNameForSearch,
        Password: values.Password,
        PasswordFile: values.PasswordFile,
    };

    if (sourceMode === 'hunter' || sourceMode === 'hunter_fofa') {
        config.Hunter = true;
        config.HunterPageSize = values.HunterPageSize;
        config.HunterMaxPageCount = values.HunterMaxPageCount;
    }
    if (sourceMode === 'fofa' || sourceMode === 'hunter_fofa') {
        config.Fofa = true;
        config.FofaMaxCount = values.FofaMaxCount;
    }
    if (sourceMode === 'quake') {
        config.Quake = true;
        config.QuakeSize = values.QuakeSize;
    }
    if (sourceMode === 'hunter') {
        config.LowPerceptionMode = values.LowPerceptionMode;
    }
    if (sourceMode !== 'direct') {
        config.OnlyIPPort = values.OnlyIPPort;
    }

    return compactObject(config);
}

const TaskManagement: React.FC = () => {
    const [loading, setLoading] = useState(true);
    const [tasks, setTasks] = useState<API.RootTask[]>([]);
    const [createOpen, setCreateOpen] = useState(false);
    const [creating, setCreating] = useState(false);
    const [form] = Form.useForm();
    const { message } = App.useApp();
    const navigate = useNavigate();
    const sourceMode = (Form.useWatch('source_mode', form) as TaskSourceMode | undefined) || 'direct';
    const watchedProjectId = Form.useWatch('project_id', form) as string | undefined;
    const watchedTargets = Form.useWatch('targets', form) as string | undefined;
    const selectorPairs = Form.useWatch('agent_selector_pairs', form) as { key?: string; value?: string }[] | undefined;
    const globalProjectId = localStorage.getItem('active_project_id') || '';
    const [projects, setProjects] = useState<API.Project[]>([]);
    const [nodes, setNodes] = useState<API.AgentNode[]>([]);
    const [detailOpen, setDetailOpen] = useState(false);
    const [detailLoading, setDetailLoading] = useState(false);
    const [taskDetail, setTaskDetail] = useState<API.TaskDetailResponse | null>(null);
    const [selectorPreview, setSelectorPreview] = useState<API.TaskSelectorPreview | null>(null);
    const [selectorPreviewLoading, setSelectorPreviewLoading] = useState(false);
    const canManageTasks = canAccessRole('operator');
    const pageRef = useRef<HTMLDivElement>(null);

    /* GSAP entrance */
    useEffect(() => {
        if (!pageRef.current) return;
        const els = pageRef.current.querySelectorAll('.task-animate-in');
        if (els.length === 0) return;
        const ctx = gsap.context(() => {
            gsap.from(els, {
                y: 24, opacity: 0, duration: 0.45,
                stagger: 0.08, ease: 'power2.out', clearProps: 'transform,opacity',
            });
        }, pageRef);
        return () => ctx.revert();
    }, []);

    const fetchTasks = async () => {
        setLoading(true);
        try {
            const result = await listTasks(globalProjectId);
            setTasks(result || []);
        } catch (error) {
            console.error('Failed to fetch tasks:', error);
        } finally {
            setLoading(false);
        }
    };

    const fetchProjects = async () => {
        try {
            const result = await listProjects();
            setProjects((result || []).filter((p) => p.Status !== 'archived'));
        } catch (error) {
            console.error('Failed to fetch projects:', error);
        }
    };

    const fetchNodes = async () => {
        try {
            const result = await getNodes();
            setNodes(result || []);
        } catch (error) {
            console.error('Failed to fetch nodes:', error);
        }
    };

    useEffect(() => {
        fetchTasks();
        fetchProjects();
        fetchNodes();
        const timer = setInterval(fetchTasks, 10000);
        const ws = connectWebSocket(() => undefined, undefined, {
            onReconnect: () => {
                fetchTasks();
                fetchNodes();
            },
        });
        return () => {
            clearInterval(timer);
            ws.close();
        };
    }, []);

    useAutoContext({
        task_stats: {
            total: tasks.length,
            running: tasks.filter(t => t.Status === 'RUNNING').length,
            failed: tasks.filter(t => t.Status === 'FAILED' || t.Status === 'ERROR').length,
        },
        recent_tasks: tasks.slice(0, 8).map(t => ({
            id: t.ID,
            name: t.Name,
            status: t.Status,
            total_targets: t.TotalTargets,
            completed_targets: t.CompletedTargets,
            created_at: t.CreatedAt,
        })),
        viewing_task_detail: detailOpen ? taskDetail : null,
    });

    const handleCreate = async () => {
        if (!canManageTasks) return;
        try {
            const values = await form.validateFields();
            setCreating(true);

            const advancedConfig = parseAdvancedConfig(values.advanced_config_json);
            const configObj = {
                ...buildTaskConfig(values),
                ...advancedConfig,
            };

            const selectedProjectId = values.project_id;
            if (!selectedProjectId) {
                message.error('请选择所属项目');
                setCreating(false);
                return;
            }

            await createTask({
                project_id: selectedProjectId,
                name: values.name,
                targets: values.targets,
                config: configObj,
                priority: values.priority ?? 1,
                timeout_sec: values.timeout_sec ?? 3600,
                agent_selector: selectorFromPairs(values.agent_selector_pairs),
                agent_selector_rules: selectorRulesFromJSON(values.agent_selector_rules_json),
            });

            message.success('任务创建成功');
            setCreateOpen(false);
            form.resetFields();
            form.setFieldsValue(createInitialValues);
            fetchTasks();
        } catch (error: unknown) {
            if (typeof error === 'string') {
                message.error(error);
            } else if (error instanceof Error) {
                message.error(error.message);
            }
        } finally {
            setCreating(false);
        }
    };

    const currentSelector = useMemo(() => selectorFromPairs(selectorPairs), [selectorPairs]);
    const tagOptions = Array.from(new Set(nodes.flatMap((node) => Object.keys(parseNodeTags(node.Tags))))).sort();
    const tagValueOptions = (key?: string) => Array.from(new Set(
        nodes.map((node) => parseNodeTags(node.Tags)[key || '']).filter(Boolean)
    )).sort();
    const matchedNodes = currentSelector
        ? nodes.filter((node) => {
            if (node.Status !== 'Alive') return false;
            const tags = parseNodeTags(node.Tags);
            return Object.entries(currentSelector).every(([key, value]) => {
                const nodeValue = tags[key];
                return nodeValue === value || nodeValue === 'all' || nodeValue === 'any' || nodeValue === '*';
            });
        })
        : nodes.filter((node) => node.Status === 'Alive');
    const matchedCapacity = matchedNodes.reduce(
        (sum, node) => sum + Math.max((node.Capacity || 0) - (node.RunningTasks || 0), 0),
        0
    );
    const previewMatchedNodes = selectorPreview?.matched_nodes ?? matchedNodes.length;
    const previewCapacity = selectorPreview?.available_slots ?? matchedCapacity;
    const previewReasons = selectorPreview?.reasons || [];
    const previewGroups = selectorPreview?.groups || [];

    useEffect(() => {
        if (!createOpen) {
            setSelectorPreview(null);
            return;
        }
        const projectId = watchedProjectId || globalProjectId;
        if (!projectId || !watchedTargets?.trim()) {
            setSelectorPreview(null);
            return;
        }
        const timer = window.setTimeout(async () => {
            setSelectorPreviewLoading(true);
            try {
                const values = form.getFieldsValue(true);
                const result = await previewTaskSelector({
                    project_id: projectId,
                    targets: watchedTargets,
                    config: buildTaskConfig(values),
                    agent_selector: currentSelector,
                    agent_selector_rules: selectorRulesFromJSON(values.agent_selector_rules_json),
                });
                setSelectorPreview(result);
            } catch (error) {
                console.warn('Failed to preview task selector:', error);
                setSelectorPreview(null);
            } finally {
                setSelectorPreviewLoading(false);
            }
        }, 300);
        return () => window.clearTimeout(timer);
    }, [createOpen, watchedProjectId, watchedTargets, sourceMode, currentSelector, form, globalProjectId]);

    const handleDelete = async (taskId: string) => {
        if (!canManageTasks) return;
        try {
            await deleteTask(taskId);
            message.success('任务已删除');
            fetchTasks();
        } catch {
            message.error('删除失败');
        }
    };

    const handleCancel = async (taskId: string) => {
        if (!canManageTasks) return;
        try {
            await cancelTask(taskId);
            message.success('取消指令已下发');
            fetchTasks();
        } catch {
            message.error('取消失败');
        }
    };

    const handleShowDetail = async (taskId: string) => {
        setDetailOpen(true);
        setDetailLoading(true);
        try {
            const result = await getTaskDetail(taskId);
            setTaskDetail(result);
        } catch {
            message.error('获取任务详情失败');
        } finally {
            setDetailLoading(false);
        }
    };

    const getStatusTag = (status: string) => {
        const { color, text } = getTaskStatusMeta(status);
        return <Tag color={color}>{text}</Tag>;
    };

    const columns: ColumnsType<API.RootTask> = [
        {
            title: '任务名称',
            dataIndex: 'Name',
            key: 'name',
            ellipsis: true,
            render: (name: string, record) => (
                <Space direction="vertical" size={0}>
                    <Text strong style={{ fontSize: 13 }}>{name}</Text>
                    <Text style={{ fontSize: 11, color: '#94a3b8', fontFamily: 'monospace' }}>
                        {record.ID}
                    </Text>
                </Space>
            ),
        },
        {
            title: '状态',
            dataIndex: 'Status',
            key: 'status',
            width: 100,
            render: (status: string) => getStatusTag(status),
            filters: [
                { text: '等待中', value: 'Queued' },
                { text: '运行中', value: 'Running' },
                { text: '部分完成', value: 'PartialDone' },
                { text: '已完成', value: 'FINISHED' },
                { text: '失败', value: 'Failed' },
                { text: '超时', value: 'Timeout' },
                { text: '取消中', value: 'CancelPending' },
                { text: '已取消', value: 'Cancelled' },
            ],
            onFilter: (value, record) => normalizeTaskStatus(record.Status) === normalizeTaskStatus(String(value)),
        },
        {
            title: '进度',
            key: 'progress',
            width: 180,
            render: (_, record) => {
                // 优先展示目标维度进度，降级使用批次维度
                const hasTargetProgress = record.TotalTargets > 0;
                const total = hasTargetProgress ? record.TotalTargets : record.TotalChunks;
                const completed = hasTargetProgress ? record.CompletedTargets : record.CompletedChunks;
                if (total === 0) return <Text type="secondary">-</Text>;
                const pct = Math.round((completed / total) * 100);
                const normalized = normalizeTaskStatus(record.Status);
                const progressStatus = isTaskFinished(normalized)
                    ? 'success'
                    : isTaskFailedLike(normalized)
                        ? 'exception'
                        : normalized === 'CANCELLED'
                            ? 'normal'
                            : 'active';
                const strokeColor = isTaskFinished(normalized)
                    ? '#10b981'
                    : isTaskFailedLike(normalized)
                        ? '#ef4444'
                        : normalized === 'CANCELLED'
                            ? '#94a3b8'
                            : '#0ea5e9';
                return (
                    <Space direction="vertical" size={0} style={{ width: '100%' }}>
                        <Progress
                            percent={pct}
                            size="small"
                            status={progressStatus}
                            strokeColor={strokeColor}
                            style={{ marginBottom: 0 }}
                        />
                        <Text style={{ fontSize: 11, color: '#94a3b8' }}>
                            {hasTargetProgress
                                ? `${record.CompletedTargets}/${record.TotalTargets} 目标 · ${record.CompletedChunks}/${record.TotalChunks} 批次`
                                : `${record.CompletedChunks}/${record.TotalChunks} 分片`
                            }
                        </Text>
                    </Space>
                );
            },
        },
        {
            title: '优先级',
            dataIndex: 'Priority',
            key: 'priority',
            width: 100,
            render: (value: number) => {
                const map: Record<number, string> = {
                    0: 'P0 / 紧急',
                    1: 'P1 / 普通',
                    2: 'P2 / 低',
                };
                return <Text style={{ fontSize: 12 }}>{map[value] || String(value)}</Text>;
            },
        },
        {
            title: '创建时间',
            dataIndex: 'CreatedAt',
            key: 'created_at',
            width: 170,
            render: (value: string) => <Text style={{ fontSize: 12, color: '#64748b' }}>{value}</Text>,
        },
        {
            title: '操作',
            key: 'actions',
            width: 200,
            render: (_, record) => (
                <Space size={4}>
                    <Button type="link" size="small" icon={<InfoCircleOutlined />}
                        onClick={() => handleShowDetail(record.ID)}>
                        详情
                    </Button>
                    <Button type="link" size="small" icon={<EyeOutlined />}
                        onClick={() => navigate(`/tasks/${record.ID}/results`)}>
                        结果
                    </Button>
                    {canManageTasks && isTaskCancellable(record.Status) && (
                        <Popconfirm title="确认取消此任务？" onConfirm={() => handleCancel(record.ID)}>
                            <Button type="text" size="small" danger icon={<StopOutlined />}>
                                取消
                            </Button>
                        </Popconfirm>
                    )}
                    {canManageTasks && (
                        <Popconfirm title="确认删除此任务？" onConfirm={() => handleDelete(record.ID)}>
                            <Button type="text" size="small" danger icon={<DeleteOutlined />}>
                                删除
                            </Button>
                        </Popconfirm>
                    )}
                </Space>
            ),
        },
    ];

    return (
        <div ref={pageRef} style={{ position: 'relative', overflow: 'hidden' }}>
            <NetworkCanvas color="#10b981" count={30} speed={0.15} linkDist={100} />
            <div className="task-animate-in" style={{ position: 'relative', zIndex: 1, display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
                <Title level={4} style={{ margin: 0, color: '#1e293b', fontWeight: 600 }}>
                    <RocketOutlined style={{ marginRight: 8, color: '#10b981' }} />
                    任务管理
                </Title>
                <Space>
                    <Button icon={<ReloadOutlined />} onClick={fetchTasks} loading={loading}>
                        刷新
                    </Button>
                    {canManageTasks && (
                        <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>
                            创建任务
                        </Button>
                    )}
                </Space>
            </div>

            <ProCard className="glass-card task-animate-in" style={{ background: 'transparent', border: 'none', position: 'relative', zIndex: 1 }}>
                {loading && tasks.length === 0 ? (
                    <div style={{ display: 'flex', justifyContent: 'center', padding: '60px 0' }}>
                        <Spin size="large" />
                    </div>
                ) : tasks.length === 0 ? (
                    <Empty
                        image={Empty.PRESENTED_IMAGE_SIMPLE}
                        description="暂无扫描任务"
                        style={{ padding: '60px 0' }}
                    >
                        {canManageTasks && (
                            <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>
                                创建第一个任务
                            </Button>
                        )}
                    </Empty>
                ) : (
                    <Table
                        columns={columns}
                        dataSource={tasks}
                        rowKey="ID"
                        pagination={{ pageSize: 15, showSizeChanger: true, showTotal: (total) => `共 ${total} 个任务` }}
                        size="middle"
                    />
                )}
            </ProCard>

            {canManageTasks && (
                <Modal
                    title="创建扫描任务"
                    open={createOpen}
                    onCancel={() => setCreateOpen(false)}
                    onOk={handleCreate}
                    okText="创建"
                    confirmLoading={creating}
                    width={920}
                    destroyOnHidden
                >
                <Form 
                    form={form} 
                    layout="vertical" 
                    style={{ marginTop: 16 }} 
                    initialValues={{
                        ...createInitialValues,
                        project_id: globalProjectId || undefined
                    }}
                >
                    <Row gutter={16}>
                        <Col span={12}>
                            <Form.Item label="所属项目" name="project_id" rules={[{ required: true, message: '请选择所属项目' }]}>
                                <Select 
                                    placeholder="选择扫描任务归属的项目"
                                    options={projects.map(p => ({ label: p.Name, value: p.ID }))}
                                />
                            </Form.Item>
                        </Col>
                        <Col span={12}>
                            <Form.Item label="任务名称" name="name" rules={[{ required: true, message: '请输入任务名称' }]}>
                                <Input placeholder="输入任务名称" />
                            </Form.Item>
                        </Col>
                    </Row>
                    <Row gutter={16}>
                        <Col span={12}>
                            <Form.Item label="目标来源" name="source_mode">
                                <Select options={sourceModeOptions} />
                            </Form.Item>
                        </Col>
                    </Row>

                    <Alert
                        type="info"
                        showIcon
                        style={{ marginBottom: 16 }}
                        message="输入规则"
                        description={sourceModeHints[sourceMode]}
                    />

                    <Form.Item
                        label="扫描目标"
                        name="targets"
                        rules={[{ required: true, message: '请输入扫描目标' }]}
                    >
                        <TextArea
                            rows={6}
                            placeholder={
                                sourceMode === 'direct'
                                    ? '192.168.1.10\n192.168.1.10:8080\nhttps://example.com\nexample.com\n10.0.0.1/24'
                                    : sourceMode === 'quake'
                                        ? 'service:http\nport:443'
                                        : 'icp.name="xxx有限公司"\ntitle="nginx"'
                            }
                        />
                    </Form.Item>

                    <Divider orientation="left">任务控制</Divider>
                    <Row gutter={16}>
                        <Col span={8}>
                            <Form.Item label="任务优先级" name="priority" extra="P0 最高，P2 最低">
                                <Select options={[
                                    { value: 0, label: 'P0 / 紧急' },
                                    { value: 1, label: 'P1 / 普通' },
                                    { value: 2, label: 'P2 / 低' },
                                ]} />
                            </Form.Item>
                        </Col>
                        <Col span={8}>
                            <Form.Item label="任务超时(秒)" name="timeout_sec" extra="0 表示不启用超时回收">
                                <InputNumber min={0} step={60} style={{ width: '100%' }} />
                            </Form.Item>
                        </Col>
                    </Row>
                    <Divider orientation="left">调度选择</Divider>
                    <Alert
                        type={previewMatchedNodes > 0 ? 'success' : 'warning'}
                        showIcon
                        icon={selectorPreviewLoading ? <Spin size="small" /> : undefined}
                        style={{ marginBottom: 12 }}
                        message={`匹配在线节点 ${previewMatchedNodes} 个，可用槽位 ${previewCapacity} 个`}
                        description={previewReasons.length > 0 ? previewReasons.slice(0, 3).join('；') : undefined}
                    />
                    {previewGroups.length > 0 && (
                        <Space direction="vertical" size={6} style={{ width: '100%', marginBottom: 12 }}>
                            {previewGroups.map((group, index) => (
                                <div key={`${group.target_type}-${index}`} style={{
                                    border: '1px solid #e2e8f0',
                                    borderRadius: 6,
                                    padding: '8px 10px',
                                    background: '#f8fafc',
                                }}>
                                    <Space wrap size={6}>
                                        <Tag color={group.matched_nodes > 0 ? 'blue' : 'orange'}>
                                            {targetTypeLabels[group.target_type] || group.target_type}
                                        </Tag>
                                        <Text style={{ fontSize: 12 }}>{group.target_count} 目标 / {group.batch_count} 批次</Text>
                                        <Text style={{ fontSize: 12 }}>匹配 {group.matched_nodes} 节点</Text>
                                        <Text style={{ fontSize: 12 }}>空闲 {group.available_slots} 槽</Text>
                                        {typeof group.immediate_batches === 'number' && (
                                            <Text style={{ fontSize: 12 }}>立即 {group.immediate_batches} / 等待 {group.waiting_batches || 0} 批</Text>
                                        )}
                                        {Object.entries(group.selector || {}).map(([key, value]) => (
                                            <Tag key={key} style={{ fontSize: 11 }}>{key}={value}</Tag>
                                        ))}
                                    </Space>
                                    {group.reasons?.length > 0 && (
                                        <div style={{ marginTop: 4 }}>
                                            <Text type="secondary" style={{ fontSize: 12 }}>
                                                {group.reasons.join('；')}
                                            </Text>
                                        </div>
                                    )}
                                </div>
                            ))}
                        </Space>
                    )}
                    <Form.List name="agent_selector_pairs">
                        {(fields, { add, remove }) => (
                            <Space direction="vertical" style={{ width: '100%' }} size={8}>
                                {fields.map((field) => (
                                    <Row key={field.key} gutter={8} align="middle">
                                        <Col span={9}>
                                            <Form.Item {...field} name={[field.name, 'key']} noStyle>
                                                <Select
                                                    showSearch
                                                    placeholder="标签键"
                                                    options={tagOptions.map((key) => ({ label: key, value: key }))}
                                                />
                                            </Form.Item>
                                        </Col>
                                        <Col span={11}>
                                            <Form.Item shouldUpdate noStyle>
                                                {() => {
                                                    const key = form.getFieldValue(['agent_selector_pairs', field.name, 'key']);
                                                    return (
                                                        <Form.Item {...field} name={[field.name, 'value']} noStyle>
                                                            <Select
                                                                showSearch
                                                                placeholder="标签值"
                                                                options={tagValueOptions(key).map((value) => ({ label: value, value }))}
                                                            />
                                                        </Form.Item>
                                                    );
                                                }}
                                            </Form.Item>
                                        </Col>
                                        <Col span={4}>
                                            <Button danger onClick={() => remove(field.name)}>删除</Button>
                                        </Col>
                                    </Row>
                                ))}
                                <Button onClick={() => add()} block>
                                    添加标签条件
                                </Button>
                            </Space>
                        )}
                    </Form.List>
                    <Form.Item
                        label="高级选择器规则"
                        name="agent_selector_rules_json"
                        extra='可选 JSON，例如 {"match":{"region":["cn-hangzhou","cn-shanghai"]},"not_match":{"cloud":"test"}}'
                    >
                        <Input.TextArea rows={3} placeholder='{"match":{},"not_match":{}}' />
                    </Form.Item>

                    <Divider orientation="left">扫描配置</Divider>
                    <Collapse
                        bordered={false}
                        style={{ background: 'transparent' }}
                        items={[
                            {
                                key: 'portscan',
                                label: <Space><RadarChartOutlined style={{ color: '#0ea5e9' }} />端口扫描</Space>,
                                children: (
                                    <>
                                        <Row gutter={16}>
                                            <Col span={8}>
                                                <Form.Item label="端口范围" name="Ports" extra="留空使用默认 Top1000">
                                                    <Input placeholder="80,443,8080,8443" />
                                                </Form.Item>
                                            </Col>
                                            <Col span={8}>
                                                <Form.Item label="扫描方式" name="PortScanType">
                                                    <Select options={[
                                                        { value: 'tcp', label: 'TCP 连接扫描' },
                                                        { value: 'syn', label: 'SYN 半开扫描' },
                                                    ]} />
                                                </Form.Item>
                                            </Col>
                                            <Col span={8}>
                                                <Form.Item label={<>端口数阈值 <Tooltip title="单IP端口数超过此值将被丢弃"><InfoCircleOutlined /></Tooltip></>} name="PortsThreshold">
                                                    <InputNumber min={1} style={{ width: '100%' }} />
                                                </Form.Item>
                                            </Col>
                                        </Row>
                                        <Row gutter={16}>
                                            <Col span={8}>
                                                <Form.Item label="TCP 扫描线程" name="TCPPortScanThreads">
                                                    <InputNumber min={1} style={{ width: '100%' }} />
                                                </Form.Item>
                                            </Col>
                                            <Col span={8}>
                                                <Form.Item label="SYN 扫描线程" name="SYNPortScanThreads">
                                                    <InputNumber min={1} style={{ width: '100%' }} />
                                                </Form.Item>
                                            </Col>
                                            <Col span={8}>
                                                <Form.Item label="端口扫描超时(秒)" name="TCPPortScanTimeout">
                                                    <InputNumber min={1} style={{ width: '100%' }} />
                                                </Form.Item>
                                            </Col>
                                        </Row>
                                    </>
                                ),
                            },
                            {
                                key: 'alive',
                                label: <Space><WifiOutlined style={{ color: '#10b981' }} />主机发现</Space>,
                                children: (
                                    <Row gutter={16}>
                                        <Col span={8}>
                                            <Form.Item label={<>跳过主机发现 <Tooltip title="禁用ICMP和TCP探活，直接扫描"><InfoCircleOutlined /></Tooltip></>} name="SkipHostDiscovery" valuePropName="checked">
                                                <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                                            </Form.Item>
                                        </Col>
                                        <Col span={8}>
                                            <Form.Item label="禁用 ICMP 探测" name="NoICMPPing" valuePropName="checked">
                                                <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                                            </Form.Item>
                                        </Col>
                                        <Col span={8}>
                                            <Form.Item label="启用 TCP 探活" name="TCPPing" valuePropName="checked">
                                                <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                                            </Form.Item>
                                        </Col>
                                    </Row>
                                ),
                            },
                            {
                                key: 'nmap',
                                label: <Space><ApiOutlined style={{ color: '#8b5cf6' }} />协议识别</Space>,
                                children: (
                                    <Row gutter={16}>
                                        <Col span={12}>
                                            <Form.Item label="协议识别线程" name="GetBannerThreads">
                                                <InputNumber min={1} style={{ width: '100%' }} />
                                            </Form.Item>
                                        </Col>
                                        <Col span={12}>
                                            <Form.Item label="协议识别超时(秒)" name="GetBannerTimeout">
                                                <InputNumber min={1} style={{ width: '100%' }} />
                                            </Form.Item>
                                        </Col>
                                    </Row>
                                ),
                            },
                            {
                                key: 'subdomain',
                                label: <Space><GlobalOutlined style={{ color: '#f59e0b' }} />子域名探测</Space>,
                                children: (
                                    <>
                                        <Row gutter={16}>
                                            <Col span={8}>
                                                <Form.Item label="开启子域名枚举" name="Subdomain" valuePropName="checked">
                                                    <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                                                </Form.Item>
                                            </Col>
                                            <Col span={8}>
                                                <Form.Item label="关闭子域爆破" name="NoSubdomainBruteForce" valuePropName="checked">
                                                    <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                                                </Form.Item>
                                            </Col>
                                            <Col span={8}>
                                                <Form.Item label="关闭被动枚举" name="NoSubFinder" valuePropName="checked">
                                                    <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                                                </Form.Item>
                                            </Col>
                                        </Row>
                                        <Row gutter={16}>
                                            <Col span={8}>
                                                <Form.Item label="允许 CDN 资产" name="AllowCDNAssets" valuePropName="checked">
                                                    <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                                                </Form.Item>
                                            </Col>
                                            <Col span={8}>
                                                <Form.Item label="允许解析到内网" name="AllowLocalAreaDomain" valuePropName="checked">
                                                    <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                                                </Form.Item>
                                            </Col>
                                            <Col span={8}>
                                                <Form.Item label="关闭域名绑定探测" name="NoHostBind" valuePropName="checked">
                                                    <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                                                </Form.Item>
                                            </Col>
                                        </Row>
                                    </>
                                ),
                            },
                            {
                                key: 'web',
                                label: <Space><SearchOutlined style={{ color: '#06b6d4' }} />Web 探针</Space>,
                                children: (
                                    <Row gutter={16}>
                                        <Col span={8}>
                                            <Form.Item label="Web 探针线程" name="WebThreads">
                                                <InputNumber min={1} style={{ width: '100%' }} />
                                            </Form.Item>
                                        </Col>
                                        <Col span={8}>
                                            <Form.Item label="Web 超时(秒)" name="WebTimeout">
                                                <InputNumber min={1} style={{ width: '100%' }} />
                                            </Form.Item>
                                        </Col>
                                        <Col span={8}>
                                            <Form.Item label="关闭主动目录指纹" name="NoDirSearch" valuePropName="checked">
                                                <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                                            </Form.Item>
                                        </Col>
                                    </Row>
                                ),
                            },
                            {
                                key: 'vuln',
                                label: <Space><BugOutlined style={{ color: '#ef4444' }} />漏洞探测</Space>,
                                children: (
                                    <>
                                        <Row gutter={16}>
                                            <Col span={8}>
                                                <Form.Item label="关闭漏洞探测" name="NoPoc" valuePropName="checked">
                                                    <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                                                </Form.Item>
                                            </Col>
                                            <Col span={8}>
                                                <Form.Item label="启用 GoPoc" name="GolangPoc" valuePropName="checked">
                                                    <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                                                </Form.Item>
                                            </Col>
                                            <Col span={8}>
                                                <Form.Item label="禁用通用 POC" name="DisableGeneralPoc" valuePropName="checked">
                                                    <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                                                </Form.Item>
                                            </Col>
                                        </Row>
                                        <Row gutter={16}>
                                            <Col span={8}>
                                                <Form.Item label="GoPoc 线程" name="GoPocThreads">
                                                    <InputNumber min={1} style={{ width: '100%' }} />
                                                </Form.Item>
                                            </Col>
                                            <Col span={8}>
                                                <Form.Item label="排除 Tags" name="ExcludeTags">
                                                    <Input placeholder="etag1,etag2" />
                                                </Form.Item>
                                            </Col>
                                            <Col span={8}>
                                                <Form.Item label="漏洞等级过滤" name="Severities">
                                                    <Input placeholder="critical,high" />
                                                </Form.Item>
                                            </Col>
                                        </Row>
                                        <Row gutter={16}>
                                            <Col span={12}>
                                                <Form.Item label="限定 POC 名称" name="PocNameForSearch">
                                                    <Input placeholder="模糊匹配，如 nginx" />
                                                </Form.Item>
                                            </Col>
                                        </Row>
                                    </>
                                ),
                            },
                            {
                                key: 'passwd',
                                label: <Space><KeyOutlined style={{ color: '#f97316' }} />爆破密码</Space>,
                                children: (
                                    <Row gutter={16}>
                                        <Col span={12}>
                                            <Form.Item label="自定义弱口令" name="Password" extra="格式: admin : password">
                                                <Input placeholder="admin : password" />
                                            </Form.Item>
                                        </Col>
                                        <Col span={12}>
                                            <Form.Item label="弱口令文件" name="PasswordFile">
                                                <Input placeholder="config/password.txt" />
                                            </Form.Item>
                                        </Col>
                                    </Row>
                                ),
                            },

                            ...(sourceMode !== 'direct' ? [{
                                key: 'uncover',
                                label: <Space><CloudServerOutlined style={{ color: '#6366f1' }} />网络空间搜索引擎</Space>,
                                children: (
                                    <>
                                        <Row gutter={16}>
                                            <Col span={8}>
                                                <Form.Item label="输出 IP:Port 格式" name="OnlyIPPort" valuePropName="checked">
                                                    <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                                                </Form.Item>
                                            </Col>
                                            {sourceMode === 'hunter' && (
                                                <Col span={8}>
                                                    <Form.Item label={<>低感知模式 <Tooltip title="从Hunter直接取响应判断指纹，跳过端口扫描"><InfoCircleOutlined /></Tooltip></>} name="LowPerceptionMode" valuePropName="checked">
                                                        <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                                                    </Form.Item>
                                                </Col>
                                            )}
                                        </Row>
                                        <Row gutter={16}>
                                            {(sourceMode === 'hunter' || sourceMode === 'hunter_fofa') && (
                                                <>
                                                    <Col span={8}>
                                                        <Form.Item label="Hunter 每页数量" name="HunterPageSize">
                                                            <InputNumber min={1} max={100} style={{ width: '100%' }} />
                                                        </Form.Item>
                                                    </Col>
                                                    <Col span={8}>
                                                        <Form.Item label="Hunter 最大页数" name="HunterMaxPageCount">
                                                            <InputNumber min={1} style={{ width: '100%' }} />
                                                        </Form.Item>
                                                    </Col>
                                                </>
                                            )}
                                            {(sourceMode === 'fofa' || sourceMode === 'hunter_fofa') && (
                                                <Col span={8}>
                                                    <Form.Item label="Fofa 最大数量" name="FofaMaxCount">
                                                        <InputNumber min={1} max={10000} style={{ width: '100%' }} />
                                                    </Form.Item>
                                                </Col>
                                            )}
                                            {sourceMode === 'quake' && (
                                                <Col span={8}>
                                                    <Form.Item label="Quake 最大数量" name="QuakeSize">
                                                        <InputNumber min={1} style={{ width: '100%' }} />
                                                    </Form.Item>
                                                </Col>
                                            )}
                                        </Row>
                                    </>
                                ),
                            }] : []),
                            {
                                key: 'advanced',
                                label: <Space><ExperimentOutlined style={{ color: '#64748b' }} />高级配置</Space>,
                                children: (
                                    <Form.Item
                                        label="额外 Agent 配置 JSON"
                                        name="advanced_config_json"
                                        extra="JSON 会直接合并进任务配置；键名请使用 Agent 实际配置字段，例如 NucleiTemplate、APIConfigFilePath、NoInteractsh。"
                                    >
                                        <TextArea
                                            rows={6}
                                            placeholder={`{\n  "NucleiTemplate": "config/pocs",\n  "APIConfigFilePath": "config/api-config.yaml",\n  "NoInteractsh": true\n}`}
                                        />
                                    </Form.Item>
                                ),
                            },
                        ]}
                    />
                </Form>
                </Modal>
            )}

            {/* 任务详情 Drawer */}
            <Drawer
                title={
                    taskDetail ? (
                        <Space>
                            <RocketOutlined style={{ color: '#10b981' }} />
                            <span>{taskDetail.task.name}</span>
                            {getStatusTag(taskDetail.task.status)}
                        </Space>
                    ) : '任务详情'
                }
                open={detailOpen}
                onClose={() => { setDetailOpen(false); setTaskDetail(null); }}
                width={920}
                destroyOnClose
            >
                {detailLoading ? (
                    <div style={{ display: 'flex', justifyContent: 'center', padding: '80px 0' }}>
                        <Spin size="large" />
                    </div>
                ) : taskDetail ? (
                    <div>
                        {/* 概况统计卡片 */}
                        <Row gutter={16} style={{ marginBottom: 24 }}>
                            <Col span={6}>
                                <div style={{
                                    background: 'linear-gradient(135deg, #0ea5e9 0%, #06b6d4 100%)',
                                    borderRadius: 12, padding: '20px 16px', color: '#fff',
                                }}>
                                    <Statistic
                                        title={<span style={{ color: 'rgba(255,255,255,0.85)', fontSize: 12 }}>进度</span>}
                                        value={taskDetail.task.total_targets > 0
                                            ? Math.round((taskDetail.task.completed_targets / taskDetail.task.total_targets) * 100)
                                            : taskDetail.task.total_chunks > 0
                                                ? Math.round((taskDetail.task.completed_chunks / taskDetail.task.total_chunks) * 100)
                                                : 0}
                                        suffix="%"
                                        valueStyle={{ color: '#fff', fontSize: 28, fontWeight: 700 }}
                                    />
                                </div>
                            </Col>
                            <Col span={6}>
                                <div style={{
                                    background: 'linear-gradient(135deg, #3b82f6 0%, #6366f1 100%)',
                                    borderRadius: 12, padding: '20px 16px', color: '#fff',
                                }}>
                                    <Statistic
                                        title={<span style={{ color: 'rgba(255,255,255,0.85)', fontSize: 12 }}>资产</span>}
                                        value={taskDetail.result_stats.assets}
                                        valueStyle={{ color: '#fff', fontSize: 28, fontWeight: 700 }}
                                    />
                                </div>
                            </Col>
                            <Col span={6}>
                                <div style={{
                                    background: 'linear-gradient(135deg, #06b6d4 0%, #14b8a6 100%)',
                                    borderRadius: 12, padding: '20px 16px', color: '#fff',
                                }}>
                                    <Statistic
                                        title={<span style={{ color: 'rgba(255,255,255,0.85)', fontSize: 12 }}>指纹</span>}
                                        value={taskDetail.result_stats.fingerprints}
                                        valueStyle={{ color: '#fff', fontSize: 28, fontWeight: 700 }}
                                    />
                                </div>
                            </Col>
                            <Col span={6}>
                                <div style={{
                                    background: 'linear-gradient(135deg, #ef4444 0%, #f97316 100%)',
                                    borderRadius: 12, padding: '20px 16px', color: '#fff',
                                }}>
                                    <Statistic
                                        title={<span style={{ color: 'rgba(255,255,255,0.85)', fontSize: 12 }}>漏洞</span>}
                                        value={taskDetail.result_stats.vulns}
                                        valueStyle={{ color: '#fff', fontSize: 28, fontWeight: 700 }}
                                    />
                                </div>
                            </Col>
                        </Row>

                        {/* 漏洞严重度分布 */}
                        {taskDetail.result_stats.vulns > 0 && (
                            <div style={{ marginBottom: 20 }}>
                                <Space wrap>
                                    {Object.entries(taskDetail.result_stats.severity).map(([sev, count]) => {
                                        const colorMap: Record<string, string> = {
                                            Critical: '#ef4444', High: '#f97316', Medium: '#f59e0b',
                                            Low: '#3b82f6', Info: '#6b7280', Unknown: '#94a3b8',
                                        };
                                        return (
                                            <Tag key={sev} color={colorMap[sev] || '#94a3b8'} style={{ fontSize: 12 }}>
                                                {sev}: {count}
                                            </Tag>
                                        );
                                    })}
                                </Space>
                            </div>
                        )}

                        {/* 任务基本信息 */}
                        <Descriptions column={2} bordered size="small" style={{ marginBottom: 20 }}>
                            <Descriptions.Item label="任务 ID">
                                <Text copyable style={{ fontFamily: 'monospace', fontSize: 12 }}>{taskDetail.task.id}</Text>
                            </Descriptions.Item>
                            <Descriptions.Item label="优先级">
                                {({ 0: 'P0 / 紧急', 1: 'P1 / 普通', 2: 'P2 / 低' } as Record<number, string>)[taskDetail.task.priority] || String(taskDetail.task.priority)}
                            </Descriptions.Item>
                            <Descriptions.Item label="目标进度">
                                <Space>
                                    <Progress
                                        type="circle"
                                        size={40}
                                        percent={taskDetail.task.total_targets > 0
                                            ? Math.round((taskDetail.task.completed_targets / taskDetail.task.total_targets) * 100)
                                            : 0}
                                    />
                                    <Text style={{ fontSize: 12 }}>
                                        {taskDetail.task.completed_targets}/{taskDetail.task.total_targets} 目标
                                    </Text>
                                </Space>
                            </Descriptions.Item>
                            <Descriptions.Item label="批次进度">
                                <Space>
                                    <Progress
                                        type="circle"
                                        size={40}
                                        percent={taskDetail.task.total_chunks > 0
                                            ? Math.round((taskDetail.task.completed_chunks / taskDetail.task.total_chunks) * 100)
                                            : 0}
                                    />
                                    <Text style={{ fontSize: 12 }}>
                                        {taskDetail.task.completed_chunks}/{taskDetail.task.total_chunks} 批次
                                    </Text>
                                </Space>
                            </Descriptions.Item>
                            <Descriptions.Item label="超时时间">
                                {taskDetail.task.timeout_sec > 0 ? `${taskDetail.task.timeout_sec} 秒` : '未设置'}
                            </Descriptions.Item>
                            <Descriptions.Item label="规则版本">
                                <Tag color="blue">{taskDetail.task.rule_version || '-'}</Tag>
                            </Descriptions.Item>
                            <Descriptions.Item label="创建时间" span={2}>
                                {taskDetail.task.created_at}
                            </Descriptions.Item>
                        </Descriptions>

                        {/* 原始目标 */}
                        {taskDetail.task.original_targets && (
                            <>
                                <Divider orientation="left" style={{ fontSize: 13 }}>
                                    <AimOutlined style={{ marginRight: 4 }} />原始目标
                                </Divider>
                                <pre style={{
                                    background: '#f1f5f9', border: '1px solid #e2e8f0',
                                    borderRadius: 8, padding: 12, fontSize: 12,
                                    maxHeight: 160, overflow: 'auto', whiteSpace: 'pre-wrap',
                                    fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
                                    color: '#334155',
                                }}>
                                    {taskDetail.task.original_targets}
                                </pre>
                            </>
                        )}

                        {/* 扫描配置 */}
                        {taskDetail.task.config && typeof taskDetail.task.config === 'object' && (
                            <>
                                <Divider orientation="left" style={{ fontSize: 13 }}>
                                    <AuditOutlined style={{ marginRight: 4 }} />扫描配置
                                </Divider>
                                <pre style={{
                                    background: '#0f172a', color: '#e2e8f0',
                                    borderRadius: 8, padding: 12, fontSize: 11,
                                    maxHeight: 200, overflow: 'auto', whiteSpace: 'pre-wrap',
                                    fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
                                }}>
                                    {JSON.stringify(taskDetail.task.config, null, 2)}
                                </pre>
                            </>
                        )}

                        {/* 子任务状态分布 */}
                        {Object.keys(taskDetail.status_distribution).length > 0 && (
                            <>
                                <Divider orientation="left" style={{ fontSize: 13 }}>
                                    批次状态分布
                                </Divider>
                                <Space wrap style={{ marginBottom: 12 }}>
                                    {Object.entries(taskDetail.status_distribution).map(([status, count]) => {
                                        const { color, text } = getTaskStatusMeta(status);
                                        return (
                                            <Badge key={status} count={count} color={color === 'processing' ? '#1677ff' : undefined} overflowCount={9999}>
                                                <Tag color={color} style={{ marginRight: 0 }}>{text}</Tag>
                                            </Badge>
                                        );
                                    })}
                                </Space>
                            </>
                        )}

                        {/* 任务原因统计 */}
                        {taskDetail.reason_stats?.length > 0 && (
                            <>
                                <Divider orientation="left" style={{ fontSize: 13 }}>
                                    调度与终态原因
                                </Divider>
                                <Space direction="vertical" size={6} style={{ width: '100%', marginBottom: 12 }}>
                                    {taskDetail.reason_stats.map((item, index) => {
                                        const { color, text } = getTaskStatusMeta(item.status);
                                        return (
                                            <Alert
                                                key={`${item.status}-${index}`}
                                                type={item.status.toLowerCase().includes('fail') || item.status.toLowerCase().includes('timeout') ? 'warning' : 'info'}
                                                showIcon
                                                message={
                                                    <Space wrap>
                                                        <Tag color={color}>{text}</Tag>
                                                        <Text>{item.reason}</Text>
                                                        <Text type="secondary">{item.count} 批次 / {item.target_count} 目标</Text>
                                                    </Space>
                                                }
                                            />
                                        );
                                    })}
                                </Space>
                            </>
                        )}

                        {/* 子任务列表 */}
                        <Divider orientation="left" style={{ fontSize: 13 }}>
                            子任务列表 ({taskDetail.sub_tasks.length})
                        </Divider>
                        <Table
                            dataSource={taskDetail.sub_tasks}
                            rowKey="id"
                            size="small"
                            pagination={{ pageSize: 10, showTotal: (t) => `共 ${t} 个批次` }}
                            columns={[
                                {
                                    title: '批次 ID', dataIndex: 'id', key: 'id', ellipsis: true, width: 220,
                                    render: (v: string) => <Text style={{ fontFamily: 'monospace', fontSize: 11 }}>{v}</Text>,
                                },
                                {
                                    title: '状态', dataIndex: 'status', key: 'status', width: 90,
                                    render: (v: string) => getStatusTag(v),
                                },
                                {
                                    title: 'Agent', dataIndex: 'agent_id', key: 'agent_id', ellipsis: true, width: 140,
                                    render: (v: string) => v ? <Tag color="blue" style={{ fontSize: 11 }}>{v}</Tag> : <Text type="secondary">-</Text>,
                                },
                                {
                                    title: '目标数', dataIndex: 'target_count', key: 'target_count', width: 80,
                                    sorter: (a, b) => a.target_count - b.target_count,
                                },
                                {
                                    title: '重试', key: 'retry', width: 70,
                                    render: (_, r) => <Text style={{ fontSize: 12 }}>{r.retry_count}/{r.max_retry}</Text>,
                                },
                                {
                                    title: '更新时间', dataIndex: 'updated_at', key: 'updated_at', width: 170,
                                    render: (v: string) => <Text style={{ fontSize: 11, color: '#64748b' }}>{v}</Text>,
                                },
                            ]}
                        />
                    </div>
                ) : null}
            </Drawer>
        </div>
    );
};

export default TaskManagement;
