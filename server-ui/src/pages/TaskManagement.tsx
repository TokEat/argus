import React, { useEffect, useMemo, useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
    Alert,
    App,
    Badge,
    Button,
	Checkbox,
    Col,
    Collapse,
    Descriptions,
    Divider,
    Dropdown,
    Empty,
    Form,
    Input,
    InputNumber,
    Modal,
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
    ApiOutlined,
    BugOutlined,
    InboxOutlined,
    ExperimentOutlined,
    EyeOutlined,
    GlobalOutlined,
    InfoCircleOutlined,
    KeyOutlined,
    MoreOutlined,
    PauseCircleOutlined,
    PlayCircleOutlined,
    PlusOutlined,
    RadarChartOutlined,
    ReloadOutlined,
    RocketOutlined,
    SearchOutlined,
    StopOutlined,
    UnorderedListOutlined,
    WifiOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import type { MenuProps } from 'antd';
import { appendTargets, archiveTaskBatch, connectWebSocket, createTask, deleteTask, executeTaskRiskValidation, getTaskConfigRevisions, getTaskDetail, getNodes, listPocRulesPage, listProjects, listTasks, pauseTask, pauseTaskBatch, previewTaskRiskValidation, previewTaskSelector, resumeTask, resumeTaskBatch, retryTask, retryTaskBatch, stopTask, stopTaskBatch, updateTaskConfig, validateTargets } from '../services/api';
import { isTaskCancellable, isTaskFailedLike, isTaskFinished, isTaskPausable, isTaskResumable, isTaskRetryable, normalizeTaskStatus } from '../utils/taskStatus';
import { canAccessRole } from '../utils/auth';
import { useAutoContext } from '../contexts/GlobalAIContext';
import NetworkCanvas from '../components/NetworkCanvas';
import { scanPolicyInitialValues, type ScanPolicyFormValues } from '../components/tasks/ScanPolicyComposer';
import ScanTaskCreateModal from '../components/tasks/ScanTaskCreateModal';
import TaskBatchDrawer from './taskManagement/TaskBatchDrawer';
import TaskDetailDrawer from './taskManagement/TaskDetailDrawer';
import {
    batchActionLabels,
    isIdempotencyConflict,
    isNetworkOrTimeout,
    newIdempotencyKey,
    renderTaskStatusTag,
    targetTypeLabels,
    type AppendIntent,
    type BatchAction,
    type BatchRetryIntent,
    type CreateIntent,
    type RetryIntent,
} from './taskManagement/shared';

const { Title, Text } = Typography;
const { TextArea } = Input;

const directTargetHint = '每行一个显式目标，支持 IP、IP:Port、CIDR、IP 段、域名、域名:Port、URL。';
const legacyProviderConfigKeys = new Set([
    'hunter', 'hunterpagesize', 'huntermaxpagecount',
    'fofa', 'fofamaxcount',
    'quake', 'quakesize',
    'lowperceptionmode', 'onlyipport', 'apiconfigfilepath',
]);

type RiskValidationIntent = {
    key: string;
    taskId: string;
    previewSession: number;
    request: API.ExecuteRiskValidationRequest;
    fingerprint: string;
};

const riskLevelLabels: Record<API.RiskValidationPreviewCandidate['risk_level'], string> = {
    unknown: '风险未分类', info: '信息级', low: '低风险', medium: '中风险', high: '高风险',
};

const riskLevelColors: Record<API.RiskValidationPreviewCandidate['risk_level'], string> = {
    unknown: 'orange', info: 'default', low: 'green', medium: 'gold', high: 'red',
};

const severityColors: Record<string, string> = {
    critical: 'magenta', high: 'red', medium: 'orange', low: 'blue', info: 'default', unknown: 'default',
};

const excludedRiskReasonLabels: Record<string, string> = {
    missing_poc: 'POC 不存在',
    poc_not_approved: 'POC 未审核启用',
    invalid_poc_governance: 'POC 执行治理元数据无效',
    unsupported_match_type: 'Workflow 匹配类型不受支持',
};

const legacyScanUIEnabled = false;

const createInitialValues = {
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
    Subdomain: true,
    NoSubdomainBruteForce: true,
    NoSubFinder: false,
    NoHostBind: true,
    NoDomainProbe: false,
    NoResolvedIPScan: false,
    WebThreads: 200,
    WebTimeout: 10,
    NoDirSearch: true,
    NoPoc: true,
    GolangPoc: false,
    DisableGeneralPoc: true,
    GoPocThreads: 50,
};

function parseProjectTargetList(raw?: string): string[] {
    if (!raw?.trim()) return [];
    try {
        const parsed = JSON.parse(raw);
        if (!Array.isArray(parsed)) return [];
        return parsed.map((item) => typeof item === 'string' ? item.trim() : '').filter(Boolean);
    } catch {
        return [];
    }
}

function projectDefaultTargets(project?: API.Project): string[] {
    return Array.from(new Set([
        ...parseProjectTargetList(project?.SeedTargets),
        ...parseProjectTargetList(project?.Scope),
    ]));
}

const invertedSwitchBinding = {
    getValueFromEvent: (checked: boolean) => !checked,
    getValueProps: (value?: boolean) => ({ checked: value !== true }),
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
    const parsed = JSON.parse(trimmed);
    if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
        throw new Error('agent_selector_rules 必须是 JSON 对象');
    }
    return parsed as API.AgentSelectorRules;
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
    return Object.fromEntries(
        Object.entries(parsed as Record<string, unknown>)
            .filter(([key]) => !legacyProviderConfigKeys.has(key.toLowerCase()))
    );
}

function buildTaskConfig(formValues: Record<string, unknown>) {
    const values: Record<string, unknown> = { ...createInitialValues, ...formValues };
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
        NoDomainProbe: values.NoDomainProbe,
        NoResolvedIPScan: values.NoResolvedIPScan,
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

    return compactObject(config);
}

const TaskManagement: React.FC = () => {
    const [loading, setLoading] = useState(true);
    const [tasks, setTasks] = useState<API.RootTask[]>([]);
    const [createOpen, setCreateOpen] = useState(false);
    const [creating, setCreating] = useState(false);
    const [form] = Form.useForm();
    const { message, modal } = App.useApp();
    const navigate = useNavigate();
    const watchedProjectId = Form.useWatch('project_id', form) as string | undefined;
    const watchedTargets = Form.useWatch('targets', form) as string | undefined;
    const selectorPairs = Form.useWatch('agent_selector_pairs', form) as { key?: string; value?: string }[] | undefined;
    const globalProjectId = localStorage.getItem('active_project_id') || '';
    const [projects, setProjects] = useState<API.Project[]>([]);
    const [nodes, setNodes] = useState<API.AgentNode[]>([]);
    const [taskPagination, setTaskPagination] = useState({ current: 1, pageSize: 20, total: 0 });
    const taskPaginationRef = useRef({ current: 1, pageSize: 20, total: 0 });
    const [showArchived, setShowArchived] = useState(false);
    const showArchivedRef = useRef(false);
    const [detailOpen, setDetailOpen] = useState(false);
    const [batchOpen, setBatchOpen] = useState(false);
    const [detailLoading, setDetailLoading] = useState(false);
    const [taskDetail, setTaskDetail] = useState<API.TaskDetailResponse | null>(null);
	const [riskPreviewOpen, setRiskPreviewOpen] = useState(false);
	const [riskPreviewLoading, setRiskPreviewLoading] = useState(false);
	const [riskPreview, setRiskPreview] = useState<API.RiskValidationPreviewResponse | null>(null);
	const [riskSpecifiedPocs, setRiskSpecifiedPocs] = useState<string[]>([]);
	const [riskPocOptions, setRiskPocOptions] = useState<{ label: React.ReactNode; value: string }[]>([]);
	const [riskPocOptionsLoading, setRiskPocOptionsLoading] = useState(false);
	const [riskAuthorizedConfirmed, setRiskAuthorizedConfirmed] = useState(false);
	const [riskSecondConfirmed, setRiskSecondConfirmed] = useState(false);
	const [riskExecuting, setRiskExecuting] = useState(false);
    const [configRevisions, setConfigRevisions] = useState<API.TaskConfigRevision[]>([]);
    const [configEditOpen, setConfigEditOpen] = useState(false);
    const [configSaving, setConfigSaving] = useState(false);
    const [configForm] = Form.useForm();
    const [appendOpen, setAppendOpen] = useState(false);
    const [appendValue, setAppendValue] = useState('');
    const [appendSaving, setAppendSaving] = useState(false);
    const [selectorPreview, setSelectorPreview] = useState<API.TaskSelectorPreview | null>(null);
    const [selectorPreviewLoading, setSelectorPreviewLoading] = useState(false);
    const [scanPlan, setScanPlan] = useState<API.ScanPlanPreview | null>(null);
    const [targetValidationOpen, setTargetValidationOpen] = useState(false);
    const [validTargets, setValidTargets] = useState<string[]>([]);
    const [invalidTargets, setInvalidTargets] = useState<API.InvalidTarget[]>([]);
    const [invalidTargetEdits, setInvalidTargetEdits] = useState<string[]>([]);
    const pendingCreateRef = useRef<API.CreateTaskRequest | null>(null);
    const createIntentRef = useRef<CreateIntent | null>(null);
    const appendIntentRef = useRef<AppendIntent | null>(null);
    const appendInFlightRef = useRef(false);
    const retryIntentRef = useRef<RetryIntent | null>(null);
    const retryInFlightRef = useRef(new Map<string, RetryIntent>());
    const batchRetryIntentsRef = useRef(new Map<string, BatchRetryIntent>());
    const batchRetryInFlightRef = useRef(new Map<string, BatchRetryIntent>());
    const detailTaskIdRef = useRef<string | null>(null);
    const detailSessionRef = useRef(0);
    const riskPreviewSessionRef = useRef(0);
    const riskIntentRef = useRef<RiskValidationIntent | null>(null);
    const riskInFlightRef = useRef<RiskValidationIntent | null>(null);
    const canManageTasks = canAccessRole('operator');
	const riskTaskStatus = taskDetail ? normalizeTaskStatus(taskDetail.task.status) : '';
	const canExecuteRiskValidation = Boolean(
		canManageTasks && taskDetail && !taskDetail.task.archived_at &&
		(isTaskFinished(riskTaskStatus) || isTaskFailedLike(riskTaskStatus) || riskTaskStatus === 'STOPPED'),
	);
    const fetchTasks = async (
        page = taskPaginationRef.current.current,
        pageSize = taskPaginationRef.current.pageSize,
    ) => {
        setLoading(true);
        try {
            const result = await listTasks({
                projectId: globalProjectId || undefined,
                page,
                pageSize,
                archived: showArchivedRef.current ? 'only' : undefined,
            });
            setTasks(result.items || []);
            const nextPagination = {
                current: result.page || page,
                pageSize: result.page_size || pageSize,
                total: result.total || 0,
            };
            taskPaginationRef.current = nextPagination;
            setTaskPagination(nextPagination);
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
            total: taskPagination.total,
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
        viewing_task_detail: (detailOpen || batchOpen) ? taskDetail : null,
    });

    const clearCreateIntent = () => {
        createIntentRef.current = null;
    };

    const cancelCreate = () => {
        clearCreateIntent();
        pendingCreateRef.current = null;
        setTargetValidationOpen(false);
        setValidTargets([]);
        setInvalidTargets([]);
        setInvalidTargetEdits([]);
        setCreateOpen(false);
        setScanPlan(null);
    };

    const invalidateCreateDraft = () => {
        clearCreateIntent();
        pendingCreateRef.current = null;
        setTargetValidationOpen(false);
        setValidTargets([]);
        setInvalidTargets([]);
        setInvalidTargetEdits([]);
    };

	const returnToCreateDraft = () => {
		invalidateCreateDraft();
	};

    const finishCreate = async (request: API.CreateTaskRequest) => {
        const fingerprint = JSON.stringify(request);
        let intent = createIntentRef.current;
        if (!intent || intent.fingerprint !== fingerprint) {
            intent = { key: newIdempotencyKey(), fingerprint, request };
            createIntentRef.current = intent;
        }
        const result = await createTask(intent.request, intent.key);
        const skippedCount = result.skipped_targets?.length || 0;
        message.success(result.replayed
            ? '任务创建已确认，已复用此前结果'
            : skippedCount > 0 ? `任务创建成功，已跳过 ${skippedCount} 个无效目标` : '任务创建成功');
        clearCreateIntent();
        setCreateOpen(false);
        setTargetValidationOpen(false);
        pendingCreateRef.current = null;
        form.resetFields();
        form.setFieldsValue(scanPolicyInitialValues);
        fetchTasks(1, taskPaginationRef.current.pageSize);
    };

    const handleCreate = async () => {
        if (!canManageTasks) return;
        try {
            const values = await form.validateFields() as ScanPolicyFormValues;
            setCreating(true);
            const selectedProjectId = values.project_id;
            if (!selectedProjectId) {
                message.error('请选择所属项目');
                return;
            }
            if (!scanPlan) {
                message.error('请先完成有效的实时执行计划');
                return;
            }
            const request: API.CreateTaskRequest = {
                project_id: selectedProjectId,
                name: typeof values.name === 'string' && values.name.trim() ? values.name.trim() : undefined,
                targets: values.targets || '',
                priority: values.priority ?? 1,
                timeout_sec: values.timeout_sec ?? 3600,
                policy: scanPlan.policy,
                plan_hash: scanPlan.plan_hash,
            };
            await finishCreate(request);
        } catch (error: unknown) {
            if (isIdempotencyConflict(error)) {
                invalidateCreateDraft();
                message.error('创建请求冲突，表单内容已变化，请重新创建');
            } else if (isNetworkOrTimeout(error)) {
                message.error('创建请求未确认完成，网络恢复后可直接重试');
            } else if (typeof error === 'string') {
                message.error(error);
            } else if (error instanceof Error) {
                message.error(error.message);
            }
        } finally {
            setCreating(false);
        }
    };

    const handleSkipInvalidTargets = async () => {
        const request = pendingCreateRef.current;
        if (!request) return;
        setCreating(true);
        try {
            await finishCreate({ ...request, skip_unsupported: true });
        } catch (error: unknown) {
            if (isIdempotencyConflict(error)) {
                invalidateCreateDraft();
                message.error('创建请求冲突，表单内容已变化，请重新创建');
            } else if (isNetworkOrTimeout(error)) {
                message.error('创建请求未确认完成，网络恢复后可直接重试');
            } else if (typeof error === 'string') message.error(error);
            else if (error instanceof Error) message.error(error.message);
        } finally {
            setCreating(false);
        }
    };

    const handleRevalidateTargets = async () => {
        const request = pendingCreateRef.current;
        if (!request) return;
        const targets = [...validTargets, ...invalidTargetEdits.map((target) => target.trim()).filter(Boolean)].join('\n');
        // Corrected unsupported targets are a different final write payload.
        clearCreateIntent();
        setCreating(true);
        try {
            const validation = await validateTargets({ targets, config: request.config });
            if ((validation.invalid || []).length > 0) {
                setValidTargets(validation.valid || []);
                setInvalidTargets(validation.invalid || []);
                setInvalidTargetEdits((validation.invalid || []).map((item) => item.target));
                message.warning(`仍有 ${validation.invalid.length} 个目标无法识别`);
                return;
            }
            await finishCreate({ ...request, targets, skip_unsupported: false });
        } catch (error: unknown) {
            if (isIdempotencyConflict(error)) {
                invalidateCreateDraft();
                message.error('创建请求冲突，表单内容已变化，请重新创建');
            } else if (isNetworkOrTimeout(error)) {
                message.error('创建请求未确认完成，网络恢复后可直接重试');
            } else if (typeof error === 'string') message.error(error);
            else if (error instanceof Error) message.error(error.message);
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
    const selectedCreateProject = projects.find((project) => project.ID === (watchedProjectId || globalProjectId));
    const selectedProjectTargets = projectDefaultTargets(selectedCreateProject);

    const handleCreateProjectChange = (projectId: string) => {
        invalidateCreateDraft();
        const currentTargets = form.getFieldValue('targets');
        if (typeof currentTargets === 'string' && currentTargets.trim()) return;
        const targetText = projectDefaultTargets(projects.find((project) => project.ID === projectId)).join('\n');
        if (targetText) form.setFieldValue('targets', targetText);
    };

    // 被动收集进行中时轮询刷新任务详情，让进度条实时推进；收集结束或抽屉关闭即停。
    useEffect(() => {
        if ((!detailOpen && !batchOpen) || !taskDetail?.passive_collection?.active) return;
        const taskId = taskDetail.task.id;
        const timer = setInterval(async () => {
            if (detailTaskIdRef.current !== taskId) return;
            try {
                const refreshed = await getTaskDetail(taskId);
                if (detailTaskIdRef.current === taskId) setTaskDetail(refreshed);
            } catch {
                // 轮询失败忽略，下个周期重试
            }
        }, 3000);
        return () => clearInterval(timer);
    }, [detailOpen, batchOpen, taskDetail?.task?.id, taskDetail?.passive_collection?.active]);

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
    }, [createOpen, watchedProjectId, watchedTargets, currentSelector, form, globalProjectId]);

    const handleArchive = async (taskId: string) => {
        if (!canManageTasks) return;
        try {
            await deleteTask(taskId);
            message.success('任务已归档，扫描结果与审计记录已保留');
            fetchTasks();
        } catch {
            message.error('归档失败，请先停止仍在运行的任务');
        }
    };

    const openCreateTask = () => {
        const projectId = globalProjectId || projects[0]?.ID;
        const selectedProject = projects.find((project) => project.ID === projectId);
        const projectTargets = projectDefaultTargets(selectedProject);
        form.resetFields();
        form.setFieldsValue({
            ...scanPolicyInitialValues,
            project_id: projectId || undefined,
            targets: projectTargets.length > 0 ? projectTargets.join('\n') : undefined,
        });
        setScanPlan(null);
        setCreateOpen(true);
    };

    const handleArchivedViewChange = (checked: boolean) => {
        showArchivedRef.current = checked;
        setShowArchived(checked);
        const nextPagination = { ...taskPaginationRef.current, current: 1, total: 0 };
        taskPaginationRef.current = nextPagination;
        setTaskPagination(nextPagination);
        fetchTasks(1, nextPagination.pageSize);
    };

    const handleCancel = async (taskId: string) => {
        if (!canManageTasks) return;
        try {
            await stopTask(taskId);
            message.success('取消指令已下发');
            fetchTasks();
        } catch {
            message.error('取消失败');
        }
    };

    const handlePause = async (taskId: string) => {
        if (!canManageTasks) return;
        try {
            await pauseTask(taskId);
            message.success('任务已暂停');
            fetchTasks();
        } catch {
            message.error('暂停失败');
        }
    };

    const handleResume = async (taskId: string) => {
        if (!canManageTasks) return;
        try {
            await resumeTask(taskId);
            message.success('任务已恢复');
            fetchTasks();
        } catch {
            message.error('恢复失败');
        }
    };

    const handleRetry = async (taskId: string) => {
        if (!canManageTasks || retryInFlightRef.current.has(taskId)) return;
        let intent = retryIntentRef.current;
        if (!intent || intent.taskId !== taskId) {
            intent = { key: newIdempotencyKey(), taskId };
            retryIntentRef.current = intent;
        }
        retryInFlightRef.current.set(taskId, intent);
        try {
            const result = await retryTask(intent.taskId, intent.key);
            const pendingText = result.dispatch_pending > 0
                ? `，${result.dispatch_pending} 个批次等待队列恢复`
                : '';
            message.success(result.replayed
                ? `重试请求已确认，已复用此前结果${pendingText}`
                : `已为 ${result.retried_batches} 个失败批次追加重试${pendingText}`);
            if (retryIntentRef.current === intent) retryIntentRef.current = null;
            fetchTasks();
            if (detailTaskIdRef.current === taskId) {
                const detail = await getTaskDetail(taskId);
                if (detailTaskIdRef.current === taskId) setTaskDetail(detail);
            }
        } catch (error: unknown) {
            if (isIdempotencyConflict(error)) {
                if (retryIntentRef.current === intent) retryIntentRef.current = null;
                message.error('重试请求冲突，请重新确认后提交');
            } else if (isNetworkOrTimeout(error)) {
                message.error('重试请求未确认完成，网络恢复后可直接重试');
            } else if (error instanceof Error) {
                if (retryIntentRef.current === intent) retryIntentRef.current = null;
                message.error(error.message);
            } else {
                if (retryIntentRef.current === intent) retryIntentRef.current = null;
                message.error('重试失败');
            }
        } finally {
            if (retryInFlightRef.current.get(taskId) === intent) retryInFlightRef.current.delete(taskId);
        }
    };

    const taskActionItems = (record: API.RootTask): MenuProps['items'] => {
        const items: MenuProps['items'] = [];
        if (isTaskPausable(record.Status)) {
            items.push({ key: 'pause', icon: <PauseCircleOutlined />, label: '暂停' });
        }
        if (isTaskResumable(record.Status)) {
            items.push({ key: 'resume', icon: <PlayCircleOutlined />, label: '恢复' });
        }
        if (isTaskCancellable(record.Status)) {
            items.push({ key: 'cancel', icon: <StopOutlined />, label: '立即停止', danger: true });
        }
        if (isTaskRetryable(record.Status)) {
            items.push({ key: 'retry', icon: <ReloadOutlined />, label: '重试失败批次' });
        }
        const normalized = normalizeTaskStatus(record.Status);
        const canArchive = isTaskFinished(normalized) || isTaskFailedLike(normalized) || normalized === 'STOPPED';
        if (canArchive) {
            if (items.length > 0) {
                items.push({ type: 'divider' });
            }
            items.push({ key: 'archive', icon: <InboxOutlined />, label: '归档' });
        }
        return items;
    };

    const handleTaskAction = (record: API.RootTask, action: string) => {
        const definitions: Record<string, {
            title: string;
            content: string;
            danger?: boolean;
            run: () => Promise<void>;
        }> = {
            pause: {
                title: '确认暂停任务？',
                content: `任务“${record.Name}”将停止派发新的扫描批次。`,
                run: () => handlePause(record.ID),
            },
            resume: {
                title: '确认恢复任务？',
                content: `任务“${record.Name}”的待执行批次将重新进入队列。`,
                run: () => handleResume(record.ID),
            },
            cancel: {
                title: '确认立即停止任务？',
                content: `任务“${record.Name}”将停止所有未领取批次，并向正在执行的 Agent 下发取消。`,
                danger: true,
                run: () => handleCancel(record.ID),
            },
            retry: {
                title: '确认重试失败批次？',
                content: `任务“${record.Name}”中失败、超时或已停止的批次将使用当前配置与最新规则追加新尝试；成功批次不会重复扫描。`,
                run: () => handleRetry(record.ID),
            },
            archive: {
                title: '确认归档任务？',
                content: `任务“${record.Name}”将从默认列表隐藏，扫描结果与操作审计会继续保留。`,
                run: () => handleArchive(record.ID),
            },
        };
        const definition = definitions[action];
        if (!definition) return;
        modal.confirm({
            title: definition.title,
            content: definition.content,
            okText: '确认',
            cancelText: '取消',
            okButtonProps: { danger: definition.danger },
            onOk: definition.run,
            onCancel: () => {
                if (action === 'retry') {
                    retryIntentRef.current = null;
                }
            },
        });
    };

    const loadTaskDetail = async (taskId: string, detailSession: number) => {
        detailTaskIdRef.current = taskId;
        setDetailLoading(true);
        try {
            const result = await getTaskDetail(taskId);
            const isCurrentDetail = () => detailTaskIdRef.current === taskId && detailSessionRef.current === detailSession;
            if (!isCurrentDetail()) return;
            setTaskDetail(result);
            try {
                const revisions = await getTaskConfigRevisions(taskId);
                if (isCurrentDetail()) setConfigRevisions(revisions.items || []);
            } catch {
                if (isCurrentDetail()) setConfigRevisions([]);
            }
        } catch {
            if (detailTaskIdRef.current === taskId && detailSessionRef.current === detailSession) message.error('获取任务详情失败');
        } finally {
            if (detailTaskIdRef.current === taskId && detailSessionRef.current === detailSession) setDetailLoading(false);
        }
    };

    const handleShowDetail = async (taskId: string) => {
        appendIntentRef.current = null;
        retryIntentRef.current = null;
        riskPreviewSessionRef.current += 1;
        riskIntentRef.current = null;
        riskInFlightRef.current = null;
        setRiskExecuting(false);
        const detailSession = ++detailSessionRef.current;
        setDetailOpen(true);
        await loadTaskDetail(taskId, detailSession);
    };

    const handleShowBatches = async (taskId: string) => {
        const detailSession = ++detailSessionRef.current;
        setBatchOpen(true);
        await loadTaskDetail(taskId, detailSession);
    };

    const closeDetailDrawer = () => {
        if (riskInFlightRef.current) return;
        appendIntentRef.current = null;
        retryIntentRef.current = null;
        riskPreviewSessionRef.current += 1;
        riskIntentRef.current = null;
        riskInFlightRef.current = null;
        setRiskExecuting(false);
        setDetailOpen(false);
        if (!batchOpen) {
            detailTaskIdRef.current = null;
            detailSessionRef.current += 1;
            setTaskDetail(null);
            setConfigRevisions([]);
        }
    };

    const closeBatchDrawer = () => {
        setBatchOpen(false);
        if (!detailOpen) {
            detailTaskIdRef.current = null;
            detailSessionRef.current += 1;
            setTaskDetail(null);
            setConfigRevisions([]);
        }
    };

    const openConfigEditor = () => {
        if (!taskDetail || taskDetail.task.archived_at) return;
        const current = configRevisions.find((item) => item.version === taskDetail.task.current_config_version) || configRevisions[0];
        configForm.setFieldsValue({
            config_json: JSON.stringify(current?.config || taskDetail.task.config || {}, null, 2),
            priority: current?.priority ?? taskDetail.task.priority,
            timeout_sec: current?.timeout_sec ?? taskDetail.task.timeout_sec,
            agent_selector_json: JSON.stringify(current?.agent_selector || {}, null, 2),
            agent_selector_rules_json: JSON.stringify(current?.agent_selector_rules || {}, null, 2),
            change_note: '',
        });
        setConfigEditOpen(true);
    };

    const openAppendTargets = () => {
        if (!taskDetail || taskDetail.task.archived_at) return;
        appendIntentRef.current = null;
        setAppendValue('');
        setAppendOpen(true);
    };

    const closeAppendTargets = () => {
        if (appendInFlightRef.current) return;
        appendIntentRef.current = null;
        setAppendOpen(false);
        setAppendValue('');
    };

    const handleAppendTargets = async () => {
        if (appendInFlightRef.current) return;
        if (!taskDetail || !appendValue.trim()) {
            message.warning('请输入至少一个新目标');
            return;
        }
        const taskId = taskDetail.task.id;
        const fingerprint = `${taskId}\u0000${appendValue}`;
        let intent = appendIntentRef.current;
        if (!intent || intent.fingerprint !== fingerprint) {
            intent = { key: newIdempotencyKey(), fingerprint, taskId, targets: appendValue };
            appendIntentRef.current = intent;
        }
        appendInFlightRef.current = true;
        setAppendSaving(true);
        try {
            const result = await appendTargets(intent.taskId, intent.targets, intent.key);
            if (result.new_targets === 0) {
                message.info(`没有新增目标，已关联并跳过 ${result.duplicate_targets} 个重复目标`);
            } else {
                message.success(result.replayed
                    ? '增加批次已确认，已复用此前结果'
                    : `已增加 ${result.new_batches} 个批次、${result.new_targets} 个目标`);
            }
            appendIntentRef.current = null;
            setAppendOpen(false);
            setAppendValue('');
            const [detail, revisions] = await Promise.all([
                getTaskDetail(intent.taskId),
                getTaskConfigRevisions(intent.taskId),
            ]);
            setTaskDetail(detail);
            setConfigRevisions(revisions.items || []);
            fetchTasks();
        } catch (error: unknown) {
            if (isIdempotencyConflict(error)) {
                appendIntentRef.current = null;
                message.error('追加请求冲突，请确认目标后重新提交');
            } else if (isNetworkOrTimeout(error)) {
                message.error('追加请求未确认完成，网络恢复后可直接重试');
            } else if (error instanceof Error) {
                appendIntentRef.current = null;
                message.error(error.message);
            } else {
                appendIntentRef.current = null;
                message.error('增加批次失败');
            }
        } finally {
            appendInFlightRef.current = false;
            setAppendSaving(false);
        }
    };

    const invalidateRiskValidationIntent = () => {
        riskIntentRef.current = null;
    };

    const loadRiskValidationPreview = async (page: number = 1, pageSize: number = 50, specifiedPocs: string[] = riskSpecifiedPocs) => {
        if (!taskDetail || riskInFlightRef.current) return;
        const taskId = taskDetail.task.id;
        const previewSession = ++riskPreviewSessionRef.current;
        invalidateRiskValidationIntent();
        setRiskPreviewOpen(true);
        setRiskPreviewLoading(true);
		setRiskAuthorizedConfirmed(false);
		setRiskSecondConfirmed(false);
        try {
			const result = await previewTaskRiskValidation(taskId, page, pageSize, { specified_pocs: specifiedPocs });
            if (detailTaskIdRef.current === taskId && riskPreviewSessionRef.current === previewSession) setRiskPreview(result);
        } catch (error) {
            console.error('Failed to preview task risk validation:', error);
            if (detailTaskIdRef.current === taskId && riskPreviewSessionRef.current === previewSession) message.error('风险验证预览生成失败');
        } finally {
            if (detailTaskIdRef.current === taskId && riskPreviewSessionRef.current === previewSession) setRiskPreviewLoading(false);
        }
    };

	const _openRiskValidationPreview = async () => {
		setRiskSpecifiedPocs([]);
		setRiskPocOptions([]);
		setRiskPocOptionsLoading(true);
		void loadRiskValidationPreview(1, 50, []);
		try {
			const result = await listPocRulesPage({ page: 1, page_size: 200 });
			setRiskPocOptions((result.items || [])
				.filter((rule) => rule.enabled && rule.state.toLowerCase() === 'approved')
				.map((rule) => ({
					value: rule.source_file,
					label: <Space size={6}><Text>{rule.name || rule.source_file}</Text><Tag color={riskLevelColors[rule.risk_level]}>{riskLevelLabels[rule.risk_level]}</Tag></Space>,
				})));
		} catch {
			message.warning('已审核 POC 列表加载失败，仍可使用 Workflow 自动匹配');
		} finally {
			setRiskPocOptionsLoading(false);
		}
	};
	if (legacyScanUIEnabled) void _openRiskValidationPreview;

	const closeRiskValidationPreview = () => {
		if (riskInFlightRef.current) return;
		riskPreviewSessionRef.current += 1;
		invalidateRiskValidationIntent();
		setRiskPreviewOpen(false);
		setRiskPreview(null);
		setRiskSpecifiedPocs([]);
		setRiskAuthorizedConfirmed(false);
		setRiskSecondConfirmed(false);
	};

	const handleExecuteRiskValidation = async () => {
		if (!taskDetail || !riskPreview || !riskAuthorizedConfirmed) return;
		if (riskPreview.summary.second_confirmation_required && !riskSecondConfirmed) {
			message.warning('高风险或风险未分类 POC 必须完成二次确认');
			return;
		}
		const taskId = taskDetail.task.id;
		const previewSession = riskPreviewSessionRef.current;
		const request: API.ExecuteRiskValidationRequest = {
			plan_hash: riskPreview.plan_hash,
			specified_pocs: [...riskSpecifiedPocs],
			// The table is paginated for inspection only. An empty selection retains
			// the preview contract's full, plan-hash-bound candidate set.
			selected: [],
			confirmed: true,
			second_confirmation: riskSecondConfirmed,
		};
		const fingerprint = JSON.stringify(request);
		let intent = riskIntentRef.current;
		if (!intent || intent.taskId !== taskId || intent.previewSession !== previewSession || intent.fingerprint !== fingerprint) {
			intent = { key: newIdempotencyKey(), taskId, previewSession, request, fingerprint };
			riskIntentRef.current = intent;
		}
		if (riskInFlightRef.current === intent) return;
		riskInFlightRef.current = intent;
		setRiskExecuting(true);
		try {
			const result = await executeTaskRiskValidation(intent.taskId, intent.request, intent.key);
			const isCurrent = riskIntentRef.current === intent && detailTaskIdRef.current === intent.taskId && riskPreviewSessionRef.current === intent.previewSession;
			if (!isCurrent) return;
			message.success(result.replayed
				? `风险验证已确认，已复用此前结果${result.dispatch_pending > 0 ? '，等待队列恢复' : ''}`
				: `已创建风险验证批次，包含 ${result.candidate_count} 个候选项${result.dispatch_pending > 0 ? '，等待队列恢复' : ''}`);
			invalidateRiskValidationIntent();
			riskInFlightRef.current = null;
			closeRiskValidationPreview();
			await Promise.all([handleShowDetail(intent.taskId), fetchTasks()]);
		} catch (error: unknown) {
			const isCurrent = riskIntentRef.current === intent && detailTaskIdRef.current === intent.taskId && riskPreviewSessionRef.current === intent.previewSession;
			if (!isCurrent) return;
			if (isIdempotencyConflict(error)) {
				invalidateRiskValidationIntent();
				message.error('风险验证请求冲突，请重新预览后确认');
			} else if (isNetworkOrTimeout(error)) {
				message.error('风险验证请求未确认完成，网络恢复后可直接重试');
			} else if (error instanceof Error) {
				invalidateRiskValidationIntent();
				message.error(error.message);
			} else {
				invalidateRiskValidationIntent();
				message.error('风险验证批次创建失败');
			}
		} finally {
			if (riskInFlightRef.current === intent) {
				riskInFlightRef.current = null;
				if (detailTaskIdRef.current === intent.taskId && riskPreviewSessionRef.current === intent.previewSession) setRiskExecuting(false);
			}
		}
	};

    const handleBatchAction = (batch: API.TaskBatchSummary, action: BatchAction) => {
        if (!taskDetail) return;
        const descriptions: Record<BatchAction, string> = {
            pause: batch.status.toUpperCase() === 'RUNNING'
                ? '已领取的执行允许完成，但暂停期间不会自动重试。'
                : '未领取的执行会停止派发，恢复后继续。',
            resume: '恢复后会继续当前执行，或为暂停期间已失败的批次追加一次新尝试。',
            stop: '运行中的执行会向 Agent 下发取消；未领取的执行会立即停止。',
            retry: '将保留历史执行，并使用当前任务配置与最新规则追加一次强制复测。',
            archive: '批次将退出默认列表和进度聚合，但扫描结果、尝试历史和审计会保留。',
        };
        modal.confirm({
            title: batchActionLabels[action],
            content: descriptions[action],
            okText: '确认',
            cancelText: '取消',
            okButtonProps: { danger: action === 'stop' || action === 'archive' },
            onOk: async () => {
                const taskId = taskDetail.task.id;
                if (action === 'pause') await pauseTaskBatch(taskId, batch.id);
                if (action === 'resume') await resumeTaskBatch(taskId, batch.id);
                if (action === 'stop') await stopTaskBatch(taskId, batch.id);
                if (action === 'retry') {
                    const scope = `${taskId}\u0000${batch.id}`;
                    if (batchRetryInFlightRef.current.has(scope)) return;
                    let intent = batchRetryIntentsRef.current.get(scope);
                    if (!intent) {
                        intent = { key: newIdempotencyKey(), taskId, batchId: batch.id, detailSession: detailSessionRef.current };
                        batchRetryIntentsRef.current.set(scope, intent);
                    } else if (intent.detailSession !== detailSessionRef.current) {
                        // Preserve the retry key after a network failure, but bind this
                        // submission to the currently open detail session. The old
                        // promise still has the old object and cannot clear this lock.
                        intent = { ...intent, detailSession: detailSessionRef.current };
                        batchRetryIntentsRef.current.set(scope, intent);
                    }
                    batchRetryInFlightRef.current.set(scope, intent);
                    const isCurrentDetail = () => detailTaskIdRef.current === intent.taskId
                        && detailSessionRef.current === intent.detailSession;
                    try {
                        const result = await retryTaskBatch(intent.taskId, intent.batchId, intent.key);
                        const pendingText = (result.dispatch_pending || 0) > 0
                            ? `，${result.dispatch_pending} 个批次等待队列恢复`
                            : '';
                        if (isCurrentDetail()) {
                            message.success(result.replayed
                                ? `批次重试已确认，已复用此前结果${pendingText}`
                                : `已为该批次追加重试${pendingText}`);
                        }
                        if (batchRetryIntentsRef.current.get(scope) === intent) batchRetryIntentsRef.current.delete(scope);
                        const detail = await getTaskDetail(intent.taskId);
                        if (isCurrentDetail()) setTaskDetail(detail);
                        fetchTasks();
                    } catch (error: unknown) {
                        if (isIdempotencyConflict(error)) {
                            if (batchRetryIntentsRef.current.get(scope) === intent) batchRetryIntentsRef.current.delete(scope);
                            if (isCurrentDetail()) message.error('批次重试请求冲突，请重新确认后提交');
                        } else if (isNetworkOrTimeout(error)) {
                            if (isCurrentDetail()) message.error('批次重试未确认完成，网络恢复后可直接重试');
                        } else {
                            if (batchRetryIntentsRef.current.get(scope) === intent) batchRetryIntentsRef.current.delete(scope);
                            if (isCurrentDetail()) message.error(error instanceof Error ? error.message : '批次重试失败');
                        }
                    } finally {
                        if (batchRetryInFlightRef.current.get(scope) === intent) batchRetryInFlightRef.current.delete(scope);
                    }
                    return;
                }
                if (action === 'archive') await archiveTaskBatch(taskId, batch.id);
                const detail = await getTaskDetail(taskId);
                setTaskDetail(detail);
                fetchTasks();
                message.success(`${batchActionLabels[action]}已提交`);
            },
            onCancel: () => {
                if (action === 'retry') batchRetryIntentsRef.current.delete(`${taskDetail.task.id}\u0000${batch.id}`);
            },
        });
    };

    const handleSaveTaskConfig = async () => {
        if (!taskDetail) return;
        try {
            const values = await configForm.validateFields();
            const config = parseAdvancedConfig(values.config_json);
            const agentSelector = parseAdvancedConfig(values.agent_selector_json) as Record<string, string>;
            const agentSelectorRules = parseAdvancedConfig(values.agent_selector_rules_json) as API.AgentSelectorRules;
            setConfigSaving(true);
            const result = await updateTaskConfig(taskDetail.task.id, {
                config,
                priority: values.priority,
                timeout_sec: values.timeout_sec,
                agent_selector: agentSelector,
                agent_selector_rules: agentSelectorRules,
                change_note: values.change_note,
            });
            const [detail, revisions] = await Promise.all([
                getTaskDetail(taskDetail.task.id),
                getTaskConfigRevisions(taskDetail.task.id),
            ]);
            setTaskDetail(detail);
            setConfigRevisions(revisions.items || []);
            setConfigEditOpen(false);
            fetchTasks();
            message.success(result.unchanged ? '配置没有变化，继续使用当前版本' : `已创建配置版本 v${result.current_config_version}`);
        } catch (error) {
            if (error instanceof SyntaxError) {
                message.error('配置与选择器必须是有效的 JSON 对象');
            } else if (error && typeof error === 'object' && 'errorFields' in error) {
                return;
            } else {
                message.error('保存任务配置失败');
            }
        } finally {
            setConfigSaving(false);
        }
    };

    const getStatusTag = (status: string) => renderTaskStatusTag(status);

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
            render: (status: string, record) => (
                <Space size={4} wrap>
                    {getStatusTag(status)}
                    {record.ArchivedAt && <Tag>已归档</Tag>}
                </Space>
            ),
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
                        : normalized === 'STOPPED'
                            ? 'normal'
                            : 'active';
                const strokeColor = isTaskFinished(normalized)
                    ? '#10b981'
                    : isTaskFailedLike(normalized)
                        ? '#ef4444'
                        : normalized === 'STOPPED'
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
            width: 280,
            fixed: 'right',
            render: (_, record) => (
                <Space size={4}>
                    <Button type="link" size="small" icon={<InfoCircleOutlined />}
                        onClick={() => handleShowDetail(record.ID)}>
                        详情
                    </Button>
                    <Button type="link" size="small" icon={<UnorderedListOutlined />}
                        onClick={() => handleShowBatches(record.ID)}>
                        批次
                    </Button>
                    <Button type="link" size="small" icon={<EyeOutlined />}
                        onClick={() => navigate(`/tasks/${record.ID}/results`)}>
                        结果
                    </Button>
                    {record.ArchivedAt ? (
                        <Tag icon={<InboxOutlined />}>已归档</Tag>
                    ) : canManageTasks ? (
                        <Dropdown
                            trigger={['click']}
                            placement="bottomRight"
                            menu={{
                                items: taskActionItems(record),
                                onClick: ({ key, domEvent }) => {
                                    domEvent.stopPropagation();
                                    handleTaskAction(record, key);
                                },
                            }}
                        >
                            <Button
                                type="text"
                                size="small"
                                icon={<MoreOutlined />}
                                aria-label={`管理任务 ${record.Name}`}
                            >
                                更多
                            </Button>
                        </Dropdown>
                    ) : (
                        <Tooltip title="需要操作员权限">
                            <span>
                                <Button
                                    type="text"
                                    size="small"
                                    icon={<MoreOutlined />}
                                    disabled
                                    aria-label="更多操作（需要操作员权限）"
                                >
                                    更多
                                </Button>
                            </span>
                        </Tooltip>
                    )}
                </Space>
            ),
        },
    ];

    return (
        <div style={{ position: 'relative', overflow: 'hidden' }}>
            <NetworkCanvas color="#10b981" count={30} speed={0.15} linkDist={100} />
            <div style={{ position: 'relative', zIndex: 1, display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
                <Title level={4} style={{ margin: 0, color: '#1e293b', fontWeight: 600 }}>
                    <RocketOutlined style={{ marginRight: 8, color: '#10b981' }} />
                    任务管理
                </Title>
                <Space>
                    <Space size={6}>
                        <Text type="secondary">查看归档</Text>
                        <Switch
                            size="small"
                            checked={showArchived}
                            onChange={handleArchivedViewChange}
                            aria-label="查看归档任务"
                        />
                    </Space>
                    <Button icon={<ReloadOutlined />} onClick={() => fetchTasks()} loading={loading}>
                        刷新
                    </Button>
                    {canManageTasks && (
                        <Button type="primary" icon={<PlusOutlined />} onClick={openCreateTask}>
                            创建任务
                        </Button>
                    )}
                </Space>
            </div>

            <ProCard className="glass-card" style={{ background: 'transparent', border: 'none', position: 'relative', zIndex: 1 }}>
                {loading && tasks.length === 0 ? (
                    <div style={{ display: 'flex', justifyContent: 'center', padding: '60px 0' }}>
                        <Spin size="large" />
                    </div>
                ) : tasks.length === 0 ? (
                    <Empty
                        image={Empty.PRESENTED_IMAGE_SIMPLE}
                        description={showArchived ? '暂无归档任务' : '暂无扫描任务'}
                        style={{ padding: '60px 0' }}
                    >
                        {canManageTasks && !showArchived && (
                            <Button type="primary" icon={<PlusOutlined />} onClick={openCreateTask}>
                                创建第一个任务
                            </Button>
                        )}
                    </Empty>
                ) : (
                    <Table
                        columns={columns}
                        dataSource={tasks}
                        rowKey="ID"
                        pagination={{
                            current: taskPagination.current,
                            pageSize: taskPagination.pageSize,
                            total: taskPagination.total,
                            showSizeChanger: true,
                            pageSizeOptions: [10, 20, 50, 100],
                            showTotal: (total) => `共 ${total} 个任务`,
                        }}
                        onChange={(pagination) => {
                            fetchTasks(pagination.current || 1, pagination.pageSize || taskPaginationRef.current.pageSize);
                        }}
                        scroll={{ x: 1000 }}
                        size="middle"
                    />
                )}
            </ProCard>

            {canManageTasks && <ScanTaskCreateModal open={createOpen} creating={creating} form={form} projects={projects}
                activeProjectId={globalProjectId} plan={scanPlan} onPlanChange={setScanPlan}
                onCancel={cancelCreate} onCreate={handleCreate} onDraftChange={invalidateCreateDraft} />}

            {legacyScanUIEnabled && canManageTasks && (
                <Modal
                    title="创建扫描任务"
                    open={createOpen}
                    onCancel={cancelCreate}
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
                    onValuesChange={() => {
                        // Any semantic form edit starts a new creation intent.  This
                        // also prevents a pending target-validation payload from being
                        // submitted after the user changes the underlying form.
                        if (!creating) invalidateCreateDraft();
                    }}
                >
                    <Row gutter={16}>
                        <Col span={12}>
                            <Form.Item label="所属项目" name="project_id" rules={[{ required: true, message: '请选择所属项目' }]}>
                                <Select 
                                    placeholder="选择扫描任务归属的项目"
                                    options={projects.map(p => ({ label: p.Name, value: p.ID }))}
                                    onChange={handleCreateProjectChange}
                                />
                            </Form.Item>
                        </Col>
                        <Col span={12}>
                            <Form.Item label="任务名称（可选）" name="name" extra="留空时按首个目标自动生成">
                                <Input placeholder="自动生成任务名称" />
                            </Form.Item>
                        </Col>
                    </Row>
                    <Alert
                        type="info"
                        showIcon
                        style={{ marginBottom: 16 }}
                        message="输入规则"
                        description={directTargetHint}
                    />

                    <Form.Item
                        label="扫描目标"
                        name="targets"
                        rules={[{ required: true, message: '请输入扫描目标' }]}
                    >
                        <TextArea
                            rows={6}
                            placeholder={'192.168.1.10\n192.168.1.10:8080\nhttps://example.com\nexample.com\n10.0.0.1/24'}
                        />
                    </Form.Item>

                    <Alert
                        type="success"
                        showIcon
                        style={{ marginBottom: 12 }}
                        message={`自动安全测绘 · ${selectedCreateProject?.Name || '当前项目'}`}
                        description={selectedProjectTargets.length > 0
                            ? `已载入项目范围 ${selectedProjectTargets.length} 个目标；自动选择 Agent 和平衡扫描参数。POC、子域爆破、目录探测和密码探测默认关闭。`
                            : '自动选择 Agent 和平衡扫描参数。POC、子域爆破、目录探测和密码探测默认关闭。'}
                    />
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
                    <Collapse
                        bordered={false}
                        style={{ background: 'transparent' }}
                        items={[{
                            key: 'advanced-task-settings',
                            label: <Space><ExperimentOutlined style={{ color: '#64748b' }} />高级设置</Space>,
                            children: (
                                <>
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
                                            <Form.Item label={<>主机发现 <Tooltip title="关闭后跳过 ICMP 和 TCP 探活，直接扫描"><InfoCircleOutlined /></Tooltip></>} name="SkipHostDiscovery" {...invertedSwitchBinding}>
                                                <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                                            </Form.Item>
                                        </Col>
                                        <Col span={8}>
                                            <Form.Item label="ICMP 探测" name="NoICMPPing" {...invertedSwitchBinding}>
                                                <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                                            </Form.Item>
                                        </Col>
                                        <Col span={8}>
                                            <Form.Item label="TCP 探活" name="TCPPing" valuePropName="checked">
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
                                                <Form.Item label="子域名枚举" name="Subdomain" valuePropName="checked">
                                                    <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                                                </Form.Item>
                                            </Col>
                                            <Col span={8}>
                                                <Form.Item label="子域爆破" name="NoSubdomainBruteForce" {...invertedSwitchBinding}>
                                                    <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                                                </Form.Item>
                                            </Col>
                                            <Col span={8}>
                                                <Form.Item label="被动枚举" name="NoSubFinder" {...invertedSwitchBinding}>
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
                                                <Form.Item label="域名绑定探测" name="NoHostBind" {...invertedSwitchBinding}>
                                                    <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                                                </Form.Item>
                                            </Col>
                                        </Row>
                                        <Row gutter={16}>
                                            <Col span={8}>
                                                <Form.Item
                                                    label="域名+端口探测"
                                                    name="NoDomainProbe"
                                                    {...invertedSwitchBinding}
                                                    tooltip="开启后，域名解析 IP 上发现的开放 Web 端口将以 域名:端口 形式探测并产出资产，不再以 IP 形式重复探测"
                                                >
                                                    <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                                                </Form.Item>
                                            </Col>
                                            <Col span={8}>
                                                <Form.Item
                                                    label="解析 IP 扫描"
                                                    name="NoResolvedIPScan"
                                                    {...invertedSwitchBinding}
                                                    tooltip="开启后对非 CDN 域名的解析 IP 做存活探测和端口扫描；关闭则跳过 IP 扫描，仅按任务端口设置以 域名:端口 形式盲探 Web"
                                                >
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
                                            <Form.Item label="主动目录指纹" name="NoDirSearch" {...invertedSwitchBinding}>
                                                <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                                            </Form.Item>
                                        </Col>
                                    </Row>
                                ),
                            },
                            {
                                key: 'vuln',
                                label: <Space><BugOutlined style={{ color: '#ef4444' }} />风险验证</Space>,
                                children: (
                                    <Alert
                                        type="info"
                                        showIcon
                                        message="POC 已与普通资产扫描隔离"
                                        description="先完成资产扫描，再从任务详情打开“风险验证预览”。只有确认预览后才会创建独立风险验证批次，高风险或未分类 POC 还需要二次确认。"
                                    />
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
                            {
                                key: 'advanced',
                                label: <Space><ExperimentOutlined style={{ color: '#64748b' }} />高级配置</Space>,
                                children: (
                                    <Form.Item
                                        label="额外 Agent 配置 JSON"
                                        name="advanced_config_json"
                                        extra="JSON 会直接合并进任务配置；键名请使用 Agent 实际配置字段，例如 NucleiTemplate、NoInteractsh。"
                                    >
                                        <TextArea
                                            rows={6}
                                            placeholder={`{\n  "NucleiTemplate": "config/pocs",\n  "NoInteractsh": true\n}`}
                                        />
                                    </Form.Item>
                                ),
                            },
                        ]}
                    />
                                </>
                            ),
                        }]}
                    />
                </Form>
                </Modal>
            )}

            {legacyScanUIEnabled && <Modal
                title="目标预校验"
                open={targetValidationOpen}
				onCancel={returnToCreateDraft}
                width={760}
                destroyOnHidden
                footer={[
					<Button key="cancel" onClick={returnToCreateDraft}>返回修改</Button>,
                    <Button key="skip" onClick={handleSkipInvalidTargets} loading={creating}>跳过无效项并创建</Button>,
                    <Button key="revalidate" type="primary" onClick={handleRevalidateTargets} loading={creating}>重新校验并创建</Button>,
                ]}
            >
                <Alert
                    type="warning"
                    showIcon
                    message={`发现 ${invalidTargets.length} 个无法识别的目标`}
                    description={`已识别 ${validTargets.length} 个有效目标。修正后重新校验，或明确跳过无效项。`}
                    style={{ marginBottom: 16 }}
                />
                <Space direction="vertical" size={10} style={{ width: '100%' }}>
                    {invalidTargets.map((item, index) => (
                        <div key={`${item.target}-${index}`} style={{ display: 'grid', gridTemplateColumns: '180px minmax(0, 1fr)', gap: 10, alignItems: 'center' }}>
                            <Tag color="error" style={{ margin: 0, whiteSpace: 'normal' }}>{item.reason}</Tag>
                            <Input
                                aria-label={`修正目标 ${index + 1}`}
                                value={invalidTargetEdits[index] || ''}
                                onChange={(event) => setInvalidTargetEdits((current) => current.map((value, itemIndex) => itemIndex === index ? event.target.value : value))}
                            />
                        </div>
                    ))}
                </Space>
            </Modal>}

            <TaskDetailDrawer
                open={detailOpen}
                loading={detailLoading}
                detail={taskDetail}
                configRevisions={configRevisions}
                canManageTasks={canManageTasks}
                onClose={closeDetailDrawer}
                onUpdateConfig={openConfigEditor}
            />

            <TaskBatchDrawer
                open={batchOpen}
                loading={detailLoading}
                detail={taskDetail}
                canManageTasks={canManageTasks}
                onClose={closeBatchDrawer}
                onAppend={openAppendTargets}
                onBatchAction={handleBatchAction}
                onBulkRetryFailed={() => {
                    if (!taskDetail) return;
                    const record = tasks.find((item) => item.ID === taskDetail.task.id);
                    handleTaskAction(record || {
                        ID: taskDetail.task.id,
                        Name: taskDetail.task.name,
                        Status: taskDetail.task.status,
                    } as API.RootTask, 'retry');
                }}
            />

			{legacyScanUIEnabled && riskPreview && <Modal
				title="风险验证预览"
				open={riskPreviewOpen}
				onCancel={closeRiskValidationPreview}
				closable={!riskExecuting}
				keyboard={!riskExecuting}
				maskClosable={!riskExecuting}
				width={1180}
				footer={[
					<Button key="close" onClick={closeRiskValidationPreview} disabled={riskExecuting}>关闭</Button>,
					...(canManageTasks ? [
						<Button
							key="execute"
							type="primary"
							danger={Boolean(riskPreview?.summary.second_confirmation_required)}
							loading={riskExecuting}
							disabled={!canExecuteRiskValidation || !riskPreview || riskPreview.total === 0 || !riskAuthorizedConfirmed || Boolean(riskPreview.summary.second_confirmation_required && !riskSecondConfirmed)}
							onClick={handleExecuteRiskValidation}
						>
							确认并创建风险验证批次
						</Button>,
					] : []),
				]}
				destroyOnHidden
			>
				<Alert
					type="warning"
					showIcon
					message="此页面只生成预览，不会执行任何 POC"
					description="候选项来自当前任务资产、已审核 Workflow 和已审核 POC。只有完成明确确认后才会创建仅执行这些 POC 的独立批次；高风险和未分类规则还需要二次确认。"
					style={{ marginBottom: 16 }}
				/>
				<div style={{ marginBottom: 16 }}>
					<Text strong>指定额外 POC（可选）</Text>
					<Space.Compact style={{ width: '100%', marginTop: 8 }}>
						<Select
							mode="multiple"
							showSearch
							allowClear
							aria-label="指定额外 POC"
							placeholder="默认仅使用 Workflow 匹配；可选择已审核 POC 对当前任务资产验证"
							value={riskSpecifiedPocs}
							onChange={(values) => { invalidateRiskValidationIntent(); setRiskSpecifiedPocs(values); }}
							options={riskPocOptions}
							loading={riskPocOptionsLoading}
							disabled={riskExecuting}
							optionFilterProp="value"
							style={{ flex: 1 }}
						/>
						<Button loading={riskPreviewLoading} disabled={riskExecuting} onClick={() => loadRiskValidationPreview(1, 50, riskSpecifiedPocs)}>重新生成预览</Button>
					</Space.Compact>
				</div>
				{riskPreviewLoading && !riskPreview ? (
					<div style={{ display: 'flex', justifyContent: 'center', padding: '64px 0' }}><Spin size="large" /></div>
				) : riskPreview ? (
					<>
						<Row gutter={12} style={{ marginBottom: 16 }}>
							<Col span={6}><Statistic title="指纹资产" value={riskPreview.summary.unique_assets} suffix={` / ${riskPreview.summary.fingerprint_hits} 指纹`} /></Col>
							<Col span={6}><Statistic title="候选 POC" value={riskPreview.summary.candidates} suffix={` / ${riskPreview.summary.poc_rules} 规则`} /></Col>
							<Col span={6}><Statistic title="预计请求量" value={riskPreview.summary.estimated_requests} /></Col>
							<Col span={6}>
								<Statistic
									title="二次确认项"
									value={riskPreview.summary.second_confirmation_items}
									valueStyle={{ color: riskPreview.summary.second_confirmation_required ? '#dc2626' : '#16a34a' }}
								/>
							</Col>
						</Row>
						<Descriptions size="small" bordered column={2} style={{ marginBottom: 16 }}>
							<Descriptions.Item label="当前规则版本"><Tag color="blue">{riskPreview.rule_version || 'unknown'}</Tag></Descriptions.Item>
							<Descriptions.Item label="任务规则快照"><Tag>{riskPreview.task_rule_version || 'unknown'}</Tag></Descriptions.Item>
							<Descriptions.Item label="配置版本"><Tag color="cyan">v{riskPreview.config_version}</Tag></Descriptions.Item>
							<Descriptions.Item label="预览计划哈希"><Text code copyable>{riskPreview.plan_hash.slice(0, 16)}…</Text></Descriptions.Item>
						</Descriptions>
						{riskPreview.summary.second_confirmation_required && (
							<Alert
								type="error"
								showIcon
								message={`${riskPreview.summary.second_confirmation_items} 个候选项属于高风险或风险未分类，执行前必须二次确认`}
								style={{ marginBottom: 12 }}
							/>
						)}
						{((riskPreview.unmatched_products?.length ?? 0) > 0 || (riskPreview.excluded?.length ?? 0) > 0) && (
							<Alert
								type="info"
								showIcon
								message="部分指纹未生成候选项"
								description={
									<Space direction="vertical" size={4}>
										{(riskPreview.unmatched_products?.length ?? 0) > 0 && (
											<div>无已审核 Workflow：{riskPreview.unmatched_products.map(product => <Tag key={product}>{product}</Tag>)}</div>
										)}
										{(riskPreview.excluded || []).map(item => (
											<div key={`${item.product}-${item.poc_name}-${item.reason}`}>
												<Tag color="orange">{item.product}</Tag>
												<Text code>{item.poc_name}</Text>
												<Text type="secondary"> — {excludedRiskReasonLabels[item.reason] || item.reason}</Text>
											</div>
										))}
									</Space>
								}
								style={{ marginBottom: 12 }}
							/>
						)}
						<Table
							rowKey={(row) => `${row.endpoint}-${row.poc_content_hash}-${row.poc_file}`}
							dataSource={riskPreview.items}
							loading={riskPreviewLoading}
							size="small"
							scroll={{ x: 1080 }}
							pagination={{
								current: riskPreview.page,
								pageSize: riskPreview.page_size,
								total: riskPreview.total,
								showSizeChanger: true,
								disabled: riskExecuting,
								pageSizeOptions: [20, 50, 100, 200],
								showTotal: (total) => `共 ${total} 个候选执行项`,
							}}
							onChange={(pagination) => loadRiskValidationPreview(pagination.current || 1, pagination.pageSize || 50)}
							locale={{ emptyText: <Empty description="当前任务指纹没有匹配到可验证 POC" image={Empty.PRESENTED_IMAGE_SIMPLE} /> }}
							columns={[
								{
									title: '资产 / 端点', key: 'asset', width: 300,
									render: (_, row) => (
										<Space direction="vertical" size={0}>
											<Text copyable style={{ fontFamily: 'monospace', fontSize: 12 }}>{row.endpoint}</Text>
											<Text type="secondary">{row.asset.title || row.asset.service || row.asset.protocol || row.asset.target}</Text>
										</Space>
									),
								},
								{
									title: '产品 / Workflow', key: 'products', width: 190,
									render: (_, row) => (
										<Space direction="vertical" size={2}>
											<Space size={[4, 4]} wrap>{row.products.map(product => <Tag color="blue" key={product}>{product}</Tag>)}</Space>
											<Text type="secondary">{row.match_types.join(', ')}</Text>
										</Space>
									),
								},
								{
									title: 'POC', key: 'poc', width: 220,
									render: (_, row) => (
										<Space direction="vertical" size={0}>
											<Text strong>{row.poc_name}</Text>
											<Text type="secondary" style={{ fontFamily: 'monospace', fontSize: 11 }}>{row.poc_file}</Text>
										</Space>
									),
								},
								{
									title: '严重性 / 执行风险', key: 'risk', width: 210,
									render: (_, row) => (
										<Space size={[4, 4]} wrap>
											<Tag color={severityColors[row.severity] || 'default'}>{row.severity.toUpperCase()}</Tag>
											<Tag color={row.execution_class === 'verification' ? 'purple' : 'blue'}>{row.execution_class === 'verification' ? '验证型' : '检测型'}</Tag>
											<Tag color={riskLevelColors[row.risk_level]}>{riskLevelLabels[row.risk_level]}</Tag>
										</Space>
									),
								},
								{
									title: '预计请求', dataIndex: 'estimated_requests', key: 'estimated_requests', width: 110,
									render: (value: number, row) => (
										<Tooltip title={row.estimate_basis === 'template_upper_bound' ? '根据模板路径和 payload 组合估算的上界' : '模板无法解析，按至少 1 次请求估算'}>
											<Text strong>{value}</Text>
										</Tooltip>
									),
								},
							]}
						/>
						{canManageTasks && (
							<Space direction="vertical" size={8} style={{ width: '100%', marginTop: 16 }}>
								{!canExecuteRiskValidation && (
									<Alert type="info" showIcon message="任务需先完成、失败、超时或停止，才能创建风险验证批次" />
								)}
								<Checkbox disabled={riskExecuting} checked={riskAuthorizedConfirmed} onChange={(event) => { invalidateRiskValidationIntent(); setRiskAuthorizedConfirmed(event.target.checked); }}>
									我确认这些目标均在当前项目授权范围内，并同意执行预览中的全部 POC 请求
								</Checkbox>
								{riskPreview.summary.second_confirmation_required && (
									<Checkbox disabled={riskExecuting} checked={riskSecondConfirmed} onChange={(event) => { invalidateRiskValidationIntent(); setRiskSecondConfirmed(event.target.checked); }}>
										<Text type="danger">我已复核高风险或风险未分类规则，确认继续执行</Text>
									</Checkbox>
								)}
							</Space>
						)}
					</>
				) : null}
			</Modal>}

            <Modal
                title="增加扫描批次"
                open={appendOpen}
                onCancel={closeAppendTargets}
                onOk={handleAppendTargets}
                confirmLoading={appendSaving}
                cancelButtonProps={{ disabled: appendSaving }}
                closable={!appendSaving}
                keyboard={!appendSaving}
                maskClosable={!appendSaving}
                okText="增加批次"
                width={680}
                destroyOnHidden
            >
                <Alert
                    type="info"
                    showIcon
                    message={`新批次使用当前任务配置 v${taskDetail?.task.current_config_version || 1}`}
                    description="目标会先规范化并与本任务已有批次去重；新增目标会自动扩展当前项目的 SeedTargets 和授权 Scope。"
                    style={{ marginBottom: 16 }}
                />
                <TextArea
                    aria-label="新增批次目标"
                    rows={8}
                    value={appendValue}
                    disabled={appendSaving}
                    onChange={(event) => {
                        appendIntentRef.current = null;
                        setAppendValue(event.target.value);
                    }}
                    placeholder="每行一个目标，例如：\n192.168.1.10\nhttps://example.com\nexample.com"
                />
            </Modal>

            <Modal
                title={`更新任务配置（当前 v${taskDetail?.task.current_config_version || 1}）`}
                open={configEditOpen}
                onCancel={() => setConfigEditOpen(false)}
                onOk={handleSaveTaskConfig}
                confirmLoading={configSaving}
                okText="保存为新版本"
                width={720}
                destroyOnHidden
            >
                <Alert
                    type="info"
                    showIcon
                    message="新版本只用于之后新增的批次；已创建批次继续保留原配置快照。"
                    style={{ marginBottom: 16 }}
                />
                <Form form={configForm} layout="vertical">
                    <Row gutter={12}>
                        <Col span={12}>
                            <Form.Item name="priority" label="优先级" rules={[{ required: true }]}>
                                <Select options={[
                                    { value: 0, label: 'P0 / 紧急' },
                                    { value: 1, label: 'P1 / 普通' },
                                    { value: 2, label: 'P2 / 低' },
                                ]} />
                            </Form.Item>
                        </Col>
                        <Col span={12}>
                            <Form.Item name="timeout_sec" label="批次超时（秒）" rules={[{ required: true }]}>
                                <InputNumber min={0} style={{ width: '100%' }} />
                            </Form.Item>
                        </Col>
                    </Row>
                    <Form.Item name="config_json" label="扫描配置 JSON" rules={[{ required: true }]}>
                        <TextArea rows={8} spellCheck={false} />
                    </Form.Item>
                    <Row gutter={12}>
                        <Col span={12}>
                            <Form.Item name="agent_selector_json" label="Agent 选择器 JSON" rules={[{ required: true }]}>
                                <TextArea rows={4} spellCheck={false} />
                            </Form.Item>
                        </Col>
                        <Col span={12}>
                            <Form.Item name="agent_selector_rules_json" label="Agent 选择规则 JSON" rules={[{ required: true }]}>
                                <TextArea rows={4} spellCheck={false} />
                            </Form.Item>
                        </Col>
                    </Row>
                    <Form.Item name="change_note" label="变更说明" rules={[{ max: 500 }]}>
                        <Input placeholder="说明本次调整的原因（可选）" />
                    </Form.Item>
                </Form>
            </Modal>
        </div>
    );
};

export default TaskManagement;
