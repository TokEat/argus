import React, { useEffect, useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
    Alert,
    App,
    Badge,
    Button,
    Dropdown,
    Empty,
    Form,
    Input,
    Modal,
    Progress,
    Space,
    Spin,
    Switch,
    Table,
    Tag,
    Tooltip,
    Typography,
} from 'antd';
import { ProCard } from '@ant-design/pro-components';
import {
    EyeOutlined,
    InboxOutlined,
    InfoCircleOutlined,
    MoreOutlined,
    PauseCircleOutlined,
    PlayCircleOutlined,
    PlusOutlined,
    ReloadOutlined,
    RocketOutlined,
    StopOutlined,
    UnorderedListOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import type { MenuProps } from 'antd';
import { appendTargets, archiveTaskBatch, connectWebSocket, createTask, deleteTask, getTaskConfigRevisions, getTaskDetail, listProjects, listTasks, pauseTask, pauseTaskBatch, resumeTask, resumeTaskBatch, retryTask, retryTaskBatch, stopTask, stopTaskBatch } from '../services/api';
import { isTaskCancellable, isTaskFailedLike, isTaskFinished, isTaskPausable, isTaskResumable, isTaskRetryable, normalizeTaskStatus } from '../utils/taskStatus';
import { canAccessRole } from '../utils/auth';
import { useAutoContext } from '../contexts/GlobalAIContext';
import NetworkCanvas from '../components/NetworkCanvas';
import { scanPolicyInitialValues, type ScanPolicyFormValues } from '../components/tasks/ScanPolicyComposer';
import ScanTaskCreateModal from '../components/tasks/ScanTaskCreateModal';
import TaskConfigUpdateModal from '../components/tasks/TaskConfigUpdateModal';
import TaskBatchDrawer from './taskManagement/TaskBatchDrawer';
import TaskDetailDrawer from './taskManagement/TaskDetailDrawer';
import {
    batchActionLabels,
    isIdempotencyConflict,
    isNetworkOrTimeout,
    newIdempotencyKey,
    renderTaskStatusTag,
    type AppendIntent,
    type BatchAction,
    type BatchRetryIntent,
    type CreateIntent,
    type RetryIntent,
} from './taskManagement/shared';

const { Title, Text } = Typography;
const { TextArea } = Input;

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

const TaskManagement: React.FC = () => {
    const [loading, setLoading] = useState(true);
    const [tasks, setTasks] = useState<API.RootTask[]>([]);
    const [createOpen, setCreateOpen] = useState(false);
    const [creating, setCreating] = useState(false);
    const [form] = Form.useForm();
    const { message, modal } = App.useApp();
    const navigate = useNavigate();
    const globalProjectId = localStorage.getItem('active_project_id') || '';
    const [projects, setProjects] = useState<API.Project[]>([]);
    const [taskPagination, setTaskPagination] = useState({ current: 1, pageSize: 20, total: 0 });
    const taskPaginationRef = useRef({ current: 1, pageSize: 20, total: 0 });
    const [showArchived, setShowArchived] = useState(false);
    const showArchivedRef = useRef(false);
    const [detailOpen, setDetailOpen] = useState(false);
    const [batchOpen, setBatchOpen] = useState(false);
    const [detailLoading, setDetailLoading] = useState(false);
    const [taskDetail, setTaskDetail] = useState<API.TaskDetailResponse | null>(null);
    const [configRevisions, setConfigRevisions] = useState<API.TaskConfigRevision[]>([]);
    const [configEditOpen, setConfigEditOpen] = useState(false);
    const [appendOpen, setAppendOpen] = useState(false);
    const [appendValue, setAppendValue] = useState('');
    const [appendSaving, setAppendSaving] = useState(false);
    const [scanPlan, setScanPlan] = useState<API.ScanPlanPreview | null>(null);
    const createIntentRef = useRef<CreateIntent | null>(null);
    const appendIntentRef = useRef<AppendIntent | null>(null);
    const appendInFlightRef = useRef(false);
    const retryIntentRef = useRef<RetryIntent | null>(null);
    const retryInFlightRef = useRef(new Map<string, RetryIntent>());
    const batchRetryIntentsRef = useRef(new Map<string, BatchRetryIntent>());
    const batchRetryInFlightRef = useRef(new Map<string, BatchRetryIntent>());
    const detailTaskIdRef = useRef<string | null>(null);
    const detailSessionRef = useRef(0);
    const canManageTasks = canAccessRole('operator');
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


    useEffect(() => {
        fetchTasks();
        fetchProjects();
        const timer = setInterval(fetchTasks, 10000);
        const ws = connectWebSocket(() => undefined, undefined, {
            onReconnect: () => {
                fetchTasks();
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
        setCreateOpen(false);
        setScanPlan(null);
    };

    const invalidateCreateDraft = () => {
        clearCreateIntent();
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
        appendIntentRef.current = null;
        retryIntentRef.current = null;
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

            <TaskConfigUpdateModal
                open={configEditOpen}
                taskId={taskDetail?.task.id || ''}
                detail={taskDetail}
                revisions={configRevisions}
                projects={projects}
                projectId={
                    taskDetail?.task.project_id
                    || tasks.find((item) => item.ID === taskDetail?.task.id)?.ProjectID
                    || globalProjectId
                }
                onClose={() => setConfigEditOpen(false)}
                onSaved={(nextDetail, nextRevisions) => {
                    setTaskDetail(nextDetail);
                    setConfigRevisions(nextRevisions);
                    fetchTasks();
                }}
            />
        </div>
    );
};

export default TaskManagement;
