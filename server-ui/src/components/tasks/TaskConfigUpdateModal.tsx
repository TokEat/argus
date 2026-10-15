import { useEffect, useState } from 'react';
import { Alert, App, Form, Input, Modal } from 'antd';
import ScanPolicyComposer, {
    policyToFormValues,
    scanPolicyInitialValues,
    type ScanPolicyFormValues,
} from './ScanPolicyComposer';
import { getTaskConfigRevisions, getTaskDetail, updateTaskConfig } from '../../services/api';

export type TaskConfigUpdateFormValues = ScanPolicyFormValues & { change_note?: string };

function targetsTextFromOriginal(raw?: string): string {
    if (!raw?.trim()) return '';
    try {
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) {
            return parsed.filter((item): item is string => typeof item === 'string' && Boolean(item.trim())).join('\n');
        }
    } catch {
        // fall through — treat as plain multiline text
    }
    return raw;
}

export function resolveTaskProjectId(detail: API.TaskDetailResponse, fallback?: string): string {
    const task = detail.task as { project_id?: string; ProjectID?: string };
    return [task.project_id, task.ProjectID, fallback, localStorage.getItem('active_project_id') || '']
        .map((value) => String(value || '').trim())
        .find(Boolean) || '';
}

export function buildConfigUpdateInitialValues(
    detail: API.TaskDetailResponse,
    revisions: API.TaskConfigRevision[],
    projectId: string,
): TaskConfigUpdateFormValues {
    const current = revisions.find((item) => item.version === detail.task.current_config_version) || revisions[0];
    const policy = detail.scan_policy?.policy;
    return {
        ...scanPolicyInitialValues,
        ...policyToFormValues(policy),
        project_id: projectId || undefined,
        targets: targetsTextFromOriginal(detail.task.original_targets),
        priority: current?.priority ?? detail.task.priority ?? 1,
        timeout_sec: current?.timeout_sec ?? detail.task.timeout_sec ?? 3600,
        change_note: '',
    };
}

interface Props {
    open: boolean;
    taskId: string;
    detail: API.TaskDetailResponse | null;
    revisions: API.TaskConfigRevision[];
    projects: API.Project[];
    projectId?: string;
    onClose: () => void;
    onSaved: (detail: API.TaskDetailResponse, revisions: API.TaskConfigRevision[]) => void;
}

export default function TaskConfigUpdateModal({
    open, taskId, detail, revisions, projects, projectId, onClose, onSaved,
}: Props) {
    const { message } = App.useApp();
    const [form] = Form.useForm<TaskConfigUpdateFormValues>();
    const [plan, setPlan] = useState<API.ScanPlanPreview | null>(null);
    const [saving, setSaving] = useState(false);
    const lockedProjectId = detail ? resolveTaskProjectId(detail, projectId) : (projectId || '');

    useEffect(() => {
        if (!open || !detail) return;
        form.setFieldsValue(buildConfigUpdateInitialValues(detail, revisions, lockedProjectId));
        setPlan(null);
    }, [open, detail, revisions, form, lockedProjectId]);

    const handleSave = async () => {
        if (!detail || detail.task.id !== taskId) return;
        try {
            await form.validateFields();
            if (!plan) {
                message.error('请先完成有效的实时执行计划');
                return;
            }
            const values = form.getFieldsValue(true);
            setSaving(true);
            const result = await updateTaskConfig(taskId, {
                policy: plan.policy,
                plan_hash: plan.plan_hash,
                priority: values.priority ?? 1,
                timeout_sec: values.timeout_sec ?? 3600,
                change_note: values.change_note,
            });
            const [nextDetail, nextRevisions] = await Promise.all([
                getTaskDetail(taskId),
                getTaskConfigRevisions(taskId),
            ]);
            onSaved(nextDetail, nextRevisions.items || []);
            onClose();
            message.success(result.unchanged
                ? '配置没有变化，继续使用当前版本'
                : `已创建配置版本 v${result.current_config_version}`);
        } catch (error) {
            if (error && typeof error === 'object' && 'errorFields' in error) return;
            if (typeof error === 'string') {
                message.error(error);
            } else if (error instanceof Error) {
                message.error(error.message || '保存任务配置失败');
            } else {
                message.error('保存任务配置失败');
            }
        } finally {
            setSaving(false);
        }
    };

    return (
        <Modal
            title="更新任务配置"
            open={open}
            onCancel={onClose}
            onOk={handleSave}
            confirmLoading={saving}
            okText="保存为新版本"
            okButtonProps={{ disabled: !plan }}
            width={1320}
            destroyOnHidden
            styles={{ body: { maxHeight: '75vh', overflowY: 'auto' } }}
        >
            <Alert
                type="info"
                showIcon
                style={{ marginBottom: 16 }}
                message="新版本只用于之后新增的批次"
                description="已在执行或已完成的批次仍使用创建时的配置快照。策略阶段状态若已派生/完成，不会因本次保存回滚。"
            />
            <Form form={form} layout="vertical">
                <ScanPolicyComposer
                    form={form}
                    projects={projects}
                    onPlanChange={setPlan}
                    mode="update"
                    lockedProjectId={lockedProjectId}
                />
                <Form.Item name="change_note" label="变更说明" style={{ marginTop: 12 }}>
                    <Input.TextArea rows={2} maxLength={500} showCount placeholder="说明本次调整原因（可选）" />
                </Form.Item>
            </Form>
        </Modal>
    );
}
