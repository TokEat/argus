import React from 'react';
import { Tag } from 'antd';
import { getTaskStatusMeta } from '../../utils/taskStatus';

export type BatchAction = 'pause' | 'resume' | 'stop' | 'retry' | 'archive';

export type CreateIntent = {
    key: string;
    fingerprint: string;
    request: API.CreateTaskRequest;
};

export type AppendIntent = {
    key: string;
    fingerprint: string;
    taskId: string;
    targets: string;
};

export type RetryIntent = {
    key: string;
    taskId: string;
};

export type BatchRetryIntent = {
    key: string;
    taskId: string;
    batchId: string;
    detailSession: number;
};

export const newIdempotencyKey = () => globalThis.crypto?.randomUUID?.()
    || `argus-${Date.now()}-${Math.random().toString(36).slice(2)}`;

export const isIdempotencyConflict = (error: unknown) => {
    if (typeof error === 'object' && error !== null && 'status' in error && (error as { status?: unknown }).status === 409) return true;
    const text = typeof error === 'string' ? error : error instanceof Error ? error.message : '';
    return /idempotency.*conflict|conflict.*idempotency|idempotency-key.*already used|different task creation request|幂等.*冲突/i.test(text);
};

export const isNetworkOrTimeout = (error: unknown) => {
    const status = typeof error === 'object' && error !== null && 'status' in error
        ? (error as { status?: unknown }).status
        : undefined;
    if (typeof status === 'number') return false;
    const code = typeof error === 'object' && error !== null && 'code' in error
        ? String((error as { code?: unknown }).code || '')
        : '';
    const text = typeof error === 'string' ? error : error instanceof Error ? error.message : '';
    return /^(ERR_NETWORK|ECONNABORTED|ETIMEDOUT)$/i.test(code) || /network|timeout|timed out|网络|超时/i.test(text);
};

export const targetTypeLabels: Record<string, string> = {
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

export const coverageLinkMeta: Record<string, { label: string; color: string }> = {
    executed: { label: '实际执行', color: 'blue' },
    reused: { label: '历史复用', color: 'green' },
    in_flight: { label: '执行中关联', color: 'gold' },
};

export const coverageLinkStatusLabels: Record<string, { label: string; color: string }> = {
    active: { label: '执行中', color: 'processing' },
    waiting: { label: '等待来源', color: 'warning' },
    completed: { label: '已完成', color: 'success' },
    resolved: { label: '来源已完成', color: 'success' },
    failed: { label: '执行失败', color: 'error' },
    source_failed: { label: '来源失败', color: 'error' },
};

export const batchActionLabels: Record<BatchAction, string> = {
    pause: '暂停批次',
    resume: '恢复批次',
    stop: '立即停止',
    retry: '重试批次',
    archive: '归档批次',
};

export const attemptTriggerLabels: Record<string, string> = {
    initial: '初次执行',
    automatic_retry: '失败重试',
    timeout_retry: '超时重试',
    split_retry: '拆分重试',
    agent_offline_recovery: '掉线恢复',
    spot_recovery: 'Spot 恢复',
    manual_retry: '手动重试',
    legacy_retry: '历史重试',
};

const terminalBatchStatuses = new Set(['COMPLETED', 'FINISHED', 'DONE', 'SUCCESS', 'SUCCEEDED', 'FAILED', 'TIMEOUT', 'STOPPED', 'CANCELLED', 'CANCELED']);
const activeBatchStatuses = new Set(['QUEUED', 'PENDING', 'DISPATCHING', 'RUNNING', 'RECOVERED']);
const failedRetryBatchStatuses = new Set(['FAILED', 'TIMEOUT', 'STOPPED', 'CANCELLED', 'CANCELED']);

export function availableBatchActions(batch: API.TaskBatchSummary): BatchAction[] {
    if (batch.archived_at) return [];
    const status = (batch.status || '').trim().toUpperCase();
    const control = (batch.control_state || 'active').trim().toLowerCase();
    if (control === 'stopping') return [];
    if (control === 'paused') {
        const actions: BatchAction[] = ['resume'];
        if (status === 'PAUSED' || status === 'RUNNING') actions.push('stop');
        return actions;
    }
    if (activeBatchStatuses.has(status)) return ['pause', 'stop'];
    if (terminalBatchStatuses.has(status)) return ['retry', 'archive'];
    return [];
}

export function isFailedRetryableBatch(batch: API.TaskBatchSummary): boolean {
    if (batch.archived_at) return false;
    const status = (batch.status || batch.display_status || '').trim().toUpperCase();
    const control = (batch.control_state || 'active').trim().toLowerCase();
    if (control === 'paused' || control === 'stopping') return false;
    return failedRetryBatchStatuses.has(status);
}

export function failedRetryableBatches(detail: API.TaskDetailResponse | null): API.TaskBatchSummary[] {
    return (detail?.batches || []).filter(isFailedRetryableBatch);
}

export function renderTaskStatusTag(status: string) {
    const { color, text } = getTaskStatusMeta(status);
    return <Tag color={color}>{text}</Tag>;
}

export const auditActionLabels: Record<string, string> = {
    pause: '暂停',
    resume: '恢复',
    stop: '停止',
    archive: '归档',
    config_update: '更新配置',
    batch_append: '增加批次',
    notebook_distribution_materialize: '测绘笔记本分发',
    batch_pause: '暂停批次',
    batch_resume: '恢复批次',
    batch_stop: '停止批次',
    batch_retry: '重试批次',
    batch_archive: '归档批次',
    retry: '重试失败批次',
};
