export interface TaskStatusMeta {
    color: string;
    text: string;
}

export type TaskState =
    | 'UNKNOWN'
    | 'CREATED'
    | 'QUEUED'
    | 'RUNNING'
    | 'PARTIAL'
    | 'PAUSING'
    | 'PAUSED'
    | 'STOPPING'
    | 'STOPPED'
    | 'COMPLETED'
    | 'FAILED'
    | 'TIMEOUT';

export function normalizeTaskStatus(status?: string): string {
    switch ((status || '').trim().toUpperCase()) {
        case 'CREATED': return 'CREATED';
        case 'QUEUED':
        case 'PENDING': return 'QUEUED';
        case 'RUNNING': return 'RUNNING';
        case 'PARTIAL':
        case 'PARTIALDONE': return 'PARTIAL';
        case 'PAUSING': return 'PAUSING';
        case 'PAUSED': return 'PAUSED';
        case 'STOPPING':
        case 'CANCELPENDING': return 'STOPPING';
        case 'STOPPED':
        case 'CANCELLED':
        case 'CANCELED': return 'STOPPED';
        case 'COMPLETED':
        case 'FINISHED':
        case 'DONE':
        case 'SUCCESS':
        case 'SUCCEEDED': return 'COMPLETED';
        case 'FAILED': return 'FAILED';
        case 'TIMEOUT': return 'TIMEOUT';
        default: return 'UNKNOWN';
    }
}

export function getTaskStatusMeta(status?: string): TaskStatusMeta {
    switch (normalizeTaskStatus(status)) {
        case 'CREATED':
            return { color: 'blue', text: '已创建' };
        case 'QUEUED':
        case 'PENDING':
            return { color: 'orange', text: '等待中' };
        case 'RUNNING':
            return { color: 'processing', text: '运行中' };
        case 'PARTIAL':
            return { color: 'cyan', text: '部分完成' };
        case 'COMPLETED':
            return { color: 'success', text: '已完成' };
        case 'PAUSING':
            return { color: 'warning', text: '暂停中' };
        case 'PAUSED':
            return { color: 'warning', text: '已暂停' };
        case 'STOPPING':
            return { color: 'warning', text: '取消中' };
        case 'STOPPED':
            return { color: 'default', text: '已取消' };
        case 'FAILED':
            return { color: 'error', text: '失败' };
        case 'TIMEOUT':
            return { color: 'magenta', text: '超时' };
        default:
            return { color: 'default', text: status || '-' };
    }
}

export function isTaskCancellable(status?: string): boolean {
    switch (normalizeTaskStatus(status)) {
        case 'QUEUED':
        case 'PENDING':
        case 'RUNNING':
        case 'PARTIAL':
        case 'PAUSED':
            return true;
        default:
            return false;
    }
}

export function isTaskPausable(status?: string): boolean {
    switch (normalizeTaskStatus(status)) {
        case 'QUEUED':
        case 'RUNNING':
        case 'PARTIAL':
            return true;
        default:
            return false;
    }
}

export function isTaskResumable(status?: string): boolean {
    return normalizeTaskStatus(status) === 'PAUSED';
}

export function isTaskFailedLike(status?: string): boolean {
    switch (normalizeTaskStatus(status)) {
        case 'FAILED':
        case 'TIMEOUT':
            return true;
        default:
            return false;
    }
}

export function isTaskRetryable(status?: string): boolean {
    switch (normalizeTaskStatus(status)) {
        case 'PARTIAL':
        case 'FAILED':
        case 'TIMEOUT':
        case 'STOPPED':
            return true;
        default:
            return false;
    }
}

export function isTaskFinished(status?: string): boolean {
    switch (normalizeTaskStatus(status)) {
        case 'COMPLETED':
            return true;
        default:
            return false;
    }
}
