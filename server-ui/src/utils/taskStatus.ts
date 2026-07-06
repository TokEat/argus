export interface TaskStatusMeta {
    color: string;
    text: string;
}

export function normalizeTaskStatus(status?: string): string {
    return (status || '').trim().toUpperCase();
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
        case 'PARTIALDONE':
            return { color: 'cyan', text: '部分完成' };
        case 'FINISHED':
        case 'DONE':
            return { color: 'success', text: '已完成' };
        case 'PAUSED':
            return { color: 'warning', text: '已暂停' };
        case 'CANCELPENDING':
            return { color: 'warning', text: '取消中' };
        case 'CANCELLED':
        case 'CANCELED':
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
        case 'PARTIALDONE':
            return true;
        default:
            return false;
    }
}

export function isTaskPausable(status?: string): boolean {
    switch (normalizeTaskStatus(status)) {
        case 'QUEUED':
        case 'RUNNING':
        case 'PARTIALDONE':
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

export function isTaskFinished(status?: string): boolean {
    switch (normalizeTaskStatus(status)) {
        case 'FINISHED':
        case 'DONE':
            return true;
        default:
            return false;
    }
}
