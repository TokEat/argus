import { describe, expect, it } from 'vitest';
import {
    getTaskStatusMeta,
    isTaskCancellable,
    isTaskFinished,
    isTaskPausable,
    isTaskResumable,
    isTaskRetryable,
    normalizeTaskStatus,
} from './taskStatus';

describe('task status compatibility', () => {
    it.each([
        ['Pending', 'QUEUED'],
        ['PartialDone', 'PARTIAL'],
        ['FINISHED', 'COMPLETED'],
        ['DONE', 'COMPLETED'],
        ['CancelPending', 'STOPPING'],
        ['Cancelled', 'STOPPED'],
        ['canceled', 'STOPPED'],
    ])('normalizes %s to %s', (input, expected) => {
        expect(normalizeTaskStatus(input)).toBe(expected);
    });

    it('keeps the task action matrix stable for legacy states', () => {
        expect(isTaskPausable('PartialDone')).toBe(true);
        expect(isTaskCancellable('Running')).toBe(true);
        expect(isTaskResumable('Paused')).toBe(true);
        expect(isTaskCancellable('Paused')).toBe(true);
        expect(isTaskRetryable('Failed')).toBe(true);
        expect(isTaskRetryable('Timeout')).toBe(true);
        expect(isTaskRetryable('Cancelled')).toBe(true);
        expect(isTaskRetryable('PartialDone')).toBe(true);
        expect(isTaskFinished('FINISHED')).toBe(true);
        expect(isTaskPausable('FINISHED')).toBe(false);
        expect(isTaskRetryable('FINISHED')).toBe(false);
    });

    it('uses canonical labels for transition states', () => {
        expect(getTaskStatusMeta('CancelPending').text).toBe('取消中');
        expect(getTaskStatusMeta('FINISHED').text).toBe('已完成');
    });
});
