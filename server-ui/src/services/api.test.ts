import { beforeEach, describe, expect, it, vi } from 'vitest';

const { postMock, requestInterceptors, responseInterceptors } = vi.hoisted(() => ({
    postMock: vi.fn(),
    requestInterceptors: { use: vi.fn() },
    responseInterceptors: { use: vi.fn() },
}));

vi.mock('axios', () => ({
    default: {
        create: vi.fn(() => ({
            post: postMock,
            interceptors: {
                request: requestInterceptors,
                response: responseInterceptors,
            },
        })),
    },
}));

import { appendTargets, connectWebSocket, createTask, executeTaskRiskValidation, retryTask, retryTaskBatch } from './api';

describe('createTask API', () => {
    beforeEach(() => postMock.mockReset());

    it('sends Idempotency-Key only when supplied', async () => {
        const request = { project_id: 'project-1', targets: 'https://example.test' };
        postMock.mockResolvedValueOnce({ status: 'ok' }).mockResolvedValueOnce({ status: 'ok' });

        await createTask(request);
        await createTask(request, 'intent-key');

        expect(postMock).toHaveBeenNthCalledWith(1, '/tasks', request, undefined);
        expect(postMock).toHaveBeenNthCalledWith(2, '/tasks', request, {
            headers: { 'Idempotency-Key': 'intent-key' },
        });
    });
});

describe('appendTargets API', () => {
    beforeEach(() => postMock.mockReset());

    it('sends Idempotency-Key only when supplied and normalizes older responses', async () => {
        postMock.mockResolvedValueOnce({ status: 'unchanged' }).mockResolvedValueOnce({ status: 'appended', replayed: true });

        const older = await appendTargets('task/1', 'https://example.test');
        const replay = await appendTargets('task/1', 'https://example.test', 'append-key');

        expect(postMock).toHaveBeenNthCalledWith(1, '/tasks/task%2F1/append', { targets: 'https://example.test' }, undefined);
        expect(postMock).toHaveBeenNthCalledWith(2, '/tasks/task%2F1/append', { targets: 'https://example.test' }, {
            headers: { 'Idempotency-Key': 'append-key' },
        });
        expect(older.replayed).toBe(false);
        expect(replay.replayed).toBe(true);
    });
});

describe('retryTask API', () => {
    beforeEach(() => postMock.mockReset());

    it('sends Idempotency-Key only when supplied and normalizes older responses', async () => {
        postMock.mockResolvedValueOnce({ status: 'retried' }).mockResolvedValueOnce({ status: 'retried', replayed: true });

        const older = await retryTask('task/1');
        const replay = await retryTask('task/1', 'retry-key');

        expect(postMock).toHaveBeenNthCalledWith(1, '/tasks/task%2F1/retry', undefined, undefined);
        expect(postMock).toHaveBeenNthCalledWith(2, '/tasks/task%2F1/retry', undefined, {
            headers: { 'Idempotency-Key': 'retry-key' },
        });
        expect(older.replayed).toBe(false);
        expect(replay.replayed).toBe(true);
    });
});

describe('retryTaskBatch API', () => {
    beforeEach(() => postMock.mockReset());

    it('sends Idempotency-Key only when supplied and normalizes older responses', async () => {
        postMock.mockResolvedValueOnce({ status: 'retried' }).mockResolvedValueOnce({ status: 'retried', replayed: true });

        const older = await retryTaskBatch('task/1', 'batch/1');
        const replay = await retryTaskBatch('task/1', 'batch/1', 'batch-retry-key');

        expect(postMock).toHaveBeenNthCalledWith(1, '/tasks/task%2F1/batches/batch%2F1/retry', undefined, undefined);
        expect(postMock).toHaveBeenNthCalledWith(2, '/tasks/task%2F1/batches/batch%2F1/retry', undefined, {
            headers: { 'Idempotency-Key': 'batch-retry-key' },
        });
        expect(older.replayed).toBe(false);
        expect(replay.replayed).toBe(true);
    });
});

describe('executeTaskRiskValidation API', () => {
    beforeEach(() => postMock.mockReset());

    it('sends Idempotency-Key only when supplied and normalizes older responses', async () => {
        const body = { plan_hash: 'plan', selected: [], confirmed: true, second_confirmation: true };
        postMock.mockResolvedValueOnce({ status: 'scheduled' }).mockResolvedValueOnce({ status: 'scheduled', replayed: true });

        const older = await executeTaskRiskValidation('task/1', body);
        const replay = await executeTaskRiskValidation('task/1', body, 'risk-key');

        expect(postMock).toHaveBeenNthCalledWith(1, '/tasks/task%2F1/risk-validation', body, undefined);
        expect(postMock).toHaveBeenNthCalledWith(2, '/tasks/task%2F1/risk-validation', body, {
            headers: { 'Idempotency-Key': 'risk-key' },
        });
        expect(older.replayed).toBe(false);
        expect(replay.replayed).toBe(true);
    });
});

class MockWebSocket {
    static instances: MockWebSocket[] = [];
    url: string;
    onopen?: () => void;
    onmessage?: (event: MessageEvent) => void;
    onerror?: () => void;
    onclose?: () => void;
    close = vi.fn();

    constructor(url: string) {
        this.url = url;
        MockWebSocket.instances.push(this);
    }
}

describe('connectWebSocket', () => {
    beforeEach(() => {
        MockWebSocket.instances = [];
        localStorage.clear();
        vi.stubGlobal('WebSocket', MockWebSocket);
    });

    it('passes the JWT token through the query string', () => {
        localStorage.setItem('token', 'jwt-token');
        const onMessage = vi.fn();

        connectWebSocket(onMessage);

        expect(MockWebSocket.instances[0].url).toContain('/api/v1/ws?token=jwt-token');
    });

    it('parses JSON messages and ignores malformed payloads', () => {
        const onMessage = vi.fn();
        connectWebSocket(onMessage);

        MockWebSocket.instances[0].onmessage?.({ data: '{"type":"heartbeat"}' } as MessageEvent);
        MockWebSocket.instances[0].onmessage?.({ data: 'not-json' } as MessageEvent);

        expect(onMessage).toHaveBeenCalledTimes(1);
        expect(onMessage).toHaveBeenCalledWith({ type: 'heartbeat' });
    });

    it('reconnects with the last received event id', () => {
        vi.useFakeTimers();
        localStorage.setItem('token', 'jwt-token');
        const onMessage = vi.fn();

        connectWebSocket(onMessage, undefined, { onReconnect: vi.fn() });
        MockWebSocket.instances[0].onmessage?.({ data: '{"id":42,"type":"task"}' } as MessageEvent);
        MockWebSocket.instances[0].onclose?.();
        vi.advanceTimersByTime(3000);

        expect(MockWebSocket.instances[1].url).toContain('last_event_id=42');
        vi.useRealTimers();
    });
});
