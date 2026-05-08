import { describe, expect, it, vi, beforeEach } from 'vitest';
import { connectWebSocket } from './api';

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
});
