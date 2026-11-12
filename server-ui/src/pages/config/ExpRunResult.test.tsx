import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { ExpRunResult, expRunSummaryText } from './ExpRunResult';

describe('ExpRunResult', () => {
    it('renders only user-facing result and evidence fields', () => {
        render(<ExpRunResult value={{
            run: {
                id: 'internal-run-id',
                exp_id: 'internal-exp-id',
                source_sha256: 'a'.repeat(64),
                action: 'run',
                revision: 3,
                status: 'Succeeded',
            },
            artifact: {
                status: 'Succeeded',
                result: { vulnerable: true, cve: 'CVE-2026-0001', username: 'root', password: 'secret', output: 'uid=0(root)', internal_transport: { headers: { Server: 'hidden' } } },
                evidence: { command_executed: true },
            },
        }} />);

        expect(screen.getByText('已确认目标存在漏洞')).toBeInTheDocument();
        expect(screen.getByText('CVE-2026-0001')).toBeInTheDocument();
        expect(screen.getByText('root')).toBeInTheDocument();
        expect(screen.getByText('secret')).toBeInTheDocument();
        expect(screen.getByText('uid=0(root)')).toBeInTheDocument();
        expect(screen.getByText('命令执行回证')).toBeInTheDocument();
        expect(screen.queryByText('internal-run-id')).not.toBeInTheDocument();
        expect(screen.queryByText('internal-exp-id')).not.toBeInTheDocument();
        expect(screen.queryByText('internal transport')).not.toBeInTheDocument();
        expect(screen.queryByText('Server')).not.toBeInTheDocument();
        expect(screen.queryByText('Raw')).not.toBeInTheDocument();
        expect(screen.queryByText('日志')).not.toBeInTheDocument();
    });

    it('renders complete HTTP request and response content as readable packets', async () => {
        const user = userEvent.setup();
        render(<ExpRunResult value={{
            status: 'Succeeded',
            result: { vulnerable: false },
            debug: {
                events: [{
                    kind: 'http', operation: 'POST', target: 'http://target.invalid/login', status_code: 401, duration_ms: 12,
                    request: {
                        method: 'POST', url: 'http://target.invalid/login',
                        headers: { 'Content-Type': 'application/json', Cookie: 'session=full-value' },
                        body: '{"username":"admin"}', body_encoding: 'utf8',
                    },
                    response: {
                        status_code: 401, final_url: 'http://target.invalid/login',
                        headers: { 'Content-Type': ['application/json'], 'Set-Cookie': ['retry=yes'] },
                        body: '{"error":"denied"}', body_encoding: 'utf8',
                    },
                }],
            },
        }} />);

        expect(screen.getByRole('tab', { name: '请求 / 响应 (1)' })).toBeInTheDocument();
        await user.click(screen.getByText(/HTTP POST · http:\/\/target\.invalid\/login/));
        expect(screen.getByText('HTTP 请求包')).toBeInTheDocument();
        expect(screen.getByText(/Cookie: session=full-value/)).toBeInTheDocument();
        expect(screen.getByText(/\{"username":"admin"\}/)).toBeInTheDocument();
        expect(screen.getByText('HTTP 响应包')).toBeInTheDocument();
        expect(screen.getByText(/Set-Cookie: retry=yes/)).toBeInTheDocument();
        expect(screen.getByText(/\{"error":"denied"\}/)).toBeInTheDocument();
    });

    it('surfaces failures without protocol metadata', () => {
        render(<ExpRunResult value={{ status: 'Failed', error: 'target denied by exact authorization', id: 'internal-id' }} />);
        expect(screen.getByText('执行失败')).toBeInTheDocument();
        expect(screen.getByText('target denied by exact authorization')).toBeInTheDocument();
        expect(screen.queryByText('internal-id')).not.toBeInTheDocument();
    });

    it('turns YakVM panic stacks into a concise actionable error', () => {
        render(<ExpRunResult value={{
            status: 'Failed',
            error: 'Panic Stack: __yak_main__ 37 > panic(probe_err)\\nYakVM Panic: Yaksha egress is disabled',
        }} />);
        expect(screen.getByText(/当前运行出口为 disabled/)).toBeInTheDocument();
        expect(screen.queryByText(/Panic Stack/)).not.toBeInTheDocument();
    });

    it('asks for manual review when the EXP has no reliable marker', () => {
        render(<ExpRunResult value={{
            status: 'Succeeded',
            result: { verdict: 'manual_review', reason: '响应没有稳定回显，请结合响应包判断', message: 'HTTP 500' },
        }} />);
        expect(screen.getByText('EXP 无可靠自动判据，需要人工判断')).toBeInTheDocument();
        expect(screen.getAllByText('响应没有稳定回显，请结合响应包判断').length).toBeGreaterThan(0);
        expect(screen.queryByText('已确认目标存在漏洞')).not.toBeInTheDocument();
    });

    it('summarizes audit rows without JSON', () => {
        expect(expRunSummaryText({ status: 'Succeeded', has_error: false })).toBe('执行成功');
        expect(expRunSummaryText({ status: 'Failed', has_error: true })).toBe('执行失败');
        expect(expRunSummaryText({ status: 'Succeeded', has_error: false }, 'Rejected')).toBe('已拒绝');
    });
});
