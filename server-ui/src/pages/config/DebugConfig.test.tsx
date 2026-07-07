import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { App } from 'antd';
import DebugConfig from './DebugConfig';
import { debugFingerprint } from '../../services/api';

const wsMock = vi.hoisted(() => ({
    callbacks: [] as ((data: unknown) => void)[],
}));

vi.mock('@monaco-editor/react', () => ({
    default: () => <div data-testid="monaco-editor" />,
}));

vi.mock('../../services/api', () => ({
    getFingerprintDict: vi.fn().mockResolvedValue([{
        product: 'OnlyOne',
        rules: ['body="only-one"', 'title="OnlyOne"', '  ', 'header="only-one" || cert="only-one"'],
    }]),
    getWorkflowDict: vi.fn().mockResolvedValue([]),
    getDirDict: vi.fn().mockResolvedValue([]),
    listArsenals: vi.fn().mockResolvedValue([]),
    getNodes: vi.fn().mockResolvedValue([
        { AgentID: 'agent-1', Status: 'Alive', Version: 'v2.3.0' },
    ]),
    connectWebSocket: vi.fn((callback: (data: unknown) => void) => {
        wsMock.callbacks.push(callback);
        return { close: vi.fn() };
    }),
    debugFingerprint: vi.fn().mockResolvedValue({ session_id: 'debug-1', status: 'started' }),
    cancelDebugSession: vi.fn().mockResolvedValue({ status: 'cancelled' }),
}));

describe('DebugConfig', () => {
    beforeEach(() => {
        wsMock.callbacks = [];
        vi.mocked(debugFingerprint).mockResolvedValue({ session_id: 'debug-1', status: 'started' });
    });

    it('renders separate workflow and single fingerprint debug panels', async () => {
        render(
            <App>
                <DebugConfig />
            </App>,
        );

        await waitFor(() => expect(screen.getByText('Workflow 规则调试')).toBeInTheDocument());
        expect(screen.getByText('Finger 规则调试')).toBeInTheDocument();
        expect(screen.getByLabelText('指纹规则')).toBeInTheDocument();
    });

    it('starts finger debug with only a fingerprint rule', async () => {
        const user = userEvent.setup();
        render(
            <App>
                <DebugConfig />
            </App>,
        );

        await waitFor(() => expect(screen.getByText('Finger 规则调试')).toBeInTheDocument());
        await waitFor(() => expect(screen.getAllByText(/agent-1/).length).toBeGreaterThan(0));

        const ruleInput = screen.getByTestId('finger-debug-rule');
        expect(ruleInput.tagName).toBe('TEXTAREA');
        await user.type(ruleInput, '  body="only-one"  {enter}{enter}  && title="OnlyOne"  ');
        await user.click(screen.getAllByRole('button', { name: /开始调试/i })[0]);

        await waitFor(() => expect(debugFingerprint).toHaveBeenCalled());
        expect(debugFingerprint).toHaveBeenLastCalledWith(expect.objectContaining({
            custom_only: true,
            custom_rule: 'body="only-one"\n&& title="OnlyOne"',
        }));
        expect(debugFingerprint).toHaveBeenLastCalledWith(expect.not.objectContaining({
            custom_rules: expect.any(Array),
        }));
        expect(debugFingerprint).toHaveBeenLastCalledWith(expect.not.objectContaining({
            custom_product: expect.any(String),
        }));
    });

    it('starts workflow debug with a specified fingerprint only', async () => {
        const user = userEvent.setup();
        render(
            <App>
                <DebugConfig />
            </App>,
        );

        await waitFor(() => expect(screen.getByText('Workflow 规则调试')).toBeInTheDocument());
        await waitFor(() => expect(screen.getAllByText(/agent-1/).length).toBeGreaterThan(0));

        await user.type(screen.getByTestId('workflow-fingerprint-product'), 'OnlyOne');
        const ruleInput = screen.getByTestId('workflow-fingerprint-rule');
        expect(ruleInput.tagName).toBe('TEXTAREA');
        await user.type(ruleInput, 'body="only-one"');
        await user.click(screen.getAllByRole('button', { name: /开始调试/i })[1]);

        await waitFor(() => expect(debugFingerprint).toHaveBeenCalled());
        expect(debugFingerprint).toHaveBeenLastCalledWith(expect.objectContaining({
            custom_only: true,
            custom_product: 'OnlyOne',
            custom_rule: 'body="only-one"',
        }));
        expect(debugFingerprint).toHaveBeenLastCalledWith(expect.not.objectContaining({
            custom_rules: expect.any(Array),
        }));
    });

    it('fills all fingerprint rules when selecting a product for finger debug', async () => {
        const user = userEvent.setup();
        render(
            <App>
                <DebugConfig />
            </App>,
        );

        await waitFor(() => expect(screen.getByText('Finger 规则调试')).toBeInTheDocument());
        await waitFor(() => expect(screen.getAllByText(/agent-1/).length).toBeGreaterThan(0));

        const productSelect = screen.getByTestId('finger-debug-product');
        fireEvent.mouseDown(productSelect.querySelector('[role="combobox"]') as HTMLElement);
        const optionContent = await screen.findByText('OnlyOne', { selector: '.ant-select-item-option-content' });
        fireEvent.click(optionContent.closest('.ant-select-item-option') as HTMLElement);

        const ruleInput = screen.getByTestId('finger-debug-rule');
        await waitFor(() => expect(ruleInput).toHaveValue('body="only-one"\ntitle="OnlyOne"\n  \nheader="only-one" || cert="only-one"'));

        await user.click(screen.getAllByRole('button', { name: /开始调试/i })[0]);

        await waitFor(() => expect(debugFingerprint).toHaveBeenCalled());
        expect(debugFingerprint).toHaveBeenLastCalledWith(expect.objectContaining({
            custom_only: true,
            custom_product: 'OnlyOne',
            custom_rule: 'body="only-one"\ntitle="OnlyOne"\nheader="only-one" || cert="only-one"',
            custom_rules: ['body="only-one"', 'title="OnlyOne"', 'header="only-one" || cert="only-one"'],
        }));
    });

    it('shows a fingerprint result that arrives before the start request resolves', async () => {
        const user = userEvent.setup();
        let resolveDebug!: (value: { session_id: string; status: string }) => void;
        vi.mocked(debugFingerprint).mockImplementationOnce(() => new Promise((resolve) => {
            resolveDebug = resolve;
        }));

        render(
            <App>
                <DebugConfig />
            </App>,
        );

        await waitFor(() => expect(screen.getByText('Finger 规则调试')).toBeInTheDocument());
        await user.type(screen.getByTestId('finger-debug-rule'), 'body="only-one"');
        await user.click(screen.getAllByRole('button', { name: /开始调试/i })[0]);

        await waitFor(() => expect(debugFingerprint).toHaveBeenCalled());
        act(() => {
            wsMock.callbacks.forEach((callback) => callback({
                type: 'debug_result',
                session_id: 'debug-early',
                timestamp: Date.now(),
                matched: true,
                template_id: 'Finger',
                matched_at: 'https://target.local/',
                extracted: ['[custom]DebugFingerprint'],
            }));
        });

        await act(async () => {
            resolveDebug({ session_id: 'debug-early', status: 'started' });
        });

        expect(await screen.findByText(/DebugFingerprint/)).toBeInTheDocument();
    });
});
