import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { App } from 'antd';
import { MemoryRouter } from 'react-router-dom';
import Login from './Login';

vi.mock('gsap', () => ({
    default: {
        context: (_fn: () => void) => ({ revert: vi.fn() }),
        fromTo: vi.fn(),
        to: vi.fn(),
        timeline: () => ({ fromTo: vi.fn().mockReturnThis(), to: vi.fn().mockReturnThis() }),
    },
}));

vi.mock('../components/NetworkCanvas', () => ({
    default: () => <div data-testid="network-canvas" />,
}));

describe('Login', () => {
    it('renders the login form controls', () => {
        render(
            <MemoryRouter>
                <App>
                    <Login />
                </App>
            </MemoryRouter>
        );

        expect(screen.getByPlaceholderText('租户 ID')).toBeInTheDocument();
        expect(screen.getByPlaceholderText('密码')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /登\s*录/i })).toBeInTheDocument();
    });
});
