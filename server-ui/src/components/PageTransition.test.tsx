import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Link, MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import PageTransition from './PageTransition';

describe('PageTransition', () => {
    it('remounts the animated page container when the route changes', async () => {
        const user = userEvent.setup();
        const { container } = render(
            <MemoryRouter initialEntries={['/first']}>
                <Link to="/second">切换页面</Link>
                <Routes>
                    <Route path="*" element={<PageTransition><div>页面内容</div></PageTransition>} />
                </Routes>
            </MemoryRouter>,
        );
        const firstContainer = container.querySelector('.page-container');
        expect(firstContainer).not.toBeNull();

        await user.click(screen.getByRole('link', { name: '切换页面' }));
        await waitFor(() => expect(container.querySelector('.page-container')).not.toBe(firstContainer));
        expect(screen.getByText('页面内容')).toBeInTheDocument();
    });
});
