import { describe, expect, it } from 'vitest';
import { menuRoutes, type RouteConfig } from './routes';

const flattenRoutes = (routes: RouteConfig[]): RouteConfig[] => (
    routes.flatMap((route) => [route, ...flattenRoutes(route.children ?? [])])
);

describe('route permissions', () => {
    const routes = flattenRoutes(menuRoutes);

    it('requires admin for the arsenal menu and every config route', () => {
        const configRoutes = routes.filter((route) => route.path === '/config' || route.path.startsWith('/config/'));
        expect(configRoutes.map((route) => route.path)).toEqual(expect.arrayContaining([
            '/config',
            '/config/workflow',
            '/config/poc',
            '/config/active-finger',
            '/config/dir',
            '/config/exploit',
            '/config/debug',
        ]));
        expect(configRoutes.every((route) => route.minRole === 'admin')).toBe(true);
    });

    it('requires admin for MCP management', () => {
        expect(routes.find((route) => route.path === '/mcp-admin')?.minRole).toBe('admin');
        expect(routes.find((route) => route.path === '/mcp-admin')?.name).toBe('MCP 管理');
    });

    it('does not raise unrelated task and project pages above viewer', () => {
        expect(routes.find((route) => route.path === '/tasks')?.minRole).toBe('viewer');
        expect(routes.find((route) => route.path === '/projects')?.minRole).toBe('viewer');
    });
});
