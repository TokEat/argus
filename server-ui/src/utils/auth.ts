export type UserRole = 'viewer' | 'operator' | 'admin';

export const roleLevel: Record<UserRole, number> = {
    viewer: 1,
    operator: 2,
    admin: 3,
};

export const roleLabel: Record<UserRole, string> = {
    viewer: '观察者',
    operator: '操作员',
    admin: '管理员',
};

export const normalizeRole = (role?: string | null): UserRole => {
    if (role === 'admin' || role === 'operator' || role === 'viewer') return role;
    return 'viewer';
};

export const getTokenClaims = (): Record<string, unknown> => {
    const token = localStorage.getItem('token') || '';
    const payload = token.split('.')[1];
    if (!payload) return {};
    try {
        const normalized = payload.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(payload.length / 4) * 4, '=');
        const json = decodeURIComponent(Array.prototype.map.call(atob(normalized), (c: string) =>
            `%${(`00${c.charCodeAt(0).toString(16)}`).slice(-2)}`
        ).join(''));
        return JSON.parse(json);
    } catch {
        return {};
    }
};

export const getTokenClaim = (key: string): string => {
    const value = getTokenClaims()[key];
    return typeof value === 'string' ? value : '';
};

export const getCurrentUserRole = (): UserRole => {
    const role = normalizeRole(getTokenClaim('role'));
    if (role !== 'viewer' || getTokenClaim('role') === 'viewer') return role;
    return normalizeRole(getTokenClaim('role_base'));
};

export const canAccessRole = (minRole: UserRole = 'viewer', role: string | UserRole = getCurrentUserRole()): boolean => {
    return roleLevel[normalizeRole(role)] >= roleLevel[minRole];
};
