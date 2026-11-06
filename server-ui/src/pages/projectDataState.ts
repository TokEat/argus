import { DEFAULT_RESULT_PAGE_SIZE } from './taskResultTabs';

// 「项目数据」浏览页的路由状态：所有分页/排序/筛选状态都写进 URL 查询参数，
// 由 useEffect 监听 searchParams 触发拉取，从根本上避免“翻页/筛选后退回第一页”的状态重置 bug。

export type ProjectDataTab = 'assets' | 'vulns' | 'fingerprints' | 'domains';

export interface ProjectDataState {
    tab: ProjectDataTab;
    page: number;
    pageSize: number;
    sort?: string;
    order?: 'asc' | 'desc';
    search?: string;
    kind?: string;
    severity?: string;
    source?: string;
}

export const PROJECT_DATA_TABS: ProjectDataTab[] = ['assets', 'vulns', 'fingerprints', 'domains'];

export const PROJECT_DATA_TAB_LABELS: Record<ProjectDataTab, string> = {
    assets: '资产',
    vulns: '漏洞',
    fingerprints: '指纹',
    domains: '域名',
};

const DEFAULT_STATE: ProjectDataState = { tab: 'assets', page: 1, pageSize: DEFAULT_RESULT_PAGE_SIZE };

const PAGE_SIZE_MIN = 10;
const PAGE_SIZE_MAX = 200;

function isTab(value: string | null): value is ProjectDataTab {
    return value === 'assets' || value === 'vulns' || value === 'fingerprints' || value === 'domains';
}

function parsePage(raw: string | null): number {
    const n = parseInt(raw || '', 10);
    return Number.isFinite(n) && n >= 1 ? n : 1;
}

function parsePageSize(raw: string | null): number {
    const n = parseInt(raw || '', 10);
    if (!Number.isFinite(n) || n < PAGE_SIZE_MIN || n > PAGE_SIZE_MAX) return DEFAULT_RESULT_PAGE_SIZE;
    return n;
}

export function parseProjectDataState(sp: URLSearchParams): ProjectDataState {
    const tabParam = sp.get('tab');
    const sort = sp.get('sort') || undefined;
    const orderParam = sp.get('order');
    return {
        tab: isTab(tabParam) ? tabParam : DEFAULT_STATE.tab,
        page: parsePage(sp.get('page')),
        pageSize: parsePageSize(sp.get('pageSize')),
        sort: sort || undefined,
        order: orderParam === 'asc' || orderParam === 'desc' ? orderParam : undefined,
        search: sp.get('search') || undefined,
        kind: sp.get('kind') || undefined,
        severity: sp.get('severity') || undefined,
        source: sp.get('source') || undefined,
    };
}

export function toSearchParams(s: ProjectDataState): URLSearchParams {
    const sp = new URLSearchParams();
    if (s.tab !== DEFAULT_STATE.tab) sp.set('tab', s.tab);
    if (s.page !== DEFAULT_STATE.page) sp.set('page', String(s.page));
    if (s.pageSize !== DEFAULT_STATE.pageSize) sp.set('pageSize', String(s.pageSize));
    if (s.sort) sp.set('sort', s.sort);
    if (s.order) sp.set('order', s.order);
    if (s.search) sp.set('search', s.search);
    if (s.kind) sp.set('kind', s.kind);
    if (s.severity) sp.set('severity', s.severity);
    if (s.source) sp.set('source', s.source);
    return sp;
}

// 变更 tab / 任意筛选 / 排序时把 page 归 1；仅翻页（page/pageSize）时保留当前页。
export function updateProjectDataState(cur: ProjectDataState, patch: Partial<ProjectDataState>): ProjectDataState {
    const next: ProjectDataState = { ...cur, ...patch };
    const onlyPaging =
        Object.keys(patch).every((key) => key === 'page' || key === 'pageSize');
    next.page = onlyPaging ? Math.max(1, next.page) : 1;
    if (!next.sort) next.order = undefined;
    return next;
}
