import { describe, expect, it } from 'vitest';
import {
    parseProjectDataState,
    toSearchParams,
    updateProjectDataState,
} from './projectDataState';

describe('projectDataState', () => {
    it('parses defaults for empty params', () => {
        expect(parseProjectDataState(new URLSearchParams())).toEqual({
            tab: 'assets',
            page: 1,
            pageSize: 20,
            sort: undefined,
            order: undefined,
            search: undefined,
            kind: undefined,
            severity: undefined,
            source: undefined,
        });
    });

    it('round-trips a non-default state through the URL', () => {
        const state = parseProjectDataState(new URLSearchParams(
            'tab=vulns&page=3&pageSize=50&sort=severity&order=desc&search=sqli&severity=!info',
        ));
        expect(state).toEqual({
            tab: 'vulns',
            page: 3,
            pageSize: 50,
            sort: 'severity',
            order: 'desc',
            search: 'sqli',
            kind: undefined,
            severity: '!info',
            source: undefined,
        });
        const sp = toSearchParams(state);
        expect(parseProjectDataState(sp)).toEqual(state);
    });

    it('falls back on invalid values', () => {
        const state = parseProjectDataState(new URLSearchParams('tab=nope&page=0&pageSize=9999&order=sideways'));
        expect(state.tab).toBe('assets');
        expect(state.page).toBe(1);
        expect(state.pageSize).toBe(20);
        expect(state.order).toBeUndefined();
    });

    it('omits defaults from the URL string', () => {
        const sp = toSearchParams({ tab: 'assets', page: 1, pageSize: 20 });
        expect(sp.toString()).toBe('');
    });

    it('resets page to 1 on tab/filter/sort changes but keeps it on paging', () => {
        const base = parseProjectDataState(new URLSearchParams('page=4'));
        expect(updateProjectDataState(base, { page: 5 }).page).toBe(5);
        expect(updateProjectDataState(base, { pageSize: 50 }).page).toBe(4);
        expect(updateProjectDataState(base, { tab: 'vulns' }).page).toBe(1);
        expect(updateProjectDataState(base, { search: 'x' }).page).toBe(1);
        expect(updateProjectDataState(base, { sort: 'severity', order: 'desc' }).page).toBe(1);
        expect(updateProjectDataState(base, { severity: 'info' }).page).toBe(1);
    });

    it('clears order when sort is cleared', () => {
        const sorted = parseProjectDataState(new URLSearchParams('sort=severity&order=desc'));
        expect(updateProjectDataState(sorted, { sort: undefined }).order).toBeUndefined();
    });
});
