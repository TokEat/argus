import { describe, expect, it } from 'vitest';
import {
    assetMatchesKind,
    fingerprintGroupSources,
    firstNonEmptyAssetKind,
    firstNonEmptyResultTab,
    visibleAssetKinds,
} from './taskResultTabs';

describe('taskResultTabs', () => {
    it('prefers vulnerabilities, then assets, then fingerprints', () => {
        expect(firstNonEmptyResultTab(1, 9, 9)).toBe('vulns');
        expect(firstNonEmptyResultTab(0, 2, 9)).toBe('assets');
        expect(firstNonEmptyResultTab(0, 0, 1)).toBe('fingerprints');
        expect(firstNonEmptyResultTab(0, 0, 0)).toBe('vulns');
    });

    it('hides empty asset kinds and keeps 其他 only when needed', () => {
        expect(visibleAssetKinds({ web: 0, host_port: 3, domain: 0, resolution: 1, other: 0 })).toEqual([
            'host_port',
            'resolution',
        ]);
        expect(visibleAssetKinds({ web: 0, host_port: 0, domain: 0, resolution: 0, other: 2 })).toEqual(['other']);
        expect(visibleAssetKinds(emptyZero)).toEqual(['web']);
    });

    it('picks the first non-empty asset kind in display order', () => {
        expect(firstNonEmptyAssetKind({ web: 0, host_port: 0, domain: 4, resolution: 1 })).toBe('domain');
        expect(firstNonEmptyAssetKind({ web: 2, host_port: 9 })).toBe('web');
    });

    it('matches historical Protocol values to display groups', () => {
        expect(assetMatchesKind('Web', 'web')).toBe(true);
        expect(assetMatchesKind('PortScan', 'web')).toBe(false);
        expect(assetMatchesKind('PortScan', 'host_port')).toBe(true);
        expect(assetMatchesKind('IPAlive', 'host_port')).toBe(false);
        expect(assetMatchesKind('IPAlive', 'other')).toBe(true);
        expect(assetMatchesKind('DNS-SubFinder', 'domain')).toBe(true);
        expect(assetMatchesKind('RealIP', 'resolution')).toBe(true);
        expect(assetMatchesKind('https', 'other')).toBe(true);
    });

    it('orders fingerprint sources with directory-scan first', () => {
        expect(fingerprintGroupSources({
            Targets: [
                { Source: 'passive' },
                { Source: 'directory' },
                { Source: 'fallback' },
            ],
        })).toEqual(['directory', 'fallback', 'passive']);
    });
});

const emptyZero = { web: 0, host_port: 0, domain: 0, resolution: 0, other: 0 };
