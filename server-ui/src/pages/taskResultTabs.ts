export type ResultTabKey = 'vulns' | 'assets' | 'fingerprints';
export type AssetKind = 'web' | 'host_port' | 'domain' | 'resolution' | 'other';
export type ResultPageState = { current: number; pageSize: number; total: number };

export const DEFAULT_RESULT_PAGE_SIZE = 20;
export const initialResultPageState: ResultPageState = { current: 1, pageSize: DEFAULT_RESULT_PAGE_SIZE, total: 0 };

export const ASSET_KIND_ORDER: AssetKind[] = ['web', 'host_port', 'domain', 'resolution'];

export const ASSET_KIND_LABELS: Record<AssetKind, string> = {
    web: 'Web 站点',
    host_port: '主机与端口',
    domain: '域名',
    resolution: '解析关系',
    other: '其他',
};

export const ASSET_KIND_PROTOCOLS: Record<Exclude<AssetKind, 'other'>, string[]> = {
    web: ['Web', 'Domain-Bind'],
    host_port: ['PortScan', 'Protocol', 'ProtocolCheck', 'Nmap', 'IPAlive', 'Fofa', 'Hunter', 'Quake'],
    domain: ['Domain', 'DNS-SubFinder', 'DNS-Brute', 'CDN-Domain'],
    resolution: ['RealIP'],
};

const knownAssetProtocols = new Set(ASSET_KIND_ORDER.flatMap((kind) => ASSET_KIND_PROTOCOLS[kind]));

export function assetMatchesKind(protocol: string, kind: AssetKind): boolean {
    if (kind === 'other') {
        return !knownAssetProtocols.has(protocol);
    }
    return ASSET_KIND_PROTOCOLS[kind].includes(protocol);
}

export const emptyAssetKindCounts = (): Record<AssetKind, number> => ({
    web: 0,
    host_port: 0,
    domain: 0,
    resolution: 0,
    other: 0,
});

export function firstNonEmptyResultTab(vulnerabilities: number, assets: number, fingerprints: number): ResultTabKey {
    if (vulnerabilities > 0) return 'vulns';
    if (assets > 0) return 'assets';
    if (fingerprints > 0) return 'fingerprints';
    return 'vulns';
}

export function visibleAssetKinds(counts: Partial<Record<AssetKind, number>> | undefined): AssetKind[] {
    const visible = ASSET_KIND_ORDER.filter((kind) => (counts?.[kind] || 0) > 0);
    if ((counts?.other || 0) > 0) {
        visible.push('other');
    }
    return visible.length > 0 ? visible : ['web'];
}

export function firstNonEmptyAssetKind(counts: Partial<Record<AssetKind, number>> | undefined): AssetKind {
    return visibleAssetKinds(counts)[0] || 'web';
}

export function assetKindCount(counts: Partial<Record<AssetKind, number>> | undefined, kind: AssetKind): number {
    return counts?.[kind] || 0;
}
