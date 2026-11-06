export type ResultTabKey = 'vulns' | 'assets' | 'fingerprints' | 'content';
export type AssetKind = 'web' | 'host_port' | 'domain' | 'resolution' | 'other';
export type ResultPageState = { current: number; pageSize: number; total: number };

export const DEFAULT_RESULT_PAGE_SIZE = 20;
export const initialResultPageState: ResultPageState = { current: 1, pageSize: DEFAULT_RESULT_PAGE_SIZE, total: 0 };

export const ASSET_KIND_ORDER: Array<Exclude<AssetKind, 'other'>> = ['web', 'host_port', 'domain', 'resolution'];

export const ASSET_KIND_LABELS: Record<AssetKind, string> = {
    web: 'Web 站点',
    host_port: '主机与端口',
    domain: '域名',
    resolution: '解析关系',
    other: '其他',
};

export const ASSET_KIND_PROTOCOLS: Record<Exclude<AssetKind, 'other'>, string[]> = {
    web: ['Web', 'Domain-Bind'],
    host_port: ['PortScan', 'Protocol', 'ProtocolCheck', 'Nmap', 'Fofa', 'Hunter', 'Quake'],
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

export function firstNonEmptyResultTab(vulnerabilities: number, assets: number, fingerprints: number, contentFindings: number = 0): ResultTabKey {
    if (vulnerabilities > 0) return 'vulns';
    if (assets > 0) return 'assets';
    if (fingerprints > 0) return 'fingerprints';
    if (contentFindings > 0) return 'content';
    return 'vulns';
}

export function visibleAssetKinds(counts: Partial<Record<AssetKind, number>> | undefined): AssetKind[] {
    const visible: AssetKind[] = ASSET_KIND_ORDER.filter((kind) => (counts?.[kind] || 0) > 0);
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

export type FingerprintSource = 'passive' | 'directory' | 'behavior' | 'fallback';

export const FINGERPRINT_SOURCE_LABELS: Record<FingerprintSource, string> = {
    passive: '被动命中',
    directory: '主动路径',
    behavior: '行为探针',
    fallback: '路径推断',
};

export const FINGERPRINT_SOURCE_COLORS: Record<FingerprintSource, string> = {
    passive: 'default',
    directory: 'magenta',
    behavior: 'purple',
    fallback: 'orange',
};

export const FINGERPRINT_SOURCE_FILTERS: Array<{ value: '' | FingerprintSource; label: string }> = [
    { value: '', label: '全部来源' },
    { value: 'directory', label: FINGERPRINT_SOURCE_LABELS.directory },
    { value: 'passive', label: FINGERPRINT_SOURCE_LABELS.passive },
    { value: 'behavior', label: FINGERPRINT_SOURCE_LABELS.behavior },
    { value: 'fallback', label: FINGERPRINT_SOURCE_LABELS.fallback },
];

export function isFingerprintSource(value: string | undefined): value is FingerprintSource {
    return value === 'passive' || value === 'directory' || value === 'behavior' || value === 'fallback';
}

export function fingerprintSourceLabel(source?: string, fallback?: string): string {
    if (fallback) return fallback;
    if (isFingerprintSource(source)) return FINGERPRINT_SOURCE_LABELS[source];
    return source || FINGERPRINT_SOURCE_LABELS.passive;
}

export function fingerprintSourceColor(source?: string): string {
    if (isFingerprintSource(source)) return FINGERPRINT_SOURCE_COLORS[source];
    return 'default';
}

export function fingerprintGroupSources(group: { Sources?: string[]; Targets?: Array<{ Source?: string }> }): FingerprintSource[] {
    const raw = group.Sources?.length
        ? group.Sources
        : (group.Targets || []).map((target) => target.Source).filter((source): source is string => Boolean(source));
    const unique: FingerprintSource[] = [];
    (['directory', 'behavior', 'fallback', 'passive'] as FingerprintSource[]).forEach((source) => {
        if (raw.includes(source) && !unique.includes(source)) unique.push(source);
    });
    return unique;
}
