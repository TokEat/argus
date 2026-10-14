export type ResultTabKey = 'vulns' | 'assets' | 'fingerprints' | 'content';
export type ResultPageState = { current: number; pageSize: number; total: number };

export const DEFAULT_RESULT_PAGE_SIZE = 20;
export const initialResultPageState: ResultPageState = { current: 1, pageSize: DEFAULT_RESULT_PAGE_SIZE, total: 0 };

export function firstNonEmptyResultTab(vulnerabilities: number, assets: number, fingerprints: number, contentFindings: number = 0): ResultTabKey {
    if (vulnerabilities > 0) return 'vulns';
    if (assets > 0) return 'assets';
    if (fingerprints > 0) return 'fingerprints';
    if (contentFindings > 0) return 'content';
    return 'vulns';
}
