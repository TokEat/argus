export const DEFAULT_SOURCE = `target = cli.String("target", cli.setVerboseName("目标地址"), cli.setRequired(true))
cli.check()

yaksha.result({
    "vulnerable": false,
    "target": target,
})
`;

export const jsonText = (value: unknown) => JSON.stringify(value, null, 2);
export const editorSource = (value: string) => value.replace(/\r\n?/g, '\n');
export const NETWORK_CALL_PATTERN = /\byaksha\s*\.\s*(?:httpRequest|httpGet|tcpExchange|dial)\s*\(/;
export const LITERAL_NETWORK_TARGET_PATTERN = /\b(?:https?|tcp):\/\/[^\s"'`<>]+/g;

export const normalizeNetworkTarget = (value: unknown): string | null => {
    if (typeof value !== 'string' || !value.trim()) return null;
    const raw = value.trim();
    const candidate = raw.includes('://') ? raw : `tcp://${raw}`;
    try {
        const parsed = new URL(candidate);
        if (!['http:', 'https:', 'tcp:'].includes(parsed.protocol) || !parsed.hostname) return null;
        const port = parsed.port || (parsed.protocol === 'http:' ? '80' : parsed.protocol === 'https:' ? '443' : '');
        if (!port) return null;
        const host = parsed.hostname.includes(':') ? `[${parsed.hostname.replace(/^\[|\]$/g, '')}]` : parsed.hostname;
        return `${parsed.protocol}//${host}:${port}`;
    } catch {
        return null;
    }
};

export const networkTargetFromCLIValue = (field: API.ExpCLIParam, value: unknown): string | null => {
    if (field.input_type === 'host_port' && typeof value === 'string') return normalizeNetworkTarget(`tcp://${value}`);
    if (field.input_type === 'url') return normalizeNetworkTarget(value);
    return null;
};

export const errorMessage = (error: unknown) => error instanceof Error ? error.message : String(error || '操作失败');

export const editableTestCase = (item: API.ExpTestCase | API.ExpTestCaseInput): API.ExpTestCaseInput => ({
    name: item.name,
    params: item.params,
    fixture: item.fixture,
    expect: item.expect,
    enabled: item.enabled,
});

export const packageFingerprint = (
    source: string,
    dependencies: API.ExpDependencyRef[],
    assets: API.ExpAssetRef[],
    testCases: Array<API.ExpTestCase | API.ExpTestCaseInput>,
) => jsonText({
    source,
    dependencies,
    assets,
    test_cases: testCases.map(editableTestCase),
});
