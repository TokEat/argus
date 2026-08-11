export interface AssetDiscoverySyntaxField {
    name: string;
    description: string;
}

export interface AssetDiscoverySyntaxExample {
    expression: string;
    description: string;
}

export interface AssetDiscoverySyntaxCatalog {
    providerLabel: string;
    helpUrl: string;
    grammar: string;
    fieldOperator: '=' | ':';
    defaultJoin: '&&' | 'AND';
    operators: { token: string; description: string }[];
    fields: AssetDiscoverySyntaxField[];
    examples: AssetDiscoverySyntaxExample[];
}

export interface AssetDiscoveryCompletion {
    field: AssetDiscoverySyntaxField;
    value: string;
}

export const assetDiscoverySyntaxCatalog: Record<API.AssetDiscoveryProvider, AssetDiscoverySyntaxCatalog> = {
    fofa: {
        providerLabel: 'FOFA',
        helpUrl: 'https://fofa.info/api',
        grammar: '使用 field="value"；可用 &&、|| 组合条件。= 为匹配，== 为完全匹配，!= 为排除。',
        fieldOperator: '=',
        defaultJoin: '&&',
        operators: [
            { token: '=', description: '匹配' },
            { token: '==', description: '完全匹配' },
            { token: '!=', description: '排除' },
            { token: '&&', description: '并且' },
            { token: '||', description: '或者' },
        ],
        fields: [
            { name: 'ip', description: 'IP 或 CIDR' },
            { name: 'port', description: '端口' },
            { name: 'protocol', description: '应用层协议' },
            { name: 'domain', description: '域名' },
            { name: 'host', description: '主机名或 URL 主机' },
            { name: 'title', description: '网页标题' },
            { name: 'body', description: '网页正文（商业版）' },
            { name: 'header', description: 'HTTP 响应头' },
            { name: 'server', description: 'Server 响应头' },
            { name: 'status_code', description: 'HTTP 状态码' },
            { name: 'country', description: '国家代码' },
            { name: 'city', description: '城市' },
            { name: 'asn', description: '自治系统编号' },
            { name: 'org', description: '组织' },
        ],
        examples: [
            { expression: 'domain="example.invalid"', description: '按域名查询' },
            { expression: 'ip="192.0.2.10"', description: '按 IP 查询' },
            { expression: 'protocol="https" && port="443"', description: '组合协议和端口' },
        ],
    },
    hunter: {
        providerLabel: 'Hunter',
        helpUrl: 'https://hunter.qianxin.com/home/helpCenter',
        grammar: '使用 field="value"；用 && 表示并且、|| 表示或者。字段与可见数据受 Hunter 账号权限影响。',
        fieldOperator: '=',
        defaultJoin: '&&',
        operators: [
            { token: '=', description: '匹配' },
            { token: '&&', description: '并且' },
            { token: '||', description: '或者' },
        ],
        fields: [
            { name: 'ip', description: 'IP 或 CIDR' },
            { name: 'ip.port', description: '端口' },
            { name: 'domain', description: '完整域名' },
            { name: 'domain.suffix', description: '域名后缀' },
            { name: 'protocol', description: '应用层协议' },
            { name: 'web.title', description: '网页标题' },
            { name: 'web.body', description: '网页正文' },
            { name: 'header', description: 'HTTP 响应头' },
            { name: 'header.status_code', description: 'HTTP 状态码' },
            { name: 'product.name', description: '产品名称' },
            { name: 'ip.country', description: '国家代码' },
            { name: 'ip.province', description: '省份' },
            { name: 'ip.city', description: '城市' },
        ],
        examples: [
            { expression: 'domain.suffix="example.invalid"', description: '按域名后缀查询' },
            { expression: 'ip="192.0.2.10"', description: '按 IP 查询' },
            { expression: 'web.title="Argus" && protocol="http"', description: '组合标题和协议' },
        ],
    },
    quake: {
        providerLabel: 'Quake',
        helpUrl: 'https://quake.360.net/quake/#/help',
        grammar: '使用 field:"value"（数字可不加引号）；用 AND、OR、NOT 组合条件。',
        fieldOperator: ':',
        defaultJoin: 'AND',
        operators: [
            { token: ':', description: '字段匹配' },
            { token: 'AND', description: '并且' },
            { token: 'OR', description: '或者' },
            { token: 'NOT', description: '排除' },
        ],
        fields: [
            { name: 'ip', description: 'IP 或 CIDR' },
            { name: 'port', description: '端口' },
            { name: 'domain', description: '域名' },
            { name: 'service', description: '服务协议' },
            { name: 'service.name', description: '服务名称' },
            { name: 'service.http.host', description: 'HTTP Host' },
            { name: 'service.http.title', description: '网页标题' },
        ],
        examples: [
            { expression: 'domain:"example.invalid"', description: '按域名查询' },
            { expression: 'ip:"192.0.2.10"', description: '按 IP 查询' },
            { expression: 'service:"http" AND port:443', description: '组合服务和端口' },
        ],
    },
};

const completionTokenPattern = /([a-z][a-z0-9_.]*)$/i;

const isInsideQuotedValue = (expression: string): boolean => {
    let quote: '"' | "'" | null = null;
    let escaped = false;

    for (const character of expression) {
        if (escaped) {
            escaped = false;
            continue;
        }
        if (character === '\\') {
            escaped = true;
            continue;
        }
        if (quote) {
            if (character === quote) quote = null;
            continue;
        }
        if (character === '"' || character === "'") quote = character;
    }

    return quote !== null;
};

const canStartField = (
    catalog: AssetDiscoverySyntaxCatalog,
    expression: string,
    tokenStart: number,
): boolean => {
    const beforeToken = expression.slice(0, tokenStart).trimEnd();
    if (!beforeToken) return true;
    if (beforeToken.endsWith('(')) return true;
    if (catalog.defaultJoin === '&&') {
        return beforeToken.endsWith('&&') || beforeToken.endsWith('||');
    }
    return /(?:^|\s)(?:AND|OR|NOT)$/i.test(beforeToken);
};

export const getAssetDiscoveryCompletions = (
    provider: API.AssetDiscoveryProvider,
    expression: string,
): AssetDiscoveryCompletion[] => {
    const catalog = assetDiscoverySyntaxCatalog[provider];
    if (isInsideQuotedValue(expression)) return [];

    const match = expression.match(completionTokenPattern);
    if (!match && expression) return [];

    const token = (match?.[0] || '').toLowerCase();
    const tokenStart = expression.length - token.length;
    if (!canStartField(catalog, expression, tokenStart)) return [];

    return catalog.fields
        .filter((field) => field.name.toLowerCase().startsWith(token))
        .slice(0, 8)
        .map((field) => ({
            field,
            value: `${expression.slice(0, tokenStart)}${field.name}${catalog.fieldOperator}`,
        }));
};

export const appendAssetDiscoveryField = (
    provider: API.AssetDiscoveryProvider,
    expression: string,
    fieldName: string,
): string => {
    const catalog = assetDiscoverySyntaxCatalog[provider];
    const current = expression.trimEnd();
    const prefix = current ? `${current} ${catalog.defaultJoin} ` : '';
    return `${prefix}${fieldName}${catalog.fieldOperator}`;
};
