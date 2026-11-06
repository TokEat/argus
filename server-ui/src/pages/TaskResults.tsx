import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Alert, Typography, Tag, Tabs, Space, Spin, Button, Tooltip, Empty, Drawer, Descriptions, Divider, Popover, Input, Select, Steps, App } from 'antd';
import { ProCard } from '@ant-design/pro-components';
import {
    BugOutlined,
    GlobalOutlined,
    ScanOutlined,
    DownloadOutlined,
    ArrowLeftOutlined,
    ReloadOutlined,
    SendOutlined,
    CloudDownloadOutlined,
    LinkOutlined,
    PartitionOutlined,
    NodeIndexOutlined,
    FileTextOutlined,
    LockOutlined,
    MinusCircleOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import { useNavigate, useParams } from 'react-router-dom';
import { getVulns, getVulnFacets, getAssets, getAssetFacets, getFingerprintGroups, getAssetLineage, exportVulns, exportAssets, exportFingerprints, listCrawlSiteCandidates, listSensitiveFindings, revealCredentialFinding } from '../services/api';
import { getCurrentUserRole } from '../utils/auth';
import { useAutoContext } from '../contexts/GlobalAIContext';
import { AIVerdictTag } from '../components/VulnAITriagePanel';
import VulnAITriagePanel from '../components/VulnAITriagePanel';
import ContentFindingsPanel from '../components/tasks/ContentFindingsPanel';
import ResultTable from '../components/tasks/ResultTable';
import {
    ASSET_KIND_LABELS,
    DEFAULT_RESULT_PAGE_SIZE,
    FINGERPRINT_SOURCE_FILTERS,
    assetKindCount,
    assetMatchesKind,
    emptyAssetKindCounts,
    fingerprintGroupSources,
    fingerprintSourceColor,
    fingerprintSourceLabel,
    firstNonEmptyAssetKind,
    firstNonEmptyResultTab,
    initialResultPageState,
    visibleAssetKinds,
    type AssetKind,
    type FingerprintSource,
    type ResultPageState,
    type ResultTabKey,
} from './taskResultTabs';
import dayjs from 'dayjs';

const { Title, Text } = Typography;

// 漏洞表列 dataIndex → 服务端排序字段（getVulns 排序白名单）。未命中的列不传 sort，
// 由服务端回退默认排序；排序全部服务端完成（列表服务端分页）。
const VULN_SORT_FIELD_MAP: Record<string, string> = {
    Severity: 'severity',
    Plugin: 'plugin',
    Target: 'target',
    AIStatus: 'ai_status',
    Status: 'status',
    MatchedAt: 'matched_at',
    CreatedAt: 'created_at',
    UpdatedAt: 'updated_at',
};

// 从漏洞 Payload（server 已写入的脱敏 safePayload）提取凭据发现 ID。
// 爆破类插件（SSH-Crack 等）命中后 server 只在 Payload 里放脱敏影子
// （info_left="credential evidence sealed"）+ credential_finding_id 关联键，
// 明文凭据密封在 credential_finding_secrets 表，需 admin 走 reveal 接口解密。
function extractCredentialFindingId(payload?: string): string | null {
    if (!payload) return null;
    try {
        const parsed = JSON.parse(payload) as { go_poc?: { credential_finding_id?: unknown } };
        const id = parsed?.go_poc?.credential_finding_id;
        return typeof id === 'string' && id ? id : null;
    } catch {
        return null;
    }
}

const TaskResults: React.FC = () => {
    const { taskId } = useParams<{ taskId: string }>();
    const { modal, message } = App.useApp();
    const [loading, setLoading] = useState(true);
    const [tabLoading, setTabLoading] = useState<Record<ResultTabKey, boolean>>({
        vulns: false,
        assets: false,
        fingerprints: false,
        content: false,
    });
    const [vulns, setVulns] = useState<API.Vulnerability[]>([]);
    const [assets, setAssets] = useState<API.Asset[]>([]);
    const [fingerprints, setFingerprints] = useState<API.FingerprintGroup[]>([]);
    const [vulnSort, setVulnSort] = useState<{ field?: string; order?: 'asc' | 'desc' }>({});
    const [vulnPagination, setVulnPagination] = useState<ResultPageState>(initialResultPageState);
    const [assetPagination, setAssetPagination] = useState<ResultPageState>(initialResultPageState);
    const [fingerprintPagination, setFingerprintPagination] = useState<ResultPageState>(initialResultPageState);
    // 内容分析（关联资产候选 + 敏感信息）合计数，用于空结果判定与默认页签选择。
    const [contentFindingsTotal, setContentFindingsTotal] = useState(0);
    const [fingerprintSearch, setFingerprintSearch] = useState('');
    const [fingerprintSource, setFingerprintSource] = useState<'' | FingerprintSource>('');
    const [assetKind, setAssetKind] = useState<AssetKind>('web');
    const [assetKindCounts, setAssetKindCounts] = useState<Record<AssetKind, number>>(emptyAssetKindCounts);
    const [assetTotal, setAssetTotal] = useState(0);
    const [assetResolutions, setAssetResolutions] = useState<API.AssetResolution[]>([]);
    const [activeTab, setActiveTab] = useState<ResultTabKey>('vulns');
    const [selectedVuln, setSelectedVuln] = useState<API.Vulnerability | null>(null);
    const [drawerOpen, setDrawerOpen] = useState(false);
    // 扫描链路溯源 Drawer
    const [lineageDrawerOpen, setLineageDrawerOpen] = useState(false);
    const [lineageNodes, setLineageNodes] = useState<API.AssetLineageNode[]>([]);
    const [lineageLoading, setLineageLoading] = useState(false);
    const [lineageTitle, setLineageTitle] = useState('');
    // 凭据揭示（复用凭据发现面板同款 RBAC：viewer 看脱敏，admin 审计揭示）。
    const isAdmin = getCurrentUserRole() === 'admin';
    const revealCredential = useCallback(async (findingId: string) => {
        try {
            const secret = await revealCredentialFinding(findingId);
            modal.confirm({
                title: '已审计揭示凭据', icon: <LockOutlined />, okText: '关闭', cancelButtonProps: { style: { display: 'none' } },
                content: (
                    <Space direction="vertical">
                        <Text>用户名：<Text code copyable>{secret.username}</Text></Text>
                        <Text>密码：<Text code copyable>{secret.password}</Text></Text>
                        <Text type="secondary">本次揭示已写入审计记录，请按最小权限使用。</Text>
                    </Space>
                ),
            });
        } catch (error) {
            message.error(typeof error === 'string' ? error : '凭据揭示失败');
        }
    }, [modal, message]);
    // 各页签的服务端搜索词（state 用于展示，ref 供稳定的 fetch 函数读取，避免级联重抓）
    const [vulnSearch, setVulnSearch] = useState('');
    const [assetSearch, setAssetSearch] = useState('');
    const vulnSearchRef = useRef('');
    const assetSearchRef = useRef('');
    // sort 的 ref 镜像：fetchVulnsPage 依赖它而非 vulnSort state，
    // 避免 onChange 每次新建 sort 对象导致回调重建、触发首屏 effect 重置页码。
    const vulnSortRef = useRef<{ field?: string; order?: 'asc' | 'desc' }>({});
    // 漏洞/信息 子视图：'vulns' 排除 info 级，'info' 仅 info 级。ref 供稳定的
    // fetchVulnsPage 读取，severity 过滤在服务端完成（与服务端分页一致）。
    const vulnSeverityFilterRef = useRef<string[]>([]);
    const [vulnSeverityFilter, setVulnSeverityFilter] = useState<string[]>([]);
    const vulnSeverityViewRef = useRef<'vulns' | 'info'>('vulns');
    // 插件/状态/AI 研判过滤：多选值存 ref 供稳定的 fetchVulnsPage 读取，过滤在服务端完成。
    const [vulnPluginFilter, setVulnPluginFilter] = useState<string[]>([]);
    const [vulnStatusFilter, setVulnStatusFilter] = useState<string[]>([]);
    const [vulnAIStatusFilter, setVulnAIStatusFilter] = useState<string[]>([]);
    const vulnPluginFilterRef = useRef<string[]>([]);
    const vulnStatusFilterRef = useRef<string[]>([]);
    const vulnAIStatusFilterRef = useRef<string[]>([]);
    // 主机/端口过滤：同一多选 ref 模式，选项来自 facets 的 hosts/ports 维度。
    const [vulnHostFilter, setVulnHostFilter] = useState<string[]>([]);
    const [vulnPortFilter, setVulnPortFilter] = useState<string[]>([]);
    const [vulnFilterField, setVulnFilterField] = useState<'plugin' | 'severity' | 'status' | 'aiStatus' | 'host' | 'port' | 'search'>('plugin');
    const vulnHostFilterRef = useRef<string[]>([]);
    const vulnPortFilterRef = useRef<string[]>([]);
    const [vulnFacets, setVulnFacets] = useState<API.VulnFacets>({ plugins: [], statuses: [], ai_statuses: [], hosts: [], ports: [] });
    const vulnValueByField: Record<typeof vulnFilterField, string[]> = {
        plugin: vulnPluginFilter,
        severity: vulnSeverityFilter,
        status: vulnStatusFilter,
        aiStatus: vulnAIStatusFilter,
        host: vulnHostFilter,
        port: vulnPortFilter,
        search: [],
    };
    const vulnFacetByField: Record<typeof vulnFilterField, Array<{ value: string; count: number }>> = {
        plugin: vulnFacets.plugins,
        severity: ['critical', 'high', 'medium', 'low', 'info'].map(value => ({ value, count: 0 })),
        status: vulnFacets.statuses,
        aiStatus: vulnFacets.ai_statuses,
        host: vulnFacets.hosts,
        port: vulnFacets.ports.map(value => ({ value: String(value), count: 0 })),
        search: [],
    };
    const [fingerprintStats, setFingerprintStats] = useState<API.FingerprintGroupStats | null>(null);
    // 资产服务/指纹/标题过滤：多选值存 ref 供稳定的 fetchAssetsPage 读取，过滤在服务端完成。
    // 值形如 "nginx"（包含）或 "!Travel Blog"（排除，点选排除追加）。title 维度高基数、无下拉，
    // 由搜索框（包含）+ 点选排除（!value）驱动；service/fingerprint 有 facets 下拉。
    const [assetServiceFilter, setAssetServiceFilter] = useState<string[]>([]);
    const [assetFingerprintFilter, setAssetFingerprintFilter] = useState<string[]>([]);
    const [assetTitleFilter, setAssetTitleFilter] = useState<string[]>([]);
    const assetServiceFilterRef = useRef<string[]>([]);
    const assetFingerprintFilterRef = useRef<string[]>([]);
    const assetTitleFilterRef = useRef<string[]>([]);
    const [assetFacets, setAssetFacets] = useState<API.AssetFacets>({ services: [], fingerprints: [] });
    const navigate = useNavigate();

    const setTabBusy = useCallback((key: ResultTabKey, value: boolean) => {
        setTabLoading((cur) => ({ ...cur, [key]: value }));
    }, []);

    const fetchVulnsPage = useCallback(async (page: number, pageSize: number, sortField?: string, sortOrder?: 'asc' | 'desc') => {
        setTabBusy('vulns', true);
        try {
            const projectId = localStorage.getItem('active_project_id') || undefined;
            const sort = sortField ?? vulnSortRef.current.field;
            const order = sortOrder ?? vulnSortRef.current.order;
            const severity = vulnSeverityFilterRef.current.length > 0
                ? vulnSeverityFilterRef.current.join(',')
                : (vulnSeverityViewRef.current === 'info' ? 'info' : '!info');
            const res = await getVulns({
                taskId,
                projectId,
                page,
                pageSize,
                sort,
                order,
                search: vulnSearchRef.current || undefined,
                severity,
                plugin: vulnPluginFilterRef.current.join(',') || undefined,
                status: vulnStatusFilterRef.current.join(',') || undefined,
                aiStatus: vulnAIStatusFilterRef.current.join(',') || undefined,
                host: vulnHostFilterRef.current.join(',') || undefined,
                port: vulnPortFilterRef.current.join(',') || undefined,
            });
            setVulns(res.items || []);
            setVulnPagination({
                current: res.page || page,
                pageSize: res.page_size || pageSize,
                total: res.total || 0,
            });
            return res.total || 0;
        } catch (error) {
            console.error('Failed to fetch vulnerabilities:', error);
            setVulns([]);
            return 0;
        } finally {
            setTabBusy('vulns', false);
        }
    }, [setTabBusy, taskId]);

    // 过滤维度选项与列表同源（任务+项目+搜索+severity 视图），搜索/子视图变化时刷新。
    const fetchVulnFacets = useCallback(async () => {
        if (!taskId) return;
        try {
            const projectId = localStorage.getItem('active_project_id') || undefined;
    const severity = vulnSeverityViewRef.current === 'info' ? 'info' : '!info';
            const facets = await getVulnFacets(taskId, {
                projectId,
                severity,
                search: vulnSearchRef.current || undefined,
                host: vulnHostFilterRef.current.join(',') || undefined,
                port: vulnPortFilterRef.current.join(',') || undefined,
            });
            setVulnFacets(facets);
        } catch (error) {
            console.error('Failed to fetch vuln facets:', error);
        }
    }, [taskId]);

    // 资产过滤维度（服务/指纹）下拉。kind 是当前资产视图（对应漏洞 severity 视图），
    // 使服务下拉随页签收缩；search 使选项与当前搜索口径对齐。选项不随已选服务/指纹收缩。
    const fetchAssetFacets = useCallback(async (kind: AssetKind) => {
        if (!taskId) return;
        try {
            const projectId = localStorage.getItem('active_project_id') || undefined;
            const facets = await getAssetFacets(taskId, {
                projectId,
                kind,
                search: assetSearchRef.current || undefined,
            });
            setAssetFacets(facets);
        } catch (error) {
            console.error('Failed to fetch asset facets:', error);
        }
    }, [taskId]);

    const applyAssetStats = useCallback((stats: API.AssetKindStats | undefined, fallbackTotal: number, kind: AssetKind) => {
        const counts = emptyAssetKindCounts();
        if (stats) {
            counts.web = stats.web || 0;
            counts.host_port = stats.host_port || 0;
            counts.domain = stats.domain || 0;
            counts.resolution = stats.resolution || 0;
            counts.other = stats.other || 0;
            setAssetTotal(stats.total || fallbackTotal);
            setAssetResolutions(stats.resolutions || []);
        } else {
            counts[kind] = fallbackTotal;
            setAssetTotal(fallbackTotal);
            setAssetResolutions([]);
        }
        setAssetKindCounts(counts);
        return counts;
    }, []);

    const fetchAssetsPage = useCallback(async (page: number, pageSize: number, kind: AssetKind) => {
        setTabBusy('assets', true);
        try {
            const projectId = localStorage.getItem('active_project_id') || undefined;
            const res = await getAssets({
                taskId, projectId, page, pageSize, kind,
                search: assetSearchRef.current || undefined,
                service: assetServiceFilterRef.current.join(',') || undefined,
                title: assetTitleFilterRef.current.join(',') || undefined,
                fingerprint: assetFingerprintFilterRef.current.join(',') || undefined,
            });
            const items = (res.items || []).filter((asset) => assetMatchesKind(asset.Protocol, kind));
            setAssets(items);
            setAssetPagination({
                current: res.page || page,
                pageSize: res.page_size || pageSize,
                total: res.stats ? (res.total || 0) : items.length,
            });
            const counts = applyAssetStats(res.stats, res.stats?.total ?? res.total ?? items.length, kind);
            return { kindTotal: res.total || items.length, allTotal: res.stats?.total ?? res.total ?? items.length, counts };
        } catch (error) {
            console.error('Failed to fetch assets:', error);
            setAssets([]);
            applyAssetStats(undefined, 0, kind);
            return { kindTotal: 0, allTotal: 0, counts: emptyAssetKindCounts() };
        } finally {
            setTabBusy('assets', false);
        }
    }, [applyAssetStats, setTabBusy, taskId]);

    const fetchFingerprintsPage = useCallback(async (page: number, pageSize: number, search = '', source: '' | FingerprintSource = '') => {
        setTabBusy('fingerprints', true);
        try {
            const projectId = localStorage.getItem('active_project_id') || undefined;
            const res = await getFingerprintGroups({
                taskId,
                projectId,
                page,
                pageSize,
                search: search.trim() || undefined,
                source: source || undefined,
            });
            setFingerprints(res.items || []);
            setFingerprintStats(res.stats ?? null);
            setFingerprintPagination({
                current: res.page || page,
                pageSize: res.page_size || pageSize,
                total: res.total || 0,
            });
            return res.total || 0;
        } catch (error) {
            console.error('Failed to fetch fingerprints:', error);
            setFingerprints([]);
            setFingerprintStats(null);
            return 0;
        } finally {
            setTabBusy('fingerprints', false);
        }
    }, [setTabBusy, taskId]);

    // 内容分析合计数（关联资产候选 + 敏感信息）。独立容错：内容分析为可选能力，
    // 其请求失败不应导致整页结果空白，故单独捕获并计 0。
    const fetchContentTotals = useCallback(async (): Promise<number> => {
        try {
            const projectId = localStorage.getItem('active_project_id') || undefined;
            const [crawl, sensitive] = await Promise.all([
                listCrawlSiteCandidates({ taskId, projectId, page: 1, pageSize: 1 }),
                listSensitiveFindings({ taskId, projectId, page: 1, pageSize: 1 }),
            ]);
            return (crawl?.total || 0) + (sensitive?.total || 0);
        } catch (error) {
            console.error('Failed to fetch content analysis totals:', error);
            return 0;
        }
    }, [taskId]);

    const fetchFirstPages = useCallback(async () => {
        setLoading(true);
        try {
            const [vulnerabilityTotal, assetPage, fingerprintTotal, contentTotal] = await Promise.all([
                fetchVulnsPage(1, DEFAULT_RESULT_PAGE_SIZE),
                fetchAssetsPage(1, DEFAULT_RESULT_PAGE_SIZE, 'web'),
                fetchFingerprintsPage(1, DEFAULT_RESULT_PAGE_SIZE),
                fetchContentTotals(),
                fetchVulnFacets(),
            ]);
            setContentFindingsTotal(contentTotal);
            const nextKind = firstNonEmptyAssetKind(assetPage.counts);
            let allAssets = assetPage.allTotal;
            if (nextKind !== 'web') {
                const selected = await fetchAssetsPage(1, DEFAULT_RESULT_PAGE_SIZE, nextKind);
                allAssets = selected.allTotal;
            }
            setAssetKind(nextKind);
            void fetchAssetFacets(nextKind);
            setActiveTab(firstNonEmptyResultTab(vulnerabilityTotal, allAssets, fingerprintTotal, contentTotal));
        } finally {
            setLoading(false);
        }
    }, [fetchAssetFacets, fetchAssetsPage, fetchContentTotals, fetchFingerprintsPage, fetchVulnFacets, fetchVulnsPage]);

    const fetchCurrentPages = useCallback(async () => {
        setLoading(true);
        try {
            const [, , , contentTotal] = await Promise.all([
                fetchVulnsPage(vulnPagination.current, vulnPagination.pageSize),
                fetchAssetsPage(assetPagination.current, assetPagination.pageSize, assetKind),
                fetchFingerprintsPage(fingerprintPagination.current, fingerprintPagination.pageSize, fingerprintSearch, fingerprintSource),
                fetchContentTotals(),
            ]);
            setContentFindingsTotal(contentTotal);
        } finally {
            setLoading(false);
        }
    }, [
        assetKind,
        assetPagination,
        fetchAssetsPage,
        fetchContentTotals,
        fetchFingerprintsPage,
        fetchVulnsPage,
        fingerprintPagination,
        fingerprintSearch,
        fingerprintSource,
        vulnPagination,
    ]);

    // 切换任务时清空各页签搜索/统计，避免跨任务残留过滤态。
    // 声明在 fetchFirstPages effect 之前，保证先清 ref 再触发重抓。
    useEffect(() => {
        vulnSearchRef.current = '';
        setVulnSearch('');
        assetSearchRef.current = '';
        setAssetSearch('');
        assetServiceFilterRef.current = [];
        setAssetServiceFilter([]);
        assetFingerprintFilterRef.current = [];
        setAssetFingerprintFilter([]);
        assetTitleFilterRef.current = [];
        setAssetTitleFilter([]);
        setAssetFacets({ services: [], fingerprints: [] });
        vulnSortRef.current = {};
        setVulnSort({});
        vulnSeverityViewRef.current = 'vulns';

        vulnPluginFilterRef.current = [];
        setVulnPluginFilter([]);
        vulnStatusFilterRef.current = [];
        setVulnStatusFilter([]);
        vulnAIStatusFilterRef.current = [];
        setVulnAIStatusFilter([]);
        vulnHostFilterRef.current = [];
        setVulnHostFilter([]);
        vulnPortFilterRef.current = [];
        setVulnPortFilter([]);
        setVulnFacets({ plugins: [], statuses: [], ai_statuses: [], hosts: [], ports: [] });
        setFingerprintSearch('');
        setFingerprintSource('');
        setFingerprintStats(null);
        setDrawerOpen(false);
    }, [taskId]);

    useEffect(() => {
        fetchFirstPages();
    }, [fetchFirstPages]);

    useAutoContext({
        task_id: taskId,
        active_tab: activeTab,
        stats: {
            vulns: vulnPagination.total,
            assets: assetTotal,
            fingerprints: fingerprintPagination.total,
            asset_kind: assetKind,
            asset_kinds: assetKindCounts,
        },
        vulns_summary: vulns.slice(0, 10).map(v => ({
            id: v.ID,
            target: v.Target,
            severity: v.Severity,
            plugin: v.Plugin,
        })),
        assets_summary: assets.slice(0, 10).map(a => ({
            id: a.ID,
            target: a.Target,
            protocol: a.Protocol,
            port: a.Port,
            title: a.Title,
            service: a.Service,
            fingerprints: (a.Fingerprints || []).map((match) => match.ProductName),
        })),
        fingerprints_summary: fingerprints.slice(0, 10).map(f => ({
            product_name: f.ProductName,
            target_count: f.TargetCount,
            sources: fingerprintGroupSources(f),
            targets: f.Targets?.slice(0, 5).map(target => target.MatchedURL || target.Target) || [],
        })),
        viewing_vuln: drawerOpen ? selectedVuln : null,
    });

    const handleExport = async () => {
        try {
            const projectId = localStorage.getItem('active_project_id') || undefined;
            let blob: Blob;
            let filename: string;
            if (activeTab === 'assets') {
                blob = await exportAssets(projectId, taskId, assetKind);
                filename = `assets-${assetKind}-${taskId || 'all'}.csv`;
            } else if (activeTab === 'fingerprints') {
                blob = await exportFingerprints(projectId, taskId, fingerprintSearch, fingerprintSource);
                filename = `fingerprints-${taskId || 'all'}.csv`;
            } else {
                blob = await exportVulns(projectId, taskId);
                filename = `vulns-${taskId || 'all'}.csv`;
            }
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
        } catch {
            console.error('Export failed');
        }
    };

    const handleVulnClick = (record: API.Vulnerability) => {
        setSelectedVuln(record);
        setDrawerOpen(true);
    };

    const parseReferences = (ref: string): string[] => {
        if (!ref) return [];
        try {
            const parsed = JSON.parse(ref);
            return Array.isArray(parsed) ? parsed : [ref];
        } catch {
            return ref ? [ref] : [];
        }
    };

    const normalizeSeverity = (severity?: string) => {
        if (!severity) return 'Unknown';
        const normalized = severity.charAt(0).toUpperCase() + severity.slice(1).toLowerCase();
        return ['Critical', 'High', 'Medium', 'Low', 'Info'].includes(normalized) ? normalized : 'Unknown';
    };

    const getSeverityColor = (severity: string) => {
        const normalized = normalizeSeverity(severity);
        const map: Record<string, string> = {
            Critical: '#ef4444', High: '#f97316', Medium: '#f59e0b',
            Low: '#3b82f6', Info: '#14b8a6', Unknown: '#94a3b8',
        };
        return map[normalized] || '#94a3b8';
    };

    // ── Target helpers ──
    const extractHostFromTarget = (target: string): string => {
        if (!target) return '-';
        try {
            if (target.includes('://')) {
                const u = new URL(target);
                return u.hostname;
            }
        } catch { /* ignore */ }
        const parts = target.split(':');
        return parts[0] || target;
    };

    const extractPortFromTarget = (target: string, port: number): number => {
        if (port > 0) return port;
        if (!target) return 0;
        try {
            if (target.includes('://')) {
                const u = new URL(target);
                if (u.port) return parseInt(u.port);
                if (u.protocol === 'https:') return 443;
                if (u.protocol === 'http:') return 80;
            }
        } catch { /* ignore */ }
        const parts = target.split(':');
        if (parts.length >= 2) {
            const p = parseInt(parts[parts.length - 1]);
            if (!isNaN(p) && p > 0 && p <= 65535) return p;
        }
        return 0;
    };

    // ── 域名 ↔ 解析 IP 关联：来自整任务 RealIP 统计，不跟当前页走 ──
    const { ipToDomains, domainToIPs } = useMemo(() => {
        const ipMap = new Map<string, string[]>();
        const domainMap = new Map<string, string[]>();
        assetResolutions.forEach((row) => {
            const domain = row.domain?.trim();
            const ips = (row.ips || []).map((ip) => ip.trim()).filter(Boolean);
            if (!domain || ips.length === 0) return;
            domainMap.set(domain, ips);
            ips.forEach((ip) => {
                const domains = ipMap.get(ip) || [];
                if (!domains.includes(domain)) domains.push(domain);
                ipMap.set(ip, domains);
            });
        });
        return { ipToDomains: ipMap, domainToIPs: domainMap };
    }, [assetResolutions]);

    const parseAssetResolution = (asset: API.Asset): { domain: string; ips: string[] } => {
        let domain = '';
        let ips: string[] = [];
        if (asset.Tags) {
            try {
                const payload = JSON.parse(asset.Tags) as { domain?: unknown; ips?: unknown };
                if (typeof payload.domain === 'string') domain = payload.domain.trim();
                if (Array.isArray(payload.ips)) {
                    ips = payload.ips.filter((item): item is string => typeof item === 'string' && item.trim() !== '').map((item) => item.trim());
                }
            } catch { /* ignore malformed tags */ }
        }
        if (!domain) domain = asset.Target || '';
        if (ips.length === 0) ips = domainToIPs.get(domain) || [];
        return { domain, ips };
    };

    const ipv4Pattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
    const relatedHostsFor = (host: string): string[] => {
        if (ipv4Pattern.test(host)) return ipToDomains.get(host) || [];
        return domainToIPs.get(host) || [];
    };


    const isJsonString = (s: string): boolean => {
        if (!s) return false;
        return (s.startsWith('{') && s.endsWith('}')) || (s.startsWith('[') && s.endsWith(']'));
    };

    const protocolColors: Record<string, string> = {
        'Web': 'green', 'Nmap': 'purple', 'PortScan': 'blue',
        'Protocol': 'geekblue', 'Domain': 'cyan', 'Domain-Bind': 'cyan',
        'IPAlive': 'default',
    };

    // 下钻联动：指纹目标 → 资产/漏洞页签并按目标主机过滤
    const handleViewAssets = (target: string) => {
        const host = extractHostFromTarget(target);
        assetSearchRef.current = host;
        setAssetSearch(host);
        setAssetPagination(prev => ({ ...prev, current: 1 }));
        setActiveTab('assets');
        void fetchAssetsPage(1, assetPagination.pageSize, assetKind);
    };

    const handleViewVulns = (target: string) => {
        const host = extractHostFromTarget(target);
        vulnSearchRef.current = host;
        setVulnSearch(host);
        setVulnPagination(prev => ({ ...prev, current: 1 }));
        setActiveTab('vulns');
        void fetchVulnsPage(1, vulnPagination.pageSize);
        void fetchVulnFacets();
    };

    const clearAssetFilter = () => {
        assetSearchRef.current = '';
        setAssetSearch('');
        assetServiceFilterRef.current = [];
        setAssetServiceFilter([]);
        assetFingerprintFilterRef.current = [];
        setAssetFingerprintFilter([]);
        assetTitleFilterRef.current = [];
        setAssetTitleFilter([]);
        setAssetPagination(prev => ({ ...prev, current: 1 }));
        void fetchAssetsPage(1, assetPagination.pageSize, assetKind);
        void fetchAssetFacets(assetKind);
    };

    const clearVulnFilter = () => {
        vulnSearchRef.current = '';
        setVulnSearch('');
        setVulnPagination(prev => ({ ...prev, current: 1 }));
        void fetchVulnsPage(1, vulnPagination.pageSize);
        void fetchVulnFacets();
    };

    const clearVulnDimensions = () => {
        vulnSearchRef.current = '';
        setVulnSearch('');
        for (const [ref, setter] of [
            [vulnPluginFilterRef, setVulnPluginFilter],
            [vulnSeverityFilterRef, setVulnSeverityFilter],
            [vulnStatusFilterRef, setVulnStatusFilter],
            [vulnAIStatusFilterRef, setVulnAIStatusFilter],
            [vulnHostFilterRef, setVulnHostFilter],
            [vulnPortFilterRef, setVulnPortFilter],
        ] as const) {
            ref.current = [];
            setter([]);
        }
    };

    const handleVulnFieldChange = (value: typeof vulnFilterField) => {
        if (value === vulnFilterField) return;
        clearVulnDimensions();
        setVulnFilterField(value);
        setVulnPagination(prev => ({ ...prev, current: 1 }));
        void fetchVulnsPage(1, vulnPagination.pageSize);
        void fetchVulnFacets();
    };

    const refreshVulnFilter = () => {
        setVulnPagination(prev => ({ ...prev, current: 1 }));
        void fetchVulnsPage(1, vulnPagination.pageSize);
        void fetchVulnFacets();
    };

    // 插件/状态/AI 研判/主机/端口过滤变化：写 ref 供稳定的 fetchVulnsPage 读取，回第 1 页重抓。
    // 各维度独立（facets 不随单维度选择收缩），选项始终来自服务端当前作用域。
    const handleVulnFilterChange = (kind: 'plugin' | 'severity' | 'status' | 'aiStatus' | 'host' | 'port', values: string[]) => {
        if (kind === 'severity') {
            vulnSeverityFilterRef.current = values;
            setVulnSeverityFilter(values);
        } else if (kind === 'plugin') {
            vulnPluginFilterRef.current = values;
            setVulnPluginFilter(values);
        } else if (kind === 'status') {
            vulnStatusFilterRef.current = values;
            setVulnStatusFilter(values);
        } else if (kind === 'host') {
            vulnHostFilterRef.current = values;
            setVulnHostFilter(values);
        } else if (kind === 'port') {
            vulnPortFilterRef.current = values;
            setVulnPortFilter(values);
        } else {
            vulnAIStatusFilterRef.current = values;
            setVulnAIStatusFilter(values);
        }
        setVulnPagination(prev => ({ ...prev, current: 1 }));
        void fetchVulnsPage(1, vulnPagination.pageSize);
    };

    // 服务/指纹多选过滤变化：写 ref 供稳定的 fetchAssetsPage 读取，回第 1 页重抓。
    // 选项始终来自服务端当前作用域（facets 不随单维度选择收缩），与漏洞口径一致。
    const handleAssetFilterChange = (dimension: 'service' | 'fingerprint', values: string[]) => {
        if (dimension === 'service') {
            assetServiceFilterRef.current = values;
            setAssetServiceFilter(values);
        } else {
            // 指纹下拉只驱动包含项，保留点选排除的 "!" 项（chips 栏单独展示/移除）。
            const excludes = assetFingerprintFilterRef.current.filter(v => v.startsWith('!'));
            const next = [...excludes, ...values];
            assetFingerprintFilterRef.current = next;
            setAssetFingerprintFilter(next);
        }
        setAssetPagination(prev => ({ ...prev, current: 1 }));
        void fetchAssetsPage(1, assetPagination.pageSize || DEFAULT_RESULT_PAGE_SIZE, assetKind);
    };

    // 点选排除：向 title/fingerprint 维度追加 "!value"。去重，写 ref+state，回第 1 页重抓。
    const addAssetExclude = (dimension: 'title' | 'fingerprint', rawValue: string) => {
        const value = rawValue.trim();
        if (!value) return;
        const excluded = `!${value}`;
        const ref = dimension === 'title' ? assetTitleFilterRef : assetFingerprintFilterRef;
        const set = dimension === 'title' ? setAssetTitleFilter : setAssetFingerprintFilter;
        if (ref.current.includes(excluded)) return;
        const next = [...ref.current, excluded];
        ref.current = next;
        set(next);
        setAssetPagination(prev => ({ ...prev, current: 1 }));
        void fetchAssetsPage(1, assetPagination.pageSize || DEFAULT_RESULT_PAGE_SIZE, assetKind);
    };

    // chips 栏单项移除：从指定维度删掉一个值（含 "!value" 排除项），回第 1 页重抓。
    const removeAssetFilterValue = (dimension: 'service' | 'title' | 'fingerprint', value: string) => {
        if (dimension === 'service') {
            const next = assetServiceFilterRef.current.filter(v => v !== value);
            assetServiceFilterRef.current = next;
            setAssetServiceFilter(next);
        } else if (dimension === 'title') {
            const next = assetTitleFilterRef.current.filter(v => v !== value);
            assetTitleFilterRef.current = next;
            setAssetTitleFilter(next);
        } else {
            const next = assetFingerprintFilterRef.current.filter(v => v !== value);
            assetFingerprintFilterRef.current = next;
            setAssetFingerprintFilter(next);
        }
        setAssetPagination(prev => ({ ...prev, current: 1 }));
        void fetchAssetsPage(1, assetPagination.pageSize || DEFAULT_RESULT_PAGE_SIZE, assetKind);
    };

    // 扫描链路溯源：拉取资产链路并打开 Steps Drawer
    const openAssetLineage = async (asset: API.Asset) => {
        const projectId = localStorage.getItem('active_project_id') || undefined;
        if (!projectId) return;
        setLineageTitle(asset.Target);
        setLineageNodes([]);
        setLineageDrawerOpen(true);
        setLineageLoading(true);
        try {
            const res = await getAssetLineage(projectId, asset.ID);
            setLineageNodes(res.nodes || []);
        } catch {
            setLineageNodes([]);
        } finally {
            setLineageLoading(false);
        }
    };

    // 受控排序展示：与 vulnSort 对齐，未排序列返回 null。服务端排序字段映射见 VULN_SORT_FIELD_MAP。
    const vulnColumnSortOrder = (field: string): 'ascend' | 'descend' | null =>
        vulnSort.field === field ? (vulnSort.order === 'asc' ? 'ascend' : 'descend') : null;

    const vulnColumns: ColumnsType<API.Vulnerability> = [
        {
            title: '主机',
            key: 'host',
            width: 160,
            render: (_, record) => {
                const host = extractHostFromTarget(record.Target);
                return (
                    <Text copyable={{ text: host }} ellipsis={{ tooltip: host }} style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, fontWeight: 500, maxWidth: 120, display: 'inline-block' }}>
                        {host}
                    </Text>
                );
            },
        },
        {
            title: '插件',
            dataIndex: 'Plugin',
            key: 'plugin',
            ellipsis: true,
            sorter: true,
            sortOrder: vulnColumnSortOrder('plugin'),
            render: (v: string) => (
                <Space size={4} style={{ width: '100%', flexWrap: 'nowrap' }}>
                    <Tooltip title={v}>
                        <Text strong style={{ fontSize: 13, minWidth: 0 }} ellipsis>{v}</Text>
                    </Tooltip>
                    <Tooltip title={`快速排除漏洞类型：${v}`}>
                        <Button
                            type="text"
                            size="small"
                            className="result-exclude-button"
                            aria-label={`排除 ${v}`}
                            icon={<MinusCircleOutlined />}
                            onClick={(event) => {
                                event.stopPropagation();
                                if (!v || vulnPluginFilterRef.current.includes(`!${v}`)) return;
                                const next = [...vulnPluginFilterRef.current, `!${v}`];
                                vulnPluginFilterRef.current = next;
                                setVulnPluginFilter(next);
                                setVulnPagination(prev => ({ ...prev, current: 1 }));
                                void fetchVulnsPage(1, vulnPagination.pageSize);
                            }}
                        />
                    </Tooltip>
                </Space>
            ),
        },
        {
            title: '危害等级',
            dataIndex: 'Severity',
            key: 'severity',
            width: 100,
            render: (v: string) => {
                const normalized = normalizeSeverity(v);
                return <Tag color={getSeverityColor(normalized)}>{normalized}</Tag>;
            },
            sorter: true,
            sortDirections: ['descend', 'ascend'],
            sortOrder: vulnColumnSortOrder('severity'),
        },
        {
            title: 'AI 研判',
            dataIndex: 'AIStatus',
            key: 'ai_status',
            width: 110,
            sorter: true,
            sortOrder: vulnColumnSortOrder('ai_status'),
            render: (v: string, record: API.Vulnerability) => (
                <Space direction="vertical" size={2}>
                    <AIVerdictTag verdict={v} />
                    {v && (record.AIConfidence ?? 0) > 0 && (
                        <Text type="secondary" style={{ fontSize: 11 }}>
                            {((record.AIConfidence ?? 0) * 100).toFixed(0)}%
                        </Text>
                    )}
                    {record.TaintStatus && (
                        <Tooltip title={record.TaintReason || '该主机多端口返回同一响应页，疑似 WAF/catch-all 拦截，证据不可信'}>
                            <Tag color="volcano" style={{ marginInlineEnd: 0, fontSize: 11 }}>疑似WAF页</Tag>
                        </Tooltip>
                    )}
                </Space>
            ),
        },
        {
            title: '匹配位置',
            dataIndex: 'MatchedAt',
            key: 'matched_at',
            ellipsis: true,
            sorter: true,
            sortOrder: vulnColumnSortOrder('matched_at'),
            render: (v: string) => v ? (
                <Text style={{ fontSize: 12, fontFamily: 'monospace', color: '#0ea5e9' }} ellipsis={{ tooltip: v }}>{v}</Text>
            ) : <Text type="secondary">-</Text>,
        },
        {
            title: '请求/响应',
            key: 'has_packet',
            width: 90,
            align: 'center',
            render: (_: unknown, record: API.Vulnerability) => {
                const hasData = record.Request || record.Response;
                return hasData
                    ? <Tag color="green" style={{ cursor: 'pointer' }}><SendOutlined /> 有</Tag>
                    : <Text type="secondary" style={{ fontSize: 12 }}>-</Text>;
            },
        },
        {
            title: '凭据',
            key: 'credential',
            width: 104,
            align: 'center',
            render: (_: unknown, record: API.Vulnerability) => {
                const findingId = extractCredentialFindingId(record.Payload);
                if (!findingId) return <Text type="secondary" style={{ fontSize: 12 }}>-</Text>;
                return isAdmin
                    ? <Button size="small" type="link" style={{ padding: 0 }} icon={<LockOutlined />} onClick={() => revealCredential(findingId)}>审计揭示</Button>
                    : <Tooltip title="弱口令已命中，凭据已密封存储；仅 Admin 可审计揭示"><Tag icon={<LockOutlined />} color="gold" style={{ marginInlineEnd: 0 }}>已捕获</Tag></Tooltip>;
            },
        },
        {
            title: '发现时间',
            dataIndex: 'CreatedAt',
            key: 'created_at',
            width: 170,
            sorter: true,
            sortOrder: vulnColumnSortOrder('created_at'),
            render: (v: string) => {
                if (!v) return '-';
                return <Text style={{ fontSize: 12, color: '#64748b' }}>{dayjs(v).format('YYYY-MM-DD HH:mm:ss')}</Text>;
            },
        },
    ];


    const renderRelatedHost = (host: string, cdn?: boolean) => {
        const related = relatedHostsFor(host).filter((item) => item !== host);
        const shown = related.slice(0, 2);
        return (
            <Space size={4} wrap>
                <Text copyable={{ text: host }} ellipsis={{ tooltip: host }} style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, fontWeight: 500, maxWidth: 190, display: 'inline-block' }}>
                    {host}
                </Text>
                {cdn && <Tag color="orange" style={{ margin: 0, fontSize: 10 }}>CDN</Tag>}
                {shown.length > 0 && (
                    <Tooltip title={`关联主机：${related.join('、')}`}>
                        <span style={{ display: 'inline-flex', gap: 2 }}>
                            <Text type="secondary" style={{ fontSize: 10 }}>↔</Text>
                            {shown.map((item) => (
                                <Tag key={item} color="default" style={{ margin: 0, fontSize: 10, fontFamily: "'JetBrains Mono', monospace" }}>
                                    {item}
                                </Tag>
                            ))}
                            {related.length > shown.length && (
                                <Tag style={{ margin: 0, fontSize: 10 }}>+{related.length - shown.length}</Tag>
                            )}
                        </span>
                    </Tooltip>
                )}
            </Space>
        );
    };

    const createdAtColumn: ColumnsType<API.Asset>[number] = {
        title: '发现时间',
        dataIndex: 'CreatedAt',
        key: 'created_at',
        width: 160,
        sorter: (a, b) => new Date(a.CreatedAt).getTime() - new Date(b.CreatedAt).getTime(),
        render: (v: string) => {
            if (!v) return '-';
            return <Text style={{ fontSize: 12, color: '#64748b' }}>{dayjs(v).format('YYYY-MM-DD HH:mm:ss')}</Text>;
        },
    };

    // 扫描链路溯源：打开该资产的发现链路 Drawer（本地能力，挂到各资产类别列尾）
    const lineageActionColumn: ColumnsType<API.Asset>[number] = {
        title: '操作',
        key: 'actions',
        width: 80,
        render: (_, record) => (
            <Button
                type="link"
                size="small"
                style={{ padding: 0 }}
                icon={<PartitionOutlined />}
                onClick={() => void openAssetLineage(record)}
            >
                溯源
            </Button>
        ),
    };

    const cdnColumn: ColumnsType<API.Asset>[number] = {
        title: 'CDN',
        key: 'cdn',
        width: 90,
        render: (_, record) => record.CDN
            ? <Tag color="orange" style={{ margin: 0 }}>疑似 CDN</Tag>
            : <Text type="secondary">-</Text>,
    };

    const protocolColumn: ColumnsType<API.Asset>[number] = {
        title: '来源',
        dataIndex: 'Protocol',
        key: 'protocol',
        width: 120,
        render: (v: string) => <Tag color={protocolColors[v] || 'default'} style={{ margin: 0, fontSize: 11 }}>{v}</Tag>,
    };

    const renderAssetURL = (url?: string) => {
        if (!url) return <Text type="secondary">-</Text>;
        if (url.startsWith('http://') || url.startsWith('https://')) {
            return (
                <Tooltip title={url}>
                    <a href={url} target="_blank" rel="noopener noreferrer" style={{ fontSize: 12, fontFamily: 'monospace' }}>
                        <LinkOutlined style={{ marginRight: 4 }} />{url.replace(/^https?:\/\//, '').slice(0, 40)}
                    </a>
                </Tooltip>
            );
        }
        if (isJsonString(url)) {
            let preview = '';
            try {
                const parsed = JSON.parse(url);
                preview = parsed.ip || parsed.type || 'evidence';
            } catch {
                preview = 'data';
            }
            return (
                <Popover
                    content={<pre style={{ maxWidth: 500, maxHeight: 300, overflow: 'auto', fontSize: 11, margin: 0 }}>{JSON.stringify(JSON.parse(url), null, 2)}</pre>}
                    title="原始数据"
                    trigger="hover"
                >
                    <Tag color="default" style={{ cursor: 'pointer', fontSize: 10, margin: 0 }}>📋 {preview}</Tag>
                </Popover>
            );
        }
        return <Text style={{ fontSize: 12, color: '#64748b' }} ellipsis={{ tooltip: url }}>{url}</Text>;
    };

    const renderAssetFingerprints = (matches?: API.AssetFingerprintMatch[]) => {
        if (!matches || matches.length === 0) return <Text type="secondary">-</Text>;
        return (
            <Space size={4} wrap>
                {matches.map((match) => {
                    const active = match.Source && match.Source !== 'passive';
                    return (
                        <Tooltip key={`${match.ProductName}-${match.Source || 'passive'}`} title={`点击排除此指纹：${match.ProductName}`}>
                            <Tag
                                color={active ? fingerprintSourceColor(match.Source) : 'cyan'}
                                style={{ margin: 0, cursor: 'pointer' }}
                                onClick={(e) => { e.stopPropagation(); addAssetExclude('fingerprint', match.ProductName); }}
                            >
                                {match.ProductName}
                                {active ? ` · ${fingerprintSourceLabel(match.Source, match.SourceLabel)}` : ''}
                            </Tag>
                        </Tooltip>
                    );
                })}
            </Space>
        );
    };

    // 当前资产过滤条件可视化：搜索 + 服务/指纹包含 + 标题/指纹排除，逐项可删（chips 栏）。
    const hasAssetFilters = Boolean(assetSearch) || assetServiceFilter.length > 0 || assetFingerprintFilter.length > 0 || assetTitleFilter.length > 0;
    const clearAssetSearch = () => {
        assetSearchRef.current = '';
        setAssetSearch('');
        setAssetPagination(prev => ({ ...prev, current: 1 }));
        void fetchAssetsPage(1, assetPagination.pageSize || DEFAULT_RESULT_PAGE_SIZE, assetKind);
        void fetchAssetFacets(assetKind);
    };
    const renderAssetFilterChips = () => {
        const chips: React.ReactNode[] = [];
        if (assetSearch) {
            chips.push(<Tag key="search" closable color="purple" onClose={clearAssetSearch}>搜索: {assetSearch}</Tag>);
        }
        assetServiceFilter.forEach((value) => chips.push(
            <Tag key={`svc-${value}`} closable color="blue" onClose={() => removeAssetFilterValue('service', value)}>服务: {value}</Tag>
        ));
        assetFingerprintFilter.forEach((value) => {
            const excluded = value.startsWith('!');
            chips.push(
                <Tag key={`fp-${value}`} closable color={excluded ? 'orange' : 'blue'} onClose={() => removeAssetFilterValue('fingerprint', value)}>
                    {excluded ? `排除指纹: ${value.slice(1)}` : `指纹: ${value}`}
                </Tag>
            );
        });
        assetTitleFilter.forEach((value) => {
            const excluded = value.startsWith('!');
            chips.push(
                <Tag key={`ttl-${value}`} closable color={excluded ? 'orange' : 'blue'} onClose={() => removeAssetFilterValue('title', value)}>
                    {excluded ? `排除标题: ${value.slice(1)}` : `标题: ${value}`}
                </Tag>
            );
        });
        return chips;
    };

    const assetColumnsForKind = (kind: AssetKind): ColumnsType<API.Asset> => {
        if (kind === 'resolution') {
            return [
                {
                    title: '域名',
                    key: 'domain',
                    width: 240,
                    render: (_, record) => {
                        const { domain } = parseAssetResolution(record);
                        return renderRelatedHost(domain || record.Target, record.CDN);
                    },
                },
                {
                    title: '解析 IP',
                    key: 'ips',
                    render: (_, record) => {
                        const { ips } = parseAssetResolution(record);
                        if (ips.length === 0) return <Text type="secondary">-</Text>;
                        return (
                            <Space size={4} wrap>
                                {ips.map((ip) => (
                                    <Tag key={ip} style={{ margin: 0, fontFamily: "'JetBrains Mono', monospace" }}>{ip}</Tag>
                                ))}
                            </Space>
                        );
                    },
                },
                cdnColumn,
                createdAtColumn,
                lineageActionColumn,
            ];
        }
        const hostColumn: ColumnsType<API.Asset>[number] = {
            title: kind === 'domain' ? '域名' : '主机',
            key: 'host',
            width: 240,
            render: (_, record) => renderRelatedHost(extractHostFromTarget(record.Target), record.CDN && kind !== 'web' && kind !== 'domain'),
        };
        if (kind === 'web') {
            return [
                hostColumn,
                cdnColumn,
                {
                    title: 'URL',
                    key: 'url',
                    ellipsis: true,
                    render: (_, record) => renderAssetURL(record.URL || record.Target),
                },
                {
                    title: '标题',
                    dataIndex: 'Title',
                    key: 'title',
                    ellipsis: { showTitle: false },
                    render: (v: string) => v
                        ? (
                            <Space size={4} style={{ width: '100%' }}>
                                <Tooltip title={v}><Text style={{ fontSize: 12 }} ellipsis>{v}</Text></Tooltip>
                                <Tooltip title={`排除此标题：${v}`}>
                                    <Button
                                        type="text"
                                        size="small"
                                        icon={<MinusCircleOutlined />}
                                        onClick={(e) => { e.stopPropagation(); addAssetExclude('title', v); }}
                                    />
                                </Tooltip>
                            </Space>
                        )
                        : <Text type="secondary">-</Text>,
                },
                {
                    title: '匹配指纹',
                    key: 'fingerprints',
                    render: (_, record) => renderAssetFingerprints(record.Fingerprints),
                },
                {
                    title: '服务',
                    dataIndex: 'Service',
                    key: 'service',
                    width: 120,
                    render: (v: string) => v ? <Tag color="geekblue" style={{ margin: 0 }}>{v}</Tag> : <Text type="secondary">-</Text>,
                },
                protocolColumn,
                createdAtColumn,
                lineageActionColumn,
            ];
        }
        if (kind === 'host_port') {
            return [
                hostColumn,
                {
                    title: '端口',
                    key: 'port',
                    width: 90,
                    render: (_, record) => {
                        const port = extractPortFromTarget(record.Target, record.Port);
                        return port > 0
                            ? <Tag color="blue" style={{ margin: 0, fontFamily: 'monospace', fontWeight: 600 }}>{port}</Tag>
                            : <Text type="secondary">-</Text>;
                    },
                    sorter: (a, b) => extractPortFromTarget(a.Target, a.Port) - extractPortFromTarget(b.Target, b.Port),
                },
                protocolColumn,
                {
                    title: '服务',
                    dataIndex: 'Service',
                    key: 'service',
                    width: 140,
                    render: (v: string) => v ? <Tag color="geekblue" style={{ margin: 0 }}>{v}</Tag> : <Text type="secondary">-</Text>,
                },
                createdAtColumn,
                lineageActionColumn,
            ];
        }
        if (kind === 'domain') {
            return [
                hostColumn,
                cdnColumn,
                protocolColumn,
                {
                    title: '关联 IP',
                    key: 'related_ips',
                    render: (_, record) => {
                        const host = extractHostFromTarget(record.Target);
                        const ips = relatedHostsFor(host).filter((item) => ipv4Pattern.test(item));
                        if (ips.length === 0) return <Text type="secondary">-</Text>;
                        return (
                            <Space size={4} wrap>
                                {ips.map((ip) => (
                                    <Tag key={ip} style={{ margin: 0, fontFamily: "'JetBrains Mono', monospace" }}>{ip}</Tag>
                                ))}
                            </Space>
                        );
                    },
                },
                createdAtColumn,
                lineageActionColumn,
            ];
        }
        return [
            hostColumn,
            cdnColumn,
            protocolColumn,
            {
                title: '标题',
                dataIndex: 'Title',
                key: 'title',
                ellipsis: { showTitle: false },
                render: (v: string) => v
                    ? <Tooltip title={v}><Text style={{ fontSize: 12 }}>{v}</Text></Tooltip>
                    : <Text type="secondary">-</Text>,
            },
            createdAtColumn,
            lineageActionColumn,
        ];
    };

    const fpColumns: ColumnsType<API.FingerprintGroup> = [
        {
            title: '产品名称',
            dataIndex: 'ProductName',
            key: 'product_name',
            width: 280,
            render: (v: string, record) => (
                <Space size={4} wrap>
                    <Tag color="cyan">{v}</Tag>
                    {fingerprintGroupSources(record).map((source) => (
                        <Tag key={source} color={fingerprintSourceColor(source)} style={{ margin: 0 }}>
                            {fingerprintSourceLabel(source)}
                        </Tag>
                    ))}
                </Space>
            ),
        },
        {
            title: '命中数',
            dataIndex: 'TargetCount',
            key: 'target_count',
            width: 110,
            sorter: (a, b) => (a.TargetCount || 0) - (b.TargetCount || 0),
            defaultSortOrder: 'descend',
            render: (v: number) => <Tag color="blue">{v || 0}</Tag>,
        },
        {
            title: '目标',
            key: 'targets',
            render: (_, record) => {
                const targets = record.Targets || [];
                if (targets.length === 0) return <Text type="secondary">-</Text>;
                return (
                    <div style={{ maxHeight: 180, overflow: 'auto', display: 'grid', gap: 6 }}>
                        {targets.map((target, index) => {
                            const displayURL = target.MatchedURL || target.Target;
                            return (
                                <Space key={`${displayURL}-${index}`} size={6} wrap>
                                    <Text
                                        copyable={{ text: displayURL }}
                                        style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12 }}
                                    >
                                        {displayURL}
                                    </Text>
                                    {target.Source && (
                                        <Tag color={fingerprintSourceColor(target.Source)} style={{ margin: 0, fontSize: 11 }}>
                                            {fingerprintSourceLabel(target.Source, target.SourceLabel)}
                                        </Tag>
                                    )}
                                    {target.RuleName && target.RuleName !== 'Finger' && target.RuleName !== 'Active-Finger' && (
                                        <Tag color="default">{target.RuleName}</Tag>
                                    )}
                                    {target.Evidence && (
                                        <Popover
                                            content={<pre style={{ maxWidth: 520, maxHeight: 320, overflow: 'auto', fontSize: 11, margin: 0 }}>{target.Evidence}</pre>}
                                            title="匹配证据"
                                            trigger="hover"
                                        >
                                            <Tag color="geekblue" style={{ cursor: 'pointer', margin: 0, fontSize: 11 }}>证据</Tag>
                                        </Popover>
                                    )}
                                    <Button type="link" size="small" style={{ padding: 0 }} onClick={() => handleViewAssets(target.Target)}>看资产</Button>
                                    <Button type="link" size="small" style={{ padding: 0 }} onClick={() => handleViewVulns(target.Target)}>看漏洞</Button>
                                </Space>
                            );
                        })}
                    </div>
                );
            },
        },
        {
            title: '最近发现',
            dataIndex: 'LastSeen',
            key: 'last_seen',
            width: 170,
            render: (v: string) => {
                if (!v) return '-';
                return <Text style={{ fontSize: 12, color: '#64748b' }}>{dayjs(v).format('YYYY-MM-DD HH:mm:ss')}</Text>;
            },
        },
    ];

    const cardStyle = {
        background: 'transparent',
        border: 'none'
    };

    // Severity statistics
    const severityStats = vulns.reduce((acc, v) => {
        const severity = normalizeSeverity(v.Severity);
        acc[severity] = (acc[severity] || 0) + 1;
        return acc;
    }, {} as Record<string, number>);

    return (
        <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
                <Space>
                    <Button icon={<ArrowLeftOutlined />} onClick={() => navigate('/tasks')}>返回</Button>
                    <Title level={4} style={{ margin: 0, color: '#1e293b', fontWeight: 600 }}>
                        扫描结果
                    </Title>
                    {taskId && (
                        <Tag color="blue" style={{ fontFamily: 'monospace', fontSize: 11 }}>
                            {taskId}
                        </Tag>
                    )}
                </Space>
                <Space>
                    {/* Severity breakdown */}
                    {Object.entries(severityStats).map(([severity, count]) => {
                        return (
                            <Tag key={severity} color={getSeverityColor(severity)}>
                                当前页 {severity}: {count}
                            </Tag>
                        );
                    })}
                    <Tag color="blue"><GlobalOutlined /> 资产 {assetTotal}</Tag>
                    <Tag color="cyan"><ScanOutlined /> 指纹 {fingerprintPagination.total}</Tag>
                    <Button icon={<ReloadOutlined />} onClick={fetchCurrentPages} loading={loading}>刷新</Button>
                    <Button icon={<DownloadOutlined />} onClick={handleExport}>导出 CSV</Button>
                </Space>
            </div>

            <ProCard className="glass-card" style={cardStyle}>
                {loading ? (
                    <div style={{ display: 'flex', justifyContent: 'center', padding: '60px 0' }}>
                        <Spin size="large" />
                    </div>
                ) : vulnPagination.total === 0 && assetTotal === 0 && fingerprintPagination.total === 0 && contentFindingsTotal === 0 ? (
                    <Empty description="暂无扫描结果" style={{ padding: '60px 0' }} />
                ) : (
                    <Tabs
                        activeKey={activeTab}
                        onChange={(key) => setActiveTab(key as ResultTabKey)}
                        items={[
                            {
                                key: 'vulns',
                                label: <span><BugOutlined /> 漏洞 ({vulnPagination.total})</span>,
                                children: (
                                    <>
                                        {vulnSearch && (
                                            <Alert
                                                type="info"
                                                showIcon
                                                style={{ marginBottom: 12 }}
                                                message={(
                                                    <Space size={8}>
                                                        <span>已按关键词 <Text code>{vulnSearch}</Text> 过滤</span>
                                                        <Button type="link" size="small" style={{ padding: 0 }} onClick={clearVulnFilter}>清除过滤</Button>
                                                    </Space>
                                                )}
                                            />
                                        )}
                                        <div className="result-filter-bar">
                                            <Select
                                                aria-label="漏洞筛选字段"
                                                value={vulnFilterField}
                                                style={{ width: 145, flexShrink: 0 }}
                                                onChange={handleVulnFieldChange}
                                                options={[
                                                    { label: '漏洞名称', value: 'plugin' },
                                                    { label: '危害等级', value: 'severity' },
                                                    { label: '处理状态', value: 'status' },
                                                    { label: 'AI 研判', value: 'aiStatus' },
                                                    { label: '主机', value: 'host' },
                                                    { label: '端口', value: 'port' },
                                                    { label: '关键词', value: 'search' },
                                                ]}
                                            />
                                            {vulnFilterField === 'search' ? (
                                                <Input.Search
                                                    allowClear
                                                    placeholder="输入目标 / CVE / 描述，回车过滤"
                                                    value={vulnSearch}
                                                    onChange={(event) => setVulnSearch(event.target.value)}
                                                    onSearch={(value) => {
                                                        const next = value.trim();
                                                        vulnSearchRef.current = next;
                                                        setVulnSearch(next);
                                                        setVulnPagination(prev => ({ ...prev, current: 1 }));
                                                        void fetchVulnsPage(1, vulnPagination.pageSize);
                                                        void fetchVulnFacets();
                                                    }}
                                                    style={{ flex: 1, minWidth: 240 }}
                                                />
                                            ) : (
                                                <Select
                                                    mode="tags"
                                                    allowClear
                                                    showSearch
                                                    placeholder="选择或输入筛选值，可用 !值 排除"
                                                    aria-label="漏洞筛选值"
                                                    style={{ flex: 1, minWidth: 240 }}
                                                    maxTagCount="responsive"
                                                    value={vulnValueByField[vulnFilterField]}
                                                    onChange={(values) => {
                                                        if (vulnFilterField === 'severity' && values.includes('info')) {
                                                            clearVulnDimensions();
                                                            vulnSeverityViewRef.current = 'info';

                                                            refreshVulnFilter();
                                                            return;
                                                        }
                                                        vulnSeverityViewRef.current = 'vulns';

                                                        handleVulnFilterChange(vulnFilterField, values);
                                                    }}
                                                    options={vulnFacetByField[vulnFilterField].map(({ value, count }) => ({
                                                        label: `${value}${count ? ` (${count})` : ''}`,
                                                        value,
                                                    }))}
                                                />
                                            )}
                                            {(vulnValueByField[vulnFilterField].some(value => value.length > 0) || (vulnFilterField === 'search' && vulnSearch.length > 0)) && (
                                                <Button type="link" onClick={() => {
                                                    clearVulnDimensions();
                                                    vulnSeverityViewRef.current = 'vulns';

                                                    refreshVulnFilter();
                                                }}>清除条件</Button>
                                            )}
                                        </div>
                                        <ResultTable
                                            bordered
                                            columns={vulnColumns}
                                            dataSource={vulns}
                                            rowKey="ID"
                                            loading={tabLoading.vulns}
                                        pagination={{
                                            current: vulnPagination.current,
                                            pageSize: vulnPagination.pageSize,
                                            total: vulnPagination.total,
                                            showSizeChanger: true,
                                            pageSizeOptions: ['10', '20', '50', '100', '200'],
                                            showTotal: (t) => `共 ${t} 条`,
                                        }}
                                        onChange={(pagination, _filters, sorter) => {
                                            const sort = Array.isArray(sorter) ? sorter[0] : sorter;
                                            const sortField = sort?.field ? VULN_SORT_FIELD_MAP[String(sort.field)] : undefined;
                                            const sortOrder: 'asc' | 'desc' | undefined = sort?.order === 'ascend' ? 'asc' : sort?.order === 'descend' ? 'desc' : undefined;
                                            const nextSort = { field: sortField, order: sortOrder };
                                            setVulnSort(nextSort);
                                            vulnSortRef.current = nextSort;
                                            fetchVulnsPage(
                                                pagination.current || 1,
                                                pagination.pageSize || DEFAULT_RESULT_PAGE_SIZE,
                                                sortField,
                                                sortOrder,
                                            );
                                        }}
                                        size="middle"
                                        onRow={(record) => ({
                                            onClick: () => handleVulnClick(record),
                                            style: { cursor: 'pointer' },
                                        })}
                                        rowClassName={(_, index) => index % 2 === 1 ? 'table-row-light' : 'table-row-dark'}
                                    />
                                    </>
                                ),
                            },
                            {
                                key: 'assets',
                                label: <span><GlobalOutlined /> 资产 ({assetTotal})</span>,
                                children: (
                                    <>
                                        <Space wrap style={{ marginBottom: 12 }}>
                                            <Input.Search
                                                allowClear
                                                placeholder="搜索目标/URL/标题/服务"
                                                defaultValue={assetSearch}
                                                onSearch={(value) => {
                                                    const nextSearch = value.trim();
                                                    assetSearchRef.current = nextSearch;
                                                    setAssetSearch(nextSearch);
                                                    setAssetPagination(prev => ({ ...prev, current: 1 }));
                                                    void fetchAssetsPage(1, assetPagination.pageSize || DEFAULT_RESULT_PAGE_SIZE, assetKind);
                                                    void fetchAssetFacets(assetKind);
                                                }}
                                                style={{ width: 240 }}
                                            />
                                            <Select
                                                mode="multiple"
                                                allowClear
                                                placeholder="按服务过滤"
                                                style={{ minWidth: 200 }}
                                                maxTagCount={2}
                                                value={assetServiceFilter}
                                                onChange={(values) => handleAssetFilterChange('service', values)}
                                                options={assetFacets.services.map(s => ({ label: `${s.value} (${s.count})`, value: s.value }))}
                                            />
                                            <Select
                                                mode="multiple"
                                                allowClear
                                                placeholder="按指纹过滤"
                                                style={{ minWidth: 200 }}
                                                maxTagCount={2}
                                                value={assetFingerprintFilter.filter(v => !v.startsWith('!'))}
                                                onChange={(values) => handleAssetFilterChange('fingerprint', values)}
                                                options={assetFacets.fingerprints.map(f => ({ label: `${f.value} (${f.count})`, value: f.value }))}
                                            />
                                        </Space>
                                        {hasAssetFilters && (
                                            <Alert
                                                type="info"
                                                showIcon
                                                style={{ marginBottom: 12 }}
                                                message={(
                                                    <Space size={8} wrap>
                                                        {renderAssetFilterChips()}
                                                        <Button type="link" size="small" style={{ padding: 0 }} onClick={clearAssetFilter}>清除全部过滤</Button>
                                                    </Space>
                                                )}
                                            />
                                        )}
                                    <Tabs
                                        size="small"
                                        activeKey={assetKind}
                                        onChange={(key) => {
                                            const nextKind = key as AssetKind;
                                            setAssetKind(nextKind);
                                            fetchAssetsPage(1, assetPagination.pageSize || DEFAULT_RESULT_PAGE_SIZE, nextKind);
                                            void fetchAssetFacets(nextKind);
                                        }}
                                        items={visibleAssetKinds(assetKindCounts).map((kind) => ({
                                            key: kind,
                                            label: `${ASSET_KIND_LABELS[kind]} (${assetKindCount(assetKindCounts, kind)})`,
                                            children: (
                                                <ResultTable
                                                    bordered
                                                    columns={assetColumnsForKind(kind)}
                                                    dataSource={kind === assetKind ? assets : []}
                                                    rowKey="ID"
                                                    loading={tabLoading.assets}
                                                    pagination={{
                                                        current: assetPagination.current,
                                                        pageSize: assetPagination.pageSize,
                                                        total: assetPagination.total,
                                                        showSizeChanger: true,
                                                        pageSizeOptions: ['10', '20', '50', '100', '200'],
                                                        showTotal: (t) => `共 ${t} 条`,
                                                        onChange: (page, pageSize) => fetchAssetsPage(page, pageSize, kind),
                                                    }}
                                                    size="middle"
                                                    rowClassName={(_, index) => index % 2 === 1 ? 'table-row-light' : 'table-row-dark'}
                                                />
                                            ),
                                        }))}
                                    />
                                    </>
                                ),
                            },
                            {
                                key: 'fingerprints',
                                label: <span><ScanOutlined /> 指纹 ({fingerprintPagination.total})</span>,
                                children: (
                                    <Space direction="vertical" size={12} style={{ width: '100%' }}>
                                        <Space wrap>
                                            <Input.Search
                                                allowClear
                                                placeholder="搜索产品名称或 URL"
                                                defaultValue={fingerprintSearch}
                                                onSearch={(value) => {
                                                    const nextSearch = value.trim();
                                                    setFingerprintSearch(nextSearch);
                                                    fetchFingerprintsPage(1, fingerprintPagination.pageSize || DEFAULT_RESULT_PAGE_SIZE, nextSearch, fingerprintSource);
                                                }}
                                                style={{ width: 280 }}
                                            />
                                            <Select
                                                value={fingerprintSource}
                                                options={FINGERPRINT_SOURCE_FILTERS}
                                                style={{ width: 220 }}
                                                onChange={(value) => {
                                                    const nextSource = value as '' | FingerprintSource;
                                                    setFingerprintSource(nextSource);
                                                    fetchFingerprintsPage(1, fingerprintPagination.pageSize || DEFAULT_RESULT_PAGE_SIZE, fingerprintSearch, nextSource);
                                                }}
                                            />
                                            <Space size={8} wrap>
                                                <Tag>产品种类 {fingerprintPagination.total}</Tag>
                                                <Tag color="blue">命中总数 {fingerprintStats ? fingerprintStats.total_hits : '-'}</Tag>
                                                <Tag color="cyan">涉及目标 {fingerprintStats ? fingerprintStats.distinct_targets : '-'}</Tag>
                                                <Tag color="geekblue">当前页命中 {fingerprints.reduce((sum, f) => sum + (f.TargetCount || 0), 0)}</Tag>
                                            </Space>
                                        </Space>
                                        <ResultTable
                                            bordered
                                            columns={fpColumns}
                                            dataSource={fingerprints}
                                            rowKey="ProductName"
                                            loading={tabLoading.fingerprints}
                                            pagination={{
                                                current: fingerprintPagination.current,
                                                pageSize: fingerprintPagination.pageSize,
                                                total: fingerprintPagination.total,
                                                showSizeChanger: true,
                                                pageSizeOptions: ['10', '20', '50', '100', '200'],
                                                showTotal: (t) => `共 ${t} 条`,
                                                onChange: (page, pageSize) => fetchFingerprintsPage(page, pageSize, fingerprintSearch, fingerprintSource),
                                            }}
                                            size="middle"
                                            rowClassName={(_, index) => index % 2 === 1 ? 'table-row-light' : 'table-row-dark'}
                                        />
                                    </Space>
                                ),
                            },
                            {
                                key: 'content',
                                label: <span><FileTextOutlined /> 内容分析 ({contentFindingsTotal})</span>,
                                children: <ContentFindingsPanel taskId={taskId} active={activeTab === 'content'} />,
                            },
                        ]}
                    />
                )}
            </ProCard>

            {/* 漏洞详情 Drawer */}
            <Drawer
                title={
                    <Space>
                        <BugOutlined style={{ color: getSeverityColor(selectedVuln?.Severity || '') }} />
                        <span>漏洞详情</span>
                        {selectedVuln && <Tag color={getSeverityColor(selectedVuln.Severity)}>{normalizeSeverity(selectedVuln.Severity)}</Tag>}
                    </Space>
                }
                open={drawerOpen}
                onClose={() => setDrawerOpen(false)}
                width={860}
                destroyOnClose
            >
                {selectedVuln && (
                    <div>
                        <Descriptions column={2} bordered size="small">
                            <Descriptions.Item label="插件 / 模板" span={2}>
                                <Text strong copyable>{selectedVuln.Plugin}</Text>
                            </Descriptions.Item>
                            <Descriptions.Item label="目标">
                                <Text copyable style={{ fontFamily: 'monospace' }}>{selectedVuln.Target}</Text>
                            </Descriptions.Item>
                            <Descriptions.Item label="危害等级">
                                <Tag color={getSeverityColor(selectedVuln.Severity)}>
                                    {normalizeSeverity(selectedVuln.Severity)}
                                </Tag>
                            </Descriptions.Item>
                            {selectedVuln.MatchedAt && (
                                <Descriptions.Item label="匹配位置" span={2}>
                                    <a href={selectedVuln.MatchedAt} target="_blank" rel="noopener noreferrer">
                                        <LinkOutlined /> {selectedVuln.MatchedAt}
                                    </a>
                                </Descriptions.Item>
                            )}
                            <Descriptions.Item label="发现时间" span={2}>
                                {selectedVuln.CreatedAt ? dayjs(selectedVuln.CreatedAt).format('YYYY-MM-DD HH:mm:ss') : '-'}
                            </Descriptions.Item>
                        </Descriptions>

                        <VulnAITriagePanel
                            vuln={selectedVuln}
                            onChanged={() => fetchVulnsPage(vulnPagination.current, vulnPagination.pageSize)}
                        />

                        {selectedVuln.Description && (
                            <>
                                <Divider orientation="left" style={{ fontSize: 13 }}>漏洞描述</Divider>
                                <div style={{
                                    background: '#f8fafc', border: '1px solid #e2e8f0',
                                    borderRadius: 8, padding: '12px 16px', whiteSpace: 'pre-wrap',
                                    fontSize: 13, lineHeight: 1.6, color: '#334155',
                                }}>
                                    {selectedVuln.Description}
                                </div>
                            </>
                        )}

                        {parseReferences(selectedVuln.Reference).length > 0 && (
                            <>
                                <Divider orientation="left" style={{ fontSize: 13 }}>参考链接</Divider>
                                <ul style={{ paddingLeft: 20 }}>
                                    {parseReferences(selectedVuln.Reference).map((ref, i) => (
                                        <li key={i} style={{ marginBottom: 4 }}>
                                            <a href={ref} target="_blank" rel="noopener noreferrer" style={{ fontSize: 13 }}>
                                                {ref}
                                            </a>
                                        </li>
                                    ))}
                                </ul>
                            </>
                        )}

                        {(selectedVuln.Request || selectedVuln.Response) && (
                            <>
                                <Divider orientation="left" style={{ fontSize: 13 }}>
                                    <SendOutlined /> 请求 / <CloudDownloadOutlined /> 响应
                                </Divider>
                                <div style={{ display: 'flex', gap: 12 }}>
                                    {/* 请求包 */}
                                    <div style={{ flex: 1, minWidth: 0 }}>
                                        <div style={{
                                            background: '#0f172a', color: '#4ade80',
                                            borderRadius: '8px 8px 0 0', padding: '8px 12px',
                                            fontSize: 12, fontWeight: 600, display: 'flex',
                                            alignItems: 'center', gap: 6,
                                        }}>
                                            <SendOutlined /> Request
                                        </div>
                                        <pre style={{
                                            background: '#1e293b', color: '#e2e8f0',
                                            margin: 0, padding: 12, borderRadius: '0 0 8px 8px',
                                            fontSize: 12, lineHeight: 1.5, fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
                                            whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                                            maxHeight: 400, overflow: 'auto',
                                            border: '1px solid #334155', borderTop: 'none',
                                        }}>
                                            {selectedVuln.Request || '(无请求数据)'}
                                        </pre>
                                    </div>
                                    {/* 响应包 */}
                                    <div style={{ flex: 1, minWidth: 0 }}>
                                        <div style={{
                                            background: '#0f172a', color: '#fb923c',
                                            borderRadius: '8px 8px 0 0', padding: '8px 12px',
                                            fontSize: 12, fontWeight: 600, display: 'flex',
                                            alignItems: 'center', gap: 6,
                                        }}>
                                            <CloudDownloadOutlined /> Response
                                        </div>
                                        <pre style={{
                                            background: '#1e293b', color: '#e2e8f0',
                                            margin: 0, padding: 12, borderRadius: '0 0 8px 8px',
                                            fontSize: 12, lineHeight: 1.5, fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
                                            whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                                            maxHeight: 400, overflow: 'auto',
                                            border: '1px solid #334155', borderTop: 'none',
                                        }}>
                                            {selectedVuln.Response || '(无响应数据)'}
                                        </pre>
                                    </div>
                                </div>
                            </>
                        )}

                        {selectedVuln.Payload && (
                            <>
                                <Divider orientation="left" style={{ fontSize: 13 }}>原始 Payload</Divider>
                                <pre style={{
                                    background: '#f1f5f9', border: '1px solid #e2e8f0',
                                    borderRadius: 8, padding: 12, fontSize: 11, maxHeight: 200,
                                    overflow: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                                }}>
                                    {(() => {
                                        try { return JSON.stringify(JSON.parse(selectedVuln.Payload), null, 2); }
                                        catch { return selectedVuln.Payload; }
                                    })()}
                                </pre>
                            </>
                        )}

                    </div>
                )}
            </Drawer>

            {/* 扫描链路溯源 Drawer */}
            <Drawer
                title={
                    <Space>
                        <PartitionOutlined style={{ color: '#1677ff' }} />
                        <span>资产溯源</span>
                        {lineageTitle && <Text type="secondary" style={{ fontSize: 12, fontFamily: 'monospace' }}>{lineageTitle}</Text>}
                    </Space>
                }
                open={lineageDrawerOpen}
                onClose={() => setLineageDrawerOpen(false)}
                width={480}
                destroyOnClose
            >
                <Spin spinning={lineageLoading}>
                    {lineageNodes.length === 0 && !lineageLoading ? (
                        <Empty description="暂无链路数据（仅新扫描产生的资产含溯源信息）" />
                    ) : (
                        <Steps
                            direction="vertical"
                            current={lineageNodes.length - 1}
                            items={lineageNodes.map((node, index) => {
                                const isLast = index === lineageNodes.length - 1;
                                const icon = node.node_type === 'input'
                                    ? <NodeIndexOutlined />
                                    : node.node_type === 'vulnerability'
                                        ? <BugOutlined />
                                        : node.node_type === 'fingerprint'
                                            ? <ScanOutlined />
                                            : <GlobalOutlined />;
                                const title = node.node_type === 'input' ? '扫描起点' : (node.stage || node.node_type);
                                return {
                                    icon,
                                    title: (
                                        <Text strong={isLast} style={{ fontSize: 13 }}>
                                            {title}
                                        </Text>
                                    ),
                                    description: node.target
                                        ? (
                                            <Text copyable={{ text: node.target }} style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12 }}>
                                                {node.target}
                                            </Text>
                                        )
                                        : (
                                            <Text type="secondary" style={{ fontSize: 12 }}>原始扫描输入</Text>
                                        ),
                                };
                            })}
                        />
                    )}
                </Spin>
            </Drawer>
        </div>
    );
};

export default TaskResults;
