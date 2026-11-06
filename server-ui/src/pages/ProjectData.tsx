import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { Alert, Button, Input, Select, Space, Table, Tabs, Tag, Typography, message } from 'antd';
import { ArrowLeftOutlined, DownloadOutlined, ImportOutlined, ReloadOutlined } from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import {
    exportProjectData,
    getAssets,
    getDomains,
    getFingerprints,
    getVulns,
} from '../services/api';
import {
    PROJECT_DATA_TAB_LABELS,
    PROJECT_DATA_TABS,
    parseProjectDataState,
    toSearchParams,
    updateProjectDataState,
} from './projectDataState';
import type { ProjectDataState } from './projectDataState';
import { ASSET_KIND_LABELS, FINGERPRINT_SOURCE_FILTERS } from './taskResultTabs';
import type { AssetKind } from './taskResultTabs';
import { canAccessRole, getCurrentUserRole } from '../utils/auth';
import ProjectDataImportModal from '../components/ProjectDataImportModal';

const { Title, Text } = Typography;

const SEVERITY_OPTIONS = ['Critical', 'High', 'Medium', 'Low', 'Info'];

function normalizeSeverity(s?: string): string {
    const v = (s || '').trim().toLowerCase();
    const found = SEVERITY_OPTIONS.find((x) => x.toLowerCase() === v);
    return found || 'Unknown';
}

function severityColor(s: string): string {
    switch (normalizeSeverity(s)) {
        case 'Critical': return 'red';
        case 'High': return 'volcano';
        case 'Medium': return 'orange';
        case 'Low': return 'gold';
        case 'Info': return 'blue';
        default: return 'default';
    }
}

function formatTime(v?: string): string {
    if (!v) return '-';
    const d = new Date(v);
    return Number.isNaN(d.getTime()) ? v : d.toLocaleString();
}

export default function ProjectData() {
    const { projectId } = useParams<{ projectId: string }>();
    const navigate = useNavigate();
    const [searchParams, setSearchParams] = useSearchParams();
    const state = useMemo(() => parseProjectDataState(searchParams), [searchParams]);

    const [items, setItems] = useState<unknown[]>([]);
    const [total, setTotal] = useState(0);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [refreshKey, setRefreshKey] = useState(0);
    const [importOpen, setImportOpen] = useState(false);
    const [exporting, setExporting] = useState(false);

    const role = getCurrentUserRole();
    const canImport = canAccessRole('operator', role);

    const update = useCallback((patch: Partial<ProjectDataState>) => {
        setSearchParams(toSearchParams(updateProjectDataState(state, patch)), { replace: true });
    }, [state, setSearchParams]);

    useEffect(() => {
        if (!projectId) return;
        let live = true;
        (async () => {
            setLoading(true);
            setError('');
            try {
                const params = {
                    projectId,
                    page: state.page,
                    pageSize: state.pageSize,
                    sort: state.sort,
                    order: state.order,
                    search: state.search,
                    kind: state.tab === 'assets' ? state.kind : undefined,
                    severity: state.tab === 'vulns' ? state.severity : undefined,
                    source: state.tab === 'fingerprints' ? state.source : undefined,
                };
                let res: { items?: unknown[]; total?: number };
                switch (state.tab) {
                    case 'vulns': res = await getVulns(params); break;
                    case 'fingerprints': res = await getFingerprints(params); break;
                    case 'domains': res = await getDomains(params); break;
                    default: res = await getAssets(params);
                }
                if (live) {
                    setItems(res.items || []);
                    setTotal(res.total || 0);
                }
            } catch (e) {
                if (live) {
                    setItems([]);
                    setTotal(0);
                    setError(e instanceof Error ? e.message : String(e));
                }
            } finally {
                if (live) setLoading(false);
            }
        })();
        return () => {
            live = false;
        };
    }, [state, projectId, refreshKey]);

    const handleExport = async () => {
        if (!projectId) return;
        setExporting(true);
        try {
            const blob = await exportProjectData(projectId);
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `project-${projectId}.argus.json.gz`;
            document.body.appendChild(a);
            a.click();
            a.remove();
            URL.revokeObjectURL(url);
        } catch (e) {
            message.error(`导出失败：${e instanceof Error ? e.message : e}`);
        } finally {
            setExporting(false);
        }
    };

    const handleTableChange = (pagination: { current?: number; pageSize?: number }, _filters: unknown, sorter: unknown) => {
        const s = Array.isArray(sorter) ? sorter[0] : (sorter as { field?: unknown; order?: unknown });
        const sortField = s?.field ? String(s.field) : undefined;
        const order = s?.order === 'ascend' ? ('asc' as const) : s?.order === 'descend' ? ('desc' as const) : undefined;
        update({
            page: pagination.current || 1,
            pageSize: pagination.pageSize || 20,
            sort: sortField,
            order,
        });
    };

    const columns = useMemo<ColumnsType<never>>(() => {
        switch (state.tab) {
            case 'vulns':
                return [
                    {
                        title: '目标',
                        dataIndex: 'Target',
                        key: 'target',
                        render: (v: string) => <Text style={{ fontSize: 12 }}>{v}</Text>,
                    },
                    {
                        title: '插件',
                        dataIndex: 'Plugin',
                        key: 'plugin',
                        render: (v: string) => <Tag>{v}</Tag>,
                    },
                    {
                        title: '危害等级',
                        dataIndex: 'Severity',
                        key: 'severity',
                        sorter: true,
                        sortOrder: state.sort === 'severity' ? (state.order === 'asc' ? 'ascend' : 'descend') : null,
                        render: (v: string) => <Tag color={severityColor(v)}>{normalizeSeverity(v)}</Tag>,
                    },
                    {
                        title: '状态',
                        dataIndex: 'Status',
                        key: 'status',
                        render: (v: string) => v || '-',
                    },
                    {
                        title: '发现时间',
                        dataIndex: 'CreatedAt',
                        key: 'created_at',
                        sorter: true,
                        sortOrder: state.sort === 'created_at' ? (state.order === 'asc' ? 'ascend' : 'descend') : null,
                        render: (v: string) => formatTime(v),
                    },
                ] as ColumnsType<never>;
            case 'fingerprints':
                return [
                    { title: '目标', dataIndex: 'Target', key: 'target' },
                    { title: '产品', dataIndex: 'ProductName', key: 'product', render: (v: string) => <Tag color="geekblue">{v}</Tag> },
                    { title: '规则', dataIndex: 'RuleName', key: 'rule', render: (v: string) => <Text type="secondary" style={{ fontSize: 12 }}>{v}</Text> },
                    { title: '发现时间', dataIndex: 'CreatedAt', key: 'created_at', render: (v: string) => formatTime(v) },
                ] as ColumnsType<never>;
            case 'domains':
                return [
                    { title: '域名', dataIndex: 'Name', key: 'name' },
                    { title: 'ICP', dataIndex: 'ICP', key: 'icp', render: (v: string) => v || '-' },
                    { title: '状态', dataIndex: 'Status', key: 'status', render: (v: string) => <Tag>{v || 'alive'}</Tag> },
                    { title: '发现时间', dataIndex: 'CreatedAt', key: 'created_at', render: (v: string) => formatTime(v) },
                ] as ColumnsType<never>;
            default:
                return [
                    { title: '目标', dataIndex: 'Target', key: 'target', render: (v: string) => <Text style={{ fontSize: 12 }}>{v}</Text> },
                    {
                        title: '类型',
                        dataIndex: 'Protocol',
                        key: 'protocol',
                        render: (v: string) => <Tag style={{ margin: 0, fontSize: 11 }}>{v}</Tag>,
                    },
                    { title: '端口', dataIndex: 'Port', key: 'port', width: 80, render: (v: number) => v || '-' },
                    { title: '标题', dataIndex: 'Title', key: 'title', render: (v: string) => v || '-' },
                    { title: '服务', dataIndex: 'Service', key: 'service', render: (v: string) => v || '-' },
                    { title: '发现时间', dataIndex: 'CreatedAt', key: 'created_at', render: (v: string) => formatTime(v) },
                ] as ColumnsType<never>;
        }
    }, [state.tab, state.sort, state.order]);

    const filterBar = (
        <Space wrap style={{ marginBottom: 12 }}>
            <Input.Search
                allowClear
                placeholder="搜索"
                style={{ width: 240 }}
                defaultValue={state.search}
                onSearch={(v) => update({ search: v.trim() || undefined })}
            />
            {state.tab === 'assets' && (
                <Select
                    allowClear
                    placeholder="资产类型"
                    style={{ width: 140 }}
                    value={state.kind}
                    onChange={(v) => update({ kind: v })}
                    options={(Object.keys(ASSET_KIND_LABELS) as AssetKind[]).map((k) => ({ value: k, label: ASSET_KIND_LABELS[k] }))}
                />
            )}
            {state.tab === 'vulns' && (
                <Select
                    allowClear
                    placeholder="危害等级"
                    style={{ width: 130 }}
                    value={state.severity}
                    onChange={(v) => update({ severity: v })}
                    options={SEVERITY_OPTIONS.map((s) => ({ value: s.toLowerCase(), label: s }))}
                />
            )}
            {state.tab === 'fingerprints' && (
                <Select
                    allowClear
                    placeholder="来源"
                    style={{ width: 130 }}
                    value={state.source}
                    onChange={(v) => update({ source: v })}
                    options={FINGERPRINT_SOURCE_FILTERS.filter((o) => o.value).map((o) => ({ value: o.value, label: o.label }))}
                />
            )}
        </Space>
    );

    return (
        <div style={{ padding: 16 }}>
            <Space style={{ marginBottom: 12 }} wrap>
                <Button icon={<ArrowLeftOutlined />} onClick={() => navigate('/projects')}>返回项目</Button>
                <Title level={4} style={{ margin: 0 }}>项目数据</Title>
                <Text type="secondary">{projectId}</Text>
            </Space>
            <Space style={{ marginBottom: 12, display: 'flex', justifyContent: 'flex-end' }} wrap>
                <Button icon={<ReloadOutlined />} onClick={() => setRefreshKey((k) => k + 1)}>刷新</Button>
                <Button icon={<DownloadOutlined />} loading={exporting} onClick={handleExport}>导出</Button>
                {canImport && (
                    <Button type="primary" icon={<ImportOutlined />} onClick={() => setImportOpen(true)}>导入</Button>
                )}
            </Space>
            {error && <Alert type="error" message={error} style={{ marginBottom: 12 }} showIcon />}
            <Tabs
                activeKey={state.tab}
                onChange={(key) => update({ tab: key as ProjectDataState['tab'] })}
                items={PROJECT_DATA_TABS.map((tab) => ({ key: tab, label: PROJECT_DATA_TAB_LABELS[tab] }))}
            />
            {filterBar}
            <Table
                bordered
                columns={columns}
                dataSource={items as never[]}
                rowKey={(record) => String((record as { ID?: number }).ID ?? JSON.stringify(record))}
                loading={loading}
                pagination={{
                    current: state.page,
                    pageSize: state.pageSize,
                    total,
                    showSizeChanger: true,
                    pageSizeOptions: ['10', '20', '50', '100', '200'],
                    showTotal: (t) => `共 ${t} 条`,
                }}
                onChange={handleTableChange}
                size="middle"
            />
            <ProjectDataImportModal
                open={importOpen}
                onClose={() => setImportOpen(false)}
                mergeProjectId={projectId}
                onImported={() => setRefreshKey((k) => k + 1)}
            />
        </div>
    );
}
