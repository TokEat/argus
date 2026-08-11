import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
    Alert,
    App,
    AutoComplete,
    Button,
    Card,
    Descriptions,
    Drawer,
    Empty,
    Input,
    Select,
    Space,
    Table,
    Tag,
    Typography,
} from 'antd';
import {
    DownloadOutlined,
    EyeOutlined,
    GlobalOutlined,
    LinkOutlined,
    ReloadOutlined,
    SearchOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import dayjs from 'dayjs';
import { listProjects } from '../services/api';
import { canAccessRole } from '../utils/auth';
import {
    exportProjectAssetDiscoveryQuery,
    getProjectAssetDiscoveryQuery,
    archiveProjectAssetDiscoveryNotebookItems,
    listProjectAssetDiscoveryQueries,
    queryProjectAssetDiscovery,
} from '../features/assetDiscovery/api';
import NotebookDistributionPreview from '../features/assetDiscovery/NotebookDistributionPreview';
import {
    appendAssetDiscoveryField,
    assetDiscoverySyntaxCatalog,
    getAssetDiscoveryCompletions,
} from '../features/assetDiscovery/syntaxCatalog';

const { Paragraph, Text, Title } = Typography;

const providerOptions: { label: string; value: API.AssetDiscoveryProvider }[] = [
    { label: 'FOFA', value: 'fofa' },
    { label: 'Hunter', value: 'hunter' },
    { label: 'Quake', value: 'quake' },
];

const providerColor: Record<string, string> = {
    fofa: 'blue',
    hunter: 'cyan',
    quake: 'purple',
};

const queryPlaceholders: Record<API.AssetDiscoveryProvider, string> = {
    fofa: '例如：domain="example.com"',
    hunter: '例如：domain="example.com"',
    quake: '例如：domain:"example.com"',
};

const AssetDiscovery: React.FC = () => {
    const { message } = App.useApp();
    const canQuery = canAccessRole('operator');
    const [projects, setProjects] = useState<API.Project[]>([]);
    const [projectLoading, setProjectLoading] = useState(true);
    const [projectId, setProjectId] = useState('');
    const [queryProvider, setQueryProvider] = useState<API.AssetDiscoveryProvider>('fofa');
    const [expression, setExpression] = useState('');
    const [completionOpen, setCompletionOpen] = useState(false);
    const [completionIndex, setCompletionIndex] = useState(-1);
    const [querying, setQuerying] = useState(false);
    const [history, setHistory] = useState<API.AssetDiscoveryQueryHistory | null>(null);
    const [historyLoading, setHistoryLoading] = useState(false);
    const [historyProvider, setHistoryProvider] = useState<API.AssetDiscoveryProvider | undefined>();
    const [historyPage, setHistoryPage] = useState(1);
    const [historyPageSize, setHistoryPageSize] = useState(20);
    const [detailOpen, setDetailOpen] = useState(false);
    const [detailLoading, setDetailLoading] = useState(false);
    const [selectedQuery, setSelectedQuery] = useState<API.AssetDiscoveryQuerySummary | null>(null);
    const [detail, setDetail] = useState<API.AssetDiscoveryQueryDetail | null>(null);
    const [preview, setPreview] = useState<API.AssetDiscoveryQueryPreview | null>(null);
    const [detailPage, setDetailPage] = useState(1);
    const [detailPageSize, setDetailPageSize] = useState(100);
    const [exportingQueryId, setExportingQueryId] = useState<number | null>(null);
    const [archiving, setArchiving] = useState(false);
    const [selectedAssetIds, setSelectedAssetIds] = useState<number[]>([]);
    const [notebookReload, setNotebookReload] = useState(0);
    const historyRequest = useRef(0);
    const detailRequest = useRef(0);
    const queryRequest = useRef(0);
    const exportRequest = useRef(0);
    const archiveRequest = useRef(0);
    const querySyntax = assetDiscoverySyntaxCatalog[queryProvider];
    const completions = getAssetDiscoveryCompletions(queryProvider, expression);
    const completionOptions = completions.map((completion, index) => ({
        value: completion.value,
        label: (
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: 16, fontWeight: index === completionIndex ? 600 : undefined }}>
                <Text code>{completion.field.name}{querySyntax.fieldOperator}</Text>
                <Text type="secondary">{completion.field.description}</Text>
            </div>
        ),
    }));

    const handleCompletionKeyDown = (event: React.KeyboardEvent<HTMLInputElement>) => {
        if (!completions.length) return;
        if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
            event.preventDefault();
            event.stopPropagation();
            setCompletionOpen(true);
            setCompletionIndex((current) => {
                if (event.key === 'ArrowDown') return current >= completions.length - 1 ? 0 : current + 1;
                return current <= 0 ? completions.length - 1 : current - 1;
            });
            return;
        }
        if (event.key === 'Enter' && completionOpen) {
            event.preventDefault();
            event.stopPropagation();
            setExpression(completions[completionIndex >= 0 ? completionIndex : 0].value);
            setCompletionOpen(false);
            setCompletionIndex(-1);
        }
    };

    const loadProjects = useCallback(async () => {
        setProjectLoading(true);
        try {
            const result = await listProjects();
            const available = result || [];
            setProjects(available);
            const remembered = localStorage.getItem('active_project_id') || '';
            const nextProject = available.some((project) => project.ID === remembered) ? remembered : available[0]?.ID || '';
            setProjectId(nextProject);
            if (nextProject) localStorage.setItem('active_project_id', nextProject);
        } catch (error) {
            message.error(typeof error === 'string' ? error : '加载项目失败');
        } finally {
            setProjectLoading(false);
        }
    }, [message]);

    const loadHistory = useCallback(async () => {
        if (!projectId) {
            setHistory(null);
            return;
        }
        const requestID = ++historyRequest.current;
        setHistoryLoading(true);
        try {
            const result = await listProjectAssetDiscoveryQueries(projectId, {
                page: historyPage,
                pageSize: historyPageSize,
                provider: historyProvider,
            });
            if (requestID === historyRequest.current) setHistory(result);
        } catch (error) {
            if (requestID === historyRequest.current) {
                setHistory(null);
                message.error(typeof error === 'string' ? error : '加载测绘历史失败');
            }
        } finally {
            if (requestID === historyRequest.current) setHistoryLoading(false);
        }
    }, [historyPage, historyPageSize, historyProvider, message, projectId]);

    useEffect(() => {
        void loadProjects();
    }, [loadProjects]);

    useEffect(() => {
        void loadHistory();
    }, [loadHistory]);

    const handleProjectChange = (nextProjectId: string) => {
        queryRequest.current += 1;
        historyRequest.current += 1;
        detailRequest.current += 1;
        exportRequest.current += 1;
        archiveRequest.current += 1;
        setQuerying(false);
        setHistory(null);
        setHistoryLoading(false);
        setPreview(null);
        setSelectedQuery(null);
        setDetail(null);
        setDetailLoading(false);
        setExportingQueryId(null);
        setArchiving(false);
        setSelectedAssetIds([]);
        setProjectId(nextProjectId);
        localStorage.setItem('active_project_id', nextProjectId);
        setHistoryPage(1);
        setDetailOpen(false);
    };

    const handleRunQuery = async () => {
        const normalizedExpression = expression.trim();
        if (!projectId || !normalizedExpression || !canQuery) return;
        const requestID = ++queryRequest.current;
        const requestedProjectId = projectId;
        setQuerying(true);
        try {
            const result = await queryProjectAssetDiscovery(requestedProjectId, queryProvider, normalizedExpression);
            if (requestID !== queryRequest.current) return;
            setPreview(result);
            setSelectedQuery(null);
            setDetail(null);
            setDetailOpen(true);
            message.success(`测绘完成，返回 ${result.assets.length} 个规范资产`);
            await loadHistory();
        } catch (error) {
            if (requestID === queryRequest.current) {
                message.error(typeof error === 'string' ? error : '测绘查询失败');
            }
        } finally {
            if (requestID === queryRequest.current) setQuerying(false);
        }
    };

    const loadDetail = async (query: API.AssetDiscoveryQuerySummary, page: number, pageSize: number) => {
        if (!projectId) return;
        const requestID = ++detailRequest.current;
        setDetailLoading(true);
        try {
            const result = await getProjectAssetDiscoveryQuery(projectId, query.id, { page, pageSize });
            if (requestID === detailRequest.current) setDetail(result);
        } catch (error) {
            if (requestID === detailRequest.current) {
                setDetail(null);
                message.error(typeof error === 'string' ? error : '加载测绘明细失败');
            }
        } finally {
            if (requestID === detailRequest.current) setDetailLoading(false);
        }
    };

    const handleOpenDetail = (query: API.AssetDiscoveryQuerySummary) => {
        setPreview(null);
        setSelectedQuery(query);
        setDetail(null);
        setSelectedAssetIds([]);
        setDetailPage(1);
        setDetailOpen(true);
        void loadDetail(query, 1, detailPageSize);
    };

    const handleExportQuery = async (query: API.AssetDiscoveryQuerySummary) => {
        if (!projectId) return;
        const requestID = ++exportRequest.current;
        const requestedProjectId = projectId;
        setExportingQueryId(query.id);
        try {
            const blob = await exportProjectAssetDiscoveryQuery(requestedProjectId, query.id);
            if (requestID !== exportRequest.current) return;
            const url = window.URL.createObjectURL(blob);
            const link = document.createElement('a');
            try {
                link.href = url;
                link.download = `argus-asset-discovery-${query.id}.csv`;
                document.body.appendChild(link);
                link.click();
            } finally {
                link.remove();
                window.URL.revokeObjectURL(url);
            }
            message.success('测绘快照已导出');
        } catch (error) {
            if (requestID === exportRequest.current) {
                message.error(typeof error === 'string' ? error : '导出测绘快照失败');
            }
        } finally {
            if (requestID === exportRequest.current) setExportingQueryId(null);
        }
    };

    const handleArchiveAssets = async () => {
        if (!projectId || !selectedQuery || !canQuery || projectArchived || selectedAssetIds.length === 0) return;
        const requestID = ++archiveRequest.current;
        setArchiving(true);
        try {
            const result = await archiveProjectAssetDiscoveryNotebookItems(projectId, selectedQuery.id, selectedAssetIds);
            if (requestID !== archiveRequest.current) return;
            setSelectedAssetIds([]);
            setNotebookReload((value) => value + 1);
            message.success(result.linked_source_count === 0 ? '所选资产已在测绘笔记本中' : `已关联 ${result.linked_source_count} 条来源，新增 ${result.created_count} 条笔记本资产`);
        } catch (error) {
            if (requestID === archiveRequest.current) message.error(typeof error === 'string' ? error : '归档到测绘笔记本失败');
        } finally {
            if (requestID === archiveRequest.current) setArchiving(false);
        }
    };

    const historyColumns: ColumnsType<API.AssetDiscoveryQuerySummary> = [
        {
            title: '时间',
            dataIndex: 'created_at',
            width: 170,
            render: (value: string) => dayjs(value).format('YYYY-MM-DD HH:mm:ss'),
        },
        {
            title: '来源',
            dataIndex: 'provider',
            width: 100,
            render: (value: string) => <Tag color={providerColor[value] || 'default'}>{value.toUpperCase()}</Tag>,
        },
        {
            title: '查询表达式',
            dataIndex: 'expression',
            ellipsis: true,
            render: (value: string) => <Text code title={value}>{value}</Text>,
        },
        {
            title: '结果',
            dataIndex: 'returned_count',
            width: 110,
            render: (value: number, record) => (
                <Space size={4}>
                    <Text>{value}</Text>
                    {record.truncated && <Tag color="warning">已截断</Tag>}
                </Space>
            ),
        },
        {
            title: '操作',
            key: 'action',
            width: 170,
            render: (_, record) => (
                <Space size={0}>
                    <Button type="link" size="small" icon={<EyeOutlined />} onClick={() => handleOpenDetail(record)}>
                        查看
                    </Button>
                    <Button
                        type="link"
                        size="small"
                        icon={<DownloadOutlined />}
                        loading={exportingQueryId === record.id}
                        onClick={() => void handleExportQuery(record)}
                    >
                        导出
                    </Button>
                </Space>
            ),
        },
    ];

    const assetColumns = useMemo<ColumnsType<API.AssetDiscoveryQueryAsset>>(() => [
        { title: '#', dataIndex: 'position', width: 60, render: (value: number | undefined) => value === undefined ? '-' : value + 1 },
        {
            title: '目标',
            dataIndex: 'target',
            width: 310,
            render: (value: string) => <Paragraph copyable={{ text: value }} ellipsis={{ rows: 1 }} style={{ margin: 0 }}>{value}</Paragraph>,
        },
        { title: 'IP', dataIndex: 'ip', width: 150, render: (value?: string) => value || '-' },
        { title: '端口', dataIndex: 'port', width: 80 },
        { title: '协议', dataIndex: 'protocol', width: 90, render: (value?: string) => value || '-' },
        { title: '域名', dataIndex: 'domain', width: 200, ellipsis: true, render: (value?: string) => value || '-' },
        { title: '标题', dataIndex: 'title', width: 240, ellipsis: true, render: (value?: string) => value || '-' },
        { title: '来源', dataIndex: 'source', width: 90, render: (value: string) => <Tag>{value.toUpperCase()}</Tag> },
    ], []);

    const visibleAssets = preview?.assets || detail?.assets || [];
    const currentProject = projects.find((project) => project.ID === projectId);
    const projectArchived = currentProject?.Status === 'archived';
    const canArchiveAssets = canQuery && !projectArchived && !preview && !!detail && !!selectedQuery;

    return (
        <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
                <div>
                    <Title level={4} style={{ margin: 0 }}>
                        <GlobalOutlined style={{ marginRight: 8, color: '#0ea5e9' }} />
                        资产测绘
                    </Title>
                    <Text type="secondary">在项目授权范围内查询外网资产，并保留可追溯的规范结果快照。</Text>
                </div>
                <Select
                    aria-label="当前项目"
                    loading={projectLoading}
                    value={projectId || undefined}
                    placeholder="选择项目"
                    style={{ width: 260 }}
                    onChange={handleProjectChange}
                    options={projects.map((project) => ({ label: project.Name, value: project.ID }))}
                />
            </div>

            {projects.length === 0 && !projectLoading ? (
                <Card><Empty description="暂无可用项目，请先创建或加入项目" /></Card>
            ) : (
                <>
                    <Card title="新建测绘查询" style={{ marginBottom: 16 }}>
                        {canQuery && !projectArchived ? (
                            <Space direction="vertical" size={12} style={{ width: '100%' }}>
                                <Space.Compact style={{ width: '100%' }}>
                                    <Select
                                        aria-label="测绘来源"
                                        value={queryProvider}
                                        style={{ width: 150 }}
                                        onChange={setQueryProvider}
                                        options={providerOptions}
                                    />
                                    <AutoComplete
                                        value={expression}
                                        options={completionOptions}
                                        open={completionOpen && completionOptions.length > 0}
                                        onChange={(value) => {
                                            setExpression(value.slice(0, 4096));
                                            setCompletionOpen(true);
                                            setCompletionIndex(-1);
                                        }}
                                        onSelect={(value) => {
                                            setExpression(value);
                                            setCompletionOpen(false);
                                            setCompletionIndex(-1);
                                        }}
                                        onOpenChange={setCompletionOpen}
                                        filterOption={false}
                                        style={{ flex: 1 }}
                                        popupMatchSelectWidth={520}
                                    >
                                        <Input
                                            aria-label="查询表达式"
                                            allowClear
                                            placeholder={queryPlaceholders[queryProvider]}
                                            onFocus={() => setCompletionOpen(true)}
                                            onKeyDown={handleCompletionKeyDown}
                                        />
                                    </AutoComplete>
                                </Space.Compact>
                                <div
                                    aria-label={`${querySyntax.providerLabel} 语法速查`}
                                    style={{
                                        border: '1px solid #e5e7eb',
                                        borderRadius: 8,
                                        padding: '12px 14px',
                                        background: '#fafafa',
                                    }}
                                >
                                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, marginBottom: 8 }}>
                                        <Text strong>{querySyntax.providerLabel} 官方常用语法</Text>
                                        <Typography.Link href={querySyntax.helpUrl} target="_blank" rel="noreferrer">
                                            官方帮助 <LinkOutlined />
                                        </Typography.Link>
                                    </div>
                                    <Paragraph style={{ marginBottom: 10 }}>{querySyntax.grammar}</Paragraph>
                                    <Space direction="vertical" size={8} style={{ width: '100%' }}>
                                        <Space size={[6, 6]} wrap>
                                            <Text type="secondary">运算符</Text>
                                            {querySyntax.operators.map((operator) => (
                                                <Tag key={operator.token} title={operator.description}>{operator.token}</Tag>
                                            ))}
                                        </Space>
                                        <Space size={[6, 6]} wrap>
                                            <Text type="secondary">常用字段</Text>
                                            {querySyntax.fields.map((field) => (
                                                <Button
                                                    key={field.name}
                                                    size="small"
                                                    title={`${field.description}；点击插入`}
                                                    onClick={() => setExpression(appendAssetDiscoveryField(queryProvider, expression, field.name))}
                                                >
                                                    {field.name}
                                                </Button>
                                            ))}
                                        </Space>
                                        <Space size={[6, 6]} wrap>
                                            <Text type="secondary">安全示例</Text>
                                            {querySyntax.examples.map((example) => (
                                                <Button
                                                    key={example.expression}
                                                    size="small"
                                                    type="dashed"
                                                    title={example.description}
                                                    onClick={() => setExpression(example.expression)}
                                                >
                                                    <Text code>{example.expression}</Text>
                                                </Button>
                                            ))}
                                        </Space>
                                    </Space>
                                    <Text type="secondary" style={{ display: 'block', marginTop: 10 }}>
                                        输入字段前缀后可用方向键和 Enter 选择补全。
                                    </Text>
                                </div>
                                <Text type="secondary">
                                    当前表达式 {expression.length}/4096；默认最多返回 100 条，不会自动创建扫描任务或执行 POC。
                                </Text>
                                <div style={{ display: 'flex', justifyContent: 'flex-end', alignItems: 'center' }}>
                                    <Button
                                        type="primary"
                                        icon={<SearchOutlined />}
                                        loading={querying}
                                        disabled={!projectId || !expression.trim()}
                                        onClick={handleRunQuery}
                                    >
                                        开始测绘
                                    </Button>
                                </div>
                            </Space>
                        ) : projectArchived ? (
                            <Alert type="warning" showIcon message="项目已归档" description="归档项目可继续查看历史结果，但不能从页面发起新的测绘查询。" />
                        ) : (
                            <Alert type="info" showIcon message="当前账号为只读角色" description="你可以查看项目测绘历史；发起新查询需要 operator 或 admin 权限。" />
                        )}
                    </Card>

                    <Card
                        title={`查询历史${currentProject ? ` · ${currentProject.Name}` : ''}`}
                        extra={(
                            <Space>
                                <Select
                                    aria-label="历史来源筛选"
                                    allowClear
                                    placeholder="全部来源"
                                    style={{ width: 140 }}
                                    value={historyProvider}
                                    options={providerOptions}
                                    onChange={(value) => {
                                        setHistoryProvider(value);
                                        setHistoryPage(1);
                                    }}
                                />
                                <Button icon={<ReloadOutlined />} loading={historyLoading} onClick={() => void loadHistory()}>
                                    刷新
                                </Button>
                            </Space>
                        )}
                    >
                        <Table
                            rowKey="id"
                            loading={historyLoading}
                            columns={historyColumns}
                            dataSource={history?.items || []}
                            scroll={{ x: 850 }}
                            pagination={{
                                current: historyPage,
                                pageSize: historyPageSize,
                                total: history?.total || 0,
                                showSizeChanger: true,
                                pageSizeOptions: [20, 50, 100],
                                showTotal: (total) => `共 ${total} 次查询`,
                                onChange: (page, pageSize) => {
                                    setHistoryPage(pageSize === historyPageSize ? page : 1);
                                    setHistoryPageSize(pageSize);
                                },
                            }}
                            locale={{ emptyText: projectId ? '暂无测绘历史' : '请先选择项目' }}
                        />
                    </Card>

                    <Card
                        title="测绘笔记本"
                        style={{ marginTop: 16 }}
                    >
                        <NotebookDistributionPreview key={`${projectId}:${notebookReload}`} projectId={projectId} projectName={currentProject?.Name} enabled={canQuery && !projectArchived} message={message} />
                    </Card>
                </>
            )}

            <Drawer
                title={preview ? '本次测绘结果' : '历史测绘明细'}
                width="min(1100px, 94vw)"
                open={detailOpen}
                onClose={() => setDetailOpen(false)}
                destroyOnHidden
            >
                {detailLoading ? (
                    <Table loading columns={assetColumns} dataSource={[]} pagination={false} />
                ) : (
                    <>
                        <Descriptions size="small" bordered column={{ xs: 1, sm: 2, md: 3 }} style={{ marginBottom: 16 }}>
                            <Descriptions.Item label="来源">{(preview?.provider || selectedQuery?.provider || '-').toUpperCase()}</Descriptions.Item>
                            <Descriptions.Item label="返回资产">{preview?.assets.length ?? selectedQuery?.returned_count ?? 0}</Descriptions.Item>
                            <Descriptions.Item label="Provider 总量">{preview?.provider_total ?? selectedQuery?.provider_total ?? 0}</Descriptions.Item>
                            {!preview && <Descriptions.Item label="查询时间">{selectedQuery ? dayjs(selectedQuery.created_at).format('YYYY-MM-DD HH:mm:ss') : '-'}</Descriptions.Item>}
                            {!preview && <Descriptions.Item label="查询表达式" span={2}><Text code>{selectedQuery?.expression || '-'}</Text></Descriptions.Item>}
                        </Descriptions>
                        <Table
                            rowKey={(record) => (record as API.AssetDiscoveryQueryHistoryAsset).id ?? `${record.position ?? 'preview'}:${record.target}`}
                            columns={assetColumns}
                            dataSource={visibleAssets}
                            rowSelection={canArchiveAssets ? {
                                selectedRowKeys: selectedAssetIds,
                                onChange: (keys) => {
                                    const nextIDs = keys.map(Number);
                                    if (nextIDs.length > 100) message.warning('单次最多归档 100 条资产');
                                    setSelectedAssetIds(nextIDs.slice(0, 100));
                                },
                                getCheckboxProps: (record) => {
                                    const id = (record as API.AssetDiscoveryQueryHistoryAsset).id;
                                    return { disabled: id === undefined || (selectedAssetIds.length >= 100 && !selectedAssetIds.includes(id)) };
                                },
                            } : undefined}
                            scroll={{ x: 1420 }}
                            pagination={preview ? false : {
                                current: detailPage,
                                pageSize: detailPageSize,
                                total: detail?.total || selectedQuery?.returned_count || 0,
                                showSizeChanger: true,
                                pageSizeOptions: [100, 200, 500],
                                onChange: (page, pageSize) => {
                                    if (!selectedQuery) return;
                                    const nextPage = pageSize === detailPageSize ? page : 1;
                                    setDetailPage(nextPage);
                                    setDetailPageSize(pageSize);
                                    void loadDetail(selectedQuery, nextPage, pageSize);
                                },
                            }}
                            locale={{ emptyText: '本次查询没有返回规范资产' }}
                        />
                        {canArchiveAssets && (
                            <div style={{ display: 'flex', justifyContent: 'flex-end', alignItems: 'center', gap: 12, marginTop: 16 }}>
                                <Text type="secondary">已选 {selectedAssetIds.length}/100</Text>
                                <Button type="primary" disabled={selectedAssetIds.length === 0} loading={archiving} onClick={() => void handleArchiveAssets()}>
                                    归档到笔记本
                                </Button>
                            </div>
                        )}
                    </>
                )}
            </Drawer>
        </div>
    );
};

export default AssetDiscovery;
