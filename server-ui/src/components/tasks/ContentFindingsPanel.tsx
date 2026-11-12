import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Input, Select, Space, Tabs, Tag, Tooltip, Typography } from 'antd';
import { LinkOutlined, SearchOutlined } from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import { listCrawlSiteCandidates, listSensitiveFindings } from '../../services/api';
import { DEFAULT_RESULT_PAGE_SIZE } from '../../pages/taskResultTabs';
import ResultTable from './ResultTable';

const { Text } = Typography;

interface PageState {
    current: number;
    pageSize: number;
    total: number;
}

const initialPage: PageState = { current: 1, pageSize: DEFAULT_RESULT_PAGE_SIZE, total: 0 };

const AI_STATUS_LABEL: Record<string, string> = {
    pending: '待分析',
    confirmed: '已确认',
    duplicate: '重复',
    rejected: '已忽略',
};
const AI_STATUS_COLOR: Record<string, string> = {
    pending: 'blue',
    confirmed: 'green',
    duplicate: 'orange',
    rejected: 'red',
};

const KIND_LABEL: Record<string, string> = {
    email: '邮箱',
    phone: '电话',
    idcard: '身份证',
    username: '用户名',
    account: '账号',
    apikey: 'API 密钥',
    token: '令牌',
    secret: '机密',
    keyword: '关键词',
    custom: '自定义',
};
const KIND_COLOR: Record<string, string> = {
    email: 'geekblue',
    phone: 'purple',
    idcard: 'magenta',
    username: 'blue',
    account: 'volcano',
    apikey: 'gold',
    token: 'lime',
    secret: 'red',
    keyword: 'cyan',
    custom: 'default',
};

// 路径前缀候选类型：path_app=按路径反代的独立应用；hidden_path=仅 JS 出现的隐藏端点。
const SITE_TYPE_LABEL: Record<string, string> = {
    path_app: '路径应用',
    hidden_path: '隐藏端点',
};
const SITE_TYPE_COLOR: Record<string, string> = {
    path_app: 'geekblue',
    hidden_path: 'orange',
};

function siteTypeTag(siteType?: string) {
    if (!siteType || !SITE_TYPE_LABEL[siteType]) return null;
    return <Tag color={SITE_TYPE_COLOR[siteType]}>{SITE_TYPE_LABEL[siteType]}</Tag>;
}

function aiStatusTag(status?: string) {
    if (!status) return <Tag>未知</Tag>;
    return <Tag color={AI_STATUS_COLOR[status] || 'default'}>{AI_STATUS_LABEL[status] || status}</Tag>;
}

function confidenceText(value?: number): string {
    if (value === undefined || value === null) return '-';
    return `${Math.round(value * 100)}%`;
}

interface ContentFindingsPanelProps {
    taskId?: string;
    /** 仅当所在页签被激活时才发起请求，避免无关抓取。 */
    active?: boolean;
}

const ContentFindingsPanel: React.FC<ContentFindingsPanelProps> = ({ taskId, active = true }) => {
    // 关联资产候选
    const [crawlItems, setCrawlItems] = useState<API.CrawlSiteCandidate[]>([]);
    const [crawlPage, setCrawlPage] = useState<PageState>(initialPage);
    const [crawlLoading, setCrawlLoading] = useState(false);
    const [crawlStatus, setCrawlStatus] = useState('');
    const [crawlSearchInput, setCrawlSearchInput] = useState('');
    const crawlSearchRef = useRef('');
    const crawlStatusRef = useRef('');

    // 敏感信息
    const [sensitiveItems, setSensitiveItems] = useState<API.SensitiveFinding[]>([]);
    const [sensitivePage, setSensitivePage] = useState<PageState>(initialPage);
    const [sensitiveLoading, setSensitiveLoading] = useState(false);
    const [sensitiveKind, setSensitiveKind] = useState('');
    const [sensitiveStatus, setSensitiveStatus] = useState('');
    const [sensitiveSearchInput, setSensitiveSearchInput] = useState('');
    const sensitiveKindRef = useRef('');
    const sensitiveStatusRef = useRef('');
    const sensitiveSearchRef = useRef('');
    const [activeSubTab, setActiveSubTab] = useState<'crawl' | 'sensitive'>('crawl');

    const fetchCrawl = useCallback(async (page: number, pageSize: number) => {
        setCrawlLoading(true);
        try {
            const projectId = localStorage.getItem('active_project_id') || undefined;
            const res = await listCrawlSiteCandidates({
                taskId: taskId || undefined,
                projectId,
                aiStatus: crawlStatusRef.current || undefined,
                search: crawlSearchRef.current || undefined,
                page,
                pageSize,
            });
            setCrawlItems(res.items || []);
            setCrawlPage({ current: res.page || page, pageSize: res.page_size || pageSize, total: res.total || 0 });
        } catch (error) {
            console.error('Failed to fetch crawl site candidates:', error);
            setCrawlItems([]);
        } finally {
            setCrawlLoading(false);
        }
    }, [taskId]);

    const fetchSensitive = useCallback(async (page: number, pageSize: number) => {
        setSensitiveLoading(true);
        try {
            const projectId = localStorage.getItem('active_project_id') || undefined;
            const res = await listSensitiveFindings({
                taskId: taskId || undefined,
                projectId,
                kind: sensitiveKindRef.current || undefined,
                aiStatus: sensitiveStatusRef.current || undefined,
                search: sensitiveSearchRef.current || undefined,
                page,
                pageSize,
            });
            setSensitiveItems(res.items || []);
            setSensitivePage({ current: res.page || page, pageSize: res.page_size || pageSize, total: res.total || 0 });
        } catch (error) {
            console.error('Failed to fetch sensitive findings:', error);
            setSensitiveItems([]);
        } finally {
            setSensitiveLoading(false);
        }
    }, [taskId]);

    // 页签首次激活时抓取两类的第一页。
    useEffect(() => {
        if (!active) return;
        fetchCrawl(1, DEFAULT_RESULT_PAGE_SIZE);
        fetchSensitive(1, DEFAULT_RESULT_PAGE_SIZE);
    }, [active, taskId, fetchCrawl, fetchSensitive]);

    const crawlColumns: ColumnsType<API.CrawlSiteCandidate> = [
        {
            title: 'URL',
            dataIndex: 'URL',
            key: 'URL',
            ellipsis: true,
            render: (_, record) => (
                <Tooltip title={record.LinkContext ? `链接上下文：${record.LinkContext}` : record.URL}>
                    <Space size={4}>
                        {siteTypeTag(record.SiteType)}
                        <LinkOutlined style={{ color: '#1677ff' }} />
                        <Text copyable={{ text: record.URL }} style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12 }}>
                            {record.URL}
                        </Text>
                    </Space>
                </Tooltip>
            ),
        },
        {
            title: '主机',
            dataIndex: 'Host',
            key: 'Host',
            width: 180,
            render: (_, record) => <Text style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12 }}>{record.Port ? `${record.Host}:${record.Port}` : record.Host}</Text>,
        },
        {
            title: '来源页面',
            dataIndex: 'SourceURL',
            key: 'SourceURL',
            ellipsis: true,
            render: (value: string) => value ? <Text type="secondary" style={{ fontSize: 12 }}>{value}</Text> : <Text type="secondary">-</Text>,
        },
        {
            title: 'AI 判定',
            dataIndex: 'AIStatus',
            key: 'AIStatus',
            width: 110,
            render: (_, record) => (
                <Space size={4}>
                    {aiStatusTag(record.AIStatus)}
                    {record.AIControl && record.AIConfidence !== undefined && (
                        <Text type="secondary" style={{ fontSize: 11 }}>{confidenceText(record.AIConfidence)}</Text>
                    )}
                </Space>
            ),
        },
        {
            title: 'AI 理由',
            dataIndex: 'AIReason',
            key: 'AIReason',
            ellipsis: true,
            render: (value: string) => value
                ? <Tooltip title={value}><Text type="secondary" style={{ fontSize: 12 }}>{value}</Text></Tooltip>
                : <Text type="secondary">-</Text>,
        },
        {
            title: '资产入库',
            dataIndex: 'AssetPromoted',
            key: 'AssetPromoted',
            width: 100,
            render: (value: boolean) => value ? <Tag color="green">已入库</Tag> : <Tag>未入库</Tag>,
        },
    ];

    const sensitiveColumns: ColumnsType<API.SensitiveFinding> = [
        {
            title: '类型',
            dataIndex: 'Kind',
            key: 'Kind',
            width: 100,
            render: (value: string) => <Tag color={KIND_COLOR[value] || 'default'}>{KIND_LABEL[value] || value || '未知'}</Tag>,
        },
        {
            title: '取值',
            dataIndex: 'Value',
            key: 'Value',
            ellipsis: true,
            render: (value: string) => <Text copyable={value ? { text: value } : false} style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12 }}>{value || '-'}</Text>,
        },
        {
            title: '主机',
            dataIndex: 'Host',
            key: 'Host',
            width: 180,
            render: (value: string) => <Text style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12 }}>{value || '-'}</Text>,
        },
        {
            title: 'AI 判定',
            dataIndex: 'AIStatus',
            key: 'AIStatus',
            width: 110,
            render: (_, record) => (
                <Space size={4}>
                    {aiStatusTag(record.AIStatus)}
                    {record.AIControl && record.AIConfidence !== undefined && (
                        <Text type="secondary" style={{ fontSize: 11 }}>{confidenceText(record.AIConfidence)}</Text>
                    )}
                </Space>
            ),
        },
        {
            title: '片段',
            dataIndex: 'Snippet',
            key: 'Snippet',
            ellipsis: true,
            render: (value: string) => value
                ? <Tooltip title={<pre style={{ maxWidth: 480, maxHeight: 300, overflow: 'auto', margin: 0, whiteSpace: 'pre-wrap' }}>{value}</pre>}><Text style={{ fontSize: 12 }}>{value}</Text></Tooltip>
                : <Text type="secondary">-</Text>,
        },
        {
            title: 'AI 提取',
            dataIndex: 'Context',
            key: 'Context',
            ellipsis: true,
            render: (value: string) => value
                ? <Tooltip title={<pre style={{ maxWidth: 480, maxHeight: 300, overflow: 'auto', margin: 0, whiteSpace: 'pre-wrap' }}>{value}</pre>}><Tag color="geekblue" style={{ cursor: 'pointer' }}>结构化</Tag></Tooltip>
                : <Text type="secondary">-</Text>,
        },
    ];

    return (
        <div>
            <Tabs
                activeKey={activeSubTab}
                onChange={(k) => setActiveSubTab(k as 'crawl' | 'sensitive')}
                destroyOnHidden={true}
                items={[
                    {
                        key: 'crawl',
                        label: <span><LinkOutlined /> 关联资产候选 ({crawlPage.total})</span>,
                        children: (
                            <div key="crawl-pane">
                                <Space style={{ marginBottom: 12 }} wrap>
                                    <Input.Search
                                        allowClear
                                        placeholder="按 URL / 主机搜索"
                                        style={{ width: 260 }}
                                        value={crawlSearchInput}
                                        onChange={(e) => setCrawlSearchInput(e.target.value)}
                                        onSearch={(value: string) => {
                                            crawlSearchRef.current = value.trim();
                                            fetchCrawl(1, crawlPage.pageSize);
                                        }}
                                    />
                                    <Select
                                        allowClear
                                        placeholder="AI 状态"
                                        style={{ width: 140 }}
                                        value={crawlStatus || undefined}
                                        onChange={(value) => {
                                            crawlStatusRef.current = value || '';
                                            setCrawlStatus(value || '');
                                            fetchCrawl(1, crawlPage.pageSize);
                                        }}
                                        options={Object.keys(AI_STATUS_LABEL).map((key) => ({ value: key, label: AI_STATUS_LABEL[key] }))}
                                    />
                                </Space>
                                <ResultTable
                                    bordered
                                    columns={crawlColumns}
                                    dataSource={crawlItems}
                                    rowKey="ID"
                                    loading={crawlLoading}
                                    pagination={{
                                        current: crawlPage.current,
                                        pageSize: crawlPage.pageSize,
                                        total: crawlPage.total,
                                        showSizeChanger: true,
                                        pageSizeOptions: ['10', '20', '50', '100'],
                                        showTotal: (t) => `共 ${t} 条`,
                                        onChange: (page, pageSize) => fetchCrawl(page, pageSize),
                                    }}
                                    size="middle"
                                    rowClassName={(_, index) => index % 2 === 1 ? 'table-row-light' : 'table-row-dark'}
                                />
                            </div>
                        ),
                    },
                    {
                        key: 'sensitive',
                        label: <span><SearchOutlined /> 敏感信息 ({sensitivePage.total})</span>,
                        children: (
                            <div key="sensitive-pane">
                                <Space style={{ marginBottom: 12 }} wrap>
                                    <Input.Search
                                        allowClear
                                        placeholder="按取值 / 主机搜索"
                                        style={{ width: 240 }}
                                        value={sensitiveSearchInput}
                                        onChange={(e) => setSensitiveSearchInput(e.target.value)}
                                        onSearch={(value: string) => {
                                            sensitiveSearchRef.current = value.trim();
                                            fetchSensitive(1, sensitivePage.pageSize);
                                        }}
                                    />
                                    <Select
                                        allowClear
                                        placeholder="类型"
                                        style={{ width: 130 }}
                                        value={sensitiveKind || undefined}
                                        onChange={(value) => {
                                            sensitiveKindRef.current = value || '';
                                            setSensitiveKind(value || '');
                                            fetchSensitive(1, sensitivePage.pageSize);
                                        }}
                                        options={Object.keys(KIND_LABEL).map((key) => ({ value: key, label: KIND_LABEL[key] }))}
                                    />
                                    <Select
                                        allowClear
                                        placeholder="AI 状态"
                                        style={{ width: 130 }}
                                        value={sensitiveStatus || undefined}
                                        onChange={(value) => {
                                            sensitiveStatusRef.current = value || '';
                                            setSensitiveStatus(value || '');
                                            fetchSensitive(1, sensitivePage.pageSize);
                                        }}
                                        options={Object.keys(AI_STATUS_LABEL).map((key) => ({ value: key, label: AI_STATUS_LABEL[key] }))}
                                    />
                                </Space>
                                <ResultTable
                                    bordered
                                    columns={sensitiveColumns}
                                    dataSource={sensitiveItems}
                                    rowKey="ID"
                                    loading={sensitiveLoading}
                                    pagination={{
                                        current: sensitivePage.current,
                                        pageSize: sensitivePage.pageSize,
                                        total: sensitivePage.total,
                                        showSizeChanger: true,
                                        pageSizeOptions: ['10', '20', '50', '100'],
                                        showTotal: (t) => `共 ${t} 条`,
                                        onChange: (page, pageSize) => fetchSensitive(page, pageSize),
                                    }}
                                    size="middle"
                                    rowClassName={(_, index) => index % 2 === 1 ? 'table-row-light' : 'table-row-dark'}
                                />
                            </div>
                        ),
                    },
                ]}
            />
        </div>
    );
};

export default ContentFindingsPanel;
