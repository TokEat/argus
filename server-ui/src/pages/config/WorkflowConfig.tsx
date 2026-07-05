import React, { useState, useEffect, useMemo } from 'react';
import { Button, Space, Tag, Popconfirm, Input, Table, Empty, App, Tooltip, Badge, Statistic, Row, Col, Segmented, Alert } from 'antd';
import { ProCard } from '@ant-design/pro-components';
import {
    PlusOutlined,
    EditOutlined,
    DeleteOutlined,
    SearchOutlined,
    ApartmentOutlined,
    ScanOutlined,
    BugOutlined,
    WarningOutlined,
    CheckCircleOutlined,
    GlobalOutlined,
    AimOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import {
    getWorkflowDictPage,
    deleteWorkflowDict,
} from '../../services/api';
import WorkflowEditDrawer from './WorkflowEditDrawer';
import { canAccessRole } from '../../utils/auth';

interface EnrichedWorkflow extends API.WorkflowSummary {
    _fingerprintBound: boolean;
    _missingPocs: string[];
}

interface WorkflowOverviewStats {
    total: number;
    fpMissing: number;
    pocMissing: number;
    totalPocs: number;
    fingerprintRules: number;
}

const EMPTY_WORKFLOW_STATS: WorkflowOverviewStats = {
    total: 0,
    fpMissing: 0,
    pocMissing: 0,
    totalPocs: 0,
    fingerprintRules: 0,
};

const GENERAL_POC_PREFIX = 'General-Poc-';
const isGeneralPoc = (product: string) => product.startsWith(GENERAL_POC_PREFIX);

const statsFromCurrentPage = (items: API.WorkflowSummary[], total: number): WorkflowOverviewStats => ({
    total,
    fpMissing: items.filter((item) => !item.is_general_poc && !item.fingerprint_bound).length,
    pocMissing: items.filter((item) => (item.missing_poc_count || 0) > 0 || (item.missing_pocs || []).length > 0).length,
    totalPocs: items.reduce((sum, item) => sum + (item.poc_count ?? item.pocs?.length ?? 0), 0),
    fingerprintRules: items.reduce((sum, item) => sum + (item.fingerprint_rule_count || 0), 0),
});

const normalizeStats = (stats: API.WorkflowStats | undefined, items: API.WorkflowSummary[], total: number): WorkflowOverviewStats => {
    if (!stats) return statsFromCurrentPage(items, total);
    return {
        total: stats.total || 0,
        fpMissing: stats.fp_missing || 0,
        pocMissing: stats.poc_missing || 0,
        totalPocs: stats.total_pocs || 0,
        fingerprintRules: stats.fingerprint_rules || 0,
    };
};

import { useAutoContext } from '../../contexts/GlobalAIContext';

const WorkflowConfig: React.FC = () => {
    const [loading, setLoading] = useState(true);
    const [dictionaries, setDictionaries] = useState<API.WorkflowSummary[]>([]);
    const [total, setTotal] = useState(0);
    const [page, setPage] = useState(1);
    const [pageSize, setPageSize] = useState(15);
    const [searchKeyword, setSearchKeyword] = useState('');
    const [healthFilter, setHealthFilter] = useState<'all' | 'fp_missing' | 'poc_missing' | 'healthy'>('all');
    const [ruleScope, setRuleScope] = useState<'specific' | 'general'>('specific');
    const [stats, setStats] = useState<WorkflowOverviewStats>(EMPTY_WORKFLOW_STATS);
    const [drawer, setDrawer] = useState<{ open: boolean; workflow?: API.WorkflowItem; isGeneralPoc?: boolean }>({ open: false });
    const { message } = App.useApp();
    const canManageRules = canAccessRole('operator');

    const fetchData = async () => {
        setLoading(true);
        try {
            const res = await getWorkflowDictPage({
                page,
                page_size: pageSize,
                q: searchKeyword || undefined,
                scope: ruleScope,
                health: healthFilter,
            });
            const items = res.items || [];
            const nextTotal = res.total || 0;
            setDictionaries(items);
            setTotal(nextTotal);
            setStats(normalizeStats(res.stats, items, nextTotal));
        } catch {
            message.error('加载 Workflow 弹药库失败');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchData();
    }, [page, pageSize, searchKeyword, healthFilter, ruleScope]);

    const enriched: EnrichedWorkflow[] = useMemo(
        () =>
            dictionaries.map((d) => ({
                ...d,
                _fingerprintBound: d.fingerprint_bound,
                _missingPocs: d.missing_pocs || [],
            })),
        [dictionaries],
    );

    const filtered = enriched;

    useAutoContext({
        workflow_scope: ruleScope,
        workflow_stats: { ...stats, total_matching: total },
    });

    const handleCreate = () => {
        if (!canManageRules) return;
        setDrawer({ open: true, workflow: undefined, isGeneralPoc: ruleScope === 'general' });
    };
    const handleEdit = (record: API.WorkflowItem) => {
        if (!canManageRules) return;
        setDrawer({ open: true, workflow: record, isGeneralPoc: isGeneralPoc(record.product) });
    };

    const handleDelete = async (product: string) => {
        if (!canManageRules) return;
        try {
            await deleteWorkflowDict(product);
            message.success('Workflow 已删除');
            setPage(1);
            fetchData();
        } catch (err: unknown) {
            message.error(typeof err === 'string' ? err : '删除失败');
        }
    };

    const columns: ColumnsType<EnrichedWorkflow> = [
        {
            title: ruleScope === 'general' ? '探测规则名称' : '关联产品 (Product)',
            dataIndex: 'product',
            key: 'product',
            width: 260,
            render: (text: string) => {
                const isGP = isGeneralPoc(text);
                const displayName = isGP ? text.replace(GENERAL_POC_PREFIX, '') : text;
                return (
                    <Space>
                        {isGP ? <GlobalOutlined style={{ color: '#f59e0b' }} /> : <ApartmentOutlined style={{ color: '#8b5cf6' }} />}
                        <span style={{ fontWeight: 600 }}>{displayName}</span>
                        {isGP && <Tag color="orange" style={{ fontSize: 11, lineHeight: '18px' }}>全局探测</Tag>}
                    </Space>
                );
            },
        },
        {
            title: '触发阶段',
            dataIndex: 'type',
            key: 'type',
            width: 220,
            render: (types: string[]) => {
                const typeDesc: Record<string, string> = {
                    root: '根路径 (scheme://host)',
                    base: '完整路径 (scheme://host/a/b/c)',
                    dir: '逐级目录 (/a, /a/b, ...)',
                    'dir-fallback': '目录探测命中时直接标记指纹',
                };
                return (
                    <Space wrap>
                        {types?.map((t, idx) => (
                            <Tooltip title={typeDesc[t] || t} key={idx}>
                                <Tag color="geekblue">{t}</Tag>
                            </Tooltip>
                        ))}
                    </Space>
                );
            },
        },
        ...(ruleScope !== 'general' ? [{
            title: (
                <Tooltip title="该 Product 是否在指纹库中有识别规则。无则该 Workflow 永远不会被触发。">
                    <Space size={4}>
                        <ScanOutlined />
                        <span>指纹</span>
                    </Space>
                </Tooltip>
            ),
            key: 'fingerprint',
            width: 110,
            align: 'center' as const,
            render: (_: unknown, record: EnrichedWorkflow) =>
                record._fingerprintBound ? (
                    <Tag icon={<CheckCircleOutlined />} color="green">已配置</Tag>
                ) : (
                    <Tag icon={<WarningOutlined />} color="orange">缺失</Tag>
                ),
        }] : []),
        {
            title: (
                <Space size={4}>
                    <BugOutlined />
                    <span>POC</span>
                </Space>
            ),
            key: 'pocs',
            render: (_, record) => {
                const total = record.pocs?.length || 0;
                const missing = record._missingPocs.length;
                if (total === 0) return <Tag color="default">未挂载</Tag>;
                return (
                    <Space wrap>
                        <Badge
                            count={total}
                            showZero={false}
                            style={{ backgroundColor: '#3b82f6' }}
                            title={`共挂载 ${total} 个 POC`}
                        />
                        {missing > 0 && (
                            <Tooltip title={`弹药库缺失：${record._missingPocs.join(', ')}`}>
                                <Tag color="red" icon={<WarningOutlined />}>{missing} 个文件缺失</Tag>
                            </Tooltip>
                        )}
                        <span style={{ fontSize: 12, color: '#94a3b8' }}>
                            {(record.pocs || []).slice(0, 2).join(', ')}{total > 2 ? ` +${total - 2}` : ''}
                        </span>
                    </Space>
                );
            },
        },
        ...(canManageRules ? [{
            title: '操作',
            key: 'actions',
            width: 160,
            align: 'center' as const,
            render: (_: unknown, record: EnrichedWorkflow) => (
                <Space size={4}>
                    <Button type="link" size="small" icon={<EditOutlined />} onClick={() => handleEdit(record)}>
                        编辑
                    </Button>
                    <Popconfirm title="确认删除该 Workflow？" onConfirm={() => handleDelete(record.product)}>
                        <Button type="link" danger size="small" icon={<DeleteOutlined />}>删除</Button>
                    </Popconfirm>
                </Space>
            ),
        }] : []),
    ];

    return (
        <>
            {/* 一级分区切换 */}
            <div style={{ marginBottom: 16 }}>
                <Segmented
                    value={ruleScope}
                    onChange={(v) => { setRuleScope(v as 'specific' | 'general'); setHealthFilter('all'); setSearchKeyword(''); setPage(1); }}
                    options={[
                        { label: <Space><AimOutlined />指纹关联</Space>, value: 'specific' },
                        { label: <Space><GlobalOutlined />通用探测</Space>, value: 'general' },
                    ]}
                    size="large"
                    style={{ fontWeight: 500 }}
                />
            </div>

            {/* 通用探测说明 */}
            {ruleScope === 'general' && (
                <Alert
                    message="通用探测规则对所有扫描目标自动生效，不依赖指纹识别。适用于 Shiro、Actuator 等需主动 Probe 的中间件检测。"
                    type="info"
                    showIcon
                    icon={<GlobalOutlined />}
                    style={{ marginBottom: 16 }}
                    closable
                />
            )}

            {/* 概览统计 */}
            <ProCard
                className="glass-card"
                style={{ marginBottom: 16, background: 'transparent' }}
                bodyStyle={{ padding: '12px 16px' }}
            >
                <Row gutter={16}>
                    <Col flex="1">
                        <Statistic
                            title={ruleScope === 'general' ? '通用探测规则' : 'Workflow 总数'}
                            value={stats.total}
                            prefix={ruleScope === 'general' ? <GlobalOutlined style={{ color: '#f59e0b' }} /> : <ApartmentOutlined style={{ color: '#8b5cf6' }} />}
                        />
                    </Col>
                    {ruleScope !== 'general' && (
                        <Col flex="1">
                            <Statistic
                                title="指纹缺失"
                                value={stats.fpMissing}
                                valueStyle={{ color: stats.fpMissing > 0 ? '#f59e0b' : '#10b981' }}
                                prefix={<ScanOutlined />}
                            />
                        </Col>
                    )}
                    <Col flex="1">
                        <Statistic
                            title="POC 文件缺失"
                            value={stats.pocMissing}
                            valueStyle={{ color: stats.pocMissing > 0 ? '#ef4444' : '#10b981' }}
                            prefix={<BugOutlined />}
                        />
                    </Col>
                    <Col flex="1">
                        <Statistic
                            title={ruleScope === 'general' ? 'POC 覆盖数' : '挂载 POC 总数'}
                            value={stats.totalPocs}
                            valueStyle={{ color: '#3b82f6' }}
                            prefix={<BugOutlined style={{ color: '#3b82f6' }} />}
                        />
                    </Col>
                    {ruleScope !== 'general' && (
                        <Col flex="1">
                            <Statistic
                                title="指纹规则总数"
                                value={stats.fingerprintRules}
                                valueStyle={{ color: '#06b6d4' }}
                                prefix={<ScanOutlined style={{ color: '#06b6d4' }} />}
                            />
                        </Col>
                    )}
                </Row>
            </ProCard>

            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16, gap: 12, flexWrap: 'wrap' }}>
                <Space wrap>
                    <Input
                        placeholder="搜索 product / type / POC 文件名"
                        prefix={<SearchOutlined style={{ color: '#94a3b8' }} />}
                        value={searchKeyword}
                        onChange={(e) => { setSearchKeyword(e.target.value); setPage(1); }}
                        style={{ width: 320 }}
                        allowClear
                    />
                    {ruleScope !== 'general' && <Segmented
                        value={healthFilter}
                        onChange={(v) => { setHealthFilter(v as typeof healthFilter); setPage(1); }}
                        options={[
                            { label: '全部', value: 'all' },
                            { label: '指纹缺失', value: 'fp_missing' },
                            { label: 'POC 缺失', value: 'poc_missing' },
                            { label: '健康', value: 'healthy' },
                        ]}
                    />}
                </Space>
                <Space>
                    <Tag>当前页 {filtered.length} / 匹配 {total} 条</Tag>
                    {canManageRules && (
                        <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>
                            {ruleScope === 'general' ? '新增通用探测规则' : '新增 Workflow'}
                        </Button>
                    )}
                </Space>
            </div>

            <ProCard className="glass-card" style={{ background: 'transparent', border: 'none', padding: 0 }}>
                {filtered.length === 0 && !loading ? (
                    <Empty description="暂无 Workflow 编排" style={{ padding: '60px 0' }} />
                ) : (
                    <Table
                        columns={columns}
                        dataSource={filtered}
                        rowKey="product"
                        loading={loading}
                        pagination={{
                            current: page,
                            pageSize,
                            total,
                            showSizeChanger: true,
                            showTotal: (t) => `共 ${t} 条`,
                            onChange: (nextPage, nextPageSize) => {
                                setPage(nextPage);
                                setPageSize(nextPageSize);
                            },
                        }}
                        size="middle"
                    />
                )}
            </ProCard>

            {canManageRules && (
                <WorkflowEditDrawer
                    open={drawer.open}
                    workflow={drawer.workflow}
                    isGeneralPoc={drawer.isGeneralPoc}
                    onClose={() => setDrawer({ open: false })}
                    onSaved={() => {
                        setDrawer({ open: false });
                        fetchData();
                    }}
                />
            )}
        </>
    );
};

export default WorkflowConfig;
