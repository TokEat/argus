import React, { useState, useEffect, useMemo } from 'react';
import { Button, Space, Tag, Popconfirm, Input, Table, Empty, App, Tooltip, Badge, Statistic, Row, Col, Segmented } from 'antd';
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
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import {
    getWorkflowDict,
    deleteWorkflowDict,
    getFingerprintDict,
    listArsenals,
} from '../../services/api';
import WorkflowEditDrawer from './WorkflowEditDrawer';

interface EnrichedWorkflow extends API.WorkflowItem {
    _fingerprintBound: boolean;
    _missingPocs: string[];
}

const WorkflowConfig: React.FC = () => {
    const [loading, setLoading] = useState(true);
    const [dictionaries, setDictionaries] = useState<API.WorkflowItem[]>([]);
    const [fingerprintProducts, setFingerprintProducts] = useState<Set<string>>(new Set());
    const [pocFiles, setPocFiles] = useState<Set<string>>(new Set());
    const [pocFileCount, setPocFileCount] = useState<number>(0);
    const [searchKeyword, setSearchKeyword] = useState('');
    const [healthFilter, setHealthFilter] = useState<'all' | 'fp_missing' | 'poc_missing' | 'healthy'>('all');
    const [drawer, setDrawer] = useState<{ open: boolean; workflow?: API.WorkflowItem }>({ open: false });
    const { message } = App.useApp();

    const fetchData = async () => {
        setLoading(true);
        try {
            const [wfs, fps, pocs] = await Promise.all([
                getWorkflowDict(),
                getFingerprintDict(),
                listArsenals('poc', true, true),
            ]);
            setDictionaries(wfs || []);
            setFingerprintProducts(new Set((fps || []).map((f) => f.product)));
            // workflow 中引用 POC 时可能不带 .yaml 后缀，这里入库时同时存入原名与去后缀名。
            const pocSet = new Set<string>();
            (pocs || []).forEach((p) => {
                pocSet.add(p.FileName);
                pocSet.add(p.FileName.replace(/\.(ya?ml)$/i, ''));
            });
            setPocFiles(pocSet);
            setPocFileCount((pocs || []).length);
        } catch {
            message.error('加载 Workflow 弹药库失败');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchData();
    }, []);

    const enriched: EnrichedWorkflow[] = useMemo(
        () =>
            dictionaries.map((d) => ({
                ...d,
                _fingerprintBound: fingerprintProducts.has(d.product),
                _missingPocs: (d.pocs || []).filter((p) => !pocFiles.has(p)),
            })),
        [dictionaries, fingerprintProducts, pocFiles],
    );

    const filtered = useMemo(() => {
        let arr = enriched;
        if (healthFilter === 'fp_missing') arr = arr.filter((d) => !d._fingerprintBound);
        else if (healthFilter === 'poc_missing') arr = arr.filter((d) => d._missingPocs.length > 0);
        else if (healthFilter === 'healthy') arr = arr.filter((d) => d._fingerprintBound && d._missingPocs.length === 0);
        if (!searchKeyword) return arr;
        const lower = searchKeyword.toLowerCase();
        return arr.filter(
            (d) =>
                d.product.toLowerCase().includes(lower) ||
                d.pocs?.some((p) => p.toLowerCase().includes(lower)) ||
                d.type?.some((t) => t.toLowerCase().includes(lower)),
        );
    }, [enriched, searchKeyword, healthFilter]);

    const stats = useMemo(() => {
        const total = enriched.length;
        const fpMissing = enriched.filter((e) => !e._fingerprintBound).length;
        const pocMissing = enriched.filter((e) => e._missingPocs.length > 0).length;
        return { total, fpMissing, pocMissing };
    }, [enriched]);

    const handleCreate = () => setDrawer({ open: true, workflow: undefined });
    const handleEdit = (record: API.WorkflowItem) => setDrawer({ open: true, workflow: record });

    const handleDelete = async (product: string) => {
        try {
            await deleteWorkflowDict(product);
            message.success('Workflow 已删除');
            fetchData();
        } catch (err: unknown) {
            message.error(typeof err === 'string' ? err : '删除失败');
        }
    };

    const columns: ColumnsType<EnrichedWorkflow> = [
        {
            title: '关联产品 (Product)',
            dataIndex: 'product',
            key: 'product',
            width: 260,
            sorter: (a, b) => a.product.localeCompare(b.product),
            render: (text: string) => (
                <Space>
                    <ApartmentOutlined style={{ color: '#8b5cf6' }} />
                    <span style={{ fontWeight: 600 }}>{text}</span>
                </Space>
            ),
        },
        {
            title: '触发阶段',
            dataIndex: 'type',
            key: 'type',
            width: 180,
            render: (types: string[]) => (
                <Space wrap>
                    {types?.map((t, idx) => (
                        <Tag color="geekblue" key={idx}>{t}</Tag>
                    ))}
                </Space>
            ),
        },
        {
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
            align: 'center',
            filters: [
                { text: '已配置', value: 'ok' },
                { text: '缺失', value: 'missing' },
            ],
            onFilter: (value, record) => (value === 'ok' ? record._fingerprintBound : !record._fingerprintBound),
            render: (_, record) =>
                record._fingerprintBound ? (
                    <Tag icon={<CheckCircleOutlined />} color="green">已配置</Tag>
                ) : (
                    <Tag icon={<WarningOutlined />} color="orange">缺失</Tag>
                ),
        },
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
        {
            title: '操作',
            key: 'actions',
            width: 160,
            align: 'center',
            render: (_, record) => (
                <Space size={4}>
                    <Button type="link" size="small" icon={<EditOutlined />} onClick={() => handleEdit(record)}>
                        编辑
                    </Button>
                    <Popconfirm title="确认删除该 Workflow？" onConfirm={() => handleDelete(record.product)}>
                        <Button type="link" danger size="small" icon={<DeleteOutlined />}>删除</Button>
                    </Popconfirm>
                </Space>
            ),
        },
    ];

    return (
        <>
            {/* 概览统计 */}
            <ProCard
                className="glass-card"
                style={{ marginBottom: 16, background: 'transparent' }}
                bodyStyle={{ padding: '12px 16px' }}
            >
                <Row gutter={16}>
                    <Col flex="1">
                        <Statistic title="Workflow 总数" value={stats.total} prefix={<ApartmentOutlined style={{ color: '#8b5cf6' }} />} />
                    </Col>
                    <Col flex="1">
                        <Statistic
                            title="指纹缺失"
                            value={stats.fpMissing}
                            valueStyle={{ color: stats.fpMissing > 0 ? '#f59e0b' : '#10b981' }}
                            prefix={<ScanOutlined />}
                        />
                    </Col>
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
                            title="指纹库总条数"
                            value={fingerprintProducts.size}
                            valueStyle={{ color: '#06b6d4' }}
                            prefix={<ScanOutlined style={{ color: '#06b6d4' }} />}
                        />
                    </Col>
                    <Col flex="1">
                        <Statistic
                            title="POC 库总条数"
                            value={pocFileCount}
                            valueStyle={{ color: '#3b82f6' }}
                            prefix={<BugOutlined style={{ color: '#3b82f6' }} />}
                        />
                    </Col>
                </Row>
            </ProCard>

            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16, gap: 12, flexWrap: 'wrap' }}>
                <Space wrap>
                    <Input
                        placeholder="搜索 product / type / POC 文件名"
                        prefix={<SearchOutlined style={{ color: '#94a3b8' }} />}
                        value={searchKeyword}
                        onChange={(e) => setSearchKeyword(e.target.value)}
                        style={{ width: 320 }}
                        allowClear
                    />
                    <Segmented
                        value={healthFilter}
                        onChange={(v) => setHealthFilter(v as typeof healthFilter)}
                        options={[
                            { label: `全部 (${enriched.length})`, value: 'all' },
                            { label: `指纹缺失 (${stats.fpMissing})`, value: 'fp_missing' },
                            { label: `POC 缺失 (${stats.pocMissing})`, value: 'poc_missing' },
                            { label: `健康 (${enriched.length - enriched.filter((e) => !e._fingerprintBound || e._missingPocs.length > 0).length})`, value: 'healthy' },
                        ]}
                    />
                </Space>
                <Space>
                    <Tag>{filtered.length} / {enriched.length} 条</Tag>
                    <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>新增 Workflow</Button>
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
                        pagination={{ pageSize: 15, showSizeChanger: true, showTotal: (t) => `共 ${t} 条` }}
                        size="middle"
                    />
                )}
            </ProCard>

            <WorkflowEditDrawer
                open={drawer.open}
                workflow={drawer.workflow}
                onClose={() => setDrawer({ open: false })}
                onSaved={() => {
                    setDrawer({ open: false });
                    fetchData();
                }}
            />
        </>
    );
};

export default WorkflowConfig;
