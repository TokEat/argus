import React, { useState, useEffect, useMemo } from 'react';
import { Alert, AutoComplete, Button, Space, Tag, Popconfirm, Modal, Input, Table, Empty, App, Form, Segmented, Tooltip } from 'antd';
import { ProCard } from '@ant-design/pro-components';
import {
    PlusOutlined,
    EditOutlined,
    DeleteOutlined,
    SearchOutlined,
    ScanOutlined,
    LinkOutlined,
    DisconnectOutlined,
    FolderOpenOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import { useNavigate } from 'react-router-dom';
import {
    getFingerprintDict,
    addFingerprintDict,
    updateFingerprintDict,
    deleteFingerprintDict,
    getWorkflowDict,
    getDirDict,
} from '../../services/api';
import { useAutoContext } from '../../contexts/GlobalAIContext';
import { canAccessRole } from '../../utils/auth';

interface EnrichedFingerprint extends API.FingerprintItem {
    _refWorkflow: boolean;
    _refDir: boolean;
}

const rulesToText = (rules?: string[]) => (rules || []).join('\n');

const textToRules = (value?: string) =>
    String(value || '')
        .split(/\r?\n/)
        .map((rule) => rule.trim())
        .filter(Boolean);

const DirConfig: React.FC = () => {
    const [loading, setLoading] = useState(true);
    const [dictionaries, setDictionaries] = useState<API.FingerprintItem[]>([]);
    const [workflowProducts, setWorkflowProducts] = useState<Set<string>>(new Set());
    const [dirProducts, setDirProducts] = useState<Set<string>>(new Set());
    const [dirDictionaries, setDirDictionaries] = useState<API.DirItem[]>([]);
    const [searchKeyword, setSearchKeyword] = useState('');
    const [refFilter, setRefFilter] = useState<'all' | 'linked' | 'orphan'>('all');
    const [page, setPage] = useState(1);
    const [pageSize, setPageSize] = useState(15);
    const [modalVisible, setModalVisible] = useState(false);
    const [isNew, setIsNew] = useState(false);
    const [currentProduct, setCurrentProduct] = useState<string>('');
    const [form] = Form.useForm();
    const { message } = App.useApp();
    const navigate = useNavigate();
    const canManageRules = canAccessRole('admin');

    const fetchData = async () => {
        setLoading(true);
        try {
            const [fps, wfs, dirs] = await Promise.all([
                getFingerprintDict(),
                getWorkflowDict(),
                getDirDict(),
            ]);
            setDictionaries(fps || []);
            setWorkflowProducts(new Set((wfs || []).map((w) => w.product)));
            setDirProducts(new Set((dirs || []).map((d) => d.product)));
            setDirDictionaries(dirs || []);
        } catch {
            message.error('加载被动规则失败');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => { fetchData(); }, []);

    useAutoContext({
        fingerprint_dictionary: {
            total_rules: dictionaries.length,
            search_keyword: searchKeyword,
            ref_filter: refFilter,
        },
        editing_fingerprint_rule: modalVisible ? {
            product: currentProduct,
            rules: textToRules(form.getFieldValue('rules')),
            is_new: isNew
        } : null
    });

    const enriched: EnrichedFingerprint[] = useMemo(
        () =>
            dictionaries.map((d) => ({
                ...d,
                _refWorkflow: workflowProducts.has(d.product),
                _refDir: dirProducts.has(d.product),
            })),
        [dictionaries, workflowProducts, dirProducts],
    );

    const filtered = useMemo(() => {
        let arr = enriched;
        if (refFilter === 'linked') arr = arr.filter((d) => d._refWorkflow || d._refDir);
        else if (refFilter === 'orphan') arr = arr.filter((d) => !d._refWorkflow && !d._refDir);
        if (!searchKeyword) return arr;
        const lower = searchKeyword.toLowerCase();
        return arr.filter((d) =>
            d.product.toLowerCase().includes(lower) ||
            d.rules?.some((p) => p.toLowerCase().includes(lower)),
        );
    }, [enriched, searchKeyword, refFilter]);

    const stats = useMemo(() => {
        const linked = enriched.filter((e) => e._refWorkflow || e._refDir).length;
        return { total: enriched.length, linked, orphan: enriched.length - linked };
    }, [enriched]);

    const handleCreate = () => {
        if (!canManageRules) return;
        setIsNew(true);
        setCurrentProduct('');
        form.resetFields();
        form.setFieldsValue({ rules: '' });
        setModalVisible(true);
    };

    const handleEdit = (record: API.FingerprintItem) => {
        if (!canManageRules) return;
        setIsNew(false);
        setCurrentProduct(record.product);
        form.setFieldsValue({
            product: record.product,
            rules: rulesToText(record.rules),
        });
        setModalVisible(true);
    };

    const handleSave = async () => {
        if (!canManageRules) return;
        try {
            const values = await form.validateFields();
            if (isNew) {
                await addFingerprintDict({
                    product: values.product,
                    rules: textToRules(values.rules),
                });
                message.success('追加成功，全局规则库已通知更新。');
            } else {
                await updateFingerprintDict(currentProduct, {
                    product: values.product,
                    rules: textToRules(values.rules),
                });
                message.success('更新成功，全局规则库已通知更新。');
            }
            setModalVisible(false);
            fetchData();
        } catch (error: unknown) {
            const errBody = error as Error;
            if (typeof error === 'string') {
                message.error(error);
            } else if (errBody && errBody.message) {
                // ant form error
            }
        }
    };

    const handleDelete = async (product: string) => {
        if (!canManageRules) return;
        try {
            await deleteFingerprintDict(product);
            message.success('已删除');
            fetchData();
        } catch (error: unknown) { 
            message.error(typeof error === 'string' ? error : '删除失败'); 
        }
    };

    const openDirPaths = (product: string) => {
        navigate(`/config/dir?product=${encodeURIComponent(product)}`);
    };

    const columns: ColumnsType<EnrichedFingerprint> = [
        {
            title: '指纹标识产品名 (Product)',
            dataIndex: 'product',
            key: 'product',
            width: 280,
            sorter: (a, b) => a.product.localeCompare(b.product),
            render: (text: string) => (
                <Space>
                    <ScanOutlined style={{ color: '#0ea5e9' }} />
                    <span style={{ fontWeight: 600 }}>{text}</span>
                </Space>
            ),
        },
        {
            title: '关联',
            key: 'reference',
            width: 200,
            filters: [
                { text: '已关联 Workflow', value: 'wf' },
                { text: '已关联路径探针', value: 'dir' },
                { text: '未关联', value: 'orphan' },
            ],
            onFilter: (v, r) => v === 'wf' ? r._refWorkflow : v === 'dir' ? r._refDir : !r._refWorkflow && !r._refDir,
            render: (_, r) => (
                <Space size={4}>
                    {r._refWorkflow ? (
                        <Tooltip title="在 workflow.yaml 中被引用，该指纹命中后会触发 POC">
                            <Tag color="green" icon={<LinkOutlined />}>Workflow</Tag>
                        </Tooltip>
                    ) : null}
                    {r._refDir ? (
                        <Tooltip title="该产品已关联路径探针；启用主动路径指纹后，Scanner 会请求这些路径，再用同产品被动规则复核响应。">
                            <Button type="link" size="small" style={{ padding: 0 }} onClick={() => openDirPaths(r.product)} aria-label={`编辑 ${r.product} 路径探针`}>
                                <Tag color="blue" icon={<LinkOutlined />} style={{ cursor: 'pointer', marginInlineEnd: 0 }}>路径探针</Tag>
                            </Button>
                        </Tooltip>
                    ) : null}
                    {!r._refWorkflow && !r._refDir ? (
                        <Tooltip title="扫描命中仍会记录被动指纹，但没有同产品的 Workflow 或路径探针用于后续验证。">
                            <Tag color="default" icon={<DisconnectOutlined />}>未关联</Tag>
                        </Tooltip>
                    ) : null}
                </Space>
            ),
        },
        {
            title: '提取规则链路 (Rules)',
            dataIndex: 'rules',
            key: 'rules',
            render: (rules: string[]) => (
                <Space wrap style={{ padding: '4px 0' }}>
                    {rules?.map((r, idx) => (
                        <Tag
                            color="cyan"
                            key={idx}
                            style={{ whiteSpace: 'normal', wordBreak: 'break-all', maxWidth: '600px', padding: '4px 8px' }}
                        >
                            <span style={{ fontFamily: 'monospace', fontSize: '13px' }}>{r}</span>
                        </Tag>
                    ))}
                </Space>
            ),
        },
        ...(canManageRules ? [{
            title: '操作',
            key: 'actions',
            width: 220,
            align: 'center' as const,
            render: (_: unknown, record: EnrichedFingerprint) => (
                <Space size={4}>
                    <Button type="link" size="small" icon={<FolderOpenOutlined />} onClick={() => openDirPaths(record.product)}>
                        {record._refDir ? '路径探针' : '关联路径探针'}
                    </Button>
                    <Button type="link" size="small" icon={<EditOutlined />} onClick={() => handleEdit(record)}>编辑</Button>
                    <Popconfirm title="确认删除该产品的指纹规则？" onConfirm={() => handleDelete(record.product)}>
                        <Button type="link" danger size="small" icon={<DeleteOutlined />}>删除</Button>
                    </Popconfirm>
                </Space>
            ),
        }] : []),
    ];

    return (
        <>
            <Alert
                type="info"
                showIcon
                style={{ marginBottom: 16 }}
                message="被动识别与主动路径是两条互补链路"
                description="被动规则分析已有响应；启用主动路径指纹后，Scanner 会独立请求已配置路径，并用同产品被动规则复核响应。路径探针不是被动命中后的条件触发器。"
            />
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16, gap: 12, flexWrap: 'wrap' }}>
                <Space wrap>
                    <Input
                        placeholder="搜索指纹产品特征或规则内容..."
                        prefix={<SearchOutlined style={{ color: '#94a3b8' }} />}
                        value={searchKeyword}
                        onChange={(e) => {
                            setSearchKeyword(e.target.value);
                            setPage(1);
                        }}
                        style={{ width: 280 }}
                        allowClear
                    />
                    <Segmented
                        value={refFilter}
                        onChange={(v) => {
                            setRefFilter(v as typeof refFilter);
                            setPage(1);
                        }}
                        options={[
                            { label: `全部 (${stats.total})`, value: 'all' },
                            { label: `已关联 (${stats.linked})`, value: 'linked' },
                            { label: `未关联 (${stats.orphan})`, value: 'orphan' },
                        ]}
                    />
                </Space>
                <Space>
                    <Tag>{filtered.length} / {enriched.length} 条</Tag>
                    {canManageRules && <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>新增特征指纹</Button>}
                </Space>
            </div>

            <ProCard className="glass-card" style={{ background: 'transparent', border: 'none', padding: 0 }}>
                {filtered.length === 0 && !loading ? (
                    <Empty description="暂无指纹特征" style={{ padding: '60px 0' }} />
                ) : (
                    <Table
                        columns={columns}
                        dataSource={filtered}
                        rowKey="product"
                        loading={loading}
                        pagination={{
                            current: page,
                            pageSize,
                            total: filtered.length,
                            showSizeChanger: true,
                            pageSizeOptions: [15, 20, 50, 100],
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
            <Modal
                    title={isNew ? '添加指纹提取规则' : `编辑指纹特征 — ${currentProduct}`}
                    open={modalVisible}
                    onCancel={() => setModalVisible(false)}
                    onOk={handleSave}
                    width={700}
                    destroyOnClose
                >
                <div style={{ padding: '16px 0 0 0' }}>
                    <Form form={form} layout="vertical">
                        <Form.Item
                            label={
                                <Space>
                                    <span>产品名称 (Product)</span>
                                    <Tooltip title="选择已有路径探针后，会使用相同 Product 建立运行时关联。">
                                        <Tag color="blue" style={{ cursor: 'help' }}>联动路径探针</Tag>
                                    </Tooltip>
                                </Space>
                            }
                            name="product" 
                            rules={[{ required: true, message: '请填写指纹名称' }]}
                            extra="可搜索并选择已有路径探针，也可直接输入新产品名。关联始终使用相同 Product。"
                        >
                            <AutoComplete
                                placeholder="输入产品名，或选择已有路径探针"
                                allowClear
                                showSearch
                                filterOption={(input, option) =>
                                    String(option?.value || '').toLowerCase().includes(input.toLowerCase())
                                }
                                options={dirDictionaries
                                    .slice()
                                    .sort((a, b) => a.product.localeCompare(b.product))
                                    .map((item) => ({
                                        value: item.product,
                                        label: (
                                            <Space>
                                                <span>{item.product}</span>
                                                <Tag color="geekblue">{item.paths?.length || 0} 条路径</Tag>
                                            </Space>
                                        ),
                                    }))}
                            />
                        </Form.Item>

                        <Form.Item 
                            label="判定规则语句集 (Rules)" 
                            name="rules"
                            rules={[
                                { required: true, message: '请提供至少1个匹配规则' },
                                {
                                    validator: (_, value) =>
                                        textToRules(value).length > 0
                                            ? Promise.resolve()
                                            : Promise.reject(new Error('请提供至少1个匹配规则')),
                                },
                            ]}
                            extra="每行一条 CEL 或 GoExpr 规则；多行保存为多条规则，规则之间按 OR 关系处理。"
                        >
                            <Input.TextArea
                                autoSize={{ minRows: 5, maxRows: 12 }}
                                placeholder="每行一条规则，规则之间按 OR 关系处理"
                                style={{ fontFamily: 'monospace', fontSize: 13 }}
                            />
                        </Form.Item>
                    </Form>
                </div>
                </Modal>
            )}
        </>
    );
};

export default DirConfig;
