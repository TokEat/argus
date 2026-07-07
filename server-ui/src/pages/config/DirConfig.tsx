import React, { useState, useEffect, useMemo } from 'react';
import { Button, Space, Tag, Popconfirm, Modal, Input, Table, Empty, App, Form, Segmented, Tooltip } from 'antd';
import { ProCard } from '@ant-design/pro-components';
import {
    PlusOutlined,
    EditOutlined,
    DeleteOutlined,
    SearchOutlined,
    ScanOutlined,
    LinkOutlined,
    DisconnectOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
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
    const [searchKeyword, setSearchKeyword] = useState('');
    const [refFilter, setRefFilter] = useState<'all' | 'linked' | 'orphan'>('all');
    const [page, setPage] = useState(1);
    const [pageSize, setPageSize] = useState(15);
    const [modalVisible, setModalVisible] = useState(false);
    const [isNew, setIsNew] = useState(false);
    const [currentProduct, setCurrentProduct] = useState<string>('');
    const [form] = Form.useForm();
    const { message } = App.useApp();
    const canManageRules = canAccessRole('operator');

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
        } catch {
            message.error('加载 Fingerprint 指纹库失败');
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
            title: 'Workflow / Dir 关联',
            key: 'reference',
            width: 200,
            filters: [
                { text: '已关联 Workflow', value: 'wf' },
                { text: '已关联 Dir', value: 'dir' },
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
                        <Tooltip title="在 dir.yaml 中被引用，该指纹命中后会触发路径探测">
                            <Tag color="blue" icon={<LinkOutlined />}>Dir</Tag>
                        </Tooltip>
                    ) : null}
                    {!r._refWorkflow && !r._refDir ? (
                        <Tooltip title="该指纹不被任何 Workflow 或 Dir 规则引用，扫描命中后什么也不会发生">
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
            width: 140,
            align: 'center' as const,
            render: (_: unknown, record: EnrichedFingerprint) => (
                <Space size={4}>
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
                            label="提取指纹名称 (Product Name)" 
                            name="product" 
                            rules={[{ required: true, message: '请填写指纹名称' }]}
                            extra="例如 `Liferay-Portal-System`"
                        >
                            <Input placeholder="输入该匹配规则对应的产品特征名" />
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
