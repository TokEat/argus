import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Alert, Button, Space, Tag, Popconfirm, Modal, Input, Table, Empty, App, Form, Select, AutoComplete, Tooltip } from 'antd';
import { ProCard } from '@ant-design/pro-components';
import {
    PlusOutlined,
    EditOutlined,
    DeleteOutlined,
    SearchOutlined,
    ScanOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import { useSearchParams } from 'react-router-dom';
import { getDirDict, addDirDict, updateDirDict, deleteDirDict, getFingerprintDict } from '../../services/api';
import { useAutoContext } from '../../contexts/GlobalAIContext';
import { canAccessRole } from '../../utils/auth';

const DirProbeConfig: React.FC = () => {
    const [loading, setLoading] = useState(true);
    const [dictionaries, setDictionaries] = useState<API.DirItem[]>([]);
    const [filtered, setFiltered] = useState<API.DirItem[]>([]);
    const [searchKeyword, setSearchKeyword] = useState('');
    const [modalVisible, setModalVisible] = useState(false);
    const [isNew, setIsNew] = useState(false);
    const [currentProduct, setCurrentProduct] = useState<string>('');
    const [page, setPage] = useState(1);
    const [pageSize, setPageSize] = useState(15);
    const [fingerprintProducts, setFingerprintProducts] = useState<Set<string>>(new Set());
    const [form] = Form.useForm();
    const { message } = App.useApp();
    const [searchParams] = useSearchParams();
    const handledProduct = useRef<string>('');
    const canManageRules = canAccessRole('admin');

    const fetchData = async () => {
        setLoading(true);
        try {
            const [result, fps] = await Promise.all([getDirDict(), getFingerprintDict()]);
            setDictionaries(result || []);
            setFingerprintProducts(new Set((fps || []).map((f) => f.product)));
        } catch {
            message.error('加载 Dir 探测规则失败');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => { fetchData(); }, []);

    useAutoContext({
        dir_dictionary: {
            total_rules: dictionaries.length,
            search_keyword: searchKeyword,
        },
        editing_dir_rule: modalVisible ? {
            product: currentProduct,
            paths: form.getFieldValue('paths'),
            is_new: isNew
        } : null
    });

    useEffect(() => {
        if (!searchKeyword) {
            setFiltered(dictionaries);
        } else {
            const lower = searchKeyword.toLowerCase();
            setFiltered(dictionaries.filter(d =>
                d.product.toLowerCase().includes(lower) ||
                d.paths?.some(p => p.toLowerCase().includes(lower))
            ));
        }
    }, [searchKeyword, dictionaries]);

    const handleCreate = () => {
        if (!canManageRules) return;
        setIsNew(true);
        setCurrentProduct('');
        form.resetFields();
        setModalVisible(true);
    };

    const handleEdit = useCallback((record: API.DirItem) => {
        if (!canManageRules) return;
        setIsNew(false);
        setCurrentProduct(record.product);
        form.setFieldsValue({
            product: record.product,
            paths: record.paths || [],
        });
        setModalVisible(true);
    }, [canManageRules, form]);

    useEffect(() => {
        const product = (searchParams.get('product') || '').trim();
        if (loading || !product || handledProduct.current === product) return;

        handledProduct.current = product;
        setSearchKeyword(product);
        if (!canManageRules) return;

        const existing = dictionaries.find((item) => item.product === product);
        if (existing) {
            handleEdit(existing);
            return;
        }

        setIsNew(true);
        setCurrentProduct(product);
        form.resetFields();
        form.setFieldsValue({ product, paths: [] });
        setModalVisible(true);
    }, [canManageRules, dictionaries, form, handleEdit, loading, searchParams]);

    const handleSave = async () => {
        if (!canManageRules) return;
        try {
            const values = await form.validateFields();
            if (isNew) {
                await addDirDict({
                    product: values.product,
                    paths: values.paths || [],
                });
                message.success('追加成功，全局规则库已通知更新。');
            } else {
                await updateDirDict(currentProduct, {
                    product: values.product,
                    paths: values.paths || [],
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
            await deleteDirDict(product);
            message.success('已删除');
            fetchData();
        } catch (error: unknown) {
            message.error(typeof error === 'string' ? error : '删除失败');
        }
    };

    const columns: ColumnsType<API.DirItem> = [
        {
            title: '产品名 (Product)',
            dataIndex: 'product',
            key: 'product',
            width: 300,
            render: (text: string) => (
                <Space>
                    <ScanOutlined style={{ color: '#0ea5e9' }} />
                    <span style={{ fontWeight: 600 }}>{text}</span>
                </Space>
            ),
        },
        {
            title: '探测路径 (Paths)',
            dataIndex: 'paths',
            key: 'paths',
            render: (paths: string[]) => (
                <Space wrap style={{ padding: '4px 0' }}>
                    {paths?.map((p, idx) => (
                        <Tag
                            color="geekblue"
                            key={idx}
                            style={{ whiteSpace: 'normal', wordBreak: 'break-all', maxWidth: '600px', padding: '4px 8px' }}
                        >
                            <span style={{ fontFamily: 'monospace', fontSize: '13px' }}>{p}</span>
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
            render: (_: unknown, record: API.DirItem) => (
                <Space size={4}>
                    <Button type="link" size="small" icon={<EditOutlined />} onClick={() => handleEdit(record)}>编辑</Button>
                    <Popconfirm title="确认删除该产品的探测路径？" onConfirm={() => handleDelete(record.product)}>
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
                message="路径探针去特征路径上看是不是该产品"
                description="启用主动路径指纹后，Scanner 会在 HTTP 探测后请求每个产品的特征路径。路径是提问，命中必须靠与路径无关的标题、Header、Cookie 或独特正文；正文里出现探测路径本身不算确认。有独立内容证据时写入 Active-Finger 并可供 Workflow/POC 使用。dir-fallback 只记录「这条路径值得看」，不作为已识别、不调度 POC。深度预设默认开启该阶段。"
            />
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
                <Input
                    placeholder="搜索产品或探测路径..."
                    prefix={<SearchOutlined style={{ color: '#94a3b8' }} />}
                    value={searchKeyword}
                    onChange={(e) => {
                        setSearchKeyword(e.target.value);
                        setPage(1);
                    }}
                    style={{ width: 280 }}
                    allowClear
                />
                {canManageRules && <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>新增 Dir 规则</Button>}
            </div>

            <ProCard className="glass-card" style={{ background: 'transparent', border: 'none', padding: 0 }}>
                {filtered.length === 0 && !loading ? (
                    <Empty description="暂无 Dir 探测规则" style={{ padding: '60px 0' }} />
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
                            showTotal: (total) => `共 ${total} 条`,
                            onChange: (nextPage, nextPageSize) => {
                                setPage(nextPageSize === pageSize ? nextPage : 1);
                                setPageSize(nextPageSize);
                            },
                        }}
                        size="middle"
                    />
                )}
            </ProCard>

            {canManageRules && (
            <Modal
                    title={isNew ? '添加 Dir 探测规则' : `编辑 Dir 规则 — ${currentProduct}`}
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
                                    <span>产品名 (Product Name)</span>
                                    <Tooltip title="下拉可选择被动指纹库中的 product 名。主动路径请求完成后，Scanner 会用这个同名产品的被动规则复核路径响应。">
                                        <Tag color="blue" style={{ cursor: 'help' }}>联动指纹库</Tag>
                                    </Tooltip>
                                </Space>
                            }
                            name="product"
                            rules={[{ required: true, message: '请填写产品名' }]}
                            extra={`指纹库当前共 ${fingerprintProducts.size} 个 product。优先选择已有 product，路径响应通常需由同名被动规则确认后写入 Active-Finger。`}
                        >
                            <AutoComplete
                                placeholder="例：Tomcat、Spring-Boot（输入后下拉可选指纹库已有 product）"
                                allowClear
                                showSearch
                                filterOption={(input, option) =>
                                    (option?.value as string)?.toLowerCase().includes(input.toLowerCase())
                                }
                                options={Array.from(fingerprintProducts).sort().map((p) => ({
                                    value: p,
                                    label: (
                                        <Space>
                                            <span>{p}</span>
                                            <Tag color="green">指纹已配置</Tag>
                                        </Space>
                                    ),
                                }))}
                            />
                        </Form.Item>

                        <Form.Item
                            label="探测路径列表 (Paths)"
                            name="paths"
                            rules={[
                                { required: true, message: '请提供至少 1 条路径' },
                                {
                                    validator: (_, value?: string[]) => {
                                        const paths = value || [];
                                        if (paths.length > 128) return Promise.reject(new Error('每个产品最多 128 条路径'));
                                        if (paths.some((path) => !path.trim().startsWith('/') || path.trim().startsWith('//'))) {
                                            return Promise.reject(new Error('路径必须以单个 / 开头'));
                                        }
                                        return Promise.resolve();
                                    },
                                },
                            ]}
                            extra="按回车确认为一条根相对路径，例如 `/manager/html`、`/actuator`；保存时 Server 会 trim 并去重。"
                        >
                            <Select
                                mode="tags"
                                style={{ width: '100%' }}
                                placeholder="例：/manager/html"
                                tokenSeparators={[]}
                            />
                        </Form.Item>
                    </Form>
                </div>
                </Modal>
            )}
        </>
    );
};

export default DirProbeConfig;
