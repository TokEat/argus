import React, { useState, useEffect } from 'react';
import { Button, Space, Tag, Popconfirm, Modal, Input, Table, Empty, App, Form, Select, AutoComplete, Tooltip } from 'antd';
import { ProCard } from '@ant-design/pro-components';
import {
    PlusOutlined,
    EditOutlined,
    DeleteOutlined,
    SearchOutlined,
    ScanOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import { getDirDict, addDirDict, updateDirDict, deleteDirDict, getFingerprintDict } from '../../services/api';

const DirProbeConfig: React.FC = () => {
    const [loading, setLoading] = useState(true);
    const [dictionaries, setDictionaries] = useState<API.DirItem[]>([]);
    const [filtered, setFiltered] = useState<API.DirItem[]>([]);
    const [searchKeyword, setSearchKeyword] = useState('');
    const [modalVisible, setModalVisible] = useState(false);
    const [isNew, setIsNew] = useState(false);
    const [currentProduct, setCurrentProduct] = useState<string>('');
    const [fingerprintProducts, setFingerprintProducts] = useState<Set<string>>(new Set());
    const [form] = Form.useForm();
    const { message } = App.useApp();

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
        setIsNew(true);
        setCurrentProduct('');
        form.resetFields();
        setModalVisible(true);
    };

    const handleEdit = (record: API.DirItem) => {
        setIsNew(false);
        setCurrentProduct(record.product);
        form.setFieldsValue({
            product: record.product,
            paths: record.paths || [],
        });
        setModalVisible(true);
    };

    const handleSave = async () => {
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
        {
            title: '操作',
            key: 'actions',
            width: 140,
            align: 'center',
            render: (_, record) => (
                <Space size={4}>
                    <Button type="link" size="small" icon={<EditOutlined />} onClick={() => handleEdit(record)}>编辑</Button>
                    <Popconfirm title="确认删除该产品的探测路径？" onConfirm={() => handleDelete(record.product)}>
                        <Button type="link" danger size="small" icon={<DeleteOutlined />}>删除</Button>
                    </Popconfirm>
                </Space>
            ),
        },
    ];

    return (
        <>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
                <Input
                    placeholder="搜索产品或探测路径..."
                    prefix={<SearchOutlined style={{ color: '#94a3b8' }} />}
                    value={searchKeyword}
                    onChange={(e) => setSearchKeyword(e.target.value)}
                    style={{ width: 280 }}
                    allowClear
                />
                <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>新增 Dir 规则</Button>
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
                        pagination={{ pageSize: 15, showSizeChanger: true }}
                        size="middle"
                    />
                )}
            </ProCard>

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
                                    <Tooltip title="下拉可选择「指纹库中已存在」的 product 名，在与 Workflow / Fingerprint 统一名称后，扫描器识别到资产才会触发对应的 Dir 探测路径。">
                                        <Tag color="blue" style={{ cursor: 'help' }}>联动指纹库</Tag>
                                    </Tooltip>
                                </Space>
                            }
                            name="product"
                            rules={[{ required: true, message: '请填写产品名' }]}
                            extra={`指纹库当前共 ${fingerprintProducts.size} 个 product，选中已有 product 可保证识别后能触发该 Dir 探测规则。`}
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
                            rules={[{ required: true, message: '请提供至少 1 条路径' }]}
                            extra="按回车键确认为一条路径，例如 `/manager/html`、`/actuator`"
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
        </>
    );
};

export default DirProbeConfig;
