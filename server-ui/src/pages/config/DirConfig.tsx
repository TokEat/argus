import React, { useState, useEffect } from 'react';
import { Button, Space, Tag, Popconfirm, Modal, Input, Table, Empty, App, Form, Select } from 'antd';
import { ProCard } from '@ant-design/pro-components';
import {
    PlusOutlined,
    EditOutlined,
    DeleteOutlined,
    SearchOutlined,
    ScanOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import { getFingerprintDict, addFingerprintDict, updateFingerprintDict, deleteFingerprintDict } from '../../services/api';

const DirConfig: React.FC = () => {
    const [loading, setLoading] = useState(true);
    const [dictionaries, setDictionaries] = useState<API.FingerprintItem[]>([]);
    const [filtered, setFiltered] = useState<API.FingerprintItem[]>([]);
    const [searchKeyword, setSearchKeyword] = useState('');
    const [modalVisible, setModalVisible] = useState(false);
    const [isNew, setIsNew] = useState(false);
    const [currentProduct, setCurrentProduct] = useState<string>('');
    const [form] = Form.useForm();
    const { message } = App.useApp();

    const fetchData = async () => {
        setLoading(true);
        try {
            const result = await getFingerprintDict();
            setDictionaries(result || []);
        } catch {
            message.error('加载 Fingerprint 指纹库失败');
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
                d.rules?.some(p => p.toLowerCase().includes(lower))
            ));
        }
    }, [searchKeyword, dictionaries]);

    const handleCreate = () => {
        setIsNew(true);
        setCurrentProduct('');
        form.resetFields();
        setModalVisible(true);
    };

    const handleEdit = (record: API.FingerprintItem) => {
        setIsNew(false);
        setCurrentProduct(record.product);
        form.setFieldsValue({
            product: record.product,
            rules: record.rules || [],
        });
        setModalVisible(true);
    };

    const handleSave = async () => {
        try {
            const values = await form.validateFields();
            if (isNew) {
                await addFingerprintDict({
                    product: values.product,
                    rules: values.rules || [],
                });
                message.success('追加成功，全局规则库已通知更新。');
            } else {
                await updateFingerprintDict(currentProduct, {
                    product: values.product,
                    rules: values.rules || [],
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
            await deleteFingerprintDict(product);
            message.success('已删除');
            fetchData();
        } catch (error: unknown) { 
            message.error(typeof error === 'string' ? error : '删除失败'); 
        }
    };

    const columns: ColumnsType<API.FingerprintItem> = [
        {
            title: '指纹标识产品名 (Product)',
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
        {
            title: '操作',
            key: 'actions',
            width: 140,
            align: 'center',
            render: (_, record) => (
                <Space size={4}>
                    <Button type="link" size="small" icon={<EditOutlined />} onClick={() => handleEdit(record)}>编辑</Button>
                    <Popconfirm title="确认删除该产品的指纹规则？" onConfirm={() => handleDelete(record.product)}>
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
                    placeholder="搜索指纹产品特征或规则内容..."
                    prefix={<SearchOutlined style={{ color: '#94a3b8' }} />}
                    value={searchKeyword}
                    onChange={(e) => setSearchKeyword(e.target.value)}
                    style={{ width: 280 }}
                    allowClear
                />
                <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>新增特征指纹</Button>
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
                        pagination={{ pageSize: 15, showSizeChanger: true }} 
                        size="middle" 
                    />
                )}
            </ProCard>

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
                            rules={[{ required: true, message: '请提供至少1个匹配规则' }]}
                            extra="输入 CEL 或 GoExpr 形式提取逻辑，按回车键确认为一条规则（多条为 OR 或列表关系）"
                        >
                            <Select 
                                mode="tags" 
                                style={{ width: '100%' }} 
                                placeholder="例：body=&#34;Liferay&#34; || header=&#34;liferay&#34;" 
                                tokenSeparators={[]}
                            />
                        </Form.Item>
                    </Form>
                </div>
            </Modal>
        </>
    );
};

export default DirConfig;
