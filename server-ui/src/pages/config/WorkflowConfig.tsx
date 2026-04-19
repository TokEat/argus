import React, { useState, useEffect } from 'react';
import { Button, Space, Tag, Popconfirm, Modal, Input, Table, Empty, App, Form, Select } from 'antd';
import { ProCard } from '@ant-design/pro-components';
import {
    PlusOutlined,
    EditOutlined,
    DeleteOutlined,
    SearchOutlined,
    ApartmentOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import { getWorkflowDict, addWorkflowDict, updateWorkflowDict, deleteWorkflowDict, listArsenals } from '../../services/api';

const WorkflowConfig: React.FC = () => {
    const [loading, setLoading] = useState(true);
    const [dictionaries, setDictionaries] = useState<API.WorkflowItem[]>([]);
    const [filtered, setFiltered] = useState<API.WorkflowItem[]>([]);
    const [searchKeyword, setSearchKeyword] = useState('');
    const [modalVisible, setModalVisible] = useState(false);
    const [isNew, setIsNew] = useState(false);
    const [currentProduct, setCurrentProduct] = useState<string>('');
    const [pocList, setPocList] = useState<{label:string; value:string}[]>([]);
    const [form] = Form.useForm();
    const { message } = App.useApp();

    const fetchData = async () => {
        setLoading(true);
        try {
            const result = await getWorkflowDict();
            setDictionaries(result || []);
            
            // 下拉搜索字典支持
            const pocs = await listArsenals('poc', true, true);
            if (pocs && pocs.length > 0) {
                setPocList(pocs.map(p => ({ label: p.FileName, value: p.FileName })));
            }
        } catch {
            message.error('加载 Workflow 字典失败');
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
                d.pocs?.some(p => p.toLowerCase().includes(lower)) ||
                d.type?.some(t => t.toLowerCase().includes(lower))
            ));
        }
    }, [searchKeyword, dictionaries]);

    const handleCreate = () => {
        setIsNew(true);
        setCurrentProduct('');
        form.resetFields();
        setModalVisible(true);
    };

    const handleEdit = (record: API.WorkflowItem) => {
        setIsNew(false);
        setCurrentProduct(record.product);
        form.setFieldsValue({
            product: record.product,
            type: record.type || [],
            pocs: record.pocs || [],
        });
        setModalVisible(true);
    };

    const handleSave = async () => {
        try {
            const values = await form.validateFields();
            if (isNew) {
                await addWorkflowDict({
                    product: values.product,
                    type: values.type || [],
                    pocs: values.pocs || [],
                });
                message.success('追加成功，全局规则库已通知更新。');
            } else {
                await updateWorkflowDict(currentProduct, {
                    product: values.product,
                    type: values.type || [],
                    pocs: values.pocs || [],
                });
                message.success('更新成功，全局规则库已通知更新。');
            }
            setModalVisible(false);
            fetchData();
        } catch (error: unknown) {
            const errBody = error as Error;
            // validation errors are objects
            if (typeof error === 'string') {
                message.error(error);
            } else if (errBody && errBody.message) {
                // ant d form error object skip
            }
        }
    };

    const handleDelete = async (product: string) => {
        try {
            await deleteWorkflowDict(product);
            message.success('已删除');
            fetchData();
        } catch (error: unknown) { 
            message.error(typeof error === 'string' ? error : '删除失败'); 
        }
    };

    const columns: ColumnsType<API.WorkflowItem> = [
        {
            title: '关联产品 (Product)',
            dataIndex: 'product',
            key: 'product',
            width: 280,
            render: (text: string) => (
                <Space>
                    <ApartmentOutlined style={{ color: '#8b5cf6' }} />
                    <span style={{ fontWeight: 600 }}>{text}</span>
                </Space>
            ),
        },
        {
            title: '扫描阶段类型 (Type)',
            dataIndex: 'type',
            key: 'type',
            width: 250,
            render: (types: string[]) => (
                <Space wrap>
                    {types?.map((t, idx) => (
                        <Tag color="geekblue" key={idx}>{t}</Tag>
                    ))}
                </Space>
            ),
        },
        {
            title: '触发 POC (Pocs)',
            dataIndex: 'pocs',
            key: 'pocs',
            render: (pocs: string[]) => (
                <Space wrap>
                    {pocs?.map((p, idx) => (
                        <Tag color="red" key={idx}>{p}</Tag>
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
                    <Popconfirm title="确认删除该规则链的关联映射？" onConfirm={() => handleDelete(record.product)}>
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
                    placeholder="搜索关联产品、类型或 POC..."
                    prefix={<SearchOutlined style={{ color: '#94a3b8' }} />}
                    value={searchKeyword}
                    onChange={(e) => setSearchKeyword(e.target.value)}
                    style={{ width: 280 }}
                    allowClear
                />
                <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>新增规则映射</Button>
            </div>

            <ProCard className="glass-card" style={{ background: 'transparent', border: 'none', padding: 0 }}>
                {filtered.length === 0 && !loading ? (
                    <Empty description="暂无关联映射" style={{ padding: '60px 0' }} />
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
                title={isNew ? '添加 Workflow 映射规则' : `编辑规则映射 — ${currentProduct}`}
                open={modalVisible}
                onCancel={() => setModalVisible(false)}
                onOk={handleSave}
                width={650}
                destroyOnClose
            >
                <div style={{ padding: '16px 0 0 0' }}>
                    <Form form={form} layout="vertical">
                        <Form.Item 
                            label="关联产品 / 特征名 (Product)" 
                            name="product" 
                            rules={[{ required: true, message: '请填写关联产品名称' }]}
                        >
                            <Input placeholder="输入精准组件名称，如 Liferay 或 Spring-Framework" />
                        </Form.Item>

                        <Form.Item 
                            label="触发阶段 (Type) [选填]" 
                            name="type"
                        >
                            <Select 
                                mode="tags" 
                                style={{ width: '100%' }} 
                                placeholder="输入扫描阶段类型标记，按回车添加，如 poc" 
                            />
                        </Form.Item>

                        <Form.Item 
                            label="挂载 POC 链路 (Pocs) [选填]" 
                            name="pocs"
                        >
                            <Select 
                                mode="tags" 
                                style={{ width: '100%' }} 
                                placeholder="输入并搜索需要下发的 POC 名称，支持下拉选择" 
                                showSearch
                                options={pocList}
                                filterOption={(input, option) =>
                                    (option?.label ?? '').toString().toLowerCase().includes(input.toLowerCase())
                                }
                            />
                        </Form.Item>
                    </Form>
                </div>
            </Modal>
        </>
    );
};

export default WorkflowConfig;
