import React, { useState, useEffect } from 'react';
import { Button, Space, Tag, Popconfirm, Modal, Typography, Input, Table, Empty, App } from 'antd';
import {
    PlusOutlined,
    EditOutlined,
    DeleteOutlined,
    BugOutlined,
    CheckOutlined,
    SearchOutlined,
} from '@ant-design/icons';
import Editor from '@monaco-editor/react';
import type { ColumnsType } from 'antd/es/table';
import { listArsenals, saveArsenal, deleteArsenal, approveArsenal, aiAnalyzeArsenal } from '../../services/api';

const { Text } = Typography;

const PocConfig: React.FC = () => {
    const [loading, setLoading] = useState(true);
    const [arsenals, setArsenals] = useState<API.Arsenal[]>([]);
    const [filtered, setFiltered] = useState<API.Arsenal[]>([]);
    const [searchKeyword, setSearchKeyword] = useState('');
    const [editorVisible, setEditorVisible] = useState(false);
    const [isNew, setIsNew] = useState(false);
    const [currentArsenal, setCurrentArsenal] = useState<API.Arsenal | null>(null);
    const [editorContent, setEditorContent] = useState('');
    const [newFileName, setNewFileName] = useState('');
    const { message: msg } = App.useApp();

    const fetchData = async () => {
        setLoading(true);
        try {
            const result = await listArsenals('poc');
            setArsenals(result || []);
            applyFilter(result || [], searchKeyword);
        } catch {
            msg.error('加载 POC 弹药库失败');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchData();
    }, []);

    const applyFilter = (data: API.Arsenal[], keyword: string) => {
        if (!keyword) {
            setFiltered(data);
        } else {
            const lower = keyword.toLowerCase();
            setFiltered(data.filter(a => a.FileName.toLowerCase().includes(lower)));
        }
    };

    useEffect(() => {
        applyFilter(arsenals, searchKeyword);
    }, [searchKeyword, arsenals]);

    const handleCreate = () => {
        setIsNew(true);
        setCurrentArsenal(null);
        setNewFileName('');
        setEditorContent(`id: poc-template

info:
  name: POC Template
  author: your-name
  severity: medium
  description: Description here
  tags: tag1,tag2

http:
  - method: GET
    path:
      - "{{BaseURL}}/path"
    matchers:
      - type: word
        words:
          - "keyword"
`);
        setEditorVisible(true);
    };

    const handleEdit = (record: API.Arsenal) => {
        setIsNew(false);
        setCurrentArsenal(record);
        setEditorContent(record.Content);
        setEditorVisible(true);
    };

    const handleSave = async () => {
        try {
            const fileName = isNew ? newFileName.trim() : currentArsenal?.FileName || '';
            if (!fileName) {
                msg.error('请输入文件名');
                return;
            }
            await saveArsenal('poc', fileName, editorContent);
            msg.success(isNew ? 'POC 创建成功（草稿状态）' : 'POC 更新成功');
            setEditorVisible(false);
            fetchData();
        } catch (error: unknown) {
            msg.error(typeof error === 'string' ? error : '保存失败');
        }
    };

    const handleDelete = async (fileName: string) => {
        try {
            await deleteArsenal('poc', fileName);
            msg.success('POC 已删除');
            fetchData();
        } catch {
            msg.error('删除失败');
        }
    };

    const handleApprove = async (fileName: string) => {
        try {
            await approveArsenal('poc', fileName);
            msg.success('POC 已审核通过，已触发全网 Agent 规则重载');
            fetchData();
        } catch {
            msg.error('审核失败');
        }
    };

    const handleAiAnalyze = async () => {
        try {
            const result = await aiAnalyzeArsenal(editorContent);
            Modal.info({
                title: 'AI 分析结果',
                content: (
                    <div>
                        <p><strong>建议：</strong><Tag color={result.suggestion === 'Approve' ? 'green' : 'red'}>{result.suggestion}</Tag></p>
                        <p><strong>原因：</strong>{result.reason}</p>
                        <p><strong>置信度：</strong>{(result.confidence * 100).toFixed(0)}%</p>
                    </div>
                ),
            });
        } catch {
            msg.error('AI 分析失败');
        }
    };

    const getStateTag = (state: string) => {
        if (state === 'Approved') return <Tag color="green">已审核</Tag>;
        return <Tag color="orange">草稿</Tag>;
    };

    const columns: ColumnsType<API.Arsenal> = [
        {
            title: '文件名',
            dataIndex: 'FileName',
            key: 'filename',
            ellipsis: true,
            render: (name: string) => (
                <Space>
                    <BugOutlined style={{ color: '#ef4444' }} />
                    <Text strong>{name}</Text>
                </Space>
            ),
        },
        {
            title: '状态',
            dataIndex: 'State',
            key: 'state',
            width: 100,
            render: (state: string) => getStateTag(state),
            filters: [
                { text: '已审核', value: 'Approved' },
                { text: '草稿', value: 'Draft' },
            ],
            onFilter: (value, record) => record.State === value,
        },
        {
            title: 'Hash',
            dataIndex: 'Hash',
            key: 'hash',
            width: 140,
            ellipsis: true,
            render: (v: string) => <Text style={{ fontSize: 11, fontFamily: 'monospace', color: '#94a3b8' }}>{v?.slice(0, 12)}</Text>,
        },
        {
            title: '更新时间',
            dataIndex: 'UpdatedAt',
            key: 'updated_at',
            width: 170,
            render: (v: string) => <Text style={{ fontSize: 12, color: '#64748b' }}>{v}</Text>,
        },
        {
            title: '操作',
            key: 'actions',
            width: 250,
            render: (_, record) => (
                <Space size={4}>
                    <Button type="link" size="small" icon={<EditOutlined />} onClick={() => handleEdit(record)}>
                        编辑
                    </Button>
                    {record.State === 'Draft' && (
                        <Popconfirm title="确认审核通过？将触发全网 Agent 规则重载" onConfirm={() => handleApprove(record.FileName)}>
                            <Button type="link" size="small" style={{ color: '#10b981' }} icon={<CheckOutlined />}>
                                审核
                            </Button>
                        </Popconfirm>
                    )}
                    <Popconfirm title={`确认删除 ${record.FileName}？`} onConfirm={() => handleDelete(record.FileName)}>
                        <Button type="link" danger size="small" icon={<DeleteOutlined />}>
                            删除
                        </Button>
                    </Popconfirm>
                </Space>
            ),
        },
    ];

    return (
        <>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
                <Input
                    placeholder="搜索 POC..."
                    prefix={<SearchOutlined style={{ color: '#94a3b8' }} />}
                    value={searchKeyword}
                    onChange={(e) => setSearchKeyword(e.target.value)}
                    style={{ width: 260 }}
                    allowClear
                />
                <Space>
                    <Tag>{filtered.length} / {arsenals.length} 条</Tag>
                    <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>
                        新增 POC
                    </Button>
                </Space>
            </div>

            {filtered.length === 0 && !loading ? (
                <Empty description="暂无 POC 规则" style={{ padding: '60px 0' }} />
            ) : (
                <Table
                    columns={columns}
                    dataSource={filtered}
                    rowKey="ID"
                    loading={loading}
                    pagination={{ pageSize: 15, showTotal: (t) => `共 ${t} 条` }}
                    size="middle"
                />
            )}

            {/* POC Editor Modal */}
            <Modal
                title={isNew ? '新建 POC' : `编辑 POC — ${currentArsenal?.FileName}`}
                open={editorVisible}
                onCancel={() => setEditorVisible(false)}
                width={900}
                footer={[
                    <Button key="ai" onClick={handleAiAnalyze}>AI 分析</Button>,
                    <Button key="cancel" onClick={() => setEditorVisible(false)}>取消</Button>,
                    <Button key="save" type="primary" onClick={handleSave}>保存（草稿）</Button>,
                ]}
                destroyOnClose
            >
                {isNew && (
                    <div style={{ marginBottom: 16 }}>
                        <Text strong style={{ display: 'block', marginBottom: 8 }}>文件名 *</Text>
                        <Input
                            value={newFileName}
                            onChange={(e) => setNewFileName(e.target.value)}
                            placeholder="例: CVE-2024-XXXX.yaml"
                        />
                    </div>
                )}
                <div style={{ height: 500, border: '1px solid #e2e8f0', borderRadius: 8, overflow: 'hidden' }}>
                    <Editor
                        height="100%"
                        language="yaml"
                        theme="vs-dark"
                        value={editorContent}
                        onChange={(val) => setEditorContent(val || '')}
                        options={{ minimap: { enabled: false }, fontSize: 13 }}
                    />
                </div>
            </Modal>
        </>
    );
};

export default PocConfig;
