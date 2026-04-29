import React, { useState, useEffect, useMemo } from 'react';
import { Button, Space, Tag, Popconfirm, Modal, Drawer, Typography, Input, Table, Empty, App, Tooltip, Segmented } from 'antd';
import { ProCard } from '@ant-design/pro-components';
import {
    PlusOutlined,
    EditOutlined,
    DeleteOutlined,
    BugOutlined,
    CheckOutlined,
    SearchOutlined,
    LinkOutlined,
    DisconnectOutlined,
    WarningOutlined,
    RobotOutlined,
} from '@ant-design/icons';
import Editor from '@monaco-editor/react';
import type { ColumnsType } from 'antd/es/table';
import { listArsenals, saveArsenal, deleteArsenal, approveArsenal, getWorkflowDict } from '../../services/api';
import { useGlobalAI, useAutoContext } from '../../contexts/GlobalAIContext';
import PocDebugPanel from './PocDebugPanel';
import { canAccessRole } from '../../utils/auth';

const { Text } = Typography;

const PocConfig: React.FC = () => {
    const { visible, openGlobalAI, registerEditableTarget } = useGlobalAI();
    const [loading, setLoading] = useState(true);
    const [arsenals, setArsenals] = useState<API.Arsenal[]>([]);
    /** key: 不带后缀的 POC 名，value: 引用它的 workflow product 列表 */
    const [usageMap, setUsageMap] = useState<Map<string, string[]>>(new Map());
    const [usageFilter, setUsageFilter] = useState<'all' | 'in_workflow' | 'not_in_workflow'>('all');
    const [searchKeyword, setSearchKeyword] = useState('');
    const [editorVisible, setEditorVisible] = useState(false);
    const [isNew, setIsNew] = useState(false);
    const [currentArsenal, setCurrentArsenal] = useState<API.Arsenal | null>(null);
    const [editorContent, setEditorContent] = useState('');
    const [newFileName, setNewFileName] = useState('');
    const [debugVisible, setDebugVisible] = useState(false);
    const canManageArsenals = canAccessRole('operator');
    const canApproveArsenals = canAccessRole('admin');

    useAutoContext(editorVisible ? {
        action: 'editing_poc_in_modal',
        file_name: isNew ? newFileName : currentArsenal?.FileName || 'untitled.yaml',
        poc_content: editorContent,
        editable_target: {
            type: 'poc',
            label: isNew ? newFileName : currentArsenal?.FileName || 'untitled.yaml'
        }
    } : {});

    const handleDiagnose = (contextData: any) => {
        setDebugVisible(false);
        openGlobalAI({
            module: 'poc_list',
            action: 'debug',
            raw_data: contextData,
            file_name: isNew ? newFileName.trim() : currentArsenal?.FileName || ''
        });
    };
    const { message: msg } = App.useApp();

    const fetchData = async () => {
        setLoading(true);
        try {
            const [pocs, wfs] = await Promise.all([
                listArsenals('poc'),
                getWorkflowDict().catch(() => [] as API.WorkflowItem[]),
            ]);
            setArsenals(pocs || []);
            // 构造引用反向索引：POC 名（去后缀后） -> workflow product 列表
            const map = new Map<string, string[]>();
            (wfs || []).forEach((wf) => {
                (wf.pocs || []).forEach((rawName) => {
                    const key = rawName.replace(/\.(ya?ml)$/i, '');
                    if (!map.has(key)) map.set(key, []);
                    map.get(key)!.push(wf.product);
                });
            });
            setUsageMap(map);
        } catch {
            msg.error('加载 POC 弹药库失败');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchData();
    }, []);

    /** 返回该 POC 被哪些 workflow 引用（同时考虑带/不带后缀） */
    const getUsage = (fileName: string): string[] => {
        const stripped = fileName.replace(/\.(ya?ml)$/i, '');
        return usageMap.get(stripped) || usageMap.get(fileName) || [];
    };

    const filtered = useMemo(() => {
        let arr = arsenals;
        if (usageFilter === 'in_workflow') arr = arr.filter((a) => getUsage(a.FileName).length > 0);
        else if (usageFilter === 'not_in_workflow') arr = arr.filter((a) => getUsage(a.FileName).length === 0);
        if (!searchKeyword) return arr;
        const lower = searchKeyword.toLowerCase();
        return arr.filter((a) => a.FileName.toLowerCase().includes(lower));
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [arsenals, searchKeyword, usageFilter, usageMap]);

    const usageStats = useMemo(() => {
        const inWf = arsenals.filter((a) => getUsage(a.FileName).length > 0).length;
        return { inWf, notInWf: arsenals.length - inWf };
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [arsenals, usageMap]);

    const handleCreate = () => {
        if (!canManageArsenals) return;
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
        setDebugVisible(false);
        setEditorVisible(true);
    };

    const handleEdit = (record: API.Arsenal) => {
        if (!canManageArsenals) return;
        setIsNew(false);
        setCurrentArsenal(record);
        setEditorContent(record.Content);
        setDebugVisible(false);
        setEditorVisible(true);
    };

    /** 校验新建文件名是否与现有 POC 重名（兼容带不带 .yaml 后缀两种写法） */
    const checkDuplicate = (raw: string): API.Arsenal | null => {
        const name = raw.trim();
        if (!name) return null;
        const withExt = /\.ya?ml$/i.test(name) ? name : `${name}.yaml`;
        const stripped = name.replace(/\.ya?ml$/i, '');
        return arsenals.find((a) => {
            const aStripped = a.FileName.replace(/\.ya?ml$/i, '');
            return a.FileName === name || a.FileName === withExt || aStripped === stripped;
        }) || null;
    };

    const duplicateOf = useMemo(() => (isNew ? checkDuplicate(newFileName) : null),
        // eslint-disable-next-line react-hooks/exhaustive-deps
        [isNew, newFileName, arsenals]);

    const doSave = async (fileName: string) => {
        if (!canManageArsenals) return;
        await saveArsenal('poc', fileName, editorContent);
        msg.success(isNew ? (duplicateOf ? `POC ${fileName} 已覆盖（重置为草稿状态）` : 'POC 创建成功（草稿状态）') : 'POC 更新成功');
        setEditorVisible(false);
        fetchData();
    };

    const saveDraftFromAI = async (contentOverride?: string) => {
        if (!canManageArsenals) {
            throw '当前角色无权保存 POC';
        }
        const fileName = isNew ? newFileName.trim() : currentArsenal?.FileName || '';
        if (!fileName) {
            throw '请输入文件名';
        }
        if (isNew && duplicateOf) {
            throw '文件名已存在，请使用编辑器底部保存按钮确认覆盖';
        }
        const finalName = fileName;
        const draftContent = typeof contentOverride === 'string' ? contentOverride : editorContent;
        await saveArsenal('poc', finalName, draftContent);
        if (draftContent !== editorContent) {
            setEditorContent(draftContent);
        }
        msg.success(isNew ? (duplicateOf ? `POC ${finalName} 已覆盖（重置为草稿状态）` : 'POC 创建成功（草稿状态）') : 'POC 更新成功');
        fetchData();
    };

    useEffect(() => {
        if (!editorVisible) return undefined;
        return registerEditableTarget({
            id: 'poc-config-editor',
            type: 'poc',
            label: isNew ? newFileName || 'untitled.yaml' : currentArsenal?.FileName || 'untitled.yaml',
            getContent: () => editorContent,
            applyContent: (nextContent: string) => setEditorContent(nextContent),
            saveDraft: saveDraftFromAI,
        });
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [editorVisible, isNew, newFileName, currentArsenal?.FileName, editorContent, duplicateOf, registerEditableTarget]);

    const handleSave = async () => {
        if (!canManageArsenals) return;
        try {
            const fileName = isNew ? newFileName.trim() : currentArsenal?.FileName || '';
            if (!fileName) {
                msg.error('请输入文件名');
                return;
            }
            if (isNew && duplicateOf) {
                Modal.confirm({
                    title: '文件名已存在，将覆盖现有 POC',
                    icon: <WarningOutlined style={{ color: '#faad14' }} />,
                    content: (
                        <div>
                            <p>弹药库中已存在 <Text code>{duplicateOf.FileName}</Text>（当前状态：{duplicateOf.State}）。</p>
                            <p>继续保存将<strong>覆盖其内容</strong>，并把状态<strong>强制重置为草稿</strong>，需要重新审核才能生效。</p>
                            {getUsage(duplicateOf.FileName).length > 0 && (
                                <p style={{ color: '#ef4444' }}>⚠ 该 POC 当前被 {getUsage(duplicateOf.FileName).length} 个 Workflow 引用，覆盖后所有引用都会立即失效（直到重新审核）。</p>
                            )}
                        </div>
                    ),
                    okText: '确认覆盖',
                    okButtonProps: { danger: true },
                    cancelText: '取消',
                    onOk: async () => {
                        try { await doSave(duplicateOf.FileName); }
                        catch (e: unknown) { msg.error(typeof e === 'string' ? e : '保存失败'); }
                    },
                });
                return;
            }
            await doSave(fileName);
        } catch (error: unknown) {
            msg.error(typeof error === 'string' ? error : '保存失败');
        }
    };

    const handleDelete = async (fileName: string) => {
        if (!canManageArsenals) return;
        try {
            await deleteArsenal('poc', fileName);
            msg.success('POC 已删除');
            fetchData();
        } catch {
            msg.error('删除失败');
        }
    };

    const handleApprove = async (fileName: string) => {
        if (!canApproveArsenals) return;
        try {
            await approveArsenal('poc', fileName);
            msg.success('POC 已审核通过，已触发全网 Agent 规则重载');
            fetchData();
        } catch {
            msg.error('审核失败');
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
            title: (
                <Tooltip title="该 POC 是否被任何 Workflow 引用。未被引用的 POC 不会被扫描器主动触发。">
                    <Space size={4}><LinkOutlined /><span>Workflow 关联</span></Space>
                </Tooltip>
            ),
            key: 'usage',
            width: 200,
            render: (_, record) => {
                const used = getUsage(record.FileName);
                if (used.length === 0) {
                    return <Tag icon={<DisconnectOutlined />} color="default">不在 Workflow</Tag>;
                }
                return (
                    <Tooltip title={used.slice(0, 20).join(', ') + (used.length > 20 ? ` +${used.length - 20}` : '')}>
                        <Tag icon={<LinkOutlined />} color="blue">
                            {used.length} 个 Workflow
                        </Tag>
                    </Tooltip>
                );
            },
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
        ...(canManageArsenals ? [{
            title: '操作',
            key: 'actions',
            width: 250,
            render: (_: unknown, record: API.Arsenal) => (
                <Space size={4}>
                    <Button type="link" size="small" icon={<EditOutlined />} onClick={() => handleEdit(record)}>
                        编辑
                    </Button>
                    {canApproveArsenals && record.State === 'Draft' && (
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
        }] : []),
    ];

    return (
        <>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16, gap: 12, flexWrap: 'wrap' }}>
                <Space wrap>
                    <Input
                        placeholder="搜索 POC..."
                        prefix={<SearchOutlined style={{ color: '#94a3b8' }} />}
                        value={searchKeyword}
                        onChange={(e) => setSearchKeyword(e.target.value)}
                        style={{ width: 260 }}
                        allowClear
                    />
                    <Segmented
                        value={usageFilter}
                        onChange={(v) => setUsageFilter(v as typeof usageFilter)}
                        options={[
                            { label: `全部 (${arsenals.length})`, value: 'all' },
                            { label: `在 Workflow 中 (${usageStats.inWf})`, value: 'in_workflow' },
                            { label: `不在 Workflow 中 (${usageStats.notInWf})`, value: 'not_in_workflow' },
                        ]}
                    />
                </Space>
                <Space>
                    <Tag>{filtered.length} / {arsenals.length} 条</Tag>
                    {canManageArsenals && (
                        <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>
                            新增 POC
                        </Button>
                    )}
                </Space>
            </div>

            <ProCard className="glass-card" style={{ background: 'transparent', border: 'none', padding: 0 }}>
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
            </ProCard>

            {canManageArsenals && (
            <Drawer
                    title={isNew ? '新建 POC' : `编辑 POC — ${currentArsenal?.FileName}`}
                    open={editorVisible}
                    onClose={() => setEditorVisible(false)}
                    width={debugVisible ? 1400 : 900}
                    style={{ transform: visible ? 'translateX(-400px)' : 'none', transition: 'transform 0.3s' }}
                    mask={!visible}
                    maskClosable={false}
                    footer={
                    <div style={{ textAlign: 'right' }}>
                        <Space>
                            <Button icon={<BugOutlined />} onClick={() => { setDebugVisible((v) => !v); }}>
                                {debugVisible ? '收起调试' : '调试'}
                            </Button>
                            <Button onClick={() => openGlobalAI({
                                module: 'poc_list',
                                action: 'review',
                                file_name: isNew ? newFileName.trim() : currentArsenal?.FileName || '',
                                suggested_prompt: '请审查当前 POC，指出误报风险、结构问题和可改进点；如果需要修改，请输出完整更新后的 YAML。'
                            })}>
                                AI 分析
                            </Button>
                            <Button onClick={() => setEditorVisible(false)}>取消</Button>
                            <Button type="primary" onClick={handleSave}>保存（草稿）</Button>
                        </Space>
                    </div>
                    }
                    destroyOnClose
                >
                <div style={{ display: 'flex', gap: 16, height: 'calc(100vh - 200px)', minHeight: 600 }}>
                    <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: 12 }}>
                            <div style={{ flex: 1 }}>
                                {isNew && <Text strong style={{ display: 'block', marginBottom: 8 }}>文件名 *</Text>}
                                {!isNew && <Text strong style={{ display: 'block', marginBottom: 8, color: '#64748b' }}>POC 代码编辑</Text>}
                            </div>
                            <Button
                                type="dashed"
                                icon={<RobotOutlined />}
                                onClick={() => openGlobalAI({
                                    module: 'poc_list',
                                    action: 'generate',
                                    file_name: isNew ? newFileName.trim() : currentArsenal?.FileName || '',
                                    suggested_prompt: '请基于当前编辑器内容生成或优化这个 POC，输出完整可应用的 YAML。'
                                })}
                            >
                                AI 辅助生成
                            </Button>
                        </div>
                        {isNew && (
                            <div style={{ marginBottom: 16 }}>
                                <Input
                                    value={newFileName}
                                    onChange={(e) => setNewFileName(e.target.value)}
                                    placeholder="例: CVE-2024-XXXX.yaml"
                                    status={duplicateOf ? 'warning' : undefined}
                                    suffix={duplicateOf ? <WarningOutlined style={{ color: '#faad14' }} /> : undefined}
                                />
                                {duplicateOf && (
                                    <div style={{ marginTop: 6, fontSize: 12, color: '#d97706' }}>
                                        <WarningOutlined /> 已存在 <Text code>{duplicateOf.FileName}</Text>（{duplicateOf.State}），保存将覆盖并重置为草稿
                                        {getUsage(duplicateOf.FileName).length > 0 && <span style={{ color: '#ef4444' }}>，且会让 {getUsage(duplicateOf.FileName).length} 个 Workflow 引用立即失效</span>}
                                    </div>
                                )}
                            </div>
                        )}
                        <div style={{ flex: 1, border: '1px solid #e2e8f0', borderRadius: 8, overflow: 'hidden' }}>
                            <Editor
                                height="100%"
                                language="yaml"
                                theme="vs-dark"
                                value={editorContent}
                                onChange={(val) => setEditorContent(val || '')}
                                options={{ minimap: { enabled: false }, fontSize: 13 }}
                            />
                        </div>
                    </div>
                    <div style={{ width: 550, flexShrink: 0, display: debugVisible ? 'flex' : 'none', flexDirection: 'column', overflowY: 'auto' }}>
                        <PocDebugPanel visible={debugVisible} pocContent={editorContent} onDiagnose={handleDiagnose} />
                    </div>
                </div>
                </Drawer>
            )}
        </>
    );
};

export default PocConfig;
