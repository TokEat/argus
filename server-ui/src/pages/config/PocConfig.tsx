import React, { useState, useEffect, useMemo } from 'react';
import { Alert, Button, Space, Tag, Popconfirm, Modal, Drawer, Typography, Input, Table, Empty, App, Tooltip, Segmented } from 'antd';
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
import { listPocRulesPage, getWorkflowDictPage, getArsenal, saveArsenal, deleteArsenal, approveArsenal } from '../../services/api';
import { useGlobalAI, useAutoContext } from '../../contexts/GlobalAIContext';
import PocDebugPanel from './PocDebugPanel';
import PocWorkflowLinkModal from './PocWorkflowLinkModal';
import { canAccessRole } from '../../utils/auth';

const { Text } = Typography;
const WORKFLOW_USAGE_PAGE_SIZE = 100;
const POC_INDEX_PAGE_SIZE = 200;

const PocConfig: React.FC = () => {
    const { visible, openGlobalAI, registerEditableTarget } = useGlobalAI();
    const [loading, setLoading] = useState(true);
    const [usageLoading, setUsageLoading] = useState(true);
    const [pocRules, setPocRules] = useState<API.PocRuleMetadata[]>([]);
    const [pocIndex, setPocIndex] = useState<API.PocRuleMetadata[]>([]);
    const [total, setTotal] = useState(0);
    const [page, setPage] = useState(1);
    const [pageSize, setPageSize] = useState(15);
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
    const [workflowLinkOpen, setWorkflowLinkOpen] = useState(false);
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

    async function fetchWorkflowUsageSummaries(): Promise<API.WorkflowSummary[]> {
        const all: API.WorkflowSummary[] = [];
        let nextPage = 1;
        for (;;) {
            const res = await getWorkflowDictPage({ scope: 'all', page: nextPage, page_size: WORKFLOW_USAGE_PAGE_SIZE }).catch(() => null);
            if (!res) return all;
            all.push(...(res.items || []));
            if (!res.has_more) return all;
            nextPage += 1;
        }
    }

    async function fetchPocRuleSummaries(keyword: string): Promise<API.PocRuleMetadata[]> {
        const all: API.PocRuleMetadata[] = [];
        let nextPage = 1;
        for (;;) {
            const res = await listPocRulesPage({
                all: '1',
                page: nextPage,
                page_size: POC_INDEX_PAGE_SIZE,
                q: keyword || undefined,
            }).catch(() => null);
            if (!res) return all;
            all.push(...(res.items || []));
            if (!res.has_more) return all;
            nextPage += 1;
        }
    }

    const buildUsageMap = (workflows: API.WorkflowSummary[]) => {
        const map = new Map<string, string[]>();
        workflows.forEach((wf) => {
            (wf.pocs || []).forEach((rawName) => {
                const key = rawName.replace(/\.(ya?ml)$/i, '');
                if (!map.has(key)) map.set(key, []);
                map.get(key)!.push(wf.product);
            });
        });
        return map;
    };

    const fetchPageData = async () => {
        setLoading(true);
        try {
            const keyword = searchKeyword.trim();
            const pocs = await listPocRulesPage({ all: '1', page, page_size: pageSize, q: keyword || undefined });
            setPocRules(pocs.items || []);
            setTotal(pocs.total || 0);
        } catch {
            msg.error('加载 POC 弹药库失败');
        } finally {
            setLoading(false);
        }
    };

    const fetchUsageData = async () => {
        setUsageLoading(true);
        try {
            const keyword = searchKeyword.trim();
            const [allPocs, workflows] = await Promise.all([
                fetchPocRuleSummaries(keyword),
                fetchWorkflowUsageSummaries(),
            ]);
            setPocIndex(allPocs);
            setUsageMap(buildUsageMap(workflows));
        } catch {
            msg.error('加载 POC Workflow 统计失败');
        } finally {
            setUsageLoading(false);
        }
    };

    const fetchData = async () => {
        await Promise.all([fetchPageData(), fetchUsageData()]);
    };

    /** 返回该 POC 被哪些 workflow 引用（同时考虑带/不带后缀） */
    const getUsage = (fileName: string): string[] => {
        const stripped = fileName.replace(/\.(ya?ml)$/i, '');
        return usageMap.get(stripped) || usageMap.get(fileName) || [];
    };

    const filteredIndex = useMemo(() => {
        let arr = pocIndex;
        if (usageFilter === 'in_workflow') arr = arr.filter((a) => getUsage(a.source_file).length > 0);
        else if (usageFilter === 'not_in_workflow') arr = arr.filter((a) => getUsage(a.source_file).length === 0);
        return arr;
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [pocIndex, usageFilter, usageMap]);

    const visibleRows = useMemo(() => {
        if (usageFilter === 'all') return pocRules;
        const offset = (page - 1) * pageSize;
        return filteredIndex.slice(offset, offset + pageSize);
    }, [filteredIndex, page, pageSize, pocRules, usageFilter]);

    const activeTotal = usageFilter === 'all' ? total : filteredIndex.length;

    useEffect(() => {
        if (usageFilter === 'all') fetchPageData();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [page, pageSize, searchKeyword, usageFilter]);

    useEffect(() => {
        fetchUsageData();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [searchKeyword]);

    useEffect(() => {
        if (usageFilter === 'all') return;
        const maxPage = Math.max(1, Math.ceil(filteredIndex.length / pageSize));
        if (page > maxPage) setPage(maxPage);
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [usageFilter, filteredIndex.length, pageSize]);

    const usageStats = useMemo(() => {
        const inWf = pocIndex.filter((a) => getUsage(a.source_file).length > 0).length;
        return { inWf, notInWf: pocIndex.length - inWf };
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [pocIndex, usageMap]);

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
  metadata:
    argus-execution-class: detection

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
        setWorkflowLinkOpen(false);
        setEditorVisible(true);
    };

    const handleEdit = async (record: API.PocRuleMetadata) => {
        if (!canManageArsenals) return;
        setIsNew(false);
        setCurrentArsenal(null);
        setEditorContent('');
        setDebugVisible(false);
        setWorkflowLinkOpen(false);
        setEditorVisible(true);
        try {
            const arsenal = await getArsenal('poc', record.source_file);
            setCurrentArsenal(arsenal);
            setEditorContent(arsenal.Content || '');
        } catch {
            setCurrentArsenal({
                ID: record.artifact_id,
                TenantID: record.tenant_id,
                Type: 'poc',
                FileName: record.source_file,
                Content: '',
                Hash: record.content_hash,
                PreviousHash: '',
                Version: record.version,
                State: record.state,
                CreatedAt: record.created_at,
                UpdatedAt: record.updated_at,
            });
            msg.error('加载 POC 内容失败');
        }
    };

    /** 校验新建文件名是否与现有 POC 重名（兼容带不带 .yaml 后缀两种写法） */
    const checkDuplicate = (raw: string): API.PocRuleMetadata | null => {
        const name = raw.trim();
        if (!name) return null;
        const withExt = /\.ya?ml$/i.test(name) ? name : `${name}.yaml`;
        const stripped = name.replace(/\.ya?ml$/i, '');
        const candidates = pocIndex.length > 0 ? pocIndex : pocRules;
        return candidates.find((a) => {
            const aStripped = a.source_file.replace(/\.ya?ml$/i, '');
            return a.source_file === name || a.source_file === withExt || aStripped === stripped;
        }) || null;
    };

    const findDuplicatePoc = async (raw: string): Promise<API.PocRuleMetadata | null> => {
        const local = checkDuplicate(raw);
        if (local) return local;
        const name = raw.trim();
        if (!name) return null;
        const withExt = /\.ya?ml$/i.test(name) ? name : `${name}.yaml`;
        const stripped = name.replace(/\.ya?ml$/i, '');
        const res = await listPocRulesPage({ all: '1', page: 1, page_size: 20, q: stripped });
        return (res.items || []).find((item) => {
            const itemStripped = item.source_file.replace(/\.ya?ml$/i, '');
            return item.source_file === name || item.source_file === withExt || itemStripped === stripped;
        }) || null;
    };

    const duplicateOf = useMemo(() => (isNew ? checkDuplicate(newFileName) : null),
        // eslint-disable-next-line react-hooks/exhaustive-deps
        [isNew, newFileName, pocRules]);

    const doSave = async (fileName: string) => {
        if (!canManageArsenals) return;
        const remoteDuplicate = isNew ? await findDuplicatePoc(fileName) : null;
        if (isNew && remoteDuplicate && !duplicateOf) {
            msg.error(`POC ${remoteDuplicate.source_file} 已存在，请搜索后进入编辑确认覆盖`);
            return;
        }
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
        const remoteDuplicate = isNew ? await findDuplicatePoc(fileName) : null;
        if (isNew && remoteDuplicate) {
            throw `POC ${remoteDuplicate.source_file} 已存在，请搜索后进入编辑确认覆盖`;
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
                            <p>弹药库中已存在 <Text code>{duplicateOf.source_file}</Text>（当前状态：{duplicateOf.state}）。</p>
                            <p>继续保存将<strong>覆盖其内容</strong>，并把状态<strong>强制重置为草稿</strong>，需要重新审核才能生效。</p>
                            {getUsage(duplicateOf.source_file).length > 0 && (
                                <p style={{ color: '#ef4444' }}>⚠ 该 POC 当前被 {getUsage(duplicateOf.source_file).length} 个 Workflow 引用，覆盖后所有引用都会立即失效（直到重新审核）。</p>
                            )}
                        </div>
                    ),
                    okText: '确认覆盖',
                    okButtonProps: { danger: true },
                    cancelText: '取消',
                    onOk: async () => {
                        try { await doSave(duplicateOf.source_file); }
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

    const getExecutionClassTag = (value: API.PocRuleMetadata['execution_class']) => (
        value === 'verification'
            ? <Tag color="purple">验证型</Tag>
            : <Tag color="blue">检测型</Tag>
    );

    const getRiskTag = (record: API.PocRuleMetadata) => {
        const labels: Record<API.PocRuleMetadata['risk_level'], string> = {
            unknown: '风险未分类', info: '信息级', low: '低风险', medium: '中风险', high: '高风险',
        };
        const colors: Record<API.PocRuleMetadata['risk_level'], string> = {
            unknown: 'orange', info: 'default', low: 'green', medium: 'gold', high: 'red',
        };
        return (
            <Tooltip title={record.requires_second_confirmation ? '执行前必须二次确认' : '执行前仍需明确确认'}>
                <Tag color={colors[record.risk_level]} icon={record.requires_second_confirmation ? <WarningOutlined /> : undefined}>
                    {labels[record.risk_level]}
                </Tag>
            </Tooltip>
        );
    };

    const currentPocFileName = isNew ? newFileName.trim() : currentArsenal?.FileName || '';
    const currentPocUsage = currentPocFileName ? getUsage(currentPocFileName) : [];

    const columns: ColumnsType<API.PocRuleMetadata> = [
        {
            title: '文件名',
            dataIndex: 'source_file',
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
            dataIndex: 'state',
            key: 'state',
            width: 100,
            render: (state: string) => getStateTag(state),
            filters: [
                { text: '已审核', value: 'Approved' },
                { text: '草稿', value: 'Draft' },
            ],
            onFilter: (value, record) => record.state === value,
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
                const used = getUsage(record.source_file);
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
            title: (
                <Tooltip title="执行类别和执行风险独立于漏洞严重度；所有 POC 只能在风险验证流程中确认后执行。">
                    <span>执行治理</span>
                </Tooltip>
            ),
            key: 'execution_governance',
            width: 190,
            render: (_, record) => (
                <Space direction="vertical" size={2}>
                    {getExecutionClassTag(record.execution_class)}
                    {getRiskTag(record)}
                </Space>
            ),
        },
        {
            title: 'Hash',
            dataIndex: 'content_hash',
            key: 'hash',
            width: 140,
            ellipsis: true,
            render: (v: string) => <Text style={{ fontSize: 11, fontFamily: 'monospace', color: '#94a3b8' }}>{v?.slice(0, 12)}</Text>,
        },
        {
            title: '更新时间',
            dataIndex: 'updated_at',
            key: 'updated_at',
            width: 170,
            render: (v: string) => <Text style={{ fontSize: 12, color: '#64748b' }}>{v}</Text>,
        },
        ...(canManageArsenals ? [{
            title: '操作',
            key: 'actions',
            width: 250,
            render: (_: unknown, record: API.PocRuleMetadata) => (
                <Space size={4}>
                    <Button type="link" size="small" icon={<EditOutlined />} onClick={() => handleEdit(record)}>
                        编辑
                    </Button>
                    {canApproveArsenals && record.state === 'Draft' && (
                        <Popconfirm title="确认审核通过？将触发全网 Agent 规则重载" onConfirm={() => handleApprove(record.source_file)}>
                            <Button type="link" size="small" style={{ color: '#10b981' }} icon={<CheckOutlined />}>
                                审核
                            </Button>
                        </Popconfirm>
                    )}
                    <Popconfirm title={`确认删除 ${record.source_file}？`} onConfirm={() => handleDelete(record.source_file)}>
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
                        onChange={(e) => { setSearchKeyword(e.target.value); setPage(1); }}
                        style={{ width: 260 }}
                        allowClear
                    />
                    <Segmented
                        value={usageFilter}
                        onChange={(v) => {
                            setUsageFilter(v as typeof usageFilter);
                            setPage(1);
                        }}
                        options={[
                            { label: `全部 (${pocIndex.length || total})`, value: 'all' },
                            { label: `在 Workflow 中 (${usageStats.inWf})`, value: 'in_workflow' },
                            { label: `不在 Workflow 中 (${usageStats.notInWf})`, value: 'not_in_workflow' },
                        ]}
                    />
                </Space>
                <Space>
                    <Tag>当前页 {visibleRows.length} / 匹配 {activeTotal} 条</Tag>
                    {canManageArsenals && (
                        <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>
                            新增 POC
                        </Button>
                    )}
                </Space>
            </div>

            <Alert
                type="warning"
                showIcon
                style={{ marginBottom: 12 }}
                message="POC 不随普通资产扫描自动执行"
                description="所有 POC 仅能通过风险验证流程显式确认；高风险或未分类规则必须二次确认。需要利用、持久化或状态变更的能力必须使用独立 EXP 包。"
            />

            <ProCard className="glass-card" style={{ background: 'transparent', border: 'none', padding: 0 }}>
                {visibleRows.length === 0 && !loading && !usageLoading ? (
                    <Empty description="暂无 POC 规则" style={{ padding: '60px 0' }} />
                ) : (
                    <Table
                        columns={columns}
                        dataSource={visibleRows}
                        rowKey="id"
                        loading={loading || (usageFilter !== 'all' && usageLoading)}
                        pagination={{
                            current: page,
                            pageSize,
                            total: activeTotal,
                            showSizeChanger: true,
                            showTotal: (t) => `共 ${t} 条`,
                            onChange: (nextPage, nextPageSize) => {
                                setPage(nextPage);
                                setPageSize(nextPageSize);
                            },
                        }}
                        size="middle"
                        scroll={{ x: 1180 }}
                    />
                )}
            </ProCard>

            {canManageArsenals && (
            <Drawer
                    title={isNew ? '新建 POC' : `编辑 POC — ${currentArsenal?.FileName}`}
                    open={editorVisible}
                    onClose={() => {
                        setWorkflowLinkOpen(false);
                        setEditorVisible(false);
                    }}
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
                                        <WarningOutlined /> 已存在 <Text code>{duplicateOf.source_file}</Text>（{duplicateOf.state}），保存将覆盖并重置为草稿
                                        {getUsage(duplicateOf.source_file).length > 0 && <span style={{ color: '#ef4444' }}>，且会让 {getUsage(duplicateOf.source_file).length} 个 Workflow 引用立即失效</span>}
                                    </div>
                                )}
                            </div>
                        )}
                        {!isNew && currentPocFileName && (
                            <div style={{ marginBottom: 12 }}>
                                {currentPocUsage.length === 0 ? (
                                    <Alert
                                        type="warning"
                                        showIcon
                                        message="该 POC 不在 Workflow 中"
                                        description="扫描不会主动触发该 POC。请关联到匹配的 Workflow product 后再发布或审核扫描规则。"
                                        action={
                                            <Button size="small" type="primary" icon={<LinkOutlined />} onClick={() => setWorkflowLinkOpen(true)}>
                                                关联到 Workflow
                                            </Button>
                                        }
                                    />
                                ) : (
                                    <Alert
                                        type="info"
                                        showIcon
                                        message="该 POC 已关联 Workflow"
                                        description={
                                            <Space size={4} wrap>
                                                {currentPocUsage.slice(0, 8).map((product) => (
                                                    <Tag key={product} icon={<LinkOutlined />} color="blue">{product}</Tag>
                                                ))}
                                                {currentPocUsage.length > 8 && <Tag>+{currentPocUsage.length - 8}</Tag>}
                                            </Space>
                                        }
                                    />
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
            {canManageArsenals && currentPocFileName && (
                <PocWorkflowLinkModal
                    open={workflowLinkOpen}
                    pocFileName={currentPocFileName}
                    onClose={() => setWorkflowLinkOpen(false)}
                    onLinked={fetchData}
                />
            )}
        </>
    );
};

export default PocConfig;
