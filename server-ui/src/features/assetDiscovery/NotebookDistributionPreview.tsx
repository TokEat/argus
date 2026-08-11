import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Alert, Button, Descriptions, Drawer, Input, Modal, Select, Space, Table, Tag, Typography } from 'antd';
import { DeleteOutlined, EditOutlined, ReloadOutlined, SearchOutlined, UndoOutlined } from '@ant-design/icons';
import dayjs from 'dayjs';
import type { ColumnsType } from 'antd/es/table';
import { listTasks } from '../../services/api';
import { normalizeTaskStatus } from '../../utils/taskStatus';
import {
    listAccessibleAssetDiscoveryNotebookItems,
    listProjectAssetDiscoveryNotebookItems,
    materializeProjectAssetDiscoveryNotebookDistribution,
    previewProjectAssetDiscoveryNotebookDistribution,
    setProjectAssetDiscoveryNotebookItemRemoved,
    updateProjectAssetDiscoveryNotebookItem,
} from './api';

const { Paragraph, Text } = Typography;

const cannotAppend = (task: API.RootTask) => {
    const status = normalizeTaskStatus(task.Status);
    return !!task.ArchivedAt || ['CREATED', 'STOPPING', 'UNKNOWN'].includes(status);
};

const newIdempotencyKey = () => globalThis.crypto?.randomUUID?.()
    || `argus-${Date.now()}-${Math.random().toString(36).slice(2)}`;

const isPreviewExpired = (error: unknown) => {
    const text = typeof error === 'string' ? error : error instanceof Error ? error.message : '';
    return /\b409\b|(?:plan|preview).*(?:expired|stale)|(?:expired|stale).*(?:plan|preview)/i.test(text);
};

const isIdempotencyConflict = (error: unknown) => {
    const text = typeof error === 'string' ? error : error instanceof Error ? error.message : '';
    return /idempotency.*conflict|conflict.*idempotency/i.test(text);
};

interface Props {
    projectId: string;
    projectName?: string;
    enabled: boolean;
    message: { error: (content: string) => void; success: (content: string) => void };
}

const NotebookDistributionPreview: React.FC<Props> = ({ projectId, projectName, enabled, message }) => {
    const [scope, setScope] = useState<'project' | 'accessible'>('project');
    const [notebook, setNotebook] = useState<API.AssetDiscoveryNotebookList | null>(null);
    const [notebookLoading, setNotebookLoading] = useState(false);
    const [page, setPage] = useState(1);
    const [pageSize, setPageSize] = useState(20);
    const [selectedItemIds, setSelectedItemIds] = useState<number[]>([]);
    const [tasks, setTasks] = useState<API.RootTask[]>([]);
    const [tasksLoading, setTasksLoading] = useState(false);
    const [taskId, setTaskId] = useState<string>();
    const [preview, setPreview] = useState<API.AssetDiscoveryNotebookDistributionPreview | null>(null);
    const [previewOpen, setPreviewOpen] = useState(false);
    const [previewing, setPreviewing] = useState(false);
    const [materializing, setMaterializing] = useState(false);
    const [queryInput, setQueryInput] = useState('');
    const [tagInput, setTagInput] = useState('');
    const [query, setQuery] = useState('');
    const [tagFilter, setTagFilter] = useState('');
    const [stateFilter, setStateFilter] = useState<'active' | 'removed' | 'all'>('active');
    const [editingItem, setEditingItem] = useState<API.AssetDiscoveryNotebookItem | null>(null);
    const [editingTags, setEditingTags] = useState('');
    const [editingNote, setEditingNote] = useState('');
    const [savingItem, setSavingItem] = useState(false);
    const [changingItemId, setChangingItemId] = useState<number | null>(null);
    const [removingItem, setRemovingItem] = useState<API.AssetDiscoveryNotebookItem | null>(null);
    const notebookRequest = useRef(0);
    const tasksRequest = useRef(0);
    const previewRequest = useRef(0);
    const materializeRequest = useRef(0);
    const materializingRef = useRef(false);
    const idempotencyKey = useRef<string | undefined>(undefined);
    const projectScope = scope === 'project';
    const batchTypes = preview ? Object.entries(preview.batch_profile.batches_by_type) : [];
    const targetCategories = preview ? Object.entries({ IP: preview.target_summary.ips, 'IP:端口': preview.target_summary.ip_ports, CIDR: preview.target_summary.cidrs, IP范围: preview.target_summary.ip_ranges, 域名: preview.target_summary.domains, '域名:端口': preview.target_summary.domain_ports, URL: preview.target_summary.urls, 搜索输入: preview.target_summary.search_inputs }).filter(([, amount]) => amount > 0) : [];

    const invalidatePreview = useCallback(() => {
        previewRequest.current += 1;
        materializeRequest.current += 1;
        idempotencyKey.current = undefined;
        materializingRef.current = false;
        setPreview(null);
        setPreviewOpen(false);
        setPreviewing(false);
        setMaterializing(false);
    }, []);

    const loadNotebook = useCallback(async () => {
        if (projectScope && !projectId) return;
        const requestId = ++notebookRequest.current;
        setNotebookLoading(true);
        try {
            const params: { page: number; pageSize: number; q?: string; tag?: string; state?: 'active' | 'removed' | 'all' } = { page, pageSize };
            if (query) params.q = query;
            if (tagFilter) params.tag = tagFilter;
            if (stateFilter !== 'active') params.state = stateFilter;
            const result = projectScope
                ? await listProjectAssetDiscoveryNotebookItems(projectId, params)
                : await listAccessibleAssetDiscoveryNotebookItems(params);
            if (requestId === notebookRequest.current) setNotebook(result);
        } catch (error) {
            if (requestId === notebookRequest.current) {
                setNotebook(null);
                message.error(typeof error === 'string' ? error : '加载测绘笔记本失败');
            }
        } finally {
            if (requestId === notebookRequest.current) setNotebookLoading(false);
        }
    }, [message, page, pageSize, projectId, projectScope, query, stateFilter, tagFilter]);

    const loadTasks = useCallback(async () => {
        if (!projectId || !enabled) {
            setTasks([]);
            return;
        }
        const requestId = ++tasksRequest.current;
        setTasksLoading(true);
        try {
            const taskById = new Map<string, API.RootTask>();
            let nextPage = 1;
            let hasMore = true;
            while (hasMore) {
                const result = await listTasks({ projectId, page: nextPage, pageSize: 100, archived: 'active' });
                if (requestId !== tasksRequest.current) return;
                result.items.forEach((task) => taskById.set(task.ID, task));
                hasMore = result.has_more;
                nextPage += 1;
            }
            setTasks(Array.from(taskById.values()).filter((task) => !cannotAppend(task)));
        } catch (error) {
            if (requestId === tasksRequest.current) {
                setTasks([]);
                message.error(typeof error === 'string' ? error : '加载可追加任务失败');
            }
        } finally {
            if (requestId === tasksRequest.current) setTasksLoading(false);
        }
    }, [enabled, message, projectId]);

    useEffect(() => {
        notebookRequest.current += 1;
        tasksRequest.current += 1;
        invalidatePreview();
        setNotebook(null);
        setSelectedItemIds([]);
        setTaskId(undefined);
        setPage(1);
        setQueryInput('');
        setTagInput('');
        setQuery('');
        setTagFilter('');
        setStateFilter('active');
    }, [enabled, invalidatePreview, projectId]);
    useEffect(() => () => {
        notebookRequest.current += 1;
        tasksRequest.current += 1;
        previewRequest.current += 1;
        materializeRequest.current += 1;
    }, []);
    useEffect(() => { void loadNotebook(); }, [loadNotebook]);
    useEffect(() => { void loadTasks(); }, [loadTasks]);

    const handlePreview = async () => {
        if (!projectId || !taskId || selectedItemIds.length < 1 || selectedItemIds.length > 100 || !enabled) return;
        invalidatePreview();
        const requestId = ++previewRequest.current;
        setPreviewing(true);
        try {
            const result = await previewProjectAssetDiscoveryNotebookDistribution(projectId, taskId, selectedItemIds);
            if (requestId === previewRequest.current) {
                setPreview(result);
                setPreviewOpen(true);
            }
        } catch (error) {
            if (requestId === previewRequest.current) message.error(typeof error === 'string' ? error : '预览分发失败');
        } finally {
            if (requestId === previewRequest.current) setPreviewing(false);
        }
    };

    const handleMaterialize = async () => {
        if (!projectId || !taskId || !preview || materializingRef.current || !enabled) return;
        materializingRef.current = true;
        const requestId = ++materializeRequest.current;
        const key = idempotencyKey.current || newIdempotencyKey();
        idempotencyKey.current = key;
        setMaterializing(true);
        try {
            const result = await materializeProjectAssetDiscoveryNotebookDistribution(projectId, {
                task_id: taskId,
                item_ids: selectedItemIds,
                plan_hash: preview.plan_hash,
            }, key);
            if (requestId !== materializeRequest.current) return;
            const dispatchSuffix = result.dispatch.pending > 0
                ? `，${result.dispatch.pending} 个批次等待队列恢复`
                : '';
            message.success((result.replayed
                ? '笔记本分发已确认（已复用此前结果）'
                : result.outcome === 'unchanged'
                    ? '选中目标均已在任务中，未创建新批次'
                    : `已追加 ${result.counts.fresh} 个目标并创建 ${result.counts.batches_created} 个批次`) + dispatchSuffix);
            invalidatePreview();
            setSelectedItemIds([]);
            setTaskId(undefined);
            void loadNotebook();
            void loadTasks();
        } catch (error) {
            if (requestId !== materializeRequest.current) return;
            if (isIdempotencyConflict(error)) {
                message.error('确认请求冲突，请重新预览后确认');
                invalidatePreview();
            } else if (isPreviewExpired(error)) {
                message.error('预览已过期或任务状态已变化，请重新预览后确认');
                invalidatePreview();
            } else {
                message.error(typeof error === 'string' ? error : '确认笔记本分发失败，可直接重试');
            }
        } finally {
            if (requestId === materializeRequest.current) {
                materializingRef.current = false;
                setMaterializing(false);
            }
        }
    };

    const applyFilters = () => {
        invalidatePreview();
        setSelectedItemIds([]);
        setPage(1);
        setQuery(queryInput.trim().slice(0, 256));
        setTagFilter(tagInput.trim().toLowerCase().slice(0, 64));
    };

    const openEditor = (item: API.AssetDiscoveryNotebookItem) => {
        setEditingItem(item);
        setEditingTags((item.tags || []).join(', '));
        setEditingNote(item.note || '');
    };

    const saveEditor = async () => {
        if (!editingItem || !enabled || !projectScope || savingItem) return;
        const tags = Array.from(new Set(editingTags
            .split(/[,，]/)
            .map((value) => value.trim().toLowerCase())
            .filter(Boolean)));
        if (tags.length > 20 || tags.some((value) => new TextEncoder().encode(value).length > 64)) {
            message.error('标签最多 20 个，且每个标签不超过 64 字节');
            return;
        }
        if (new TextEncoder().encode(editingNote).length > 4096) {
            message.error('备注不能超过 4096 字节');
            return;
        }
        setSavingItem(true);
        try {
            await updateProjectAssetDiscoveryNotebookItem(projectId, editingItem.id, { tags, note: editingNote });
            setEditingItem(null);
            message.success('笔记本标签和备注已更新');
            await loadNotebook();
        } catch (error) {
            message.error(typeof error === 'string' ? error : '更新笔记本条目失败');
        } finally {
            setSavingItem(false);
        }
    };

    const changeRemovedState = async (item: API.AssetDiscoveryNotebookItem, removed: boolean) => {
        if (!enabled || !projectScope || changingItemId !== null) return;
        setChangingItemId(item.id);
        try {
            await setProjectAssetDiscoveryNotebookItemRemoved(projectId, item.id, removed);
            setSelectedItemIds((current) => current.filter((id) => id !== item.id));
            invalidatePreview();
            message.success(removed ? '已从默认笔记本视图移除，历史来源仍保留' : '笔记本条目已恢复');
            await loadNotebook();
        } catch (error) {
            message.error(typeof error === 'string' ? error : removed ? '移除笔记本条目失败' : '恢复笔记本条目失败');
        } finally {
            setChangingItemId(null);
        }
    };

    const notebookColumns: ColumnsType<API.AssetDiscoveryNotebookItem> = [
        ...(!projectScope ? [{ title: '项目', dataIndex: 'project_name', width: 180, ellipsis: true, render: (value: string, item: API.AssetDiscoveryNotebookItem) => value || item.project_id || '-' }] : []),
        { title: '目标', dataIndex: 'target', ellipsis: true },
        { title: '标签', dataIndex: 'tags', width: 190, render: (values: string[] = []) => values.length ? <Space size={[2, 2]} wrap>{values.map((value) => <Tag key={value}>{value}</Tag>)}</Space> : '-' },
        { title: '备注', dataIndex: 'note', width: 220, ellipsis: true, render: (value: string) => value || '-' },
        { title: '来源数', dataIndex: 'source_count', width: 90 },
        { title: '状态', key: 'state', width: 90, render: (_: unknown, item: API.AssetDiscoveryNotebookItem) => item.removed_at ? <Tag>已移除</Tag> : <Tag color="green">使用中</Tag> },
        { title: '最近归档', dataIndex: 'last_archived_at', width: 170, render: (value: string) => dayjs(value).format('YYYY-MM-DD HH:mm:ss') },
        ...(enabled && projectScope ? [{
            title: '操作', key: 'actions', width: 150, render: (_: unknown, item: API.AssetDiscoveryNotebookItem) => <Space size={0}>
                <Button type="link" size="small" icon={<EditOutlined />} disabled={materializing || !!item.removed_at} onClick={() => openEditor(item)}>编辑</Button>
                {item.removed_at
                    ? <Button type="link" size="small" icon={<UndoOutlined />} loading={changingItemId === item.id} disabled={materializing} onClick={() => void changeRemovedState(item, false)}>恢复</Button>
                    : <Button danger type="link" size="small" icon={<DeleteOutlined />} loading={changingItemId === item.id} disabled={materializing} onClick={() => setRemovingItem(item)}>移除</Button>}
            </Space>,
        }] : []),
    ];

    return <>
        <Space direction="vertical" size={10} style={{ width: '100%', marginBottom: 12 }}>
            <Space wrap>
                <div aria-label="笔记本范围" style={{ display: 'inline-flex' }}>
                    {(['project', 'accessible'] as const).map((value) => <button
                        key={value}
                        type="button"
                        aria-pressed={scope === value}
                        disabled={materializing}
                        style={{
                            border: '1px solid #d9d9d9',
                            background: scope === value ? '#1677ff' : '#fff',
                            color: scope === value ? '#fff' : 'inherit',
                            padding: '4px 15px',
                            cursor: materializing ? 'not-allowed' : 'pointer',
                            borderRadius: value === 'project' ? '6px 0 0 6px' : '0 6px 6px 0',
                        }}
                        onClick={() => {
                            invalidatePreview();
                            setSelectedItemIds([]);
                            setScope(value);
                            setPage(1);
                        }}
                    >{value === 'project' ? '当前项目' : '可访问项目'}</button>)}
                </div>
                <Input aria-label="搜索笔记本目标" allowClear value={queryInput} maxLength={256} placeholder="搜索目标" style={{ width: 230 }} onChange={(event) => setQueryInput(event.target.value)} onPressEnter={applyFilters} />
                <Input aria-label="筛选笔记本标签" allowClear value={tagInput} maxLength={64} placeholder="按标签筛选" style={{ width: 180 }} onChange={(event) => setTagInput(event.target.value)} onPressEnter={applyFilters} />
                <Select aria-label="笔记本状态筛选" value={stateFilter} style={{ width: 130 }} options={[{ value: 'active', label: '使用中' }, { value: 'removed', label: '已移除' }, { value: 'all', label: '全部状态' }]} onChange={(value) => { invalidatePreview(); setSelectedItemIds([]); setStateFilter(value); setPage(1); }} />
                <Button icon={<SearchOutlined />} onClick={applyFilters}>筛选</Button>
            </Space>
            {!projectScope && <Text type="secondary">跨项目视图只聚合当前账号实际可访问的项目；编辑和分发请切回对应项目。</Text>}
        </Space>
        <Table
            rowKey="id"
            loading={notebookLoading}
            dataSource={notebook?.items || []}
            rowSelection={enabled && projectScope && stateFilter === 'active' ? {
                selectedRowKeys: selectedItemIds,
                onChange: (keys) => {
                    if (materializingRef.current) return;
                    invalidatePreview();
                    setSelectedItemIds(keys.map(Number).slice(0, 100));
                },
                getCheckboxProps: (record) => ({ disabled: materializing || !!record.removed_at || (!selectedItemIds.includes(record.id) && selectedItemIds.length >= 100) }),
            } : undefined}
            pagination={{
                current: page, pageSize, total: notebook?.total || 0, showSizeChanger: true, pageSizeOptions: [20, 50, 100],
                disabled: materializing,
                showTotal: (total) => `共 ${total} 条资产`,
                onChange: (nextPage, nextPageSize) => {
                    if (materializingRef.current) return;
                    invalidatePreview();
                    setSelectedItemIds([]);
                    setPage(nextPageSize === pageSize ? nextPage : 1);
                    setPageSize(nextPageSize);
                },
            }}
            size="small"
            columns={notebookColumns}
            locale={{ emptyText: projectId ? '暂无测绘笔记本资产' : '请先选择项目' }}
        />
        {enabled && projectScope && stateFilter === 'active' && <Space direction="vertical" size={10} style={{ width: '100%', marginTop: 12 }}>
            <Space wrap>
                <Text>已选 {selectedItemIds.length}/100 条</Text>
                <Select aria-label="追加到现有任务" showSearch optionFilterProp="label" loading={tasksLoading} disabled={materializing} value={taskId} onChange={(value) => { if (materializingRef.current) return; invalidatePreview(); setTaskId(value); }} placeholder="选择同项目现有任务" style={{ minWidth: 280 }} options={tasks.map((task) => ({ value: task.ID, label: `${task.Name} · ${task.Status}` }))} />
                <Button type="primary" loading={previewing} disabled={!taskId || selectedItemIds.length < 1 || selectedItemIds.length > 100 || materializing} onClick={() => void handlePreview()}>预览分发</Button>
                <Button icon={<ReloadOutlined />} disabled={materializing} onClick={() => { void loadNotebook(); void loadTasks(); }}>刷新</Button>
            </Space>
            <Text type="secondary">先生成只读预览；确认后才会追加目标、扩展项目范围并创建扫描批次。</Text>
        </Space>}
        <Drawer title="笔记本分发预览" width="min(760px, 94vw)" open={previewOpen} closable={!materializing} maskClosable={!materializing} keyboard={!materializing} onClose={() => { if (!materializingRef.current) setPreviewOpen(false); }} destroyOnHidden>
            {preview && <Space direction="vertical" size={16} style={{ width: '100%' }}>
                <Alert type="warning" showIcon message="尚未执行" description="确认后会按当前任务安全配置追加新目标、扩展 Scope 与 SeedTargets，并创建 Batch/Attempt。不会自动启用 POC 或 EXP。" />
                <Descriptions bordered size="small" column={2}>
                    <Descriptions.Item label="项目">{projectName || preview.project.id}</Descriptions.Item>
                    <Descriptions.Item label="任务">{preview.task.name}</Descriptions.Item>
                    <Descriptions.Item label="任务状态">{preview.task.status}</Descriptions.Item>
                    <Descriptions.Item label="任务配置版本">{preview.task.config_version}</Descriptions.Item>
                    <Descriptions.Item label="规则版本">{preview.task.rule_version || '-'}</Descriptions.Item>
                    <Descriptions.Item label="计划哈希"><Text code copyable={{ text: preview.plan_hash }} ellipsis={{ tooltip: preview.plan_hash }} style={{ maxWidth: 180, display: 'inline-block' }}>{preview.plan_hash}</Text></Descriptions.Item>
                    <Descriptions.Item label="请求 / 选中">{preview.counts.requested} / {preview.counts.selected}</Descriptions.Item>
                    <Descriptions.Item label="新增 / 重复">{preview.counts.fresh} / {preview.counts.duplicates}</Descriptions.Item>
                    <Descriptions.Item label="预计 Scope 增量">{preview.counts.project_scope_added}</Descriptions.Item>
                    <Descriptions.Item label="预计 SeedTargets 增量">{preview.counts.project_seed_targets_added}</Descriptions.Item>
                    <Descriptions.Item label="预计批次">{preview.batch_profile.total_batches} 批 / {preview.batch_profile.total_targets} 目标</Descriptions.Item>
                    <Descriptions.Item label="批次分类">{batchTypes.length ? batchTypes.map(([type, batches]) => <Tag key={type}>{type}: {batches} 批（每批 {preview.batch_profile.batch_size[type] || '-'}）</Tag>) : '-'}</Descriptions.Item>
                    <Descriptions.Item label="目标分类" span={2}>{targetCategories.length ? <Space size={[4, 4]} wrap>{targetCategories.map(([type, amount]) => <Tag key={type}>{type}: {amount}</Tag>)}</Space> : '-'}</Descriptions.Item>
                </Descriptions>
                <Table rowKey="item_id" size="small" pagination={false} dataSource={preview.items} columns={[{ title: '目标', dataIndex: 'target' }, { title: '结果', dataIndex: 'disposition', width: 100, render: (value) => <Tag color={value === 'new' ? 'green' : 'default'}>{value === 'new' ? '新增' : '重复'}</Tag> }]} />
                <Button danger type="primary" loading={materializing} disabled={materializing} onClick={() => void handleMaterialize()}>确认追加并创建批次</Button>
            </Space>}
        </Drawer>
        <Modal title="编辑笔记本条目" open={!!editingItem} confirmLoading={savingItem} okText="保存" cancelText="取消" onOk={() => void saveEditor()} onCancel={() => { if (!savingItem) setEditingItem(null); }} maskClosable={!savingItem} keyboard={!savingItem}>
            <Space direction="vertical" size={12} style={{ width: '100%' }}>
                <div><Text type="secondary">目标</Text><Paragraph copyable style={{ marginBottom: 0 }}>{editingItem?.target}</Paragraph></div>
                <div><Text type="secondary">标签（逗号分隔，最多 20 个）</Text><Input aria-label="笔记本标签" value={editingTags} onChange={(event) => setEditingTags(event.target.value)} placeholder="例如：重点资产, 待验证" /></div>
                <div><Text type="secondary">备注</Text><Input.TextArea aria-label="笔记本备注" value={editingNote} onChange={(event) => setEditingNote(event.target.value)} autoSize={{ minRows: 4, maxRows: 8 }} showCount maxLength={4096} /></div>
            </Space>
        </Modal>
        <Modal
            title="移除笔记本条目？"
            open={!!removingItem}
            confirmLoading={removingItem ? changingItemId === removingItem.id : false}
            okText="移除"
            cancelText="取消"
            okButtonProps={{ danger: true }}
            onOk={async () => {
                if (!removingItem) return;
                await changeRemovedState(removingItem, true);
                setRemovingItem(null);
            }}
            onCancel={() => { if (changingItemId === null) setRemovingItem(null); }}
            maskClosable={changingItemId === null}
            keyboard={changingItemId === null}
        >
            条目会退出默认列表和任务分发选择，但来源、历史和已分发记录仍会保留。
        </Modal>
    </>;
};

export default NotebookDistributionPreview;
