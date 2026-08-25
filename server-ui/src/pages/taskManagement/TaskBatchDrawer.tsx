import React from 'react';
import {
    Alert, Badge, Button, Divider, Drawer, Dropdown, Space, Spin, Table, Tag, Typography,
} from 'antd';
import { InboxOutlined, MoreOutlined, PlusOutlined, ReloadOutlined, UnorderedListOutlined } from '@ant-design/icons';
import { getTaskStatusMeta, isTaskRetryable } from '../../utils/taskStatus';
import {
    attemptTriggerLabels,
    availableBatchActions,
    batchActionLabels,
    failedRetryableBatches,
    renderTaskStatusTag,
    targetTypeLabels,
    type BatchAction,
} from './shared';

const { Text } = Typography;

type Props = {
    open: boolean;
    loading: boolean;
    detail: API.TaskDetailResponse | null;
    canManageTasks: boolean;
    onClose: () => void;
    onAppend: () => void;
    onBatchAction: (batch: API.TaskBatchSummary, action: BatchAction) => void;
    onBulkRetryFailed: () => void;
};

export default function TaskBatchDrawer({
    open, loading, detail, canManageTasks, onClose, onAppend, onBatchAction, onBulkRetryFailed,
}: Props) {
    const failedBatches = failedRetryableBatches(detail);
    const canMutate = Boolean(canManageTasks && detail && !detail.task.archived_at);
    const canBulkRetry = Boolean(canMutate && detail && isTaskRetryable(detail.task.status) && failedBatches.length > 0);

    return (
        <Drawer
            title={
                detail ? (
                    <Space>
                        <UnorderedListOutlined style={{ color: '#1677ff' }} />
                        <span>批次 · {detail.task.name}</span>
                        {renderTaskStatusTag(detail.task.status)}
                    </Space>
                ) : '批次管理'
            }
            open={open}
            extra={canMutate ? (
                <Space>
                    <Button icon={<PlusOutlined />} onClick={onAppend}>增加批次</Button>
                    <Button
                        type="primary"
                        icon={<ReloadOutlined />}
                        disabled={!canBulkRetry}
                        onClick={onBulkRetryFailed}
                    >
                        批量重试失败批次{failedBatches.length > 0 ? ` (${failedBatches.length})` : ''}
                    </Button>
                </Space>
            ) : null}
            onClose={onClose}
            width={1080}
            destroyOnClose
        >
            {loading ? (
                <div style={{ display: 'flex', justifyContent: 'center', padding: '80px 0' }}>
                    <Spin size="large" />
                </div>
            ) : detail ? (
                <div>
                    {Object.keys(detail.status_distribution).length > 0 && (
                        <>
                            <Divider orientation="left" style={{ fontSize: 13 }}>批次状态分布</Divider>
                            <Space wrap style={{ marginBottom: 12 }}>
                                {Object.entries(detail.status_distribution).map(([status, count]) => {
                                    const { color, text } = getTaskStatusMeta(status);
                                    return (
                                        <Badge key={status} count={count} color={color === 'processing' ? '#1677ff' : undefined} overflowCount={9999}>
                                            <Tag color={color} style={{ marginRight: 0 }}>{text}</Tag>
                                        </Badge>
                                    );
                                })}
                            </Space>
                        </>
                    )}

                    {detail.reason_stats?.length > 0 && (
                        <>
                            <Divider orientation="left" style={{ fontSize: 13 }}>调度与终态原因</Divider>
                            <Space direction="vertical" size={6} style={{ width: '100%', marginBottom: 12 }}>
                                {detail.reason_stats.map((item, index) => {
                                    const { color, text } = getTaskStatusMeta(item.status);
                                    return (
                                        <Alert
                                            key={`${item.status}-${index}`}
                                            type={item.status.toLowerCase().includes('fail') || item.status.toLowerCase().includes('timeout') ? 'warning' : 'info'}
                                            showIcon
                                            message={
                                                <Space wrap>
                                                    <Tag color={color}>{text}</Tag>
                                                    <Text>{item.reason}</Text>
                                                    <Text type="secondary">{item.count} 批次 / {item.target_count} 目标</Text>
                                                </Space>
                                            }
                                        />
                                    );
                                })}
                            </Space>
                        </>
                    )}

                    <Divider orientation="left" style={{ fontSize: 13 }}>
                        批次列表 ({detail.batches?.length || detail.sub_tasks.length})
                    </Divider>
                    <Table
                        dataSource={detail.batches || []}
                        rowKey="id"
                        size="small"
                        scroll={{ x: 1180 }}
                        pagination={{ pageSize: 10, showTotal: (t) => `共 ${t} 个批次（含已归档历史）` }}
                        columns={[
                            {
                                title: '批次 ID', dataIndex: 'id', key: 'id', ellipsis: true, width: 230,
                                render: (v: string, row) => (
                                    <Space size={4}>
                                        <Text style={{ fontFamily: 'monospace', fontSize: 11 }}>{v}</Text>
                                        {row.archived_at && <Tag icon={<InboxOutlined />}>已归档</Tag>}
                                    </Space>
                                ),
                            },
                            { title: '尝试', dataIndex: 'current_attempt_no', key: 'current_attempt_no', width: 70, render: (v: number, row) => <Tag>#{v || 1}/{row.attempt_count || 1}</Tag> },
                            {
                                title: '状态', dataIndex: 'display_status', key: 'display_status', width: 100,
                                render: (v: string) => renderTaskStatusTag(v),
                            },
                            {
                                title: '类型', dataIndex: 'target_type', key: 'target_type', width: 90,
                                render: (v: string) => <Tag>{targetTypeLabels[v] || v || '-'}</Tag>,
                            },
                            {
                                title: 'Agent', dataIndex: 'agent_id', key: 'agent_id', ellipsis: true, width: 140,
                                render: (v: string) => v ? <Tag color="blue" style={{ fontSize: 11 }}>{v}</Tag> : <Text type="secondary">-</Text>,
                            },
                            {
                                title: '目标数', dataIndex: 'target_count', key: 'target_count', width: 80,
                                sorter: (a, b) => a.target_count - b.target_count,
                            },
                            {
                                title: '重试', key: 'retry', width: 70,
                                render: (_, r) => <Text style={{ fontSize: 12 }}>{r.retry_count}/{r.max_retry}</Text>,
                            },
                            {
                                title: '配置', dataIndex: 'config_version', key: 'config_version', width: 70,
                                render: (version: number) => <Tag color="cyan">v{version || 1}</Tag>,
                            },
                            {
                                title: '更新时间', dataIndex: 'updated_at', key: 'updated_at', width: 170,
                                render: (v: string) => <Text style={{ fontSize: 11, color: '#64748b' }}>{v}</Text>,
                            },
                            {
                                title: '操作', key: 'actions', fixed: 'right', width: 80,
                                render: (_, row) => {
                                    const actions = canMutate ? availableBatchActions(row) : [];
                                    if (actions.length === 0) {
                                        return <Text type="secondary">-</Text>;
                                    }
                                    return (
                                        <Dropdown
                                            trigger={['click']}
                                            menu={{
                                                items: actions.map((action) => ({
                                                    key: action,
                                                    label: batchActionLabels[action],
                                                    danger: action === 'stop' || action === 'archive',
                                                })),
                                                onClick: ({ key }) => onBatchAction(row, key as BatchAction),
                                            }}
                                        >
                                            <Button aria-label={`管理批次 ${row.id}`} size="small" icon={<MoreOutlined />} />
                                        </Dropdown>
                                    );
                                },
                            },
                        ]}
                    />

                    {(detail.attempts?.length || 0) > 0 && (
                        <>
                            <Divider orientation="left" style={{ fontSize: 13 }}>
                                执行尝试历史 ({detail.attempts?.length || 0})
                            </Divider>
                            <Table
                                dataSource={detail.attempts}
                                rowKey="id"
                                size="small"
                                scroll={{ x: 1250 }}
                                pagination={{ pageSize: 10, showTotal: (t) => `共 ${t} 次执行` }}
                                columns={[
                                    {
                                        title: '批次 ID', dataIndex: 'batch_id', key: 'batch_id', ellipsis: true, width: 210,
                                        render: (v: string) => <Text style={{ fontFamily: 'monospace', fontSize: 11 }}>{v || '-'}</Text>,
                                    },
                                    { title: '尝试', dataIndex: 'attempt_no', key: 'attempt_no', width: 65, render: (v: number) => <Tag>#{v || 1}</Tag> },
                                    {
                                        title: '触发方式', dataIndex: 'trigger', key: 'trigger', width: 130,
                                        render: (v: string) => attemptTriggerLabels[v] || v || '-',
                                    },
                                    { title: '状态', dataIndex: 'status', key: 'status', width: 90, render: (v: string) => renderTaskStatusTag(v) },
                                    {
                                        title: 'Agent', dataIndex: 'agent_id', key: 'agent_id', ellipsis: true, width: 130,
                                        render: (v: string) => v ? <Tag color="blue">{v}</Tag> : <Text type="secondary">-</Text>,
                                    },
                                    {
                                        title: '版本', key: 'versions', width: 145,
                                        render: (_, row) => <Space size={4}><Tag color="cyan">配置 v{row.config_version || 1}</Tag><Tag>{row.rule_version || '-'}</Tag></Space>,
                                    },
                                    {
                                        title: '失败原因', dataIndex: 'failure_reason', key: 'failure_reason', ellipsis: true, width: 240,
                                        render: (v: string) => v || <Text type="secondary">-</Text>,
                                    },
                                    { title: '开始时间', dataIndex: 'started_at', key: 'started_at', width: 180, render: (v?: string | null) => v || '-' },
                                    { title: '完成时间', dataIndex: 'finished_at', key: 'finished_at', width: 180, render: (v?: string | null) => v || '-' },
                                ]}
                            />
                        </>
                    )}
                </div>
            ) : null}
        </Drawer>
    );
}
