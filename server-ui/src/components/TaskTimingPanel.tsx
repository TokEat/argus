import { Alert, Divider, Table, Tag, Typography } from 'antd';

const { Text } = Typography;

const timingPreparationLabels: Record<string, string> = {
    process_startup: '启动准备',
    rule_prepare: '规则准备',
    context_init: '扫描上下文准备',
};

const timingOutcomeMeta: Record<string, { label: string; color: string }> = {
    success: { label: '成功', color: 'success' },
    negative: { label: '阴性', color: 'default' },
    failed: { label: '失败', color: 'error' },
    skipped: { label: '跳过', color: 'warning' },
};

const formatTimingDuration = (event: API.TaskTimingEvent): string => {
    if (typeof event.duration_ms === 'number') {
        if (event.duration_ms === 0 && typeof event.duration_ns === 'number' && event.duration_ns > 0) {
            return '<1 ms';
        }
        return `${event.duration_ms} ms`;
    }
    if (typeof event.duration_ns === 'number') {
        if (event.duration_ns > 0 && event.duration_ns < 1_000_000) return '<1 ms';
        return `${(event.duration_ns / 1_000_000).toFixed(3)} ms`;
    }
    return '—';
};

interface TaskTimingPanelProps {
    timing: API.TaskTimingProjection;
    stageLabels: Record<string, string>;
}

const TaskTimingPanel = ({ timing, stageLabels }: TaskTimingPanelProps) => (
    <>
        <Divider orientation="left" style={{ fontSize: 13 }}>
            执行阶段计时 ({timing.attempts.length})
        </Divider>
        <Alert
            type="info"
            showIcon
            style={{ marginBottom: 12 }}
            message="阶段耗时由 Agent 进程内计时；各阶段合计可能与尝试的墙钟时间不同。"
        />
        {timing.truncated && (
            <Alert
                type="warning"
                showIcon
                style={{ marginBottom: 12 }}
                message="计时记录已截断，仅显示可返回的部分事件。"
            />
        )}
        {timing.attempts.map((attempt) => (
            <div key={attempt.attempt_id} style={{ marginBottom: 16 }}>
                <Text strong>尝试 {attempt.attempt_id}</Text>
                {!attempt.available ? (
                    <Alert
                        type="info"
                        showIcon
                        style={{ marginTop: 8 }}
                        message="旧版 Agent 暂无阶段计时"
                    />
                ) : (
                    <Table
                        style={{ marginTop: 8 }}
                        dataSource={attempt.events || []}
                        rowKey={(event, index) => `${event.kind}-${event.stage || ''}-${event.started_at || ''}-${index}`}
                        size="small"
                        pagination={false}
                        locale={{ emptyText: '该尝试尚无可展示的阶段计时事件' }}
                        columns={[
                            {
                                title: '分段', key: 'segment', width: 190,
                                render: (_, event: API.TaskTimingEvent) => event.kind === 'stage'
                                    ? <Tag color="blue">阶段：{stageLabels[event.stage || ''] || event.stage || '未知'}</Tag>
                                    : <Tag>{timingPreparationLabels[event.kind] || event.kind}</Tag>,
                            },
                            {
                                title: '结果', dataIndex: 'outcome', key: 'outcome', width: 100,
                                render: (outcome: string) => {
                                    const meta = timingOutcomeMeta[outcome];
                                    return <Tag color={meta?.color}>{meta?.label || outcome || '—'}</Tag>;
                                },
                            },
                            { title: '耗时', key: 'duration', width: 100, render: (_, event: API.TaskTimingEvent) => formatTimingDuration(event) },
                            { title: '开始时间', dataIndex: 'started_at', key: 'started_at', width: 180, render: (value?: string) => value || '—' },
                            { title: '完成时间', dataIndex: 'finished_at', key: 'finished_at', width: 180, render: (value?: string) => value || '—' },
                        ]}
                    />
                )}
            </div>
        ))}
    </>
);

export default TaskTimingPanel;
