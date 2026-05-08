import React, { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Alert, Button, DatePicker, Empty, Form, Input, InputNumber, Select, Space, Table, Tag, Typography, message } from 'antd';
import { FileTextOutlined, DownloadOutlined, ReloadOutlined } from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import dayjs from 'dayjs';
import { getAgentLogRetention, getAgentLogSummary, getAgentLogs, getNodes, updateAgentLogRetention } from '../services/api';

const { Title, Text } = Typography;
const { RangePicker } = DatePicker;

const levelColors: Record<string, string> = {
    ERROR: 'red',
    WARN: 'orange',
    INFO: 'blue',
    DEBUG: 'default',
};

const filterStorageKey = 'argus_agent_log_filters';

const loadInitialFilters = () => {
    try {
        const raw = localStorage.getItem(filterStorageKey);
        if (!raw) throw new Error('empty');
        const parsed = JSON.parse(raw) as {
            agent_id?: string;
            level?: string;
            q?: string;
            limit?: number;
            since?: number;
            until?: number;
        };
        return {
            agent_id: parsed.agent_id,
            level: parsed.level,
            q: parsed.q,
            limit: parsed.limit || 100,
            range: parsed.since && parsed.until ? [dayjs(parsed.since), dayjs(parsed.until)] : [dayjs().subtract(6, 'hour'), dayjs()],
        };
    } catch {
        return { limit: 100, range: [dayjs().subtract(6, 'hour'), dayjs()] };
    }
};

const persistFilters = (values: Record<string, unknown>) => {
    const range = (values.range || []) as dayjs.Dayjs[];
    localStorage.setItem(filterStorageKey, JSON.stringify({
        agent_id: values.agent_id,
        level: values.level,
        q: values.q,
        limit: values.limit,
        since: range[0] ? range[0].valueOf() : undefined,
        until: range[1] ? range[1].valueOf() : undefined,
    }));
};

const AgentLogs: React.FC = () => {
    const [searchParams] = useSearchParams();
    const [form] = Form.useForm();
    const [nodes, setNodes] = useState<API.AgentNode[]>([]);
    const [logs, setLogs] = useState<API.AgentLog[]>([]);
    const [summary, setSummary] = useState<API.AgentLogSummary | null>(null);
    const [retentionDays, setRetentionDays] = useState<number>(14);
    const [retentionSaving, setRetentionSaving] = useState(false);
    const [loading, setLoading] = useState(false);

    const selectedAgentID = Form.useWatch('agent_id', form);

    const fetchNodes = async () => {
        const result = await getNodes();
        setNodes(result || []);
        const initialAgent = searchParams.get('agent_id') || result?.[0]?.AgentID;
        if (initialAgent && !form.getFieldValue('agent_id')) {
            form.setFieldValue('agent_id', initialAgent);
        }
    };

    const rangeToQuery = (range: dayjs.Dayjs[] = []) => ({
        since: range[0] ? range[0].valueOf() : undefined,
        until: range[1] ? range[1].valueOf() : undefined,
    });

    const fetchRetention = async () => {
        const result = await getAgentLogRetention();
        setRetentionDays(result.retention_days || 14);
    };

    const fetchSummary = async (values = form.getFieldsValue()) => {
        const range = values.range || [];
        const result = await getAgentLogSummary({
            agent_id: values.agent_id,
            limit: 10,
            ...rangeToQuery(range),
        });
        setSummary(result);
        setRetentionDays(result.retention_days || retentionDays);
    };

    const fetchLogs = async () => {
        const values = form.getFieldsValue();
        persistFilters(values);
        if (!values.agent_id) {
            setLogs([]);
            fetchSummary(values).catch(() => undefined);
            return;
        }
        setLoading(true);
        try {
            const range = values.range || [];
            const result = await getAgentLogs(values.agent_id, {
                limit: values.limit || 100,
                level: values.level,
                q: values.q,
                ...rangeToQuery(range),
            });
            setLogs(result || []);
            await fetchSummary(values);
        } catch (error) {
            message.error(typeof error === 'string' ? error : '加载 Agent 日志失败');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchNodes().catch(() => message.error('加载节点失败'));
        fetchRetention().catch(() => undefined);
    }, []);

    useEffect(() => {
        if (selectedAgentID) {
            fetchLogs();
        }
    }, [selectedAgentID]);

    const handleSaveRetention = async () => {
        setRetentionSaving(true);
        try {
            const result = await updateAgentLogRetention(retentionDays);
            setRetentionDays(result.retention_days);
            message.success(`日志保留策略已保存，清理 ${result.deleted || 0} 条过期日志`);
            fetchLogs();
        } catch (error) {
            message.error(typeof error === 'string' ? error : '保存日志保留策略失败');
        } finally {
            setRetentionSaving(false);
        }
    };

    const downloadLogs = () => {
        const text = logs.map((log) => {
            const ts = log.Timestamp ? dayjs(log.Timestamp).format('YYYY-MM-DD HH:mm:ss') : log.CreatedAt;
            return `[${ts}] [${log.Level}] ${log.Message}`;
        }).join('\n');
        const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${selectedAgentID || 'agent'}-${Date.now()}.log`;
        a.click();
        URL.revokeObjectURL(url);
    };

    const columns: ColumnsType<API.AgentLog> = useMemo(() => [
        {
            title: '时间',
            dataIndex: 'Timestamp',
            width: 180,
            render: (value: number, record) => (
                <Text style={{ fontSize: 12 }}>
                    {value ? dayjs(value).format('YYYY-MM-DD HH:mm:ss') : record.CreatedAt}
                </Text>
            ),
        },
        {
            title: '级别',
            dataIndex: 'Level',
            width: 90,
            render: (level: string) => <Tag color={levelColors[level] || 'default'}>{level || '-'}</Tag>,
        },
        {
            title: '消息',
            dataIndex: 'Message',
            render: (value: string) => <Text style={{ whiteSpace: 'pre-wrap' }}>{value}</Text>,
        },
    ], []);

    return (
        <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
                <Title level={4} style={{ margin: 0, color: '#1e293b', fontWeight: 600 }}>
                    <FileTextOutlined style={{ marginRight: 8, color: '#0ea5e9' }} />
                    Agent 日志
                </Title>
                <Space>
                    <Text type="secondary">保留</Text>
                    <InputNumber min={1} max={365} value={retentionDays} onChange={(value) => setRetentionDays(value || 14)} style={{ width: 86 }} />
                    <Text type="secondary">天</Text>
                    <Button onClick={handleSaveRetention} loading={retentionSaving}>保存策略</Button>
                    <Button icon={<DownloadOutlined />} onClick={downloadLogs} disabled={logs.length === 0}>
                        导出
                    </Button>
                    <Button type="primary" icon={<ReloadOutlined />} onClick={fetchLogs} loading={loading}>
                        刷新
                    </Button>
                </Space>
            </div>

            <Form
                form={form}
                layout="inline"
                initialValues={loadInitialFilters()}
                style={{ marginBottom: 16, gap: 8 }}
                onValuesChange={(changed) => {
                    persistFilters(form.getFieldsValue());
                    if (!('agent_id' in changed)) {
                        fetchLogs();
                    }
                }}
            >
                <Form.Item name="agent_id">
                    <Select
                        showSearch
                        placeholder="选择 Agent"
                        style={{ width: 260 }}
                        options={nodes.map((node) => ({ label: node.AgentID, value: node.AgentID }))}
                    />
                </Form.Item>
                <Form.Item name="level">
                    <Select
                        allowClear
                        placeholder="级别"
                        style={{ width: 120 }}
                        options={['INFO', 'WARN', 'ERROR', 'DEBUG'].map((level) => ({ label: level, value: level }))}
                    />
                </Form.Item>
                <Form.Item name="q">
                    <Input.Search allowClear placeholder="搜索消息" style={{ width: 220 }} onSearch={fetchLogs} />
                </Form.Item>
                <Form.Item name="range">
                    <RangePicker showTime />
                </Form.Item>
                <Form.Item name="limit">
                    <Select
                        style={{ width: 110 }}
                        options={[100, 200, 500, 1000].map((value) => ({ label: `${value} 条`, value }))}
                    />
                </Form.Item>
            </Form>

            {summary && (
                <Space direction="vertical" size={8} style={{ width: '100%', marginBottom: 16 }}>
                    <Space wrap>
                        {summary.level_counts.map((item) => (
                            <Tag key={item.level || 'UNKNOWN'} color={levelColors[item.level] || 'default'}>
                                {item.level || 'UNKNOWN'}: {item.count}
                            </Tag>
                        ))}
                        <Tag color="default">保留 {summary.retention_days} 天</Tag>
                    </Space>
                    {summary.recent_errors.length > 0 && (
                        <Alert
                            type="warning"
                            showIcon
                            message={`最近错误/告警 ${summary.recent_errors.length} 条`}
                            description={summary.recent_errors.slice(0, 3).map((log) => `[${log.Level}] ${log.AgentID}: ${log.Message}`).join('；')}
                        />
                    )}
                </Space>
            )}

            {nodes.length === 0 ? (
                <Empty description="暂无 Agent 节点" />
            ) : (
                <Table
                    rowKey="ID"
                    columns={columns}
                    dataSource={logs}
                    loading={loading}
                    pagination={{ pageSize: 20, showSizeChanger: true }}
                    scroll={{ y: 560 }}
                />
            )}
        </div>
    );
};

export default AgentLogs;
