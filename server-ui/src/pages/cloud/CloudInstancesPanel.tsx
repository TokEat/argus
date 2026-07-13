import { ApiOutlined, CheckCircleOutlined, ClockCircleOutlined, CloudOutlined, DeleteOutlined, ExclamationCircleOutlined, LoadingOutlined, RocketOutlined, SettingOutlined, StopOutlined, SyncOutlined, WifiOutlined } from '@ant-design/icons';
import { Alert, Badge, Button, Descriptions, Empty, Popconfirm, Space, Spin, Steps, Table, Tag, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';

const { Text } = Typography;

interface CloudInstancesPanelProps {
    loading: boolean;
    instances: API.CloudInstance[];
    onReboot: (id: string) => void;
    onDelete: (id: string) => void;
}

const renderLifecycle = (record: API.CloudInstance) => {
    const stages = [
        { title: '参数准备', desc: '生成 AgentID、渲染 Cloud-Init' },
        { title: '创建实例', desc: '调用云厂商 API 创建 ECS' },
        { title: 'OS 启动', desc: '等待操作系统就绪' },
        { title: 'Agent 注册', desc: 'Cloud-Init 拉取并启动 Agent' },
        { title: '运行中', desc: '已就绪，等待任务调度' },
        { title: '已释放', desc: 'TTL 超时或手动销毁' },
    ];
    let currentStep = 0;
    let stepStatus: 'process' | 'error' | 'finish' | 'wait' = 'process';
    switch (record.status) {
        case 'Provisioning': currentStep = 1; break;
        case 'WaitingReady': currentStep = record.ip ? 3 : 2; break;
        case 'Running': currentStep = 4; stepStatus = 'finish'; break;
        case 'Rebooting': currentStep = 3; break;
        case 'Terminating': currentStep = 5; break;
        case 'Terminated': currentStep = 5; stepStatus = 'finish'; break;
        case 'Error': currentStep = record.provider_instance_id ? (record.ip ? 3 : 2) : 1; stepStatus = 'error'; break;
        default: currentStep = 0;
    }
    const launchedAt = record.launched_at ? new Date(record.launched_at) : null;
    const terminatedAt = record.terminated_at ? new Date(record.terminated_at) : null;
    const durationMs = launchedAt ? ((terminatedAt || new Date()).getTime() - launchedAt.getTime()) : 0;
    const durationMin = Math.floor(durationMs / 60000);
    const durationSec = Math.floor((durationMs % 60000) / 1000);

    return (
        <div style={{ padding: '12px 16px' }}>
            <Steps
                current={currentStep}
                status={stepStatus}
                size="small"
                items={stages.map((stage, index) => {
                    let icon;
                    if (index < currentStep || (index === currentStep && stepStatus === 'finish')) icon = <CheckCircleOutlined />;
                    else if (index === currentStep && stepStatus === 'error') icon = <ExclamationCircleOutlined />;
                    else if (index === currentStep && stepStatus === 'process') icon = <LoadingOutlined />;
                    if (!icon) icon = [<SettingOutlined />, <CloudOutlined />, <ClockCircleOutlined />, <ApiOutlined />, <RocketOutlined />, <StopOutlined />][index];
                    return { title: stage.title, description: stage.desc, icon };
                })}
            />
            <div style={{ marginTop: 16, display: 'flex', gap: 16, flexWrap: 'wrap' }}>
                <div style={{ flex: 1, minWidth: 280, background: '#f8fafc', borderRadius: 8, padding: '12px 16px', border: '1px solid #e2e8f0' }}>
                    <div style={{ fontSize: 12, fontWeight: 600, color: '#475569', marginBottom: 8 }}><CloudOutlined style={{ marginRight: 4 }} />实例信息</div>
                    <Descriptions size="small" column={2} labelStyle={{ fontSize: 11, color: '#94a3b8', paddingBottom: 2 }} contentStyle={{ fontSize: 12, fontFamily: 'monospace', paddingBottom: 2 }}>
                        <Descriptions.Item label="内部 ID"><Text copyable style={{ fontSize: 11 }}>{record.id}</Text></Descriptions.Item>
                        <Descriptions.Item label="云实例 ID"><Text copyable style={{ fontSize: 11 }}>{record.provider_instance_id || '-'}</Text></Descriptions.Item>
                        <Descriptions.Item label="Agent ID"><Text style={{ fontSize: 11, color: record.agent_id ? '#10b981' : '#94a3b8' }}>{record.agent_id || '待注册'}</Text></Descriptions.Item>
                        <Descriptions.Item label="IP 地址"><Text style={{ fontSize: 11 }}>{record.ip || '分配中'}</Text></Descriptions.Item>
                        <Descriptions.Item label="地域"><Text style={{ fontSize: 11 }}>{record.region || '-'}</Text></Descriptions.Item>
                        <Descriptions.Item label="竞价实例">{record.spot ? <Tag color="gold" style={{ fontSize: 10 }}>Spot</Tag> : <Tag style={{ fontSize: 10 }}>按量</Tag>}</Descriptions.Item>
                    </Descriptions>
                </div>
                <div style={{ flex: 1, minWidth: 280, background: '#f8fafc', borderRadius: 8, padding: '12px 16px', border: '1px solid #e2e8f0' }}>
                    <div style={{ fontSize: 12, fontWeight: 600, color: '#475569', marginBottom: 8 }}><ClockCircleOutlined style={{ marginRight: 4 }} />时间线</div>
                    <Descriptions size="small" column={1} labelStyle={{ fontSize: 11, color: '#94a3b8', paddingBottom: 2 }} contentStyle={{ fontSize: 12, paddingBottom: 2 }}>
                        <Descriptions.Item label="创建时间">{record.created_at ? new Date(record.created_at).toLocaleString('zh-CN') : '-'}</Descriptions.Item>
                        <Descriptions.Item label="启动时间">{record.launched_at ? new Date(record.launched_at).toLocaleString('zh-CN') : '-'}</Descriptions.Item>
                        {record.terminated_at && <Descriptions.Item label="释放时间">{new Date(record.terminated_at).toLocaleString('zh-CN')}</Descriptions.Item>}
                        <Descriptions.Item label="运行时长">
                            <Text style={{ color: '#0ea5e9', fontWeight: 600 }}>{durationMin > 0 ? `${durationMin} 分 ` : ''}{durationSec} 秒</Text>
                            {!['Terminated', 'Error'].includes(record.status) && <Tag color="processing" style={{ fontSize: 10, marginLeft: 6 }}>计时中</Tag>}
                        </Descriptions.Item>
                    </Descriptions>
                </div>
            </div>
            {record.error_message && <Alert type="error" showIcon message="错误详情" description={<Text style={{ fontFamily: 'monospace', fontSize: 12 }}>{record.error_message}</Text>} style={{ marginTop: 12, fontSize: 12 }} />}
        </div>
    );
};

export const CloudInstancesPanel = ({ loading, instances, onReboot, onDelete }: CloudInstancesPanelProps) => {
    const columns: ColumnsType<API.CloudInstance> = [
        {
            title: '状态', dataIndex: 'status', key: 'status', width: 100,
            render: (status: string) => {
                let color = 'default';
                if (status === 'Running') color = 'success';
                else if (status === 'Provisioning' || status === 'WaitingReady') color = 'processing';
                else if (status === 'Error') color = 'error';
                return <Badge status={color as any} text={<Tag color={color === 'success' ? '#10b981' : color === 'processing' ? '#0ea5e9' : '#94a3b8'}>{status}</Tag>} />;
            },
        },
        {
            title: '云实例 ID', dataIndex: 'provider_instance_id', key: 'provider_instance_id',
            render: (id: string, record) => <Space direction="vertical" size="small"><Text copyable={{ text: id }} style={{ fontFamily: 'monospace', fontSize: 12 }}>{id || '分配中...'}</Text>{record.spot && <Tag color="gold" style={{ fontSize: 10, lineHeight: '14px' }}>Spot</Tag>}</Space>,
        },
        { title: 'Agent 连接', dataIndex: 'agent_id', key: 'agent_id', render: (id: string) => id ? <Text style={{ color: '#10b981', fontSize: 12 }}><WifiOutlined /> 已绑定</Text> : <Text type="secondary" style={{ fontSize: 12 }}>待连接</Text> },
        { title: 'IP 地址', dataIndex: 'ip', key: 'ip', width: 140, render: (ip: string) => ip || <Text type="secondary">-</Text> },
        { title: '创建时间', dataIndex: 'created_at', key: 'created_at', width: 160, render: (value: string) => <Text style={{ fontSize: 12, color: '#64748b' }}>{value ? new Date(value).toLocaleString('zh-CN') : '-'}</Text> },
        {
            title: '操作', key: 'actions', width: 180,
            render: (_: unknown, record: API.CloudInstance) => (
                <Space>
                    <Popconfirm title="确认重启此云主机？Agent 将通过 systemd 自动恢复。" onConfirm={() => onReboot(record.id)}>
                        <Button type="link" size="small" icon={<SyncOutlined />} disabled={!['Running', 'Error', 'WaitingReady'].includes(record.status)}>重启</Button>
                    </Popconfirm>
                    <Popconfirm title={['Error', 'Terminated'].includes(record.status) ? '确认清理此失败/已终止的记录？' : '确认销毁此云主机？'} onConfirm={() => onDelete(record.id)}>
                        <Button type="link" size="small" danger icon={<DeleteOutlined />}>{['Error', 'Terminated'].includes(record.status) ? '清理' : '销毁'}</Button>
                    </Popconfirm>
                </Space>
            ),
        },
    ];

    return (
        <div style={{ padding: '20px 0' }}>
            {loading && instances.length === 0 ? (
                <div style={{ display: 'flex', justifyContent: 'center', padding: '60px 0' }}><Spin size="large" /></div>
            ) : instances.length === 0 ? (
                <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="当前没有正在运行或被调度的云实例" style={{ padding: '60px 0' }} />
            ) : (
                <Table columns={columns} dataSource={instances} rowKey="id" pagination={{ pageSize: 20, showTotal: total => `共 ${total} 个实例` }} size="middle" expandable={{ expandedRowRender: renderLifecycle, rowExpandable: () => true }} />
            )}
        </div>
    );
};
