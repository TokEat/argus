import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
    Alert,
    App,
    Button,
    Col,
    Divider,
    Empty,
    Form,
    Input,
    InputNumber,
    Modal,
    Popconfirm,
    Progress,
    Row,
    Select,
    Space,
    Spin,
    Switch,
    Table,
    Tag,
    Typography,
} from 'antd';
import { ProCard } from '@ant-design/pro-components';
import {
    DeleteOutlined,
    EyeOutlined,
    PlusOutlined,
    ReloadOutlined,
    RocketOutlined,
    StopOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import { cancelTask, createTask, deleteTask, listTasks } from '../services/api';

const { Title, Text } = Typography;
const { TextArea } = Input;

type TaskSourceMode = 'direct' | 'hunter' | 'fofa' | 'hunter_fofa' | 'quake';

const sourceModeOptions = [
    { value: 'direct', label: '直接目标' },
    { value: 'hunter', label: 'Hunter' },
    { value: 'fofa', label: 'Fofa' },
    { value: 'hunter_fofa', label: 'Hunter + Fofa' },
    { value: 'quake', label: 'Quake' },
];

const sourceModeHints: Record<TaskSourceMode, string> = {
    direct: '每行一个目标，支持 IP、IP:Port、CIDR、IP 段、域名、域名:Port、URL。',
    hunter: '每行一个 Hunter 查询语句，需使用 field=value 形式，例如 icp.name="xxx有限公司"。',
    fofa: '每行一个 Fofa 查询语句，需使用 field=value 形式，例如 title="nginx"。',
    hunter_fofa: '每行一个通用查询语句，将同时交给 Hunter 与 Fofa，需使用 field=value 形式。',
    quake: '每行一个 Quake 查询语句，需使用 field:value 形式，例如 service:http。',
};

const createInitialValues = {
    source_mode: 'direct' as TaskSourceMode,
    priority: 1,
    timeout_sec: 3600,
    PortScanType: 'tcp',
    TCPPortScanThreads: 1000,
    SYNPortScanThreads: 10000,
    PortsThreshold: 300,
    TCPPortScanTimeout: 6,
    GetBannerThreads: 500,
    GetBannerTimeout: 5,
    WebThreads: 200,
    WebTimeout: 10,
    GoPocThreads: 50,
    HunterPageSize: 100,
    HunterMaxPageCount: 10,
    FofaMaxCount: 100,
    QuakeSize: 100,
};

function compactObject(input: Record<string, unknown>) {
    return Object.fromEntries(
        Object.entries(input).filter(([, value]) => value !== undefined && value !== null && value !== '')
    );
}

function parseAdvancedConfig(raw?: string) {
    const trimmed = raw?.trim();
    if (!trimmed) {
        return {};
    }

    const parsed = JSON.parse(trimmed);
    if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
        throw new Error('高级配置必须是 JSON 对象');
    }
    return parsed as Record<string, unknown>;
}

function buildTaskConfig(values: Record<string, unknown>) {
    const sourceMode = (values.source_mode as TaskSourceMode) || 'direct';
    const config: Record<string, unknown> = {
        Ports: values.Ports,
        PortScanType: values.PortScanType,
        SkipHostDiscovery: values.SkipHostDiscovery,
        NoICMPPing: values.NoICMPPing,
        TCPPing: values.TCPPing,
        TCPPortScanThreads: values.TCPPortScanThreads,
        SYNPortScanThreads: values.SYNPortScanThreads,
        PortsThreshold: values.PortsThreshold,
        TCPPortScanTimeout: values.TCPPortScanTimeout,
        GetBannerThreads: values.GetBannerThreads,
        GetBannerTimeout: values.GetBannerTimeout,
        Subdomain: values.Subdomain,
        NoSubdomainBruteForce: values.NoSubdomainBruteForce,
        NoSubFinder: values.NoSubFinder,
        AllowCDNAssets: values.AllowCDNAssets,
        AllowLocalAreaDomain: values.AllowLocalAreaDomain,
        NoHostBind: values.NoHostBind,
        WebThreads: values.WebThreads,
        WebTimeout: values.WebTimeout,
        NoDirSearch: values.NoDirSearch,
        NoPoc: values.NoPoc,
        GolangPoc: values.GolangPoc,
        DisableGeneralPoc: values.DisableGeneralPoc,
        GoPocThreads: values.GoPocThreads,
        ExcludeTags: values.ExcludeTags,
        Severities: values.Severities,
        PocNameForSearch: values.PocNameForSearch,
        Password: values.Password,
        PasswordFile: values.PasswordFile,
    };

    if (sourceMode === 'hunter' || sourceMode === 'hunter_fofa') {
        config.Hunter = true;
        config.HunterPageSize = values.HunterPageSize;
        config.HunterMaxPageCount = values.HunterMaxPageCount;
    }
    if (sourceMode === 'fofa' || sourceMode === 'hunter_fofa') {
        config.Fofa = true;
        config.FofaMaxCount = values.FofaMaxCount;
    }
    if (sourceMode === 'quake') {
        config.Quake = true;
        config.QuakeSize = values.QuakeSize;
    }
    if (sourceMode === 'hunter') {
        config.LowPerceptionMode = values.LowPerceptionMode;
    }
    if (sourceMode !== 'direct') {
        config.OnlyIPPort = values.OnlyIPPort;
    }

    return compactObject(config);
}

const TaskManagement: React.FC = () => {
    const [loading, setLoading] = useState(true);
    const [tasks, setTasks] = useState<API.RootTask[]>([]);
    const [createOpen, setCreateOpen] = useState(false);
    const [creating, setCreating] = useState(false);
    const [form] = Form.useForm();
    const { message } = App.useApp();
    const navigate = useNavigate();
    const sourceMode = (Form.useWatch('source_mode', form) as TaskSourceMode | undefined) || 'direct';

    const fetchTasks = async () => {
        setLoading(true);
        try {
            const result = await listTasks();
            setTasks(result || []);
        } catch (error) {
            console.error('Failed to fetch tasks:', error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchTasks();
        const timer = setInterval(fetchTasks, 10000);
        return () => clearInterval(timer);
    }, []);

    const handleCreate = async () => {
        try {
            const values = await form.validateFields();
            setCreating(true);

            const advancedConfig = parseAdvancedConfig(values.advanced_config_json);
            const configObj = {
                ...buildTaskConfig(values),
                ...advancedConfig,
            };

            await createTask({
                name: values.name,
                targets: values.targets,
                config: configObj,
                priority: values.priority ?? 1,
                timeout_sec: values.timeout_sec ?? 3600,
            });

            message.success('任务创建成功');
            setCreateOpen(false);
            form.resetFields();
            form.setFieldsValue(createInitialValues);
            fetchTasks();
        } catch (error: unknown) {
            if (typeof error === 'string') {
                message.error(error);
            } else if (error instanceof Error) {
                message.error(error.message);
            }
        } finally {
            setCreating(false);
        }
    };

    const handleDelete = async (taskId: string) => {
        try {
            await deleteTask(taskId);
            message.success('任务已删除');
            fetchTasks();
        } catch {
            message.error('删除失败');
        }
    };

    const handleCancel = async (taskId: string) => {
        try {
            await cancelTask(taskId);
            message.success('取消指令已下发');
            fetchTasks();
        } catch {
            message.error('取消失败');
        }
    };

    const getStatusTag = (status: string) => {
        const map: Record<string, { color: string; text: string }> = {
            Pending: { color: 'orange', text: '等待中' },
            Running: { color: 'processing', text: '运行中' },
            FINISHED: { color: 'success', text: '已完成' },
            Cancelled: { color: 'default', text: '已取消' },
            CancelPending: { color: 'warning', text: '取消中' },
        };
        const { color, text } = map[status] || { color: 'default', text: status };
        return <Tag color={color}>{text}</Tag>;
    };

    const columns: ColumnsType<API.RootTask> = [
        {
            title: '任务名称',
            dataIndex: 'Name',
            key: 'name',
            ellipsis: true,
            render: (name: string, record) => (
                <Space direction="vertical" size={0}>
                    <Text strong style={{ fontSize: 13 }}>{name}</Text>
                    <Text style={{ fontSize: 11, color: '#94a3b8', fontFamily: 'monospace' }}>
                        {record.ID}
                    </Text>
                </Space>
            ),
        },
        {
            title: '状态',
            dataIndex: 'Status',
            key: 'status',
            width: 100,
            render: (status: string) => getStatusTag(status),
            filters: [
                { text: '等待中', value: 'Pending' },
                { text: '运行中', value: 'Running' },
                { text: '已完成', value: 'FINISHED' },
                { text: '已取消', value: 'Cancelled' },
            ],
            onFilter: (value, record) => record.Status === value,
        },
        {
            title: '进度',
            key: 'progress',
            width: 160,
            render: (_, record) => {
                if (record.TotalChunks === 0) return <Text type="secondary">-</Text>;
                const pct = Math.round((record.CompletedChunks / record.TotalChunks) * 100);
                return (
                    <Space direction="vertical" size={0} style={{ width: '100%' }}>
                        <Progress
                            percent={pct}
                            size="small"
                            status={pct >= 100 ? 'success' : 'active'}
                            strokeColor={pct >= 100 ? '#10b981' : '#0ea5e9'}
                            style={{ marginBottom: 0 }}
                        />
                        <Text style={{ fontSize: 11, color: '#94a3b8' }}>
                            {record.CompletedChunks}/{record.TotalChunks} 分片
                        </Text>
                    </Space>
                );
            },
        },
        {
            title: '优先级',
            dataIndex: 'Priority',
            key: 'priority',
            width: 100,
            render: (value: number) => {
                const map: Record<number, string> = {
                    0: 'P0 / 紧急',
                    1: 'P1 / 普通',
                    2: 'P2 / 低',
                };
                return <Text style={{ fontSize: 12 }}>{map[value] || String(value)}</Text>;
            },
        },
        {
            title: '创建时间',
            dataIndex: 'CreatedAt',
            key: 'created_at',
            width: 170,
            render: (value: string) => <Text style={{ fontSize: 12, color: '#64748b' }}>{value}</Text>,
        },
        {
            title: '操作',
            key: 'actions',
            width: 200,
            render: (_, record) => (
                <Space size={4}>
                    <Button type="link" size="small" icon={<EyeOutlined />}
                        onClick={() => navigate(`/tasks/${record.ID}/results`)}>
                        结果
                    </Button>
                    {(record.Status === 'Pending' || record.Status === 'Running') && (
                        <Popconfirm title="确认取消此任务？" onConfirm={() => handleCancel(record.ID)}>
                            <Button type="text" size="small" danger icon={<StopOutlined />}>
                                取消
                            </Button>
                        </Popconfirm>
                    )}
                    <Popconfirm title="确认删除此任务？" onConfirm={() => handleDelete(record.ID)}>
                        <Button type="text" size="small" danger icon={<DeleteOutlined />}>
                            删除
                        </Button>
                    </Popconfirm>
                </Space>
            ),
        },
    ];

    return (
        <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
                <Title level={4} style={{ margin: 0, color: '#1e293b', fontWeight: 600 }}>
                    <RocketOutlined style={{ marginRight: 8, color: '#10b981' }} />
                    任务管理
                </Title>
                <Space>
                    <Button icon={<ReloadOutlined />} onClick={fetchTasks} loading={loading}>
                        刷新
                    </Button>
                    <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>
                        创建任务
                    </Button>
                </Space>
            </div>

            <ProCard className="glass-card" style={{ background: 'transparent', border: 'none' }}>
                {loading && tasks.length === 0 ? (
                    <div style={{ display: 'flex', justifyContent: 'center', padding: '60px 0' }}>
                        <Spin size="large" />
                    </div>
                ) : tasks.length === 0 ? (
                    <Empty
                        image={Empty.PRESENTED_IMAGE_SIMPLE}
                        description="暂无扫描任务"
                        style={{ padding: '60px 0' }}
                    >
                        <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>
                            创建第一个任务
                        </Button>
                    </Empty>
                ) : (
                    <Table
                        columns={columns}
                        dataSource={tasks}
                        rowKey="ID"
                        pagination={{ pageSize: 15, showSizeChanger: true, showTotal: (total) => `共 ${total} 个任务` }}
                        size="middle"
                    />
                )}
            </ProCard>

            <Modal
                title="创建扫描任务"
                open={createOpen}
                onCancel={() => setCreateOpen(false)}
                onOk={handleCreate}
                okText="创建"
                confirmLoading={creating}
                width={920}
                destroyOnHidden
            >
                <Form form={form} layout="vertical" style={{ marginTop: 16 }} initialValues={createInitialValues}>
                    <Row gutter={16}>
                        <Col span={12}>
                            <Form.Item label="任务名称" name="name" rules={[{ required: true, message: '请输入任务名称' }]}>
                                <Input placeholder="输入任务名称" />
                            </Form.Item>
                        </Col>
                        <Col span={12}>
                            <Form.Item label="目标来源" name="source_mode">
                                <Select options={sourceModeOptions} />
                            </Form.Item>
                        </Col>
                    </Row>

                    <Alert
                        type="info"
                        showIcon
                        style={{ marginBottom: 16 }}
                        message="输入规则"
                        description={sourceModeHints[sourceMode]}
                    />

                    <Form.Item
                        label="扫描目标"
                        name="targets"
                        rules={[{ required: true, message: '请输入扫描目标' }]}
                    >
                        <TextArea
                            rows={6}
                            placeholder={
                                sourceMode === 'direct'
                                    ? '192.168.1.10\n192.168.1.10:8080\nhttps://example.com\nexample.com\n10.0.0.1/24'
                                    : sourceMode === 'quake'
                                        ? 'service:http\nport:443'
                                        : 'icp.name="xxx有限公司"\ntitle="nginx"'
                            }
                        />
                    </Form.Item>

                    <Divider orientation="left">任务控制</Divider>
                    <Row gutter={16}>
                        <Col span={8}>
                            <Form.Item label="任务优先级" name="priority" extra="P0 最高，P2 最低">
                                <Select options={[
                                    { value: 0, label: 'P0 / 紧急' },
                                    { value: 1, label: 'P1 / 普通' },
                                    { value: 2, label: 'P2 / 低' },
                                ]} />
                            </Form.Item>
                        </Col>
                        <Col span={8}>
                            <Form.Item label="任务超时(秒)" name="timeout_sec" extra="0 表示不启用超时回收">
                                <InputNumber min={0} step={60} style={{ width: '100%' }} />
                            </Form.Item>
                        </Col>
                        <Col span={8}>
                            <Form.Item label="端口范围" name="Ports" extra="留空时使用默认 Top1000">
                                <Input placeholder="80,443,8080,8443" />
                            </Form.Item>
                        </Col>
                    </Row>

                    <Divider orientation="left">扫描参数</Divider>
                    <Row gutter={16}>
                        <Col span={8}>
                            <Form.Item label="端口扫描方式" name="PortScanType">
                                <Select options={[
                                    { value: 'tcp', label: 'TCP' },
                                    { value: 'syn', label: 'SYN' },
                                ]} />
                            </Form.Item>
                        </Col>
                        <Col span={8}>
                            <Form.Item label="TCP 扫描线程" name="TCPPortScanThreads">
                                <InputNumber min={1} style={{ width: '100%' }} />
                            </Form.Item>
                        </Col>
                        <Col span={8}>
                            <Form.Item label="SYN 扫描线程" name="SYNPortScanThreads">
                                <InputNumber min={1} style={{ width: '100%' }} />
                            </Form.Item>
                        </Col>
                    </Row>

                    <Row gutter={16}>
                        <Col span={8}>
                            <Form.Item label="协议识别线程" name="GetBannerThreads">
                                <InputNumber min={1} style={{ width: '100%' }} />
                            </Form.Item>
                        </Col>
                        <Col span={8}>
                            <Form.Item label="协议识别超时(秒)" name="GetBannerTimeout">
                                <InputNumber min={1} style={{ width: '100%' }} />
                            </Form.Item>
                        </Col>
                        <Col span={8}>
                            <Form.Item label="Web 探针线程" name="WebThreads">
                                <InputNumber min={1} style={{ width: '100%' }} />
                            </Form.Item>
                        </Col>
                    </Row>

                    <Row gutter={16}>
                        <Col span={8}>
                            <Form.Item label="Web 超时(秒)" name="WebTimeout">
                                <InputNumber min={1} style={{ width: '100%' }} />
                            </Form.Item>
                        </Col>
                        <Col span={8}>
                            <Form.Item label="GoPoc 线程" name="GoPocThreads">
                                <InputNumber min={1} style={{ width: '100%' }} />
                            </Form.Item>
                        </Col>
                        <Col span={8}>
                            <Form.Item label="端口数阈值" name="PortsThreshold">
                                <InputNumber min={1} style={{ width: '100%' }} />
                            </Form.Item>
                        </Col>
                    </Row>

                    <Row gutter={16}>
                        <Col span={8}>
                            <Form.Item label="端口扫描超时(秒)" name="TCPPortScanTimeout">
                                <InputNumber min={1} style={{ width: '100%' }} />
                            </Form.Item>
                        </Col>
                        <Col span={8}>
                            <Form.Item label="排除 Tags" name="ExcludeTags">
                                <Input placeholder="etag1,etag2" />
                            </Form.Item>
                        </Col>
                        <Col span={8}>
                            <Form.Item label="漏洞等级过滤" name="Severities">
                                <Input placeholder="critical,high" />
                            </Form.Item>
                        </Col>
                    </Row>

                    <Row gutter={16}>
                        <Col span={12}>
                            <Form.Item label="限定 POC 名称" name="PocNameForSearch">
                                <Input placeholder="nginx" />
                            </Form.Item>
                        </Col>
                        <Col span={12}>
                            <Form.Item label="自定义弱口令" name="Password" extra="格式示例：admin : password">
                                <Input placeholder="admin : password" />
                            </Form.Item>
                        </Col>
                    </Row>

                    <Row gutter={16}>
                        <Col span={12}>
                            <Form.Item label="弱口令文件" name="PasswordFile">
                                <Input placeholder="config/password.txt" />
                            </Form.Item>
                        </Col>
                    </Row>

                    <Divider orientation="left">布尔开关</Divider>
                    <Row gutter={16}>
                        <Col span={8}>
                            <Form.Item label="跳过主机发现" name="SkipHostDiscovery" valuePropName="checked">
                                <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                            </Form.Item>
                        </Col>
                        <Col span={8}>
                            <Form.Item label="禁用 ICMP 探测" name="NoICMPPing" valuePropName="checked">
                                <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                            </Form.Item>
                        </Col>
                        <Col span={8}>
                            <Form.Item label="启用 TCP 探活" name="TCPPing" valuePropName="checked">
                                <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                            </Form.Item>
                        </Col>
                    </Row>

                    <Row gutter={16}>
                        <Col span={8}>
                            <Form.Item label="子域名枚举" name="Subdomain" valuePropName="checked">
                                <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                            </Form.Item>
                        </Col>
                        <Col span={8}>
                            <Form.Item label="关闭子域爆破" name="NoSubdomainBruteForce" valuePropName="checked">
                                <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                            </Form.Item>
                        </Col>
                        <Col span={8}>
                            <Form.Item label="关闭被动子域枚举" name="NoSubFinder" valuePropName="checked">
                                <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                            </Form.Item>
                        </Col>
                    </Row>

                    <Row gutter={16}>
                        <Col span={8}>
                            <Form.Item label="允许 CDN 资产" name="AllowCDNAssets" valuePropName="checked">
                                <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                            </Form.Item>
                        </Col>
                        <Col span={8}>
                            <Form.Item label="允许解析到内网" name="AllowLocalAreaDomain" valuePropName="checked">
                                <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                            </Form.Item>
                        </Col>
                        <Col span={8}>
                            <Form.Item label="关闭域名绑定探测" name="NoHostBind" valuePropName="checked">
                                <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                            </Form.Item>
                        </Col>
                    </Row>

                    <Row gutter={16}>
                        <Col span={8}>
                            <Form.Item label="关闭主动目录指纹" name="NoDirSearch" valuePropName="checked">
                                <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                            </Form.Item>
                        </Col>
                        <Col span={8}>
                            <Form.Item label="关闭漏洞探测" name="NoPoc" valuePropName="checked">
                                <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                            </Form.Item>
                        </Col>
                        <Col span={8}>
                            <Form.Item label="启用 GoPoc" name="GolangPoc" valuePropName="checked">
                                <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                            </Form.Item>
                        </Col>
                    </Row>

                    <Row gutter={16}>
                        <Col span={8}>
                            <Form.Item label="禁用通用 POC" name="DisableGeneralPoc" valuePropName="checked">
                                <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                            </Form.Item>
                        </Col>
                        {sourceMode !== 'direct' && (
                            <Col span={8}>
                                <Form.Item label="搜索引擎输出 IP:Port" name="OnlyIPPort" valuePropName="checked">
                                    <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                                </Form.Item>
                            </Col>
                        )}
                        {sourceMode === 'hunter' && (
                            <Col span={8}>
                                <Form.Item label="低感知模式" name="LowPerceptionMode" valuePropName="checked">
                                    <Switch checkedChildren="开启" unCheckedChildren="关闭" />
                                </Form.Item>
                            </Col>
                        )}
                    </Row>

                    {sourceMode !== 'direct' && (
                        <>
                            <Divider orientation="left">搜索引擎参数</Divider>
                            <Row gutter={16}>
                                {(sourceMode === 'hunter' || sourceMode === 'hunter_fofa') && (
                                    <>
                                        <Col span={8}>
                                            <Form.Item label="Hunter 每页数量" name="HunterPageSize">
                                                <InputNumber min={1} max={100} style={{ width: '100%' }} />
                                            </Form.Item>
                                        </Col>
                                        <Col span={8}>
                                            <Form.Item label="Hunter 最大页数" name="HunterMaxPageCount">
                                                <InputNumber min={1} style={{ width: '100%' }} />
                                            </Form.Item>
                                        </Col>
                                    </>
                                )}
                                {(sourceMode === 'fofa' || sourceMode === 'hunter_fofa') && (
                                    <Col span={8}>
                                        <Form.Item label="Fofa 最大数量" name="FofaMaxCount">
                                            <InputNumber min={1} max={10000} style={{ width: '100%' }} />
                                        </Form.Item>
                                    </Col>
                                )}
                                {sourceMode === 'quake' && (
                                    <Col span={8}>
                                        <Form.Item label="Quake 最大数量" name="QuakeSize">
                                            <InputNumber min={1} style={{ width: '100%' }} />
                                        </Form.Item>
                                    </Col>
                                )}
                            </Row>
                        </>
                    )}

                    <Divider orientation="left">高级配置</Divider>
                    <Form.Item
                        label="额外 Agent 配置 JSON"
                        name="advanced_config_json"
                        extra="这里填的 JSON 会直接合并进任务配置；键名请使用 Agent 实际配置字段，例如 NucleiTemplate、APIConfigFilePath、NoInteractsh。"
                    >
                        <TextArea
                            rows={6}
                            placeholder={`{\n  "NucleiTemplate": "config/pocs",\n  "APIConfigFilePath": "config/api-config.yaml",\n  "NoInteractsh": true\n}`}
                        />
                    </Form.Item>
                </Form>
            </Modal>
        </div>
    );
};

export default TaskManagement;

