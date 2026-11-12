import { CheckCircleOutlined, PlayCircleOutlined, SafetyCertificateOutlined, SearchOutlined, ThunderboltOutlined, UserOutlined } from '@ant-design/icons';
import { Alert, Button, Descriptions, Popconfirm, Space, Table, Tag, Tooltip, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';

const { Text } = Typography;

interface CloudAccountsPanelProps {
    accounts: API.CloudAccount[];
    isAdmin: boolean;
    canManage: (account?: API.CloudAccount | null) => boolean;
    onOneClick: (accountId: string) => void;
    onPermissions: (accountId: string) => void;
    onDiscover: (accountId: string) => void;
    onTest: (accountId: string) => void;
    onBindings: (account: API.CloudAccount) => void;
    onDelete: (accountId: string) => void;
}

export const CloudAccountsPanel = ({
    accounts,
    isAdmin,
    canManage,
    onOneClick,
    onPermissions,
    onDiscover,
    onTest,
    onBindings,
    onDelete,
}: CloudAccountsPanelProps) => {
    const columns: ColumnsType<API.CloudAccount> = [
        { title: '凭证别名', dataIndex: 'name', key: 'name', render: (value: string) => <Text strong>{value}</Text> },
        { title: '提供商', dataIndex: 'provider', key: 'provider', render: (provider: string) => <Tag color="blue">{provider.toUpperCase()}</Tag> },
        {
            title: '归属', key: 'owner', width: 150,
            render: (_: unknown, account: API.CloudAccount) => (
                <Space direction="vertical" size={2}>
                    <Text style={{ fontSize: 12 }}>{account.owner_username || account.owner_user_id || '-'}</Text>
                    <Tag color={account.access_level === 'bound' ? 'cyan' : account.access_level === 'owner' ? 'green' : 'purple'} style={{ fontSize: 10, width: 'fit-content' }}>
                        {account.access_level === 'bound' ? '被授权使用' : account.access_level === 'owner' ? '我的凭证' : '管理员可管'}
                    </Tag>
                </Space>
            ),
        },
        { title: '地域', dataIndex: 'region', key: 'region', render: (region: string) => region ? <Tag color="green">{region}</Tag> : <Tag color="orange">待选择</Tag> },
        {
            title: '配置状态', key: 'config_status',
            render: (_: unknown, account: API.CloudAccount) => account.default_instance_type && account.default_image_id && account.default_security_group && account.default_v_switch
                ? <Tag color="success" icon={<CheckCircleOutlined />}>已就绪</Tag>
                : <Tag color="warning">待配置</Tag>,
        },
        { title: '状态', dataIndex: 'status', key: 'status', render: (status: string) => <Tag color={status === 'active' ? 'success' : 'default'}>{status === 'active' ? '正常' : '已禁用'}</Tag> },
        {
            title: '操作', key: 'action', width: 320,
            render: (_: unknown, account: API.CloudAccount) => {
                const manageable = canManage(account);
                return (
                    <Space wrap>
                        <Tooltip title={manageable ? '' : '被授权凭证只能使用，不能修改基础配置'}>
                            <Button type="link" size="small" icon={<ThunderboltOutlined />} disabled={!manageable} style={{ color: manageable ? '#0ea5e9' : undefined, fontWeight: 600 }} onClick={() => onOneClick(account.id)}>一键配置</Button>
                        </Tooltip>
                        <Button type="link" size="small" icon={<SafetyCertificateOutlined />} style={{ color: '#8b5cf6' }} onClick={() => onPermissions(account.id)}>权限检查</Button>
                        <Button type="link" size="small" icon={<SearchOutlined />} onClick={() => onDiscover(account.id)}>自动探测</Button>
                        <Button type="link" size="small" icon={<PlayCircleOutlined />} onClick={() => onTest(account.id)}>连通性</Button>
                        {isAdmin && <Button type="link" size="small" icon={<UserOutlined />} onClick={() => onBindings(account)}>绑定用户</Button>}
                        {manageable && <Popconfirm title="确认删除此凭证？" onConfirm={() => onDelete(account.id)}><Button type="link" danger size="small">删除</Button></Popconfirm>}
                    </Space>
                );
            },
        },
    ];

    const renderExpandedRow = (account: API.CloudAccount) => {
        const ossReady = Boolean(account.oss_bucket && account.oss_endpoint);
        const configReady = Boolean(account.default_instance_type && account.default_image_id && account.default_security_group && account.default_v_switch);
        return (
            <div style={{ padding: '8px 16px' }}>
                <div style={{ marginBottom: 12, display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                    <Tag color={configReady ? 'success' : 'warning'} style={{ fontSize: 12, padding: '2px 10px' }}>{configReady ? '实例配置就绪' : '实例配置不完整'}</Tag>
                    <Tag color={ossReady ? 'success' : 'default'} style={{ fontSize: 12, padding: '2px 10px' }}>{ossReady ? 'OSS 分发就绪' : 'HTTP Fallback 分发'}</Tag>
                </div>
                <Descriptions size="small" column={3} bordered labelStyle={{ background: '#f8fafc', fontWeight: 500, width: 120 }} contentStyle={{ fontFamily: 'monospace', fontSize: 12 }}>
                    <Descriptions.Item label="实例规格">{account.default_instance_type || <Text type="danger">未配置</Text>}</Descriptions.Item>
                    <Descriptions.Item label="系统镜像">{account.default_image_id || <Text type="danger">未配置</Text>}</Descriptions.Item>
                    <Descriptions.Item label="安全组">{account.default_security_group || <Text type="danger">未配置</Text>}</Descriptions.Item>
                    <Descriptions.Item label="交换机">{account.default_v_switch || <Text type="danger">未配置</Text>}</Descriptions.Item>
                    <Descriptions.Item label="OSS Bucket">{account.oss_bucket ? <Text style={{ color: '#10b981' }}>{account.oss_bucket}</Text> : <Text type="secondary">未配置</Text>}</Descriptions.Item>
                    <Descriptions.Item label="OSS Endpoint">{account.oss_endpoint ? <Text style={{ color: '#10b981' }}>{account.oss_endpoint}</Text> : <Text type="secondary">未配置</Text>}</Descriptions.Item>
                    <Descriptions.Item label="绑定用户">
                        {isAdmin && account.bound_user_ids?.length ? <Text>{account.bound_user_ids.length} 个用户</Text> : <Text type="secondary">{account.access_level === 'bound' ? '由管理员授权' : '仅自己可用'}</Text>}
                    </Descriptions.Item>
                </Descriptions>
            </div>
        );
    };

    return (
        <div style={{ padding: '20px 0' }}>
            <Alert message="所有 AccessKey 和 Secret 均在入库前通过 AES-256-GCM 算法进行加密存储。点击「自动探测」可通过 AK/SK 自动发现云资源并配置。" type="success" showIcon style={{ marginBottom: 16 }} />
            <Table columns={columns} dataSource={accounts} rowKey="id" pagination={false} size="middle" expandable={{ expandedRowRender: renderExpandedRow, rowExpandable: () => true }} />
        </div>
    );
};
