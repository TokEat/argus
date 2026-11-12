import { CloudUploadOutlined, InboxOutlined, PlayCircleOutlined } from '@ant-design/icons';
import { Alert, Button, Empty, Space, Table, Tag, Typography } from 'antd';
import { OSSFileBrowser } from './OSSFileBrowser';

const { Text } = Typography;

interface CloudAgentDistributionPanelProps {
    accounts: API.CloudAccount[];
    onUpload: (account: API.CloudAccount) => void;
    onTest: (account: API.CloudAccount) => void;
}

export const CloudAgentDistributionPanel = ({ accounts, onUpload, onTest }: CloudAgentDistributionPanelProps) => (
    <div style={{ padding: '20px 0' }}>
        <Alert
            message="Agent 二进制分发管理"
            description="弹性扩缩创建的 ECS 实例通过 OSS 内网高速下载 Agent 二进制（预签名 URL，1小时过期）。请确保凭证已配置 OSS Bucket 和 Endpoint，并已上传 Agent 制品。"
            type="info"
            showIcon
            style={{ marginBottom: 16 }}
        />
        {accounts.length === 0 ? (
            <Empty description="请先在「API 凭证管理」中添加云凭证" style={{ padding: '60px 0' }} />
        ) : (
            <Table
                dataSource={accounts}
                rowKey="id"
                pagination={false}
                size="middle"
                columns={[
                    {
                        title: '凭证别名', dataIndex: 'name', key: 'name',
                        render: (value: string) => <Text strong>{value}</Text>,
                    },
                    {
                        title: 'OSS Bucket', dataIndex: 'oss_bucket', key: 'oss_bucket',
                        render: (value: string) => value
                            ? <Text style={{ color: '#10b981', fontFamily: 'monospace', fontSize: 12 }}>{value}</Text>
                            : <Tag color="default">未配置</Tag>,
                    },
                    {
                        title: 'OSS Endpoint', dataIndex: 'oss_endpoint', key: 'oss_endpoint',
                        render: (value: string) => value
                            ? <Text style={{ color: '#10b981', fontFamily: 'monospace', fontSize: 12 }}>{value}</Text>
                            : <Tag color="default">未配置</Tag>,
                    },
                    {
                        title: '分发通道', key: 'channel',
                        render: (_: unknown, record: API.CloudAccount) => record.oss_bucket && record.oss_endpoint
                            ? <Tag color="blue">OSS 内网高速分发</Tag>
                            : <Tag color="red">未配置 OSS（无法分发）</Tag>,
                    },
                    {
                        title: '操作', key: 'actions', width: 260,
                        render: (_: unknown, record: API.CloudAccount) => (
                            <Space>
                                <Button
                                    type="primary"
                                    size="small"
                                    icon={<CloudUploadOutlined />}
                                    disabled={!record.oss_bucket || !record.oss_endpoint}
                                    onClick={() => onUpload(record)}
                                >上传 Agent</Button>
                                <Button
                                    size="small"
                                    icon={<PlayCircleOutlined />}
                                    disabled={!record.oss_bucket || !record.oss_endpoint}
                                    onClick={() => onTest(record)}
                                >OSS 测试</Button>
                            </Space>
                        ),
                    },
                ]}
            />
        )}

        {accounts.some(account => account.oss_bucket && account.oss_endpoint) && (
            <div style={{ marginTop: 24 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
                    <InboxOutlined style={{ color: '#0ea5e9', fontSize: 16 }} />
                    <Text strong style={{ fontSize: 15 }}>OSS 制品浏览器</Text>
                    <Text type="secondary" style={{ fontSize: 12 }}>查看已上传到 OSS 的 Agent 文件</Text>
                </div>
                {accounts.filter(account => account.oss_bucket && account.oss_endpoint).map(account => (
                    <OSSFileBrowser key={account.id} account={account} />
                ))}
            </div>
        )}
    </div>
);
