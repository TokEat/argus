import { DeleteOutlined, FileOutlined, InboxOutlined, ReloadOutlined } from '@ant-design/icons';
import { ProCard } from '@ant-design/pro-components';
import { Button, Empty, message, Popconfirm, Space, Spin, Table, Tag, Typography } from 'antd';
import { useState } from 'react';
import { deleteOSSFile, listOSSFiles } from '../../services/api';
import { extractErrorMsg } from './utils';

const { Text } = Typography;

interface OSSFileBrowserProps {
    account: API.CloudAccount;
}

export const OSSFileBrowser = ({ account }: OSSFileBrowserProps) => {
    const [ossFiles, setOssFiles] = useState<API.OSSFileInfo[]>([]);
    const [ossLoading, setOssLoading] = useState(false);
    const [loaded, setLoaded] = useState(false);

    const fetchOSSFiles = async () => {
        setOssLoading(true);
        try {
            const res = await listOSSFiles(account.id);
            setOssFiles(res.files || []);
        } catch {
            setOssFiles([]);
        } finally {
            setOssLoading(false);
            setLoaded(true);
        }
    };

    const handleDelete = async (objectKey: string) => {
        try {
            await deleteOSSFile(account.id, objectKey);
            message.success('文件已从 OSS 删除');
            fetchOSSFiles();
        } catch (err) {
            message.error(`删除失败: ${extractErrorMsg(err) || String(err)}`);
        }
    };

    return (
        <ProCard
            bordered
            size="small"
            style={{ marginBottom: 12 }}
            title={
                <Space>
                    <Tag color="blue" style={{ margin: 0 }}>{account.name}</Tag>
                    <Text type="secondary" style={{ fontSize: 12 }}>
                        {account.oss_bucket} / argus/agent/
                    </Text>
                </Space>
            }
            extra={
                <Button size="small" icon={<ReloadOutlined />} onClick={fetchOSSFiles} loading={ossLoading}>
                    {loaded ? '刷新' : '加载文件列表'}
                </Button>
            }
        >
            {!loaded ? (
                <div style={{ textAlign: 'center', padding: '24px 0', color: '#94a3b8' }}>
                    <InboxOutlined style={{ fontSize: 28, marginBottom: 8 }} />
                    <div style={{ fontSize: 13 }}>点击「加载文件列表」查看 OSS 中的 Agent 制品</div>
                </div>
            ) : ossLoading ? (
                <div style={{ display: 'flex', justifyContent: 'center', padding: '24px 0' }}><Spin /></div>
            ) : ossFiles.length === 0 ? (
                <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="OSS 中暂无 Agent 文件" style={{ padding: '16px 0' }} />
            ) : (
                <Table
                    dataSource={ossFiles}
                    rowKey="key"
                    pagination={false}
                    size="small"
                    columns={[
                        {
                            title: 'Object Key', dataIndex: 'key', key: 'key',
                            render: (key: string) => {
                                const name = key.split('/').pop() || key;
                                return (
                                    <Space>
                                        <FileOutlined style={{ color: '#64748b' }} />
                                        <div>
                                            <Text style={{ fontFamily: 'monospace', fontSize: 13 }}>{name}</Text>
                                            <br />
                                            <Text type="secondary" style={{ fontSize: 11 }}>{key}</Text>
                                        </div>
                                    </Space>
                                );
                            },
                        },
                        {
                            title: '大小', dataIndex: 'size', key: 'size', width: 110,
                            render: (size: number) => {
                                if (size > 1024 * 1024) return <Text type="secondary">{(size / 1024 / 1024).toFixed(1)} MB</Text>;
                                if (size > 1024) return <Text type="secondary">{(size / 1024).toFixed(1)} KB</Text>;
                                return <Text type="secondary">{size} B</Text>;
                            },
                        },
                        {
                            title: '最后修改', dataIndex: 'last_modified', key: 'last_modified', width: 180,
                            render: (value: string) => <Text style={{ fontSize: 12, color: '#64748b' }}>{value ? new Date(value).toLocaleString('zh-CN') : '-'}</Text>,
                        },
                        {
                            title: '操作', key: 'actions', width: 80,
                            render: (_: unknown, record: API.OSSFileInfo) => (
                                <Popconfirm title="确认从 OSS 删除此文件？" onConfirm={() => handleDelete(record.key)}>
                                    <Button type="text" danger size="small" icon={<DeleteOutlined />} />
                                </Popconfirm>
                            ),
                        },
                    ]}
                />
            )}
        </ProCard>
    );
};
