import React, { useState } from 'react';
import { Typography, Table, Tag, Space, Button, Drawer, Alert, message } from 'antd';
import { ProCard } from '@ant-design/pro-components';
import { CopyOutlined, EyeOutlined } from '@ant-design/icons';
import type { McpAdminTool } from '../services/mcpAdmin';
import { toolCategoryLabel } from './mcpManagementShared';

const { Text, Paragraph, Title } = Typography;

const jsonBlock = (value: unknown) => JSON.stringify(value ?? {}, null, 2);

const McpToolCatalog: React.FC<{ tools: McpAdminTool[]; loading: boolean }> = ({ tools, loading }) => {
    const [selected, setSelected] = useState<McpAdminTool | null>(null);

    const copyJSON = async (value: unknown, ok: string) => {
        await navigator.clipboard.writeText(jsonBlock(value));
        message.success(ok);
    };

    return (
        <ProCard className="glass-card" style={{ background: 'transparent', border: 'none' }}>
            <Alert
                type="info"
                showIcon
                style={{ marginBottom: 16 }}
                message="只读投影当前 MCP 工具定义。标题与说明、参数随 tools() 自动更新；调用示例由 InputSchema 生成。本页不会发起 tools/call，也不会改变 tools/list。"
            />
            <Table
                rowKey="name"
                loading={loading}
                dataSource={tools}
                pagination={false}
                size="middle"
                locale={{ emptyText: '暂无工具目录' }}
                columns={[
                    {
                        title: '工具',
                        dataIndex: 'name',
                        width: 240,
                        render: (value: string) => <Text code>{value}</Text>,
                    },
                    {
                        title: '分级',
                        dataIndex: 'category',
                        width: 110,
                        render: (value: string) => {
                            const meta = toolCategoryLabel[value] || { color: 'default', text: value || '-' };
                            return <Tag color={meta.color}>{meta.text}</Tag>;
                        },
                    },
                    {
                        title: '调用审计',
                        dataIndex: 'auditable',
                        width: 140,
                        render: (value: boolean, row: McpAdminTool) => (
                            value ? <Tag color="red">{row.audit_when ? row.audit_when : '计入'}</Tag> : <Tag>不记</Tag>
                        ),
                    },
                    {
                        title: '说明',
                        key: 'description',
                        render: (_: unknown, row: McpAdminTool) => (
                            <Paragraph
                                ellipsis={{ rows: 2 }}
                                style={{ marginBottom: 0, cursor: 'pointer', maxWidth: 520 }}
                                onClick={() => setSelected(row)}
                            >
                                {row.title || row.description}
                            </Paragraph>
                        ),
                    },
                    {
                        title: '操作',
                        width: 90,
                        render: (_: unknown, row: McpAdminTool) => (
                            <Button size="small" icon={<EyeOutlined />} aria-label="详情" onClick={() => setSelected(row)}>详情</Button>
                        ),
                    },
                ]}
            />
            <Drawer title={selected?.title || selected?.name || '工具详情'} width={760} open={!!selected} onClose={() => setSelected(null)}>
                {selected && (
                    <Space direction="vertical" size={16} style={{ width: '100%' }}>
                        <Space wrap>
                            <Text code>{selected.name}</Text>
                            <Tag color={toolCategoryLabel[selected.category]?.color || 'default'}>
                                {toolCategoryLabel[selected.category]?.text || selected.category || '-'}
                            </Tag>
                            {selected.auditable ? <Tag color="red">{selected.audit_when ? selected.audit_when : '计入审计'}</Tag> : <Tag>不记审计</Tag>}
                        </Space>
                        <div>
                            <Title level={5} style={{ marginTop: 0 }}>说明</Title>
                            <Paragraph style={{ marginBottom: 0, whiteSpace: 'pre-wrap' }}>{selected.description}</Paragraph>
                        </div>
                        <div>
                            <Space style={{ marginBottom: 8 }}>
                                <Title level={5} style={{ margin: 0 }}>调用示例</Title>
                                <Button
                                    size="small"
                                    icon={<CopyOutlined />}
                                    onClick={() => copyJSON(selected.example_call, '已复制 tools/call 示例')}
                                >
                                    复制 JSON
                                </Button>
                            </Space>
                            <Paragraph style={{ marginBottom: 0 }}>
                                <pre style={{ margin: 0, padding: 12, background: '#0f172a', color: '#e2e8f0', borderRadius: 8, fontSize: 12, whiteSpace: 'pre-wrap' }}>
                                    {jsonBlock(selected.example_call)}
                                </pre>
                            </Paragraph>
                        </div>
                        <div>
                            <Title level={5}>输入参数</Title>
                            <Paragraph style={{ marginBottom: 0 }}>
                                <pre style={{ margin: 0, padding: 12, background: '#0f172a', color: '#e2e8f0', borderRadius: 8, fontSize: 12, whiteSpace: 'pre-wrap', maxHeight: 280, overflow: 'auto' }}>
                                    {jsonBlock(selected.input_schema)}
                                </pre>
                            </Paragraph>
                        </div>
                    </Space>
                )}
            </Drawer>
        </ProCard>
    );
};

export default McpToolCatalog;
