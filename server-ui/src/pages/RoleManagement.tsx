import React from 'react';
import { Typography, Tag, Space, Row, Col, List, Table, Divider } from 'antd';
import { ProCard } from '@ant-design/pro-components';
import { SafetyOutlined, CrownOutlined, ToolOutlined, EyeOutlined } from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';

const { Title, Text, Paragraph } = Typography;

const roles = [
    {
        key: 'admin',
        name: '管理员',
        icon: <CrownOutlined style={{ fontSize: 28, color: '#ef4444' }} />,
        color: '#ef4444',
        gradient: 'linear-gradient(135deg, #ef4444, #f87171)',
        description: '当前租户内最高权限，可管理用户、系统配置、云资源和规则发布。',
        permissions: [
            '包含操作员和观察者的全部权限',
            '管理当前租户用户、角色、启停状态和密码',
            '管理 MCP Key、API Key、AI 配置和模型连通性测试',
            '管理全租户云账号、AK/SK 用户绑定和 OSS 分发',
            '审批或回滚弹药库规则发布',
            '生成客户端构建产物',
        ],
    },
    {
        key: 'operator',
        name: '操作员',
        icon: <ToolOutlined style={{ fontSize: 28, color: '#f59e0b' }} />,
        color: '#f59e0b',
        gradient: 'linear-gradient(135deg, #f59e0b, #fbbf24)',
        description: '负责日常扫描和规则维护，不接触租户级系统配置和用户管理。',
        permissions: [
            '创建项目和扫描任务',
            '追加目标、取消任务、删除任务',
            '查看队列深度、Agent 日志和节点状态',
            '删除节点记录、清理离线节点',
            '创建、编辑、删除弹药库草稿规则和字典',
            '添加自己的 AK/SK，使用自己或管理员绑定的云资源与 OSS',
            '使用 AI 分析、调试和全局问答能力',
        ],
    },
    {
        key: 'viewer',
        name: '观察者',
        icon: <EyeOutlined style={{ fontSize: 28, color: '#10b981' }} />,
        color: '#10b981',
        gradient: 'linear-gradient(135deg, #10b981, #34d399)',
        description: '只读权限，只能查看当前租户数据和导出扫描结果。',
        permissions: [
            '查看仪表盘、项目、任务和任务详情',
            '查看 Agent 节点状态',
            '查看漏洞、资产、指纹结果',
            '查看融合画像、弹药库规则和字典',
            '导出漏洞报表',
            '接收当前租户 WebSocket 实时更新',
        ],
    },
];

const matrix = [
    { module: '租户隔离', viewer: '仅本租户', operator: '仅本租户', admin: '仅本租户' },
    { module: '仪表盘 / 项目 / 任务 / 结果', viewer: '查看', operator: '查看 + 任务操作', admin: '全部' },
    { module: '项目创建', viewer: '-', operator: '允许', admin: '允许' },
    { module: '任务下发 / 追加 / 取消 / 删除', viewer: '-', operator: '允许', admin: '允许' },
    { module: '节点状态 / 队列 / Agent 日志', viewer: '查看节点', operator: '查看 + 运维', admin: '全部' },
    { module: '弹药库规则 / 字典', viewer: '查看', operator: '草稿维护', admin: '维护 + 审批 + 回滚' },
    { module: '漏洞报表', viewer: '导出', operator: '导出', admin: '导出' },
    { module: 'AI 分析 / 全局问答', viewer: '-', operator: '允许', admin: '允许' },
    { module: '用户与角色管理', viewer: '-', operator: '-', admin: '允许' },
    { module: '云资源与 OSS 分发', viewer: '-', operator: '自有/被绑定 AK/SK', admin: '全租户 + 绑定管理' },
    { module: 'MCP / API Key / AI 配置', viewer: '-', operator: '-', admin: '允许' },
    { module: '客户端构建', viewer: '-', operator: '-', admin: '允许' },
];

const columns: ColumnsType<(typeof matrix)[number]> = [
    { title: '功能域', dataIndex: 'module', key: 'module', width: 220 },
    { title: '观察者 viewer', dataIndex: 'viewer', key: 'viewer' },
    { title: '操作员 operator', dataIndex: 'operator', key: 'operator' },
    { title: '管理员 admin', dataIndex: 'admin', key: 'admin' },
];

const cardStyle = {
    background: '#ffffff', borderRadius: 12,
    border: '1px solid #e2e8f0',
    boxShadow: '0 1px 3px 0 rgba(0, 0, 0, 0.04)',
};

const RoleManagement: React.FC = () => {
    return (
        <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
                <Title level={4} style={{ margin: 0, color: '#1e293b', fontWeight: 600 }}>
                    <SafetyOutlined style={{ marginRight: 8, color: '#6366f1' }} />
                    角色权限管理
                </Title>
                <Tag color="blue">3 个角色</Tag>
            </div>

            <Row gutter={[16, 16]}>
                {roles.map((role) => (
                    <Col xs={24} md={8} key={role.key}>
                        <ProCard style={{ ...cardStyle, height: '100%' }} bodyStyle={{ padding: 0 }}>
                            <div style={{
                                background: role.gradient, padding: '24px 20px',
                                borderRadius: '12px 12px 0 0',
                                display: 'flex', alignItems: 'center', gap: 12,
                            }}>
                                <div style={{
                                    width: 48, height: 48, borderRadius: 12,
                                    background: 'rgba(255,255,255,0.2)',
                                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                                    color: '#fff',
                                }}>
                                    {role.icon}
                                </div>
                                <div>
                                    <Text style={{ color: '#fff', fontSize: 18, fontWeight: 600 }}>{role.name}</Text>
                                    <div>
                                        <Tag style={{
                                            background: 'rgba(255,255,255,0.2)',
                                            border: 'none', color: '#fff',
                                            borderRadius: 20, fontSize: 10,
                                        }}>{role.key}</Tag>
                                    </div>
                                </div>
                            </div>
                            <div style={{ padding: '16px 20px' }}>
                                <Paragraph style={{ color: '#64748b', fontSize: 13, marginBottom: 16 }}>
                                    {role.description}
                                </Paragraph>
                                <Text strong style={{ fontSize: 12, color: '#1e293b', marginBottom: 8, display: 'block' }}>
                                    权限列表
                                </Text>
                                <List
                                    size="small"
                                    dataSource={role.permissions}
                                    renderItem={(item) => (
                                        <List.Item style={{ padding: '4px 0', border: 'none' }}>
                                            <Space size={6}>
                                                <div style={{
                                                    width: 5, height: 5, borderRadius: '50%',
                                                    background: role.color,
                                                }} />
                                                <Text style={{ fontSize: 12, color: '#475569' }}>{item}</Text>
                                            </Space>
                                        </List.Item>
                                    )}
                                />
                            </div>
                        </ProCard>
                    </Col>
                ))}
            </Row>

            <Divider />

            <ProCard style={{ ...cardStyle }} bodyStyle={{ padding: 16 }}>
                <Title level={5} style={{ marginTop: 0, marginBottom: 12, color: '#1e293b' }}>功能权限矩阵</Title>
                <Table
                    columns={columns}
                    dataSource={matrix}
                    rowKey="module"
                    pagination={false}
                    size="small"
                />
                <Paragraph style={{ marginTop: 12, marginBottom: 0, color: '#64748b', fontSize: 12 }}>
                    未在后端权限表显式声明的新接口默认要求管理员权限；所有业务查询都以登录令牌中的 tenant_id 作为隔离边界。
                </Paragraph>
            </ProCard>
        </div>
    );
};

export default RoleManagement;
