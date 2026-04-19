import React from 'react';
import { Typography, Tag, Space, Row, Col, List } from 'antd';
import { ProCard } from '@ant-design/pro-components';
import { SafetyOutlined, CrownOutlined, ToolOutlined, EyeOutlined } from '@ant-design/icons';

const { Title, Text, Paragraph } = Typography;

const roles = [
    {
        key: 'admin',
        name: '管理员',
        icon: <CrownOutlined style={{ fontSize: 28, color: '#ef4444' }} />,
        color: '#ef4444',
        gradient: 'linear-gradient(135deg, #ef4444, #f87171)',
        description: '拥有系统完全控制权限，可管理所有资源和用户。',
        permissions: [
            '创建、编辑、删除任务',
            '管理 Agent 节点',
            '管理弹药库规则（POC / 指纹 / Workflow）',
            '审批规则发布',
            '管理用户和角色',
            '查看和导出所有报表',
            '系统配置与 MCP 密钥管理',
            '云实例创建与销毁',
            '客户端编译构建',
        ],
    },
    {
        key: 'operator',
        name: '操作员',
        icon: <ToolOutlined style={{ fontSize: 28, color: '#f59e0b' }} />,
        color: '#f59e0b',
        gradient: 'linear-gradient(135deg, #f59e0b, #fbbf24)',
        description: '可执行日常扫描任务和规则管理，不具备用户管理权限。',
        permissions: [
            '创建、编辑、取消任务',
            '查看 Agent 节点状态',
            '管理弹药库规则',
            '提交规则审批',
            '查看和导出报表',
            '查看融合画像',
        ],
    },
    {
        key: 'viewer',
        name: '观察者',
        icon: <EyeOutlined style={{ fontSize: 28, color: '#10b981' }} />,
        color: '#10b981',
        gradient: 'linear-gradient(135deg, #10b981, #34d399)',
        description: '只读权限，可查看扫描结果和系统状态。',
        permissions: [
            '查看任务列表和状态',
            '查看 Agent 节点状态',
            '查看漏洞、资产、指纹结果',
            '查看融合画像',
            '导出报表',
        ],
    },
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
        </div>
    );
};

export default RoleManagement;
