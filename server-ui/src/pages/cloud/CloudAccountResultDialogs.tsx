import { CheckCircleOutlined, CheckOutlined, CloseOutlined, CopyOutlined, FileOutlined, LockOutlined, PlayCircleOutlined, SafetyCertificateOutlined, ThunderboltOutlined, UserOutlined } from '@ant-design/icons';
import { Alert, Badge, Button, Collapse, Descriptions, Drawer, Empty, message, Modal, Space, Spin, Table, Tag, Tooltip, Typography } from 'antd';

const { Text } = Typography;

interface CloudSetupResultModalProps {
    open: boolean;
    result: any;
    onClose: () => void;
}

export const CloudSetupResultModal = ({ open, result, onClose }: CloudSetupResultModalProps) => (
    <Modal
        title={<><ThunderboltOutlined style={{ color: '#0ea5e9' }} /> 一键配置结果</>}
        open={open}
        onCancel={onClose}
        footer={[<Button key="ok" type="primary" onClick={onClose}>知道了</Button>]}
        width={640}
    >
        {result && (
            <div>
                {result.warnings?.length > 0 && (
                    <Alert
                        type="warning"
                        showIcon
                        style={{ marginBottom: 16 }}
                        message="部分资源发现失败"
                        description={<ul style={{ margin: 0, paddingLeft: 16 }}>{result.warnings.map((warning: string, index: number) => <li key={index} style={{ marginBottom: 4 }}>{warning}</li>)}</ul>}
                    />
                )}
                {result.policy_created && (
                    <Alert type="success" showIcon message="已自动创建调度策略（默认关闭），请在「引擎调度 & 开关」标签页中查看和启用。" style={{ marginBottom: 16 }} />
                )}
                <Descriptions
                    title="当前凭证配置"
                    bordered
                    size="small"
                    column={1}
                    labelStyle={{ width: 120, fontWeight: 500, background: '#f8fafc' }}
                    contentStyle={{ fontFamily: 'monospace', fontSize: 13 }}
                >
                    <Descriptions.Item label="地域">
                        {result.current_config?.region ? <Tag color="green">{result.current_config.region}</Tag> : <Tag color="red">未配置</Tag>}
                    </Descriptions.Item>
                    <Descriptions.Item label="实例规格">
                        {result.current_config?.instance_type ? <><Tag color="blue">{result.current_config.instance_type}</Tag>{result.chosen?.instance_type && <Tag color="cyan">本次更新</Tag>}</> : <Tag color="red">未配置</Tag>}
                    </Descriptions.Item>
                    <Descriptions.Item label="系统镜像">
                        {result.current_config?.image_id ? <><Text code style={{ fontSize: 12 }}>{result.current_config.image_id}</Text>{result.chosen?.image_name && <Text type="secondary" style={{ marginLeft: 8, fontSize: 11 }}>({result.chosen.image_name})</Text>}{result.chosen?.image_id && <Tag color="cyan" style={{ marginLeft: 4 }}>本次更新</Tag>}</> : <Tag color="red">未配置</Tag>}
                    </Descriptions.Item>
                    <Descriptions.Item label="安全组">
                        {result.current_config?.security_group ? <><Text code style={{ fontSize: 12 }}>{result.current_config.security_group}</Text>{result.chosen?.security_group && <Tag color="cyan" style={{ marginLeft: 4 }}>本次更新</Tag>}</> : <Tag color="red">未配置 — 需在阿里云控制台创建安全组</Tag>}
                    </Descriptions.Item>
                    <Descriptions.Item label="交换机">
                        {result.current_config?.v_switch ? <><Text code style={{ fontSize: 12 }}>{result.current_config.v_switch}</Text>{result.chosen?.v_switch && <Tag color="cyan" style={{ marginLeft: 4 }}>本次更新</Tag>}</> : <Tag color="red">未配置 — 需在阿里云控制台创建 VPC 和交换机</Tag>}
                    </Descriptions.Item>
                    <Descriptions.Item label="OSS 存储桶">
                        {result.current_config?.oss_bucket ? <><Text code style={{ fontSize: 12 }}>{result.current_config.oss_bucket}</Text>{result.chosen?.oss_bucket && <Tag color="cyan" style={{ marginLeft: 4 }}>自动创建</Tag>}</> : <Tag color="red">未配置</Tag>}
                    </Descriptions.Item>
                    <Descriptions.Item label="OSS 访问节点">
                        {result.current_config?.oss_endpoint ? <><Text code style={{ fontSize: 12 }}>{result.current_config.oss_endpoint}</Text>{result.chosen?.oss_endpoint && <Tag color="cyan" style={{ marginLeft: 4 }}>自动配置</Tag>}</> : <Tag color="red">未配置</Tag>}
                    </Descriptions.Item>
                </Descriptions>
                <div style={{ marginTop: 16, padding: '8px 12px', background: '#f1f5f9', borderRadius: 6, fontSize: 12, color: '#64748b' }}>
                    资源发现统计：实例规格 {result.discovery?.instance_types || 0} 个 | 镜像 {result.discovery?.images || 0} 个 | 安全组 {result.discovery?.security_groups || 0} 个 | 交换机 {result.discovery?.v_switches || 0} 个
                </div>
            </div>
        )}
    </Modal>
);

interface CloudPermissionDrawerProps {
    open: boolean;
    loading: boolean;
    error: string | null;
    data: any;
    onClose: () => void;
}

const copyMinimumPolicy = (data: any) => {
    const actions = (data.required_permissions || []).map((permission: any) => permission.action_pattern);
    const policy = JSON.stringify({
        Version: '1',
        Statement: [
            { Effect: 'Allow', Action: actions.filter((action: string) => action.startsWith('ecs:')), Resource: '*' },
            { Effect: 'Allow', Action: actions.filter((action: string) => action.startsWith('oss:')), Resource: '*' },
        ],
    }, null, 2);
    navigator.clipboard.writeText(policy);
    message.success('最小权限策略 JSON 已复制到剪贴板');
};

export const CloudPermissionDrawer = ({ open, loading, error, data, onClose }: CloudPermissionDrawerProps) => (
    <Drawer
        title={<span><SafetyCertificateOutlined style={{ marginRight: 8, color: '#8b5cf6' }} />AK/SK 权限检查</span>}
        open={open}
        onClose={onClose}
        width={720}
        destroyOnClose
    >
        {loading ? (
            <div style={{ textAlign: 'center', padding: '80px 0' }}>
                <Spin size="large" />
                <div style={{ marginTop: 16 }}><Text type="secondary">正在通过 STS/RAM API 检查凭证权限...</Text></div>
                <div style={{ marginTop: 8, fontSize: 12, color: '#94a3b8' }}>首次检查可能需要 10-20 秒</div>
            </div>
        ) : error ? (
            <Alert
                type="error"
                showIcon
                message="权限检查失败"
                description={<><div style={{ marginBottom: 8 }}>{error}</div><Text type="secondary" style={{ fontSize: 12 }}>可能原因：AK/SK 无效、网络不通、或缺少 sts:GetCallerIdentity / ram:ListPoliciesForUser 权限。</Text></>}
            />
        ) : data ? (
            <div>
                <Alert
                    type={data.can_one_click_setup ? 'success' : 'warning'}
                    showIcon
                    icon={data.can_one_click_setup ? <CheckCircleOutlined /> : <CloseOutlined />}
                    message={data.can_one_click_setup ? '权限充足，可以执行一键配置' : `缺少 ${data.missing_permissions?.length || 0} 项权限，无法完成一键配置`}
                    description={!data.can_one_click_setup && data.missing_permissions?.length > 0 && (
                        <div style={{ marginTop: 8 }}>
                            <Text type="secondary">缺失权限：</Text>
                            <div style={{ marginTop: 4, display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                                {data.missing_permissions.map((permission: string) => <Tag key={permission} color="error" style={{ fontSize: 11 }}>{permission}</Tag>)}
                            </div>
                        </div>
                    )}
                    style={{ marginBottom: 20 }}
                />
                <div style={{ background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)', borderRadius: 12, padding: '20px 24px', marginBottom: 20, color: '#fff' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 12 }}>
                        <UserOutlined style={{ fontSize: 24 }} />
                        <div>
                            <div style={{ fontWeight: 600, fontSize: 16 }}>
                                {data.identity_type === 'Root' ? '主账号 (Root)' : data.identity_type === 'RAMUser' ? `RAM 用户: ${data.user_name}` : data.identity_type === 'RAMRole' ? `RAM 角色: ${data.user_name}` : `STS 临时凭证: ${data.user_name || '未知'}`}
                            </div>
                            <div style={{ opacity: 0.8, fontSize: 12, marginTop: 2 }}>Account ID: {data.account_id}</div>
                        </div>
                    </div>
                    <div style={{ fontSize: 11, opacity: 0.7, fontFamily: 'monospace', wordBreak: 'break-all' }}>ARN: {data.identity_arn}</div>
                </div>
                <div style={{ marginBottom: 20 }}>
                    <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
                        <LockOutlined style={{ color: '#8b5cf6' }} />绑定的权限策略 ({data.policies?.length || 0})
                    </div>
                    {data.policies?.length > 0 ? (
                        <Table
                            size="small"
                            dataSource={data.policies}
                            rowKey={(record: any) => `${record.policy_name}-${record.attach_source}`}
                            pagination={false}
                            columns={[
                                { title: '策略名称', dataIndex: 'policy_name', key: 'policy_name', render: (name: string) => <Text strong style={{ fontSize: 12, fontFamily: 'monospace' }}>{name}</Text> },
                                { title: '类型', dataIndex: 'policy_type', key: 'policy_type', width: 80, render: (type: string) => <Tag color={type === 'System' ? 'blue' : 'orange'}>{type === 'System' ? '系统' : '自定义'}</Tag> },
                                {
                                    title: '来源', dataIndex: 'attach_source', key: 'attach_source', width: 120,
                                    render: (source: string) => source === 'User' ? <Tag color="green">用户直绑</Tag> : source === 'Role' ? <Tag color="purple">角色绑定</Tag> : source === 'RootAccount' ? <Tag color="gold">主账号</Tag> : source?.startsWith('Group:') ? <Tag color="cyan">组: {source.slice(6)}</Tag> : <Tag>{source}</Tag>,
                                },
                                { title: '描述', dataIndex: 'description', key: 'description', render: (description: string) => <Text type="secondary" style={{ fontSize: 11 }}>{description || '-'}</Text> },
                            ]}
                            expandable={{
                                expandedRowRender: (record: any) => record.policy_document ? (
                                    <pre style={{ background: '#1e1e1e', color: '#d4d4d4', padding: 16, borderRadius: 8, fontSize: 11, maxHeight: 300, overflow: 'auto', margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                                        {(() => { try { return JSON.stringify(JSON.parse(record.policy_document), null, 2); } catch { return record.policy_document; } })()}
                                    </pre>
                                ) : <Text type="secondary">系统策略不展示 Policy Document</Text>,
                                rowExpandable: () => true,
                            }}
                        />
                    ) : <Empty description="未查询到绑定的权限策略" image={Empty.PRESENTED_IMAGE_SIMPLE} />}
                </div>
                <div>
                    <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
                        <SafetyCertificateOutlined style={{ color: '#0ea5e9' }} />
                        一键配置所需权限检查 ({data.required_permissions?.filter((permission: any) => permission.satisfied).length || 0}/{data.required_permissions?.length || 0})
                    </div>
                    <Collapse
                        defaultActiveKey={['ECS', 'VPC', 'OSS']}
                        style={{ background: '#fafafa' }}
                        items={['ECS', 'VPC', 'OSS'].map(category => {
                            const items = (data.required_permissions || []).filter((permission: any) => permission.category === category);
                            const satisfiedCount = items.filter((permission: any) => permission.satisfied).length;
                            const allSatisfied = satisfiedCount === items.length;
                            return {
                                key: category,
                                label: <Space><Tag color={allSatisfied ? 'success' : 'error'} style={{ fontWeight: 600 }}>{category}</Tag><Text type={allSatisfied ? undefined : 'danger'} style={{ fontSize: 13 }}>{satisfiedCount}/{items.length} 项已授权</Text>{allSatisfied && <CheckOutlined style={{ color: '#10b981', fontSize: 12 }} />}</Space>,
                                children: (
                                    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                                        {items.map((permission: any) => (
                                            <div key={permission.action_pattern} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 12px', background: '#fff', borderRadius: 6, border: `1px solid ${permission.satisfied ? '#d1fae5' : '#fecaca'}` }}>
                                                <div><Text style={{ fontFamily: 'monospace', fontSize: 12, fontWeight: 500 }}>{permission.action_pattern}</Text><br /><Text type="secondary" style={{ fontSize: 11 }}>{permission.description}</Text></div>
                                                {permission.satisfied ? <Tag icon={<CheckOutlined />} color="success">已授权</Tag> : <Tag icon={<CloseOutlined />} color="error">未授权</Tag>}
                                            </div>
                                        ))}
                                    </div>
                                ),
                            };
                        })}
                    />
                    {!data.can_one_click_setup && (
                        <div style={{ marginTop: 20 }}>
                            <Alert
                                type="info"
                                showIcon
                                message="快速修复"
                                description={<div><div style={{ marginBottom: 8 }}>在阿里云 RAM 控制台创建自定义策略，粘贴以下 JSON 即可授予一键配置所需的最小权限：</div><Tooltip title="点击复制最小权限策略 JSON"><Button size="small" icon={<CopyOutlined />} onClick={() => copyMinimumPolicy(data)}>复制最小权限策略 JSON</Button></Tooltip></div>}
                            />
                        </div>
                    )}
                </div>
            </div>
        ) : null}
    </Drawer>
);

interface CloudOSSTestModalProps {
    open: boolean;
    loading: boolean;
    result: any;
    onClose: () => void;
}

export const CloudOSSTestModal = ({ open, loading, result, onClose }: CloudOSSTestModalProps) => (
    <Modal
        title={<><PlayCircleOutlined style={{ marginRight: 8, color: '#8b5cf6' }} />OSS 连通性测试报告</>}
        open={open}
        onCancel={onClose}
        footer={[<Button key="ok" type="primary" onClick={onClose}>知道了</Button>]}
        width={600}
    >
        {loading ? (
            <div style={{ textAlign: 'center', padding: '40px 0' }}><Spin size="large" /><div style={{ marginTop: 16 }}><Text type="secondary">正在测试 OSS 连通性...</Text></div></div>
        ) : result ? (
            <div>
                <Alert type={result.connection ? 'success' : 'error'} showIcon message={result.connection ? 'OSS 连通性测试通过' : 'OSS 连接失败'} description={result.connection_err || undefined} style={{ marginBottom: 20 }} />
                <Descriptions bordered size="small" column={1} labelStyle={{ width: 130, fontWeight: 500, background: '#f8fafc' }} contentStyle={{ fontFamily: 'monospace', fontSize: 13 }}>
                    <Descriptions.Item label="Bucket"><Text copyable style={{ fontSize: 13 }}>{result.bucket || '-'}</Text></Descriptions.Item>
                    <Descriptions.Item label="Endpoint"><Text copyable style={{ fontSize: 13 }}>{result.endpoint || '-'}</Text></Descriptions.Item>
                    <Descriptions.Item label="连接状态">{result.connection ? <Tag icon={<CheckCircleOutlined />} color="success">已连通</Tag> : <Tag icon={<CloseOutlined />} color="error">连接失败</Tag>}</Descriptions.Item>
                    {result.connection && <><Descriptions.Item label="Agent 文件数"><Badge count={result.file_count || 0} showZero style={{ backgroundColor: result.file_count > 0 ? '#10b981' : '#94a3b8' }} /><Text type="secondary" style={{ marginLeft: 8, fontSize: 12 }}>(共 {((result.total_size || 0) / 1024 / 1024).toFixed(1)} MB)</Text></Descriptions.Item><Descriptions.Item label="核心制品">{result.agent_ready ? <><Tag color="success">已就绪</Tag><Text type="secondary" style={{ fontSize: 11 }}>{result.required_agent}</Text></> : <><Tag color="warning">未上传</Tag><Text type="secondary" style={{ fontSize: 11 }}>需要上传 {result.required_agent}</Text></>}</Descriptions.Item></>}
                </Descriptions>
                {result.connection && result.files?.length > 0 && (
                    <div style={{ marginTop: 16 }}>
                        <Text strong style={{ fontSize: 13, marginBottom: 8, display: 'block' }}><FileOutlined style={{ marginRight: 4 }} />OSS 中的 Agent 文件</Text>
                        {result.files.map((file: any) => {
                            const name = file.key?.split('/').pop() || file.key;
                            const isRequired = file.key === result.required_agent;
                            return <div key={file.key} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '6px 12px', borderRadius: 4, background: isRequired ? '#f0fdf4' : '#f8fafc', border: isRequired ? '1px solid #bbf7d0' : '1px solid #f1f5f9', marginBottom: 4 }}><Space><FileOutlined style={{ color: isRequired ? '#10b981' : '#64748b' }} /><Text style={{ fontFamily: 'monospace', fontSize: 12 }}>{name}</Text>{isRequired && <Tag color="green" style={{ fontSize: 10 }}>核心制品</Tag>}</Space><Text type="secondary" style={{ fontSize: 12 }}>{(file.size / 1024 / 1024).toFixed(1)} MB</Text></div>;
                        })}
                    </div>
                )}
            </div>
        ) : null}
    </Modal>
);
