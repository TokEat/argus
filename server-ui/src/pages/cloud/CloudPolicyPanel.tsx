import { CodeOutlined, DeleteOutlined } from '@ant-design/icons';
import { ProCard } from '@ant-design/pro-components';
import { Alert, Button, Col, Form, Input, InputNumber, Popconfirm, Row, Select, Space, Switch, Typography } from 'antd';
import type { FormInstance } from 'antd';
import Editor from '@monaco-editor/react';
import type { CloudPolicyFormValues } from './utils';

const { Paragraph, Title } = Typography;

interface CloudPolicyPanelProps {
    policies: API.CloudScalingPolicy[];
    accounts: API.CloudAccount[];
    currentPolicyId: string | null;
    form: FormInstance;
    initialValues: CloudPolicyFormValues;
    userDataScript: string;
    onPolicyChange: (policyId: string | null) => void;
    onUserDataScriptChange: (value: string) => void;
    onToggle: (enabled: boolean) => void;
    onSubmit: () => void;
    onDelete: () => void;
}

export const CloudPolicyPanel = ({
    policies,
    accounts,
    currentPolicyId,
    form,
    initialValues,
    userDataScript,
    onPolicyChange,
    onUserDataScriptChange,
    onToggle,
    onSubmit,
    onDelete,
}: CloudPolicyPanelProps) => (
    <div style={{ padding: '20px 0', maxWidth: 800 }}>
        <ProCard bordered style={{ marginBottom: 24 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                <Title level={5} style={{ margin: 0 }}>引擎调度开关</Title>
                <Switch
                    checkedChildren="已启用"
                    unCheckedChildren="已停用"
                    checked={policies.find(policy => policy.id === currentPolicyId)?.enabled ?? false}
                    onChange={onToggle}
                    disabled={!currentPolicyId}
                />
            </div>

            {policies.length > 0 && (
                <div style={{ marginBottom: 16 }}>
                    <div style={{ marginBottom: 6, fontWeight: 500 }}>选择策略（共 {policies.length} 条）</div>
                    <Select
                        style={{ width: '100%' }}
                        value={currentPolicyId ?? '__new__'}
                        onChange={(value) => onPolicyChange(value === '__new__' ? null : value)}
                        options={[
                            ...policies.map(policy => ({ value: policy.id, label: `${policy.name}${policy.enabled ? '' : '（已停用）'}` })),
                            { value: '__new__', label: '＋ 新建策略' },
                        ]}
                    />
                </div>
            )}
            <Paragraph type="secondary">
                配置 AutoScaler (自动伸缩引擎) 的行为模式。系统将根据后台任务队列深度，向指定云厂商自动请求或销毁 Spot 竞价实例。
            </Paragraph>

            {!currentPolicyId && (
                <Alert message="暂无伸缩策略，请填写下方表单创建一个新策略" type="info" showIcon style={{ marginBottom: 16 }} />
            )}

            <Form form={form} layout="vertical" initialValues={initialValues}>
                <Form.Item name="name" label="策略名称" rules={[{ required: true }]}>
                    <Input placeholder="例: 默认全局扩容策略" />
                </Form.Item>
                <Form.Item name="cloud_account_id" label="绑定的云凭证" rules={[{ required: true }]}>
                    <Select placeholder="请选择凭证" options={accounts.map(account => ({ value: account.id, label: `${account.name} (${account.provider})` }))} />
                </Form.Item>
                <Row gutter={16}>
                    <Col span={12}>
                        <Form.Item name="min_instances" label="最小实例数" extra="平时保持的最低机器数量">
                            <InputNumber min={0} max={100} style={{ width: '100%' }} />
                        </Form.Item>
                    </Col>
                    <Col span={12}>
                        <Form.Item name="max_instances" label="最大实例数" extra="硬性上限，防止账单爆炸">
                            <InputNumber min={1} max={500} style={{ width: '100%' }} />
                        </Form.Item>
                    </Col>
                </Row>
                <Row gutter={16}>
                    <Col span={8}>
                        <Form.Item name="scale_up_threshold" label="扩容阈值" extra="队列任务数 > 此值则扩容；填 0 表示有任务就扩容">
                            <InputNumber min={0} style={{ width: '100%' }} />
                        </Form.Item>
                    </Col>
                    <Col span={8}>
                        <Form.Item name="scale_down_threshold" label="缩容阈值" extra="队列任务数 <= 此值则缩容">
                            <InputNumber min={0} style={{ width: '100%' }} />
                        </Form.Item>
                    </Col>
                    <Col span={8}>
                        <Form.Item name="cooldown_seconds" label="冷却时间 (秒)" extra="两次伸缩操作间的最小间隔">
                            <InputNumber min={60} style={{ width: '100%' }} />
                        </Form.Item>
                    </Col>
                </Row>
                <Row gutter={16}>
                    <Col span={12}>
                        <Form.Item name="spot_strategy" label="竞价实例策略">
                            <Select options={[
                                { value: 'NoSpot', label: '按量付费 (不使用竞价)' },
                                { value: 'SpotAsPriceGo', label: '系统自动出价 (推荐)' },
                                { value: 'SpotWithPriceLimit', label: '设置最高限价' },
                            ]} />
                        </Form.Item>
                    </Col>
                    <Col span={12}>
                        <Form.Item name="instance_ttl_minutes" label="TTL 回收 (分钟)" extra="到期优先等待任务空闲，超过 30 分钟宽限仍未空闲才强制释放">
                            <InputNumber min={10} style={{ width: '100%' }} />
                        </Form.Item>
                    </Col>
                </Row>
                <Form.Item noStyle shouldUpdate={(previous, current) => previous?.spot_strategy !== current?.spot_strategy}>
                    {({ getFieldValue }) => {
                        const strategy = getFieldValue('spot_strategy');
                        if (strategy === 'NoSpot') return null;
                        return (
                            <Row gutter={16}>
                                <Col span={12}>
                                    <Form.Item name="spot_duration_hours" label="抢占保留时长 (小时)" extra="0=无保护期(随时可回收)，1-6=保护期内不因库存被回收，推荐 1">
                                        <InputNumber min={0} max={6} style={{ width: '100%' }} />
                                    </Form.Item>
                                </Col>
                                {strategy === 'SpotWithPriceLimit' && (
                                    <Col span={12}>
                                        <Form.Item name="max_spot_price" label="最高竞价限价 (元/小时)" extra="仅在设置最高限价模式时生效">
                                            <InputNumber min={0.01} step={0.01} style={{ width: '100%' }} placeholder="例: 0.5" />
                                        </Form.Item>
                                    </Col>
                                )}
                            </Row>
                        );
                    }}
                </Form.Item>
                <Form.Item label={<span><CodeOutlined /> Cloud-Init (UserData) 注入模板</span>} extra="系统在下发实例时会自动替换 {{.DownloadURL}} {{.ServerAddr}} {{.AgentID}} {{.PSK}} 等模板变量。留空则使用内置默认模板。">
                    <div style={{ height: 350, border: '1px solid #e2e8f0', borderRadius: 8, overflow: 'hidden' }}>
                        <Editor
                            height="100%"
                            language="shell"
                            theme="vs-dark"
                            value={userDataScript}
                            onChange={(value) => onUserDataScriptChange(value || '')}
                            options={{ minimap: { enabled: false }, fontSize: 13 }}
                        />
                    </div>
                </Form.Item>
                <Space>
                    <Button type="primary" onClick={onSubmit}>保存调度策略</Button>
                    {currentPolicyId && (
                        <Popconfirm title="确认删除当前 AutoScaler 策略？" onConfirm={onDelete}>
                            <Button danger icon={<DeleteOutlined />}>删除策略</Button>
                        </Popconfirm>
                    )}
                </Space>
            </Form>
        </ProCard>
    </div>
);
