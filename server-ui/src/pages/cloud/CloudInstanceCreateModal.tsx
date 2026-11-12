import { CheckCircleOutlined, SettingOutlined, ThunderboltOutlined } from '@ant-design/icons';
import { Alert, Col, Descriptions, Form, InputNumber, Modal, Row, Select, Space, Spin, Tag, Typography } from 'antd';
import type { FormInstance } from 'antd';

const { Text } = Typography;

interface InstanceType {
    id: string;
    cpu: number;
    memory_gb: number;
    family: string;
    status: string;
}

interface CloudInstanceCreateModalProps {
    open: boolean;
    form: FormInstance;
    accounts: API.CloudAccount[];
    policies: API.CloudScalingPolicy[];
    region: string;
    regions: { region_id: string; local_name: string; endpoint: string }[];
    regionsLoading: boolean;
    availableTypes: InstanceType[];
    typesLoading: boolean;
    selectedInstanceType: string;
    priceData: any;
    priceLoading: boolean;
    onSubmit: () => void;
    onCancel: () => void;
    onAccountChange: (accountId?: string) => void;
    onRegionChange: (region: string) => void;
    onInstanceTypeChange: (instanceType: string) => void;
}

export const CloudInstanceCreateModal = ({
    open,
    form,
    accounts,
    policies,
    region,
    regions,
    regionsLoading,
    availableTypes,
    typesLoading,
    selectedInstanceType,
    priceData,
    priceLoading,
    onSubmit,
    onCancel,
    onAccountChange,
    onRegionChange,
    onInstanceTypeChange,
}: CloudInstanceCreateModalProps) => (
    <Modal
        title={<><ThunderboltOutlined style={{ marginRight: 8, color: '#f59e0b' }} />手动弹性扩容</>}
        open={open}
        onOk={onSubmit}
        onCancel={onCancel}
        okText="确认创建"
        cancelText="取消"
        width={640}
        okButtonProps={{ disabled: accounts.length === 0 }}
    >
        <Form form={form} layout="vertical" style={{ marginTop: 8 }} initialValues={{ count: 1 }}>
            <Alert
                message="手动扩容将绕过 AutoScaler 冷却限制，直接向云厂商发起实例创建请求"
                description="实例创建后将自动注入 Cloud-Init 脚本，下载并启动 Agent。请确保凭证已正确配置硬件规格和网络参数。"
                type="warning"
                showIcon
                style={{ marginBottom: 16 }}
            />
            {accounts.length === 0 ? (
                <Alert message="暂无可用云凭证，请先在「API 凭证管理」中添加并配置凭证。" type="info" showIcon style={{ marginBottom: 16 }} />
            ) : (
                <>
                    <Row gutter={16}>
                        <Col span={16}>
                            <Form.Item name="account_id" label="云凭证" rules={[{ required: true, message: '请选择云凭证' }]}>
                                <Select
                                    placeholder="选择调用凭证"
                                    options={accounts.map(account => ({
                                        value: account.id,
                                        label: (
                                            <Space>
                                                <span>{account.name}</span>
                                                {account.region && account.default_instance_type && account.default_image_id
                                                    ? <Tag color="success" style={{ fontSize: 10, lineHeight: '16px' }}>配置就绪</Tag>
                                                    : <Tag color="warning" style={{ fontSize: 10, lineHeight: '16px' }}>配置不完整</Tag>}
                                            </Space>
                                        ),
                                    }))}
                                    onChange={(accountId) => {
                                        form.validateFields(['account_id']);
                                        onAccountChange(accountId);
                                    }}
                                />
                            </Form.Item>
                        </Col>
                        <Col span={8}>
                            <Form.Item name="count" label="创建数量" rules={[{ required: true, message: '请输入数量' }]}>
                                <InputNumber min={1} max={10} style={{ width: '100%' }} addonAfter="台" />
                            </Form.Item>
                        </Col>
                    </Row>
                    {form.getFieldValue('account_id') && (
                        <Form.Item label="地域" style={{ marginBottom: 12 }}>
                            <Select
                                loading={regionsLoading}
                                value={region || undefined}
                                placeholder="选择目标地域"
                                showSearch
                                optionFilterProp="label"
                                onChange={onRegionChange}
                                options={regions.map(item => ({
                                    value: item.region_id,
                                    label: `${item.region_id}  ${item.local_name ? `(${item.local_name})` : ''}`,
                                }))}
                                style={{ width: '100%' }}
                            />
                        </Form.Item>
                    )}
                    <Form.Item noStyle shouldUpdate={(previous, current) => previous.account_id !== current.account_id || previous.count !== current.count}>
                        {({ getFieldValue }) => {
                            const accountId = getFieldValue('account_id');
                            const count = getFieldValue('count') || 1;
                            const account = accounts.find(item => item.id === accountId);
                            if (!account) return null;
                            const configReady = Boolean(account.region && account.default_instance_type && account.default_image_id);
                            const ossReady = Boolean(account.oss_bucket && account.oss_endpoint);
                            const linkedPolicy = policies.find(policy => policy.cloud_account_id === accountId);

                            return (
                                <div style={{ background: '#f8fafc', borderRadius: 10, padding: '16px 20px', border: '1px solid #e2e8f0' }}>
                                    <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
                                        <SettingOutlined style={{ color: '#0ea5e9' }} />
                                        实例创建参数预览
                                        {!configReady && <Tag color="error" style={{ fontSize: 10 }}>配置不完整，请先完成一键配置</Tag>}
                                    </div>
                                    <Descriptions
                                        size="small"
                                        column={2}
                                        bordered
                                        labelStyle={{ width: 100, fontWeight: 500, background: '#fff', fontSize: 12 }}
                                        contentStyle={{ fontSize: 12, fontFamily: 'monospace' }}
                                    >
                                        <Descriptions.Item label="地域">
                                            {region ? <Tag color="green">{region}</Tag> : <Tag color="red">未选择</Tag>}
                                        </Descriptions.Item>
                                        <Descriptions.Item label="提供商">
                                            <Tag color="blue">{account.provider === 'aliyun' ? '阿里云 ECS' : account.provider === 'aws' ? 'AWS EC2' : account.provider}</Tag>
                                        </Descriptions.Item>
                                        <Descriptions.Item label="实例规格" span={2}>
                                            {typesLoading ? (
                                                <Spin size="small" />
                                            ) : availableTypes.length > 0 ? (
                                                <Select
                                                    size="small"
                                                    style={{ width: '100%' }}
                                                    value={selectedInstanceType}
                                                    onChange={onInstanceTypeChange}
                                                    showSearch
                                                    optionFilterProp="label"
                                                    options={availableTypes.map(item => ({
                                                        value: item.id,
                                                        label: `${item.id}  (${item.cpu}核 / ${item.memory_gb}G)${item.status === 'ClosedWithStock' ? ' · 限量' : ''}`,
                                                    }))}
                                                    optionRender={(option) => {
                                                        const item = availableTypes.find(type => type.id === option.value);
                                                        return (
                                                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                                                <span style={{ fontFamily: 'monospace', fontSize: 12 }}>{item?.id}</span>
                                                                <span style={{ fontSize: 11, color: '#64748b' }}>
                                                                    {item?.cpu}核 / {item?.memory_gb}G
                                                                    {item?.status === 'ClosedWithStock' && <Tag color="orange" style={{ marginLeft: 4, fontSize: 10 }}>限量</Tag>}
                                                                </span>
                                                            </div>
                                                        );
                                                    }}
                                                />
                                            ) : (
                                                <Text style={{ fontSize: 12 }}>{account.default_instance_type || <Tag color="red">未配置</Tag>}</Text>
                                            )}
                                        </Descriptions.Item>
                                        <Descriptions.Item label="系统镜像">
                                            {account.default_image_id
                                                ? <Text style={{ fontSize: 12 }}>{account.default_image_id.length > 20 ? `${account.default_image_id.slice(0, 20)}...` : account.default_image_id}</Text>
                                                : <Tag color="red">未配置</Tag>}
                                        </Descriptions.Item>
                                        <Descriptions.Item label="安全组">
                                            {account.default_security_group ? <Text style={{ fontSize: 12 }}>{account.default_security_group}</Text> : <Tag color="orange">未配置</Tag>}
                                        </Descriptions.Item>
                                        <Descriptions.Item label="交换机">
                                            {account.default_v_switch ? <Text style={{ fontSize: 12 }}>{account.default_v_switch}</Text> : <Tag color="orange">未配置</Tag>}
                                        </Descriptions.Item>
                                    </Descriptions>
                                    <div style={{ marginTop: 12, display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                                        <div style={{ flex: 1, minWidth: 160, background: priceData ? 'linear-gradient(135deg, #f0fdf4 0%, #ecfdf5 100%)' : '#fff', borderRadius: 8, padding: '12px 16px', border: '1px solid #e2e8f0' }}>
                                            <div style={{ fontSize: 11, color: '#64748b', marginBottom: 4 }}>单台小时价</div>
                                            {priceLoading ? <Spin size="small" /> : priceData ? (
                                                <div>
                                                    <div style={{ fontSize: 20, fontWeight: 700, color: '#059669' }}>
                                                        ¥{(priceData.spot_price > 0 ? priceData.spot_price : priceData.total_hourly).toFixed(3)}
                                                        <span style={{ fontSize: 11, fontWeight: 400, color: '#94a3b8' }}>/h</span>
                                                    </div>
                                                    {priceData.spot_price > 0 && priceData.spot_discount > 0 && (
                                                        <div style={{ fontSize: 11, color: '#f59e0b', marginTop: 2 }}>
                                                            原价 ¥{priceData.instance_price.toFixed(3)}/h · 节省 {priceData.spot_discount.toFixed(0)}%
                                                        </div>
                                                    )}
                                                </div>
                                            ) : <div style={{ fontSize: 13, color: '#94a3b8' }}>选择凭证后加载</div>}
                                        </div>
                                        <div style={{ flex: 1, minWidth: 160, background: priceData ? 'linear-gradient(135deg, #eff6ff 0%, #eef2ff 100%)' : '#fff', borderRadius: 8, padding: '12px 16px', border: '1px solid #e2e8f0' }}>
                                            <div style={{ fontSize: 11, color: '#64748b', marginBottom: 4 }}>{count} 台 · {linkedPolicy ? `${linkedPolicy.instance_ttl_minutes} 分钟` : '1 小时'} 预估</div>
                                            {priceLoading ? <Spin size="small" /> : priceData ? (
                                                <div style={{ fontSize: 20, fontWeight: 700, color: '#2563eb' }}>
                                                    ¥{((priceData.spot_price > 0 ? priceData.spot_price : priceData.total_hourly) * count * (linkedPolicy ? linkedPolicy.instance_ttl_minutes / 60 : 1)).toFixed(2)}
                                                </div>
                                            ) : <div style={{ fontSize: 13, color: '#94a3b8' }}>--</div>}
                                        </div>
                                        <div style={{ flex: 1, minWidth: 160, background: '#fff', borderRadius: 8, padding: '12px 16px', border: '1px solid #e2e8f0' }}>
                                            <div style={{ fontSize: 11, color: '#64748b', marginBottom: 4 }}>竞价策略</div>
                                            <div style={{ fontSize: 14, fontWeight: 600 }}>
                                                {linkedPolicy ? (
                                                    <Tag color={linkedPolicy.spot_strategy === 'SpotAsPriceGo' ? 'orange' : linkedPolicy.spot_strategy === 'SpotWithPriceLimit' ? 'volcano' : 'blue'}>
                                                        {linkedPolicy.spot_strategy === 'SpotAsPriceGo' ? '竞价（跟随市价）' : linkedPolicy.spot_strategy === 'SpotWithPriceLimit' ? `竞价限价 ¥${linkedPolicy.max_spot_price}/h` : '按量付费'}
                                                    </Tag>
                                                ) : <Tag color="orange">抢占式（默认）</Tag>}
                                            </div>
                                        </div>
                                        <div style={{ flex: 1, minWidth: 160, background: '#fff', borderRadius: 8, padding: '12px 16px', border: '1px solid #e2e8f0' }}>
                                            <div style={{ fontSize: 11, color: '#64748b', marginBottom: 4 }}>Agent 分发</div>
                                            <div style={{ fontSize: 14, fontWeight: 600 }}>
                                                {ossReady ? <Tag color="success">OSS 内网高速</Tag> : <Tag color="warning">HTTP Fallback</Tag>}
                                            </div>
                                        </div>
                                    </div>
                                    {linkedPolicy ? (
                                        <div style={{ marginTop: 10, padding: '6px 12px', background: '#eff6ff', borderRadius: 6, fontSize: 12, color: '#3b82f6' }}>
                                            <CheckCircleOutlined style={{ marginRight: 4 }} />
                                            实例将在 {linkedPolicy.instance_ttl_minutes} 分钟后进入回收窗口，忙碌时最多宽限 30 分钟（策略: {linkedPolicy.name}）
                                        </div>
                                    ) : (
                                        <Alert message="该凭证尚未绑定调度策略，创建实例可能失败。请先在「引擎调度 & 开关」中配置策略。" type="error" showIcon style={{ marginTop: 10, fontSize: 12 }} />
                                    )}
                                </div>
                            );
                        }}
                    </Form.Item>
                </>
            )}
        </Form>
    </Modal>
);
