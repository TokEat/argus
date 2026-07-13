import { CheckCircleOutlined, SearchOutlined } from '@ant-design/icons';
import { Alert, Button, Form, Input, Modal, Select, Spin, Typography } from 'antd';
import type { FormInstance } from 'antd';

const { Text } = Typography;

interface AddCloudAccountModalProps {
    open: boolean;
    form: FormInstance;
    isAdmin: boolean;
    users: API.User[];
    onSubmit: () => void;
    onCancel: () => void;
    onLoadUsers: () => void;
}

export const AddCloudAccountModal = ({ open, form, isAdmin, users, onSubmit, onCancel, onLoadUsers }: AddCloudAccountModalProps) => (
    <Modal title="添加云服务凭证 (AK/SK)" open={open} onOk={onSubmit} onCancel={onCancel} okText="安全保存" cancelText="取消">
        <Form form={form} layout="vertical" style={{ marginTop: 16 }}>
            <Form.Item name="provider" label="提供商" initialValue="aliyun" rules={[{ required: true }]}>
                <Select options={[
                    { value: 'aliyun', label: '阿里云 ECS' },
                    { value: 'aws', label: 'AWS EC2' },
                    { value: 'tencent', label: '腾讯云 CVM' },
                ]} />
            </Form.Item>
            <Form.Item name="name" label="凭证别名" rules={[{ required: true }]}>
                <Input placeholder="例如：阿里云生产环境主账号" />
            </Form.Item>
            <Form.Item name="access_key_id" label="Access Key ID" rules={[{ required: true }]}>
                <Input placeholder="输入 AK" />
            </Form.Item>
            <Form.Item name="access_key_secret" label="Access Key Secret" rules={[{ required: true }]}>
                <Input.Password placeholder="输入 SK" />
            </Form.Item>
            <Form.Item name="region" label="地域 (Region)" extra="可选，弹性扩缩时需要指定。不填则在一键配置时自动选择。">
                <Input placeholder="可选，如 cn-shanghai、cn-hangzhou" />
            </Form.Item>
            <Form.Item label="默认云主机硬件配置" style={{ marginBottom: 4 }} extra="选填，如果留空将使用云厂商 API 的默认值">
                <Input.Group compact style={{ display: 'flex', gap: 8 }}>
                    <Form.Item name="default_instance_type" noStyle><Input placeholder="实例规格 (如 ecs.c6.large)" style={{ flex: 1 }} /></Form.Item>
                    <Form.Item name="default_image_id" noStyle><Input placeholder="系统镜像 ID (如 ubuntu_22_04)" style={{ flex: 1 }} /></Form.Item>
                </Input.Group>
            </Form.Item>
            <Form.Item label="网络与安全配置" style={{ marginBottom: 4 }}>
                <Input.Group compact style={{ display: 'flex', gap: 8 }}>
                    <Form.Item name="default_security_group" noStyle><Input placeholder="安全组 ID" style={{ flex: 1 }} /></Form.Item>
                    <Form.Item name="default_v_switch" noStyle><Input placeholder="虚拟交换机 ID" style={{ flex: 1 }} /></Form.Item>
                </Input.Group>
            </Form.Item>
            <Form.Item label="OSS 配置（可选，用于 Agent 二进制分发）" style={{ marginBottom: 4 }}>
                <Input.Group compact style={{ display: 'flex', gap: 8 }}>
                    <Form.Item name="oss_bucket" noStyle><Input placeholder="Bucket 名称，如 argus-release" style={{ flex: 1 }} /></Form.Item>
                    <Form.Item name="oss_endpoint" noStyle><Input placeholder="Endpoint，如 oss-cn-shanghai-internal.aliyuncs.com" style={{ flex: 2 }} /></Form.Item>
                </Input.Group>
            </Form.Item>
            {isAdmin && (
                <Form.Item name="bound_user_ids" label="同时绑定给用户" extra="凭证会自动绑定给创建者；这里可额外授权给当前租户的管理员或操作员。">
                    <Select
                        mode="multiple"
                        placeholder="选择可使用此 AK/SK 的用户"
                        options={users.map(user => ({ value: String(user.id), label: `${user.username} (${user.role})` }))}
                        onDropdownVisibleChange={(visible) => {
                            if (visible && users.length === 0) onLoadUsers();
                        }}
                    />
                </Form.Item>
            )}
        </Form>
    </Modal>
);

interface CloudAccountBindingModalProps {
    open: boolean;
    account: API.CloudAccount | null;
    userIds: string[];
    users: API.User[];
    saving: boolean;
    onChange: (userIds: string[]) => void;
    onSubmit: () => void;
    onCancel: () => void;
}

export const CloudAccountBindingModal = ({ open, account, userIds, users, saving, onChange, onSubmit, onCancel }: CloudAccountBindingModalProps) => (
    <Modal
        title={account ? `绑定用户 - ${account.name}` : '绑定用户'}
        open={open}
        onOk={onSubmit}
        onCancel={onCancel}
        confirmLoading={saving}
        okText="保存绑定"
        cancelText="取消"
    >
        <Alert
            message="绑定后的用户可以完整使用该 AK/SK 进行云资源与 OSS 操作；凭证基础配置仍只能由管理员或凭证所有者修改。"
            type="info"
            showIcon
            style={{ marginBottom: 16 }}
        />
        <Select
            mode="multiple"
            style={{ width: '100%' }}
            value={userIds}
            onChange={onChange}
            placeholder="选择可使用此 AK/SK 的用户"
            options={users.map(user => ({ value: String(user.id), label: `${user.username} (${user.role})` }))}
        />
    </Modal>
);

interface CloudDiscoveryModalProps {
    open: boolean;
    loading: boolean;
    saving: boolean;
    data: any;
    form: FormInstance;
    onSubmit: () => void;
    onCancel: () => void;
}

export const CloudDiscoveryModal = ({ open, loading, saving, data, form, onSubmit, onCancel }: CloudDiscoveryModalProps) => (
    <Modal
        title={<><SearchOutlined /> 云资源自动探测</>}
        open={open}
        onCancel={onCancel}
        footer={data ? [
            <Button key="cancel" onClick={onCancel}>取消</Button>,
            <Button key="save" type="primary" loading={saving} onClick={onSubmit} icon={<CheckCircleOutlined />}>保存配置</Button>,
        ] : null}
        width={720}
        destroyOnClose
    >
        {loading ? (
            <div style={{ textAlign: 'center', padding: '60px 0' }}>
                <Spin size="large" />
                <div style={{ marginTop: 16 }}><Text type="secondary">正在通过 AK/SK 查询云资源...</Text></div>
            </div>
        ) : data ? (
            <Form form={form} layout="vertical">
                <Alert message="以下资源已通过你的 AK/SK 从云厂商 API 自动获取，请在每一项中选择合适的值后保存。" type="info" showIcon style={{ marginBottom: 20 }} />
                <Form.Item name="default_instance_type" label={`实例规格 (发现 ${data.instance_types?.length || 0} 个)`} rules={[{ required: true, message: '请选择实例规格' }]}>
                    <Select placeholder="选择实例规格" showSearch optionFilterProp="label" options={(data.instance_types || []).map((item: any) => ({ value: item.id, label: `${item.id}  —  ${item.cpu}核 ${item.memory_gb}GB  (${item.family})` }))} />
                </Form.Item>
                <Form.Item name="default_image_id" label={`系统镜像 (发现 ${data.images?.length || 0} 个)`} rules={[{ required: true, message: '请选择系统镜像' }]}>
                    <Select placeholder="选择系统镜像" showSearch optionFilterProp="label" options={(data.images || []).map((item: any) => ({ value: item.id, label: `${item.name}  —  ${item.desc}` }))} />
                </Form.Item>
                <Form.Item name="default_security_group" label={`安全组 (发现 ${data.security_groups?.length || 0} 个)`} rules={[{ required: true, message: '请选择安全组' }]}>
                    <Select placeholder="选择安全组" showSearch optionFilterProp="label" options={(data.security_groups || []).map((item: any) => ({ value: item.id, label: `${item.id}  —  ${item.name || '(无名称)'}  ${item.desc}` }))} />
                </Form.Item>
                <Form.Item name="default_v_switch" label={`虚拟交换机 (发现 ${data.v_switches?.length || 0} 个)`} rules={[{ required: true, message: '请选择交换机' }]}>
                    <Select placeholder="选择交换机" showSearch optionFilterProp="label" options={(data.v_switches || []).map((item: any) => ({ value: item.id, label: `${item.id}  —  ${item.name || '(无名称)'}  ${item.desc}` }))} />
                </Form.Item>
            </Form>
        ) : (
            <div style={{ textAlign: 'center', padding: '40px 0', color: '#94a3b8' }}>
                <Text type="secondary">探测失败，请检查 AK/SK 权限是否包含 ECS 读取权限。</Text>
            </div>
        )}
    </Modal>
);
