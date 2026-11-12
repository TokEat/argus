import { Alert, Button, List, Modal, Space, Tag, Typography } from 'antd';

interface Props {
    conflict: API.CloudAccountPolicyConflict | null;
    accountName?: string;
    openingPolicyId: string | null;
    onClose: () => void;
    onOpenPolicy: (policyId: string) => void;
    onOpenPolicies: () => void;
}

export const CloudAccountDeleteBlockedModal = ({ conflict, accountName, openingPolicyId, onClose, onOpenPolicy, onOpenPolicies }: Props) => (
    <Modal
        title="凭证删除受阻"
        open={Boolean(conflict)}
        onCancel={onClose}
        closable={openingPolicyId === null}
        maskClosable={openingPolicyId === null}
        keyboard={openingPolicyId === null}
        width={600}
        footer={<Space><Button disabled={openingPolicyId !== null} onClick={onClose}>关闭</Button><Button disabled={openingPolicyId !== null} onClick={onOpenPolicies}>查看策略页</Button></Space>}
    >
        {conflict && <>
            <Alert
                type="warning"
                showIcon
                message={`凭证「${accountName || conflict.cloud_account_id}」仍关联 ${conflict.policy_count} 条伸缩策略`}
                description="停用策略不等于解除凭证关联。请先查看并按需处理关联策略，再返回凭证页重新尝试删除。"
            />
            <List
                style={{ maxHeight: 320, overflowY: 'auto', marginTop: 12 }}
                dataSource={conflict.policies}
                rowKey="id"
                locale={{ emptyText: '关联策略可能已变化，请关闭提示后重新尝试删除。' }}
                renderItem={policy => <List.Item actions={[
                    <Button key="view" type="link" aria-label={`查看策略 ${policy.name}`} loading={openingPolicyId === policy.id} disabled={openingPolicyId !== null} onClick={() => onOpenPolicy(policy.id)}>查看策略</Button>,
                ]}>
                    <Space wrap>
                        <Typography.Text>{policy.name}</Typography.Text>
                        <Tag color={policy.enabled ? 'green' : 'default'}>{policy.enabled ? '已启用' : '已停用'}</Tag>
                    </Space>
                </List.Item>}
            />
            {conflict.policies_truncated && <Typography.Paragraph type="secondary">
                当前仅显示前 {conflict.policies.length} 条，其余关联策略请在 AutoScaler 策略页核对绑定的云凭证。
            </Typography.Paragraph>}
        </>}
    </Modal>
);
