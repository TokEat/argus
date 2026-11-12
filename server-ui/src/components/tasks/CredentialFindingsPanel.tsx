import { useEffect, useState } from 'react';
import { App, Button, Space, Table, Tag, Typography } from 'antd';
import { EyeOutlined, LockOutlined } from '@ant-design/icons';
import { listTaskCredentialFindings, revealCredentialFinding } from '../../services/api';
import { getCurrentUserRole } from '../../utils/auth';

const { Text } = Typography;

export default function CredentialFindingsPanel({ taskId }: { taskId: string }) {
    const { message, modal } = App.useApp();
    const [items, setItems] = useState<API.CredentialFinding[]>([]);
    const [loading, setLoading] = useState(false);
    const isAdmin = getCurrentUserRole() === 'admin';

    useEffect(() => {
        if (!taskId) return;
        setLoading(true);
        listTaskCredentialFindings(taskId).then(setItems).catch(() => setItems([])).finally(() => setLoading(false));
    }, [taskId]);

    const reveal = async (finding: API.CredentialFinding) => {
        try {
            const secret = await revealCredentialFinding(finding.id);
            modal.confirm({
                title: '已审计揭示凭据', icon: <LockOutlined />, okText: '关闭', cancelButtonProps: { style: { display: 'none' } },
                content: <Space direction="vertical"><Text>用户名：<Text code copyable>{secret.username}</Text></Text><Text>密码：<Text code copyable>{secret.password}</Text></Text><Text type="secondary">本次揭示已写入审计记录，请按最小权限使用。</Text></Space>,
            });
        } catch (error) { message.error(typeof error === 'string' ? error : '凭据揭示失败'); }
    };

    if (!loading && items.length === 0) return null;
    return (
        <>
            <Typography.Title level={5}><LockOutlined /> 弱口令命中</Typography.Title>
            <Table size="small" loading={loading} rowKey="id" dataSource={items} pagination={false} columns={[
                { title: '目标', dataIndex: 'endpoint' },
                { title: '服务', dataIndex: 'service', render: (value: string) => <Tag>{value}</Tag> },
                { title: '插件', dataIndex: 'plugin' },
                { title: '用户名', dataIndex: 'masked_username', render: (value: string) => <Text code>{value}</Text> },
                { title: '密码', render: () => <Text code>••••••••</Text> },
                { title: '操作', width: 110, render: (_, row) => isAdmin ? <Button size="small" icon={<EyeOutlined />} onClick={() => reveal(row)}>审计揭示</Button> : <Text type="secondary">仅 Admin 可揭示</Text> },
            ]} />
        </>
    );
}
