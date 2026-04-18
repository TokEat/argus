import React from 'react';
import { Result, Typography } from 'antd';
import { TeamOutlined } from '@ant-design/icons';

const { Text } = Typography;

const UserManagement: React.FC = () => {
    return (
        <div style={{
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            minHeight: '60vh',
        }}>
            <Result
                icon={<TeamOutlined style={{ color: '#94a3b8', fontSize: 64 }} />}
                title={<span style={{ color: '#1e293b' }}>用户管理</span>}
                subTitle={
                    <Text style={{ color: '#94a3b8' }}>
                        多用户管理与 RBAC 权限控制功能正在开发中，敬请期待…
                    </Text>
                }
            />
        </div>
    );
};

export default UserManagement;
