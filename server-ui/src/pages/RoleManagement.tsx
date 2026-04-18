import React from 'react';
import { Result, Typography } from 'antd';
import { SafetyOutlined } from '@ant-design/icons';

const { Text } = Typography;

const RoleManagement: React.FC = () => {
    return (
        <div style={{
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            minHeight: '60vh',
        }}>
            <Result
                icon={<SafetyOutlined style={{ color: '#94a3b8', fontSize: 64 }} />}
                title={<span style={{ color: '#1e293b' }}>角色管理</span>}
                subTitle={
                    <Text style={{ color: '#94a3b8' }}>
                        角色权限管理功能正在开发中，敬请期待…
                    </Text>
                }
            />
        </div>
    );
};

export default RoleManagement;
