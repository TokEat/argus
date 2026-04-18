import React from 'react';
import { Result, Typography } from 'antd';
import { CloudOutlined } from '@ant-design/icons';

const { Text } = Typography;

const CloudManagement: React.FC = () => {
    return (
        <div style={{
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            minHeight: '60vh',
        }}>
            <Result
                icon={<CloudOutlined style={{ color: '#94a3b8', fontSize: 64 }} />}
                title={<span style={{ color: '#1e293b' }}>实例配置</span>}
                subTitle={
                    <Text style={{ color: '#94a3b8' }}>
                        云实例管理功能正在开发中，敬请期待…
                    </Text>
                }
            />
        </div>
    );
};

export default CloudManagement;
