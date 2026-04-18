import React from 'react';
import { Result, Typography } from 'antd';
import { BuildOutlined } from '@ant-design/icons';

const { Text } = Typography;

const ClientBuild: React.FC = () => {
    return (
        <div style={{
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            minHeight: '60vh',
        }}>
            <Result
                icon={<BuildOutlined style={{ color: '#94a3b8', fontSize: 64 }} />}
                title={<span style={{ color: '#1e293b' }}>客户端生成</span>}
                subTitle={
                    <Text style={{ color: '#94a3b8' }}>
                        客户端交叉编译功能正在开发中，敬请期待…
                    </Text>
                }
            />
        </div>
    );
};

export default ClientBuild;
