import React from 'react';
import { Result, Typography } from 'antd';
import { ApiOutlined } from '@ant-design/icons';

const { Text } = Typography;

const McpConfig: React.FC = () => {
    return (
        <div style={{
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            minHeight: '60vh',
        }}>
            <Result
                icon={<ApiOutlined style={{ color: '#94a3b8', fontSize: 64 }} />}
                title={<span style={{ color: '#1e293b' }}>MCP 配置</span>}
                subTitle={
                    <Text style={{ color: '#94a3b8' }}>
                        MCP API Key 管理功能正在开发中，敬请期待…
                    </Text>
                }
            />
        </div>
    );
};

export default McpConfig;
