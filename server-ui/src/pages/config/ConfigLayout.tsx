import React from 'react';
import { Tabs } from 'antd';
import {
    BugOutlined,
    ScanOutlined,
    ApartmentOutlined,
    FolderOpenOutlined,
} from '@ant-design/icons';
import { useNavigate, useLocation } from 'react-router-dom';



interface ConfigLayoutProps {
    children: React.ReactNode;
}

const ConfigLayout: React.FC<ConfigLayoutProps> = ({ children }) => {
    const navigate = useNavigate();
    const location = useLocation();

    const tabItems = [
        { key: '/config/workflow', label: 'Workflow 编排', icon: <ApartmentOutlined /> },
        { key: '/config/poc', label: 'POC 弹药库', icon: <BugOutlined /> },
        { key: '/config/active-finger', label: '指纹弹药库', icon: <ScanOutlined /> },
        { key: '/config/dir', label: 'Dir 探测规则', icon: <FolderOpenOutlined /> },
    ];

    return (
        <div>
            <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                marginBottom: 16,
            }}>
                <Tabs
                    activeKey={location.pathname}
                    onChange={(key) => navigate(key)}
                    items={tabItems.map((item) => ({
                        key: item.key,
                        label: (
                            <span>
                                {item.icon}
                                <span style={{ marginLeft: 6 }}>{item.label}</span>
                            </span>
                        ),
                    }))}
                    style={{ marginBottom: 0 }}
                    tabBarStyle={{ marginBottom: 0 }}
                />
            </div>
            {children}
        </div>
    );
};

export default ConfigLayout;
