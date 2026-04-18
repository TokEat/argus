import React, { useState, useEffect } from 'react';
import { Outlet, useNavigate, useLocation, Link } from 'react-router-dom';
import { Layout, Menu, Avatar, Dropdown, Space, Typography, ConfigProvider, theme, message } from 'antd';
import type { MenuProps } from 'antd';
import {
    MenuFoldOutlined,
    MenuUnfoldOutlined,
    UserOutlined,
    LogoutOutlined,
} from '@ant-design/icons';
import type { RouteConfig } from '../routes';
import { menuRoutes } from '../routes';

const { Header, Sider, Content } = Layout;
const { Text } = Typography;

const BasicLayout: React.FC = () => {
    const [collapsed, setCollapsed] = useState(false);
    const [tenantId, setTenantId] = useState('default');
    const navigate = useNavigate();
    const location = useLocation();

    useEffect(() => {
        const token = localStorage.getItem('token');
        if (!token) {
            navigate('/login');
            return;
        }
        const tid = localStorage.getItem('tenant_id') || 'default';
        setTenantId(tid);
    }, [navigate]);

    const handleLogout = () => {
        localStorage.removeItem('token');
        localStorage.removeItem('tenant_id');
        message.success('已退出登录');
        navigate('/login');
    };

    const userMenuItems: MenuProps['items'] = [
        {
            key: 'tenant',
            icon: <UserOutlined />,
            label: `租户: ${tenantId}`,
            disabled: true,
        },
        { type: 'divider' },
        {
            key: 'logout',
            icon: <LogoutOutlined />,
            label: '退出登录',
            onClick: handleLogout,
        },
    ];

    // Convert RouteConfig to Menu items
    const getMenuItems = (routes: RouteConfig[]): MenuProps['items'] => {
        return routes
            .filter((route) => !route.hideInMenu)
            .map((route) => {
                if (route.children) {
                    return {
                        key: route.path,
                        icon: route.icon,
                        label: route.name,
                        children: getMenuItems(route.children),
                    };
                }
                return {
                    key: route.path,
                    icon: route.icon,
                    label: <Link to={route.path}>{route.name}</Link>,
                };
            });
    };

    // Find selected keys based on current path
    const getSelectedKeys = (): string[] => {
        const pathname = location.pathname;
        if (pathname.startsWith('/config')) return ['/config/poc'];
        const exactMatch = menuRoutes.find((r) => r.path === pathname);
        if (exactMatch) return [pathname];

        for (const route of menuRoutes) {
            if (route.children) {
                const child = route.children.find((c) => pathname.startsWith(c.path));
                if (child) return [child.path];
            }
            if (pathname.startsWith(route.path)) return [route.path];
        }
        return ['/dashboard'];
    };

    // Find open keys for submenus
    const getOpenKeys = (): string[] => {
        const pathname = location.pathname;
        for (const route of menuRoutes) {
            if (route.children) {
                const child = route.children.find((c) => pathname.startsWith(c.path));
                if (child) return [route.path];
            }
        }
        return [];
    };

    return (
        <ConfigProvider
            theme={{
                algorithm: theme.defaultAlgorithm,
                token: {
                    colorPrimary: '#0ea5e9',
                    borderRadius: 8,
                    colorBgContainer: '#ffffff',
                    colorBgElevated: '#ffffff',
                    colorBgLayout: '#f8fafc',
                    colorBorder: '#e2e8f0',
                    colorText: '#1e293b',
                    colorTextSecondary: '#64748b',
                    fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif",
                },
                components: {
                    Menu: {
                        itemBg: 'transparent',
                        itemSelectedBg: '#e0f2fe',
                        itemSelectedColor: '#0284c7',
                        itemHoverBg: '#f1f5f9',
                        subMenuItemBg: 'transparent',
                    },
                    Button: {
                        primaryShadow: '0 4px 14px 0 rgba(14, 165, 233, 0.25)',
                    },
                    Card: {
                        boxShadow: '0 1px 3px 0 rgba(0, 0, 0, 0.04), 0 1px 2px -1px rgba(0, 0, 0, 0.04)',
                    },
                },
            }}
        >
            <Layout style={{ minHeight: '100vh' }}>
                <Sider
                    trigger={null}
                    collapsible
                    collapsed={collapsed}
                    width={240}
                    style={{
                        background: '#ffffff',
                        borderRight: '1px solid #e2e8f0',
                        overflow: 'auto',
                        height: '100vh',
                        position: 'fixed',
                        left: 0,
                        top: 0,
                        bottom: 0,
                        zIndex: 100,
                        boxShadow: '1px 0 3px rgba(0, 0, 0, 0.02)',
                    }}
                >
                    <div
                        style={{
                            height: 64,
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: collapsed ? 'center' : 'flex-start',
                            padding: collapsed ? 0 : '0 24px',
                            borderBottom: '1px solid #e2e8f0',
                            background: '#ffffff',
                        }}
                    >
                        {!collapsed && (
                            <Text
                                strong
                                style={{
                                    fontSize: 17,
                                    color: '#0f172a',
                                    whiteSpace: 'nowrap',
                                    fontWeight: 600,
                                    letterSpacing: '-0.3px',
                                }}
                            >
                                Argus
                            </Text>
                        )}
                    </div>

                    <Menu
                        mode="inline"
                        selectedKeys={getSelectedKeys()}
                        defaultOpenKeys={getOpenKeys()}
                        items={getMenuItems(menuRoutes)}
                        style={{
                            background: 'transparent',
                            borderRight: 0,
                            marginTop: 8,
                            padding: '0 8px',
                        }}
                    />
                </Sider>

                <Layout style={{ marginLeft: collapsed ? 80 : 240, transition: 'margin-left 0.2s' }}>
                    <Header
                        style={{
                            padding: '0 24px',
                            background: '#ffffff',
                            borderBottom: '1px solid #e2e8f0',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            position: 'sticky',
                            top: 0,
                            zIndex: 99,
                            boxShadow: '0 1px 2px rgba(0, 0, 0, 0.02)',
                        }}
                    >
                        <div
                            onClick={() => setCollapsed(!collapsed)}
                            style={{
                                cursor: 'pointer',
                                fontSize: 18,
                                padding: '8px 12px',
                                borderRadius: 8,
                                transition: 'background 0.2s',
                                color: '#64748b',
                            }}
                            onMouseEnter={(e) => (e.currentTarget.style.background = '#f1f5f9')}
                            onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                        >
                            {collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />}
                        </div>

                        <Dropdown menu={{ items: userMenuItems }} placement="bottomRight">
                            <Space style={{ cursor: 'pointer' }}>
                                <Avatar
                                    size={36}
                                    style={{
                                        background: 'linear-gradient(135deg, #0ea5e9 0%, #06b6d4 100%)',
                                    }}
                                    icon={<UserOutlined />}
                                />
                                <Text style={{ color: '#1e293b', fontWeight: 500 }}>
                                    {tenantId}
                                </Text>
                            </Space>
                        </Dropdown>
                    </Header>

                    <Content
                        style={{
                            margin: 24,
                            minHeight: 280,
                        }}
                    >
                        <div className="page-container">
                            <Outlet />
                        </div>
                    </Content>
                </Layout>
            </Layout>
        </ConfigProvider>
    );
};

export default BasicLayout;
