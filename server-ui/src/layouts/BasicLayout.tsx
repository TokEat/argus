import React, { useState, useEffect, useMemo, useRef } from 'react';
import { Outlet, useNavigate, useLocation, Link } from 'react-router-dom';
import { Layout, Menu, Avatar, Dropdown, Space, Typography, ConfigProvider, theme, message, Select } from 'antd';
import type { MenuProps } from 'antd';
import Draggable from 'react-draggable';
import {
    MenuFoldOutlined,
    MenuUnfoldOutlined,
    UserOutlined,
    LogoutOutlined,
    ProjectOutlined,
    SecurityScanOutlined,
} from '@ant-design/icons';
import type { RouteConfig } from '../routes';
import { menuRoutes } from '../routes';
import { listProjects } from '../services/api';
import { canAccessRole, getCurrentUserRole, roleLabel } from '../utils/auth';
import type { UserRole } from '../utils/auth';

const { Header, Sider, Content } = Layout;
const { Text } = Typography;

import { useGlobalAI } from '../contexts/GlobalAIContext';
import GlobalAIChatDrawer from '../components/GlobalAIChatDrawer';

const filterRoutesByRole = (routes: RouteConfig[], role: UserRole): RouteConfig[] => {
    return routes.reduce<RouteConfig[]>((acc, route) => {
        if (!canAccessRole(route.minRole, role)) return acc;
        const children = route.children ? filterRoutesByRole(route.children, role) : undefined;
        if (route.children && children?.length === 0) return acc;
        acc.push(children ? { ...route, children } : route);
        return acc;
    }, []);
};

const BasicLayout: React.FC = () => {
    const { visible, pageContext, editableTarget, openGlobalAI, closeGlobalAI, setPageContext } = useGlobalAI();
    const draggableRef = useRef<HTMLDivElement>(null);
    const dragPos = useRef({ x: 0, y: 0 });
    const [collapsed, setCollapsed] = useState(false);
    const [tenantId, setTenantId] = useState('default');
    const [role, setRole] = useState<UserRole>('viewer');
    const [projects, setProjects] = useState<API.Project[]>([]);
    const [selectedProject, setSelectedProject] = useState<string>('');
    const navigate = useNavigate();
    const location = useLocation();

    // Auto Route Context Injection
    useEffect(() => {
        let module = 'global';
        const path = location.pathname;
        if (path.startsWith('/assets')) module = 'asset_list';
        else if (path.startsWith('/tasks/') && path.endsWith('/results')) module = 'task_results';
        else if (path.startsWith('/tasks')) module = 'task_list';
        else if (path.startsWith('/nodes')) module = 'node_list';
        else if (path.startsWith('/config/poc')) module = 'poc_list';
        else if (path.startsWith('/config/workflow')) module = 'workflow_list';
        else if (path.startsWith('/config/dir')) module = 'dir_list';
        else if (path.startsWith('/config/active-finger')) module = 'fingerprint_list';
        else if (path.startsWith('/arsenals/poc')) module = 'poc_list';
        else if (path.startsWith('/arsenals/dict')) module = 'dict_list';
        else if (path.startsWith('/arsenals/workflow')) module = 'workflow_list';
        else if (path.startsWith('/knowledge')) module = 'knowledge_base';
        else if (path.startsWith('/dashboard')) module = 'dashboard';

        setPageContext((prev) => ({
            ...prev,
            route: path,
            module: module,
        }));
        // We do NOT want to clear selected_data here, because useAutoContext will handle local component unmounts.
    }, [location.pathname]);

    useEffect(() => {
        const token = localStorage.getItem('token');
        if (!token) {
            navigate('/login');
            return;
        }
        setRole(getCurrentUserRole());
        const tid = localStorage.getItem('tenant_id') || 'default';
        setTenantId(tid);

        listProjects().then(res => {
            const list = res || [];
            setProjects(list);
            const savedProj = localStorage.getItem('active_project_id');
            if (savedProj && list.some(p => p.ID === savedProj)) {
                setSelectedProject(savedProj);
            } else if (list.length > 0) {
                setSelectedProject(list[0].ID);
                localStorage.setItem('active_project_id', list[0].ID);
            }
        }).catch(err => {
            console.error('Failed to fetch projects', err);
        });
    }, [navigate]);

    const handleProjectChange = (value: string) => {
        setSelectedProject(value);
        localStorage.setItem('active_project_id', value);
        window.location.reload();
    };

    const handleLogout = () => {
        localStorage.removeItem('token');
        localStorage.removeItem('tenant_id');
        localStorage.removeItem('active_project_id');
        message.success('已退出登录');
        navigate('/login');
    };

    const filteredMenuRoutes = useMemo(() => filterRoutesByRole(menuRoutes, role), [role]);
    const canUseAI = canAccessRole('operator', role);

    const userMenuItems: MenuProps['items'] = [
        {
            key: 'tenant',
            icon: <UserOutlined />,
            label: `租户: ${tenantId}`,
            disabled: true,
        },
        {
            key: 'role',
            icon: <SecurityScanOutlined />,
            label: `角色: ${roleLabel[role]}`,
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
            })
            .filter(Boolean) as MenuProps['items'];
    };

    const getSelectedKeys = (): string[] => {
        const pathname = location.pathname;
        if (pathname.startsWith('/config')) return ['/config/workflow'];
        const exactMatch = filteredMenuRoutes.find((r) => r.path === pathname);
        if (exactMatch) return [pathname];

        for (const route of filteredMenuRoutes) {
            if (route.children) {
                const child = route.children.find((c) => pathname.startsWith(c.path));
                if (child) return [child.path];
            }
            if (pathname.startsWith(route.path)) return [route.path];
        }
        return ['/dashboard'];
    };

    const getOpenKeys = (): string[] => {
        const pathname = location.pathname;
        for (const route of filteredMenuRoutes) {
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
            <style>{`
                .argus-ai-fab-shell {
                    position: fixed;
                    right: 28px;
                    bottom: 34px;
                    z-index: 9999;
                    width: 170px;
                    height: 76px;
                    cursor: move;
                    display: flex;
                    align-items: center;
                    justify-content: flex-end;
                    overflow: visible;
                    pointer-events: none;
                }

                .argus-ai-fab {
                    pointer-events: auto;
                    position: relative;
                    width: 64px;
                    height: 64px;
                    border: 1px solid rgba(14, 165, 233, 0.24);
                    border-radius: 999px;
                    background: rgba(255, 255, 255, 0.72);
                    backdrop-filter: blur(24px) saturate(180%);
                    -webkit-backdrop-filter: blur(24px) saturate(180%);
                    box-shadow:
                        0 18px 40px rgba(15, 23, 42, 0.14),
                        0 8px 20px rgba(14, 165, 233, 0.16),
                        inset 0 1px 0 rgba(255, 255, 255, 0.86);
                    color: #0f172a;
                    outline: none;
                    overflow: hidden;
                    display: flex;
                    align-items: center;
                    justify-content: flex-end;
                    padding: 8px;
                    transition:
                        width 280ms cubic-bezier(0.2, 0.8, 0.2, 1),
                        transform 220ms ease,
                        box-shadow 220ms ease,
                        border-color 220ms ease,
                        background 220ms ease;
                }

                .argus-ai-fab::before {
                    content: "";
                    position: absolute;
                    inset: -1px;
                    border-radius: inherit;
                    background: conic-gradient(
                        from 120deg,
                        rgba(14, 165, 233, 0),
                        rgba(14, 165, 233, 0.52),
                        rgba(99, 102, 241, 0.3),
                        rgba(14, 165, 233, 0)
                    );
                    opacity: 0;
                    transition: opacity 220ms ease;
                    animation: argus-fab-ring 4s linear infinite;
                }

                .argus-ai-fab::after {
                    content: "";
                    position: absolute;
                    inset: 1px;
                    border-radius: inherit;
                    background: linear-gradient(135deg, rgba(255,255,255,0.92), rgba(240, 249, 255, 0.72));
                }

                .argus-ai-fab-core,
                .argus-ai-fab-label {
                    position: relative;
                    z-index: 1;
                }

                .argus-ai-fab-core {
                    width: 46px;
                    height: 46px;
                    flex: 0 0 46px;
                    border-radius: 50%;
                    background:
                        radial-gradient(circle at 35% 25%, rgba(255,255,255,0.95), rgba(255,255,255,0.2) 34%, transparent 35%),
                        linear-gradient(145deg, #38bdf8 0%, #0ea5e9 42%, #2563eb 100%);
                    box-shadow:
                        0 10px 26px rgba(37, 99, 235, 0.28),
                        inset 0 1px 0 rgba(255,255,255,0.42);
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    overflow: hidden;
                }

                .argus-ai-fab-core::before {
                    content: "";
                    position: absolute;
                    width: 150%;
                    height: 1px;
                    left: -25%;
                    top: 50%;
                    background: linear-gradient(90deg, transparent, rgba(255,255,255,0.86), transparent);
                    transform: translateY(-16px) rotate(-18deg);
                    opacity: 0.72;
                    animation: argus-fab-scan 2.8s ease-in-out infinite;
                }

                .argus-ai-fab-icon {
                    color: #fff;
                    font-size: 22px;
                    filter: drop-shadow(0 2px 5px rgba(15, 23, 42, 0.22));
                }

                .argus-ai-fab-label {
                    width: 0;
                    opacity: 0;
                    color: #0f172a;
                    font-size: 13px;
                    font-weight: 650;
                    white-space: nowrap;
                    text-align: left;
                    transform: translateX(8px);
                    transition:
                        width 260ms cubic-bezier(0.2, 0.8, 0.2, 1),
                        opacity 180ms ease,
                        transform 220ms ease;
                }

                .argus-ai-fab:hover,
                .argus-ai-fab:focus-visible {
                    width: 152px;
                    transform: translateY(-2px) scale(1.015);
                    border-color: rgba(14, 165, 233, 0.42);
                    background: rgba(255, 255, 255, 0.82);
                    box-shadow:
                        0 24px 54px rgba(15, 23, 42, 0.18),
                        0 12px 28px rgba(14, 165, 233, 0.22),
                        inset 0 1px 0 rgba(255, 255, 255, 0.9);
                }

                .argus-ai-fab:hover::before,
                .argus-ai-fab:focus-visible::before {
                    opacity: 1;
                }

                .argus-ai-fab:hover .argus-ai-fab-label,
                .argus-ai-fab:focus-visible .argus-ai-fab-label {
                    width: 76px;
                    opacity: 1;
                    transform: translateX(0);
                }

                .argus-ai-fab:active {
                    transform: translateY(0) scale(0.98);
                }

                @keyframes argus-fab-ring {
                    to { transform: rotate(360deg); }
                }

                @keyframes argus-fab-scan {
                    0%, 100% { transform: translateY(-17px) rotate(-18deg); opacity: 0; }
                    18%, 70% { opacity: 0.76; }
                    55% { transform: translateY(18px) rotate(-18deg); opacity: 0.5; }
                }
            `}</style>
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
                        items={getMenuItems(filteredMenuRoutes)}
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

                        <div style={{ flex: 1, paddingLeft: 24 }}>
                            <Space>
                                <ProjectOutlined style={{ color: '#0ea5e9' }} />
                                <Select
                                    value={selectedProject}
                                    onChange={handleProjectChange}
                                    style={{ width: 250 }}
                                    placeholder="请选择项目上下文"
                                    options={projects.map(p => ({ label: p.Name, value: p.ID }))}
                                    dropdownMatchSelectWidth={false}
                                />
                            </Space>
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

            {canUseAI && (
                <>
                    <GlobalAIChatDrawer
                        visible={visible}
                        onClose={closeGlobalAI}
                        pageContext={pageContext}
                        editableTarget={editableTarget}
                    />
                    <Draggable nodeRef={draggableRef} bounds="parent" defaultPosition={{ x: 0, y: 0 }}
                        onStart={(_, data) => {
                            dragPos.current = { x: data.x, y: data.y };
                            (window as any).isDraggingAI = false;
                        }}
                        onStop={(_, data) => {
                            const dx = Math.abs(data.x - dragPos.current.x);
                            const dy = Math.abs(data.y - dragPos.current.y);
                            if (dx > 3 || dy > 3) {
                                (window as any).isDraggingAI = true;
                                setTimeout(() => {
                                    (window as any).isDraggingAI = false;
                                }, 100);
                            } else {
                                (window as any).isDraggingAI = false;
                            }
                        }}
                    >
                        <div ref={draggableRef} className="argus-ai-fab-shell">
                            <button
                                type="button"
                                className="argus-ai-fab"
                                onClick={() => {
                                    if (!(window as any).isDraggingAI) {
                                        openGlobalAI();
                                    }
                                }}
                                aria-label="唤起 Argus Copilot"
                                title="按住拖动 / 点击唤起 Argus Copilot"
                            >
                                <span className="argus-ai-fab-label">Copilot</span>
                                <span className="argus-ai-fab-core">
                                    <SecurityScanOutlined className="argus-ai-fab-icon" />
                                </span>
                            </button>
                        </div>
                    </Draggable>
                </>
            )}
        </ConfigProvider>
    );
};

export default BasicLayout;
