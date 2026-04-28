import React from 'react';
import type { RouteObject } from 'react-router-dom';
import {
    DashboardOutlined,
    ClusterOutlined,
    CloudOutlined,
    RocketOutlined,
    SettingOutlined,
    BugOutlined,
    ScanOutlined,
    ApartmentOutlined,
    BuildOutlined,
    TeamOutlined,
    SafetyOutlined,
    KeyOutlined,
    DatabaseOutlined,
    ProfileOutlined,
    ProjectOutlined,
    RobotOutlined,
} from '@ant-design/icons';
import BasicLayout from './layouts/BasicLayout';
import Dashboard from './pages/Dashboard';
import NodeManagement from './pages/NodeManagement';
import CloudManagement from './pages/CloudManagement';
import TaskManagement from './pages/TaskManagement';
import TaskResults from './pages/TaskResults';
import ProfilesView from './pages/ProfilesView';
import ProjectManagement from './pages/ProjectManagement';
import ConfigLayout from './pages/config/ConfigLayout';
import PocConfig from './pages/config/PocConfig';
import ActiveFingerConfig from './pages/config/DirConfig';
import DirProbeConfig from './pages/config/DirProbeConfig';
import WorkflowConfig from './pages/config/WorkflowConfig';
import ClientBuild from './pages/ClientBuild';
import UserManagement from './pages/UserManagement';
import RoleManagement from './pages/RoleManagement';

import ApiKeysConfig from './pages/ApiKeysConfig';
import AIConfig from './pages/AIConfig';
import Login from './pages/Login';

// Route configuration with menu info
export interface RouteConfig {
    path: string;
    name: string;
    icon?: React.ReactNode;
    element?: React.ReactNode;
    children?: RouteConfig[];
    hideInMenu?: boolean;
}

export const menuRoutes: RouteConfig[] = [
    {
        path: '/dashboard',
        name: '首页',
        icon: <DashboardOutlined />,
        element: <Dashboard />,
    },
    {
        path: '/nodes',
        name: '节点管理',
        icon: <ClusterOutlined />,
        element: <NodeManagement />,
    },
    {
        path: '/projects',
        name: '项目管理',
        icon: <ProjectOutlined />,
        element: <ProjectManagement />,
    },
    {
        path: '/tasks',
        name: '任务管理',
        icon: <RocketOutlined />,
        element: <TaskManagement />,
    },
    {
        path: '/tasks/:taskId/results',
        name: '任务结果',
        icon: <RocketOutlined />,
        element: <TaskResults />,
        hideInMenu: true,
    },
    {
        path: '/profiles',
        name: '融合画像',
        icon: <ProfileOutlined />,
        element: <ProfilesView />,
    },
    {
        path: '/config/workflow',
        name: '弹药库管理',
        icon: <DatabaseOutlined />,
    },
    {
        path: '/config',
        name: '弹药库管理',
        icon: <DatabaseOutlined />,
        hideInMenu: true,
        children: [
            {
                path: '/config/workflow',
                name: 'Workflow 编排',
                icon: <ApartmentOutlined />,
                element: <ConfigLayout><WorkflowConfig /></ConfigLayout>,
                hideInMenu: true,
            },
            {
                path: '/config/poc',
                name: 'POC 弹药库',
                icon: <BugOutlined />,
                element: <ConfigLayout><PocConfig /></ConfigLayout>,
                hideInMenu: true,
            },
            {
                path: '/config/active-finger',
                name: '指纹弹药库',
                icon: <ScanOutlined />,
                element: <ConfigLayout><ActiveFingerConfig /></ConfigLayout>,
                hideInMenu: true,
            },
            {
                path: '/config/dir',
                name: 'Dir 探测规则',
                icon: <ScanOutlined />,
                element: <ConfigLayout><DirProbeConfig /></ConfigLayout>,
                hideInMenu: true,
            },
        ],
    },
    {
        path: '/cloud',
        name: '实例配置',
        icon: <CloudOutlined />,
        element: <CloudManagement />,
    },
    {
        path: '/client-build',
        name: '客户端生成',
        icon: <BuildOutlined />,
        element: <ClientBuild />,
    },
    {
        path: '/system',
        name: '系统管理',
        icon: <SettingOutlined />,
        children: [
            {
                path: '/users',
                name: '用户管理',
                icon: <TeamOutlined />,
                element: <UserManagement />,
            },
            {
                path: '/roles',
                name: '角色管理',
                icon: <SafetyOutlined />,
                element: <RoleManagement />,
            },

            {
                path: '/api-keys',
                name: 'API 密钥',
                icon: <KeyOutlined />,
                element: <ApiKeysConfig />,
            },
            {
                path: '/ai-config',
                name: 'AI 配置',
                icon: <RobotOutlined />,
                element: <AIConfig />,
            },
        ],
    },
];

// Convert menu routes to React Router routes
function convertToRouteObjects(routes: RouteConfig[]): RouteObject[] {
    return routes.flatMap((route) => {
        const result: RouteObject[] = [];

        if (route.element) {
            result.push({
                path: route.path,
                element: route.element,
            });
        }

        if (route.children) {
            result.push(...convertToRouteObjects(route.children));
        }

        return result;
    });
}

export const routes: RouteObject[] = [
    {
        path: '/login',
        element: <Login />,
    },
    {
        path: '/',
        element: <BasicLayout />,
        children: [
            {
                index: true,
                element: <Dashboard />,
            },
            ...convertToRouteObjects(menuRoutes),
        ],
    },
];

export default routes;
