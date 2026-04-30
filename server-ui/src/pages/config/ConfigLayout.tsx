import React, { useRef, useEffect } from 'react';
import { App, Button, Tabs } from 'antd';
import {
    BugOutlined,
    ScanOutlined,
    ApartmentOutlined,
    FolderOpenOutlined,
    ExperimentOutlined,
    DownloadOutlined,
    ThunderboltOutlined,
} from '@ant-design/icons';
import { useNavigate, useLocation } from 'react-router-dom';
import { canAccessRole } from '../../utils/auth';
import gsap from 'gsap';
import NetworkCanvas from '../../components/NetworkCanvas';
import { exportArsenalSeedDB } from '../../services/api';



interface ConfigLayoutProps {
    children: React.ReactNode;
}

const ConfigLayout: React.FC<ConfigLayoutProps> = ({ children }) => {
    const navigate = useNavigate();
    const location = useLocation();
    const pageRef = useRef<HTMLDivElement>(null);
    const { message } = App.useApp();
    const canExportSeedDB = canAccessRole('admin');

    const handleExportSeedDB = async () => {
        if (!canExportSeedDB) return;
        try {
            const blob = await exportArsenalSeedDB();
            const url = window.URL.createObjectURL(blob);
            const link = document.createElement('a');
            const ts = new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14);
            link.href = url;
            link.download = `arsenal_seed_${ts}.db`;
            document.body.appendChild(link);
            link.click();
            link.remove();
            window.URL.revokeObjectURL(url);
            message.success('弹药库安装 DB 已导出');
        } catch (err: unknown) {
            message.error(typeof err === 'string' ? err : '导出失败');
        }
    };

    /* GSAP entrance */
    useEffect(() => {
        if (!pageRef.current) return;
        const els = pageRef.current.querySelectorAll('.config-animate-in');
        if (els.length === 0) return;
        const ctx = gsap.context(() => {
            gsap.from(els, {
                y: 24, opacity: 0, duration: 0.45,
                stagger: 0.08, ease: 'power2.out', clearProps: 'transform,opacity',
            });
        }, pageRef);
        return () => ctx.revert();
    }, [location.pathname]);

    const tabItems = [
        { key: '/config/workflow', label: 'Workflow 编排', icon: <ApartmentOutlined /> },
        { key: '/config/poc', label: 'POC 弹药库', icon: <BugOutlined /> },
        { key: '/config/active-finger', label: '指纹弹药库', icon: <ScanOutlined /> },
        { key: '/config/dir', label: 'Dir 探测规则', icon: <FolderOpenOutlined /> },
        { key: '/config/exploit', label: 'EXP 验证库', icon: <ThunderboltOutlined /> },
        ...(canAccessRole('operator') ? [{ key: '/config/debug', label: '调试', icon: <ExperimentOutlined /> }] : []),
    ];

    return (
        <div ref={pageRef} style={{ position: 'relative', overflow: 'hidden' }}>
            <NetworkCanvas color="#8b5cf6" count={25} speed={0.12} linkDist={90} />
            <div className="config-animate-in" style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                marginBottom: 16,
                position: 'relative',
                zIndex: 1,
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
                {canExportSeedDB && (
                    <Button icon={<DownloadOutlined />} onClick={handleExportSeedDB}>
                        导出安装 DB
                    </Button>
                )}
            </div>
            <div className="config-animate-in" style={{ position: 'relative', zIndex: 1 }}>
                {children}
            </div>
        </div>
    );
};

export default ConfigLayout;
