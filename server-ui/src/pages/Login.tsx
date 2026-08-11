import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Form, Input, Button, App, ConfigProvider, theme } from 'antd';
import { UserOutlined, LockOutlined } from '@ant-design/icons';
import { login } from '../services/api';
import argusLogoMark from '../assets/brand/argus-logo-mark.svg';
import NetworkCanvas from '../components/NetworkCanvas';

/* ─────────────── inline styles ─────────────── */
const styles: Record<string, React.CSSProperties> = {
    root: {
        display: 'flex',
        minHeight: '100vh',
        overflow: 'hidden',
        fontFamily: "'Inter', 'PingFang SC', 'Microsoft YaHei', sans-serif",
    },

    /* ── Left panel ── */
    leftPanel: {
        flex: '0 0 58%',
        background: '#030507',
        position: 'relative',
        overflow: 'hidden',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
    },
    leftCut: {
        position: 'absolute',
        top: 0, right: -55, bottom: 0,
        width: 110,
        background: '#f7f9fc',
        transform: 'skewX(-6deg)',
        zIndex: 10,
    },
    gridOverlay: {
        position: 'absolute',
        inset: 0,
        backgroundImage: 'linear-gradient(rgba(244,247,250,0.045) 1px, transparent 1px), linear-gradient(90deg, rgba(244,247,250,0.045) 1px, transparent 1px)',
        backgroundSize: '72px 72px',
        maskImage: 'linear-gradient(90deg, rgba(0,0,0,0.95), rgba(0,0,0,0.68) 58%, transparent)',
        pointerEvents: 'none',
    },
    motionWrap: {
        position: 'relative',
        zIndex: 5,
        width: 'min(780px, 82%)',
        aspectRatio: '1.36 / 1',
        display: 'grid',
        placeItems: 'center',
    },
    motionStage: {
        position: 'absolute',
        inset: 0,
        display: 'grid',
        placeItems: 'center',
    },
    logoFrame: {
        position: 'absolute',
        width: 320,
        height: 320,
        border: '9px solid #F4F7FA',
        borderRadius: 38,
        background: 'rgba(10, 15, 23, 0.76)',
        display: 'grid',
        placeItems: 'center',
        boxShadow: '0 34px 88px rgba(0, 0, 0, 0.36)',
        overflow: 'hidden',
    },
    logoMark: {
        width: 220,
        height: 220,
        position: 'relative',
        zIndex: 3,
        filter: 'drop-shadow(0 18px 36px rgba(0, 0, 0, 0.55))',
    },
    illustrationTitle: {
        position: 'absolute',
        left: 0,
        right: 0,
        bottom: 0,
        color: '#F4F7FA',
        fontSize: 58,
        fontWeight: 800,
        letterSpacing: 14,
        textAlign: 'center',
    },
    illustrationTagline: {
        position: 'absolute',
        top: 4,
        left: 0,
        right: 0,
        color: '#8A95A5',
        fontSize: 15,
        fontWeight: 600,
        letterSpacing: 5,
        textAlign: 'center',
        textTransform: 'uppercase',
    },

    /* ── Right panel ── */
    rightPanel: {
        flex: 1,
        background: '#f7f9fc',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '40px 40px 40px 80px',
    },
    loginBox: {
        width: '100%',
        maxWidth: 340,
    },
    header: {
        marginBottom: 32,
    },
    brandHeader: {
        display: 'flex',
        alignItems: 'center',
        gap: 12,
        marginBottom: 28,
    },
    brandIcon: {
        width: 46,
        height: 46,
        borderRadius: 10,
        background: '#030507',
        padding: 8,
        boxShadow: '0 12px 26px rgba(3, 5, 7, 0.16)',
    },
    headerTitle: {
        fontSize: 22,
        fontWeight: 600,
        color: '#1a1a2e',
        marginBottom: 6,
    },
    headerSub: {
        fontSize: 13,
        color: '#8c8c9a',
    },
    footer: {
        textAlign: 'center',
        marginTop: 28,
        fontSize: 11,
        color: '#c0c0cc',
    },
};

/* ─────────────── Floating dot decoration ─────────────── */
const dots = [
    { s: 6, top: '20%', left: '15%', delay: 0 },
    { s: 4, top: '35%', left: '70%', delay: 0.8 },
    { s: 8, top: '60%', left: '22%', delay: 1.5 },
    { s: 5, top: '75%', left: '65%', delay: 0.4 },
    { s: 6, top: '12%', left: '55%', delay: 2.0 },
    { s: 4, top: '82%', left: '40%', delay: 1.2 },
];

/* ─────────────── Component ─────────────── */
const Login: React.FC = () => {
    const [loading, setLoading] = useState(false);
    const navigate = useNavigate();
    const { message } = App.useApp();
    const onFinish = async (values: { tenant_id: string; password: string }) => {
        setLoading(true);
        try {
            const result = await login({
                tenant_id: values.tenant_id,
                password: values.password,
            });
            localStorage.setItem('token', result.token);
            localStorage.setItem('tenant_id', values.tenant_id);
            message.success('登录成功');
            navigate('/dashboard');
        } catch (error: unknown) {
            const msg = typeof error === 'string' ? error : '登录失败';
            message.error(msg);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div style={styles.root}>
            {/* ──────────── LEFT PANEL ──────────── */}
            <div className="login-left-panel" style={styles.leftPanel}>
                {/* canvas particle network */}
                <NetworkCanvas color="#f4f7fa" count={42} speed={0.16} linkDist={125} style={{ opacity: 0.34 }} />
                <div style={styles.gridOverlay} />

                {/* telemetry points */}
                {dots.map((d, i) => (
                    <div
                        key={i}
                        style={{
                            position: 'absolute',
                            width: d.s, height: d.s,
                            borderRadius: '50%',
                            background: 'rgba(244,247,250,0.72)',
                            top: d.top, left: d.left,
                            animation: `twinkle 3s ${d.delay}s ease-in-out infinite`,
                            pointerEvents: 'none',
                        }}
                    />
                ))}

                {/* HyperFrames-inspired motion hero */}
                <div style={styles.motionWrap}>
                    <div style={styles.motionStage}>
                        <div className="argus-motion-in login-tagline" style={styles.illustrationTagline}>Security Automation Platform</div>
                        <div className="argus-motion-in argus-rail argus-rail-a" />
                        <div className="argus-motion-in argus-rail argus-rail-b" />
                        <div className="argus-motion-in argus-signal-ring argus-signal-left" />
                        <div className="argus-motion-in argus-signal-ring argus-signal-right" />
                        <div className="argus-motion-in" style={styles.logoFrame}>
                            <div className="argus-frame-grid" />
                            <div className="argus-scan-line" />
                            <img className="argus-logo-mark" src={argusLogoMark} alt="Argus A" style={styles.logoMark} />
                        </div>
                        <div className="argus-motion-in login-title-text" style={styles.illustrationTitle}>ARGUS</div>
                    </div>
                </div>

                {/* diagonal cut */}
                <div style={styles.leftCut} />
            </div>

            {/* ──────────── RIGHT PANEL ──────────── */}
            <div style={styles.rightPanel}>
                <ConfigProvider
                    theme={{
                        algorithm: theme.defaultAlgorithm,
                        token: {
                            colorPrimary: '#030507',
                            colorBgContainer: '#ffffff',
                            colorText: '#1a1a2e',
                            colorTextPlaceholder: '#bbbcc8',
                            colorBorder: '#e0e4ef',
                            borderRadius: 10,
                        },
                        components: {
                            Input: {
                                colorBgContainer: '#ffffff',
                                colorText: '#1a1a2e',
                            },
                        },
                    }}
                >
                    <div style={styles.loginBox}>
                        <div className="login-form-item" style={styles.brandHeader}>
                            <img src={argusLogoMark} alt="Argus" style={styles.brandIcon} />
                            <div>
                                <div style={styles.headerTitle}>ARGUS 控制台</div>
                                <div style={styles.headerSub}>输入租户 ID 和密码进入控制面板</div>
                            </div>
                        </div>

                        <Form name="login" onFinish={onFinish} autoComplete="off" size="large"
                              initialValues={{ tenant_id: 'default', password: '' }}>
                            {/* 租户 ID */}
                            <Form.Item className="login-form-item" name="tenant_id" rules={[{ required: true, message: '请输入租户 ID' }]}>
                                <Input
                                    prefix={<UserOutlined style={{ color: '#030507' }} />}
                                    placeholder="租户 ID"
                                    disabled={loading}
                                    style={{ borderRadius: 10, height: 46 }}
                                />
                            </Form.Item>

                            {/* 密码 */}
                            <Form.Item className="login-form-item" name="password" rules={[{ required: true, message: '请输入密码' }]}>
                                <Input.Password
                                    prefix={<LockOutlined style={{ color: '#030507' }} />}
                                    placeholder="密码"
                                    disabled={loading}
                                    style={{ borderRadius: 10, height: 46 }}
                                />
                            </Form.Item>

                            {/* 提交 */}
                            <Form.Item className="login-form-item" style={{ marginBottom: 0 }}>
                                <Button
                                    type="primary"
                                    htmlType="submit"
                                    loading={loading}
                                    block
                                    style={{
                                        height: 48,
                                        fontSize: 16,
                                        fontWeight: 600,
                                        letterSpacing: 6,
                                        borderRadius: 10,
                                        background: '#030507',
                                        border: 'none',
                                        boxShadow: '0 10px 24px rgba(3,5,7,0.24)',
                                    }}
                                >
                                    {loading ? '登录中…' : '登 录'}
                                </Button>
                            </Form.Item>
                        </Form>

                        <div className="login-form-item" style={styles.footer}>© 2026 Argus. All rights reserved.</div>
                    </div>
                </ConfigProvider>
            </div>

            {/* keyframes injected via style tag */}
            <style>{`
                @keyframes twinkle {
                    0%, 100% { opacity: 0.3; transform: scale(1); }
                    50%       { opacity: 1;   transform: scale(1.5); }
                }
                .argus-frame-grid {
                    position: absolute;
                    inset: 22px;
                    border: 1px solid rgba(244,247,250,0.16);
                    background-image:
                        linear-gradient(rgba(244,247,250,0.06) 1px, transparent 1px),
                        linear-gradient(90deg, rgba(244,247,250,0.06) 1px, transparent 1px);
                    background-size: 34px 34px;
                    pointer-events: none;
                }
                .argus-scan-line {
                    position: absolute;
                    left: 28px;
                    right: 28px;
                    top: 36px;
                    height: 2px;
                    background: #38D5FF;
                    opacity: 0.32;
                    box-shadow: 0 0 18px rgba(56,213,255,0.86);
                    z-index: 4;
                }
                .argus-rail {
                    position: absolute;
                    height: 3px;
                    background: #F4F7FA;
                    opacity: 0.84;
                    pointer-events: none;
                }
                .argus-rail-a {
                    width: 230px;
                    top: 88px;
                    left: 16px;
                }
                .argus-rail-b {
                    width: 320px;
                    right: 0;
                    bottom: 88px;
                }
                .argus-signal-ring {
                    position: absolute;
                    width: 132px;
                    height: 132px;
                    border: 2px solid rgba(56,213,255,0.48);
                    opacity: 0.48;
                    pointer-events: none;
                }
                .argus-signal-left {
                    left: 64px;
                    bottom: 54px;
                    transform: rotate(18deg);
                }
                .argus-signal-right {
                    right: 58px;
                    top: 42px;
                    transform: rotate(-16deg);
                }
                .argus-motion-in {
                    animation: argus-enter 0.65s cubic-bezier(0.22, 1, 0.36, 1) both;
                }
                .argus-motion-in:nth-child(2) { animation-delay: 0.08s; }
                .argus-motion-in:nth-child(3) { animation-delay: 0.16s; }
                .argus-motion-in:nth-child(4) { animation-delay: 0.24s; }
                .argus-motion-in:nth-child(5) { animation-delay: 0.32s; }
                .argus-motion-in:nth-child(6) { animation-delay: 0.40s; }
                .argus-motion-in:nth-child(7) { animation-delay: 0.48s; }
                .argus-logo-mark {
                    animation: argus-logo-float 3.2s ease-in-out infinite alternate;
                }
                .argus-scan-line {
                    animation: argus-scan 2.7s ease-in-out infinite alternate;
                }
                .argus-signal-ring {
                    animation: argus-ring-spin 10s linear infinite;
                }
                .argus-signal-right { animation-delay: -0.6s; }
                .argus-rail {
                    animation: argus-rail-shift 2.4s ease-in-out infinite alternate;
                }
                .argus-rail-b { animation-delay: -0.35s; }
                .login-form-item {
                    animation: login-form-enter 0.5s cubic-bezier(0.22, 1, 0.36, 1) both;
                }
                .login-form-item:nth-child(2) { animation-delay: 0.1s; }
                .login-form-item:nth-child(3) { animation-delay: 0.2s; }
                .login-form-item:nth-child(4) { animation-delay: 0.3s; }
                @keyframes argus-enter {
                    from { transform: translateY(26px); }
                    to { transform: translateY(0); }
                }
                @keyframes argus-logo-float {
                    from { transform: translateY(0) scale(1); }
                    to { transform: translateY(-10px) scale(1.025); }
                }
                @keyframes argus-scan {
                    from { transform: translateY(0); opacity: 0.32; }
                    to { transform: translateY(242px); opacity: 0.88; }
                }
                @keyframes argus-ring-spin {
                    to { rotate: 360deg; }
                }
                @keyframes argus-rail-shift {
                    from { translate: 0 0; opacity: 0.84; }
                    to { translate: 26px 0; opacity: 0.42; }
                }
                @keyframes login-form-enter {
                    from { transform: translateY(28px); }
                    to { transform: translateY(0); }
                }
                .ant-input-affix-wrapper:focus-within,
                .ant-input-affix-wrapper-focused {
                    border-color: #030507 !important;
                    box-shadow: 0 0 0 2px rgba(3,5,7,0.12) !important;
                }
                .ant-btn-primary:hover {
                    opacity: 0.9;
                    transform: translateY(-1px);
                    box-shadow: 0 14px 30px rgba(3,5,7,0.28) !important;
                }
                @media (prefers-reduced-motion: reduce) {
                    .argus-motion-in,
                    .argus-logo-mark,
                    .argus-scan-line,
                    .argus-signal-ring,
                    .argus-rail,
                    .login-form-item {
                        animation: none !important;
                    }
                }
                @media (max-width: 768px) {
                    .login-left-panel { display: none !important; }
                }
            `}</style>
        </div>
    );
};

export default Login;
