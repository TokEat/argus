import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Form, Input, Button, App, ConfigProvider, theme } from 'antd';
import { UserOutlined, LockOutlined } from '@ant-design/icons';
import { login } from '../services/api';
import loginIllustration from '../assets/login_illustration.png';

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
        background: 'linear-gradient(135deg, #2D1B69 0%, #4A2DB5 35%, #6B4FCC 60%, #8B6FE8 80%, #B06AE8 100%)',
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
    blob1: {
        position: 'absolute',
        width: 400, height: 400,
        background: '#FF6BCB',
        borderRadius: '50%',
        filter: 'blur(70px)',
        opacity: 0.3,
        top: -120, left: -100,
        pointerEvents: 'none',
    },
    blob2: {
        position: 'absolute',
        width: 300, height: 300,
        background: '#4FC3F7',
        borderRadius: '50%',
        filter: 'blur(60px)',
        opacity: 0.3,
        bottom: -80, right: -60,
        pointerEvents: 'none',
    },
    blob3: {
        position: 'absolute',
        width: 220, height: 220,
        background: '#7C4DFF',
        borderRadius: '50%',
        filter: 'blur(60px)',
        opacity: 0.3,
        bottom: 100, left: 40,
        pointerEvents: 'none',
    },
    illustrationWrap: {
        position: 'relative',
        zIndex: 5,
        textAlign: 'center',
        padding: '0 40px',
    },
    illustrationTitle: {
        color: '#fff',
        fontSize: 30,
        fontWeight: 700,
        letterSpacing: 6,
        marginBottom: 12,
        textShadow: '0 2px 10px rgba(0,0,0,0.4)',
    },
    illustrationImg: {
        width: 460,
        maxWidth: '80%',
        filter: 'drop-shadow(0 20px 60px rgba(0,0,0,0.45))',
    },
    illustrationTagline: {
        color: 'rgba(255,255,255,0.85)',
        fontSize: 14,
        marginTop: 16,
        letterSpacing: 1,
        textShadow: '0 1px 4px rgba(0,0,0,0.3)',
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
    const [floatY, setFloatY] = useState(0);
    const navigate = useNavigate();
    const { message } = App.useApp();

    /* floating animation */
    useEffect(() => {
        let frame: number;
        const start = performance.now();
        const animate = (now: number) => {
            const t = (now - start) / 1000;
            setFloatY(Math.sin(t * (Math.PI / 2)) * 10);
            frame = requestAnimationFrame(animate);
        };
        frame = requestAnimationFrame(animate);
        return () => cancelAnimationFrame(frame);
    }, []);

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
            <div style={styles.leftPanel}>
                {/* decorative blobs */}
                <div style={styles.blob1} />
                <div style={styles.blob2} />
                <div style={styles.blob3} />

                {/* twinkling dots */}
                {dots.map((d, i) => (
                    <div
                        key={i}
                        style={{
                            position: 'absolute',
                            width: d.s, height: d.s,
                            borderRadius: '50%',
                            background: 'rgba(255,255,255,0.7)',
                            top: d.top, left: d.left,
                            animation: `twinkle 3s ${d.delay}s ease-in-out infinite`,
                            pointerEvents: 'none',
                        }}
                    />
                ))}

                {/* illustration */}
                <div style={styles.illustrationWrap}>
                    <div style={styles.illustrationTitle}>ARGUS</div>
                    <img
                        src={loginIllustration}
                        alt="Argus Illustration"
                        style={{ ...styles.illustrationImg, transform: `translateY(${floatY}px)` }}
                    />
                    <div style={styles.illustrationTagline}>分布式漏洞扫描与资产管理平台</div>
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
                            colorPrimary: '#6B4FCC',
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
                        <div style={styles.header}>
                            <div style={styles.headerTitle}>控制台登录</div>
                            <div style={styles.headerSub}>输入租户 ID 和密码进入控制面板</div>
                        </div>

                        <Form name="login" onFinish={onFinish} autoComplete="off" size="large"
                              initialValues={{ tenant_id: 'default', password: '' }}>
                            {/* 租户 ID */}
                            <Form.Item name="tenant_id" rules={[{ required: true, message: '请输入租户 ID' }]}>
                                <Input
                                    prefix={<UserOutlined style={{ color: '#6B4FCC' }} />}
                                    placeholder="租户 ID"
                                    disabled={loading}
                                    style={{ borderRadius: 10, height: 46 }}
                                />
                            </Form.Item>

                            {/* 密码 */}
                            <Form.Item name="password" rules={[{ required: true, message: '请输入密码' }]}>
                                <Input.Password
                                    prefix={<LockOutlined style={{ color: '#6B4FCC' }} />}
                                    placeholder="密码"
                                    disabled={loading}
                                    style={{ borderRadius: 10, height: 46 }}
                                />
                            </Form.Item>

                            {/* 提交 */}
                            <Form.Item style={{ marginBottom: 0 }}>
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
                                        background: 'linear-gradient(135deg, #5B3FBC, #7B5EEA)',
                                        border: 'none',
                                        boxShadow: '0 6px 20px rgba(91,63,188,0.4)',
                                    }}
                                >
                                    {loading ? '登录中…' : '登 录'}
                                </Button>
                            </Form.Item>
                        </Form>

                        <div style={styles.footer}>© 2026 Argus. All rights reserved.</div>
                    </div>
                </ConfigProvider>
            </div>

            {/* keyframes injected via style tag */}
            <style>{`
                @keyframes twinkle {
                    0%, 100% { opacity: 0.3; transform: scale(1); }
                    50%       { opacity: 1;   transform: scale(1.5); }
                }
                .ant-input-affix-wrapper:focus-within,
                .ant-input-affix-wrapper-focused {
                    border-color: #6B4FCC !important;
                    box-shadow: 0 0 0 2px rgba(107,79,204,0.15) !important;
                }
                .ant-btn-primary:hover {
                    opacity: 0.9;
                    transform: translateY(-1px);
                    box-shadow: 0 10px 28px rgba(91,63,188,0.5) !important;
                }
                @media (max-width: 768px) {
                    .login-left-panel { display: none !important; }
                }
            `}</style>
        </div>
    );
};

export default Login;
