import React, { useEffect, useState } from 'react';
import { App, Col, Row, Statistic } from 'antd';
import { ProCard } from '@ant-design/pro-components';
import { ApartmentOutlined, BugOutlined, FileSearchOutlined, ScanOutlined } from '@ant-design/icons';
import { getDirDict, getFingerprintDict, getWorkflowDict, listArsenals } from '../../services/api';
import ArsenalRuleDebugPanel from './ArsenalRuleDebugPanel';

const DebugConfig: React.FC = () => {
    const { message } = App.useApp();
    const [loading, setLoading] = useState(true);
    const [fingerprints, setFingerprints] = useState<API.FingerprintItem[]>([]);
    const [workflows, setWorkflows] = useState<API.WorkflowItem[]>([]);
    const [dirs, setDirs] = useState<API.DirItem[]>([]);
    const [pocFiles, setPocFiles] = useState<Set<string>>(new Set());
    const [pocCount, setPocCount] = useState(0);

    const fetchData = async () => {
        setLoading(true);
        try {
            const [fps, wfs, dirItems, pocs] = await Promise.all([
                getFingerprintDict(),
                getWorkflowDict(),
                getDirDict(),
                listArsenals('poc', true, true),
            ]);
            setFingerprints(fps || []);
            setWorkflows(wfs || []);
            setDirs(dirItems || []);
            setPocCount((pocs || []).length);
            const nextPocFiles = new Set<string>();
            (pocs || []).forEach((p) => {
                nextPocFiles.add(p.FileName);
                nextPocFiles.add(p.FileName.replace(/\.(ya?ml)$/i, ''));
            });
            setPocFiles(nextPocFiles);
        } catch {
            message.error('加载调试所需弹药库数据失败');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchData();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    return (
        <div>
            <ProCard
                className="glass-card"
                loading={loading}
                style={{ marginBottom: 16, background: 'transparent' }}
                bodyStyle={{ padding: '12px 16px' }}
            >
                <Row gutter={16}>
                    <Col flex="1">
                        <Statistic title="指纹 Product" value={fingerprints.length} prefix={<ScanOutlined style={{ color: '#06b6d4' }} />} />
                    </Col>
                    <Col flex="1">
                        <Statistic title="Workflow" value={workflows.length} prefix={<ApartmentOutlined style={{ color: '#8b5cf6' }} />} />
                    </Col>
                    <Col flex="1">
                        <Statistic title="Dir 规则" value={dirs.length} prefix={<FileSearchOutlined style={{ color: '#0ea5e9' }} />} />
                    </Col>
                    <Col flex="1">
                        <Statistic title="POC 文件" value={pocCount} prefix={<BugOutlined style={{ color: '#3b82f6' }} />} />
                    </Col>
                </Row>
            </ProCard>

            <div style={{ maxWidth: 980 }}>
                <ArsenalRuleDebugPanel
                    fingerprints={fingerprints}
                    workflows={workflows}
                    dirs={dirs}
                    pocFiles={pocFiles}
                    title="Workflow 规则调试"
                />
            </div>
        </div>
    );
};

export default DebugConfig;
