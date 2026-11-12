import { Alert, Card, Col, Descriptions, Progress, Row, Space, Steps, Tag, Typography } from 'antd';

const { Text } = Typography;

const stageLabels: Record<string, string> = {
    asset_discovery: '资产发现', risk_validation: 'POC 验证', credential_validation: '弱口令验证',
};

const statusMeta: Record<string, { label: string; status: 'wait' | 'process' | 'finish' | 'error'; color: string }> = {
    pending: { label: '等待资产发现', status: 'wait', color: 'default' },
    derived: { label: '执行中', status: 'process', color: 'processing' },
    complete: { label: '已完成', status: 'finish', color: 'success' },
    skipped: { label: '已跳过', status: 'finish', color: 'default' },
    failed: { label: '部分失败', status: 'error', color: 'error' },
};

type StageDerivation = NonNullable<API.TaskDetailResponse['stage_derivations']>[number];

function stageValue(row: StageDerivation | undefined, key: 'Stage' | 'Status' | 'ItemCount') {
    if (!row) return undefined;
    const aliases = { Stage: 'stage', Status: 'status', ItemCount: 'item_count' } as const;
    return row[key] ?? row[aliases[key]];
}

function derivationReason(row: StageDerivation | undefined): string {
    if (!row) return '';
    const raw = row.Summary ?? row.summary;
    if (!raw) return '';
    try {
        const value = typeof raw === 'string' ? JSON.parse(raw) : raw;
        return typeof value?.reason === 'string' ? value.reason : '';
    } catch {
        return '';
    }
}

const skippedReasonLabels: Record<string, string> = {
    no_approved_workflow_matches: '无已审核 Workflow 命中，已跳过',
    no_eligible_services: '无符合条件的服务，已跳过',
    rule_version_drift: '规则版本发生变化，已跳过',
};

function stageMeta(status: string, enabled: boolean, row: StageDerivation | undefined) {
    if (!enabled) return { label: '未启用', status: 'wait' as const, color: 'default' };
    const meta = statusMeta[status] || statusMeta.pending;
    if (status !== 'skipped') return meta;
    const reason = derivationReason(row);
    return { ...meta, label: skippedReasonLabels[reason] || '已跳过' };
}

export default function TaskStageOverview({ detail }: { detail: API.TaskDetailResponse }) {
    if (!detail.scan_policy) return null;
    const derivations = detail.stage_derivations || [];
    const find = (stage: string) => derivations.find((row) => stageValue(row, 'Stage') === stage);
    const riskRow = find('risk_validation');
    const credentialRow = find('credential_validation');
    const riskEnabled = Boolean(detail.scan_policy.policy.capabilities.risk_validation);
    const credentialEnabled = Boolean(detail.scan_policy.policy.capabilities.credential_validation);
    const riskStatus = String(stageValue(riskRow, 'Status') || detail.scan_policy?.risk_status || 'pending');
    const credentialStatus = String(stageValue(credentialRow, 'Status') || detail.scan_policy?.credential_status || 'pending');
    const riskMeta = stageMeta(riskStatus, riskEnabled, riskRow);
    const credentialMeta = stageMeta(credentialStatus, credentialEnabled, credentialRow);
    const assetBatches = (detail.batches || []).filter((batch) => batch.kind === 'asset_scan');
    const terminalAssetStatuses = new Set(['DONE', 'FINISHED', 'COMPLETED', 'SUCCESS', 'SUCCEEDED']);
    const failedAssetStatuses = new Set(['FAILED', 'ERROR', 'TIMEOUT', 'CANCELLED', 'CANCELED', 'STOPPED']);
    const discoveryTotal = assetBatches.length > 0
        ? assetBatches.reduce((total, batch) => total + batch.target_count, 0)
        : detail.task.total_targets;
    const discoveryCompleted = assetBatches.length > 0
        ? assetBatches.reduce((total, batch) => terminalAssetStatuses.has(String(batch.status).toUpperCase()) ? total + batch.target_count : total, 0)
        : detail.task.completed_targets;
    const discoveryFailed = assetBatches.some((batch) => failedAssetStatuses.has(String(batch.status).toUpperCase()));
    const discoveryPercent = discoveryTotal > 0 ? Math.round(discoveryCompleted / discoveryTotal * 100) : 0;
    const steps = [
        { title: stageLabels.asset_discovery, status: discoveryFailed ? 'error' as const : discoveryPercent >= 100 ? 'finish' as const : 'process' as const, description: `${discoveryCompleted}/${discoveryTotal} 目标` },
        { title: stageLabels.risk_validation, status: riskMeta.status, description: riskMeta.label },
        { title: stageLabels.credential_validation, status: credentialMeta.status, description: credentialMeta.label },
    ];
    return (
        <Card size="small" title="统一扫描阶段" style={{ marginBottom: 20 }}>
            <Row gutter={20}>
                <Col xs={24} md={14}><Steps current={steps.findIndex((step) => step.status === 'process')} items={steps} /></Col>
                <Col xs={24} md={10}>
                    <Space direction="vertical" style={{ width: '100%' }}>
                        <Progress percent={discoveryPercent} size="small" />
                        <Descriptions column={1} size="small">
                            <Descriptions.Item label="策略">{detail.scan_policy.policy.preset}</Descriptions.Item>
                            <Descriptions.Item label="计划哈希"><Text code>{detail.scan_policy.plan_hash.slice(0, 12)}…</Text></Descriptions.Item>
                            <Descriptions.Item label="POC"><Tag color={riskMeta.color}>{riskMeta.label}</Tag></Descriptions.Item>
                            <Descriptions.Item label="弱口令"><Tag color={credentialMeta.color}>{credentialMeta.label}</Tag></Descriptions.Item>
                        </Descriptions>
                    </Space>
                </Col>
            </Row>
            {(riskStatus === 'failed' || credentialStatus === 'failed') && <Alert type="warning" showIcon message="任务已部分完成" description="成功资产已完成验证；未覆盖范围可在技术批次中展开查看并重试。" />}
        </Card>
    );
}
