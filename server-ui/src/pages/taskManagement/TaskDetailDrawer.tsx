import React from 'react';
import {
    Button, Col, Descriptions, Divider, Drawer, Progress, Row, Space, Spin, Statistic, Table, Tag, Tooltip, Typography,
} from 'antd';
import { AimOutlined, AuditOutlined, EditOutlined, InboxOutlined, RocketOutlined } from '@ant-design/icons';
import TaskStageOverview from '../../components/tasks/TaskStageOverview';
import CredentialFindingsPanel from '../../components/tasks/CredentialFindingsPanel';
import TaskTimingPanel from '../../components/TaskTimingPanel';
import { SCAN_STAGE_LABELS } from '../taskCoverageReasons';
import TaskCoverageSection from './TaskCoverageSection';
import { auditActionLabels, renderTaskStatusTag } from './shared';

const { Text } = Typography;

const presetLabels: Record<string, string> = {
    quick: '快速 · 常用协议',
    standard: '标准 · Top1000',
    deep: '深度 · 全端口',
    custom: '自定义',
};
const portProfileLabels: Record<string, string> = {
    'common-100': '常用协议端口',
    'top-1000': 'Top1000',
    all: '1-65535',
    custom: '自定义',
};
const scanMethodLabels: Record<string, string> = { tcp: 'TCP', syn: 'SYN（内置）' };
const intensityLabels: Record<string, string> = { low: '低', balanced: '均衡', high: '高' };

function enabledCapabilityLabels(capabilities?: API.ScanPolicy['capabilities']): string[] {
    if (!capabilities) return [];
    return ([
        [capabilities.subdomain_discovery, '被动子域'],
        [capabilities.subdomain_bruteforce, '子域爆破'],
        [capabilities.behavior_probe, '行为探针'],
        [capabilities.directory_probe, '路径指纹'],
        [capabilities.risk_validation, '自动 POC'],
        [capabilities.credential_validation, '弱口令'],
        [capabilities.host_binding, 'Host Binding'],
        [capabilities.allow_cdn_assets, 'CDN 资产'],
        [capabilities.allow_private_resolved_domains, '解析到私网'],
    ] as const).filter(([enabled]) => enabled).map(([, label]) => label);
}

function ScanPolicySummary({ policy }: { policy: API.ScanPolicy }) {
    const capabilities = enabledCapabilityLabels(policy.capabilities);
    return (
        <>
            <Divider orientation="left" style={{ fontSize: 13 }}>
                <AuditOutlined style={{ marginRight: 4 }} />扫描配置
            </Divider>
            <Descriptions column={2} bordered size="small" style={{ marginBottom: 20 }}>
                <Descriptions.Item label="预设">{presetLabels[policy.preset] || policy.preset}</Descriptions.Item>
                <Descriptions.Item label="端口">
                    {portProfileLabels[policy.port_profile] || policy.port_profile}
                    {policy.port_profile === 'custom' && policy.custom_ports ? `（${policy.custom_ports}）` : ''}
                </Descriptions.Item>
                <Descriptions.Item label="扫描方式">{scanMethodLabels[policy.scan_method] || policy.scan_method}</Descriptions.Item>
                <Descriptions.Item label="强度">{intensityLabels[policy.intensity] || policy.intensity}</Descriptions.Item>
                <Descriptions.Item label="能力" span={2}>
                    <Space wrap size={[4, 4]}>
                        {capabilities.map((label) => <Tag key={label}>{label}</Tag>)}
                        {capabilities.length === 0 && <Text type="secondary">仅基础发现</Text>}
                    </Space>
                </Descriptions.Item>
            </Descriptions>
        </>
    );
}

type Props = {
    open: boolean;
    loading: boolean;
    detail: API.TaskDetailResponse | null;
    configRevisions: API.TaskConfigRevision[];
    canManageTasks: boolean;
    onClose: () => void;
    onUpdateConfig: () => void;
};

export default function TaskDetailDrawer({
    open, loading, detail, configRevisions, canManageTasks, onClose, onUpdateConfig,
}: Props) {
    return (
        <Drawer
            title={
                detail ? (
                    <Space>
                        <RocketOutlined style={{ color: '#10b981' }} />
                        <span>{detail.task.name}</span>
                        {renderTaskStatusTag(detail.task.status)}
                    </Space>
                ) : '任务详情'
            }
            open={open}
            extra={detail && canManageTasks && !detail.task.archived_at ? (
                <Button icon={<EditOutlined />} onClick={onUpdateConfig}>更新配置</Button>
            ) : null}
            onClose={onClose}
            width={920}
            destroyOnClose
        >
            {loading ? (
                <div style={{ display: 'flex', justifyContent: 'center', padding: '80px 0' }}>
                    <Spin size="large" />
                </div>
            ) : detail ? (
                <div>
                    <TaskStageOverview detail={detail} />
                    <Row gutter={16} style={{ marginBottom: 24 }}>
                        <Col span={6}>
                            <div style={{ background: 'linear-gradient(135deg, #0ea5e9 0%, #06b6d4 100%)', borderRadius: 12, padding: '20px 16px', color: '#fff' }}>
                                <Statistic
                                    title={<span style={{ color: 'rgba(255,255,255,0.85)', fontSize: 12 }}>进度</span>}
                                    value={detail.task.total_targets > 0
                                        ? Math.round((detail.task.completed_targets / detail.task.total_targets) * 100)
                                        : detail.task.total_chunks > 0
                                            ? Math.round((detail.task.completed_chunks / detail.task.total_chunks) * 100)
                                            : 0}
                                    suffix="%"
                                    valueStyle={{ color: '#fff', fontSize: 28, fontWeight: 700 }}
                                />
                            </div>
                        </Col>
                        <Col span={6}>
                            <div style={{ background: 'linear-gradient(135deg, #3b82f6 0%, #6366f1 100%)', borderRadius: 12, padding: '20px 16px', color: '#fff' }}>
                                <Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)', fontSize: 12 }}>资产</span>} value={detail.result_stats.assets} valueStyle={{ color: '#fff', fontSize: 28, fontWeight: 700 }} />
                            </div>
                        </Col>
                        <Col span={6}>
                            <div style={{ background: 'linear-gradient(135deg, #06b6d4 0%, #14b8a6 100%)', borderRadius: 12, padding: '20px 16px', color: '#fff' }}>
                                <Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)', fontSize: 12 }}>指纹</span>} value={detail.result_stats.fingerprints} valueStyle={{ color: '#fff', fontSize: 28, fontWeight: 700 }} />
                            </div>
                        </Col>
                        <Col span={6}>
                            <div style={{ background: 'linear-gradient(135deg, #ef4444 0%, #f97316 100%)', borderRadius: 12, padding: '20px 16px', color: '#fff' }}>
                                <Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)', fontSize: 12 }}>漏洞</span>} value={detail.result_stats.vulns} valueStyle={{ color: '#fff', fontSize: 28, fontWeight: 700 }} />
                            </div>
                        </Col>
                    </Row>

                    {detail.result_stats.vulns > 0 && (
                        <div style={{ marginBottom: 20 }}>
                            <Space wrap>
                                {Object.entries(detail.result_stats.severity).map(([sev, count]) => {
                                    const colorMap: Record<string, string> = {
                                        Critical: '#ef4444', High: '#f97316', Medium: '#f59e0b',
                                        Low: '#3b82f6', Info: '#6b7280', Unknown: '#94a3b8',
                                    };
                                    return (
                                        <Tag key={sev} color={colorMap[sev] || '#94a3b8'} style={{ fontSize: 12 }}>
                                            {sev}: {count}
                                        </Tag>
                                    );
                                })}
                            </Space>
                        </div>
                    )}

                    <Descriptions column={2} bordered size="small" style={{ marginBottom: 20 }}>
                        <Descriptions.Item label="任务 ID">
                            <Text copyable style={{ fontFamily: 'monospace', fontSize: 12 }}>{detail.task.id}</Text>
                        </Descriptions.Item>
                        <Descriptions.Item label="优先级">
                            {({ 0: 'P0 / 紧急', 1: 'P1 / 普通', 2: 'P2 / 低' } as Record<number, string>)[detail.task.priority] || String(detail.task.priority)}
                        </Descriptions.Item>
                        <Descriptions.Item label="目标进度">
                            <Space>
                                <Progress
                                    type="circle"
                                    size={40}
                                    percent={detail.task.total_targets > 0
                                        ? Math.round((detail.task.completed_targets / detail.task.total_targets) * 100)
                                        : 0}
                                />
                                <Text style={{ fontSize: 12 }}>
                                    {detail.task.completed_targets}/{detail.task.total_targets} 目标
                                </Text>
                            </Space>
                        </Descriptions.Item>
                        <Descriptions.Item label="批次进度">
                            <Space>
                                <Progress
                                    type="circle"
                                    size={40}
                                    percent={detail.task.total_chunks > 0
                                        ? Math.round((detail.task.completed_chunks / detail.task.total_chunks) * 100)
                                        : 0}
                                />
                                <Text style={{ fontSize: 12 }}>
                                    {detail.task.completed_chunks}/{detail.task.total_chunks} 批次
                                </Text>
                            </Space>
                        </Descriptions.Item>
                        <Descriptions.Item label="超时时间">
                            {detail.task.timeout_sec > 0 ? `${detail.task.timeout_sec} 秒` : '未设置'}
                        </Descriptions.Item>
                        <Descriptions.Item label="规则版本">
                            <Tag color="blue">{detail.task.rule_version || '-'}</Tag>
                        </Descriptions.Item>
                        <Descriptions.Item label="创建时间">
                            {detail.task.created_at}
                        </Descriptions.Item>
                        {detail.task.archived_at && (
                            <Descriptions.Item label="归档时间" span={2}>
                                <Tag icon={<InboxOutlined />}>已归档</Tag>
                                {detail.task.archived_at}
                            </Descriptions.Item>
                        )}
                    </Descriptions>

                    {detail.passive_collection && (detail.passive_collection.active || detail.passive_collection.domains_total > 0) && (
                        <div style={{ marginBottom: 20, padding: 12, border: '1px solid #91caff', borderRadius: 6, background: '#f0f7ff' }}>
                            <Space direction="vertical" style={{ width: '100%' }} size={6}>
                                <Space wrap>
                                    <Typography.Text strong style={{ fontSize: 13 }}>被动子域收集（Server 端派发前）</Typography.Text>
                                    {detail.passive_collection.active
                                        ? <Tag color="processing">收集中（{detail.passive_collection.state}）</Tag>
                                        : <Tag color={detail.passive_collection.state === 'failed' ? 'orange' : 'green'}>
                                            {detail.passive_collection.state === 'failed' ? '超时/失败，已回退 Agent 端收集' : '已完成并派发'}
                                        </Tag>}
                                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                                        域名 {detail.passive_collection.domains_done}/{detail.passive_collection.domains_total}
                                        · 等待收集后派发的域名批次 {detail.passive_collection.held_batches.length} 个
                                    </Typography.Text>
                                </Space>
                                <Progress
                                    percent={detail.passive_collection.domains_total > 0
                                        ? Math.min(100, Math.round((detail.passive_collection.domains_done / detail.passive_collection.domains_total) * 100))
                                        : 0}
                                    size="small"
                                    status={detail.passive_collection.active ? 'active' : undefined}
                                />
                                {detail.passive_collection.held_batches.map((held) => {
                                    const heldDomains = held.domains || [];
                                    return (
                                        <Space key={held.attempt_id} size={6} wrap style={{ fontSize: 12 }}>
                                            <Tag style={{ fontSize: 11 }}>
                                                {(held.batch_id || '').length > 28 ? `${held.batch_id.slice(0, 28)}…` : held.batch_id}
                                            </Tag>
                                            <Typography.Text type="secondary">
                                                {held.domains_done}/{heldDomains.length} 域名
                                            </Typography.Text>
                                            <Tooltip title={heldDomains.join('、')}>
                                                <Typography.Text style={{ fontSize: 11, maxWidth: 360 }} ellipsis>
                                                    {heldDomains.join('、') || '-'}
                                                </Typography.Text>
                                            </Tooltip>
                                        </Space>
                                    );
                                })}
                            </Space>
                        </div>
                    )}

                    {(detail.passive_collection?.results?.length ?? 0) > 0 && (
                        <div style={{ marginBottom: 20 }}>
                            <Divider orientation="left" style={{ fontSize: 13 }}>被动收集结果</Divider>
                            <Table
                                dataSource={detail.passive_collection?.results}
                                rowKey={(row) => row.domain}
                                size="small"
                                pagination={false}
                                columns={[
                                    { title: '主域名', dataIndex: 'domain', key: 'domain', width: 180 },
                                    {
                                        title: '查询到的子域名',
                                        dataIndex: 'subdomains',
                                        render: (subs: string[]) => (
                                            <Space wrap size={[4, 4]}>
                                                {(subs || []).slice(0, 6).map((sub) => (
                                                    <Tag key={sub} style={{ fontSize: 11 }}>{sub}</Tag>
                                                ))}
                                                {(subs || []).length > 6 && (
                                                    <Tag key="__more" style={{ fontSize: 11 }}>
                                                        +{subs.length - 6} 个（展开行查看全部）
                                                    </Tag>
                                                )}
                                            </Space>
                                        ),
                                    },
                                ]}
                                expandable={{
                                    rowExpandable: (record) => (record.subdomains?.length ?? 0) > 6,
                                    expandedRowRender: (record) => (
                                        <Space wrap size={[4, 4]}>
                                            {(record.subdomains || []).map((sub) => (
                                                <Tag key={sub} style={{ fontSize: 11 }}>{sub}</Tag>
                                            ))}
                                        </Space>
                                    ),
                                }}
                            />
                        </div>
                    )}

                    {detail.task.original_targets && (
                        <>
                            <Divider orientation="left" style={{ fontSize: 13 }}>
                                <AimOutlined style={{ marginRight: 4 }} />原始目标
                            </Divider>
                            <pre style={{
                                background: '#f1f5f9', border: '1px solid #e2e8f0',
                                borderRadius: 8, padding: 12, fontSize: 12,
                                maxHeight: 160, overflow: 'auto', whiteSpace: 'pre-wrap',
                                fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
                                color: '#334155',
                            }}>
                                {detail.task.original_targets}
                            </pre>
                        </>
                    )}

                    {detail.scan_policy?.policy && <ScanPolicySummary policy={detail.scan_policy.policy} />}

                    {detail.coverage_explanation && (
                        <TaskCoverageSection explanation={detail.coverage_explanation} />
                    )}

                    {configRevisions.length > 0 && (
                        <>
                            <Divider orientation="left" style={{ fontSize: 13 }}>配置修订历史</Divider>
                            <Table
                                dataSource={configRevisions}
                                rowKey="version"
                                size="small"
                                pagination={false}
                                style={{ marginBottom: 12 }}
                                columns={[
                                    { title: '版本', dataIndex: 'version', key: 'version', width: 80, render: (version: number) => <Tag color="cyan">v{version}</Tag> },
                                    { title: '说明', dataIndex: 'change_note', key: 'change_note', render: (note: string) => note || '-' },
                                    { title: '操作者', dataIndex: 'created_by', key: 'created_by', width: 120 },
                                    { title: '时间', dataIndex: 'created_at', key: 'created_at', width: 180 },
                                ]}
                            />
                        </>
                    )}

                    {detail.audits?.length > 0 && (
                        <>
                            <Divider orientation="left" style={{ fontSize: 13 }}>
                                <AuditOutlined style={{ marginRight: 4 }} />操作审计
                            </Divider>
                            <Table
                                dataSource={detail.audits}
                                rowKey="id"
                                size="small"
                                pagination={false}
                                style={{ marginBottom: 12 }}
                                columns={[
                                    {
                                        title: '操作', dataIndex: 'action', key: 'action', width: 90,
                                        render: (action: string) => auditActionLabels[action] || action,
                                    },
                                    {
                                        title: '状态变化', key: 'status_change',
                                        render: (_, audit) => (
                                            <Space size={4}>
                                                <Tag>{audit.before_status || '-'}</Tag>
                                                <Text type="secondary">→</Text>
                                                <Tag color="blue">{audit.after_status || '-'}</Tag>
                                            </Space>
                                        ),
                                    },
                                    { title: '操作者', dataIndex: 'operator_id', key: 'operator_id', width: 120 },
                                    { title: '时间', dataIndex: 'created_at', key: 'created_at', width: 180 },
                                ]}
                            />
                        </>
                    )}

                    {detail.timing && <TaskTimingPanel timing={detail.timing} stageLabels={SCAN_STAGE_LABELS} />}
                    <CredentialFindingsPanel taskId={detail.task.id} />
                </div>
            ) : null}
        </Drawer>
    );
}
