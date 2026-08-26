import React from 'react';
import { Alert, Col, Divider, Row, Space, Statistic, Table, Tag, Tooltip, Typography } from 'antd';
import { RadarChartOutlined } from '@ant-design/icons';
import { COVERAGE_GAP_STATUS_LABELS, coverageReasonText, scanStageLabel } from '../taskCoverageReasons';
import { coverageLinkMeta, coverageLinkStatusLabels } from './shared';

const { Text } = Typography;

export default function TaskCoverageSection({ explanation }: { explanation: API.TaskCoverageExplanation }) {
    const hasContent = explanation.items.length > 0
        || explanation.invalidations.length > 0
        || Object.values(explanation.summary).some((value) => value > 0);
    if (!hasContent) return null;

    return (
        <>
            <Divider orientation="left" style={{ fontSize: 13 }}>
                <RadarChartOutlined style={{ marginRight: 4 }} />扫描复用与覆盖
            </Divider>
            <Row gutter={[12, 12]} style={{ marginBottom: 12 }}>
                <Col xs={12} md={8} lg={4}>
                    <Statistic title="实际执行工作项" value={explanation.summary.executed_work_items} valueStyle={{ color: '#1677ff', fontSize: 22 }} />
                </Col>
                <Col xs={12} md={8} lg={4}>
                    <Statistic title="历史复用阶段" value={explanation.summary.reused_stages} valueStyle={{ color: '#16a34a', fontSize: 22 }} />
                </Col>
                <Col xs={12} md={8} lg={4}>
                    <Statistic title="执行中关联" value={explanation.summary.in_flight_work_items} valueStyle={{ color: '#d97706', fontSize: 22 }} />
                </Col>
                <Col xs={12} md={8} lg={4}>
                    <Statistic title="已跳过阶段" value={explanation.summary.skipped_stages || 0} valueStyle={{ fontSize: 22 }} />
                </Col>
                <Col xs={12} md={8} lg={4}>
                    <Statistic title="阶段失败" value={explanation.summary.failed_stages || 0} valueStyle={{ color: '#c2410c', fontSize: 22 }} />
                </Col>
                <Col xs={12} md={8} lg={4}>
                    <Statistic
                        title="失效 / 过期"
                        value={(explanation.summary.invalidated_stages || 0) + (explanation.summary.expired_stages || 0)}
                        valueStyle={{ color: '#dc2626', fontSize: 22 }}
                    />
                </Col>
            </Row>
            <Alert
                type={explanation.summary.saved_stages > 0 ? 'success' : 'info'}
                showIcon
                message={explanation.summary.saved_stages > 0
                    ? `已节省 ${explanation.summary.saved_stages} 个扫描阶段、${explanation.summary.saved_targets} 个完整目标`
                    : '本次没有复用历史覆盖'}
                description="已跳过表示该批次未执行对应阶段（例如 URL 批次不做 ICMP）；阶段失败才是探测本身没有完成。失效/过期只影响下次是否复用，不代表这次漏洞或资产结果丢失。"
                style={{ marginBottom: 12 }}
            />
            {explanation.items.length > 0 && (
                <Table
                    aria-label="扫描复用明细"
                    dataSource={explanation.items}
                    rowKey={(item) => `${item.link_type}-${item.normalized_target}-${item.stage}-${item.source.attempt_id}-${item.created_at}`}
                    size="small"
                    pagination={false}
                    scroll={{ x: 980 }}
                    style={{ marginBottom: 12 }}
                    columns={[
                        {
                            title: '处理方式', dataIndex: 'link_type', key: 'link_type', width: 110,
                            render: (value: string) => {
                                const meta = coverageLinkMeta[value] || { label: value || '未知', color: 'default' };
                                return <Tag color={meta.color}>{meta.label}</Tag>;
                            },
                        },
                        {
                            title: '状态', dataIndex: 'status', key: 'status', width: 105,
                            render: (value: string) => {
                                const meta = coverageLinkStatusLabels[value] || { label: value || '未知', color: 'default' };
                                return <Tag color={meta.color}>{meta.label}</Tag>;
                            },
                        },
                        { title: '目标', dataIndex: 'normalized_target', key: 'normalized_target', ellipsis: true, width: 230, render: (value: string) => value || '-' },
                        { title: '阶段', dataIndex: 'stage', key: 'stage', width: 120, render: (value: string) => scanStageLabel(value) },
                        { title: '网络区域', dataIndex: 'network_zone', key: 'network_zone', width: 120, render: (value: string) => <Tag>{value || '-'}</Tag> },
                        {
                            title: '来源', key: 'source', ellipsis: true, width: 220,
                            render: (_, item: API.TaskCoverageExplanationItem) => item.source.task_id ? (
                                <Tooltip title={`${item.source.task_id} / ${item.source.batch_id || '-'} / ${item.source.attempt_id || '-'}`}>
                                    <Text>{item.source.task_name || item.source.task_id}</Text>
                                </Tooltip>
                            ) : <Text type="secondary">-</Text>,
                        },
                        { title: '原因', dataIndex: 'reason', key: 'reason', ellipsis: true, width: 200, render: (value: string) => coverageReasonText(value) },
                    ]}
                />
            )}
            {explanation.items_truncated && (
                <Text type="secondary">仅展示最近 100 条复用关联，顶部汇总为完整计数。</Text>
            )}
            {explanation.invalidations.length > 0 && (
                <>
                    <Text strong style={{ display: 'block', margin: '12px 0 8px' }}>覆盖缺口与原因</Text>
                    <Table
                        aria-label="扫描覆盖缺口明细"
                        dataSource={explanation.invalidations}
                        rowKey={(item) => `${item.normalized_target}-${item.stage}-${item.invalidated_at}`}
                        size="small"
                        pagination={false}
                        scroll={{ x: 1100 }}
                        style={{ marginBottom: 12 }}
                        columns={[
                            { title: '目标', dataIndex: 'normalized_target', key: 'normalized_target', ellipsis: true, width: 220 },
                            { title: '阶段', dataIndex: 'stage', key: 'stage', width: 110, render: (value: string) => scanStageLabel(value) },
                            {
                                title: '状态', dataIndex: 'status', key: 'status', width: 90,
                                render: (value: string) => {
                                    const meta = COVERAGE_GAP_STATUS_LABELS[value] || { label: value || '未知', color: 'default' };
                                    return <Tag color={meta.color}>{meta.label}</Tag>;
                                },
                            },
                            {
                                title: '指纹', key: 'fingerprints', width: 200,
                                render: (_, item: API.TaskCoverageInvalidationItem) => renderCoverageNameList(item.fingerprints),
                            },
                            {
                                title: '匹配 POC', key: 'matched_pocs', width: 220,
                                render: (_, item: API.TaskCoverageInvalidationItem) => (
                                    item.stage === 'risk_validation' && !(item.matched_pocs && item.matched_pocs.length)
                                        ? <Text type="secondary">未匹配</Text>
                                        : renderCoverageNameList(item.matched_pocs)
                                ),
                            },
                            { title: '原因', dataIndex: 'reason', key: 'reason', ellipsis: true, width: 360, render: (value: string) => coverageReasonText(value) },
                        ]}
                    />
                    {explanation.invalidations_truncated && (
                        <Text type="secondary">仅展示最近 100 条覆盖缺口，顶部汇总为完整计数。</Text>
                    )}
                </>
            )}
        </>
    );
}

function renderCoverageNameList(values?: string[]) {
    if (!values || values.length === 0) {
        return <Text type="secondary">-</Text>;
    }
    const shown = values.slice(0, 6);
    const extra = values.length - shown.length;
    return (
        <Space size={[4, 4]} wrap>
            {shown.map((value) => <Tag key={value}>{value}</Tag>)}
            {extra > 0 ? <Tooltip title={values.slice(6).join('、')}><Tag>+{extra}</Tag></Tooltip> : null}
        </Space>
    );
}
