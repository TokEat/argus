import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Alert, App, Button, Empty, Input, List, Modal, Select, Space, Spin, Tag, Typography } from 'antd';
import { ApartmentOutlined, BugOutlined, CheckOutlined, ScanOutlined } from '@ant-design/icons';
import { addWorkflowDict, getFingerprintDictPage, getWorkflowDictPage, updateWorkflowDict } from '../../services/api';

const { Text } = Typography;
const DEFAULT_WORKFLOW_TYPES = ['root', 'base'];

export interface WorkflowLinkTarget {
    product: string;
    type: string[];
    pocs: string[];
    fingerprint_bound: boolean;
    isNew: boolean;
}

interface PocWorkflowLinkModalProps {
    open: boolean;
    pocFileName: string;
    onClose: () => void;
    onLinked: () => void;
}

export const normalizePocWorkflowRef = (fileName: string): string =>
    fileName.trim().replace(/\.(ya?ml)$/i, '');

const uniqueStrings = (values: string[]) => Array.from(new Set(values.filter(Boolean)));
const normalizePocWorkflowRefs = (values: string[]) => uniqueStrings(values.map(normalizePocWorkflowRef));

const workflowToTarget = (workflow: API.WorkflowSummary): WorkflowLinkTarget => ({
    product: workflow.product,
    type: workflow.type && workflow.type.length > 0 ? workflow.type : DEFAULT_WORKFLOW_TYPES,
    pocs: workflow.pocs || [],
    fingerprint_bound: workflow.fingerprint_bound,
    isNew: false,
});

const PocWorkflowLinkModal: React.FC<PocWorkflowLinkModalProps> = ({
    open,
    pocFileName,
    onClose,
    onLinked,
}) => {
    const { message } = App.useApp();
    const [query, setQuery] = useState('');
    const [targets, setTargets] = useState<WorkflowLinkTarget[]>([]);
    const [selectedProduct, setSelectedProduct] = useState('');
    const [selectedTypes, setSelectedTypes] = useState<string[]>(DEFAULT_WORKFLOW_TYPES);
    const [loading, setLoading] = useState(false);
    const [saving, setSaving] = useState(false);
    const requestSeq = useRef(0);

    const normalizedPoc = useMemo(() => normalizePocWorkflowRef(pocFileName), [pocFileName]);
    const selectedTarget = targets.find((item) => item.product === selectedProduct);

    const loadTargets = async (keyword: string) => {
        const requestID = requestSeq.current + 1;
        requestSeq.current = requestID;
        setLoading(true);
        try {
            const [workflowPage, fingerprintPage] = await Promise.all([
                getWorkflowDictPage({
                    scope: 'all',
                    q: keyword || undefined,
                    page: 1,
                    page_size: 20,
                }),
                getFingerprintDictPage({
                    all: '1',
                    q: keyword || undefined,
                    page: 1,
                    page_size: 20,
                }),
            ]);

            if (requestID !== requestSeq.current) return;
            const byProduct = new Map<string, WorkflowLinkTarget>();
            (workflowPage.items || []).forEach((workflow) => {
                byProduct.set(workflow.product, workflowToTarget(workflow));
            });
            (fingerprintPage.items || []).forEach((fingerprint) => {
                if (!byProduct.has(fingerprint.product)) {
                    byProduct.set(fingerprint.product, {
                        product: fingerprint.product,
                        type: DEFAULT_WORKFLOW_TYPES,
                        pocs: [],
                        fingerprint_bound: true,
                        isNew: true,
                    });
                }
            });
            setTargets(Array.from(byProduct.values()).sort((a, b) => a.product.localeCompare(b.product)));
        } catch {
            if (requestID === requestSeq.current) message.error('加载 Workflow 候选失败');
        } finally {
            if (requestID === requestSeq.current) setLoading(false);
        }
    };

    useEffect(() => {
        if (!open) return undefined;
        const timer = window.setTimeout(() => {
            loadTargets(query.trim());
        }, 200);
        return () => window.clearTimeout(timer);
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [open, query]);

    useEffect(() => {
        if (!open) {
            setQuery('');
            setTargets([]);
            setSelectedProduct('');
            setSelectedTypes(DEFAULT_WORKFLOW_TYPES);
        }
    }, [open]);

    const selectTarget = (target: WorkflowLinkTarget) => {
        setSelectedProduct(target.product);
        setSelectedTypes(target.type && target.type.length > 0 ? target.type : DEFAULT_WORKFLOW_TYPES);
    };

    const handleSave = async () => {
        if (!selectedTarget || selectedTypes.length === 0) {
            message.error('请选择 Workflow product 和触发阶段');
            return;
        }
        setSaving(true);
        try {
            if (selectedTarget.isNew) {
                await addWorkflowDict({
                    product: selectedTarget.product,
                    type: selectedTypes,
                    pocs: [normalizedPoc],
                });
            } else {
                await updateWorkflowDict(selectedTarget.product, {
                    product: selectedTarget.product,
                    type: selectedTypes,
                    pocs: normalizePocWorkflowRefs([...selectedTarget.pocs, normalizedPoc]),
                });
            }
            message.success('POC 已关联到 Workflow');
            onLinked();
            onClose();
        } catch {
            message.error('关联失败，Workflow 可能已变化，请刷新后重试');
            await loadTargets(query.trim());
        } finally {
            setSaving(false);
        }
    };

    return (
        <Modal
            title="关联 POC 到 Workflow"
            open={open}
            onCancel={onClose}
            destroyOnHidden
            width={720}
            footer={
                <Space>
                    <Button onClick={onClose}>取消</Button>
                    <Button type="primary" loading={saving} disabled={!selectedTarget} onClick={handleSave}>
                        保存关联
                    </Button>
                </Space>
            }
        >
            <Space direction="vertical" size={12} style={{ width: '100%' }}>
                <Alert
                    type="warning"
                    showIcon
                    message="关联后会修改 workflow.yaml 草稿"
                    description={(
                        <span>
                            当前 POC <Text code>{normalizedPoc}</Text> 会追加到选定 product 的 Workflow，发布仍沿用现有规则审核流程。
                        </span>
                    )}
                />
                <Input
                    placeholder="搜索 Workflow 或 Fingerprint product"
                    value={query}
                    onChange={(event) => {
                        setQuery(event.target.value);
                        setSelectedProduct('');
                    }}
                    allowClear
                />
                <div style={{ minHeight: 190 }}>
                    {loading ? (
                        <div style={{ padding: '40px 0', textAlign: 'center' }}>
                            <Spin />
                        </div>
                    ) : targets.length === 0 ? (
                        <Empty description="输入 product 关键字查找 Workflow 或 Fingerprint" image={Empty.PRESENTED_IMAGE_SIMPLE} />
                    ) : (
                        <List
                            size="small"
                            bordered
                            dataSource={targets}
                            renderItem={(target) => {
                                const selected = target.product === selectedProduct;
                                const alreadyLinked = normalizePocWorkflowRefs(target.pocs).includes(normalizedPoc);
                                return (
                                    <List.Item
                                        actions={[
                                            <Button
                                                key="select"
                                                size="small"
                                                type={selected ? 'primary' : 'default'}
                                                icon={selected ? <CheckOutlined /> : undefined}
                                                onClick={() => selectTarget(target)}
                                            >
                                                {selected ? '已选择' : '选择'}
                                            </Button>,
                                        ]}
                                    >
                                        <Space direction="vertical" size={4} style={{ width: '100%' }}>
                                            <Space wrap>
                                                <Button type="link" style={{ padding: 0 }} onClick={() => selectTarget(target)}>
                                                    {target.product}
                                                </Button>
                                                {target.isNew ? (
                                                    <Tag icon={<ScanOutlined />} color="gold">仅有指纹，将新建 Workflow</Tag>
                                                ) : (
                                                    <Tag icon={<ApartmentOutlined />} color="blue">已有 Workflow</Tag>
                                                )}
                                                <Tag icon={<BugOutlined />} color={alreadyLinked ? 'green' : 'default'}>
                                                    {alreadyLinked ? '已包含当前 POC' : `${target.pocs.length} 个 POC`}
                                                </Tag>
                                                <Tag color={target.fingerprint_bound ? 'green' : 'orange'}>
                                                    {target.fingerprint_bound ? '指纹已配置' : '指纹缺失'}
                                                </Tag>
                                            </Space>
                                            <Text type="secondary" style={{ fontSize: 12 }}>
                                                触发阶段：{target.type.join(', ') || '未配置'}
                                            </Text>
                                        </Space>
                                    </List.Item>
                                );
                            }}
                        />
                    )}
                </div>
                <Select
                    mode="multiple"
                    style={{ width: '100%' }}
                    value={selectedTypes}
                    onChange={setSelectedTypes}
                    disabled={!selectedTarget}
                    placeholder="选择触发阶段"
                    options={[
                        { label: 'root — 根路径', value: 'root' },
                        { label: 'base — 完整路径', value: 'base' },
                        { label: 'dir — 逐级目录', value: 'dir' },
                        { label: 'dir-fallback — 目录探测 200 仅记录路径存在', value: 'dir-fallback' },
                    ]}
                />
            </Space>
        </Modal>
    );
};

export default PocWorkflowLinkModal;
