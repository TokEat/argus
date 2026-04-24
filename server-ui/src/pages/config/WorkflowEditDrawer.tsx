import React, { useEffect, useMemo, useState } from 'react';
import {
    Drawer,
    Button,
    Space,
    Tag,
    App,
    Form,
    Select,
    Card,
    List,
    Popconfirm,
    Empty,
    Tooltip,
    Divider,
    Badge,
    AutoComplete,
    Alert,
} from 'antd';
import {
    PlusOutlined,
    EditOutlined,
    DeleteOutlined,
    ApartmentOutlined,
    ScanOutlined,
    BugOutlined,
    CheckOutlined,
    WarningOutlined,
    GlobalOutlined,
} from '@ant-design/icons';
import {
    addWorkflowDict,
    updateWorkflowDict,
    listArsenals,
    getFingerprintDict,
    deleteArsenal,
    addFingerprintDict,
    updateFingerprintDict,
    deleteFingerprintDict,
} from '../../services/api';
import PocInlineEditor from './PocInlineEditor';
import FingerprintInlineEditor from './FingerprintInlineEditor';

interface WorkflowEditDrawerProps {
    open: boolean;
    /** 要编辑的 workflow product key；为空表示新建 */
    workflow?: API.WorkflowItem;
    /** 是否为通用探测规则模式 */
    isGeneralPoc?: boolean;
    onClose: () => void;
    onSaved?: () => void;
}

/**
 * 三栏抽屉：
 *  - 顶部：Workflow 基本信息（product / type）
 *  - 中部：指纹绑定状态与编辑入口
 *  - 底部：关联 POC 列表 + 添加 / 新建 POC
 *
 * 一个 Drawer 内即可对 Workflow / Fingerprint / POC 三类弹药做修改，
 * 无需在多个 Tab 之间跳转。
 */
const GENERAL_POC_PREFIX = 'General-Poc-';

const WorkflowEditDrawer: React.FC<WorkflowEditDrawerProps> = ({
    open,
    workflow,
    isGeneralPoc: isGPMode = false,
    onClose,
    onSaved,
}) => {
    const isNew = !workflow;
    const { message, modal } = App.useApp();
    const [form] = Form.useForm();
    const [pocOptions, setPocOptions] = useState<{ label: string; value: string }[]>([]);
    const [fingerprintProducts, setFingerprintProducts] = useState<Set<string>>(new Set());
    const [pocEditor, setPocEditor] = useState<{ open: boolean; fileName?: string; suggested?: string }>({ open: false });
    const [fpEditor, setFpEditor] = useState<{ open: boolean; product?: string; isNew?: boolean }>({ open: false });
    const [saving, setSaving] = useState(false);

    // POC 列表完全独立于 Form 之外管理，
    // 避免「修改 product 会让 AntD Form 误刷新 pocs 字段」的问题。
    // 保存时直接使用 pocsState，用户不动它就一定是原值。
    const [pocsState, setPocsState] = useState<string[]>([]);
    const [watchedProduct, setWatchedProduct] = useState<string>('');

    const loadRefData = async () => {
        try {
            const [pocs, fps] = await Promise.all([
                listArsenals('poc', true, true),
                getFingerprintDict(),
            ]);
            // 下拉选项使用不带 .yaml 后缀的名称（与 workflow.yaml 内存储习惯一致）。
            const opts: { label: string; value: string }[] = [];
            (pocs || []).forEach((p) => {
                const stripped = p.FileName.replace(/\.(ya?ml)$/i, '');
                opts.push({ label: p.FileName, value: stripped });
            });
            setPocOptions(opts);
            setFingerprintProducts(new Set((fps || []).map((f) => f.product)));
        } catch {
            message.error('加载关联弹药库失败');
        }
    };

    useEffect(() => {
        if (!open) return;
        loadRefData();
        if (isNew) {
            form.setFieldsValue({
                product: isGPMode ? GENERAL_POC_PREFIX : '',
                type: isGPMode ? ['root', 'base'] : ['web'],
            });
            setWatchedProduct(isGPMode ? GENERAL_POC_PREFIX : '');
            setPocsState([]);
        } else {
            form.setFieldsValue({
                product: workflow!.product,
                type: workflow!.type || [],
            });
            setWatchedProduct(workflow!.product);
            setPocsState(workflow!.pocs || []);
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [open, workflow]);

    const isCurrentGP = watchedProduct.startsWith(GENERAL_POC_PREFIX);

    const fingerprintBound = useMemo(
        () => !!watchedProduct && !isCurrentGP && fingerprintProducts.has(watchedProduct),
        [watchedProduct, fingerprintProducts, isCurrentGP],
    );

    const handleSaveWorkflow = async () => {
        try {
            const values = await form.validateFields();
            // POC 列表独立于 Form 之外，不会被 AntD Form 误重置
            const payload: API.WorkflowItem = {
                product: (values.product || '').trim(),
                type: values.type || [],
                pocs: pocsState,
            };
            if (!payload.product) {
                message.error('请填写 product 名称');
                return;
            }
            // 检测是否是「重命名」场景
            const isRename = !isNew && payload.product !== workflow!.product;
            if (isRename) {
                const oldName = workflow!.product;
                const newName = payload.product;
                const oldFpExists = fingerprintProducts.has(oldName);
                const newFpExists = fingerprintProducts.has(newName);
                // 拉取一下旧名对应的指纹完整规则（用于迁移）
                let oldFpRules: string[] = [];
                if (oldFpExists) {
                    try {
                        const all = await getFingerprintDict();
                        oldFpRules = all?.find((f) => f.product === oldName)?.rules || [];
                    } catch { /* ignore */ }
                }
                const proceed = await new Promise<'cancel' | 'rename_only' | 'rename_with_fp'>((resolve) => {
                    modal.confirm({
                        title: '重命名 Workflow Product？',
                        width: 560,
                        content: (
                            <div style={{ fontSize: 13, lineHeight: 1.7 }}>
                                <p>你要把 Workflow product 从 <Tag color="orange">{oldName}</Tag>改为 <Tag color="green">{newName}</Tag></p>
                                <p style={{ marginTop: 8 }}>该操作会：</p>
                                <ul style={{ paddingLeft: 18 }}>
                                    <li>workflow.yaml 中的 key 被重命名，<b>{payload.pocs.length} 个 POC 关联会完整保留</b></li>
                                    {oldFpExists && !newFpExists && (
                                        <li style={{ color: '#ef4444' }}>
                                            ⚠️ 指纹库中还存在 product「{oldName}」的 {oldFpRules.length} 条识别规则，
                                            但<b>不会自动跟随重命名</b>。重命名后，扫描器识别资产时
                                            仍会上报 product=「{oldName}」，与新 Workflow 名不匹配 →
                                            <b>POC 不会被触发</b>。
                                        </li>
                                    )}
                                    {newFpExists && (
                                        <li style={{ color: '#10b981' }}>✓ 指纹库中已存在新名「{newName}」的识别规则</li>
                                    )}
                                    {!oldFpExists && !newFpExists && (
                                        <li style={{ color: '#f59e0b' }}>⚠️ 旧名与新名都没有指纹识别规则，该 Workflow 仍不会被触发</li>
                                    )}
                                </ul>
                            </div>
                        ),
                        okText: oldFpExists && !newFpExists ? '仅重命名 Workflow' : '确认重命名',
                        cancelText: '取消',
                        okButtonProps: { danger: oldFpExists && !newFpExists },
                        onOk: () => resolve('rename_only'),
                        onCancel: () => resolve('cancel'),
                        ...(oldFpExists && !newFpExists
                            ? {
                                footer: undefined,
                                // 使用 closable + 自定义按钮不适合这里，改用 额外提示让用户点「取消」后手动调整
                            }
                            : {}),
                    });
                });
                if (proceed === 'cancel') return;
                // 执行 Workflow 重命名
                setSaving(true);
                await updateWorkflowDict(oldName, payload);
                // 如果需要同步迁移指纹规则，另外处理（这里为后期预留，当前版本默认不迁移）
                if (proceed === 'rename_with_fp' && oldFpExists && !newFpExists) {
                    try {
                        await addFingerprintDict({ product: newName, rules: oldFpRules });
                        await deleteFingerprintDict(oldName);
                        message.success(`指纹规则已同步迁移到「${newName}」`);
                    } catch {
                        message.warning('指纹规则迁移失败，请手动处理');
                    }
                }
                message.success('Workflow 已保存');
                onSaved?.();
                onClose();
                return;
            }
            setSaving(true);
            if (isNew) {
                await addWorkflowDict(payload);
                message.success('Workflow 已创建（已触发规则版本更新）');
            } else {
                await updateWorkflowDict(workflow!.product, payload);
                message.success('Workflow 已保存（已触发规则版本更新）');
            }
            onSaved?.();
            onClose();
        } catch (err: unknown) {
            const e = err as { errorFields?: unknown };
            if (e?.errorFields) return;
            message.error(typeof err === 'string' ? err : 'Workflow 保存失败');
        } finally {
            setSaving(false);
        }
    };

    // 使用占位以避免 eslint 有未使用变量告警（如未来扩展 rename_with_fp 选项）
    void updateFingerprintDict;

    const handleAddNewPoc = () => {
        const product = (form.getFieldValue('product') || 'unnamed').toString().toLowerCase().replace(/[^a-z0-9-]+/g, '-');
        const suggested = `${product || 'poc'}-${Date.now().toString(36)}.yaml`;
        setPocEditor({ open: true, suggested });
    };

    const handlePocSaved = (fileName: string) => {
        // 把新建 / 更新过的 POC 自动加入当前 workflow 的 POC 列表
        setPocsState((cur) => (cur.includes(fileName) ? cur : [...cur, fileName]));
        loadRefData();
    };

    const handleRemovePocFromWorkflow = (fileName: string) => {
        setPocsState((cur) => cur.filter((p) => p !== fileName));
    };

    const handleDeletePocCompletely = async (fileName: string) => {
        // workflow.pocs 里存的是不带后缀的短名（如 'CVE-2019-17382'），
        // 但 arsenals.file_name 是完整文件名（如 'CVE-2019-17382.yaml'）。
        // 后端按 file_name 精确匹配，所以删除时必须补 .yaml 后缀。
        const realFileName = /\.ya?ml$/i.test(fileName) ? fileName : `${fileName}.yaml`;
        try {
            await deleteArsenal('poc', realFileName);
            message.success(`POC ${fileName} 已从弹药库删除`);
            handleRemovePocFromWorkflow(fileName);
            loadRefData();
        } catch {
            message.error('POC 删除失败（请确认该 POC 文件存在于弹药库）');
        }
    };

    return (
        <Drawer
            title={
                <Space>
                    {isCurrentGP ? <GlobalOutlined style={{ color: '#f59e0b' }} /> : <ApartmentOutlined style={{ color: '#8b5cf6' }} />}
                    <span>{isNew ? (isGPMode ? '新建通用探测规则' : '新建 Workflow') : `编辑 Workflow — ${workflow?.product}`}</span>
                    {isCurrentGP && <Tag color="orange">全局探测</Tag>}
                </Space>
            }
            open={open}
            onClose={onClose}
            width={760}
            destroyOnClose
            footer={
                <div style={{ textAlign: 'right' }}>
                    <Space>
                        <Button onClick={onClose}>取消</Button>
                        <Button type="primary" loading={saving} onClick={handleSaveWorkflow}>
                            保存 Workflow
                        </Button>
                    </Space>
                </div>
            }
        >
            <Form
                form={form}
                layout="vertical"
                onValuesChange={(_, all) => {
                    setWatchedProduct(all.product || '');
                }}
            >
                {/* 1. 基本信息 */}
                <Form.Item
                    label={
                        <Space>
                            <span>Product 名称</span>
                            <Tooltip title="下拉可选择「指纹库中已存在」的 product 名，选中后会自动与该指纹绑定。也可输入新名字（后续可点右侧「新建指纹规则」补齐）。">
                                <Tag color="blue" style={{ cursor: 'help' }}>联动指纹库</Tag>
                            </Tooltip>
                        </Space>
                    }
                    name="product"
                    rules={[{ required: true, message: '请填写 product 名称' }]}
                    extra={`指纹库当前共 ${fingerprintProducts.size} 个 product，选中已有 product 可避免拼写不一致导致「指纹缺失」。`}
                >
                    <AutoComplete
                        placeholder="例：Liferay-Portal（输入后下拉可选指纹库已有 product）"
                        allowClear
                        showSearch
                        filterOption={(input, option) =>
                            (option?.value as string)?.toLowerCase().includes(input.toLowerCase())
                        }
                        options={Array.from(fingerprintProducts).sort().map((p) => ({
                            value: p,
                            label: (
                                <Space>
                                    <span>{p}</span>
                                    <Tag color="green">指纹已配置</Tag>
                                </Space>
                            ),
                        }))}
                    />
                </Form.Item>

                <Form.Item
                    label={
                        <Tooltip title="决定 POC 作用于目标 URL 的哪个层级。可多选组合。">
                            <span>触发阶段 (type)</span>
                        </Tooltip>
                    }
                    name="type"
                    extra="控制 POC 模板作用于 URL 的哪些层级，可多选组合使用。"
                >
                    <Select
                        mode="multiple"
                        placeholder="选择触发阶段"
                        options={[
                            { label: 'root — 根路径 (scheme://host)', value: 'root' },
                            { label: 'base — 完整路径 (scheme://host/a/b/c)', value: 'base' },
                            { label: 'dir — 逐级目录 (scheme://host/a, /a/b, ...)', value: 'dir' },
                            { label: 'dir-fallback — 目录探测命中 200 时直接标记指纹', value: 'dir-fallback' },
                        ]}
                        optionRender={(option) => (
                            <Tooltip title={
                                option.value === 'root' ? '对目标的根路径发送 POC 请求，如 http://target/' :
                                option.value === 'base' ? '对目标的完整发现路径发送 POC 请求，如 http://target/admin/login' :
                                option.value === 'dir' ? '对目标路径的每一级父目录逐一发送 POC 请求，如 /admin → /, /admin' :
                                '当主动目录探测命中 200 时，直接将该指纹标记到目标上，无需 finger 引擎二次验证'
                            } placement="left">
                                <span>{option.label}</span>
                            </Tooltip>
                        )}
                    />
                </Form.Item>
            </Form>

            <Divider style={{ margin: '4px 0 12px' }} />

            {/* 2. 指纹绑定 — General-Poc 模式下隐藏 */}
            {isCurrentGP ? (
                <Alert
                    message="通用探测规则不依赖指纹识别，将对所有扫描目标自动生效"
                    description="在 workflow.yaml 中以 General-Poc- 前缀命名的条目会被 mapper 自动识别为全局规则，无需指纹匹配即可触发关联的 POC 模板。"
                    type="info"
                    showIcon
                    icon={<GlobalOutlined />}
                    style={{ marginBottom: 12 }}
                />
            ) : (
            <Card
                size="small"
                style={{ marginBottom: 12 }}
                title={
                    <Space>
                        <ScanOutlined style={{ color: '#3b82f6' }} />
                        <span>指纹规则绑定</span>
                        {watchedProduct ? (
                            fingerprintBound ? (
                                <Badge status="success" text={<span style={{ fontSize: 12, color: '#10b981' }}>指纹库已配置</span>} />
                            ) : (
                                <Badge status="warning" text={<span style={{ fontSize: 12, color: '#f59e0b' }}>指纹库缺失，POC 将无法触发</span>} />
                            )
                        ) : (
                            <span style={{ fontSize: 12, color: '#94a3b8' }}>请先填写 product 名称</span>
                        )}
                    </Space>
                }
                extra={
                    <Space>
                        <Button
                            size="small"
                            icon={fingerprintBound ? <EditOutlined /> : <PlusOutlined />}
                            type={fingerprintBound ? 'default' : 'primary'}
                            disabled={!watchedProduct}
                            onClick={() =>
                                setFpEditor({ open: true, product: watchedProduct, isNew: !fingerprintBound })
                            }
                        >
                            {fingerprintBound ? '编辑指纹规则' : '新建指纹规则'}
                        </Button>
                    </Space>
                }
            >
                {!watchedProduct && <Empty description="填写 Product 后可管理对应指纹规则" image={Empty.PRESENTED_IMAGE_SIMPLE} />}
                {!!watchedProduct && fingerprintBound && (
                    <div style={{ fontSize: 12, color: '#64748b' }}>
                        <CheckOutlined style={{ color: '#10b981', marginRight: 4 }} />
                        已在指纹库中找到 product「{watchedProduct}」的规则，扫描时会自动激活。
                    </div>
                )}
                {!!watchedProduct && !fingerprintBound && (
                    <div style={{ fontSize: 12, color: '#f59e0b' }}>
                        <WarningOutlined style={{ marginRight: 4 }} />
                        当前指纹库没有 product「{watchedProduct}」的识别规则，扫描器无法识别该资产，意味着挂载的 POC 永远不会被触发。
                    </div>
                )}
            </Card>
            )}

            {/* 3. POC 关联 */}
            <Card
                size="small"
                title={
                    <Space>
                        <BugOutlined style={{ color: '#ef4444' }} />
                        <span>关联 POC ({pocsState.length})</span>
                    </Space>
                }
                extra={
                    <Space>
                        <Button size="small" icon={<PlusOutlined />} onClick={handleAddNewPoc} type="primary">
                            新建 POC
                        </Button>
                    </Space>
                }
            >
                <Select
                    mode="multiple"
                    style={{ width: '100%', marginBottom: 12 }}
                    placeholder="搜索并挂载已存在的 POC（按文件名）"
                    showSearch
                    value={pocsState}
                    onChange={(v: string[]) => setPocsState(v)}
                    options={pocOptions}
                    filterOption={(input, option) =>
                        (option?.label ?? '').toString().toLowerCase().includes(input.toLowerCase())
                    }
                    tagRender={() => <></>}
                />

                {pocsState.length === 0 ? (
                    <Empty description="尚未挂载 POC" image={Empty.PRESENTED_IMAGE_SIMPLE} />
                ) : (
                    <List
                        size="small"
                        bordered
                        dataSource={pocsState}
                        renderItem={(fileName) => {
                            const exists = pocOptions.some((o) => o.value === fileName);
                            return (
                                <List.Item
                                    actions={[
                                        <Tooltip title="编辑该 POC YAML（保存后即生效）" key="edit">
                                            <Button
                                                type="link"
                                                size="small"
                                                icon={<EditOutlined />}
                                                disabled={!exists}
                                                onClick={() => setPocEditor({ open: true, fileName })}
                                            >
                                                编辑
                                            </Button>
                                        </Tooltip>,
                                        <Button
                                            type="link"
                                            size="small"
                                            key="unlink"
                                            onClick={() => handleRemovePocFromWorkflow(fileName)}
                                        >
                                            从 Workflow 移除
                                        </Button>,
                                        <Popconfirm
                                            key="delete"
                                            title={`从弹药库永久删除 ${fileName}？`}
                                            onConfirm={() => {
                                                modal.confirm({
                                                    title: '危险操作确认',
                                                    content: `这会永久删除 POC 文件 ${fileName}，所有引用它的 Workflow 都会失效。`,
                                                    okText: '确认删除',
                                                    okButtonProps: { danger: true },
                                                    onOk: () => handleDeletePocCompletely(fileName),
                                                });
                                            }}
                                        >
                                            <Button type="link" size="small" danger icon={<DeleteOutlined />}>删除</Button>
                                        </Popconfirm>,
                                    ]}
                                >
                                    <Space>
                                        <BugOutlined style={{ color: '#ef4444' }} />
                                        <span style={{ fontFamily: 'monospace' }}>{fileName}</span>
                                        {!exists && <Tag color="red">弹药库中不存在</Tag>}
                                    </Space>
                                </List.Item>
                            );
                        }}
                    />
                )}
            </Card>

            {/* 子抽屉：POC 编辑器 */}
            <PocInlineEditor
                open={pocEditor.open}
                fileName={pocEditor.fileName}
                suggestedFileName={pocEditor.suggested}
                autoApprove
                onClose={() => setPocEditor({ open: false })}
                onSaved={handlePocSaved}
            />

            {/* 子抽屉：指纹编辑器 */}
            <FingerprintInlineEditor
                open={fpEditor.open}
                product={fpEditor.product}
                defaultProduct={fpEditor.isNew ? watchedProduct : undefined}
                onClose={() => setFpEditor({ open: false })}
                onSaved={() => loadRefData()}
            />
        </Drawer>
    );
};

export default WorkflowEditDrawer;
