import React, { useEffect, useState } from 'react';
import { Drawer, Button, Space, Input, App, Form, Select, Alert } from 'antd';
import {
    getFingerprintDict,
    addFingerprintDict,
    updateFingerprintDict,
} from '../../services/api';
import { useAutoContext } from '../../contexts/GlobalAIContext';

interface FingerprintInlineEditorProps {
    open: boolean;
    /** 要编辑的产品名；为空表示新建 */
    product?: string;
    /** 默认产品名（新建场景下） */
    defaultProduct?: string;
    onClose: () => void;
    /** 保存成功后回调，回传最终的 product 名 */
    onSaved?: (product: string) => void;
}

const FingerprintInlineEditor: React.FC<FingerprintInlineEditorProps> = ({
    open,
    product,
    defaultProduct,
    onClose,
    onSaved,
}) => {
    const isNew = !product;
    const { message } = App.useApp();
    const [form] = Form.useForm();
    const [loading, setLoading] = useState(false);
    const [saving, setSaving] = useState(false);
    const [notFound, setNotFound] = useState(false);

    useEffect(() => {
        if (!open) return;
        setNotFound(false);
        if (isNew) {
            form.setFieldsValue({ product: defaultProduct || '', rules: [] });
            return;
        }
        (async () => {
            setLoading(true);
            try {
                const all = await getFingerprintDict();
                const item = all?.find((f) => f.product === product);
                if (!item) {
                    setNotFound(true);
                    form.setFieldsValue({ product, rules: [] });
                    return;
                }
                form.setFieldsValue({ product: item.product, rules: item.rules || [] });
            } catch {
                message.error('加载指纹规则失败');
            } finally {
                setLoading(false);
            }
        })();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [open, product]);

    useAutoContext({
        editing_fingerprint_rule: open ? {
            product: form.getFieldValue('product') || product || defaultProduct,
            rules: form.getFieldValue('rules') || [],
            is_new: isNew,
            not_found_in_db: notFound
        } : null
    });

    const handleSave = async () => {
        try {
            const values = await form.validateFields();
            const finalProduct = (values.product || '').trim();
            const rules: string[] = (values.rules || []).map((r: string) => r.trim()).filter(Boolean);
            if (!finalProduct) {
                message.error('请填写 product 名称');
                return;
            }
            setSaving(true);
            if (isNew || notFound) {
                await addFingerprintDict({ product: finalProduct, rules });
            } else {
                await updateFingerprintDict(product as string, { product: finalProduct, rules });
            }
            message.success('指纹已保存（全网规则版本已更新）');
            onSaved?.(finalProduct);
            onClose();
        } catch (err: unknown) {
            const e = err as { errorFields?: unknown };
            if (e?.errorFields) return; // 表单校验错误
            message.error(typeof err === 'string' ? err : '指纹保存失败');
        } finally {
            setSaving(false);
        }
    };

    return (
        <Drawer
            title={isNew ? '新建指纹规则' : `编辑指纹规则 — ${product}`}
            open={open}
            onClose={onClose}
            width={620}
            destroyOnClose
            footer={
                <div style={{ textAlign: 'right' }}>
                    <Space>
                        <Button onClick={onClose}>取消</Button>
                        <Button type="primary" onClick={handleSave} loading={saving}>保存</Button>
                    </Space>
                </div>
            }
        >
            {notFound && (
                <Alert
                    type="warning"
                    showIcon
                    style={{ marginBottom: 12 }}
                    message={`指纹库中暂无产品 "${product}" 的规则，保存将自动新建。`}
                />
            )}
            <Form form={form} layout="vertical" disabled={loading}>
                <Form.Item
                    label="Product 名称"
                    name="product"
                    rules={[{ required: true, message: '请填写 product 名称' }]}
                    extra="必须与 Workflow 中引用的 product 一致才能正确触发 POC。"
                >
                    <Input placeholder="例：Liferay-Portal" />
                </Form.Item>
                <Form.Item
                    label="指纹规则表达式 (rules)"
                    name="rules"
                    extra='每条规则一行，按回车录入。例：title="Liferay" 或 body="liferay" || header="liferay"'
                >
                    <Select
                        mode="tags"
                        style={{ width: '100%' }}
                        placeholder='输入规则后回车，如 body="liferay"'
                        tokenSeparators={[]}
                    />
                </Form.Item>
            </Form>
        </Drawer>
    );
};

export default FingerprintInlineEditor;
