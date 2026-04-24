import React, { useState, useEffect } from 'react';
import { Drawer, Button, Space, Input, App } from 'antd';
import { BugOutlined } from '@ant-design/icons';
import Editor from '@monaco-editor/react';
import { saveArsenal, approveArsenal, listArsenals } from '../../services/api';
import PocDebugPanel from './PocDebugPanel';
import PocAiPanel from './PocAiPanel';

interface PocInlineEditorProps {
    open: boolean;
    /** 已存在的 POC 文件名；为空表示新建模式 */
    fileName?: string;
    /** 自动审核（保存后立即调用 approveArsenal） */
    autoApprove?: boolean;
    /** 默认填入的初始内容（仅新建时生效） */
    initialContent?: string;
    /** 默认建议的文件名（仅新建时生效） */
    suggestedFileName?: string;
    onClose: () => void;
    /**
     * 保存成功后回调；fileName 是最终落库的文件名（新建场景下由用户输入）。
     */
    onSaved?: (fileName: string) => void;
}

const POC_TEMPLATE = `id: poc-template

info:
  name: POC Template
  author: argus
  severity: medium
  description: ""
  tags: ""

http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - "keyword"
`;

const PocInlineEditor: React.FC<PocInlineEditorProps> = ({
    open,
    fileName,
    autoApprove,
    initialContent,
    suggestedFileName,
    onClose,
    onSaved,
}) => {
    const isNew = !fileName;
    const { message } = App.useApp();
    const [content, setContent] = useState<string>('');
    const [editingFileName, setEditingFileName] = useState<string>('');
    const [loading, setLoading] = useState<boolean>(false);
    const [saving, setSaving] = useState<boolean>(false);
    const [debugVisible, setDebugVisible] = useState<boolean>(false);
    const [aiVisible, setAiVisible] = useState<boolean>(false);

    useEffect(() => {
        if (!open) return;
        if (isNew) {
            setEditingFileName(suggestedFileName || '');
            setContent(initialContent || POC_TEMPLATE);
            setDebugVisible(false);
            return;
        }
        // 编辑已存在 POC：从 listArsenals 拉取最新内容（避免外部传入 stale）
        // workflow.yaml 中可能用不带后缀的名引用，这里同时尝试匹配带 / 不带后缀的形式。
        (async () => {
            setLoading(true);
            try {
                const all = await listArsenals('poc', true, false);
                const lookups = [fileName, `${fileName}.yaml`, `${fileName}.yml`];
                const found = all?.find((a) => lookups.includes(a.FileName));
                setContent(found?.Content || '');
                setEditingFileName(found?.FileName || (fileName as string));
                setDebugVisible(false);
            } catch {
                message.error('加载 POC 内容失败');
            } finally {
                setLoading(false);
            }
        })();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [open, fileName]);

    const handleSave = async () => {
        const finalName = (editingFileName || '').trim();
        if (!finalName) {
            message.error('请输入文件名');
            return;
        }
        if (isNew && !/\.(yml|yaml)$/i.test(finalName)) {
            message.warning('建议使用 .yaml 后缀');
        }
        setSaving(true);
        try {
            await saveArsenal('poc', finalName, content);
            if (autoApprove) {
                await approveArsenal('poc', finalName);
                message.success('已保存并审核（已触发 Agent 热重载）');
            } else {
                message.success(isNew ? 'POC 已创建（草稿）' : 'POC 已保存（草稿）');
            }
            onSaved?.(finalName);
            onClose();
        } catch (err: unknown) {
            message.error(typeof err === 'string' ? err : 'POC 保存失败');
        } finally {
            setSaving(false);
        }
    };



    return (
        <Drawer
            title={isNew ? '新建 POC' : `编辑 POC — ${fileName}`}
            open={open}
            onClose={onClose}
            width={(debugVisible || aiVisible) ? 1300 : 760}
            destroyOnClose
            footer={
                <div style={{ textAlign: 'right' }}>
                    <Space>
                        <Button icon={<BugOutlined />} onClick={() => { setDebugVisible((v) => !v); setAiVisible(false); }}>
                            {debugVisible ? '收起调试' : '调试'}
                        </Button>
                        <Button onClick={() => { setAiVisible((v) => !v); setDebugVisible(false); }}>
                            {aiVisible ? '收起 AI 分析' : 'AI 分析'}
                        </Button>
                        <Button onClick={onClose}>取消</Button>
                        <Button type="primary" onClick={handleSave} loading={saving}>
                            {autoApprove ? '保存并审核' : '保存（草稿）'}
                        </Button>
                    </Space>
                </div>
            }
        >
            <div style={{ display: 'flex', gap: 16, height: '100%' }}>
                <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column' }}>
                    {isNew && (
                        <div style={{ marginBottom: 12 }}>
                            <div style={{ marginBottom: 6, fontSize: 12, color: '#64748b' }}>文件名 *</div>
                            <Input
                                value={editingFileName}
                                placeholder="例：CVE-2024-XXXX.yaml"
                                onChange={(e) => setEditingFileName(e.target.value)}
                            />
                        </div>
                    )}
                    <div style={{ flex: 1, border: '1px solid #e2e8f0', borderRadius: 6, overflow: 'hidden' }}>
                        <Editor
                            height="100%"
                            language="yaml"
                            theme="vs-dark"
                            value={content}
                            onChange={(v) => setContent(v || '')}
                            options={{ minimap: { enabled: false }, fontSize: 13, readOnly: loading }}
                        />
                    </div>
                </div>
                <div style={{ width: 520, flexShrink: 0, display: debugVisible ? 'flex' : 'none', flexDirection: 'column', overflowY: 'auto' }}>
                    <PocDebugPanel visible={debugVisible} pocContent={content} />
                </div>
                <div style={{ width: 520, flexShrink: 0, display: aiVisible ? 'flex' : 'none', flexDirection: 'column', overflowY: 'auto' }}>
                    <PocAiPanel visible={aiVisible} pocContent={content} fileName={editingFileName || fileName || 'untitled.yaml'} />
                </div>
            </div>
        </Drawer>
    );
};

export default PocInlineEditor;
