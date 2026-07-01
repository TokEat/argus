import React, { useState, useEffect } from 'react';
import { Drawer, Button, Space, Input, App } from 'antd';
import { BugOutlined, RobotOutlined } from '@ant-design/icons';
import Editor from '@monaco-editor/react';
import { saveArsenal, approveArsenal, getArsenal } from '../../services/api';
import PocDebugPanel from './PocDebugPanel';
import { useGlobalAI, useAutoContext } from '../../contexts/GlobalAIContext';
import { canAccessRole } from '../../utils/auth';

interface PocInlineEditorProps {
    open: boolean;
    fileName?: string;
    autoApprove?: boolean;
    initialContent?: string;
    suggestedFileName?: string;
    onClose: () => void;
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
    const { visible: aiVisible, openGlobalAI, registerEditableTarget } = useGlobalAI();
    const isNew = !fileName;
    const { message } = App.useApp();
    const [content, setContent] = useState<string>('');
    const [editingFileName, setEditingFileName] = useState<string>('');
    const [loading, setLoading] = useState<boolean>(false);
    const [saving, setSaving] = useState<boolean>(false);
    const [debugVisible, setDebugVisible] = useState<boolean>(false);
    const canApproveArsenal = canAccessRole('admin');
    const shouldAutoApprove = !!autoApprove && canApproveArsenal;

    // Dynamically inject the editor state into Global AI Context
    useAutoContext(open ? {
        action: 'editing_poc',
        file_name: editingFileName || fileName || 'untitled.yaml',
        poc_content: content,
        editable_target: {
            type: 'poc',
            label: editingFileName || fileName || 'untitled.yaml'
        }
    } : {});

    const handleDiagnose = (contextData: any) => {
        setDebugVisible(false);
        openGlobalAI({
            module: 'poc_inline',
            action: 'debug',
            raw_data: contextData,
            file_name: editingFileName || fileName || 'untitled.yaml'
        });
    };

    useEffect(() => {
        if (!open) return;
        if (isNew) {
            setEditingFileName(suggestedFileName || '');
            setContent(initialContent || POC_TEMPLATE);
            setDebugVisible(false);
            return;
        }
        (async () => {
            setLoading(true);
            try {
                const lookups = [fileName, `${fileName}.yaml`, `${fileName}.yml`];
                let found: API.Arsenal | undefined;
                for (const candidate of lookups) {
                    if (!candidate) continue;
                    try {
                        found = await getArsenal('poc', candidate);
                        break;
                    } catch {
                        // Try the next filename form.
                    }
                }
                setContent(found?.Content || '');
                setEditingFileName(found?.FileName || (fileName as string));
                setDebugVisible(false);
            } catch {
                message.error('加载 POC 内容失败');
            } finally {
                setLoading(false);
            }
        })();
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
            if (shouldAutoApprove) {
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

    const saveDraftFromAI = async (contentOverride?: string) => {
        const finalName = (editingFileName || '').trim();
        if (!finalName) {
            throw '请输入文件名';
        }
        if (isNew && !/\.(yml|yaml)$/i.test(finalName)) {
            message.warning('建议使用 .yaml 后缀');
        }
        setSaving(true);
        try {
            const draftContent = typeof contentOverride === 'string' ? contentOverride : content;
            await saveArsenal('poc', finalName, draftContent);
            if (draftContent !== content) {
                setContent(draftContent);
            }
            message.success(isNew ? 'POC 已创建（草稿）' : 'POC 已保存（草稿）');
            onSaved?.(finalName);
        } finally {
            setSaving(false);
        }
    };

    useEffect(() => {
        if (!open) return undefined;
        return registerEditableTarget({
            id: 'poc-inline-editor',
            type: 'poc',
            label: editingFileName || fileName || 'untitled.yaml',
            getContent: () => content,
            applyContent: (nextContent: string) => setContent(nextContent),
            saveDraft: saveDraftFromAI,
        });
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [open, editingFileName, fileName, content, registerEditableTarget]);

    return (
        <Drawer
            title={isNew ? '新建 POC' : `编辑 POC — ${fileName}`}
            open={open}
            onClose={onClose}
            width={debugVisible ? 1300 : 760}
            destroyOnClose
            style={{ transform: aiVisible ? 'translateX(-500px)' : 'none', transition: 'transform 0.3s' }}
            mask={!aiVisible}
            footer={
                <div style={{ textAlign: 'right' }}>
                    <Space>
                        <Button icon={<BugOutlined />} onClick={() => { setDebugVisible((v) => !v); }}>
                            {debugVisible ? '收起调试' : '调试'}
                        </Button>
                        <Button onClick={() => openGlobalAI({
                            module: 'poc_inline',
                            action: 'review',
                            file_name: editingFileName || fileName || 'untitled.yaml',
                            suggested_prompt: '请审查当前 POC，指出误报风险、结构问题和可改进点；如果需要修改，请输出完整更新后的 YAML。'
                        })}>
                            AI 分析
                        </Button>
                        <Button onClick={onClose}>取消</Button>
                        <Button type="primary" onClick={handleSave} loading={saving}>
                            {shouldAutoApprove ? '保存并审核' : '保存（草稿）'}
                        </Button>
                    </Space>
                </div>
            }
        >
            <div style={{ display: 'flex', gap: 16, height: '100%' }}>
                <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column' }}>
                    <div style={{ marginBottom: 12, display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end' }}>
                        <div style={{ flex: 1, marginRight: 16 }}>
                            {isNew && <div style={{ marginBottom: 6, fontSize: 12, color: '#64748b' }}>文件名 *</div>}
                            {!isNew && <div style={{ marginBottom: 6, fontSize: 12, color: '#64748b' }}>POC 代码编辑</div>}
                            {isNew && (
                                <Input
                                    value={editingFileName}
                                    placeholder="例：CVE-2024-XXXX.yaml"
                                    onChange={(e) => setEditingFileName(e.target.value)}
                                />
                            )}
                        </div>
                        <Button
                            type="dashed"
                            icon={<RobotOutlined />}
                            onClick={() => openGlobalAI({
                                module: 'poc_inline',
                                action: 'generate',
                                file_name: editingFileName || fileName || 'untitled.yaml',
                                suggested_prompt: '请基于当前编辑器内容生成或优化这个 POC，输出完整可应用的 YAML。'
                            })}
                        >
                            AI 辅助生成
                        </Button>
                    </div>
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
                    <PocDebugPanel visible={debugVisible} pocContent={content} onDiagnose={handleDiagnose} />
                </div>
            </div>
        </Drawer>
    );
};

export default PocInlineEditor;
