import React, { useState, useEffect, useRef } from 'react';
import { Drawer, Input, Button, Spin, Tag, Typography, App } from 'antd';
import { DeleteOutlined, RadarChartOutlined, RobotOutlined, SecurityScanOutlined, SendOutlined, StopOutlined } from '@ant-design/icons';
import type { AIEditableTarget, CopilotRequestContext, PageContext } from '../contexts/GlobalAIContext';
import { confirmCopilotAction } from '../services/api';

const { Text } = Typography;

interface ChatMessage {
    role: 'user' | 'assistant' | 'system' | 'tool';
    content: string;
    toolTrace?: ToolTrace;
    proposedEdit?: ProposedEdit;
    pendingActions?: API.CopilotPendingAction[];
}

interface ToolTrace {
    id: string;
    name: string;
    args?: string;
    result?: string;
    status: 'running' | 'done' | 'error';
    durationMs?: number;
}

interface GlobalAIChatDrawerProps {
    visible: boolean;
    onClose: () => void;
    pageContext: PageContext;
    copilotContext?: CopilotRequestContext;
    editableTarget?: AIEditableTarget;
}

interface ProposedContentEdit {
    type: 'poc' | 'exp';
    content: string;
}

type ProposedEdit = ProposedContentEdit;

const safeHref = (href: string) => {
    const trimmed = href.trim();
    if (/^(https?:|mailto:)/i.test(trimmed)) return trimmed;
    return '#';
};

const renderInlineMarkdown = (text: string): React.ReactNode[] => {
    const nodes: React.ReactNode[] = [];
    // Order matters: bold before italic, strikethrough, inline code, links
    const pattern = /(\*\*(.+?)\*\*|\*(.+?)\*|~~(.+?)~~|`([^`]+)`|\[([^\]]+)\]\(([^)]+)\))/g;
    let lastIndex = 0;
    let match: RegExpExecArray | null;

    while ((match = pattern.exec(text)) !== null) {
        if (match.index > lastIndex) {
            nodes.push(text.slice(lastIndex, match.index));
        }
        if (match[2]) {
            nodes.push(<strong key={`b-${match.index}`}>{match[2]}</strong>);
        } else if (match[3]) {
            nodes.push(<em key={`i-${match.index}`}>{match[3]}</em>);
        } else if (match[4]) {
            nodes.push(<del key={`s-${match.index}`}>{match[4]}</del>);
        } else if (match[5]) {
            nodes.push(<code key={`c-${match.index}`}>{match[5]}</code>);
        } else if (match[6] && match[7]) {
            nodes.push(
                <a key={`a-${match.index}`} href={safeHref(match[7])} target="_blank" rel="noreferrer">
                    {match[6]}
                </a>,
            );
        }
        lastIndex = pattern.lastIndex;
    }

    if (lastIndex < text.length) {
        nodes.push(text.slice(lastIndex));
    }
    return nodes;
};

/** Check if a line looks like a table separator row: | --- | --- | */
const isTableSeparator = (line: string) => /^\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/.test(line.trim());

/** Parse a table row string into cells */
const parseTableCells = (line: string): string[] => {
    let trimmed = line.trim();
    if (trimmed.startsWith('|')) trimmed = trimmed.slice(1);
    if (trimmed.endsWith('|')) trimmed = trimmed.slice(0, -1);
    return trimmed.split('|').map((cell) => cell.trim());
};

/** Parse alignment from separator row */
const parseTableAlign = (line: string): ('left' | 'center' | 'right' | undefined)[] => {
    return parseTableCells(line).map((cell) => {
        const trimmed = cell.trim().replace(/\s/g, '');
        if (trimmed.startsWith(':') && trimmed.endsWith(':')) return 'center';
        if (trimmed.endsWith(':')) return 'right';
        if (trimmed.startsWith(':')) return 'left';
        return undefined;
    });
};

const MarkdownMessage: React.FC<{ content: string }> = ({ content }) => {
    const blocks: React.ReactNode[] = [];
    const lines = content.replace(/\r\n/g, '\n').split('\n');
    let paragraph: string[] = [];
    let listItems: string[] = [];
    let listType: 'ul' | 'ol' | null = null;
    let codeLines: string[] = [];
    let codeLang = '';
    let inCode = false;
    let quoteLines: string[] = [];

    const flushParagraph = () => {
        if (paragraph.length === 0) return;
        blocks.push(<p key={`p-${blocks.length}`}>{renderInlineMarkdown(paragraph.join(' '))}</p>);
        paragraph = [];
    };

    const flushList = () => {
        if (!listType || listItems.length === 0) return;
        const Tag = listType;
        blocks.push(
            <Tag key={`l-${blocks.length}`}>
                {listItems.map((item, index) => (
                    <li key={index}>{renderInlineMarkdown(item)}</li>
                ))}
            </Tag>,
        );
        listItems = [];
        listType = null;
    };

    const flushCode = () => {
        blocks.push(
            <pre key={`code-${blocks.length}`} data-lang={codeLang || undefined}>
                <code>{codeLines.join('\n')}</code>
            </pre>,
        );
        codeLines = [];
        codeLang = '';
    };

    const flushQuote = () => {
        if (quoteLines.length === 0) return;
        blocks.push(
            <blockquote key={`q-${blocks.length}`}>
                {quoteLines.map((ql, qi) => (
                    <span key={qi}>{renderInlineMarkdown(ql)}{qi < quoteLines.length - 1 ? <br /> : null}</span>
                ))}
            </blockquote>,
        );
        quoteLines = [];
    };

    const flushAll = () => {
        flushParagraph();
        flushList();
        flushQuote();
    };

    /** Try to consume a table starting at lineIndex, returns next line index or -1 if not a table */
    const tryConsumeTable = (startIdx: number): number => {
        // Need at least header + separator
        if (startIdx + 1 >= lines.length) return -1;
        const headerLine = lines[startIdx].trim();
        const sepLine = lines[startIdx + 1].trim();
        if (!headerLine.includes('|') || !isTableSeparator(sepLine)) return -1;

        const headers = parseTableCells(headerLine);
        const aligns = parseTableAlign(sepLine);
        const bodyRows: string[][] = [];
        let idx = startIdx + 2;
        while (idx < lines.length) {
            const row = lines[idx].trim();
            if (!row || !row.includes('|')) break;
            bodyRows.push(parseTableCells(row));
            idx++;
        }

        blocks.push(
            <div key={`tw-${blocks.length}`} className="ai-md-table-wrap">
                <table key={`t-${blocks.length}`}>
                    <thead>
                        <tr>
                            {headers.map((h, hi) => (
                                <th key={hi} style={aligns[hi] ? { textAlign: aligns[hi] } : undefined}>
                                    {renderInlineMarkdown(h)}
                                </th>
                            ))}
                        </tr>
                    </thead>
                    <tbody>
                        {bodyRows.map((row, ri) => (
                            <tr key={ri}>
                                {headers.map((_, ci) => (
                                    <td key={ci} style={aligns[ci] ? { textAlign: aligns[ci] } : undefined}>
                                        {renderInlineMarkdown(row[ci] || '')}
                                    </td>
                                ))}
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>,
        );

        return idx;
    };

    let i = 0;
    while (i < lines.length) {
        const line = lines[i];
        const trimmed = line.trim();

        // --- Fenced code block ---
        if (trimmed.startsWith('```')) {
            flushAll();
            if (inCode) {
                flushCode();
                inCode = false;
            } else {
                inCode = true;
                codeLang = trimmed.slice(3).trim();
                codeLines = [];
            }
            i++;
            continue;
        }
        if (inCode) {
            codeLines.push(line);
            i++;
            continue;
        }

        // --- Empty line ---
        if (!trimmed) {
            flushAll();
            i++;
            continue;
        }

        // --- Horizontal rule ---
        if (/^(-{3,}|\*{3,}|_{3,})$/.test(trimmed)) {
            flushAll();
            blocks.push(<hr key={`hr-${blocks.length}`} />);
            i++;
            continue;
        }

        // --- Table (must be checked before paragraph accumulation) ---
        if (trimmed.includes('|') && i + 1 < lines.length && isTableSeparator(lines[i + 1]?.trim())) {
            flushAll();
            const nextIdx = tryConsumeTable(i);
            if (nextIdx > 0) {
                i = nextIdx;
                continue;
            }
        }

        // --- Heading ---
        const heading = /^(#{1,6})\s+(.+)$/.exec(trimmed);
        if (heading) {
            flushAll();
            const level = Math.min(heading[1].length, 6);
            const TagName = `h${level}`;
            blocks.push(React.createElement(TagName, { key: `h-${blocks.length}` }, renderInlineMarkdown(heading[2])));
            i++;
            continue;
        }

        // --- Blockquote (supports multi-line) ---
        const quoteMatch = /^>\s?(.*)$/.exec(trimmed);
        if (quoteMatch) {
            flushParagraph();
            flushList();
            quoteLines.push(quoteMatch[1]);
            i++;
            continue;
        }
        // If we were in a quote and this line is not a quote, flush
        if (quoteLines.length > 0) {
            flushQuote();
        }

        // --- Unordered list ---
        const unordered = /^[-*+]\s+(.+)$/.exec(trimmed);
        if (unordered) {
            flushParagraph();
            flushQuote();
            if (listType && listType !== 'ul') flushList();
            listType = 'ul';
            listItems.push(unordered[1]);
            i++;
            continue;
        }

        // --- Ordered list ---
        const ordered = /^\d+[.)]\s+(.+)$/.exec(trimmed);
        if (ordered) {
            flushParagraph();
            flushQuote();
            if (listType && listType !== 'ol') flushList();
            listType = 'ol';
            listItems.push(ordered[1]);
            i++;
            continue;
        }

        // --- Paragraph text ---
        flushList();
        flushQuote();
        paragraph.push(trimmed);
        i++;
    }

    if (inCode) flushCode();
    flushAll();

    return <div className="ai-markdown">{blocks}</div>;
};

const findLastToolMessageIndex = (messages: ChatMessage[]) => {
    for (let index = messages.length - 1; index >= 0; index -= 1) {
        if (messages[index].role === 'tool') return index;
    }
    return -1;
};

const extractPocEdit = (content: string, editableTarget?: AIEditableTarget): ProposedEdit | undefined => {
    if (editableTarget?.type !== 'poc') return undefined;
    const fence = /```(?:ya?ml|yaml)\s*\n([\s\S]*?)```/i.exec(content);
    const candidate = (fence?.[1] || '').trim();
    if (!candidate) return undefined;
    if (!/^id:\s*.+/m.test(candidate) || !/\ninfo:\s*/m.test(candidate)) return undefined;
    return { type: 'poc', content: candidate.endsWith('\n') ? candidate : `${candidate}\n` };
};

const extractExpEdit = (content: string, editableTarget?: AIEditableTarget): ProposedEdit | undefined => {
    if (editableTarget?.type !== 'exp') return undefined;
    const fence = /```(?:yak|yaklang)\s*\n([\s\S]*?)```/i.exec(content);
    const candidate = (fence?.[1] || '').trim();
    if (!candidate) return undefined;
    if (!/\bcli\./.test(candidate) || !/\byaksha\.result\s*\(/.test(candidate)) {
        return undefined;
    }
    return { type: 'exp', content: candidate.endsWith('\n') ? candidate : `${candidate}\n` };
};

const stripPendingActionBlocks = (content: string) =>
    content.replace(/```pending_action\s*\n[\s\S]*?"action_type"[\s\S]*?```/gi, '').trim();

const GlobalAIChatDrawer: React.FC<GlobalAIChatDrawerProps> = ({ visible, onClose, pageContext, copilotContext, editableTarget }) => {
    const [messages, setMessages] = useState<ChatMessage[]>([]);
    const [inputValue, setInputValue] = useState('');
    const [loading, setLoading] = useState(false);
    const [streamingContent, setStreamingContent] = useState('');
    const [expandedTools, setExpandedTools] = useState<Record<string, boolean>>({});
    const [appliedEdits, setAppliedEdits] = useState<Record<string, boolean>>({});
    const [appliedEditContents, setAppliedEditContents] = useState<Record<string, string>>({});
    const [savingDraft, setSavingDraft] = useState(false);
    const [executingActionKey, setExecutingActionKey] = useState<string>('');
    const [completedActions, setCompletedActions] = useState<Record<string, string>>({});
    const messagesEndRef = useRef<HTMLDivElement>(null);
    const abortRef = useRef<AbortController | null>(null);
    const lastSuggestedPromptRef = useRef<string>('');
    const { message: msg, modal } = App.useApp();

    const scrollToBottom = () => {
        messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    };

    useEffect(() => {
        scrollToBottom();
    }, [messages, streamingContent]);

    useEffect(() => {
        if (!visible || loading) return;
        const suggested = typeof pageContext?.suggested_prompt === 'string' ? pageContext.suggested_prompt.trim() : '';
        const promptNonce = pageContext?.suggested_prompt_nonce;
        const suggestedKey = `${String(promptNonce || '')}:${suggested}`;
        const forceReplace = pageContext?.suggested_prompt_replace === true;
        if (!suggested || (!forceReplace && suggestedKey === lastSuggestedPromptRef.current)) return;
        lastSuggestedPromptRef.current = suggestedKey;
        setInputValue((prev) => (forceReplace || !prev.trim() ? suggested : prev));
    }, [visible, loading, pageContext?.suggested_prompt, pageContext?.suggested_prompt_nonce, pageContext?.suggested_prompt_replace]);

    const stopStreaming = () => {
        abortRef.current?.abort();
        abortRef.current = null;
        setLoading(false);
    };

    const handleClose = () => {
        stopStreaming();
        onClose();
    };

    const resetConversation = () => {
        stopStreaming();
        setMessages([]);
        setStreamingContent('');
        setExpandedTools({});
        setAppliedEdits({});
        setAppliedEditContents({});
        setExecutingActionKey('');
        setCompletedActions({});
        setInputValue('');
    };

    const toggleToolTrace = (id: string) => {
        setExpandedTools((prev) => ({ ...prev, [id]: !prev[id] }));
    };

    const handleSend = async () => {
        if (!inputValue.trim() || loading) return;

        const newUserMessage: ChatMessage = { role: 'user', content: inputValue };
        const updatedMessages = [...messages, newUserMessage];
        setMessages(updatedMessages);
        setInputValue('');
        setLoading(true);
        setStreamingContent('');

        const token = localStorage.getItem('token') || '';
        let assistantContent = '';
        const pendingActions: API.CopilotPendingAction[] = [];
        const controller = new AbortController();
        abortRef.current = controller;

        try {
            const resp = await fetch('/api/v1/ai/chat', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({
                    messages: updatedMessages
                        .filter((item) => item.role !== 'tool')
                        .map(({ role, content }) => ({ role, content })),
                    page_context: copilotContext || pageContext,
                }),
                signal: controller.signal,
            });

            if (!resp.ok || !resp.body) {
                msg.error('连接 AI 服务失败');
                setLoading(false);
                abortRef.current = null;
                return;
            }

            const reader = resp.body.getReader();
            const decoder = new TextDecoder();
            let buffer = '';
            let currentEvent = '';
            let failed = false;

            while (true) {
                const { done, value } = await reader.read();
                if (done) break;

                buffer += decoder.decode(value, { stream: true });
                const lines = buffer.split('\n');
                buffer = lines.pop() || '';

                for (const line of lines) {
                    if (line.startsWith('event: ')) {
                        currentEvent = line.slice(7).trim();
                    } else if (line.startsWith('data: ') && currentEvent) {
                        const jsonStr = line.slice(6);
                        try {
                            const data = JSON.parse(jsonStr);
                            if (currentEvent === 'token') {
                                const content = data.content || '';
                                assistantContent += content;
                                setStreamingContent((prev) => prev + content);
                            } else if (currentEvent === 'tool_start') {
                                const id = data.id || `${Date.now()}-${data.name || 'tool'}`;
                                setMessages((prev) => [
                                    ...prev,
                                    {
                                        role: 'tool',
                                        content: '',
                                        toolTrace: {
                                            id,
                                            name: data.name || 'unknown',
                                            args: data.args || '',
                                            status: 'running',
                                        },
                                    },
                                ]);
                            } else if (currentEvent === 'tool_end') {
                                const id = data.id || '';
                                setMessages((prev) => {
                                    const index = id ? prev.findIndex((item) => item.toolTrace?.id === id) : findLastToolMessageIndex(prev);
                                    if (index < 0) return prev;
                                    return prev.map((item, itemIndex) => itemIndex === index ? {
                                        ...item,
                                        toolTrace: item.toolTrace ? {
                                            ...item.toolTrace,
                                            status: data.status === 'error' ? 'error' : 'done',
                                            result: data.result || '工具调用完毕',
                                            durationMs: data.duration_ms,
                                        } : item.toolTrace,
                                    } : item);
                                });
                            } else if (currentEvent === 'error') {
                                failed = true;
                                msg.error(`AI 错误: ${data.message}`);
                            } else if (currentEvent === 'pending_action') {
                                pendingActions.push(data as API.CopilotPendingAction);
                            }
                        } catch (e) {
                            console.error("Failed to parse SSE data", e);
                        }
                    }
                }
            }

            setLoading(false);
            abortRef.current = null;
            if (!failed && assistantContent.trim()) {
                const displayContent = stripPendingActionBlocks(assistantContent);
                const proposedEdit = extractPocEdit(assistantContent, editableTarget) || extractExpEdit(assistantContent, editableTarget);
                setMessages((prev) => [...prev, {
                    role: 'assistant',
                    content: displayContent || (pendingActions.length > 0 ? '我准备好了一个待确认动作。' : assistantContent),
                    proposedEdit,
                    pendingActions,
                }]);
            }
            setStreamingContent('');

        } catch (error) {
            abortRef.current = null;
            if ((error as Error)?.name === 'AbortError') {
                if (assistantContent.trim()) {
                    const displayContent = stripPendingActionBlocks(assistantContent);
                    const proposedEdit = extractPocEdit(assistantContent, editableTarget) || extractExpEdit(assistantContent, editableTarget);
                    setMessages((prev) => [...prev, {
                        role: 'assistant',
                        content: displayContent || (pendingActions.length > 0 ? '我准备好了一个待确认动作。' : assistantContent),
                        proposedEdit,
                        pendingActions,
                    }]);
                }
                setStreamingContent('');
                setLoading(false);
                return;
            }
            console.error("SSE Error:", error);
            msg.error("通信中断，请重试");
            setLoading(false);
        }
    };

    const applyProposedEdit = (editKey: string, edit: ProposedEdit) => {
        if (!editableTarget || editableTarget.type !== edit.type) {
            msg.warning('当前没有可应用的编辑器');
            return;
        }
        const validation = editableTarget.canApplyContent?.(edit.content);
        if (validation && !validation.ok) {
            msg.warning(validation.reason || '当前编辑器不允许应用该内容');
            return;
        }
        editableTarget.applyContent(edit.content);
        setAppliedEdits((prev) => ({ ...prev, [editKey]: true }));
        setAppliedEditContents((prev) => ({ ...prev, [editKey]: edit.content }));
        msg.success(`已应用到 ${editableTarget.label}`);
    };

    const saveEditableDraft = async (editKey: string) => {
        if (!editableTarget?.saveDraft) {
            msg.warning('当前编辑器不支持从 Copilot 保存');
            return;
        }
        setSavingDraft(true);
        try {
            await editableTarget.saveDraft(appliedEditContents[editKey]);
            msg.success(`已保存 ${editableTarget.label} 草稿`);
        } catch (error: unknown) {
            msg.error(typeof error === 'string' ? error : '保存草稿失败');
        } finally {
            setSavingDraft(false);
        }
    };

    const riskColor = (risk?: string) => {
        if (risk === 'high') return 'red';
        if (risk === 'medium') return 'orange';
        return 'green';
    };

    const executePendingAction = (actionKey: string, action: API.CopilotPendingAction) => {
        if (completedActions[actionKey]) return;
        modal.confirm({
            title: action.title || '确认执行 Copilot 动作',
            width: 620,
            content: (
                <div className="ai-action-confirm">
                    <p>{action.summary || '该动作需要你确认后才会执行。'}</p>
                    {action.preview && <pre>{action.preview}</pre>}
                    <div className="ai-action-confirm-meta">
                        <Tag color={riskColor(action.risk_level)}>风险：{action.risk_level || 'low'}</Tag>
                        <Tag>权限：{action.required_role || 'operator'}</Tag>
                    </div>
                </div>
            ),
            okText: action.confirm_label || '确认执行',
            cancelText: '取消',
            onOk: async () => {
                setExecutingActionKey(actionKey);
                try {
                    const result = await confirmCopilotAction(action, copilotContext || pageContext);
                    setCompletedActions((prev) => ({ ...prev, [actionKey]: result.message || '已执行' }));
                    msg.success(result.message || '动作已执行');
                } catch (error: unknown) {
                    msg.error(typeof error === 'string' ? error : '动作执行失败');
                    throw error;
                } finally {
                    setExecutingActionKey('');
                }
            },
        });
    };

    return (
        <>
            <style>{`
                .ai-copilot-drawer .ant-drawer-content-wrapper {
                    box-shadow: none !important;
                    background: transparent !important;
                }
                .ai-copilot-drawer .ant-drawer-content {
                    background:
                        linear-gradient(180deg, rgba(255,255,255,0.94), rgba(248, 250, 252, 0.92)) !important;
                    border: 1px solid rgba(226, 232, 240, 0.9);
                    border-radius: 26px !important;
                    overflow: hidden !important;
                    box-shadow:
                        -10px 18px 54px rgba(15, 23, 42, 0.12),
                        0 0 0 1px rgba(255,255,255,0.64) inset !important;
                    backdrop-filter: blur(22px) saturate(160%);
                    -webkit-backdrop-filter: blur(22px) saturate(160%);
                }
                .ai-copilot-drawer .ant-drawer-header {
                    padding: 18px 20px !important;
                }
                .ai-copilot-drawer .ant-drawer-close {
                    color: #64748b !important;
                    transition: color 180ms ease, transform 180ms ease;
                }
                .ai-copilot-drawer .ant-drawer-close:hover {
                    color: #0f172a !important;
                    transform: scale(1.04);
                }
                .ai-copilot-title {
                    display: flex;
                    align-items: center;
                    gap: 12px;
                    min-width: 0;
                }
                .ai-copilot-title-core {
                    position: relative;
                    width: 38px;
                    height: 38px;
                    flex: 0 0 38px;
                    border-radius: 14px;
                    background:
                        radial-gradient(circle at 32% 24%, rgba(255,255,255,0.96), rgba(255,255,255,0.18) 34%, transparent 35%),
                        linear-gradient(145deg, #38bdf8 0%, #0ea5e9 42%, #2563eb 100%);
                    box-shadow: 0 10px 24px rgba(37, 99, 235, 0.24), inset 0 1px 0 rgba(255,255,255,0.42);
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    overflow: hidden;
                }
                .ai-copilot-title-core::after {
                    content: "";
                    position: absolute;
                    width: 150%;
                    height: 1px;
                    left: -25%;
                    top: 50%;
                    background: linear-gradient(90deg, transparent, rgba(255,255,255,0.9), transparent);
                    animation: ai-title-scan 3s ease-in-out infinite;
                }
                .ai-copilot-title-text {
                    display: flex;
                    flex-direction: column;
                    gap: 2px;
                    min-width: 0;
                }
                .ai-copilot-title-name {
                    font-weight: 680;
                    font-size: 16px;
                    color: #111827;
                    letter-spacing: 0;
                    line-height: 1.2;
                }
                .ai-copilot-title-sub {
                    font-size: 11px;
                    color: #94a3b8;
                    font-weight: 500;
                    line-height: 1.2;
                }
                .ai-copilot-module-tag {
                    border: 1px solid rgba(14, 165, 233, 0.12) !important;
                    border-radius: 999px !important;
                    background: rgba(224, 242, 254, 0.72) !important;
                    color: #0284c7 !important;
                    font-weight: 600 !important;
                    max-width: 128px;
                    overflow: hidden;
                    text-overflow: ellipsis;
                }
                .ai-copilot-body {
                    flex: 1;
                    overflow-y: auto;
                    padding: 22px 18px;
                    display: flex;
                    flex-direction: column;
                    background:
                        radial-gradient(circle at 78% 6%, rgba(14, 165, 233, 0.08), transparent 26%),
                        linear-gradient(180deg, rgba(255,255,255,0.56), rgba(248,250,252,0.34));
                }
                .ai-copilot-empty {
                    min-height: 100%;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    text-align: center;
                    padding: 24px 12px 96px;
                }
                .ai-copilot-empty-inner {
                    max-width: 320px;
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                }
                .ai-copilot-orb {
                    position: relative;
                    width: 92px;
                    height: 92px;
                    border-radius: 30px;
                    background:
                        linear-gradient(135deg, rgba(255,255,255,0.82), rgba(224,242,254,0.46)),
                        linear-gradient(145deg, #38bdf8, #2563eb);
                    box-shadow:
                        0 22px 48px rgba(37, 99, 235, 0.2),
                        inset 0 1px 0 rgba(255,255,255,0.72);
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    overflow: hidden;
                    margin-bottom: 22px;
                }
                .ai-copilot-orb::before {
                    content: "";
                    position: absolute;
                    inset: 14px;
                    border: 1px solid rgba(255,255,255,0.45);
                    border-radius: 22px;
                }
                .ai-copilot-orb::after {
                    content: "";
                    position: absolute;
                    width: 140%;
                    height: 2px;
                    background: linear-gradient(90deg, transparent, rgba(255,255,255,0.86), transparent);
                    transform: rotate(-22deg);
                    animation: ai-title-scan 3.4s ease-in-out infinite;
                }
                .ai-copilot-empty h3 {
                    margin: 0 0 10px;
                    color: #111827;
                    font-size: 22px;
                    font-weight: 700;
                    letter-spacing: 0;
                }
                .ai-copilot-empty p {
                    margin: 0;
                    color: #7c8491;
                    font-size: 14px;
                    line-height: 1.7;
                }
                .ai-copilot-suggestions {
                    margin-top: 18px;
                    display: flex;
                    flex-wrap: wrap;
                    justify-content: center;
                    gap: 8px;
                }
                .ai-copilot-suggestion {
                    padding: 7px 11px;
                    border: 1px solid rgba(148, 163, 184, 0.22);
                    border-radius: 999px;
                    background: rgba(255,255,255,0.72);
                    color: #475569;
                    font-size: 12px;
                    font-weight: 560;
                }
                .ai-message-list {
                    display: flex;
                    flex-direction: column;
                    gap: 18px;
                }
                .ai-message-row {
                    display: flex;
                    flex-direction: column;
                }
                .ai-message-row.user {
                    align-items: flex-end;
                }
                .ai-message-row.assistant {
                    align-items: flex-start;
                }
                .ai-message-bubble {
                    max-width: min(88%, 640px);
                    padding: 13px 17px;
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                    font-size: 14px;
                    line-height: 1.55;
                    letter-spacing: 0;
                    overflow-wrap: anywhere;
                }
                .ai-message-bubble.user {
                    color: #fff;
                    border-radius: 21px 21px 5px 21px;
                    background: linear-gradient(145deg, #0ea5e9 0%, #2563eb 100%);
                    box-shadow: 0 12px 28px rgba(37, 99, 235, 0.22);
                    white-space: pre-wrap;
                }
                .ai-message-bubble.assistant {
                    color: #1d1d1f;
                    border-radius: 21px 21px 21px 5px;
                    background: rgba(255,255,255,0.82);
                    border: 1px solid rgba(226, 232, 240, 0.82);
                    box-shadow: 0 14px 32px rgba(15, 23, 42, 0.06), inset 0 1px 0 rgba(255,255,255,0.86);
                    backdrop-filter: blur(14px);
                    -webkit-backdrop-filter: blur(14px);
                }
                .ai-tool-row {
                    width: min(88%, 640px);
                    align-self: flex-start;
                }
                .ai-tool-card {
                    width: 100%;
                    border: 1px solid rgba(14, 165, 233, 0.18);
                    border-radius: 16px;
                    padding: 10px 12px;
                    background: rgba(240, 249, 255, 0.72);
                    display: grid;
                    grid-template-columns: 24px 1fr auto;
                    align-items: center;
                    gap: 10px;
                    cursor: pointer;
                    text-align: left;
                    box-shadow: 0 10px 24px rgba(14, 165, 233, 0.08), inset 0 1px 0 rgba(255,255,255,0.76);
                    transition: transform 180ms ease, border-color 180ms ease, background 180ms ease;
                }
                .ai-tool-card:hover {
                    transform: translateY(-1px);
                    border-color: rgba(14, 165, 233, 0.34);
                    background: rgba(236, 253, 245, 0.72);
                }
                .ai-tool-card.error {
                    border-color: rgba(239, 68, 68, 0.24);
                    background: rgba(254, 242, 242, 0.78);
                }
                .ai-tool-icon {
                    color: #0284c7;
                    display: inline-flex;
                    align-items: center;
                    justify-content: center;
                }
                .ai-tool-card.error .ai-tool-icon {
                    color: #dc2626;
                }
                .ai-tool-main {
                    display: flex;
                    flex-direction: column;
                    min-width: 0;
                }
                .ai-tool-name {
                    color: #0f172a;
                    font-size: 13px;
                    font-weight: 650;
                    overflow: hidden;
                    text-overflow: ellipsis;
                    white-space: nowrap;
                }
                .ai-tool-meta,
                .ai-tool-toggle {
                    color: #64748b;
                    font-size: 12px;
                    font-weight: 520;
                }
                .ai-tool-detail {
                    margin-top: 8px;
                    border: 1px solid rgba(203, 213, 225, 0.62);
                    border-radius: 14px;
                    background: rgba(255,255,255,0.72);
                    padding: 10px 12px;
                    box-shadow: inset 0 1px 0 rgba(255,255,255,0.8);
                }
                .ai-tool-detail-label {
                    display: block;
                    margin: 2px 0 6px;
                    color: #64748b !important;
                    font-size: 11px !important;
                    font-weight: 650;
                    text-transform: uppercase;
                }
                .ai-tool-detail pre {
                    max-height: 190px;
                    overflow: auto;
                    margin: 0 0 8px;
                    white-space: pre-wrap;
                    overflow-wrap: anywhere;
                    font-size: 12px;
                    line-height: 1.45;
                    color: #334155;
                }
                .ai-edit-action {
                    margin-top: 12px;
                    padding-top: 10px;
                    border-top: 1px solid rgba(203, 213, 225, 0.58);
                    display: flex;
                    align-items: center;
                    flex-wrap: wrap;
                    gap: 8px;
                }
                .ai-edit-action .ant-btn {
                    border-radius: 999px;
                    background: linear-gradient(145deg, #0ea5e9 0%, #2563eb 100%);
                    box-shadow: 0 10px 22px rgba(37, 99, 235, 0.18);
                }
                .ai-edit-action-note {
                    color: #64748b !important;
                    font-size: 12px !important;
                }
                .ai-pending-actions {
                    margin-top: 12px;
                    display: flex;
                    flex-direction: column;
                    gap: 8px;
                }
                .ai-pending-action-card {
                    border: 1px solid rgba(148, 163, 184, 0.34);
                    background: rgba(248, 250, 252, 0.86);
                    border-radius: 12px;
                    padding: 10px;
                    display: flex;
                    flex-direction: column;
                    gap: 8px;
                }
                .ai-pending-action-head {
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                    gap: 10px;
                }
                .ai-pending-action-title {
                    font-weight: 650;
                    color: #0f172a;
                    min-width: 0;
                }
                .ai-pending-action-summary {
                    color: #475569 !important;
                    font-size: 12px !important;
                    line-height: 1.55 !important;
                }
                .ai-pending-action-preview {
                    margin: 0;
                    max-height: 130px;
                    overflow: auto;
                    white-space: pre-wrap;
                    overflow-wrap: anywhere;
                    border-radius: 8px;
                    background: #0f172a;
                    color: #dbeafe;
                    padding: 8px;
                    font-size: 12px;
                    line-height: 1.45;
                }
                .ai-pending-action-foot {
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                    gap: 10px;
                    flex-wrap: wrap;
                }
                .ai-action-confirm pre {
                    max-height: 220px;
                    overflow: auto;
                    white-space: pre-wrap;
                    overflow-wrap: anywhere;
                    background: #0f172a;
                    color: #dbeafe;
                    border-radius: 8px;
                    padding: 10px;
                }
                .ai-action-confirm-meta {
                    display: flex;
                    gap: 8px;
                    flex-wrap: wrap;
                    margin-top: 8px;
                }
                .ai-reset-button {
                    color: #64748b !important;
                    border-radius: 999px !important;
                }
                .ai-reset-button:hover {
                    color: #0f172a !important;
                    background: rgba(226, 232, 240, 0.62) !important;
                }
                .ai-copilot-footer {
                    padding: 16px 18px 22px;
                    background: rgba(248, 250, 252, 0.84);
                    backdrop-filter: blur(22px);
                    -webkit-backdrop-filter: blur(22px);
                    border-top: 1px solid rgba(226, 232, 240, 0.72);
                }
                .ai-input-wrap {
                    position: relative;
                    display: flex;
                    align-items: flex-end;
                }
                .ai-copilot-input.ant-input {
                    border-radius: 22px !important;
                    background: rgba(255,255,255,0.86) !important;
                    border: 1px solid rgba(203, 213, 225, 0.74) !important;
                    box-shadow: 0 10px 28px rgba(15,23,42,0.04), inset 0 1px 0 rgba(255,255,255,0.9) !important;
                    padding: 11px 84px 11px 16px !important;
                    font-size: 14px !important;
                    line-height: 1.5 !important;
                    resize: none !important;
                    transition: border-color 180ms ease, box-shadow 180ms ease;
                }
                .ai-copilot-input.ant-input:focus {
                    border-color: rgba(14, 165, 233, 0.42) !important;
                    box-shadow: 0 12px 30px rgba(14,165,233,0.1), 0 0 0 3px rgba(14,165,233,0.09) !important;
                }
                .ai-send-button,
                .ai-stop-button {
                    position: absolute !important;
                    bottom: 7px !important;
                    width: 34px !important;
                    height: 34px !important;
                    display: flex !important;
                    align-items: center !important;
                    justify-content: center !important;
                    border-color: transparent !important;
                    box-shadow: none !important;
                }
                .ai-send-button {
                    right: 7px !important;
                    background: linear-gradient(145deg, #0ea5e9, #2563eb) !important;
                }
                .ai-stop-button {
                    right: 46px !important;
                    background: rgba(241,245,249,0.92) !important;
                    color: #64748b !important;
                }
                @keyframes ai-title-scan {
                    0%, 100% { transform: translateY(-18px) rotate(-22deg); opacity: 0; }
                    18%, 72% { opacity: 0.78; }
                    55% { transform: translateY(20px) rotate(-22deg); opacity: 0.54; }
                }
                .ai-markdown {
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                    font-size: 14px;
                    line-height: 1.65;
                    color: #1d1d1f;
                    overflow-wrap: anywhere;
                }
                .ai-markdown p {
                    margin: 0 0 10px;
                }
                .ai-markdown p:last-child,
                .ai-markdown ul:last-child,
                .ai-markdown ol:last-child,
                .ai-markdown pre:last-child,
                .ai-markdown blockquote:last-child,
                .ai-markdown table:last-child,
                .ai-markdown hr:last-child {
                    margin-bottom: 0;
                }
                .ai-markdown h1,
                .ai-markdown h2,
                .ai-markdown h3,
                .ai-markdown h4,
                .ai-markdown h5,
                .ai-markdown h6 {
                    margin: 12px 0 8px;
                    font-weight: 650;
                    line-height: 1.35;
                    color: #0f172a;
                }
                .ai-markdown h1 { font-size: 18px; }
                .ai-markdown h2 { font-size: 17px; }
                .ai-markdown h3 { font-size: 16px; }
                .ai-markdown h4 { font-size: 15px; }
                .ai-markdown h5 { font-size: 14px; }
                .ai-markdown h6 { font-size: 13px; color: #475569; }
                .ai-markdown ul,
                .ai-markdown ol {
                    margin: 0 0 10px;
                    padding-left: 22px;
                }
                .ai-markdown li {
                    margin: 4px 0;
                    padding-left: 2px;
                }
                .ai-markdown strong {
                    font-weight: 650;
                    color: #0f172a;
                }
                .ai-markdown em {
                    font-style: italic;
                    color: #334155;
                }
                .ai-markdown del {
                    text-decoration: line-through;
                    color: #94a3b8;
                }
                .ai-markdown code {
                    font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
                    font-size: 0.92em;
                    padding: 2px 5px;
                    border-radius: 5px;
                    background: #f1f5f9;
                    color: #0f172a;
                }
                .ai-markdown pre {
                    margin: 0 0 10px;
                    padding: 12px;
                    border-radius: 8px;
                    background: #0f172a;
                    overflow-x: auto;
                }
                .ai-markdown pre code {
                    padding: 0;
                    background: transparent;
                    color: #e2e8f0;
                    white-space: pre;
                }
                .ai-markdown blockquote {
                    margin: 0 0 10px;
                    padding: 8px 12px;
                    border-left: 3px solid #0ea5e9;
                    background: #f8fafc;
                    color: #475569;
                }
                .ai-markdown blockquote span {
                    display: inline;
                }
                .ai-markdown a {
                    color: #0284c7;
                    text-decoration: none;
                }
                .ai-markdown a:hover {
                    text-decoration: underline;
                }
                .ai-markdown hr {
                    margin: 14px 0;
                    border: none;
                    height: 1px;
                    background: linear-gradient(90deg, transparent, #cbd5e1, transparent);
                }
                .ai-md-table-wrap {
                    margin: 0 0 10px;
                    overflow-x: auto;
                    border-radius: 10px;
                    border: 1px solid rgba(226, 232, 240, 0.82);
                }
                .ai-markdown table {
                    width: 100%;
                    border-collapse: collapse;
                    font-size: 13px;
                    line-height: 1.5;
                }
                .ai-markdown thead {
                    background: rgba(241, 245, 249, 0.82);
                }
                .ai-markdown th {
                    padding: 8px 12px;
                    font-weight: 650;
                    color: #0f172a;
                    text-align: left;
                    border-bottom: 2px solid rgba(203, 213, 225, 0.62);
                    white-space: nowrap;
                }
                .ai-markdown td {
                    padding: 7px 12px;
                    color: #334155;
                    border-bottom: 1px solid rgba(226, 232, 240, 0.52);
                }
                .ai-markdown tbody tr:last-child td {
                    border-bottom: none;
                }
                .ai-markdown tbody tr:nth-child(even) {
                    background: rgba(248, 250, 252, 0.56);
                }
                .ai-markdown tbody tr:hover {
                    background: rgba(224, 242, 254, 0.36);
                }
            `}</style>
            <Drawer
                zIndex={9999}
                rootClassName="ai-copilot-drawer"
                title={
                    <div className="ai-copilot-title">
                        <div className="ai-copilot-title-core">
                            <SecurityScanOutlined style={{ color: '#fff', fontSize: 19, zIndex: 1 }} />
                        </div>
                        <div className="ai-copilot-title-text">
                            <span className="ai-copilot-title-name">Argus Copilot</span>
                            <span className="ai-copilot-title-sub">Context aware security assistant</span>
                        </div>
                        {pageContext?.module && <Tag className="ai-copilot-module-tag">{pageContext.module}</Tag>}
                    </div>
                }
                placement="right"
                width={520}
                mask={false}
                onClose={handleClose}
                open={visible}
                extra={
                    <Button
                        className="ai-reset-button"
                        type="text"
                        icon={<DeleteOutlined />}
                        onClick={resetConversation}
                        disabled={messages.length === 0 && !streamingContent}
                    />
                }
                styles={{ body: { display: 'flex', flexDirection: 'column', padding: 0 }, header: { borderBottom: '1px solid rgba(226,232,240,0.72)', background: 'rgba(255,255,255,0.72)', backdropFilter: 'blur(18px)' } }}
                style={{
                    margin: '18px',
                    height: 'calc(100% - 36px)',
                }}
            >
            <div className="ai-copilot-body">
                {messages.length === 0 && (
                    <div className="ai-copilot-empty">
                        <div className="ai-copilot-empty-inner">
                            <div className="ai-copilot-orb">
                                <RadarChartOutlined style={{ color: '#fff', fontSize: 42, zIndex: 1 }} />
                            </div>
                            <h3>全局安全助手</h3>
                            <p>我会结合当前页面上下文，帮助你分析资产、排查任务、解释漏洞证据或编写智能 POC。</p>
                            <div className="ai-copilot-suggestions">
                                <span className="ai-copilot-suggestion">分析当前页面</span>
                                <span className="ai-copilot-suggestion">解释风险</span>
                                <span className="ai-copilot-suggestion">优化 POC</span>
                            </div>
                        </div>
                    </div>
                )}

                <div className="ai-message-list">
                    {messages.map((item, index) => {
                        if (item.role === 'tool' && item.toolTrace) {
                            const tool = item.toolTrace;
                            const expanded = !!expandedTools[tool.id];
                            const statusText = tool.status === 'running' ? '运行中' : tool.status === 'error' ? '失败' : '已完成';
                            return (
                                <div key={index} className="ai-tool-row">
                                    <button className={`ai-tool-card ${tool.status}`} onClick={() => toggleToolTrace(tool.id)}>
                                        <span className="ai-tool-icon">
                                            {tool.status === 'running' ? <Spin size="small" /> : <RobotOutlined />}
                                        </span>
                                        <span className="ai-tool-main">
                                            <span className="ai-tool-name">{tool.name}</span>
                                            <span className="ai-tool-meta">
                                                {statusText}{typeof tool.durationMs === 'number' ? ` · ${tool.durationMs}ms` : ''}
                                            </span>
                                        </span>
                                        <span className="ai-tool-toggle">{expanded ? '收起' : '详情'}</span>
                                    </button>
                                    {expanded && (
                                        <div className="ai-tool-detail">
                                            {tool.args && (
                                                <>
                                                    <Text className="ai-tool-detail-label">Args</Text>
                                                    <pre>{tool.args}</pre>
                                                </>
                                            )}
                                            {tool.result && (
                                                <>
                                                    <Text className="ai-tool-detail-label">Result</Text>
                                                    <pre>{tool.result}</pre>
                                                </>
                                            )}
                                        </div>
                                    )}
                                </div>
                            );
                        }
                        const editKey = `${index}-${item.proposedEdit?.type || 'none'}`;
                        const editApplied = !!appliedEdits[editKey];
                        return (
                            <div key={index} className={`ai-message-row ${item.role}`}>
                                <div className={`ai-message-bubble ${item.role}`}>
                                    {item.role === 'assistant' ? <MarkdownMessage content={item.content} /> : item.content}
                                    {item.role === 'assistant' && item.proposedEdit && editableTarget?.type === item.proposedEdit.type && (
                                        <div className="ai-edit-action">
                                            <Button
                                                size="small"
                                                type="primary"
                                                icon={<RobotOutlined />}
                                                disabled={editApplied}
                                                onClick={() => applyProposedEdit(editKey, item.proposedEdit!)}
                                            >
                                                {editApplied ? '已应用' : `应用到 ${editableTarget.label}`}
                                            </Button>
                                            {editApplied && editableTarget.saveDraft && (
                                                <Button
                                                    size="small"
                                                    onClick={() => saveEditableDraft(editKey)}
                                                    loading={savingDraft}
                                                >
                                                    保存草稿
                                                </Button>
                                            )}
                                            <Text className="ai-edit-action-note">
                                                {editApplied ? '已写入当前编辑器；保存草稿仍由你确认触发。' : '仅写入当前编辑器，保存仍需手动确认。'}
                                            </Text>
                                        </div>
                                    )}
                                    {item.role === 'assistant' && item.pendingActions && item.pendingActions.length > 0 && (
                                        <div className="ai-pending-actions">
                                            {item.pendingActions.map((action, actionIndex) => {
                                                const actionKey = `${index}-${action.action_type}-${actionIndex}`;
                                                const doneMessage = completedActions[actionKey];
                                                return (
                                                    <div className="ai-pending-action-card" key={actionKey}>
                                                        <div className="ai-pending-action-head">
                                                            <span className="ai-pending-action-title">{action.title || action.action_type}</span>
                                                            <Tag color={riskColor(action.risk_level)}>{action.risk_level || 'low'}</Tag>
                                                        </div>
                                                        <Text className="ai-pending-action-summary">
                                                            {action.summary || '该动作需要确认后执行。'}
                                                        </Text>
                                                        {action.preview && <pre className="ai-pending-action-preview">{action.preview}</pre>}
                                                        <div className="ai-pending-action-foot">
                                                            <Text className="ai-pending-action-summary">
                                                                需要权限：{action.required_role || 'operator'}
                                                            </Text>
                                                            <Button
                                                                size="small"
                                                                type="primary"
                                                                disabled={!!doneMessage}
                                                                loading={executingActionKey === actionKey}
                                                                onClick={() => executePendingAction(actionKey, action)}
                                                            >
                                                                {doneMessage ? '已执行' : action.confirm_label || '确认执行'}
                                                            </Button>
                                                        </div>
                                                        {doneMessage && <Text className="ai-pending-action-summary">{doneMessage}</Text>}
                                                    </div>
                                                );
                                            })}
                                        </div>
                                    )}
                                </div>
                            </div>
                        );
                    })}

                    {streamingContent && (
                        <div className="ai-message-row assistant">
                            <div className="ai-message-bubble assistant">
                                <MarkdownMessage content={streamingContent} />
                            </div>
                        </div>
                    )}

                    <div ref={messagesEndRef} />
                </div>
            </div>

            <div className="ai-copilot-footer">
                <div className="ai-input-wrap">
                    <Input.TextArea
                        className="ai-copilot-input"
                        value={inputValue}
                        onChange={e => setInputValue(e.target.value)}
                        placeholder="输入指令..."
                        autoSize={{ minRows: 1, maxRows: 5 }}
                        onPressEnter={(e) => {
                            if (!e.shiftKey) {
                                e.preventDefault();
                                handleSend();
                            }
                        }}
                        disabled={loading}
                    />
                    <Button
                        className="ai-send-button"
                        type="primary"
                        shape="circle"
                        icon={<SendOutlined style={{ marginLeft: 2 }}/>}
                        onClick={handleSend}
                        loading={loading}
                    />
                    {loading && (
                        <Button
                            className="ai-stop-button"
                            shape="circle"
                            icon={<StopOutlined />}
                            onClick={stopStreaming}
                        />
                    )}
                </div>
                <div style={{ textAlign: 'center', marginTop: 11 }}>
                    <Text style={{ fontSize: 11, color: '#98989d' }}>Argus Copilot 可能产生不准确的结果，请验证关键操作。</Text>
                </div>
            </div>
        </Drawer>
        </>
    );
};

export default GlobalAIChatDrawer;
