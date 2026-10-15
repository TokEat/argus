export const cursorConfigSnippet = (mcpUrl: string) => `{
  "mcpServers": {
    "argus": {
      "url": ${JSON.stringify(mcpUrl || 'http://127.0.0.1:8085/mcp')}
    }
  }
}`;

export const toolCategoryLabel: Record<string, { color: string; text: string }> = {
    read: { color: 'blue', text: '读取' },
    debug: { color: 'orange', text: '调试' },
    draft: { color: 'gold', text: '草稿' },
    publish: { color: 'red', text: '发布' },
    scan: { color: 'purple', text: '扫描' },
    exp: { color: 'magenta', text: 'EXP' },
};

export const formatMcpTime = (value?: string) => {
    if (!value) return '-';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return date.toLocaleString('zh-CN');
};
