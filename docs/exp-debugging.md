# Yaksha EXP 测试与调试

Yaksha EXP 使用单个 `main.yak`，调试的目标是验证该 Yaklang 源码、声明式 CLI 参数、Fixture、依赖、Asset 和授权出口。调试不替代发布门禁；所有已保存执行都绑定 `exp_id + revision + source_sha256`。

临时内存源码只能用于 inspect、validate 和永久离线的 Fixture test。真实 debug/run 必须先保存为 Server Draft Revision，并由 Server 在执行前创建 Run 审计后编排 Yaksha；源码、依赖或 Asset 引用修改后必须创建新 Revision，不能直接执行未审计的临时脚本。

## 五种动作

- `inspect`：只分析源码，生成官方 `cli.*` Schema，并提取字面量 `yaksha.call` / `yaksha.asset` 引用。
- `validate`：校验密封包、参数和出口合同，不运行 VM。
- `test`：使用 Server Fixture 验收，永久离线。
- `debug`：运行源码并返回完整未脱敏 HTTP/TCP Trace、日志、Evidence 和调用树。
- `run`：执行一次已授权操作并写入运行审计，不自动重试。

## 推荐流程

1. 在 Server Web UI 或 MCP App 创建 EXP 和 Draft Revision。
2. 执行 inspect，根据 CLI Schema 渲染和补齐参数。
3. 创建 Fixture 并运行 test；未通过不能发布。
4. 对授权目标选择 `disabled/direct/socks5/agent` 之一进行 debug。
5. 修复源码时创建新 Revision，重新执行 inspect、validate 和 test。
6. Admin 使用确定 Revision 的源码 SHA-256 人工确认发布；回滚只切换活动 Published Revision。

SOCKS5 URL 为单次 write-only 输入，不回填、不进入 Worker、Trace 或日志。Agent 出口使用 Agent 原生 TCP relay，不套 SOCKS5。`test` 无论请求内容如何都不会联网。

## 存储与访问

生产环境使用私有 MinIO 保存 `main.yak`、Asset、Trace、Evidence 和调用树；PostgreSQL 只保存治理数据、对象键、大小、哈希和审计。AI 只通过 MCP Tool/MCP App 操作逻辑对象，不获得 MinIO 凭据、对象键、宿主路径或任意文件读取能力。
