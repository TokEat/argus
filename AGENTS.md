# AGENTS.md

本文是 Argus 仓库的 Codex/AI 代理指令。执行任何任务前，先阅读本文件和 `CONTRIBUTING.md`。

## Repository role

Argus 是面向合法授权安全测试、分布式扫描、规则治理、云资源调度和 AI Copilot 辅助运营的平台。所有改动必须保持授权边界、租户隔离、RBAC、审计记录和安全默认值。

## Non-negotiable rules

- 不得削弱认证、RBAC、租户隔离、对象级授权、CORS、危险操作确认、审计日志或安全默认值。
- 不得提交真实凭据、Token、Cookie、API Key、连接串、真实目标、客户数据、本地配置、未脱敏日志或截图。
- 不得为了联调绕过租户过滤、对象归属检查、发布/审核流程、危险操作确认或审计。
- 涉及 AI Copilot、POC、EXP、Workflow、Dir 字典、云资源、OSS 分发、Agent 执行链路时，默认保持草稿优先、人工确认、审计留痕和最小权限。
- 涉及 `tenant_id`、`project_id`、`task_id`、`agent_id`、`user_id`、规则 ID、云账号 ID、构建任务 ID、日志或导出文件等对象标识时，必须验证当前用户是否拥有或被授权访问该对象。
- 不要修改与任务无关的格式、依赖、生成物、缓存或本地配置。
- 不要触碰用户已有未提交改动，除非任务明确要求并已确认。

## Default workflow

对每个非平凡任务：

1. 找到关联 Issue；如果没有，说明缺失或记录豁免原因。
2. 先读相关代码、文档、测试和配置，遵循现有模式。
3. 保持 diff 聚焦于一个逻辑目标。
4. 行为、API、配置、部署、schema、规则、模板或用户流程变化时，同步测试和文档。
5. 按 `CONTRIBUTING.md` 的验证矩阵运行最小充分验证。
6. 不能运行的检查必须说明原因、环境限制和替代验证方式。
7. 最终汇报 Summary、Files changed、Validation、Security notes、Risks / rollback notes、Checks not run。

## Definition of done

任务只有在以下条件满足时才算完成：

- 实现满足 Issue 或用户请求的验收标准。
- 相关构建、测试、lint、smoke 或手动验证已执行，或跳过原因明确。
- diff 不包含无关格式化、依赖升级、生成物、缓存、本地配置或敏感信息。
- 安全敏感路径保留身份校验、对象级授权、租户隔离、审计记录和安全默认值。
- 文档、配置模板、migration、部署脚本、PR/Issue 模板或 README 在需要时已同步。
- 已说明剩余风险和回滚方式。

## Validation matrix

- 根模块 Go 代码、scanner、shared：`go test ./...`
- Server 后端：`cd server && go test ./...`
- MCP 代理：`cd mcp && go test ./...`
- 前端：`npm --prefix server-ui run lint`、`npm --prefix server-ui run test -- --run`、`npm --prefix server-ui run build`
- 前端 smoke：`npm --prefix server-ui run test:smoke`
- 数据库 migration、schema、部署数据库路径：`make db-verify`
- 云资源调度：`make cloud-smoke`
- 发布脚本、发行包、部署脚本：`make release-artifacts`
- 跨模块或合并前完整验证：`make ci`
- 文档-only：手动检查链接、路径、命令、代码块和 README 索引

## Final response format

```text
Summary:
- ...

Files changed:
- ...

Validation:
- PASS/SKIPPED/FAIL: ...

Security notes:
- ...

Risks / rollback:
- ...
```
