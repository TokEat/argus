# AGENTS.md

本文是 Argus 仓库的代理指令，Codex、Claude Code 与 Grok 都遵守本文件。执行任务前先读本文件和 `CONTRIBUTING.md`。

指令文件：

- 本文件是唯一的完整代理指令。根目录 `CLAUDE.md` 只作为 Claude Code 入口并引用本文件，不要在那里维护第二套规则。
- 改 `config/` 或 `scanner/common/config/` 弹药库时，同时遵守 `config/AGENTS.md`。与本文件冲突时，以更深目录的文件为准。
- 目录职责见 `docs/project-structure.md`，授权边界见 `SECURITY.md`。

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

当用户要求完成 GitHub 闭环时，默认流程为：

```text
issue -> branch -> code -> test -> review -> commit -> push -> PR -> merge -> close
```

除维护者明确要求外，不要把非平凡改动直接提交到 `main`。如因维护者指令在当前分支提交，必须说明原因、提交范围、验证结果以及后续是否需要推送、PR 或合并。

## Debugging and verification

- 先复现问题、定位根因，再修改代码；不要用猜测式补丁掩盖症状。
- 涉及前端页面、API、Agent、CLI、Scanner、云调度、规则同步或部署行为时，优先做真实调用或 smoke 验证。
- 用户提供授权测试目标时，默认只做完成问题所需的最小验证；例如指纹验证优先使用 `-nopoc`，不要无故执行 POC/EXP。需要同时关掉 GoPoc 时再加 `-nogpoc`。
- 浏览器问题需要用浏览器验证；接口问题需要用真实 HTTP/API 调用验证；Scanner 行为需要用 CLI/Agent 或最小测试靶场验证。
- sandbox、网络或权限限制导致验证失败时，按规则申请必要权限重跑；仍不能运行时，记录失败原因和替代证据。
- 提交或合并前优先使用子智能体或独立 reviewer 做只读 review；Critical/Important 反馈必须修复或明确说明技术取舍。

## Issue and review discipline

- 新建 Issue 前必须确认问题真实存在、可复现，并写清楚背景、实际表现、预期表现、复现步骤、初步原因、影响范围、验收标准和回归风险。
- Issue 不应只是空标题或泛泛描述；如果问题尚未复现，先继续排查，不要为了流程创建低质量 Issue。
- 修复方案必须说明为什么不会破坏相关功能；无法完全证明时，必须列出风险和验证补救。
- 子智能体 review 只能接收最小必要 diff 和只读任务，默认 `fork_context=false`。
- 给子智能体的 review 指令必须明确包含：不得创建子智能体、不得改文件、不得执行会改变工作区或仓库状态的 git 操作、不得执行 GitHub 操作。
- 子智能体只提供 review 结论和风险提示；Issue、branch、commit、push、PR、merge、close 等 GitHub 闭环动作只能由主线程执行。

## Domain behavior changes

- 修改规则、模板、字典、扫描链路、同步链路或构建模式前，必须先理解数据来源、触发条件、运行时读取路径和输出去向。
- 不要把元数据、检索语句、展示字段或注释误认为运行时触发条件；需要从代码和实际调用链确认行为。
- 不要在不了解上下游依赖的情况下删除、改名、降级或大规模重排规则和配置。
- 对扫描覆盖率、误报率、同步一致性、构建产物或部署结果有影响的改动，必须提供可复现的最小验证。
- 涉及本地文件、数据库、内嵌资源、远端同步包或运行时缓存之间的数据转换时，必须说明权威来源、覆盖范围、幂等策略和回滚方式。

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
- Yaksha（独立 module，不在 `go.work` 内）：`cd yaksha && GOWORK=off go test ./...`
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
