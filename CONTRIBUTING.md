# 贡献与协作指南

Argus 面向合法授权的安全测试、分布式扫描、规则治理、云资源调度和 AI Copilot。贡献必须保持授权边界、租户隔离、RBAC、审计和安全默认值。人类贡献者与代码代理同时遵守本文和 `AGENTS.md`。

## 原则

- `main` 保持可构建、可发布。禁止直接提交；变更经短生命周期分支和 PR 合并，优先 Squash and merge，合并后删除任务分支。
- 非平凡改动先建 Issue，PR 用 `Fixes #n`、`Closes #n` 或 `Resolves #n` 关联。极小错别字、注释或无行为影响的格式维护可免 Issue，但 PR 要写明原因。
- PR 说明目的、影响范围、验证结果、安全风险和回滚方式。验证记录贴实际命令输出。
- 不提交真实凭据、Token、Cookie、API Key、连接串、真实目标、客户数据、未脱敏日志或截图、本地配置、生成缓存。
- 不放宽认证、RBAC、租户隔离、对象级授权、CORS、危险操作确认、审计或安全默认值。带对象标识的接口必须确认当前用户拥有或被授权访问该对象，不能只校验登录态。标识包括 `tenant_id`、`project_id`、`task_id`、`agent_id`、`user_id`、`role_id`、规则、云账号、构建任务、日志和导出文件。
- AI Copilot、POC、EXP、Workflow、Dir 字典、云资源、OSS 分发和 Agent 执行链路默认草稿优先、人工确认、审计留痕、最小权限。新增高风险动作必须声明权限、确认语义、审计字段、超时和失败行为。
- 提交信息使用 `type(scope): summary`。类型：`feat`、`fix`、`refactor`、`perf`、`test`、`docs`、`chore`、`ci`、`style`。一个提交只做一件事，不把功能、重构、格式化和依赖升级混在一起。

## Issue

非平凡改动包括：功能、缺陷、性能、重构、用户可见行为；API、WebSocket、gRPC、migration、部署、发布、配置模板；认证、RBAC、租户隔离、对象级授权、审计、安全默认值；POC、EXP、Workflow、规则库、AI Copilot、云资源、OSS、Agent 执行链路。

Issue 写清背景、目标与非目标、影响路径、验收标准、风险、验证方式，以及是否触及安全敏感能力、真实目标或敏感数据。闭环要求：PR 已关联或说明豁免；验收项已验证；CI 与 review 通过且没有未解决评论；合并后关闭 Issue。发布或生产风险补回滚与上线验证记录。

## 分支

`main` 是唯一日常主线，不设 `develop`。分支名为英文小写，单词用 `-` 连接。一条分支只处理一个目标。除极小维护外，分支名带 Issue 编号，避免 `feat/test`、`fix/bug` 这类空名称。

| 分支 | 用途 |
|------|------|
| `feat/*`、`fix/*`、`refactor/*`、`chore/*`、`docs/*`、`test/*` | 日常任务 |
| `hotfix/*` | 线上紧急修复。先 PR 回 `main`；若有未结束的 `release/*`，把同一修复同步过去，并说明影响、验证、回滚和是否补发版本 |
| `release/*` | 只在版本冻结时创建，只收发布修复。必要修复完成后回到 `main`。版本以 tag 为准 |

```bash
git switch main && git pull origin main
git switch -c feat/123-your-change
git push -u origin feat/123-your-change
```

提交前核对 `git status --short` 和 `git diff`，按验证矩阵执行，并对改到的接口、页面、部署或发布路径做手动验证。PR 标题用 Conventional Commits，例如 `fix: 修复任务队列重复确认问题`。

`main` 在代码托管平台开启保护：禁止直接 push、force push 和删除分支；PR 至少 1 人批准；必需状态检查通过；合并前与最新 `main` 同步；解决全部 review conversation；保留 Squash and merge。这些开关要在 GitHub 仓库设置里打开。

## 不得合并

- 非豁免改动未关联 Issue，或未写验证命令和结果。
- CI 未通过且维护者未明确豁免，或仍有未解决的 review。
- 安全敏感改动未说明权限、确认、审计、脱敏、超时、失败和回滚。改认证、授权、租户隔离、CORS、危险操作确认、审计或安全默认值时缺少安全 review。
- 含凭据、真实目标或敏感数据，或混入无关格式化、依赖升级、生成物、本地配置、大规模重排。
- 数据库、部署、发布或配置模板变更未同步文档和回滚说明。

## 验证矩阵

按改动范围做最小充分验证。无法执行时写明原因、环境限制和替代方式。

| 改动范围 | 最小验证 |
|----------|----------|
| 根模块 Go、scanner、shared | `go test ./...` |
| Server | `cd server && go test ./...` |
| MCP | `cd mcp && go test ./...` |
| Yaksha（不在 `go.work`） | `cd yaksha && GOWORK=off go test ./...` |
| 前端 | `npm --prefix server-ui run lint`、`npm --prefix server-ui run test -- --run`、`npm --prefix server-ui run build` |
| 前端 smoke | `npm --prefix server-ui run test:smoke` |
| 数据库 schema、部署库路径 | `make db-verify`。新增 `deploy/db/init/NNN_xxx.sql` 时同步版本常量与契约，见 `deploy/db/README.md` |
| 云资源调度 | `make cloud-smoke`；使用真实云账号时补人工 smoke |
| 发布与部署脚本 | `make release-artifacts`，并按 `docs/release-checklist.md` |
| 跨模块或合并前 | `make ci` |
| 仅文档 | 检查链接、路径、命令、代码块和 README 索引；命令示例有变化时执行对应命令 |

`make ci` 覆盖根模块、Server、MCP、Yaksha 的测试与覆盖率、数据库验证、静态契约，以及前端 lint、test、smoke、build。PR 里的验证记录要和 CI 结果对得上。

## 发布

日常发布从最新 `main` 打 tag 并推送。需要冻结提测时再开 `release/*`。发布前确认 `make ci`、`make release-artifacts`、版本号与 Release Notes、migration、配置模板、部署脚本和回滚方式。高风险变更完成安全 review，已知 beta 边界写入 Release Notes。清单见 `docs/release-checklist.md`。

## 代码代理

交给代理的任务写清目标、相关 Issue 与路径、不能越过的边界、验收标准和验证命令。完成时的汇报格式见 `AGENTS.md`。
