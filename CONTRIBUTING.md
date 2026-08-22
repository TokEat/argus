# 贡献与协作指南

本文定义 Argus 的开发协作、验证、评审和发布规则。它面向人类贡献者，也作为 AI/Codex 协作时的项目规范入口。

Argus 是面向合法授权安全测试、分布式扫描、规则治理、云资源调度和 AI Copilot 辅助运营的平台。所有贡献都必须保持授权边界、租户隔离、RBAC、审计记录和安全默认值。

## 核心原则

- `main` 始终保持可构建、可发布。
- 非平凡改动必须先有 Issue，并在 PR 中用 `Fixes #<issue>`、`Closes #<issue>` 或 `Resolves #<issue>` 关联。
- 所有功能开发、缺陷修复、重构、配置、部署和发布改动都通过短生命周期分支完成。
- PR 必须说明改动目的、影响范围、验证结果、安全风险和回滚方式。
- 涉及认证、授权、租户隔离、审计、危险操作确认、AI/POC/EXP、云资源、数据库或部署的改动必须按安全敏感改动处理。
- 不提交真实凭据、Token、Cookie、API Key、连接串、真实目标、客户数据、未脱敏日志、本地配置或生成缓存。

## Issue 与闭环规则

以下非平凡改动必须先有 Issue：

- 功能、缺陷、性能、重构和用户可见行为变化。
- API、WebSocket、gRPC、数据库 migration、部署、发布和配置模板变化。
- 认证、RBAC、租户隔离、对象级授权、审计、安全默认值变化。
- POC、EXP、Workflow、规则库、AI Copilot、云资源调度、OSS 分发、Agent 执行链路相关改动。

极小文档错别字、注释修正或无行为影响的格式维护可以不建 Issue，但 PR 必须说明原因。

Issue 至少包含：

- 背景或问题描述。
- 目标和非目标。
- 影响范围和相关路径。
- 验收标准。
- 风险点。
- 预期验证方式。
- 是否涉及安全敏感能力、真实目标交互或敏感数据。

闭环定义：

- PR 已关联 Issue，或明确说明豁免原因。
- Issue 验收标准已逐项验证。
- 必要测试、构建、手动验证和安全检查已执行并记录结果。
- CI 通过，review 通过，无 unresolved review comments。
- PR 合并后 Issue 自动关闭或由维护者手动关闭。
- 涉及发布或生产风险时，补充发布、回滚或上线验证记录。

## 分支模型

项目使用 `main + 短生命周期任务分支 + 按需 release/hotfix`。

### 长期分支

| 分支 | 用途 | 说明 |
|------|------|------|
| `main` | 稳定主线 | 默认分支，禁止直接提交，任何变更都通过 PR 合并 |
| `release/*` | 版本冻结分支 | 仅在提测、预发布、版本冻结时创建，不作为日常开发主线 |

默认不引入 `develop`。只有在后续出现长周期并行版本开发和严格预发冻结需求时，才重新评估是否增加长期分支。

### 短生命周期分支

| 类型 | 示例 | 用途 |
|------|------|------|
| `feat/*` | `feat/123-node-heartbeat-timeout` | 新功能 |
| `fix/*` | `fix/456-grpc-stream-reconnect` | 缺陷修复 |
| `refactor/*` | `refactor/789-scheduler-queue-model` | 不改变外部行为的重构 |
| `chore/*` | `chore/321-upgrade-gorm` | 构建、依赖、脚本、工程维护 |
| `docs/*` | `docs/654-update-deploy-guide` | 文档更新 |
| `test/*` | `test/987-task-lifecycle-coverage` | 测试补充或测试设施调整 |
| `hotfix/*` | `hotfix/login-token-expiry` | 线上紧急修复 |

命名要求：

- 使用英文小写，单词之间使用 `-`。
- 一条分支只处理一个需求、缺陷或维护目标。
- 除极小维护改动外，分支名建议包含 Issue 编号。
- 避免 `feat/test`、`fix/bug` 这类无信息名称。

## 推荐工作流

### 1. 从最新 `main` 创建任务分支

```bash
git switch main
git pull origin main
git switch -c feat/123-your-change
```

### 2. 在任务分支内完成开发和自测

提交前至少完成：

- `git status --short` 确认只有预期改动。
- `git diff` 确认没有无关格式化、缓存、构建产物、本地配置或敏感信息。
- 根据“验证矩阵”执行相关命令。
- 必要接口、页面、部署或发布路径完成手动验证。

### 3. 推送分支并创建 PR

```bash
git push -u origin feat/123-your-change
```

PR 标题建议使用 Conventional Commits 风格：

- `feat: 支持节点超时自动剔除`
- `fix: 修复任务队列重复确认问题`
- `docs: 完善开发协作闭环规范`

### 4. 通过评审后合并回 `main`

合并要求：

- 优先使用 `Squash and merge`。
- 保持 `main` 历史干净，避免大量零碎提交进入主线。
- 分支合并后及时删除远端和本地任务分支。

## 提交规范

提交信息使用：

```text
type(scope): summary
```

常用类型：

| 类型 | 说明 |
|------|------|
| `feat` | 新功能 |
| `fix` | 缺陷修复 |
| `refactor` | 重构 |
| `perf` | 性能优化 |
| `test` | 测试 |
| `docs` | 文档 |
| `chore` | 工程维护、依赖、脚本 |
| `ci` | CI 或自动化流程 |
| `style` | 不影响行为的格式调整 |

一个提交应保持语义完整。不要把功能、重构、格式化和依赖升级混在同一个提交里。

## 验证矩阵

贡献者必须根据改动范围选择最小充分验证命令，并在 PR 中粘贴实际执行结果。无法执行时，必须说明原因、环境限制和替代验证方式。

| 改动范围 | 最小验证 |
|----------|----------|
| 根模块 Go 代码、scanner、shared | `go test ./...` |
| Server 后端 | `cd server && go test ./...` |
| MCP 代理 | `cd mcp && go test ./...` |
| 前端代码 | `npm --prefix server-ui run lint`、`npm --prefix server-ui run test -- --run`、`npm --prefix server-ui run build` |
| 前端 smoke | `npm --prefix server-ui run test:smoke` |
| 数据库 schema、部署数据库路径 | `make db-verify`（SQL 初始化 + 启动期校验测试）。schema 变更流程（新增 `deploy/db/init/NNN_xxx.sql` 并同步版本常量与契约）见 `deploy/db/README.md` |
| 云资源调度 | `make cloud-smoke`，涉及真实云账号时补充人工 smoke 记录 |
| 发布脚本、发行包、部署脚本 | `make release-artifacts`，并按 `docs/release-checklist.md` 验收 |
| 跨模块或合并前完整验证 | `make ci` |
| 文档-only | 手动检查链接、路径、命令、代码块和 README 索引；命令示例变化时执行对应命令 |

CI 当前并行执行根模块、Server、MCP、Yaksha 的 Go 测试与覆盖率、数据库验证、静态契约和前端 lint/test/smoke/build；每个 Go 模块只执行一次带覆盖率的完整测试，避免重复运行同一测试集。PR 中的验证记录应与 CI 结果互相印证，而不是只写“已验证”。

## 安全与合规要求

禁止：

- 放宽认证、RBAC、租户隔离、对象级授权、CORS、危险操作确认、审计或安全默认值。
- 提交真实凭据、Token、Cookie、API Key、连接串、真实目标、客户数据、敏感日志、本地配置或未脱敏截图。
- 在未声明权限、确认语义、审计字段、超时和失败行为的情况下新增高风险动作。
- 将生产密钥、默认管理员凭据或真实云账号信息写入文档、测试或示例。
- 为了方便联调绕过授权、审计、租户过滤或对象归属检查。

涉及 `tenant_id`、`project_id`、`task_id`、`agent_id`、`user_id`、`role_id`、规则 ID、云账号 ID、构建任务 ID、日志文件或导出文件等对象标识的接口，必须验证当前用户是否拥有或被授权访问该对象。不能只校验登录态。

AI Copilot、POC、EXP、Workflow、Dir 字典、云资源、OSS 分发和 Agent 执行链路默认采用草稿优先、人工确认、审计留痕和最小权限原则。

## PR 合并阻断条件

以下 PR 不得合并：

- 未关联 Issue，且不属于极小文档、注释或维护改动。
- 未填写验证命令和结果。
- CI 未通过，且没有维护者明确豁免说明。
- 存在 unresolved review comments。
- 涉及安全敏感路径但未说明权限、确认、审计、脱敏、超时、失败和回滚。
- 修改认证、授权、租户隔离、CORS、危险操作确认、审计或安全默认值但没有安全 review。
- 包含真实凭据、真实目标、Token、Cookie、连接串、客户数据或未脱敏日志。
- 混入无关格式化、依赖升级、生成物、本地配置或大规模重排。
- 数据库、部署、发布或配置模板变更未同步文档和回滚说明。

## `main` 分支保护要求

`main` 必须在代码托管平台启用分支保护：

- 禁止直接 push 到 `main`。
- 必须通过 PR 合并。
- 至少 1 位 reviewer 批准。
- Required status checks 必须通过。
- 合并前分支必须与最新 `main` 同步。
- 必须解决所有 review conversation。
- 禁止 force push。
- 禁止删除 `main`。
- 优先保留 `Squash and merge`，避免 merge commit 直灌主线。

说明：仓库文件只能记录规则，分支保护需要在 GitHub 仓库设置中手动开启。

## 发布流程

### 日常发布

开发和测试节奏紧密、`main` 已受 PR 和 CI 保护、不需要单独维护待发布版本时，直接从 `main` 打 tag：

```bash
git switch main
git pull origin main
git tag v1.0.0
git push origin v1.0.0
```

### 冻结发布

当某个版本需要集中提测、修缺陷、控制变更范围时，再创建 `release/*`：

```bash
git switch main
git pull origin main
git switch -c release/v1.0.0
git push -u origin release/v1.0.0
```

规则：

- `release/*` 只接收发布相关修复，不继续堆新功能。
- 发布完成后，将必要修复同步回 `main`。
- 版本最终以 tag 作为发布标识。
- 发布前按 `docs/release-checklist.md` 验收。

发布前必须确认：

- `make ci` 通过。
- `make release-artifacts` 可生成发行包。
- 版本号、tag、Release Notes 和文档一致。
- 数据库 migration 已验证。
- 配置模板、部署脚本和回滚方式已同步。
- 高风险变更已完成安全 review。
- 已知 beta 边界已写入 Release Notes。

## Hotfix 流程

线上紧急问题使用 `hotfix/*`：

```bash
git switch main
git pull origin main
git switch -c hotfix/your-fix
```

处理完成后：

- 先通过 PR 合并回 `main`。
- 如果当前存在未结束的 `release/*` 分支，需要把同样修复同步到对应 `release/*`。
- PR 必须说明影响范围、验证结果、回滚方式和是否需要补发版本。

## AI/Codex 协作

Codex 或其他代码代理必须同时遵守本文和 `AGENTS.md`。

交给 AI/Codex 的任务建议包含：

- 目标：要解决的问题。
- 上下文：相关 Issue、模块、接口、文档和路径。
- 约束：不得触碰的安全边界、兼容要求和非目标。
- 完成条件：验收标准、验证命令、最终汇报格式。

AI/Codex 完成任务时必须汇报：

- Summary。
- Files changed。
- Validation performed。
- Security notes。
- Risks / rollback notes。
- Checks not run and why。

## 适用于当前项目的最小分支集合

当前仓库至少使用：

- `main`
- `feat/*`
- `fix/*`
- `refactor/*`
- `chore/*`
- `docs/*`
- `test/*`
- `hotfix/*`

按需启用：

- `release/*`

这套模型足够支持多人和 AI 协作，同时避免把分支体系搞得过重。
