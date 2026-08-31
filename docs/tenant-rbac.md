# 租户隔离与角色权限划分

本文档描述当前项目的多租户边界和同一租户内的角色权限。当前系统没有跨租户超级管理员角色；`admin` 只管理自己登录令牌中的 `tenant_id`。

## 租户隔离原则

- 身份来源：登录成功后 JWT 写入 `tenant_id`、`role`、`user_id`。MCP HTTP 通过 Server OAuth 签发带同样 claims 且 `aud` 为 MCP resource 的 access token。
- 请求上下文：`TenantMiddleware` 校验 JWT，并把 `tenant_id` 和 `role` 注入 Gin Context。
- 数据边界：业务查询、更新、删除都必须带 `tenant_id = 当前租户` 条件；默认租户为 `default`。
- 用户管理：管理员只能创建、修改、删除当前租户用户，不能通过请求体创建其他租户用户。
- Agent 内部接口：Agent 同步命令和规则清单使用 `x-agent-id` + `x-agent-token` session 鉴权，按注册节点绑定真实租户；PSK 仅用于 gRPC/bootstrap 引导。
- 默认兜底：RBAC 权限表未声明的新接口默认要求 `admin`，避免新增接口误开放。

## 角色层级

内置角色采用三档层级；租户可在此基础上创建自定义角色，并通过 `permissions` 列表限制可访问接口：

| 角色 | 层级 | 定位 |
| --- | --- | --- |
| `admin` | 3 | 当前租户管理员，负责用户、系统配置、项目分发、AK/SK 跨用户绑定和规则发布 |
| `operator` | 2 | 日常操作员，负责自己创建或被分发项目内的扫描任务、节点运维、规则草稿维护和已授权云资源使用 |
| `viewer` | 1 | 观察者，只读查看被授权项目数据和导出报表 |

高层级自动包含低层级能力。例如 `admin` 包含 `operator` 和 `viewer` 的全部权限。

## 功能权限矩阵

| 功能域 | viewer | operator | admin |
| --- | --- | --- | --- |
| 租户隔离 | 仅本租户 | 仅本租户 | 仅本租户 |
| 仪表盘、项目、任务、任务结果 | 查看被授权项目 | 查看/操作自己创建或被分发项目 | 全租户项目 |
| 项目创建 | - | 允许，默认归属自己 | 允许，可创建后分发给 operator |
| Server 测绘查询预览 | - | 仅被授权项目，凭据不返回 | 当前租户全部项目，凭据不返回 |
| 项目归档、删除 | - | 仅自己创建的项目 | 全租户项目 |
| 项目分发 | - | 项目 owner 可维护成员 | 可绑定当前租户 active 用户到指定项目 |
| 任务下发、追加、取消、删除 | - | 仅可访问项目内允许 | 全租户项目内允许 |
| 节点状态 | 查看 | 查看 + 删除节点记录 + 清理离线节点 | 全部 |
| 队列深度、Agent 日志 | - | 查看 | 查看 |
| 弹药库规则 | - | 仅可通过 MCP 规则工具保存草稿 | 管理、审批、回滚与 AI 审查入口 |
| 字典配置 | - | - | 查看、创建、编辑、删除 |
| 漏洞报表 | 导出 | 导出 | 导出 |
| AI 问答、调试、全局问答 | - | 允许 | 允许 |
| AI 规则分析（`/ai/arsenal/*`、`/arsenals/ai/analyze`） | - | - | 允许 |
| 用户列表 | - | 查看 active 用户用于项目成员选择 | 允许管理用户 |
| 角色管理 | - | - | 允许创建自定义角色和权限矩阵 |
| MCP Key、API Key、AI 配置 | - | - | 允许 |
| 云账号、伸缩策略、云实例、OSS 分发 | - | 使用自己创建或被绑定的 AK/SK | 全租户 AK/SK 管理 + 用户绑定 |
| 客户端构建 | - | - | 允许 |

## 当前后端接口分组

以下分组为代表性示例，不是全部接口的穷举清单；未在 RBAC 权限表中声明的新接口默认要求 `admin`。EXP Workspace（另受用户级 `exp_authorized` 门禁）、凭据字典与弱口令发现、Agent 日志告警/归档、MCP 资源与规则工具、租户配额、资产/指纹报表导出、POC 元数据检索等接口族按同层级原则分配。

### viewer 起可访问

- `GET /projects`
- `GET /tasks`、`GET /tasks/:id`、`GET /tasks/:id/config-revisions`、`GET /tasks/:id/batches`
- `POST /tasks/:id/risk-validation/preview`：虽然使用 POST 承载分页预览请求，但语义严格只读；仅返回当前租户且当前用户有项目访问权的任务数据，不创建批次、不入队、不执行 POC
- `POST /tasks/:id/risk-validation`：至少需要 operator；重新校验当前租户、项目归属、任务终态、预览计划、规则/配置版本和 POC 内容哈希，要求授权确认，高风险或未分类规则要求二次确认，并写入批次级审计。可选 `Idempotency-Key` 只在认证、RBAC、项目/任务对象授权和归档检查后重放同一已提交确认；原始 Key 不落库，同 Key 改变 plan、候选或确认字段返回 409，Key 不能替代授权或风险确认
- `GET /nodes`
- `GET /vulns`、`GET /assets`、`GET /fingerprints`、`GET /profiles`
- `GET /stats`、`GET /stats/trends`、`GET /stats/severity`、`GET /stats/task-results`、`GET /stats/recent-high-vulns`
- `GET /reports/export/vulns`（另有 assets/fingerprints 导出）
- `GET /ws`

### operator 起可访问

- `POST /projects`
- `POST /projects/:id/asset-discovery/fofa/query`、`POST /projects/:id/asset-discovery/hunter/query`、`POST /projects/:id/asset-discovery/quake/query`：只允许查询当前用户可访问的项目，凭据仅由 Server 从当前租户已批准配置读取；结果返回前必须写入不含原始表达式、凭据或 Provider 响应的审计
- `PUT /projects/:id`、`DELETE /projects/:id`：operator 仅限自己创建的项目
- `POST /tasks`、`POST /tasks/:id/append`、`POST /tasks/:id/pause|resume|stop|cancel|retry`、`POST /tasks/:id/batches/:batch_id/pause|resume|stop|retry`、`DELETE /tasks/:id/batches/:batch_id`、`PUT /tasks/:id/config`、`DELETE /tasks/:id`
  - 所有接口继续校验租户与项目归属；任务与批次的暂停、恢复、停止、重试和归档均记录操作者与前后状态。
  - 任务创建、追加、任务级/批次级重试和风险验证执行的可选 `Idempotency-Key` 都不是授权凭证：认证、operator RBAC 与对象/归档校验先于重放，唯一作用域含 tenant/project(/task[/batch])/operator/operation/Key hash；同一规范请求重放首次结果且不重复派发，异请求返回 409。
  - `DELETE /tasks/:id` 只归档已进入终态的任务，不删除批次和扫描结果；活动任务必须先停止。
  - `PUT /tasks/:id/config` 只为当前租户和已授权项目中的未归档任务创建新配置版本；旧批次快照不被覆盖，变更只影响后续批次并写审计。
- `GET /queue/depth`
- `GET /agents/:id/logs`
- `GET /users`：用于项目成员选择
- `GET /projects/:id/members`、`PUT /projects/:id/members`：仍需项目 owner 或 admin 通过业务校验
- `DELETE /nodes/:id`、`POST /nodes/clean`
- `POST /ai/chat`、`POST /ai/actions/confirm` 等 Copilot 问答与草稿确认接口
- 规则草稿保存类 MCP 工具（如 `POST /mcp/tools/rule/save`）；规则应用（apply）仍需 admin
- MCP HTTP（`POST /mcp`）使用 OAuth 签发的 access token；工具内 RBAC 仍按 token 中的 `role` 执行。本租户关闭 MCP 或拉黑该 `client_id` 后，即使 access JWT 未过期也会被拒绝。
- `GET /cloud/*`、`POST /cloud/*`、`PUT /cloud/*`、`DELETE /cloud/*`：仅限自己创建或被绑定的云账号；云账号用户绑定在业务层额外要求 admin

### 公开（无 JWT）

- `POST /auth/login`
- MCP OAuth：`GET /.well-known/oauth-protected-resource`、`GET /.well-known/oauth-authorization-server`、`GET /.well-known/openid-configuration`、`GET|POST /oauth/authorize`、`POST /oauth/token`、`POST /oauth/register`。登录使用现有用户表；access token 的 `aud` 为 MCP resource，租户与角色仍写入 JWT。公开客户端通过 DCR 注册；回环回调遵循 RFC 8252，不绑定单一 IDE。

### admin only

- 弹药库与字典读写及治理：`GET|POST|DELETE /arsenals/*`（含 approve/rollback/deprecate/seed-db）、`GET|POST|PUT|DELETE /dictionaries/*`、`POST /arsenals/ai/analyze`、`POST /ai/arsenal/analyze(/stream)`
- `POST /users`、`PUT /users/:id`、`DELETE /users/:id`
- `GET /roles`、`POST /roles`、`PUT /roles/:name`、`DELETE /roles/:name`
- `GET /mcp/keys`、`POST /mcp/keys`、`DELETE /mcp/keys/:id`
- MCP 管理：`GET|PUT /mcp/admin/status`、`GET /mcp/admin/clients`、`POST /mcp/admin/clients/:id/{revoke,disable,enable}`、`DELETE /mcp/admin/clients/:id`、`GET /mcp/admin/sessions`、`POST /mcp/admin/sessions/revoke`、`GET /mcp/admin/invocations`。仅当前租户；关闭开关会撤销该租户全部 MCP 刷新令牌。`/mcp` 与 `/oauth/authorize`、`/oauth/token` 在本租户关闭或客户端被拉黑时拒绝。调用审计只含高风险 tools/call，参数已脱敏。
- `GET /config/api-keys`、`PUT /config/api-keys`
- `GET /ai/config`、`PUT /ai/config`、`GET /ai/models`、`POST /ai/test`
- `GET /build/artifacts`、`POST /build/client`、`POST /build/jobs/:id/cancel`、`POST /build/jobs/:id/retry`
- `POST /nodes/:id/revoke-token`
- `GET /cloud/accounts/:id/bindings`、`PUT /cloud/accounts/:id/bindings`

## 项目成员角色

项目成员支持 `viewer`、`operator`、`owner` 三档。旧版 `{ "user_ids": [...] }` 请求仍兼容为 `operator` 成员；新版推荐使用 `{ "members": [{ "user_id": "1", "role": "viewer" }] }`。

## 当前边界

- 自定义角色是租户级授权，不替代项目成员的项目级访问控制。
- 项目成员的 `owner` 可维护项目成员；`viewer/operator` 只能访问或操作自己被授权的项目范围。
- 未在 RBAC 权限表中声明的新接口默认要求 `admin`。
