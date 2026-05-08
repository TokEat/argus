# 租户隔离与角色权限划分

本文档描述当前项目的多租户边界和同一租户内的角色权限。当前系统没有跨租户超级管理员角色；`admin` 只管理自己登录令牌中的 `tenant_id`。

## 租户隔离原则

- 身份来源：登录成功后 JWT 写入 `tenant_id`、`role`、`user_id`。
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
| 项目归档、删除 | - | 仅自己创建的项目 | 全租户项目 |
| 项目分发 | - | 项目 owner 可维护成员 | 可绑定当前租户 active 用户到指定项目 |
| 任务下发、追加、取消、删除 | - | 仅可访问项目内允许 | 全租户项目内允许 |
| 节点状态 | 查看 | 查看 + 删除节点记录 + 清理离线节点 | 全部 |
| 队列深度、Agent 日志 | - | 查看 | 查看 |
| 弹药库规则 | 查看 | 创建、编辑、删除草稿规则 | 维护 + 审批 + 回滚 |
| 字典配置 | 查看 | 创建、编辑、删除 | 创建、编辑、删除 |
| 漏洞报表 | 导出 | 导出 | 导出 |
| AI 分析、调试、全局问答 | - | 允许 | 允许 |
| 用户列表 | - | 查看 active 用户用于项目成员选择 | 允许管理用户 |
| 角色管理 | - | - | 允许创建自定义角色和权限矩阵 |
| MCP Key、API Key、AI 配置 | - | - | 允许 |
| 云账号、伸缩策略、云实例、OSS 分发 | - | 使用自己创建或被绑定的 AK/SK | 全租户 AK/SK 管理 + 用户绑定 |
| 客户端构建 | - | - | 允许 |

## 当前后端接口分组

### viewer 起可访问

- `GET /projects`
- `GET /tasks`、`GET /tasks/:id`
- `GET /nodes`
- `GET /vulns`、`GET /assets`、`GET /fingerprints`、`GET /profiles`
- `GET /stats`、`GET /stats/trends`、`GET /stats/severity`、`GET /stats/task-results`、`GET /stats/recent-high-vulns`
- `GET /reports/export/vulns`
- `GET /arsenals/*`
- `GET /dictionaries/*`
- `GET /ws`

### operator 起可访问

- `POST /projects`
- `PUT /projects/:id`、`DELETE /projects/:id`：operator 仅限自己创建的项目
- `POST /tasks`、`POST /tasks/:id/append`、`POST /tasks/:id/cancel`、`DELETE /tasks/:id`
- `GET /queue/depth`
- `GET /agents/:id/logs`
- `GET /users`：用于项目成员选择
- `GET /projects/:id/members`、`PUT /projects/:id/members`：仍需项目 owner 或 admin 通过业务校验
- `DELETE /nodes/:id`、`POST /nodes/clean`
- `POST /arsenals/*`、`DELETE /arsenals/*`
- `POST /dictionaries/*`、`PUT /dictionaries/*`、`DELETE /dictionaries/*`
- `POST /arsenals/ai/analyze`
- `POST /ai/arsenal/analyze`、`POST /ai/arsenal/analyze/stream`、`POST /ai/chat`
- `GET /cloud/*`、`POST /cloud/*`、`PUT /cloud/*`、`DELETE /cloud/*`：仅限自己创建或被绑定的云账号；绑定管理仍要求 admin

### admin only

- `POST /users`、`PUT /users/:id`、`DELETE /users/:id`
- `GET /roles`、`POST /roles`、`PUT /roles/:name`、`DELETE /roles/:name`
- `GET /mcp/keys`、`POST /mcp/keys`、`DELETE /mcp/keys/:id`
- `GET /config/api-keys`、`PUT /config/api-keys`
- `GET /ai/config`、`PUT /ai/config`、`GET /ai/models`、`POST /ai/test`
- `GET /build/artifacts`、`POST /build/client`、`POST /build/jobs/:id/cancel`、`POST /build/jobs/:id/retry`
- `POST /nodes/:id/revoke-token`
- `POST /arsenals/:type/:filename/approve`
- `POST /arsenals/:type/:filename/rollback`
- `GET /cloud/accounts/:id/bindings`、`PUT /cloud/accounts/:id/bindings`

## 项目成员角色

项目成员支持 `viewer`、`operator`、`owner` 三档。旧版 `{ "user_ids": [...] }` 请求仍兼容为 `operator` 成员；新版推荐使用 `{ "members": [{ "user_id": "1", "role": "viewer" }] }`。

## 当前边界

- 自定义角色是租户级授权，不替代项目成员的项目级访问控制。
- 项目成员的 `owner` 可维护项目成员；`viewer/operator` 只能访问或操作自己被授权的项目范围。
- 未在 RBAC 权限表中声明的新接口默认要求 `admin`。
