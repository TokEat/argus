# Argus 当前接口实现清单

本文档整理当前代码仓库中已经接入运行链路的对外接口实现，便于联调、测试和后续补全文档。

## 范围说明

- 当前活跃 HTTP 接口来源：`server/internal/api/router.go`、`server/internal/api/handler_dictionary.go`
- 当前活跃 WebSocket 接口来源：`server/internal/api/ws.go`
- 当前活跃 gRPC 接口来源：`server/internal/grpc/server.go`
- gRPC 协议声明来源：`shared/proto/proto/scan/agent.proto`
- 不包含未接线的 scaffold：
  - `server/internal/adapters/httpapi/router.go`
  - `server/internal/adapters/grpcagent/server.go`

## 通用约定

- HTTP 基础前缀：`/api/v1`
- 鉴权方式：JWT Bearer Token
- 例外：`POST /api/v1/auth/login` 不需要 JWT
- `GET /api/v1/ws` 也走同一套中间件，因此握手阶段同样需要 JWT
- 大多数接口返回 JSON
- `GET /api/v1/reports/export/vulns` 返回 CSV 文件流
- gRPC 服务名：`scan.AgentService`

## HTTP REST 接口

### 认证与会话

| 方法 | 路径 | 鉴权 | 当前实现 | 实现位置 |
|------|------|------|----------|----------|
| `POST` | `/api/v1/auth/login` | 否 | 校验 `tenant_id` 和 `password`，优先走数据库用户校验；若用户不存在则兼容固定密码 `8888`，成功后签发 72 小时 JWT | `server/internal/api/router.go` |

### 任务与统计

| 方法 | 路径 | 鉴权 | 当前实现 | 实现位置 |
|------|------|------|----------|----------|
| `GET` | `/api/v1/stats` | 是 | 返回任务、节点、资产、指纹、漏洞五类计数 | `server/internal/api/router.go` |
| `GET` | `/api/v1/tasks` | 是 | 返回最近 50 条 `RootTask`，按创建时间倒序 | `server/internal/api/router.go` |
| `POST` | `/api/v1/tasks` | 是 | 创建任务，支持 `targets` 为字符串或字符串数组，支持 `config` 为 JSON 对象或 JSON 字符串；按 256 个目标切分为 `SubTask`，落库后推入调度队列 | `server/internal/api/router.go` |
| `DELETE` | `/api/v1/tasks/:id` | 是 | 删除 `RootTask` 及其所有 `SubTask` | `server/internal/api/router.go` |
| `POST` | `/api/v1/tasks/:id/cancel` | 是 | 将该任务下 `Pending/Running` 子任务置为 `CancelPending`，等待 agent 轮询取消 | `server/internal/api/router.go` |

### 结果与画像

| 方法 | 路径 | 鉴权 | 当前实现 | 实现位置 |
|------|------|------|----------|----------|
| `GET` | `/api/v1/vulns` | 是 | 返回最近 500 条漏洞记录；支持 `task_id` 过滤 | `server/internal/api/router.go` |
| `GET` | `/api/v1/assets` | 是 | 返回最近 500 条资产记录；支持 `task_id` 过滤 | `server/internal/api/router.go` |
| `GET` | `/api/v1/fingerprints` | 是 | 返回最近 500 条指纹记录；支持 `task_id` 过滤 | `server/internal/api/router.go` |
| `GET` | `/api/v1/profiles` | 是 | 将资产、指纹、漏洞按 `target` 聚合成融合画像返回 | `server/internal/api/router.go` |
| `GET` | `/api/v1/reports/export/vulns` | 是 | 以 CSV 流导出漏洞数据；非 `default` 租户会按租户过滤 | `server/internal/api/router.go` |

### 节点与 Agent 指令

| 方法 | 路径 | 鉴权 | 当前实现 | 实现位置 |
|------|------|------|----------|----------|
| `GET` | `/api/v1/nodes` | 是 | 返回全部节点记录，直接映射 `db.Node` | `server/internal/api/router.go` |
| `GET` | `/api/v1/agents/:id/commands` | 是 | 供 agent 轮询控制指令；返回 `cancel_tasks` 和 `reload_rules`。会把命中的 `CancelPending` 子任务改为 `Cancelled`，并在有 `stream_msg_id` 时执行队列 ACK | `server/internal/api/router.go` |

### Arsenal 与规则清单

| 方法 | 路径 | 鉴权 | 当前实现 | 实现位置 |
|------|------|------|----------|----------|
| `GET` | `/api/v1/arsenals/:type` | 是 | 返回指定类型规则；默认仅返回 `Approved`，`?all=1` 可看全量，`?lite=1` 可省略 `Content` | `server/internal/api/router.go` |
| `POST` | `/api/v1/arsenals/:type/:filename` | 是 | 保存规则正文，计算 MD5，状态固定为 `Draft` | `server/internal/api/router.go` |
| `POST` | `/api/v1/arsenals/:type/:filename/approve` | 是 | 审批通过指定规则，将状态设为 `Approved`，并递增全局热更新计数器 | `server/internal/api/router.go` |
| `POST` | `/api/v1/arsenals/ai/analyze` | 是 | 基于关键词的 mock 审查接口，不接真实 LLM；返回 `Approve/Reject` 建议、原因和置信度 | `server/internal/api/router.go` |
| `DELETE` | `/api/v1/arsenals/:type/:filename` | 是 | 删除指定规则记录 | `server/internal/api/router.go` |
| `GET` | `/api/v1/arsenals/manifest` | 是 | 返回已审批规则的清单、哈希和值班版本号 `rule_version`，供 agent 增量拉取 | `server/internal/api/router.go` |

### Workflow 字典

| 方法 | 路径 | 鉴权 | 当前实现 | 实现位置 |
|------|------|------|----------|----------|
| `GET` | `/api/v1/dictionaries/workflow` | 是 | 从 `workflow_workflow.yaml` 对应的 Arsenal 内容中解析并返回完整工作流列表 | `server/internal/api/handler_dictionary.go` |
| `POST` | `/api/v1/dictionaries/workflow` | 是 | 新增工作流条目，保存回 Arsenal 表中的 YAML 内容，并触发热更新计数器 | `server/internal/api/handler_dictionary.go` |
| `PUT` | `/api/v1/dictionaries/workflow/:product` | 是 | 更新工作流条目，支持重命名产品名，保存回 Arsenal 表 | `server/internal/api/handler_dictionary.go` |
| `DELETE` | `/api/v1/dictionaries/workflow/:product` | 是 | 删除工作流条目并回写 Arsenal 表 | `server/internal/api/handler_dictionary.go` |

### Fingerprint 字典

| 方法 | 路径 | 鉴权 | 当前实现 | 实现位置 |
|------|------|------|----------|----------|
| `GET` | `/api/v1/dictionaries/fingerprint` | 是 | 从 `fingerprint_finger.yaml` 对应的 Arsenal 内容中解析并返回规则列表 | `server/internal/api/handler_dictionary.go` |
| `POST` | `/api/v1/dictionaries/fingerprint` | 是 | 新增指纹条目并回写 Arsenal 表 | `server/internal/api/handler_dictionary.go` |
| `PUT` | `/api/v1/dictionaries/fingerprint/:product` | 是 | 更新指纹条目，支持重命名产品名，保存回 Arsenal 表 | `server/internal/api/handler_dictionary.go` |
| `DELETE` | `/api/v1/dictionaries/fingerprint/:product` | 是 | 删除指纹条目并回写 Arsenal 表 | `server/internal/api/handler_dictionary.go` |

### 用户管理

| 方法 | 路径 | 鉴权 | 当前实现 | 实现位置 |
|------|------|------|----------|----------|
| `GET` | `/api/v1/users` | 是 | 返回用户列表，隐藏密码哈希，仅暴露基础元数据 | `server/internal/api/router.go` |
| `POST` | `/api/v1/users` | 是 | 创建用户，密码使用 bcrypt 哈希；默认角色为 `viewer`，默认租户为 `default` | `server/internal/api/router.go` |
| `PUT` | `/api/v1/users/:id` | 是 | 更新角色、状态和密码；空字段不更新 | `server/internal/api/router.go` |
| `DELETE` | `/api/v1/users/:id` | 是 | 删除用户记录 | `server/internal/api/router.go` |

### 云实例管理

| 方法 | 路径 | 鉴权 | 当前实现 | 实现位置 |
|------|------|------|----------|----------|
| `GET` | `/api/v1/cloud/instances` | 是 | 当前并不查询真实云资源，而是把 `nodes` 表映射成实例列表返回 | `server/internal/api/router.go` |
| `POST` | `/api/v1/cloud/instances` | 是 | 仅校验输入并返回 `accepted`，提示需要配置云厂商凭据；未真正创建实例 | `server/internal/api/router.go` |
| `DELETE` | `/api/v1/cloud/instances/:id` | 是 | 仅把对应节点标记为 `Offline`，未真正调用云厂商删除资源 | `server/internal/api/router.go` |

### 客户端构建

| 方法 | 路径 | 鉴权 | 当前实现 | 实现位置 |
|------|------|------|----------|----------|
| `GET` | `/api/v1/build/artifacts` | 是 | 扫描 `./release` 目录并返回产物列表、大小、平台、架构和修改时间 | `server/internal/api/router.go` |
| `POST` | `/api/v1/build/client` | 是 | 仅校验 `build.sh` 是否存在并返回 `accepted`，提示人工执行或等待 CI；未真正触发构建 | `server/internal/api/router.go` |

### MCP / API Key 管理

| 方法 | 路径 | 鉴权 | 当前实现 | 实现位置 |
|------|------|------|----------|----------|
| `GET` | `/api/v1/mcp/keys` | 是 | 从 `SystemConfig` 中读取 `mcp_%` 配置，并对密钥值做脱敏返回 | `server/internal/api/router.go` |
| `POST` | `/api/v1/mcp/keys` | 是 | 保存 `provider/key` 到 `SystemConfig`，键名格式为 `mcp_<provider>` | `server/internal/api/router.go` |
| `DELETE` | `/api/v1/mcp/keys/:id` | 是 | 删除对应 `SystemConfig.key` 记录 | `server/internal/api/router.go` |

## WebSocket 接口

| 方法 | 路径 | 鉴权 | 当前实现 | 实现位置 |
|------|------|------|----------|----------|
| `GET` | `/api/v1/ws` | 是 | 建立 WebSocket 连接并加入全局 Hub；当前只有服务端广播，没有客户端命令协议 | `server/internal/api/ws.go` |

### 当前广播消息

当前代码里明确接入的广播事件来自 `db.OnResultBatchSaved`：

| 事件类型 | 触发时机 | 当前消息体 |
|----------|----------|------------|
| `scan_result_batch` | 结果批量写入数据库后 | `{"type":"scan_result_batch","count":<批量条数>,"rtype":"<结果类型>"}` |

说明：

- Hub 本身可以广播任意 JSON 对象
- 目前代码中没有订阅、房间、主题或客户端发消息处理逻辑

## gRPC 接口

服务名：`scan.AgentService`

| RPC | 当前状态 | 当前实现 | 实现位置 |
|-----|----------|----------|----------|
| `Register` | 已实现 | 节点注册，写入/更新 `nodes` 表基础信息并返回 `success/token` | `server/internal/grpc/server.go` |
| `Heartbeat` | 已实现 | 更新节点存活时间、运行中任务数；当前固定返回 `should_terminate=false` | `server/internal/grpc/server.go` |
| `FetchTask` | 已实现 | 从调度队列拉取任务；命中任务后把 `SubTask` 改为 `Running`，更新节点运行数，必要时把 `RootTask` 改为 `Running` | `server/internal/grpc/server.go` |
| `StreamResult` | 已实现 | 接收 agent 流式上报结果，并异步写入结果缓冲/数据库 | `server/internal/grpc/server.go` |
| `TaskComplete` | 已实现 | 更新子任务状态，递减节点运行数；在 `DONE` 场景下 ACK 队列消息并更新根任务聚合状态 | `server/internal/grpc/server.go` |
| `EmergencyDump` | 已实现 | 仅记录日志并返回成功响应；当前没有真正的状态转储逻辑 | `server/internal/grpc/server.go` |
| `StreamLogs` | 仅协议声明，未接线 | `proto` 已声明，服务端实现仍注释掉，当前不可用 | `shared/proto/proto/scan/agent.proto`、`server/internal/grpc/server.go` |

### gRPC 当前使用的数据流

- 调度入口：`server/cmd/dddd-server/main.go` 将 `scheduler.TaskQueue` 的 `PopTask/AckTask` 通过 hook 注入 gRPC 服务
- `FetchTask` 负责把队列消息和数据库状态绑定起来
- `TaskComplete` 负责在成功完成时执行 ACK 和根任务完成度聚合
- `StreamResult` 负责把实时扫描输出写入异步结果通道

## 当前未纳入运行链路的接口骨架

下列代码存在，但当前 `main.go` 没有接线，不能视为现网可用接口：

| 位置 | 当前状态 | 说明 |
|------|----------|------|
| `server/internal/adapters/httpapi/router.go` | scaffold | 预留的 `/api/v2` Clean Architecture 路由入口，当前未被启动 |
| `server/internal/adapters/grpcagent/server.go` | scaffold | 所有 gRPC 方法都返回 `Unimplemented`，当前未注册到 gRPC Server |

## 维护建议

- 新增或删除 `router.go` 中的 `/api/v1` 路由时，同步更新本文档
- 若 `StreamLogs` 正式启用，需把其状态从“仅协议声明”改为“已实现”
- 若后续启用 `/api/v2` 或新的 adapter 路径，建议单独新增“版本化接口”章节，避免和当前 `api/v1` 混淆
