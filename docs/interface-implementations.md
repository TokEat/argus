# Argus 当前接口实现清单

本文档仅描述当前主链路中已经接线、能够从 `main.go` 进入运行链路的接口实现。

## 范围说明

- 当前活跃 HTTP 接口来源：
  - `server/internal/api/router.go`
  - `server/internal/api/handler_dictionary.go`
- 当前活跃 WebSocket 接口来源：
  - `server/internal/api/ws.go`
- 当前活跃 gRPC 接口来源：
  - `server/internal/grpc/server.go`
- gRPC 协议声明来源：
  - `shared/proto/proto/scan/agent.proto`
- 不包含未接线 scaffold：
  - `server/internal/adapters/httpapi/router.go`
  - `server/internal/adapters/grpcagent/server.go`

## 通用约定

- HTTP 基础前缀：`/api/v1`
- 鉴权方式：JWT Bearer Token
- 例外：`POST /api/v1/auth/login` 不需要 JWT
- 当前服务端实现中，`GET /api/v1/ws` 同样经过 JWT 中间件
- `GET /api/v1/reports/export/vulns` 返回 CSV 文件流
- gRPC 服务名：`scan.AgentService`

## HTTP REST 接口

### 认证与会话

| 方法 | 路径 | 鉴权 | 当前实现 |
|------|------|------|----------|
| `POST` | `/auth/login` | 否 | 校验 `tenant_id` 和 `password`，优先走数据库用户；若用户不存在则兼容固定密码 `8888`，成功后签发 72 小时 JWT |

### 任务与队列

| 方法 | 路径 | 鉴权 | 当前实现 |
|------|------|------|----------|
| `GET` | `/tasks` | 是 | 返回最近 50 条 `RootTask`，按创建时间倒序 |
| `POST` | `/tasks` | 是 | 创建任务；支持 `targets` 为字符串或字符串数组，`config` 为 JSON 对象或 JSON 字符串；按 256 个目标切分为 `SubTask` 并入队 |
| `DELETE` | `/tasks/:id` | 是 | 删除 `RootTask` 及其全部 `SubTask` |
| `POST` | `/tasks/:id/cancel` | 是 | 将该任务下 `Pending/Running` 子任务改为 `CancelPending` |
| `POST` | `/tasks/:id/append` | 是 | 向已有 `RootTask` 追加目标并继续切分入队 |
| `GET` | `/queue/depth` | 是 | 返回各优先级队列深度、Pending 数量和当前队列模式 |

### 统计、结果与画像

| 方法 | 路径 | 鉴权 | 当前实现 |
|------|------|------|----------|
| `GET` | `/stats` | 是 | 返回任务、节点、资产、指纹、漏洞五类计数 |
| `GET` | `/stats/trends` | 是 | 返回最近 N 天漏洞趋势 |
| `GET` | `/stats/severity` | 是 | 返回漏洞严重度分布 |
| `GET` | `/stats/task-results` | 是 | 返回任务维度的资产 / 指纹 / 漏洞统计 |
| `GET` | `/stats/recent-high-vulns` | 是 | 返回最近高危漏洞 |
| `GET` | `/vulns` | 是 | 返回最近 500 条漏洞；支持 `task_id` 过滤 |
| `GET` | `/assets` | 是 | 返回最近 500 条资产；支持 `task_id` 过滤 |
| `GET` | `/fingerprints` | 是 | 返回最近 500 条指纹；支持 `task_id` 过滤 |
| `GET` | `/profiles` | 是 | 将资产、指纹、漏洞按 `target` 聚合为融合画像 |
| `GET` | `/reports/export/vulns` | 是 | 流式导出漏洞 CSV；非 `default` 租户按租户过滤 |

### 节点与 Agent 指令

| 方法 | 路径 | 鉴权 | 当前实现 |
|------|------|------|----------|
| `GET` | `/nodes` | 是 | 返回节点列表，并附带 `RunningTaskDetails` 聚合信息 |
| `GET` | `/agents/:id/commands` | 是 | 供 Agent 轮询控制指令；返回 `cancel_tasks` 与 `reload_rules`；命中 `CancelPending` 时会更新数据库状态并尝试队列 ACK |
| `GET` | `/agents/:id/logs` | 是 | 返回指定 Agent 的遥测日志，支持 `limit` 和 `level` 过滤 |

### Arsenal 与规则清单

| 方法 | 路径 | 鉴权 | 当前实现 |
|------|------|------|----------|
| `GET` | `/arsenals/:type` | 是 | 返回指定类型规则；默认仅返回 `Approved`；`?all=1` 查看全量；`?lite=1` 省略正文 |
| `POST` | `/arsenals/:type/:filename` | 是 | 保存规则正文，计算哈希，状态固定为 `Draft` |
| `POST` | `/arsenals/:type/:filename/approve` | 是 | 审批通过规则并递增 `rule_version` |
| `POST` | `/arsenals/:type/:filename/rollback` | 是 | 交换当前版本与 `previous_hash`，回滚后重新置为 `Draft` 并递增 `rule_version` |
| `DELETE` | `/arsenals/:type/:filename` | 是 | 删除规则记录 |
| `POST` | `/ai/arsenal/analyze` | 是 | Server 侧 POC AI 审查：静态检查 + OpenAI-compatible LLM + 按内容 hash 缓存 |
| `POST` | `/arsenals/ai/analyze` | 是 | 兼容旧前端的 POC AI 审查入口，内部转到真实分析逻辑 |
| `GET` | `/arsenals/manifest` | 是 | 返回已审批规则清单、哈希和值班版本号 `rule_version` |

### Workflow / Fingerprint 字典

| 方法 | 路径 | 鉴权 | 当前实现 |
|------|------|------|----------|
| `GET` | `/dictionaries/workflow` | 是 | 从 Arsenal 中解析并返回完整 workflow 列表 |
| `POST` | `/dictionaries/workflow` | 是 | 新增 workflow 条目并回写 Arsenal |
| `PUT` | `/dictionaries/workflow/:product` | 是 | 更新 workflow 条目，支持产品名重命名 |
| `DELETE` | `/dictionaries/workflow/:product` | 是 | 删除 workflow 条目并回写 Arsenal |
| `GET` | `/dictionaries/fingerprint` | 是 | 从 Arsenal 中解析并返回指纹规则列表 |
| `POST` | `/dictionaries/fingerprint` | 是 | 新增指纹条目并回写 Arsenal |
| `PUT` | `/dictionaries/fingerprint/:product` | 是 | 更新指纹条目，支持产品名重命名 |
| `DELETE` | `/dictionaries/fingerprint/:product` | 是 | 删除指纹条目并回写 Arsenal |

### 用户与系统配置

| 方法 | 路径 | 鉴权 | 当前实现 |
|------|------|------|----------|
| `GET` | `/users` | 是 | 返回用户列表，隐藏密码哈希 |
| `POST` | `/users` | 是 | 创建用户，密码使用 bcrypt 哈希 |
| `PUT` | `/users/:id` | 是 | 更新角色、状态与密码 |
| `DELETE` | `/users/:id` | 是 | 删除用户 |
| `GET` | `/mcp/keys` | 是 | 从 `SystemConfig` 读取 `mcp_%` 配置并脱敏返回 |
| `POST` | `/mcp/keys` | 是 | 保存 `provider/key` 到 `SystemConfig` |
| `DELETE` | `/mcp/keys/:id` | 是 | 删除对应 `SystemConfig.key` |
| `GET` | `/ai/config` | 是 | 读取 Server 侧 AI 配置，API Key 脱敏返回，不下发 Agent |
| `PUT` | `/ai/config` | 是 | 保存 Server 侧 AI 配置：`ai_base_url` / `ai_api_key` / `ai_model` |

### 云实例与构建

| 方法 | 路径 | 鉴权 | 当前实现 |
|------|------|------|----------|
| `GET` | `/cloud/instances` | 是 | 当前不查询真实云资源，而是将 `nodes` 表映射为实例列表 |
| `POST` | `/cloud/instances` | 是 | 仅校验输入并返回 `accepted`，未真正创建实例 |
| `DELETE` | `/cloud/instances/:id` | 是 | 仅将对应节点标记为 `Offline` |
| `GET` | `/build/artifacts` | 是 | 扫描 `./release` 目录并返回产物列表 |
| `POST` | `/build/client` | 是 | 仅校验 `build.sh` 是否存在并返回 `accepted`，未真正触发构建 |

## WebSocket 接口

| 方法 | 路径 | 鉴权 | 当前实现 |
|------|------|------|----------|
| `GET` | `/ws` | 是 | 建立 WebSocket 连接并加入全局 Hub；当前只有服务端广播，没有客户端命令协议 |

### 当前广播事件

| 事件类型 | 触发时机 | 当前消息体 |
|----------|----------|------------|
| `scan_result_batch` | 结果批量写入数据库后 | `{"type":"scan_result_batch","count":<批量条数>,"rtype":"<结果类型>"}` |

### WebSocket 备注

- 当前服务端握手路径仍在统一 JWT 中间件之后
- 当前实现没有从 query string 中消费 token
- Hub 支持广播任意 JSON，但当前代码中只有结果批量写入事件接入了广播链路

## gRPC 接口

服务名：`scan.AgentService`

| RPC | 当前状态 | 当前实现 |
|-----|----------|----------|
| `Register` | 已实现 | 节点注册，写入/更新 `nodes` 表基础信息，当前返回 `success + dummy token` |
| `Heartbeat` | 已实现 | 更新节点存活时间、运行任务数、运行任务列表与规则版本；按 `rule_version` 判断是否需要同步规则 |
| `FetchTask` | 已实现 | 从队列拉取任务；支持容量检查与标签匹配；命中任务后改写 `SubTask` 为 `Running` |
| `StreamResult` | 已实现 | 接收 Agent 流式结果并异步写入结果缓冲池 |
| `TaskComplete` | 已实现 | 更新子任务状态、递减节点运行数，并在 `DONE` 时尝试聚合根任务状态与 ACK 队列 |
| `EmergencyDump` | 已实现 | 当前仅记录日志并返回成功响应 |
| `StreamLogs` | 已实现 | 接收 Agent 日志流并写入 `agent_logs` 表 |

## 当前未纳入运行链路的接口骨架

下列代码存在，但 `main.go` 没有接线，不应视为当前可用接口：

| 位置 | 当前状态 | 说明 |
|------|----------|------|
| `server/internal/adapters/httpapi/router.go` | scaffold | 预留 `/api/v2` 路由入口，当前未启动 |
| `server/internal/adapters/grpcagent/server.go` | scaffold | 所有 gRPC 方法都返回 `Unimplemented`，当前未注册 |

## 维护建议

- 以后新增或删除 `/api/v1` 路由时，同步更新本文档
- 以后若启用 `/api/v2`，单独增加“版本化接口”章节，不要和当前主链路混写
- 对“已存在但只返回 accepted / mock”的接口，文档里应明确标注是否真正执行了后端动作
