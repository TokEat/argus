# Argus 项目实现状态总览

> 本文档基于当前仓库代码实际状态整理。
>
> 标注说明：`✅` = 已实现并接入主链路 | `⚠️` = 代码已存在但链路未闭环 / 仅部分可用 | `❌` = 尚未实现
>
> 当前接口清单已经合并到本文末尾，避免实现状态与接口状态分散维护。

---

## 一、总体完成度

| 阶段 | 状态 | 完成度 |
|------|------|--------|
| Phase 1：数据异构化与结果防洪 | ✅ 已完成 | ~95% |
| Phase 2：分布式调度与基础控制面 | ⚠️ 核心能力已具备，但链路未完全闭环 | ~75% |
| Phase 3：运营管控、系统化与 AI 化 | ⚠️ 部分完成 | ~55% |

---

## 二、已实现功能清单 (✅)

### 控制面 (Server)

| 模块 | 功能 | 文件 |
|------|------|------|
| API Gateway | Gin REST API 主路由 | `server/internal/api/router.go` |
| 身份与权限 | JWT 登录校验 + RBAC 中间件 | `server/internal/api/router.go` `server/internal/api/middleware_rbac.go` |
| 任务管理 | RootTask / SubTask 创建、拆分、查询、删除、取消、追加目标 | `server/internal/api/router.go` |
| 调度队列 | RabbitMQ 多优先级队列 + 内存 fallback | `server/internal/scheduler/queue.go` |
| 队列恢复 | Dead-Letter 回收、旧队列迁移、死亡节点任务抢救 | `server/internal/scheduler/queue.go` `server/cmd/dddd-server/main.go` |
| 超时与重试 | 基于 `timeout_sec` 的超时扫描与自动重试守护协程 | `server/internal/api/router.go` |
| gRPC 通信 | `Register` / `Heartbeat` / `FetchTask` / `StreamResult` / `TaskComplete` / `EmergencyDump` / `StreamLogs` | `server/internal/grpc/server.go` |
| 数据模型 | PostgreSQL migration runner + schema verify | `server/internal/db` |
| 结果入库 | Asset / FingerprintHit / Vulnerability 三层结构化存储 | `server/internal/db/db.go` |
| 防洪落库 | BatchWriter 异步缓冲写入 | `server/internal/db/db.go` |
| Arsenal 管理 | POC / Finger / Workflow / Dir 的 CRUD、审批、Manifest、回滚 | `server/internal/api/router.go` |
| Dictionary API | Workflow / Fingerprint 结构化 CRUD | `server/internal/api/handler_dictionary.go` |
| 规则初始化 | 启动时从磁盘导入规则与结构化目录 | `server/internal/db/seed.go` |
| 结果查询 | 漏洞、资产、指纹、融合画像接口 | `server/internal/api/router.go` |
| 统计接口 | 首页五维统计 + 趋势 / 严重度 / 任务结果统计 / 最近高危漏洞 | `server/internal/api/router.go` `server/internal/db/stats.go` |
| WebSocket Hub | 结果批量写入后的服务端广播 | `server/internal/api/ws.go` |
| 报表导出 | 漏洞 CSV 导出 | `server/internal/api/router.go` |
| 系统管理 | 用户 CRUD、MCP Key CRUD、构建产物列表、Agent 日志查询 | `server/internal/api/router.go` |
| AI Copilot | 全局 AI 助手、多轮对话、流式输出、在线/离线 Agent 上下文感知 | `server/internal/ai/` `server/internal/api/ai_handlers.go` |
| AI 工具链 (Tool Calling) | Nuclei 文档检索、知识库查询、POC 分析审查、执行诊断 | `server/internal/ai/tools_builtins.go` |
| 云资源编排 | AutoScaler 自动伸缩引擎、阿里云 ECS Provider、实例对账与孤儿回收、AES-256-GCM 凭证加密 | `server/internal/cloud/` |

### 数据面 (Agent)

| 模块 | 功能 | 文件 |
|------|------|------|
| Worker 生命周期 | 注册、心跳、拉取任务、执行任务、完成回报 | `scanner/internal/agent/worker.go` |
| 流式结果回传 | `OutputHook -> gRPC StreamResult` | `scanner/internal/agent/worker.go` |
| 任务取消中断 | `context.Cancel` 注入扫描上下文 | `scanner/internal/agent/worker.go` |
| 并发框架 | Worker Pool 与引擎并发上限协同控制 | `scanner/internal/agent/worker.go` |
| 增量规则同步框架 | 本地 Manifest / Hash 比对、差异下载、全量降级同步 | `scanner/internal/agent/worker.go` |
| POC / EXP 调试拦截 | POC 拦截 Nuclei/GoPoc 调试请求响应；EXP Starlark 调试回传每次 `http.request` 的请求包、响应包和耗时 | `scanner/internal/agent/debug.go` `scanner/internal/exploit/starlark_api.go` `scanner/lib/nuclei/pkg/tmplexec/exec.go` |
| Spot 回收监听 | 云厂商竞价实例中断检测、紧急数据回传 | `scanner/internal/agent/signal.go` |

### 扫描引擎

| 模块 | 功能 |
|------|------|
| 空间搜索引擎 | Fofa / Hunter / Quake 集成 |
| 子域名枚举 | subfinder + 自定义爆破 |
| 存活探测 | ICMP + TCP Ping |
| 端口扫描 | TCP / SYN (Masscan) |
| 协议识别 | Banner 抓取 |
| Web 探测 | httpx 批量探测 |
| 指纹识别 | 被动 + 主动目录指纹 |
| Workflow 路由 | 指纹到 POC 的映射 |
| 漏洞检测 | Nuclei v3 + GoPoc |

### 前端 (server-ui)

| 页面 / 模块 | 当前状态 |
|-------------|----------|
| Login | 可用 |
| Dashboard | 基础概览可用 |
| NodeManagement | 节点状态与负载展示可用 |
| TaskManagement | 任务创建 / 查询 / 取消 / 删除可用 |
| TaskResults | 漏洞 / 资产 / 指纹结果查看可用 |
| ProfilesView | 融合画像查询可用 |
| POC / Workflow / Dir 配置页 | 可视化 CRUD 可用，已接入在线调试与 AI 辅助增强 |
| UserManagement | 可用 |
| McpConfig | 可用 |
| AI Copilot | 全局 Drawer 交互，支持表格/多行引用/代码块渲染、POC/EXP YAML 一键应用、草稿动作确认 |
| AI Config | 大模型渠道、参数配置、连通性测试、Copilot Prompt/动作白名单/审计管理 |

---

## 三、部分实现 / 链路未闭环 (⚠️)

| 模块 | 当前现状 | 主要缺口 |
|------|----------|----------|
| Agent 控制链路 | `commandLoop`、规则同步、Manifest 增量下载代码都已写 | Agent 侧用匿名 `http.Get` 请求受 JWT 保护的 API；`Register` 返回的 token 仅为 `dummy_token_*`，且未被 Agent 使用，导致取消指令和规则热同步主链路未真正打通 |
| WebSocket 实时看板 | 服务端广播 Hub 已可工作，已实现基于租户的数据隔离 | 前端用 `?token=` 建连，后端只认 `Authorization: Bearer`，浏览器实时订阅链路未完全对接 |
| 优先级 / 标签 / 容量调度 | 多优先级队列、节点标签匹配、`capacity` 字段与负载展示均已存在 | 任务创建接口未暴露 `agent_selector`；Agent 无法向服务端上报容量，Server 注册时容量固定为 `1` |
| 任务状态机 | `DONE` / `FAILED` / `CANCELLED` / `TIMEOUT` 的 RootTask 聚合已收口；存在活跃子任务时保持 `Running` / `PartialDone`，无活跃子任务时按 `Timeout > Failed > Cancelled > FINISHED` 收敛 | 后续可继续补充失败原因统计和前端展示 |
| 云资源编排 | AutoScaler 自动伸缩引擎已接入 `main.go`、阿里云 ECS Provider 已注册、Cloud-Init 地址注入/实例状态收敛/OSS 制品就绪校验已打通、NoStock 多可用区+多规格自动重试+规格降级引擎已实现 | 多云 Provider 扩展与端到端生命周期集成测试仍不足 |
| CloudManagement 页面 | 后端已提供完整的凭证/策略/实例 CRUD、仪表盘 API、实时价格查询、可用规格列表（23 个端点）；前端已集成手动弹容地域可选+规格可选+实时价格预估 | 前端已全量接入真实后端 API 数据流，并支持策略下发 |
| ClientBuild 页面 | 可列出 `release/` 目录产物 | 构建触发接口仅返回 `accepted`；`/release/*` 下载路径未真正挂成静态文件服务 |
| 遥测日志黑匣子 | gRPC `StreamLogs` 服务端与查询接口已实现 | Agent 端没有日志上报发送器，前端也没有日志页面入口 |
| Spot 回收处理 | `StartSpotTerminationListener` 已实现，Agent 在 `ARGUS_SPOT=1` 或 `cloud=...` 标签下会自动启用 | 云厂商直接强杀且无预警时仍依赖心跳回收兜底 |
| Dashboard 数据增强 | 趋势、严重度、任务结果统计、高危漏洞接口已实现 | Dashboard 图表仍有部分前端静态推算，未完全消费真实统计接口 |
| 角色权限系统 | RBAC 中间件已启用，固定三档角色和接口权限矩阵已对齐前端说明；云 AK/SK 已支持 owner + 用户绑定，详见 `docs/tenant-rbac.md` | 暂无角色 CRUD / 自定义权限矩阵管理接口，项目级 `project_members` 尚未启用 |
| Clean Architecture 迁移 | `core/usecase`、`adapters`、`bootstrap` 目录结构已搭好 | `/api/v2`、新 HTTP/gRPC adapter、仓储与 usecase 仍是 scaffold / `ErrNotImplemented` |

---

## 四、未实现功能清单 (❌)

| 类别 | 未实现功能 |
|------|-----------|
| **Clean Architecture 落地** | `core/usecase` 真正承接业务逻辑，替换当前 `router.go` 直连数据库模式 |
| **容器化隔离执行** | 每任务隔离 Runner、网络代理、CPU / 内存限制 |
| **角色管理后台** | 角色 CRUD、权限矩阵配置、可视化授权管理 |
| **真实客户端构建链路** | API 触发本地或 CI 构建、构建状态追踪、构建产物分发 |
| **对象存储层** | 报告文件、规则包、二进制产物的独立文件 / 对象存储 |
| **租户治理** | 任务配额、并发额度、租户级资源限制 |
| **EXP / GoPoc 元数据中心** | GoPoc / EXP 的动态索引、版本化、审核与管理 |

---

## 五、下一步建议优先级

| 优先级 | 功能 | 说明 |
|--------|------|------|
| P0 | 打通 Agent 鉴权链路 | 统一 gRPC 注册 token、Agent REST 调用鉴权、WebSocket 鉴权 |
| 已收口 | 完善任务状态收敛 | 已补齐 `FAILED / CANCELLED / TIMEOUT` 的 RootTask 聚合与终态计算 |
| P1 | 完善节点容量与标签路由 | 让 Agent 上报容量，任务创建支持 `agent_selector` |
| P1 | 接通遥测日志链路 | Agent 发送 `StreamLogs`，前端补日志查看页 |
| P2 | 推进 Clean Architecture 迁移 | 逐步把 `router.go` 中的直接业务逻辑迁入 usecase / adapter |

---

## 六、当前接口实现清单

本文只描述从 `server/cmd/dddd-server/main.go` 接线进入运行链路的接口，不把 `server/internal/adapters/httpapi`、`server/internal/adapters/grpcagent` 等 Clean Architecture scaffold 视为可用接口。

### 通用约定

- HTTP 基础前缀：`/api/v1`
- HTTP 鉴权：JWT Bearer Token，`POST /api/v1/auth/login` 例外
- 租户与 RBAC：JWT 中的 `tenant_id` 是数据隔离边界；`admin` / `operator` / `viewer` 权限矩阵见 [租户隔离与角色权限划分](tenant-rbac.md)
- WebSocket：`GET /api/v1/ws`
- gRPC 服务：`scan.AgentService`
- 协议定义：`shared/proto/proto/scan/agent.proto`

### HTTP REST

| 模块 | 代表接口 | 当前实现 |
|------|----------|----------|
| 认证与会话 | `POST /auth/login` | 数据库用户优先，兼容开发密码，成功后签发 JWT |
| 任务与队列 | `GET/POST/DELETE /tasks`、`POST /tasks/:id/cancel`、`POST /tasks/:id/append`、`GET /queue/depth` | RootTask / SubTask 创建、取消、追加、队列深度查询 |
| 统计、结果与画像 | `/stats*`、`/vulns`、`/assets`、`/fingerprints`、`/profiles`、`/reports/export/vulns` | 统计聚合、结果查询、画像聚合、漏洞 CSV 导出 |
| 节点与 Agent 指令 | `GET /nodes`、`GET /agents/:id/commands`、`GET /agents/:id/logs` | 节点列表、取消/规则重载指令、Agent 日志查询 |
| Arsenal 与规则 | `/arsenals/:type`、`/arsenals/manifest`、审批/回滚/删除接口 | 原始规则 CRUD、审批、回滚、Manifest 与 `rule_version` |
| 字典 | `/dictionaries/workflow`、`/dictionaries/fingerprint` | Workflow / Fingerprint 结构化 CRUD，并回写 Arsenal |
| 用户与系统配置 | `/users`、`/mcp/keys`、`/ai/config`、`/ai/models`、`/ai/test` | 用户管理、MCP Key、AI 配置与模型连通性测试 |
| AI Copilot | `POST /ai/chat`、`POST /ai/actions/confirm`、`GET /ai/copilot/prompts`、`GET /ai/tool-invocations`、`POST /ai/arsenal/analyze`、`POST /ai/arsenal/analyze/stream` | 全局 Copilot SSE、草稿动作确认、Prompt/动作白名单展示、工具审计、POC AI 审查同步/流式入口 |
| 云资源编排 | `/cloud/accounts*`、`/cloud/policies*`、`/cloud/instances*`、`/cloud/dashboard` | 云凭证、策略、实例生命周期、OSS、一键配置、仪表盘 |
| 构建 | `GET /build/artifacts`、`POST /build/client` | 产物列表可用；构建触发仍只返回 `accepted` |

### WebSocket

| 路径 | 当前实现 |
|------|----------|
| `GET /ws` | 建立实时连接并加入广播 Hub，当前主要用于结果批量写入后的 `scan_result_batch` 事件 |

### gRPC

| RPC | 当前实现 |
|-----|----------|
| `Register` | 节点注册，写入/更新 `nodes`，记录容量、标签、OS/Arch、租户与节点会话 token |
| `Heartbeat` | 更新节点存活时间、运行任务数、运行任务列表与规则版本，并判断是否需要同步规则 |
| `Subscribe` | Agent 长连接等待任务通知和控制信号 |
| `ClaimTask` | Agent 主动认领任务，支持 RabbitMQ 原子领取、标签匹配、容量回写和终态消息丢弃 |
| `FetchTask` | 兼容旧 Agent 的轮询接口，内部委托领取逻辑 |
| `StreamResult` | 接收 Agent 流式结果并异步写入结果缓冲池 |
| `TaskComplete` | 更新子任务状态、ACK 队列、递减节点运行数，并刷新 RootTask 聚合状态 |
| `EmergencyDump` | Spot 或紧急中断场景的兜底上报入口 |
| `StreamLogs` | 接收 Agent 日志流并写入 `agent_logs` 表 |

### 维护约定

- 新增或删除 `/api/v1` 路由时，同步更新本节。
- 如果启用 `/api/v2`，单独增加版本化接口小节，不与当前主链路混写。
- 对只返回 `accepted`、mock 或 scaffold 的接口，必须明确标注是否真正执行后端动作。
