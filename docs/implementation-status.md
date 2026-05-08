# Argus 项目实现状态总览

> 本文档基于当前仓库代码实际状态整理。
>
> 标注说明：`✅` = 已实现并接入主链路 | `⚠️` = 代码已存在但链路未闭环 / 仅部分可用 | `❌` = 尚未实现
>
> 当前接口清单已经合并到本文末尾，避免实现状态与接口状态分散维护。
>
> 最后同步：2026-05-08。本次同步以“安全闭环、质量门禁、显式调度、Agent 日志、客户端构建、Dashboard 实时化”为闭环范围。

---

## 一、总体完成度

| 阶段 | 状态 | 完成度 |
|------|------|--------|
| Phase 1：数据异构化与结果防洪 | ✅ 已完成 | ~95% |
| Phase 2：分布式调度与基础控制面 | ✅ Agent session 鉴权、容量上报、显式调度选择器已接入 | ~92% |
| Phase 3：运营管控、系统化与 AI 化 | ⚠️ 构建/日志/质量门禁已补齐基础闭环，治理能力仍需深化 | ~72% |

---

## 二、本轮修复闭环状态

| 计划项 | 当前判定 | 已接入的主链路 | 仍需跟进 |
|--------|----------|----------------|----------|
| Agent 内部 HTTP session 鉴权 | ✅ 已闭环 | Agent 保存 `RegisterResp.token`，内部 HTTP 统一携带 `x-agent-id` + `x-agent-token`；Server 按 `nodes.agent_id + token` 注入真实 `tenant_id`，并校验 `/agents/:id/commands` 路径 ID；Agent 重注册会轮换 session token，离线/紧急下线会清理 token，内部 HTTP 只接受 Alive 节点 | 长期可补 token 过期时间和审计 |
| Agent 规则同步租户隔离 | ✅ 已闭环 | `/arsenals/db*` 与 `/arsenals/manifest` 可由 Agent session 进入，按 Agent 所属租户导出规则；普通 JWT 访问仍走 JWT/RBAC | 规则包增量传输与长期制品存储 |
| 显式调度控制 | ✅ 已闭环 | `CreateTaskRequest.agent_selector` 已支持扁平字符串 map，Server 写入每个 SubTask；`POST /tasks/preview-selector` 复用服务端最终 selector 规则，并按目标类型返回匹配节点、空闲槽位和不可匹配原因；前端任务创建页展示分组调度解释 | 后续可支持表达式、反选和跨批次容量预测 |
| Agent 遥测日志 | ✅ 已闭环 | Agent gologger TeeWriter 通过 gRPC `StreamLogs` 上报；`GET /agents/:id/logs` 支持 `level/limit/q/since/until`；`/agent-logs/summary` 提供级别聚合和 ERROR/WARN 摘要；保留天数配置与定时清理已接入；前端 AgentLogs 支持筛选持久化与导出 | 长期归档、告警联动 |
| 客户端构建链路 | ✅ 已闭环 | `POST /build/client` 原子化创建 BuildJob 并后台执行 `build.sh`；`GET /build/jobs*` 和 `/release/*` 可查看状态与下载产物；BuildJob 支持取消、重试和完整日志读取 | 多组件构建、CI 制品发布 |
| Dashboard 实时化与数据化 | ✅ v1 闭环 | WebSocket envelope 包含 `type/event/version/occurred_at/data`，服务端 heartbeat，前端断线重连后刷新 Dashboard；趋势、严重度、任务结果、高危漏洞均接入后端统计接口 | 持久事件日志 replay、更多页面 backfill |
| 工程质量门禁 | ✅ 基础闭环 | 顶层 `Makefile` 提供 `test/lint/ci/coverage/frontend-smoke/cloud-smoke`；server-ui 接入 Vitest + Testing Library；GitHub Actions 覆盖根模块 Go test、`server` 子模块 Go test、Go 覆盖率输出、Cloud Provider mock smoke、前端 lint/test/smoke/build | 后续补覆盖率阈值、真实浏览器 E2E 和 UI 截图回归 |

---

## 三、已实现功能清单 (✅)

### 控制面 (Server)

| 模块 | 功能 | 文件 |
|------|------|------|
| API Gateway | Gin REST API 主路由 | `server/internal/api/router.go` |
| 身份与权限 | JWT 登录校验、RBAC 中间件、EXP 授权闸门、项目成员访问控制 | `server/internal/api/router.go` `server/internal/api/middleware_rbac.go` `server/internal/api/project_access.go` |
| 任务管理 | RootTask / SubTask 创建、拆分、查询、删除、取消、追加目标、项目访问校验 | `server/internal/api/router.go` |
| 调度队列 | RabbitMQ 多优先级队列 + 内存 fallback，支持队列深度查询与通知广播 | `server/internal/scheduler/queue.go` |
| 队列恢复 | Dead-Letter 回收、旧队列迁移、死亡节点任务抢救 | `server/internal/scheduler/queue.go` `server/cmd/dddd-server/main.go` |
| 超时与重试 | 基于 `timeout_sec` 的超时扫描与自动重试守护协程 | `server/internal/api/router.go` |
| gRPC 通信 | `Register` / `Heartbeat` / `FetchTask` / `StreamResult` / `TaskComplete` / `EmergencyDump` / `StreamLogs` | `server/internal/grpc/server.go` |
| Agent 内部 HTTP API | Agent 命令轮询、Arsenal DB Hash / SQLite DB 同步端点，使用 `x-agent-id` + `x-agent-token` session 鉴权；`x-agent-psk` 仅保留给 gRPC/bootstrap | `server/internal/api/router.go` `server/internal/api/arsenal_export.go` |
| 数据模型 | PostgreSQL migration runner + schema verify | `server/internal/db` |
| 结果入库 | Asset / FingerprintHit / Vulnerability 三层结构化存储 | `server/internal/db/db.go` |
| 防洪落库 | BatchWriter 异步缓冲写入 | `server/internal/db/db.go` |
| Arsenal 管理 | POC / Finger / Workflow / Dir / EXP 的 CRUD、审批、Manifest、回滚、Agent SQLite DB 导出 | `server/internal/api/router.go` `server/internal/api/handler_exploits.go` `server/internal/api/arsenal_export.go` |
| Dictionary API | Workflow / Fingerprint 结构化 CRUD | `server/internal/api/handler_dictionary.go` |
| 规则初始化 | 启动时从磁盘导入规则与结构化目录 | `server/internal/db/seed.go` |
| 结果查询 | 漏洞、资产、指纹、融合画像接口 | `server/internal/api/router.go` |
| 统计接口 | 首页五维统计 + 趋势 / 严重度 / 任务结果统计 / 最近高危漏洞 | `server/internal/api/router.go` `server/internal/db/stats.go` |
| WebSocket Hub | 结果批量写入与 EXP 执行状态的服务端广播 | `server/internal/api/ws.go` |
| 报表导出 | 漏洞 CSV 导出 | `server/internal/api/router.go` |
| 系统管理 | 用户 CRUD、MCP Key CRUD、构建产物列表、Agent 日志查询 | `server/internal/api/router.go` |
| AI Copilot | 全局 AI 助手、多轮对话、流式输出、在线/离线 Agent 上下文感知 | `server/internal/ai/` `server/internal/api/ai_handlers.go` |
| AI 工具链 (Tool Calling) | Nuclei 文档检索、知识库查询、POC / EXP 分析审查、执行诊断、节点容量分析 | `server/internal/ai/tools_builtins.go` `server/internal/api/ai_tools.go` |
| 云资源编排 | AutoScaler 自动伸缩引擎、阿里云 ECS Provider、实例对账与孤儿回收、AES-256-GCM 凭证加密 | `server/internal/cloud/` |

### 数据面 (Agent)

| 模块 | 功能 | 文件 |
|------|------|------|
| Worker 生命周期 | 注册、心跳、拉取任务、执行任务、完成回报 | `scanner/internal/agent/worker.go` |
| 流式结果回传 | `OutputHook -> gRPC StreamResult` | `scanner/internal/agent/worker.go` |
| 任务取消中断 | `context.Cancel` 注入扫描上下文 | `scanner/internal/agent/worker.go` |
| 并发框架 | Worker Pool 与引擎并发上限协同控制，定期向 Subscribe 流上报 `capacity_update` | `scanner/internal/agent/worker.go` |
| 动态控制 | 命令轮询接收取消任务与规则热加载信号 | `scanner/internal/agent/worker.go` |
| 规则同步 | 通过 `x-agent-id` + `x-agent-token` 拉取 Arsenal DB Hash，变更后下载完整 SQLite DB 并原子替换本地 `data/arsenal.db` | `scanner/internal/agent/worker.go` |
| POC / EXP 调试拦截 | POC 拦截 Nuclei/GoPoc 调试请求响应；EXP Starlark 调试回传每次 `http.request` 的请求包、响应包和耗时 | `scanner/internal/agent/debug.go` `scanner/internal/exploit/starlark_api.go` `scanner/lib/nuclei/pkg/tmplexec/exec.go` |
| 遥测日志 | gologger 全局 TeeWriter 通过 gRPC `StreamLogs` 持续上报 Agent 日志 | `scanner/internal/agent/worker.go` |
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
| Dashboard | 基础概览、真实趋势/严重度/任务结果/高危漏洞统计、WebSocket heartbeat 与重连刷新可用 |
| NodeManagement | 节点状态、标签、负载、空闲槽位展示可用 |
| TaskManagement | 任务创建 / 查询 / 取消 / 删除可用，创建时支持 Agent 标签选择器 |
| TaskResults | 漏洞 / 资产 / 指纹结果查看可用 |
| ProfilesView | 融合画像查询可用 |
| POC / Finger / Workflow / Dir / EXP 配置页 | 可视化 CRUD 可用，已接入在线调试、AI 辅助增强与 EXP Builder |
| UserManagement | 可用 |
| ProjectManagement | 项目 owner / operator 成员分配已接入 |
| CloudManagement | 云凭证、策略、实例、OSS 制品上传、权限检查和价格/规格选择已接入真实 API |
| ClientBuild | 构建产物、BuildJob 队列、状态和 `/release/*` 下载入口可用 |
| AgentLogs | Agent 日志筛选、查看与导出可用 |
| RoleManagement | 已接入后端角色列表、内置角色只读展示、自定义角色创建/编辑/删除、权限基线说明和租户任务配额配置 |
| McpConfig | 可用 |
| AI Copilot | 全局 Drawer 交互，支持表格/多行引用/代码块渲染、POC/EXP YAML 一键应用、草稿动作确认 |
| AI Config | 大模型渠道、参数配置、连通性测试、Copilot Prompt/动作白名单/审计管理 |

---

## 四、部分实现 / 链路未闭环 (⚠️)

| 模块 | 当前现状 | 主要缺口 |
|------|----------|----------|
| Agent 控制链路 | gRPC 仍使用 PSK 引导，Agent 已保存 `Register` session token；内部 HTTP 使用 `x-agent-id` + `x-agent-token` 绑定真实租户；重注册 token 轮换、离线 token 清理和 Alive 状态校验已接入 | 长期可补 token 过期时间、审计和主动吊销接口 |
| WebSocket 实时看板 | 服务端支持 Header/query token，Hub 按租户广播，事件 envelope 已包含 `type/event/version/occurred_at/data`，并定期发送 heartbeat；Dashboard 重连后主动刷新 | 暂不支持持久事件日志 replay，细粒度事件权限仍可继续增强 |
| 优先级 / 标签 / 容量调度 | 多优先级队列、节点标签匹配、SubTask `agent_selector`、Agent 注册容量与 `capacity_update` 都已存在；任务创建 API / UI 已暴露显式 `agent_selector`，并通过后端预览接口对齐隐式 `target_type` 合并规则；预览结果已按目标类型解释匹配节点、容量和原因 | selector 目前是扁平字符串等值匹配，后续可支持表达式、反选和跨批次容量预测 |
| 任务状态机 | `DONE` / `FAILED` / `CANCELLED` / `TIMEOUT` 的 RootTask 聚合已收口；存在活跃子任务时保持 `Running` / `PartialDone`，无活跃子任务时按 `Timeout > Failed > Cancelled > FINISHED` 收敛 | 后续可继续补充失败原因统计和前端展示 |
| 云资源编排 | AutoScaler 自动伸缩引擎已接入 `main.go`、阿里云 ECS Provider 已注册、Cloud-Init 地址注入/实例状态收敛/OSS 制品就绪校验已打通、NoStock 多可用区+多规格自动重试+规格降级引擎已实现 | 多云 Provider 扩展与端到端生命周期集成测试仍不足 |
| CloudManagement 页面 | 后端已提供完整的凭证/策略/实例 CRUD、仪表盘 API、实时价格查询、可用规格列表；前端已接入真实 API 数据流并支持策略下发 | 策略执行异常态、云实例真实生命周期、OSS fallback 和权限检查缺少自动化端到端覆盖 |
| ClientBuild 页面 | 可列出 `release/` 目录产物，`/release/*` 已挂为静态下载入口；`POST /build/client` 会原子化创建 BuildJob 并后台执行 `build.sh`；前端可查看构建队列、取消运行中任务、重试终态任务并查看完整日志 | 目前只构建 `dddd-agent`；缺少多组件构建和 CI 制品发布 |
| 遥测日志黑匣子 | Agent gologger TeeWriter 已通过 gRPC `StreamLogs` 写入 `agent_logs`；前端 Agent 日志页支持 level/关键字/时间/limit 筛选、筛选条件持久化、导出、级别聚合与错误摘要；Server 已接入保留天数配置和定时清理 | 仍缺告警联动和长期归档 |
| Spot 回收处理 | `StartSpotTerminationListener` 已实现，Agent 在 `ARGUS_SPOT=1` 或 `cloud=...` 标签下会自动启用 | 云厂商直接强杀且无预警时仍依赖心跳回收兜底 |
| Dashboard 数据增强 | 趋势、严重度、任务结果统计、高危漏洞接口已实现；Dashboard 已消费真实统计接口；WebSocket heartbeat 与重连刷新已接入 | 后续可继续补更多页面 backfill 和持久事件 replay |
| 角色与租户治理 | RBAC 中间件已启用，内置三档角色保持兼容；新增租户级自定义角色表、`/roles` CRUD、权限矩阵返回和 RoleManagement 可视化管理；自定义角色通过 `base_role` 映射到 admin/operator/viewer 权限基线；已新增租户任务配额，创建任务校验活跃任务/每日任务数，Agent 认领校验运行中批次数；云 AK/SK 已支持 owner + 用户绑定；项目 `owner/operator` 成员访问控制已接入，详见 `docs/tenant-rbac.md` | 自定义角色目前继承基线角色，尚未支持逐接口差异化授权；项目成员只有 owner/operator 两档，缺少 viewer 等更细粒度项目权限 |
| Clean Architecture 迁移 | `core/usecase`、`adapters`、`bootstrap` 目录结构已搭好 | `/api/v2`、新 HTTP/gRPC adapter、仓储与 usecase 仍是 scaffold / `ErrNotImplemented` |
| 工程质量门禁 | 已新增 GitHub Actions、顶层 `test/lint/ci/coverage/frontend-smoke/cloud-smoke` 聚合目标、Vitest + Testing Library 基础前端测试，workflow 已覆盖独立 `server` Go module、Go 覆盖率输出和云资源 mock smoke | 仍缺覆盖率阈值、真实浏览器 E2E 和 UI 截图回归 |

---

## 五、发布前保留缺口 (❌)

> 已经进入主链路或只属于长期优化的事项不再放入“未实现”列表。以下只保留发布前需要明确处理或在 Release Notes 中声明边界的项目。

| 编号 | 类别 | 发布前状态 | 发布口径 |
|------|------|------------|----------|
| REL-01 | 发布制品流水线 | 本地 `make ci`、GitHub Actions、BuildJob 队列和 `/release/*` 下载已可用；`deploy/build-bundle.sh` 默认版本已固定为 `v0.1.0` 并校验发行包必需文件；仍缺制品签名和 CI 上传 release artifact | 发布前至少产出 server / agent / server-ui 构建包，并在发布说明中标注未签名或补齐签名 |
| REL-02 | 部署配置与密钥基线 | JWT、Agent session、RBAC、租户配额、云凭证加密已接入；已新增 `deploy/production.env.example` 和默认密码/开发密钥禁用说明 | 发布包必须附最小生产配置模板，明确 `JWT_SECRET`、数据库、RabbitMQ、Agent PSK、AI Key、云 AK/SK 的配置要求 |
| REL-03 | 云资源与 OSS 发布验证 | Cloud Provider mock、OSSStore、本地对象存储、Agent 制品上传链路已有测试；真实云账号端到端弹容、回收、OSS fallback 仍需发布前 smoke | 发布前用测试云账号跑一次一键配置、制品上传、弹容、回收；若未跑真实云 smoke，需在发布说明中标注为 beta 能力 |
| REL-04 | 文档与运维入口 | README 已指向生产部署指南和 `docs/release-checklist.md`；仍需发布说明、升级/回滚和常见故障 | 发布前 README 指向部署文档、运维文档和风险声明；避免把内部路线图当成用户使用说明 |

### 已从缺口列表移除

| 原编号 | 原类别 | 当前状态 |
|--------|--------|----------|
| GAP-02 | 调度解释与任务状态可观测 | 已有后端预览接口、目标类型分组、容量和不可匹配原因展示，后续表达式/反选属于增强 |
| GAP-03 | Dashboard 真实数据消费 | 已接入真实趋势、严重度、任务结果、高危漏洞统计和重连刷新 |
| GAP-04 | Agent session 生命周期 | 已支持 token 轮换、离线清理和 Alive 校验，过期时间/主动吊销属于长期安全增强 |
| GAP-05 | 日志治理 | 已支持筛选、导出、聚合、保留天数和清理，告警/长期归档属于运维增强 |
| GAP-07 | 自定义角色与权限后台 | 已支持自定义角色 CRUD、权限基线、用户分配和前端管理，逐接口差异化授权不阻塞首版发布 |
| GAP-08 | 租户治理 | 已支持租户任务配额、创建任务校验和 Agent 认领校验，按项目/用户细分属于后续治理 |
| GAP-09 | GoPoc / EXP 高级治理 | 已支持 POC 元数据检索、EXP 批量审核、风险豁免、凭据引用和审计记录，凭据内容安全注入属于后续高级能力 |
| GAP-10 | 对象存储层 | 已有 Storage 接口、LocalStore、OSSStore、构建制品校验和漏洞 CSV 报告落库，规则包迁移不阻塞首版发布 |
| GAP-11 | Clean Architecture 落地 | 当前 `/api/v1` 主链路可用；Clean Architecture 迁移是长期维护事项，不作为发布阻塞 |

---

## 六、发布准备任务规划

| 顺序 | 任务 | 交付内容 | 验收标准 |
|------|------|----------|----------|
| 1 | 发布构建与制品整理 | 版本号固定为 `v0.1.0`；生成 server / agent / server-ui 制品；确认 `/release/*` 中 Agent 产物可下载 | `make ci` 通过；制品列表完整；发布说明包含版本号和构建来源 |
| 2 | 生产配置模板 | 已提供 `deploy/production.env.example`；标注必填密钥、默认密码禁用、数据库/RabbitMQ/AI/云账号配置 | 新环境按模板能启动 server、server-ui 和至少 1 个 Agent |
| 3 | 真实环境 smoke | 使用测试租户跑登录、节点注册、任务创建、规则同步、漏洞导出、Agent 日志、BuildJob、EXP dry-run；云能力跑一键配置和 OSS 上传 | smoke 清单全部记录通过；未验证项明确标为 beta 或可选 |
| 4 | 发布文档收口 | README 指向快速部署、租户/RBAC、安全边界、常见故障；`implementation-status.md` 只保留内部状态 | 用户能按 README 完成安装、登录、接入 Agent、创建首个任务 |

---

## 七、当前接口实现清单

本文只描述从 `server/cmd/dddd-server/main.go` 接线进入运行链路的接口，不把 `server/internal/adapters/httpapi`、`server/internal/adapters/grpcagent` 等 Clean Architecture scaffold 视为可用接口。

### 通用约定

- HTTP 基础前缀：`/api/v1`
- HTTP 鉴权：JWT Bearer Token，`POST /api/v1/auth/login` 例外
- 租户与 RBAC：JWT 中的 `tenant_id` 是数据隔离边界；`role` 可为内置角色或租户级自定义角色，`role_base` 表示自定义角色继承的内置权限基线；`admin` / `operator` / `viewer` 权限矩阵见 [租户隔离与角色权限划分](tenant-rbac.md)
- Agent 内部 HTTP：`/agents/:id/commands`、`/arsenals/db*` 使用 `x-agent-id` + `x-agent-token`；token 来源为 gRPC `RegisterResp.token`
- WebSocket：`GET /api/v1/ws`，支持 `Authorization: Bearer <JWT>` 或 `?token=<JWT>`
- gRPC 服务：`scan.AgentService`
- 协议定义：`shared/proto/proto/scan/agent.proto`

### HTTP REST

| 模块 | 代表接口 | 当前实现 |
|------|----------|----------|
| 认证与会话 | `POST /auth/login` | 数据库用户优先，兼容开发密码，成功后签发 JWT |
| 任务与队列 | `GET/POST/DELETE /tasks`、`POST /tasks/preview-selector`、`POST /tasks/:id/cancel`、`POST /tasks/:id/append`、`GET /queue/depth` | RootTask / SubTask 创建、调度选择器预览、取消、追加、队列深度查询；创建任务支持 `agent_selector` |
| 项目与成员 | `/projects*`、`GET/PUT /projects/:id/members` | 项目 CRUD、owner/operator 成员维护、任务与结果访问校验 |
| 统计、结果与画像 | `/stats*`、`/vulns`、`/assets`、`/fingerprints`、`/profiles`、`/reports/export/vulns` | 统计聚合、结果查询、画像聚合、漏洞 CSV 导出 |
| 节点与 Agent 指令 | `GET /nodes`、`GET /agents/:id/commands`、`GET /agents/:id/logs` | 节点列表、Agent session 绑定命令轮询、Agent 日志筛选查询 |
| Arsenal 与规则 | `/arsenals/:type`、`/arsenals/manifest`、`/arsenals/db*`、审批/回滚/删除接口 | 原始规则 CRUD、审批、回滚、Manifest、`rule_version`、Agent SQLite DB 同步 |
| EXP 验证与执行 | `/exploits*`、`/exploits/:id/risk-waiver`、`/exploits/batch/*`、`/exploits/audits`、`/exploit-runs*`、`/exploit-artifacts/*` | EXP 规则列表、单条/批量审核与废弃、风险豁免、审计查询、删除、dry-run、Agent 调试、正式执行、凭据引用记录、取消、cleanup、制品查询 |
| 字典 | `/dictionaries/workflow`、`/dictionaries/fingerprint` | Workflow / Fingerprint 结构化 CRUD，并回写 Arsenal |
| 用户、角色、租户与系统配置 | `/users`、`/roles`、`/tenants/:id/quotas`、`/mcp/keys`、`/ai/config`、`/ai/models`、`/ai/test` | 用户管理、自定义角色 CRUD、权限矩阵返回、租户任务配额管理、MCP Key、AI 配置与模型连通性测试 |
| AI Copilot / POC 元数据 | `GET /poc-rules`、`POST /ai/chat`、`POST /ai/actions/confirm`、`GET /ai/copilot/prompts`、`GET /ai/tool-invocations`、`POST /ai/arsenal/analyze`、`POST /ai/arsenal/analyze/stream` | POC 元数据检索、全局 Copilot SSE、草稿动作确认、Prompt/动作白名单展示、工具审计、POC AI 审查同步/流式入口 |
| 云资源编排 | `/cloud/accounts*`、`/cloud/policies*`、`/cloud/instances*`、`/cloud/dashboard` | 云凭证、策略、实例生命周期、OSS、一键配置、仪表盘 |
| 构建 | `GET /build/artifacts`、`GET /build/jobs*`、`GET /build/jobs/:id/logs`、`POST /build/jobs/:id/cancel`、`POST /build/jobs/:id/retry`、`POST /build/client`、`GET /release/*` | 产物列表、BuildJob 状态/完整日志、取消/重试、后台执行 `build.sh` 与静态下载可用 |

### 本轮验收命令

以下命令用于验证本文档描述的基础闭环。需要注意：当前 GitHub Actions 还需单独补上 `server` 子模块 Go test；本地 `make test` 已覆盖该子模块。

| 命令 | 覆盖范围 |
|------|----------|
| `make test` | 根模块 Go test、`server` 子模块 Go test、server-ui Vitest |
| `make lint` | server-ui ESLint |
| `make ci` | lint + test + server-ui build |
| `npm --prefix server-ui run build` | 前端生产构建 |

### WebSocket

| 路径 | 当前实现 |
|------|----------|
| `GET /ws` | 支持 Header / query token 建连并加入租户广播 Hub，事件 envelope 包含 `type/event/version/occurred_at/data`，当前主要用于扫描结果、EXP 状态和 heartbeat；暂不支持持久 replay |

### gRPC

| RPC | 当前实现 |
|-----|----------|
| `Register` | 节点注册，写入/更新 `nodes`，记录容量、标签、OS/Arch、租户并返回节点会话 token；Agent 使用该 token 调用内部 HTTP |
| `Heartbeat` | 更新节点存活时间、运行任务数、运行任务列表与规则版本，并判断是否需要同步规则 |
| `Subscribe` | Agent 长连接等待任务通知和控制信号，并接收 `capacity_update` 更新空闲槽位 |
| `ClaimTask` | Agent 主动认领任务，支持 RabbitMQ 原子领取、标签匹配、容量回写和终态消息丢弃 |
| `FetchTask` | 兼容旧 Agent 的轮询接口，内部委托领取逻辑 |
| `StreamResult` | 接收 Agent 流式结果并异步写入结果缓冲池 |
| `TaskComplete` | 更新子任务状态、ACK 队列、递减节点运行数，并刷新 RootTask 聚合状态 |
| `EmergencyDump` | Spot 或紧急中断场景的兜底上报入口 |
| `StreamLogs` | 接收 Agent gologger TeeWriter 日志流并写入 `agent_logs` 表 |

### 工程化与质量门禁

| 项 | 当前现状 | 缺口 |
|----|----------|------|
| 后端测试 | `server` / `scanner` 内有 Go 单测，顶层 `make test` 已聚合 Go + 前端测试 | 缺少覆盖率阈值和更完整的本地 smoke 数据集 |
| 前端测试 | `server-ui` 已接入 Vitest + Testing Library，覆盖 API service、Login、TaskManagement 基础场景 | 缺少 E2E 测试和 UI 回归截图 |
| CI/CD | 已新增 GitHub Actions，PR/主分支运行根模块 Go test、`server` 子模块 Go test、前端 lint/test/build | 缺少发布流水线和制品签名/上传 |

### 维护约定

- 新增或删除 `/api/v1` 路由时，同步更新本节。
- 如果启用 `/api/v2`，单独增加版本化接口小节，不与当前主链路混写。
- 对只返回 `accepted`、mock 或 scaffold 的接口，必须明确标注是否真正执行后端动作。
