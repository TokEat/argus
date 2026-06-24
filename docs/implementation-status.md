# Argus 项目实现状态总览

> 本文档基于当前仓库代码实际状态整理。
>
> 标注说明：`✅` = 已实现并接入主链路 | `⚠️` = 代码已存在但链路未闭环 / 仅部分可用 | `❌` = 尚未实现
>
> 当前接口清单已经合并到本文末尾，避免实现状态与接口状态分散维护。
>
> 最后同步：2026-05-08。本次同步以当前工作树代码为准；只把已经接入 `/api/v1`、Agent 运行链路或 CI/Makefile 的能力标为已实现。

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
| Agent 内部 HTTP session 鉴权 | ✅ 已闭环 | Agent 保存 `RegisterResp.token`，内部 HTTP 统一携带 `x-agent-id` + `x-agent-token`；Server 按 `nodes.agent_id + token` 注入真实 `tenant_id`，并校验 `/agents/:id/commands` 路径 ID；Agent 重注册会轮换 session token，离线/紧急下线会清理 token，内部 HTTP 只接受 Alive 节点；session 已支持过期时间、吊销时间、轮换审计和管理员主动吊销 | gRPC `ClaimTask` 仍通过现有 gRPC/bootstrap 体系和节点状态控制，没有把 session token 作为每个 RPC 的入参 |
| Agent 规则同步租户隔离 | ✅ 已闭环 | `/arsenals/db*` 与 `/arsenals/manifest` 可由 Agent session 进入，按 Agent 所属租户导出规则；普通 JWT 访问仍走 JWT/RBAC | 规则包增量传输与长期制品存储 |
| 显式调度控制 | ✅ 已闭环 | `CreateTaskRequest.agent_selector` 已支持扁平字符串 map，新增 `agent_selector_rules.match/not_match` 支持等值、多值和反选；Server 写入每个 SubTask；`POST /tasks/preview-selector` 与 Agent 认领共用匹配器，并按目标类型返回匹配节点、空闲槽位、预计立即领取批次数、等待批次数和不可匹配原因；前端任务创建页展示分组调度解释 | 后续可支持更复杂表达式 |
| Agent 遥测日志 | ✅ 已闭环 | Agent gologger TeeWriter 通过 gRPC `StreamLogs` 上报；`GET /agents/:id/logs` 支持 `level/limit/q/since/until`；`/agent-logs/summary` 提供级别聚合和 ERROR/WARN 摘要；保留天数配置与定时清理已接入；前端 AgentLogs 支持筛选持久化、导出、告警规则、告警事件和按天归档 | 归档当前写入本地对象存储根目录；长期可补 OSS 归档、归档清理和告警通知渠道 |
| 客户端构建链路 | ✅ 已闭环 | `POST /build/client` 原子化创建 BuildJob 并后台执行 `build.sh`；`GET /build/jobs*` 和 `/release/*` 可查看状态与下载产物；BuildJob 支持取消、重试、完整日志读取、多组件构建和多产物展示；GitHub Actions workflow 已配置 v0.1.0 bundle 与组件制品上传 | 后续可补制品签名；真实发布仍需等待 Actions 实际跑出 artifact |
| Dashboard 实时化与数据化 | ✅ v1 闭环 | WebSocket envelope 包含 `id/type/event/version/project_id/occurred_at/data`，服务端 heartbeat 和 replay 日志表；重连支持 `last_event_id/since` 回放并按租户/项目权限过滤；前端 Dashboard、任务列表、节点列表、AgentLogs、ClientBuild 在重连后主动刷新 | replay 日志目前没有保留期清理策略，后续可补更长周期事件保留与清理 |
| 工程质量门禁 | ✅ 基础闭环 | 顶层 `Makefile` 提供 `test/lint/ci/coverage/frontend-smoke/cloud-smoke`；server-ui 接入 Vitest + Testing Library；GitHub Actions 覆盖根模块 Go test、`server` 子模块 Go test、Go 覆盖率输出、Cloud Provider mock smoke、前端 lint/test/smoke/build | 后续补覆盖率阈值和 UI 截图回归 |

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
| 系统管理 | 用户 CRUD、MCP Key CRUD、构建产物列表、Agent 日志查询、Agent 日志告警与归档 | `server/internal/api/router.go` |
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
| POC / EXP 调试拦截 | POC 拦截 Nuclei/GoPoc 调试请求响应；EXP Python 以原生 Python 执行，请求/响应调试信息由脚本主动写入 `ctx.evidence` 摘要 | `scanner/internal/agent/debug.go` `scanner/internal/exploit/python_executor.go` |
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
| ProjectManagement | 项目 viewer / operator / owner 成员分配已接入 |
| CloudManagement | 云凭证、策略、实例、OSS 制品上传、权限检查和价格/规格选择已接入真实 API |
| ClientBuild | 构建产物、BuildJob 队列、状态和 `/release/*` 下载入口可用 |
| AgentLogs | Agent 日志筛选、查看与导出可用 |
| RoleManagement | 已接入后端角色列表、内置角色只读展示、自定义角色创建/编辑/删除、权限基线说明和租户任务配额配置 |
| McpConfig | 可用 |
| AI Copilot | 全局 Drawer 交互，支持表格/多行引用/代码块渲染、POC YAML / EXP Python 一键应用、草稿动作确认 |
| AI Config | 大模型渠道、参数配置、连通性测试、Copilot Prompt/动作白名单/审计管理 |

---

## 四、部分实现 / 链路未闭环 (⚠️)

当前无发布阻塞型“部分实现”条目。为避免误解，下面按代码实际状态同时列出闭环结果和仍然存在的边界：

| 原模块 | 闭环结果 |
|--------|----------|
| Agent 控制链路 | session token 已支持过期、吊销、轮换审计和管理员主动吊销；内部 HTTP 拒绝过期/吊销 token；Heartbeat 发现过期/吊销会要求 Agent 终止；`ClaimTask` 未增加独立 token 入参，仍依赖 gRPC/bootstrap 鉴权、节点 Alive 状态和调度匹配 |
| WebSocket 实时看板 | envelope 增加事件 ID，replay 日志已落库；重连支持 `last_event_id/since` 回放并按租户/项目权限过滤；当前没有 replay 日志 TTL 清理 |
| 优先级 / 标签 / 容量调度 | `agent_selector_rules` 已支持等值、多值和反选；预览接口与实际认领共用匹配器，并返回容量与等待批次解释 |
| 任务状态机 | 任务详情返回失败、超时、取消、待认领等原因聚合，前端可展示原因分布 |
| CloudManagement / 云资源编排 | 当前 mock smoke 覆盖凭证测试、策略创建/切换和 OSS 上传失败；另有 Agent 制品缺失、部分失败和成功路径测试；NoStock 降级、真实弹容/回收仍主要依赖现有实现和真实云 smoke，不宣称已完整自动化覆盖 |
| ClientBuild 页面 | 支持多组件构建、多产物下载、取消、重试和完整日志；GitHub Actions 已配置 release artifact 上传，但 artifact 是否产出以实际 Actions 运行结果为准 |
| 遥测日志黑匣子 | 支持筛选、导出、保留策略、告警规则、告警事件和按天 NDJSON 归档；归档目前使用本地对象存储根目录 |
| Dashboard 数据增强 | Dashboard、任务列表、节点列表、AgentLogs、ClientBuild 均接入 WebSocket 重连后的 REST backfill |
| 角色与租户治理 | 自定义角色 permissions 已作为运行时授权依据，但只能在 base_role 已允许的范围内收窄权限，不能越权提升；项目成员支持 viewer/operator/owner；租户任务配额覆盖任务创建和 Agent 认领 |
| 工程质量门禁 | GitHub Actions、顶层 Makefile、Go/Vitest/前端 smoke/Cloud mock smoke/发布制品上传已接入 |

Clean Architecture 迁移不再作为用户功能链路验收项，降级到长期架构演进；当前 `/api/v1` 主链路保持兼容，不为清状态强行暴露 `/api/v2`。

---

## 五、发布前保留缺口 (❌)

> 已经进入主链路或只属于长期优化的事项不再放入“未实现”列表。以下只保留发布前需要明确处理或在 Release Notes 中声明边界的项目。

| 编号 | 类别 | 发布前状态 | 发布口径 |
|------|------|------------|----------|
| REL-01 | 发布制品流水线 | 本地 `make ci`、GitHub Actions、BuildJob 队列和 `/release/*` 下载已可用；`deploy/build-bundle.sh` 默认版本已固定为 `v0.1.0` 并校验发行包必需文件；CI workflow 已配置上传 v0.1.0 bundle 与组件制品 | 发布前需要确认 Actions 实际产出 artifact；发布说明中标注未签名，后续补齐签名 |
| REL-02 | 部署配置与密钥基线 | JWT、Agent session、RBAC、租户配额、云凭证加密已接入；已新增 `deploy/production.env.example` 和默认密码/开发密钥禁用说明 | 发布包必须附最小生产配置模板，明确 `JWT_SECRET`、数据库、RabbitMQ、Agent PSK、AI Key、云 AK/SK 的配置要求 |
| REL-03 | 云资源与 OSS 发布验证 | Cloud Provider mock、OSSStore、本地对象存储、Agent 制品上传链路已有测试；真实云账号端到端弹容、回收、OSS fallback 仍需发布前 smoke | 发布前用测试云账号跑一次一键配置、制品上传、弹容、回收；若未跑真实云 smoke，需在发布说明中标注为 beta 能力 |
| REL-04 | 文档与运维入口 | README 已指向生产部署指南和 `docs/release-checklist.md`；仍需发布说明、升级/回滚和常见故障 | 发布前 README 指向部署文档、运维文档和风险声明；避免把内部路线图当成用户使用说明 |

### 已从缺口列表移除

| 原编号 | 原类别 | 当前状态 |
|--------|--------|----------|
| GAP-02 | 调度解释与任务状态可观测 | 已有后端预览接口、目标类型分组、容量和不可匹配原因展示，后续表达式/反选属于增强 |
| GAP-03 | Dashboard 真实数据消费 | 已接入真实趋势、严重度、任务结果、高危漏洞统计和重连刷新 |
| GAP-04 | Agent session 生命周期 | 已支持 token 轮换、过期、主动吊销、离线清理和 Alive 校验；gRPC `ClaimTask` 未增加逐 RPC session token |
| GAP-05 | 日志治理 | 已支持筛选、导出、聚合、保留天数、清理、告警规则、告警事件和本地 NDJSON 归档；OSS 归档和告警通知属于后续增强 |
| GAP-07 | 自定义角色与权限后台 | 已支持自定义角色 CRUD、权限基线、用户分配和前端管理；permissions 可在 base_role 内收窄接口权限 |
| GAP-08 | 租户治理 | 已支持租户任务配额、创建任务校验和 Agent 认领校验；按项目/用户细分属于后续治理 |
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
- Agent 内部 HTTP：`/agents/:id/commands`、`/arsenals/db*` 使用 `x-agent-id` + `x-agent-token`；token 来源为 gRPC `RegisterResp.token`，支持过期、吊销和轮换审计；gRPC 任务领取没有单独携带该 token
- WebSocket：`GET /api/v1/ws`，支持 `Authorization: Bearer <JWT>` 或 `?token=<JWT>`；重连可带 `last_event_id` 或 `since` 回放已落库事件
- gRPC 服务：`scan.AgentService`
- 协议定义：`shared/proto/proto/scan/agent.proto`

### HTTP REST

| 模块 | 代表接口 | 当前实现 |
|------|----------|----------|
| 认证与会话 | `POST /auth/login` | 数据库用户优先，兼容开发密码，成功后签发 JWT |
| 任务与队列 | `GET/POST/DELETE /tasks`、`POST /tasks/preview-selector`、`POST /tasks/:id/cancel`、`POST /tasks/:id/append`、`GET /queue/depth` | RootTask / SubTask 创建、调度选择器预览、取消、追加、队列深度查询；创建任务支持 `agent_selector` 与 `agent_selector_rules` |
| 项目与成员 | `/projects*`、`GET/PUT /projects/:id/members` | 项目 CRUD、viewer/operator/owner 成员维护、任务与结果访问校验；旧 `user_ids` 请求兼容为 operator |
| 统计、结果与画像 | `/stats*`、`/vulns`、`/assets`、`/fingerprints`、`/profiles`、`/reports/export/vulns` | 统计聚合、结果查询、画像聚合、漏洞 CSV 导出 |
| 节点与 Agent 指令 | `GET /nodes`、`POST /nodes/:id/revoke-token`、`GET /agents/:id/commands`、`GET /agents/:id/logs` | 节点列表、Agent session 主动吊销、Agent session 绑定命令轮询、Agent 日志筛选查询 |
| Arsenal 与规则 | `/arsenals/:type`、`/arsenals/manifest`、`/arsenals/db*`、审批/回滚/删除接口 | 原始规则 CRUD、审批、回滚、Manifest、`rule_version`、Agent SQLite DB 同步 |
| EXP 验证与执行 | `/exploits*`、`/exploits/:id/risk-waiver`、`/exploits/batch/*`、`/exploits/audits`、`/exploit-runs*`、`/exploit-artifacts/*` | EXP 规则列表、单条/批量审核与废弃、风险豁免、审计查询、删除、dry-run、Agent 调试、正式执行、凭据引用记录、取消、cleanup、制品查询 |
| 字典 | `/dictionaries/workflow`、`/dictionaries/fingerprint` | Workflow / Fingerprint 结构化 CRUD，并回写 Arsenal |
| 用户、角色、租户与系统配置 | `/users`、`/roles`、`/tenants/:id/quotas`、`/mcp/keys`、`/agent-logs/alert-rules`、`/agent-logs/alerts`、`/agent-logs/archive`、`/ai/config`、`/ai/models`、`/ai/test` | 用户管理、自定义角色 CRUD、权限矩阵返回、租户任务配额管理、MCP Key、Agent 日志告警/归档、AI 配置与模型连通性测试 |
| AI Copilot / POC 元数据 | `GET /poc-rules`、`POST /ai/chat`、`POST /ai/actions/confirm`、`GET /ai/copilot/prompts`、`GET /ai/tool-invocations`、`POST /ai/arsenal/analyze`、`POST /ai/arsenal/analyze/stream` | POC 元数据检索、全局 Copilot SSE、草稿动作确认、Prompt/动作白名单展示、工具审计、POC AI 审查同步/流式入口 |
| 云资源编排 | `/cloud/accounts*`、`/cloud/policies*`、`/cloud/instances*`、`/cloud/dashboard` | 云凭证、策略、实例生命周期、OSS、一键配置、仪表盘 |
| 构建 | `GET /build/artifacts`、`GET /build/jobs*`、`GET /build/jobs/:id/logs`、`POST /build/jobs/:id/cancel`、`POST /build/jobs/:id/retry`、`POST /build/client`、`GET /release/*` | 产物列表、BuildJob 状态/完整日志、取消/重试、多组件后台执行 `build.sh`、多产物下载与静态下载可用 |

### 本轮验收命令

以下命令用于验证本文档描述的基础闭环。

| 命令 | 覆盖范围 |
|------|----------|
| `make test` | 根模块 Go test、`server` 子模块 Go test、server-ui Vitest |
| `make lint` | server-ui ESLint |
| `make ci` | lint + test + coverage + frontend-smoke + cloud-smoke + server-ui build |
| `npm --prefix server-ui run build` | 前端生产构建 |

### WebSocket

| 路径 | 当前实现 |
|------|----------|
| `GET /ws` | 支持 Header / query token 建连并加入租户广播 Hub，事件 envelope 包含 `id/type/event/version/project_id/occurred_at/data`；支持 `last_event_id/since` replay；当前没有 replay 日志保留期清理 |

### gRPC

| RPC | 当前实现 |
|-----|----------|
| `Register` | 节点注册，写入/更新 `nodes`，记录容量、标签、OS/Arch、租户并返回节点会话 token；重注册会轮换 token；Agent 使用该 token 调用内部 HTTP |
| `Heartbeat` | 更新节点存活时间、运行任务数、运行任务列表与规则版本，并判断是否需要同步规则；发现 token 过期/吊销时返回终止信号 |
| `Subscribe` | Agent 长连接等待任务通知和控制信号，并接收 `capacity_update` 更新空闲槽位 |
| `ClaimTask` | Agent 主动认领任务，支持 RabbitMQ 原子领取、标签匹配、容量回写和终态消息丢弃；不单独校验内部 HTTP session token |
| `FetchTask` | 兼容旧 Agent 的轮询接口，内部委托领取逻辑 |
| `StreamResult` | 接收 Agent 流式结果并异步写入结果缓冲池 |
| `TaskComplete` | 更新子任务状态、ACK 队列、递减节点运行数，并刷新 RootTask 聚合状态 |
| `EmergencyDump` | Spot 或紧急中断场景的兜底上报入口 |
| `StreamLogs` | 接收 Agent gologger TeeWriter 日志流并写入 `agent_logs` 表 |

### 工程化与质量门禁

| 项 | 当前现状 | 缺口 |
|----|----------|------|
| 后端测试 | `server` / `scanner` 内有 Go 单测，顶层 `make test` 已聚合 Go + 前端测试 | 缺少覆盖率阈值和更完整的本地 smoke 数据集 |
| 前端测试 | `server-ui` 已接入 Vitest + Testing Library，覆盖 API service、Login、TaskManagement 基础场景和轻量 smoke | 缺少 UI 回归截图 |
| CI/CD | 已新增 GitHub Actions，PR/主分支运行根模块 Go test、`server` 子模块 Go test、前端 lint/test/smoke/build、Cloud mock smoke；另配置 release artifact 上传 job | 缺少制品签名；artifact 需以实际 Actions 运行结果验收 |

### 维护约定

- 新增或删除 `/api/v1` 路由时，同步更新本节。
- 如果启用 `/api/v2`，单独增加版本化接口小节，不与当前主链路混写。
- 对只返回 `accepted`、mock 或 scaffold 的接口，必须明确标注是否真正执行后端动作。
