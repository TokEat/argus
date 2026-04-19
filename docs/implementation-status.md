# Argus 项目实现状态总览

> 本文档基于当前仓库代码实际状态整理。
>
> 标注说明：`✅` = 已实现并接入主链路 | `⚠️` = 代码已存在但链路未闭环 / 仅部分可用 | `❌` = 尚未实现
>
> 接口清单另见：`docs/interface-implementations.md`

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
| 调度队列 | Redis Streams 多优先级队列 + 内存 fallback | `server/internal/scheduler/queue.go` |
| 队列恢复 | Dead-Letter 回收、旧队列迁移、死亡节点任务抢救 | `server/internal/scheduler/queue.go` `server/cmd/dddd-server/main.go` |
| 超时与重试 | 基于 `timeout_sec` 的超时扫描与自动重试守护协程 | `server/internal/api/router.go` |
| gRPC 通信 | `Register` / `Heartbeat` / `FetchTask` / `StreamResult` / `TaskComplete` / `EmergencyDump` / `StreamLogs` | `server/internal/grpc/server.go` |
| 数据模型 | PostgreSQL GORM AutoMigrate 全模型 | `server/internal/db/db.go` |
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

### 数据面 (Agent)

| 模块 | 功能 | 文件 |
|------|------|------|
| Worker 生命周期 | 注册、心跳、拉取任务、执行任务、完成回报 | `scanner/internal/agent/worker.go` |
| 流式结果回传 | `OutputHook -> gRPC StreamResult` | `scanner/internal/agent/worker.go` |
| 任务取消中断 | `context.Cancel` 注入扫描上下文 | `scanner/internal/agent/worker.go` |
| 并发框架 | Worker Pool 与引擎并发上限协同控制 | `scanner/internal/agent/worker.go` |
| 增量规则同步框架 | 本地 Manifest / Hash 比对、差异下载、全量降级同步 | `scanner/internal/agent/worker.go` |

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
| POC / Workflow / Dir 配置页 | 可视化 CRUD 可用 |
| UserManagement | 可用 |
| McpConfig | 可用 |

---

## 三、部分实现 / 链路未闭环 (⚠️)

| 模块 | 当前现状 | 主要缺口 |
|------|----------|----------|
| Agent 控制链路 | `commandLoop`、规则同步、Manifest 增量下载代码都已写 | Agent 侧用匿名 `http.Get` 请求受 JWT 保护的 API；`Register` 返回的 token 仅为 `dummy_token_*`，且未被 Agent 使用，导致取消指令和规则热同步主链路未真正打通 |
| WebSocket 实时看板 | 服务端广播 Hub 已可工作 | 前端用 `?token=` 建连，后端只认 `Authorization: Bearer`，浏览器实时订阅链路未闭环 |
| 优先级 / 标签 / 容量调度 | 多优先级队列、节点标签匹配、`capacity` 字段与负载展示均已存在 | 任务创建接口未暴露 `agent_selector`；Agent 无法向服务端上报容量，Server 注册时容量固定为 `1` |
| 任务状态机 | `DONE` 场景可聚合 RootTask，`timeout_sec` / 重试已落地 | `FAILED` / `CANCELLED` / `TIMEOUT` 对 RootTask 的最终收敛仍不完整 |
| 云资源编排 | `CloudProvider`、Docker Provider、阿里云 ECS Provider、`ResourceManager` 已实现 | 未接入 `main.go` 和真实调度链路；现有云实例 API 仍是 mock / 标记离线 |
| CloudManagement 页面 | 实例列表与删除动作已能打到后端 | 凭证列表是前端占位数据；`/cloud/policy` 后端不存在；Cloud-Init 脚本使用了 Agent 当前并不支持的 `--token` 参数 |
| ClientBuild 页面 | 可列出 `release/` 目录产物 | 构建触发接口仅返回 `accepted`；`/release/*` 下载路径未真正挂成静态文件服务 |
| 遥测日志黑匣子 | gRPC `StreamLogs` 服务端与查询接口已实现 | Agent 端没有日志上报发送器，前端也没有日志页面入口 |
| Spot 回收处理 | `StartSpotTerminationListener` 已实现 | Agent 启动链路未调用该监听器 |
| Dashboard 数据增强 | 趋势、严重度、任务结果统计、高危漏洞接口已实现 | Dashboard 图表仍有部分前端静态推算，未完全消费真实统计接口 |
| AI 规则审查 | `/arsenals/ai/analyze` 已可返回建议 | 当前仅关键词启发式 mock，未接真实 LLM |
| 角色权限系统 | RBAC 中间件已启用，用户角色字段可生效 | 角色管理页是静态说明页，没有角色 CRUD / 权限矩阵管理接口 |
| Clean Architecture 迁移 | `core/usecase`、`adapters`、`bootstrap` 目录结构已搭好 | `/api/v2`、新 HTTP/gRPC adapter、仓储与 usecase 仍是 scaffold / `ErrNotImplemented` |

---

## 四、未实现功能清单 (❌)

| 类别 | 未实现功能 |
|------|-----------|
| **Clean Architecture 落地** | `core/usecase` 真正承接业务逻辑，替换当前 `router.go` 直连数据库模式 |
| **真实云调度** | 自动伸缩策略持久化、实例创建/等待就绪/回收的真实运行链路 |
| **容器化隔离执行** | 每任务隔离 Runner、网络代理、CPU / 内存限制 |
| **角色管理后台** | 角色 CRUD、权限矩阵配置、可视化授权管理 |
| **真实客户端构建链路** | API 触发本地或 CI 构建、构建状态追踪、构建产物分发 |
| **对象存储层** | 报告文件、规则包、二进制产物的独立文件 / 对象存储 |
| **租户治理** | 任务配额、并发额度、租户级资源限制 |
| **EXP / GoPoc 元数据中心** | GoPoc / EXP 的动态索引、版本化、审核与管理 |
| **真实 LLM 集成** | OpenAI / DeepSeek 等审查与建议能力接入 |

---

## 五、下一步建议优先级

| 优先级 | 功能 | 说明 |
|--------|------|------|
| P0 | 打通 Agent 鉴权链路 | 统一 gRPC 注册 token、Agent REST 调用鉴权、WebSocket 鉴权 |
| P0 | 修复 Cloud / Build 假接口 | 补齐 `/cloud/policy`、真实构建触发、`/release/*` 下载服务、移除或实现 `--token` |
| P1 | 完善任务状态收敛 | 补齐 `FAILED / CANCELLED / TIMEOUT` 的 RootTask 聚合与终态计算 |
| P1 | 完善节点容量与标签路由 | 让 Agent 上报容量，任务创建支持 `agent_selector` |
| P1 | 接通遥测日志链路 | Agent 发送 `StreamLogs`，前端补日志查看页 |
| P2 | 推进 Clean Architecture 迁移 | 逐步把 `router.go` 中的直接业务逻辑迁入 usecase / adapter |
| P2 | 接入真实云资源编排 | 把 Docker / ECS Provider 挂到调度链路，而不是停留在独立实现 |
| P3 | 接入真实 LLM | 用真实模型替换当前规则审查 mock |
