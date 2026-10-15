# Argus 项目实现状态总览

> 本文档基于当前仓库代码实际状态整理。
>
> 标注说明：`✅` = 已实现并接入主链路 | `⚠️` = 代码已存在但链路未闭环 / 仅部分可用 | `❌` = 尚未实现
>
> 当前接口清单合并在本文末尾，避免实现状态与接口状态分散维护。
>
> 最后同步：2026-08-25，以当前工作树代码为准；只把已经接入 `/api/v1`、Agent 运行链路或 CI/Makefile 的能力标为已实现。
>
> 领域细节以专项文档为权威：[扫描策略 V1](scan-policy-v1.md)、[Yaksha EXP](yaksha-exp.md)、[Server 资产发现](asset-discovery.md)、[ScanPlan 与覆盖契约](scanplan-contract.md)、[云资源动态调度](cloud-resource-scheduling.md)。

---

## 一、总体完成度

| 阶段 | 状态 | 完成度 |
|------|------|--------|
| Phase 1：数据异构化与结果防洪 | ✅ 已完成 | ~95% |
| Phase 2：分布式调度与基础控制面 | ✅ Agent session 鉴权、容量上报、显式调度选择器已接入 | ~92% |
| Phase 3：运营管控、系统化与 AI 化 | ⚠️ 构建/日志/质量门禁已补齐基础闭环，治理能力仍需深化 | ~72% |

---

## 二、已实现功能清单 (✅)

### 共享契约

| 模块 | 功能 | 文件 |
|------|------|------|
| ScanPlan v1 | 统一 `external-map`、`internal-fast`、`internal-server`、`risk-validation` 场景及 Stage、Plan、WorkKey、Observation、Coverage；固定 WorkKey 哈希维度并禁止普通发现 Plan 混入风险验证 | `shared/proto/go/scanplan/contract.go` `scanner/internal/engine/scanplan_contract.go` |

### 控制面 (Server)

| 模块 | 功能 | 文件 |
|------|------|------|
| API Gateway | Gin REST API 主路由 | `server/internal/api/router.go` |
| Server 资产发现（Server-only） | 已建立 FOFA/Hunter/Quake 三个 Server Provider 核心和项目级查询 API：operator 及以上且拥有项目访问权时，Server 从当前租户已批准配置读取对应凭据，执行有界查询并原子保存审计、不可变快照和规范资产。viewer 可在对象授权范围内读取历史、导出和测绘 Notebook；operator 可维护筛选、标签、备注、软移除/恢复，并将 1–100 个条目通过预览和 Idempotency-Key 显式分发到同项目任务。Scanner 不执行测绘查询、不读本地 Provider 凭据；Agent 不同步/读写 Provider 凭据；Server 对新建、追加、派发和领取中的测绘执行配置失败关闭 | `server/internal/assetdiscovery/` `server/internal/api/asset_discovery_*` `server/internal/api/asset_discovery_notebook_operations.go` `server/internal/db/asset_discovery_notebook.go` `scanner/internal/engine/` `scanner/internal/agent/worker.go` `server-ui/src/pages/AssetDiscovery.tsx` |
| 身份与权限 | JWT 登录校验、RBAC 中间件、EXP 授权闸门、项目成员访问控制 | `server/internal/api/router.go` `server/internal/api/middleware_rbac.go` `server/internal/api/project_access.go` |
| 任务管理 | RootTask / TaskBatch / Attempt 创建、拆分、查询、暂停/恢复/停止/重试、结果保留归档、增加批次、配置版本与项目访问校验；任务级控制只修改各批次最新 Attempt，暂停期间已领取执行允许收敛且失败后保持暂停，恢复按需追加 Attempt，立即停止可从暂停态执行并向 Agent 下发取消，任务重试仅重跑失败/超时/停止批次；增加批次会规范化并幂等去重、扩展 Project SeedTargets/Scope、写审计；TaskBatch 使用独立 `control_state` 支持批次控制，`sub_tasks` 兼容表追加保存实际 Attempt；任务详情区分可管理批次与完整执行历史；普通任务 POC 配置在 API、Agent 领取和 Agent 执行三层失败关闭；风险验证支持 Workflow 匹配和指定已审核 POC，预览绑定配置/规则/内容哈希，确认后追加只执行精确 POC 的 `risk_validation` Batch，高风险二次确认、关闭自动重试并写审计 | `server/internal/api/handler_tasks.go` `server/internal/api/task_input.go` `server/internal/api/task_lifecycle.go` `server/internal/api/task_batch_lifecycle.go` `server/internal/api/task_scope.go` `server/internal/api/task_config.go` `server/internal/api/risk_validation_preview.go` `server/internal/api/risk_validation_execute.go` `server/internal/db/task_batch.go` `server/internal/db/task_attempt.go` |
| 创建任务幂等（G39A） | `POST /tasks` 可选 `Idempotency-Key`，无 header 的旧客户端保持原有非幂等行为，UI 为一次新建意图复用稳定 Key；同 tenant/project/operator/`create_task_v1`/Key 的同规范请求重放首次结果，异请求返回 409。原始 Key 不持久化；幂等账本与 RootTask、配置修订、TaskBatch、首个 Attempt、Project SeedTargets/Scope 扩展和创建审计同事务提交，仅首次提交后派发，重放不入队 | `server/internal/api/task_create_idempotency.go` `server/internal/db/task_creation_idempotency.go` `server-ui/src/pages/TaskManagement.tsx` |
| 增加批次幂等（G39B） | `POST /tasks/:id/append` 可选 `Idempotency-Key`，无 header 的旧客户端继续按 Task 内目标去重；UI 在一次追加意图内复用稳定 Key。相同 tenant/project/task/operator/`append_targets_v1`/Key 的同规范请求重放首次 outcome、业务计数与 Batch/Attempt，异请求返回 409。原始 Key/目标/配置正文不进入账本；账本与首次业务变更及 `batch_append` 审计同事务提交，仅首次新增在提交后派发。`dispatched`/`dispatch_pending` 是首次 Attempt 的当前投递状态投影，允许随恢复或暂停变化，但重放不会再次入队 | `server/internal/api/task_append_idempotency.go` `server/internal/db/task_append_idempotency.go` `server-ui/src/pages/TaskManagement.tsx` |
| 任务级重试幂等（G39C） | `POST /tasks/:id/retry` 可选 `Idempotency-Key`，无 header 的旧客户端保留原重试状态机；UI 在一次“重试失败批次”意图内复用稳定 Key。相同 tenant/project/task/operator/`retry_task_v1`/Key 的请求重放首次新增 Attempt、状态和跳过计数，异请求返回 409。原始 Key、目标和配置正文不进入账本；账本与 Attempt、RootTask 状态和单条 `retry` 审计同事务提交，仅首次提交后主动派发。`dispatch_pending` 投影首次 Attempt 的当前投递状态，重放不再次入队 | `server/internal/api/task_retry_idempotency.go` `server/internal/db/task_retry_idempotency.go` `server-ui/src/pages/TaskManagement.tsx` |
| 单批次重试幂等（G39D） | `POST /tasks/:id/batches/:batch_id/retry` 可选 `Idempotency-Key`，无 header 的旧客户端保留原批次重试状态机；UI 按 task+batch 隔离一次确认意图。相同 tenant/project/task/batch/operator/`retry_task_batch_v1`/Key 的请求重放首次 Attempt、编号、配置/规则版本和状态，异请求返回 409。账本、Attempt、Task/Batch 状态和单条 `batch_retry` 审计同事务提交，仅首次提交后主动派发；重放只投影该 Attempt 的当前投递状态 | `server/internal/api/task_batch_retry_idempotency.go` `server/internal/db/task_batch_retry_idempotency.go` `server-ui/src/pages/TaskManagement.tsx` |
| 风险验证执行幂等（G39E） | `POST /tasks/:id/risk-validation` 可选 `Idempotency-Key`，无 header 的旧客户端保持原显式确认流程；UI 将一次 preview、指定 POC/候选选择和双重确认绑定到稳定 Key。相同 tenant/project/task/operator/`execute_risk_validation_v1`/Key 的同请求重放首次 risk-validation Batch/Attempt 和冻结计数，异请求返回 409。账本、Batch、Attempt、RootTask 状态和单条 `risk_validation_execute` 审计同事务提交，仅首次提交后派发；新 Key 的陈旧 preview/config/rule/POC 内容仍失败关闭，普通扫描 POC-off 与 EXP 隔离不变 | `server/internal/api/risk_validation_execute.go` `server/internal/db/risk_validation_execution_idempotency.go` `server-ui/src/pages/TaskManagement.tsx` |
| 调度队列 | RabbitMQ 多优先级队列 + 内存 fallback，支持队列深度查询与通知广播；风险验证只允许规则版本一致且版本不低于 v2.4.0 的 Agent 领取；普通任务领取时原子占用同项目 WorkClaim，重复执行挂接等待且不占 Agent 容量 | `server/internal/scheduler/queue.go` `server/internal/grpc/server.go` `server/internal/db/scan_work_claim.go` |
| 队列恢复 | Dead-Letter 回收、旧队列迁移、死亡节点任务抢救；终态 WorkClaim 来源的等待者自动重新规划，队列发布失败保留 Dispatching 供周期恢复 | `server/internal/scheduler/queue.go` `server/internal/api/task_recovery.go` `server/cmd/argus-server/main.go` |
| 超时与重试 | 基于 `timeout_sec` 的超时扫描与自动重试守护协程 | `server/internal/api/router.go` |
| gRPC 通信 | `Register` / `Heartbeat` / `Subscribe` / `ClaimTask` / `StreamResult` / `TaskComplete` / `EmergencyDump` / `StreamLogs` | `server/internal/grpc/server.go` |
| Agent 覆盖事件 | v2.5.0 将 legacy Phase 显式映射为 ScanPlan Stage，按分配目标上报 success/negative/failed/skipped、起止时间和顺序无关内容哈希；单目标成功/阴性事件可附带不含响应正文的有界派生检查点，多目标不做错误归属；Server 只接收与当前 Agent/Attempt/目标一致的事件，旧 Agent 无事件时保持 unknown | `scanner/internal/agent/coverage_reporter.go` `server/internal/grpc/server.go` |
| 覆盖归并 | Server 用 Project Scope、配置修订、Attempt 规则版本、Agent 标签和目标类型重算 WorkKey，幂等追加 Observation 并维护当前 Coverage；公网使用共享 `public`，私网按 `private:<network_zone>` 隔离，无标签私网回退 `agent:<agent_id>`；失败/跳过、版本漂移和未知风险维度均不可复用；完整覆盖按阶段设置 TTL，上游内容变化只失效较旧依赖覆盖 | `server/internal/db/scan_observation_merge.go` `server/internal/db/scan_network_zone.go` `server/internal/db/scan_coverage_policy.go` |
| 已完成覆盖复用 | Agent 领取前按完整目标匹配同租户、项目、网络区、Scope/Config/规则版本的有效 Coverage；全量复用不分配 Agent，部分复用只下发剩余目标并将 reused links 与 Agent 租约同事务提交；公网可跨 Agent 复用，同标签私网可跨 Agent 复用，不同标签或无标签私网保持隔离；手动重试、风险验证和未知旧配置绕过 | `server/internal/db/scan_reuse.go` `server/internal/grpc/server.go` |
| 检查点恢复执行 | 单目标按 `argus.resume-plan/v1` 计算历史复用前缀与最小执行后缀；端口检查点恢复协议，协议检查点恢复 HTTP，HTTP 后续缺失因无正文而回退 HTTP；Server 在最终租约内重建复核并仅向 v2.6.0+、规则一致的 Agent 下发，Agent 独立校验后只执行并上报后缀；旧 Agent、force、过期/漂移/损坏证据保持完整扫描或失败关闭 | `shared/proto/go/scanplan/contract.go` `server/internal/db/scan_resume_plan.go` `scanner/internal/engine/resume_plan.go` |
| 执行中工作合并 | Scanner 完整目标流水线以 fingerprint WorkKey 作为互斥键；唯一 Claim 与 Agent 租约同事务提交，后续 Attempt 记录 in-flight 来源并等待；来源成功后重新走历史复用，失败/超时/停止后自动重新竞争，周期守护收敛非 RPC 终态 | `server/internal/db/scan_work_claim.go` `server/internal/grpc/server.go` `server/internal/api/task_recovery.go` |
| 任务覆盖解释 | 任务详情以 `argus.task-coverage-explanation/v1` 汇总实际执行、历史复用、当前执行中关联、失效/过期和节省量；最近明细可追溯同项目来源 Task/Batch/Attempt，tenant/project 作用域重新校验且不暴露内部 WorkKey/哈希/租约 | `server/internal/api/task_coverage_explanation.go` `server-ui/src/pages/TaskManagement.tsx` |
| 扫描计时证据（G31） | 已实现 target-free `argus.timing/v1`：Server 以活动 Attempt、分配 Agent、会话及 tenant/project/task 归属验证 `StreamResult` 中最多 16 KiB 的严格 JSON timing payload，并将同 ID 同内容幂等、不同内容冲突的证据追加到 `scan_timing_events`。任务详情在对象授权后按 Attempt 返回有界 timing projection（最多 5000 条）、结果与 unavailable；不返回 target、WorkKey、哈希、令牌或日志 | `shared/proto/go/scanplan/timing.go` `server/internal/grpc/timing.go` `server/internal/db/scan_timing_event.go` `server/internal/api/handler_tasks.go` `server-ui/src/components/TaskTimingPanel.tsx` |
| Agent 内部 HTTP API | Agent 命令轮询、Arsenal DB Hash / SQLite DB 同步端点，使用 `x-agent-id` + `x-agent-token` session 鉴权；SQLite DB 作为规则传输包，包含指纹、Workflow、Dir、POC YAML 和 POC helper assets；`x-agent-psk` 仅保留给 gRPC/bootstrap | `server/internal/api/router.go` `server/internal/api/arsenal_export.go` |
| 数据模型 | PostgreSQL migration runner + schema verify；追加式 `scan_observations`、当前 `scan_coverages`、唯一 `scan_work_claims` 与可解释 `task_coverage_links` 全部按 tenant/project 隔离，Coverage 复用和 WorkClaim 并发合并已接入调度；测绘成功审计、不可变查询快照、规范资产项和项目级去重笔记本来源已接入原子写入；分发 intent/items 与 materialization 结果表（见 `deploy/db/init/001_init.sql` 与 [数据库设计总览](db_schema.md)）均按 tenant/project 复合约束且不保存原始幂等键或 Provider 正文 | `server/internal/db` |
| 结果入库 | Asset / FingerprintHit / Vulnerability 三层结构化存储 | `server/internal/db/db.go` |
| 防洪落库 | BatchWriter 异步缓冲写入 | `server/internal/db/db.go` |
| Arsenal 管理 | POC / Finger / Workflow / Dir / EXP 的 CRUD、审批、Manifest、回滚、Agent SQLite DB 导出；POC helper assets 随规则包同步，不进入 POC 规则治理列表 | `server/internal/api/router.go` `server/internal/api/handler_exploits.go` `server/internal/api/arsenal_export.go` |
| Dictionary API | Workflow / Fingerprint 结构化 CRUD | `server/internal/api/handler_dictionary.go` |
| 规则初始化 | 启动时从磁盘导入规则与结构化目录 | `server/internal/db/seed.go` |
| 结果查询 | 漏洞、资产、指纹、融合画像接口 | `server/internal/api/router.go` |
| 统计接口 | 首页五维统计 + 趋势 / 严重度 / 任务结果统计 / 最近高危漏洞 | `server/internal/api/router.go` `server/internal/db/stats.go` |
| WebSocket Hub | 结果批量写入与 EXP 执行状态的服务端广播 | `server/internal/api/ws.go` |
| 报表导出 | 漏洞 / 资产 / 指纹 CSV 导出 | `server/internal/api/router.go` `server/internal/api/handler_results.go` |
| 系统管理 | 用户 CRUD、MCP 接入治理、构建产物列表、Agent 日志查询、Agent 日志告警与归档 | `server/internal/api/router.go` |
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
| 规则同步 | 通过 `x-agent-id` + `x-agent-token` 拉取 Arsenal DB Hash，变更后下载完整 SQLite DB 到 `data/arsenal.db`，再物化为 CLI 形态 `config/finger.yaml`、`config/workflow.yaml`、`config/dir.yaml`、`config/pocs/`、`config/dict/` 和 `config/subdomains.txt`；扫描任务读取本地 `config/`，不在扫描期从 DB 导出 POC | `scanner/internal/agent/worker.go` `scanner/internal/arsenal/materialize.go` |
| 规则同步边界 | DB 同步包只托管 Finger / Workflow / Dir / POC YAML / POC helper assets、GoPoc 字典和子域名字典；`socket.yaml` 当前没有接入扫描加载链路，不纳入同步。Provider 凭据只存在于 Server 租户配置，不进入 Scanner 发行包、Arsenal 或 Agent 通知/命令协议 | `scanner/common/config` `scanner/gopocs` `scanner/internal/scanner/subdomain` |
| 仓库规则基线回写 | Web/DB 治理结果需要进入源码规则基线时，先下载或生成 `arsenal_seed.db`，再用 `tools/arsenal-sync` 将 Approved 规则导出/对比/覆盖到 `scanner/common/config`，通过 Git diff 和 PR 审查后合并；Server 不自动写源码目录 | `tools/arsenal-sync` `scanner/common/config` |
| POC 调试拦截 | POC 拦截 Nuclei/GoPoc 调试请求响应；Agent 不再解析或执行 Python EXP | `scanner/internal/agent/debug.go` |
| Agent 原生 EXP 出口 | Agent 通过独立多路复用 EgressTunnel 提供原始 TCP 出口，Yaksha 继续负责 TLS、HTTP、目标复检与完整 Trace | `scanner/internal/agent/egress.go` `server/internal/egress/` `yaksha/internal/egress/relay.go` |
| 遥测日志 | gologger 全局 TeeWriter 通过 gRPC `StreamLogs` 持续上报 Agent 日志 | `scanner/internal/agent/worker.go` |
| Spot 回收监听 | 云厂商竞价实例中断检测、紧急数据回传 | `scanner/internal/agent/signal.go` |

### 单机 CLI

| 模块 | 功能 | 文件 |
|------|------|------|
| CLI 运行目录 | 普通扫描结果统一写入当前工作目录的 `datas/<目标_时间>/`，仅保留 `result.txt`、一份权威 HTML 报告和小型 `summary.txt`；不创建 targets/findings/coverage/timing TSV，扫描记忆也不再依赖或创建 `argus-data/state`、`argus-data/runs`。`ARGUS_HOME/argus-data` 仅保留为显式离线规则包管理兼容目录 | `scanner/cmd/cli/main.go` `scanner/internal/localstate/run.go` `scanner/internal/config/cli.go` |
| datas 历史跳过 | 历史跳过只由显式 `-ss`/`--skip-seen` 开启：从 `datas/` 已完成运行的 `result.txt` 提取历史资产并跳过已出现 IP（`-nopoc -nogpoc` 不会隐式开启）。单 IP 命中即跳过，CIDR/IP 范围剔除历史已有资产 IP 后仅扫描剩余地址，域名/URL/显式服务保守精确匹配。`-force` 固定完整扫描 | `scanner/internal/localplanner/datas_history.go` `scanner/internal/localplanner/planner.go` `scanner/internal/localstate/run.go` |
| CLI 与 Agent 计时（G31） | CLI 在进程内记录 earliest-observable startup、规则准备、`ScanContext` 初始化和实际 Stage 终态，text 模式只显示简短汇总，不再为普通 datas Run 生成 `timing.tsv`；JSON/非 text stdout 不增加人类日志。Agent 使用现有 `StreamResult` 和 `x-agent-token` 上报版本化有界契约，复用或未开始 Stage 不会伪装为执行。G31 仅建立测量/展示/基线，未实施 G32–G36 性能优化 | `scanner/cmd/cli/main.go` `scanner/internal/localstate/timing.go` `scanner/internal/timing/recorder.go` `scanner/internal/agent/worker.go` `scanner/cmd/perf-baseline/main.go` |
| CLI 品牌 | 发行命令名继续为 `argus`；Banner、版本、帮助统一显示 Argus CLI，`--version` 在规则与扫描初始化前直接返回。Scanner Pipeline 不执行测绘查询，Agent 不同步或读取 Provider 凭据 | `scanner/cmd/cli/early.go` `scanner/internal/engine/` `scanner/internal/agent/worker.go` `server/internal/api/task_dispatch.go` |
| 强制完整扫描 | CLI 可选 `-force` 仅绕过 `datas` 历史跳过；目标、端口和 POC-off 安全默认不变，本次执行继续追加证据。该指令不进入 Server/Agent 配置 | `scanner/common/flag.go` `scanner/internal/config/cli.go` `scanner/internal/localplanner/planner.go` |

### 扫描引擎

| 模块 | 功能 |
|------|------|
| 空间搜索引擎（Server-only） | FOFA / Hunter / Quake 的用户查询入口固定在 Server 项目“资产测绘”页面。Standalone CLI、Scanner 与 Agent 不读取 Provider 凭据或发起 Provider 请求。被动子域仍保留但显式排除三家 Provider 来源 |
| 子域名枚举 | subfinder + 自定义爆破 |
| 存活探测 | 同网段 ARP，其余 ICMP；ARP/ICMP 未应答的再 TCP 探活（80/443/3389/445/22）。`-PU` 再对剩余主机打常关 UDP 口，ICMP port unreachable 视为存活。`-Pn` 跳过，`-nip` 跳过 ICMP 直接 TCP |
| 内网路径 | CLI `-tr <目标>` 是单独命令（IP / 文件 / 上次 result.txt），不进入扫描流水线。自实现 UDP/ICMP TTL 探路（不调用系统 traceroute/tracert），输出 `[Path]` 跳数和 `[Topo]` 网段蓝图 |
| 端口扫描 | TCP / SYN（Masscan + 内置 SYN Linux raw socket），支持 `pacing` 打散规避（per-IP 最小探测间隔 50–5000ms，默认 500ms，TCP 精确间隔 / SYN 全局限速） |
| 协议识别 | gonmap TCP 识别 + 内网 TCP 握手 + 默认同机高价值 UDP 识别；Banner 抓取 |
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
| TaskManagement | 任务创建 / 查询 / 暂停 / 恢复 / 停止 / 归档可用；详情页支持增加批次、更新配置、批次暂停/恢复/停止/重试/归档，以及查看不可变 Attempt 历史 |
| TaskResults | 漏洞 / 资产 / 指纹结果查看可用 |
| ProfilesView | 融合画像查询可用 |
| POC / Finger / Workflow / Dir / EXP 配置页 | 可视化 CRUD 可用，已接入在线调试、AI 辅助增强与 EXP Builder |
| UserManagement | 可用 |
| ProjectManagement | 项目 viewer / operator / owner 成员分配已接入 |
| CloudManagement | 云凭证、策略、实例、OSS 制品上传、权限检查和按地域价格/规格选择已接入真实 API |
| ClientBuild | 构建产物、BuildJob 队列、状态和 `/release/*` 下载入口可用 |
| AgentLogs | Agent 日志筛选、查看与导出可用 |
| RoleManagement | 已接入后端角色列表、内置角色只读展示、自定义角色创建/编辑/删除、权限基线说明和租户任务配额配置 |
| ApiKeysConfig（原 McpConfig，`/api-keys`） | 可用 |
| AI Copilot | 全局 Drawer 交互，支持表格/多行引用/代码块渲染、POC YAML / EXP Yak 源码一键应用、草稿动作确认 |
| AI Config | 大模型渠道、参数配置、连通性测试、Copilot Prompt/动作白名单 |

---

## 三、部分实现 / 链路未闭环 (⚠️)

当前无发布阻塞型“部分实现”条目。为避免误解，下面按代码实际状态同时列出闭环结果和仍然存在的边界：

| 原模块 | 闭环结果 |
|--------|----------|
| Agent 控制链路 | session token 已支持过期、吊销、轮换审计和管理员主动吊销；内部 HTTP 拒绝过期/吊销 token；Heartbeat 发现过期/吊销会要求 Agent 终止；普通任务 `ClaimTask` 不校验 session token，仍依赖 gRPC/bootstrap 鉴权、节点 Alive 状态和调度匹配；弱口令验证类认领与 `EmergencyDump` 会强制校验 session token（及 TLS） |
| WebSocket 实时看板 | envelope 增加事件 ID，replay 日志已落库；重连支持 `last_event_id/since` 回放并按租户/项目权限过滤；当前没有 replay 日志 TTL 清理 |
| 优先级 / 标签 / 容量调度 | `agent_selector_rules` 已支持等值、多值和反选；预览接口与实际认领共用匹配器，并返回容量与等待批次解释 |
| 任务状态机 | 任务详情返回失败、超时、取消、待认领等原因聚合，前端可展示原因分布 |
| CloudManagement / 云资源编排 | 当前 mock smoke 覆盖凭证测试、策略创建/切换和 OSS 上传失败；另有 Agent 制品缺失、部分失败和成功路径测试；NoStock 降级、真实弹容/回收仍主要依赖现有实现和真实云 smoke，不宣称已完整自动化覆盖 |
| ClientBuild 页面 | 支持多组件构建、多产物下载、取消、重试和完整日志；GitHub Actions 已配置 release artifact 上传，但 artifact 是否产出以实际 Actions 运行结果为准 |
| 遥测日志黑匣子 | 支持筛选、导出、保留策略、告警规则、告警事件和按天 NDJSON 归档；归档目前使用本地对象存储根目录 |
| Dashboard 数据增强 | Dashboard、任务列表、节点列表、AgentLogs、ClientBuild 均接入 WebSocket 重连后的 REST backfill |
| 角色与租户治理 | 自定义角色 permissions 已作为运行时授权依据，但只能在 base_role 已允许的范围内收窄权限，不能越权提升；项目成员支持 viewer/operator/owner；租户任务配额覆盖任务创建和 Agent 认领 |
| 工程质量门禁 | GitHub Actions、顶层 Makefile、Go/Vitest/前端 smoke/Cloud mock smoke/发布制品上传已接入 |

当前 `/api/v1` 主链路保持兼容，没有 `/api/v2`。

---

## 四、发布前保留缺口 (❌)

> 已经进入主链路或只属于长期优化的事项不再放入“未实现”列表。以下只保留发布前需要明确处理或在 Release Notes 中声明边界的项目。

| 编号 | 类别 | 发布前状态 | 发布口径 |
|------|------|------------|----------|
| REL-01 | 发布制品流水线 | 本地 `make ci`、GitHub Actions、BuildJob 队列和 `/release/*` 下载已可用；`deploy/build-bundle.sh` 默认版本已固定为 `v0.1.0` 并校验发行包必需文件；CI workflow 已配置上传 v0.1.0 bundle 与组件制品 | 发布前需要确认 Actions 实际产出 artifact；发布说明中标注未签名，后续补齐签名 |
| REL-02 | 部署配置与密钥基线 | JWT、Agent session、RBAC、租户配额、云凭证加密已接入；已新增 `deploy/production.env.example` 和默认密码/开发密钥禁用说明 | 发布包必须附最小生产配置模板，明确 `JWT_SECRET`、数据库、RabbitMQ、Agent PSK、AI Key、云 AK/SK 的配置要求 |
| REL-03 | 云资源与 OSS 发布验证 | Cloud Provider mock、OSSStore、本地对象存储、Agent 制品上传链路已有测试；真实云账号端到端弹容、回收、OSS fallback 仍需发布前 smoke | 发布前用测试云账号跑一次一键配置、制品上传、弹容、回收；若未跑真实云 smoke，需在发布说明中标注为 beta 能力 |
| REL-04 | 文档与运维入口 | README 已指向生产部署指南和 `docs/release-checklist.md`；仍需发布说明、升级/回滚和常见故障 | 发布前 README 指向部署文档、运维文档和风险声明；避免把内部路线图当成用户使用说明 |

## 五、当前接口实现清单

本文只描述从 `server/cmd/argus-server/main.go` 接线进入运行链路的接口。

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
| 认证与会话 | `POST /auth/login` | 仅数据库 bcrypt 校验（开发模式固定密码已删除），成功后签发 JWT |
| 任务与队列 | `GET/POST/DELETE /tasks`、`POST /tasks/preview-selector`、`POST /tasks/:id/risk-validation/preview`、`POST /tasks/:id/risk-validation`、`POST /tasks/:id/pause|resume|stop|cancel|retry|append`、`GET /tasks/:id/config-revisions`、`PUT /tasks/:id/config`、`GET /tasks/:id/batches`、`POST /tasks/:id/batches/:batch_id/pause|resume|stop|retry`、`DELETE /tasks/:id/batches/:batch_id`、`GET /queue/depth` | RootTask / TaskBatch / Attempt 创建、调度选择器预览、任务与批次生命周期控制、幂等增加批次、幂等任务级重试、幂等单批次重试和队列深度查询；风险验证预览是 viewer 可用的只读 POST，可用 Workflow 或指定已审核 POC 生成带版本、内容哈希、预计请求量及二次确认提示的计划；执行是 operator 变更操作，必须提交未过期计划和授权确认，高风险二次确认后才创建不自动重试的精确 POC Batch；任务停止以 `stop` 为规范接口并保留 `cancel` 兼容别名；`append` 在任务行锁内去重并扩展当前 Project Scope/SeedTargets，可选 Key 将首次 Batch/Attempt/计数冻结为可重放结果且重放不再次入队；任务与批次 `retry` 的可选 Key 都只允许首次提交追加并派发 Attempt，HTTP 重放只投影首次 Attempt 当前投递状态；任务与批次 `DELETE` 均为保留结果的终态归档；普通资产批次重试使用当前配置/规则，风险验证批次仅在规则版本不变时复用原确认快照；所有控制接口校验租户与项目归属，变更接口写审计 |
| 项目与成员 | `/projects*`、`GET/PUT /projects/:id/members` | 项目 CRUD、viewer/operator/owner 成员维护、任务与结果访问校验；旧 `user_ids` 请求兼容为 operator |
| Server 资产发现 | Provider 查询与项目历史/导出；`GET /asset-discovery/notebook-items`；项目 Notebook GET/PATCH/remove/restore、快照归档、分发 preview/materialize | operator 及以上在已授权项目内使用当前租户已批准的 Provider 配置执行有界查询，并可从持久化快照归档 1–100 个项目级候选目标；viewer 可读取项目列表或只聚合当前账号实际可访问项目的 Notebook。列表支持目标/标签/状态筛选；operator 可维护标签、备注并软移除/恢复，全部对象级写入与关联 item 的脱敏审计同事务，removed 条目不能进入新分发。分发确认要求 Idempotency-Key 与未过期 plan hash，原子保存 intent/result、扩展 Scope/SeedTargets、创建追加式 TaskBatch/Attempt 并写审计，提交后才派发；凭据、原始幂等键、备注/标签正文和 Provider 原始响应不进入审计或确认响应 |
| 统计、结果与画像 | `/stats*`、`/vulns`、`/assets`、`/fingerprints`、`/profiles`、`/reports/export/{vulns,assets,fingerprints}` | 统计聚合、结果查询、画像聚合、三类 CSV 导出 |
| 节点与 Agent 指令 | `GET /nodes`、`POST /nodes/:id/revoke-token`、`GET /agents/:id/commands`、`GET /agents/:id/logs` | 节点列表、Agent session 主动吊销、Agent session 绑定命令轮询、Agent 日志筛选查询 |
| Arsenal 与规则 | `/arsenals/:type`、`/arsenals/manifest`、`/arsenals/db*`、审批/回滚/删除接口 | 原始规则 CRUD、审批、回滚、Manifest、`rule_version`、Agent SQLite DB 同步 |
| Yaksha EXP Workspace | `/exps*`、`/exp-assets*`、`/exp-runs*`、`/exp-egress-routes*` | 单文件 Yaklang EXP、不可变 Revision、依赖闭包、版本化 Asset、Fixture 验收、inspect/validate/test/debug/run、按哈希发布、活动版本回滚、Agent 原生出口与完整运行审计；生产对象存储为私有 MinIO |
| 字典 | `/dictionaries/workflow`、`/dictionaries/fingerprint` | Workflow / Fingerprint 结构化 CRUD，并回写 Arsenal |
| 用户、角色、租户与系统配置 | `/users`、`/roles`、`/tenants/:id/quotas`、`/mcp/admin/*`、`/agent-logs/alert-rules`、`/agent-logs/alerts`、`/agent-logs/archive`、`/ai/config`、`/ai/models`、`/ai/test` | 用户管理、自定义角色 CRUD、权限矩阵返回、租户任务配额管理、MCP 接入治理 / 会话 / 调用审计 / 治理事件 / 只读工具目录（投影 tools()，含 schema 生成的调用示例）、Agent 日志告警/归档、AI 配置与模型连通性测试 |
| AI Copilot / POC 元数据 | `GET /poc-rules`、`POST /ai/chat`、`POST /ai/actions/confirm`、`GET /ai/copilot/prompts`、`POST /ai/arsenal/analyze`、`POST /ai/arsenal/analyze/stream` | POC 元数据检索、全局 Copilot SSE、草稿动作确认、Prompt/动作白名单展示、POC AI 审查同步/流式入口 |
| 云资源编排 | `/cloud/accounts*`、`/cloud/policies*`、`/cloud/instances*`、`/cloud/dashboard` | 云凭证、策略、实例生命周期、OSS、一键配置、仪表盘 |
| 构建 | `GET /build/artifacts`、`GET /build/jobs*`、`GET /build/jobs/:id/logs`、`POST /build/jobs/:id/cancel`、`POST /build/jobs/:id/retry`、`POST /build/client`、`GET /release/*` | 产物列表、BuildJob 状态/完整日志、取消/重试、多组件后台执行 `build.sh`、多产物下载与静态下载可用 |

### 验收命令

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
| `ClaimTask` | Agent 主动认领任务，支持 RabbitMQ 原子领取、标签匹配、容量回写和终态消息丢弃；普通认领不单独校验内部 HTTP session token，弱口令验证类认领强制校验 session token 与 TLS |
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
- 对只返回 `accepted` 或 mock 的接口，必须明确标注是否真正执行后端动作。
