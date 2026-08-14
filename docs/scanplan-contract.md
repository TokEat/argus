# ScanPlan 与覆盖契约

Argus 的 Server、Agent 与离线 CLI 共享 `github.com/P0lar1ght/argus/shared/proto/go/scanplan`。当前契约版本是 `argus.scanplan/v1`；它只定义规划、覆盖和观测语义，不负责数据库持久化，也不改变现有 Scanner 流水线。

## 场景

| 场景 | 用途 | 安全边界 |
| --- | --- | --- |
| `external-map` | Server 默认外网资产测绘 | 不包含 POC/EXP 阶段 |
| `internal-fast` | 兼容保留的 CLI 本地场景标识 | 使用 `_local/_default/_local` 作为离线租户、项目和网络区域占位符；独立 CLI 不再维护阶段级长期状态 |
| `internal-server` | Server + Agent 内网扫描 | 必须使用 Agent 的实际 `network_zone`，不能按私网 IP 跨区域复用 |
| `risk-validation` | 已确认的独立 POC 验证 | Plan 只能包含强制执行的 `risk_validation`，不能混入资产发现阶段 |

稳定阶段包括搜索引擎、子域发现、CDN 分类、ICMP 发现、TCP 存活、端口扫描、协议识别、HTTP 探测、Host 绑定、安全行为探针、目录探测、指纹和风险验证。安全行为探针依赖 HTTP 探测，按规范化服务端点执行创建任务时密封的自动安全 Nuclei 文件集合；它只产生产品指纹。Scanner 旧 `PhaseEvent` 通过显式适配器映射到这些阶段；未知阶段不会被静默当作已覆盖。

## Plan

`Plan` 固定包含 schema、场景、租户、项目、网络区域、规范化目标、Scope/Config 哈希、规则版本和带依赖关系的阶段列表。验证器拒绝空维度、重复目标、重复阶段、缺失依赖、依赖环以及普通资产发现 Plan 中的风险验证阶段。

离线 CLI 仍使用完整契约，但以以下稳定占位符表达本地边界：

```text
tenant_id   = _local
project_id  = _default
network_zone = _local
```

CLI 扫描结果统一写入当前工作目录的 `datas/<目标_时间>/`。普通 Run 只保留 `result.txt`、一份权威 HTML 报告和小型 `summary.txt`；不会再为了“扫描记忆”创建 targets/findings/coverage/timing TSV，也不会创建或合并 `argus-data/state`、`argus-data/runs`。`ARGUS_HOME/argus-data` 仅作为显式离线规则包管理的兼容位置保留。

CLI 只旁路观察输出，不把 CLI 切换为 Agent 模式。旧 localstate TSV 读写代码仅为兼容既有库内测试和显式工具保留，不进入普通扫描路径。

普通 CLI 仍默认关闭 POC、通用 POC 和 GoPoc；只有 `-poc` 或 `-gp` 等显式风险参数保持原执行语义，并强制完整扫描。`-gp` 是混合派发的兼容入口；Server 策略不接受它，而是依据共享 `argus.gopoc-catalog/v1` 将协议、漏洞和凭据插件分别密封到协议识别、自动 POC 和弱口令阶段。Planner 启动时只扫描 `datas/` 下已完成历史目录的 `result.txt`：带 `summary.txt` 的 Run 必须同时满足 `status=completed` 与 `terminal_status=completed`；老格式目录只有在 `result.txt` 非空时才作为已有发现使用。`targets.tsv` 不参与扫描记忆，也不会把零 finding 的旧扫描作为跳过依据。

跳过粒度是资产差集，而不是阶段级恢复：单 IP 命中历史时直接跳过；CIDR/IP 范围会展开并剔除已有资产 IP，只扫描剩余地址；域名、URL 和显式服务目标按规范化身份精确匹配。交互终端打印跳过地址及来源目录，HTML 与 JSON `run_summary` 记录完整、部分、全跳过输入及计划/跳过资产计数。CLI 不再读取 TTL 策略、不生成 `ResumePlan`、不做端口前缀复核，也不维护长期资产差异表。显式风险参数和 `-force` 永远绕过 `datas` 历史跳过。

G28 只为 CLI 增加可选 `-force`。该开关保存在 CLI-only ScanContext 字段中，不进入 Server/Agent Config，也不改变目标、端口、规则或风险策略；Planner 读取历史后直接为所有目标生成 `full/force_full_scan` 决策。

运行历史遵循最小证据原则：`datas/` 是本地授权扫描证据，不上传 Server，也不自动清理；其中可能包含 HTML 报告、POC 请求/响应包和目标信息，应按敏感文件保护。历史跳过只读取目标和发现身份，不把 HTML 内容或原始 POC 证据作为跳过判断依据。

## Timing evidence

G31 新增独立的 `argus.timing/v1` 契约，用于保存性能测量证据，而不是扫描日志、目标数据或优化结果。事件固定为 target-free 的 `process_startup`、`rule_prepare`、`context_init` 和规范 `stage`；仅 `stage` 可携带受支持的 Stage，且只有 `stage` 可使用 `negative`。每条事件固定包含 schema、稳定 SHA-256 event ID、Attempt ID、Agent ID、kind、可选 Stage、`success/negative/failed/skipped`、UTC `started_at`/`finished_at` 和非负 `duration_ns`。ID 由这些规范字段确定性计算；不得含 target、message、配置正文、HTTP 流量、凭据、POC 细节或任意用户字符串。身份字段有长度和规范化限制，时间区间最长 24 小时。

`duration_ns` 是生产者在进程内以单调时钟计算的权威耗时；UTC 时间戳仅用于传输、排序和展示。`0` 是合法值，表示计时分辨率下无法测得更长间隔，不能当作“没有计时”或失败。各事件可能重叠，因此准备项和 Stage 的总和不是进程墙钟，也不应用作 wall time。

CLI 在 `main` 中最早可观测位置开始记录 startup，覆盖离线 Arsenal/旧运行时规则准备、`ScanContext` 初始化和实际执行的 Stage 终态。普通 datas Run 将这些事件保存在当前进程内，仅用于 text 模式显示 bootstrap、规则、上下文、Stage 分段合计及最慢 Stage，不再额外持久化 `timing.tsv`；JSON 或其他非 text stdout 不增加人类日志。Agent 侧仍使用版本化 timing 契约上报 Server。

Agent v2.7.0 起对活动 Attempt 记录规则准备、`NewScanContext` 与已真实开始的 Stage 终态，并通过既有 `StreamResult` 以 `attempt_timing_event` payload 上报；未开始或复用的阶段不会伪装为执行。payload 是单一严格 JSON 对象，最大 16 KiB。Agent 使用已注册会话的 `x-agent-token` 发送该流；Server 不信任事件声明的租户或项目，而是以活动 Attempt、已分配 Agent、会话和 Task 的 tenant/project 归属重新绑定并校验。实时接收仅允许完成时间位于过去 24 小时至未来 10 分钟的事件。相同 tenant + event ID 且内容相同为幂等重放；相同 ID 内容不同为冲突并拒绝。旧 Agent 不上报时任务仍可完成，任务详情将该 Attempt 标为 `available: false`，即 unavailable，而不是 0。

Server 将通过校验的事件追加保存，不使用会被后续 WorkKey 更新的 `ScanCoverage` 当前视图。授权后的 `GET /api/v1/tasks/:id` 仅投影当前 tenant、project 和 task 作用域中的 Attempt、受限事件字段与 `truncated` 状态；单个任务最多返回 5000 条事件。UI 按 Attempt 展示准备项、Stage、结果和 unavailable，且不暴露 target、WorkKey、配置/规则哈希、会话令牌或原始日志。

G31 只建立测量、授权展示和基线；不包含 G32–G36 的 gonmap 懒加载、HTTP 预算/Scheme、URL 去重、规则共享、HybridMap 或 Nuclei 缓存优化。CLI 计时为进程内展示，Server/Agent timing 表与投影保持原契约；不改变扫描阶段、结果、目标范围、Coverage、任务状态机或 POC/EXP 的安全默认。

## WorkKey

WorkKey 的规范字段固定为：

```text
tenant_id + project_id + network_zone + normalized_target
+ stage + scope_hash + config_hash + rule_version
```

`risk_validation` 额外且强制包含 `poc_set_hash + endpoint_content_hash`；其他阶段禁止携带这两个维度。`Digest()` 对校验后的固定字段 JSON 计算 SHA-256，任一维度变化都会得到不同键。WorkKey 不允许跨租户、项目或网络区域构造复用关系。

## Observation 与 Coverage

Agent/CLI 观测结果使用 `success`、`negative`、`failed`、`skipped`。`failed` 与 `skipped` 必须携带结构化原因；只有 `success` 或 `negative` 能形成完整覆盖，失败或跳过只能形成不完整覆盖，不能用于跳过扫描。

Agent v2.5.0 通过 `StageObservationEvent` 上报终态阶段证据。Agent 只声明 Attempt/Agent、Server 已分配的目标、Stage、结果、规则/配置/内容哈希和时间，不声明 tenant、project 或 network zone；这些信任边界由 Server 从已领取 Attempt 与 Agent 注册信息补齐。旧 Agent 未发送事件时是 unknown，不允许从旧 `phase end` 或任务终态反推完整覆盖。

单目标成功/阴性事件可附带 `argus.checkpoint/v1`。允许的形状严格绑定 Stage：ICMP/TCP 只含存活 IP，端口阶段只含开放端点，协议阶段只含端点/协议，HTTP/Host 绑定只含无凭据 URL，子域阶段只含域名；总数不超过 4096，必须排序且去重。多目标、失败、跳过或不支持的 Stage 禁止携带检查点。Server 还会把每个派生项重新约束到已分配 IP/CIDR/范围、URL authority、host:port 或域名后缀；没有可信 DNS 映射时不保存域名目标解析出的 IP 检查点。检查点不含响应正文，并通过规范哈希绑定事件 ID 与 Observation evidence hash。

`argus.resume-plan/v1` 是单目标恢复计划。计划固定携带 tenant/project/network zone、目标、Scope/Config/规则版本，把完整阶段顺序严格划分为“已复用前缀 + 待执行后缀”，并将可重放检查点绑定到 WorkKey、Coverage、不可变 Observation 及三类 SHA-256 哈希。Planner 只读取同 WorkKey、未过期、完整且来源 Attempt 已完成的 Coverage；端口检查点可作为协议识别输入，协议检查点可作为 HTTP 输入。HTTP 检查点不含正文，不能直接恢复指纹、目录或 Host 绑定，因此这些阶段缺失时固定回退到 HTTP。域名解析缺少可信 DNS 映射时回退到域名链起点。多目标、手动重试、风险验证、检查点缺失/损坏/越界或任何维度漂移都不会产生阶段跳过。

Agent v2.6.0 起支持执行恢复计划。Server 只向版本兼容且当前规则版本与 Attempt 一致的 Agent 下发计划；旧 Agent 或规则漂移 Agent 收到原配置并执行完整流水线。下发前，Server 在最终 Agent 租约事务内重新锁定并重建计划，逐字节比较规范 JSON 与摘要，并将复用前缀的 `reused` 关联和 Agent 租约原子提交。Agent 再独立按实际 Config/目标/规则版本重建必需阶段，校验计划摘要、目标边界和检查点依赖后才恢复端口或协议输入；任一字段被篡改或依赖不完整时在 Scanner 初始化前失败关闭。恢复任务只为实际执行后缀上报 CoverageEvent，已复用前缀不会被错误上报为 `skipped` 并覆盖原有效 Coverage。

Coverage 状态是 `complete`、`incomplete` 或 `invalidated`，保存执行起止时间、可选有效期、观测摘要哈希和来源 Task/Batch/Attempt。失效覆盖必须记录原因。G18 起，Server 在 Agent 领取前按目标检查当前项目覆盖：只有目标所需阶段全部命中 `complete + success/negative`，且 tenant、project、network zone、Scope、Config、规则版本和有效期一致时，才创建 `reused` 关联并跳过该目标。未知、失败、跳过、失效或过期覆盖均不会跳扫。

Server 新 Coverage 的默认有效期为：存活 5 分钟、端口 1 小时、资产发现/协议/Web/目录/指纹 6 小时、风险验证 24 小时；CLI 在 G27 使用本地可配置策略，不直接继承 Server 时钟。Scope、Config、规则或 network zone 变化通过 WorkKey 隔离，旧证据不会被删除。相同 WorkKey 的上游内容哈希改变时，仅将时间不晚于该上游事件的依赖 Coverage 失效；乱序到达的旧上游事件不能推翻更新的下游证据。显式 `manual_retry` 是强制复测边界，绕过 Coverage 和 WorkClaim，但新执行仍追加 Observation 并成为该 WorkKey 的当前 Coverage。

检查点恢复只对单目标、可证明的连续复用前缀生效；无法重放时始终回退到最早必要依赖。Server 不向旧 Agent 下发恢复字段，因此滚动升级期间不会让旧执行器误解新契约。

当前复用只在完整目标边界生效，不把一个目标裁成部分阶段交给旧 Scanner；Coverage 的来源 Attempt 也必须已经完成。全量命中的 Attempt 不分配 Agent；部分目标命中时，复用关联和剩余目标与 Agent 租约在同一事务提交，避免 Agent 变化后错误沿用其网络区。手动重试、风险验证、旧的不完整配置快照、非活动 Project/Batch 以及未通过租户归属和 Alive 检查的 Agent 固定绕过复用。

运行中来源通过 WorkClaim 关联：由于当前 Scanner 以完整目标执行流水线，Server 使用每个目标的 `fingerprint` WorkKey 作为目标级互斥键，并在同一事务提交唯一 Claim、`executed` 来源关联、Attempt Agent 租约和节点容量。命中活动 Claim 的后续 Attempt 只记录 `in_flight/waiting` 关联并进入内部等待，不占 Agent；来源成功后重新进入 Planner 复用完整 Coverage，来源失败后重新竞争 Claim 执行，不会复用失败结果。

`GET /api/v1/tasks/:id` 的 `coverage_explanation` 使用 `argus.task-coverage-explanation/v1` 返回上述决策的只读解释：完整汇总实际执行工作项、历史复用阶段、仍在等待的执行中关联、失效/过期阶段以及节省的阶段和完整目标数量；最近 100 条明细展示规范目标、Stage、network zone、状态、原因和同项目来源 Task/Batch/Attempt。失效列表只包含当前任务产生或曾由当前任务实际复用的 Coverage，避免把同项目无关历史误报为本任务决策。来源名称和证据关联都按当前 tenant/project 重新查询；WorkKey、配置哈希、租约令牌和检查点摘要不对 UI 暴露。

Server 按每个目标派生 network zone：公网 IP/CIDR/范围和无私网标签的普通公网 DNS 为 `public`；私网、特殊用途地址与 split-horizon DNS 为 `private:<network_zone>`；无标签私网 Agent 回退为 `agent:<agent_id>`。Agent 不在 Observation 中声明这个边界。已有 `--tags` 可配置 `network_zone`；只有显式 `network_scope=public` 才允许带区域标签的普通公网 DNS 进入公网区，私网或保留 IP 永不提升为公网。
