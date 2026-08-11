# ScanPlan 与覆盖契约

Argus 的 Server、Agent 与离线 CLI 共享 `github.com/P0lar1ght/argus/shared/proto/go/scanplan`。当前契约版本是 `argus.scanplan/v1`；它只定义规划、覆盖和观测语义，不负责数据库持久化，也不改变现有 Scanner 流水线。

## 场景

| 场景 | 用途 | 安全边界 |
| --- | --- | --- |
| `external-map` | Server 默认外网资产测绘 | 不包含 POC/EXP 阶段 |
| `internal-fast` | CLI 默认内网快速增量探测 | 使用 `_local/_default/_local` 作为离线租户、项目和网络区域占位符 |
| `internal-server` | Server + Agent 内网扫描 | 必须使用 Agent 的实际 `network_zone`，不能按私网 IP 跨区域复用 |
| `risk-validation` | 已确认的独立 POC 验证 | Plan 只能包含强制执行的 `risk_validation`，不能混入资产发现阶段 |

稳定阶段包括搜索引擎、子域发现、CDN 分类、ICMP 发现、TCP 存活、端口扫描、协议识别、HTTP 探测、Host 绑定、目录探测、指纹和风险验证。Scanner 旧 `PhaseEvent` 通过显式适配器映射到这些阶段；未知阶段不会被静默当作已覆盖。

## Plan

`Plan` 固定包含 schema、场景、租户、项目、网络区域、规范化目标、Scope/Config 哈希、规则版本和带依赖关系的阶段列表。验证器拒绝空维度、重复目标、重复阶段、缺失依赖、依赖环以及普通资产发现 Plan 中的风险验证阶段。

离线 CLI 仍使用完整契约，但以以下稳定占位符表达本地边界：

```text
tenant_id   = _local
project_id  = _default
network_zone = _local
```

CLI 扫描流程在可执行文件同级创建 `argus-data/` 作为离线状态根目录，或使用 `ARGUS_HOME` 覆盖到指定绝对/相对路径；相对覆盖以启动时工作目录规范化。目录以仅当前用户可访问的权限创建（Windows 由系统 ACL 语义约束），不会上传 Server。

G24 已建立 `argus-tsv/v1` 分层布局：`state/assets.tsv` 与 `state/coverage.tsv` 是长期状态表，每次扫描在唯一的 `runs/<run-id>/` 下保存 `summary.txt`、`targets.tsv`、`findings.tsv` 与 `coverage.tsv`。两行表头固定声明 schema 和列名，字段中的反斜线、制表符与换行会被可逆转义；以 `= + - @` 开头的字段也会转义，避免目标可控内容形成表格公式。已有表头损坏或版本不兼容时失败关闭且不覆盖原文件。CLI 只旁路观察输出，不把 CLI 切换为 Agent 模式。

G25 将 Run 目录设为提交日志：`running` 期间只写独立文件，扫描结束先原子写为 `finalizing`，再在跨进程状态锁下幂等归并 assets/coverage，最后原子写入 `completed|failed + merge_status=merged`。状态表更新采用同目录临时文件、文件刷盘和原子替换；Windows 使用 `MoveFileEx(REPLACE_EXISTING | WRITE_THROUGH)`，其他平台使用 rename 并同步目录。并发运行通过 `.active.lock` 的操作系统文件锁区分，恢复器不会接管仍活跃的 CLI；失锁的 `running` 固定标为 `interrupted/not_merged`，不归并不完整证据，失锁的 `finalizing` 则安全重放幂等归并。首次 G25 启动会迁移 G24 终态 Run，之后只检查保留活动标记的异常运行，避免随历史数量线性增加启动开销。

数据行损坏、列数不符、重复键或语义无效时会形成可见 warning 并在下一次原子写入中剔除；不支持的表头版本仍失败关闭。状态归并按规范键排序，重复资产折叠并保留最早 `first_seen`，较旧 `last_seen/observed_at` 不得覆盖更新证据。

G26 将 CLI 接入保守的 `internal-fast` Planner。普通扫描默认关闭 POC、通用 POC 和 GoPoc；只有已有 `-poc` 或 `-gp` 显式风险参数保持原执行语义，并强制完整扫描。Planner 按本地 WorkKey 读取同目标、配置、规则和网络区域的未过期 `success/negative` 覆盖；当前仅在 IP、CIDR 或 IP 范围的端口阶段位于可复用前缀且检查点不超过 4096 项时尝试恢复。稳定时使用状态资产派生、不含响应正文的端口检查点，从协议识别继续执行 HTTP、目录、Host 绑定与指纹阶段。域名、URL、无覆盖、过期、失败、损坏、版本漂移或检查点校验失败都不会跳扫。

G27 在数据根目录原子创建并严格加载 `argus-local-policy/v1` 的 `config.yaml`。默认 TTL 为存活 5 分钟、完整端口 1 小时、协议 6 小时、Web/Host 绑定/目录 6 小时、指纹 6 小时、显式风险验证 24 小时；搜索、子域和 CDN 等资产发现阶段使用协议档。增量执行默认每次用 200ms 单端点预算、64 并发、最多 512 个端点复核已知服务和已知主机存活，存活端口为 80/443/3389/445/22。存活端口可在 `-p` 范围外用于可达性判断，但不会扩大完整扫描范围；只有当前 `-p` 范围内的新服务或已有服务消失才触发服务变化回退。轻量存活形成独立 `tcp_liveness executed` 覆盖，端口前缀保持 `reused`。没有可复核已知主机、预算超界或结果变化时不生成恢复计划。

本地策略要求完整字段和单一 YAML 文档，并拒绝未知字段、符号链接、不支持版本、非正或超过 30 天的 TTL、10ms..10s 外超时、1..1024 外并发、1..4096 外端点上限以及重复/非法存活端口。策略的规范内容参与 ConfigHash，因此任何 TTL 或复核策略变化都会使旧覆盖失配并至少完整执行一次。风险验证 TTL 只描述用户显式执行的本地风险证据；普通扫描的 POC-off 边界不受策略文件控制。

G28 只为 CLI 增加可选 `-force`。该开关保存在 CLI-only ScanContext 字段中，不进入 Server/Agent Config，也不改变 WorkKey、目标、端口、规则或风险策略。Planner 在读取历史后直接为所有目标生成 `full/force_full_scan` 决策，不执行覆盖预复核、不创建 ResumePlan、不写 `reused` 行；完整扫描产生的 `executed` 阶段证据继续按原 WorkKey 追加并更新当前覆盖。`ScanContext.Reset` 在一个多目标 CLI Run 的执行分组之间保留 force 指令。没有 `-force` 时行为与 G27 默认增量完全一致。

G30 为每个新 Run 增加版本化 `delta.tsv`，作为先于长期状态归并写入的不可变本地差异证据。稳定种类为 `asset_new`、`service_changed`、`asset_disappeared`、`asset_not_assessed`、`stage_executed` 与 `stage_reused`：前两者由本 Run 的确定性聚合与归并前同一 asset key 比较，后两种阶段记录只来自本 Run coverage。恢复、重复完成或乱序归并复用既有 delta，不重新推导结论。仅当 completed Run 对目标执行 `full` 扫描，权威发现阶段实际为 `success` 或 `negative`，并且 scope、配置、规则均可比且历史资产能证明归属当前目标时，才能记录 `asset_disappeared`；failed、interrupted、pending、incremental、阶段缺失/失败/跳过或任一漂移一律记录 `asset_not_assessed`。确认消失在 `state/assets.tsv` 中保留确认时间和 Run；重现必须来自成功完成、可信且更晚的观察，恢复旧 delta 也必须匹配原 status/hash/time/run，因而失败 Run、延迟旧 Run 或 stale recovery 不能覆盖较新状态。重新激活后继续保持最早 `first_seen`。文本模式在成功完成后输出简洁计数摘要；`-ot json` 不向 stdout 写入该人类摘要。本地历史不上传，也不自动清理。

运行历史遵循最小证据原则：Nuclei 仅保留模板、匹配位置、严重性等摘要，不保存原始请求/响应、packet、Interactsh 详情、复现命令和提取内容；GoPoc 只保留名称、等级、描述与目标，不保存用户名、密码、命令输出或展示详情。URL 用户信息会脱敏，查询串和片段不会落盘。

## Timing evidence

G31 新增独立的 `argus.timing/v1` 契约，用于保存性能测量证据，而不是扫描日志、目标数据或优化结果。事件固定为 target-free 的 `process_startup`、`rule_prepare`、`context_init` 和规范 `stage`；仅 `stage` 可携带受支持的 Stage，且只有 `stage` 可使用 `negative`。每条事件固定包含 schema、稳定 SHA-256 event ID、Attempt ID、Agent ID、kind、可选 Stage、`success/negative/failed/skipped`、UTC `started_at`/`finished_at` 和非负 `duration_ns`。ID 由这些规范字段确定性计算；不得含 target、message、配置正文、HTTP 流量、凭据、POC 细节或任意用户字符串。身份字段有长度和规范化限制，时间区间最长 24 小时。

`duration_ns` 是生产者在进程内以单调时钟计算的权威耗时；UTC 时间戳仅用于传输、排序和展示。`0` 是合法值，表示计时分辨率下无法测得更长间隔，不能当作“没有计时”或失败。各事件可能重叠，因此准备项和 Stage 的总和不是进程墙钟，也不应用作 wall time。

CLI 在 `main` 中最早可观测位置开始记录 startup，覆盖离线 Arsenal/旧运行时规则准备、`ScanContext` 初始化和实际执行的 Stage 终态。Run 建立后将事件绑定本地 Run ID 与 `cli-local`，并严格写入 `runs/<run-id>/timing.tsv`；该文件使用版本化 TSV 表头和完整契约字段，损坏、无效或不兼容表头失败关闭。仅 text 输出分别显示 bootstrap、规则、上下文、Stage 分段合计及最慢 Stage，不把可能重叠的分段相加冒充 wall time；JSON 或其他非 text stdout 不增加人类日志。旧 Run 不含 `timing.tsv` 时为 `unavailable`，不能伪造为零耗时。

Agent v2.7.0 起对活动 Attempt 记录规则准备、`NewScanContext` 与已真实开始的 Stage 终态，并通过既有 `StreamResult` 以 `attempt_timing_event` payload 上报；未开始或复用的阶段不会伪装为执行。payload 是单一严格 JSON 对象，最大 16 KiB。Agent 使用已注册会话的 `x-agent-token` 发送该流；Server 不信任事件声明的租户或项目，而是以活动 Attempt、已分配 Agent、会话和 Task 的 tenant/project 归属重新绑定并校验。实时接收仅允许完成时间位于过去 24 小时至未来 10 分钟的事件。相同 tenant + event ID 且内容相同为幂等重放；相同 ID 内容不同为冲突并拒绝。旧 Agent 不上报时任务仍可完成，任务详情将该 Attempt 标为 `available: false`，即 unavailable，而不是 0。

Server 将通过校验的事件追加保存，不使用会被后续 WorkKey 更新的 `ScanCoverage` 当前视图。授权后的 `GET /api/v1/tasks/:id` 仅投影当前 tenant、project 和 task 作用域中的 Attempt、受限事件字段与 `truncated` 状态；单个任务最多返回 5000 条事件。UI 按 Attempt 展示准备项、Stage、结果和 unavailable，且不暴露 target、WorkKey、配置/规则哈希、会话令牌或原始日志。

G31 只建立测量、保存、授权展示和基线；不包含 G32–G36 的 gonmap 懒加载、HTTP 预算/Scheme、URL 去重、规则共享、HybridMap 或 Nuclei 缓存优化。该能力全部为 additive：移除新表/投影和 `timing.tsv` 消费即可回滚，不改变扫描阶段、结果、目标范围、Coverage、任务状态机或 POC/EXP 的安全默认。

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
