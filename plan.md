# Argus 场景化扫描与任务运营动态计划

> 本文件是该改造的权威动态计划。每个 Goal 开始、完成、阻塞、验收或发生方向变化时必须同步更新。

## 当前状态

| 字段 | 值 |
| --- | --- |
| 当前阶段 | Phase 5：CLI 兼容性、AI 接口和完整回归 |
| 当前 Goal | G41 — 剩余非 AI 能力收口与发布检查 |
| 状态 | `completed` |
| 下一候选 Goal | 无；G40 AI 继续暂缓 |
| 当前分支 | `codex/g41-non-ai-completion` |
| 关联 Issue | [#164](https://github.com/P0lar1ght/argus/issues/164)；笔记本运营与发布收口按用户本轮合并授权纳入同一 Goal |
| 上次更新 | 2026-08-10 |

## 已确认决策

- 产品层级固定为 `项目 → 任务 → 批次 → 尝试`。
- Project 聚合资产和目标范围；Task 可持续追加批次；Batch 是用户可管理的扫描单元；Attempt 保存每次真实执行和重试。
- Server 主打外网资产测绘，内网 Agent 保留为高级能力；CLI 是完全本地的内网工具，不向 Server 上传结果。
- Server 默认执行平衡资产测绘：被动子域、常用端口、协议/Web 和指纹；付费测绘 API、子域爆破、POC、爆破和 EXP 不自动开启。
- 零配置创建默认使用当前 Project，省略名称时使用首个目标，省略优先级/超时时使用 P1/3600 秒；未提供目标时可复用当前项目 SeedTargets/Scope，直接输入的新目标在创建事务内扩展项目范围并写审计，OSINT 查询不进入项目目标范围。
- Task 和 Batch 的普通删除均为归档，保留结果、覆盖记录和审计；永久清理由管理员危险操作承担。
- 任务配置允许版本化修改；新批次使用当前配置版本，旧尝试保留原配置快照。
- 新增或重试批次使用当时最新已发布规则，并在 Attempt 中保存规则版本。
- Task 暂停时停止派发新批次，Agent 已领取的 Attempt 允许完成；停止则向 Agent 下发取消，之后通过重试产生新 Attempt。
- Task 暂停期间已领取 Attempt 可以收敛；失败时 RootTask 保持暂停，恢复时只为失败执行追加新 Attempt。任务显式重试只重跑失败、超时或已停止批次，成功批次不重复扫描；`stop` 为规范接口，`cancel` 保留为兼容别名。
- Batch 使用与 Attempt 执行状态正交的 `control_state`：暂停不打断已领取 Attempt，但阻止自动重试；显式恢复或重试保留旧 Attempt 并按需追加新 Attempt；归档只退出默认列表和进度聚合。
- 完成任务增加新批次后自动重新进入运行态。
- 项目操作员向任务增加目标时自动扩展当前 Project 的 Scope/SeedTargets，并写入审计。
- 后续实现按独立纵向 Goal 交付：每个 Goal 只覆盖一条用户操作链，并同时完成数据事务、Server API、RBAC/审计、前端交互、真实 smoke 和文档；不再把后端、前端或测试按层横向拆成多个 Goal。
- 用户明确要求暂不实施 AI 相关能力；G40 保留为未开始且持续暂缓的候选项。用户进一步要求把剩余非 AI 工作合并为单一 G41 完成，因此本轮不再拆分 Notebook 运营、Provider 旧链清理和发布验收子 Goal。
- POC/Workflow 通过统一风险验证向导显式启动，默认使用当前任务指纹，在同一任务下新增 `risk_validation` Batch。
- POC 原始权威来源保持为 Arsenal Nuclei YAML；`info.metadata.argus-execution-class` 仅允许 `detection/verification`，`argus-risk-level` 使用 `low/medium/high`，旧规则安全兼容为 `detection + unknown`。
- 所有 POC 仅能经显式风险验证确认执行；`high/unknown` 必须二次确认；`exploit/exp` 分类禁止进入 POC 并必须使用独立 EXP 包，EXP 永不由 Workflow 自动触发。
- 风险验证预览严格只读：只使用当前任务已落库指纹、当前已审核且启用的 Workflow/POC，返回规则/配置版本、POC 内容哈希、预计请求量上界和稳定计划哈希；不会创建 Batch/Attempt、入队或向 Agent 下发命令。
- 风险验证执行只允许终态 Task 经 operator 明确授权确认后追加 `risk_validation` Batch；既支持 Workflow 匹配，也支持指定已审核 POC。`high/unknown` 必须二次确认，自动重试关闭，规则变化后必须重新预览；Agent 版本必须不低于 v2.4.0 且规则版本、实际 POC 内容哈希均与预览一致，执行链路仅运行精确 Nuclei 映射。
- 同项目重复工作按 WorkKey 关联复用；执行中的相同工作只派发一次；显式重试默认绕过去重。当前 Scanner 以完整目标执行流水线，因此 G19 使用每个目标的 fingerprint WorkKey 作为目标级互斥键，不把一个目标拆成不完整阶段任务。
- G18 复用只在完整目标边界生效且来源 Attempt 必须已完成：全量命中不分配 Agent；部分命中的剩余目标、reused links 与最终 Agent 租约同事务提交。手动重试、风险验证、未知旧配置以及 tenant/project/network zone/Scope/Config/规则版本不一致均安全回退扫描。
- network zone 由 Server 使用数据库中的 Agent 标签和每个目标派生：公网为 `public`；私网、特殊地址和 split-horizon DNS 按 Agent `network_zone` 进入 `private:<label>`；无标签私网按 Agent ID 隔离。`network_scope=public` 只能显式标记普通公网 DNS，不能提升私网/保留 IP；绝不因私网 IP 相同直接跨错误区域复用。
- CLI 扫描历史不使用 SQLite，采用 EXE 同级 `argus-data` 下的分层 TSV；支持 `ARGUS_HOME` 覆盖。G23 已将根目录规范化为绝对路径并写入 `ScanContext.LocalDataRoot`；扫描流程按 `0700` 创建新目录，已有目录和文件不被覆盖，Agent 不使用也不上报该路径。
- G24 固定使用 `argus-tsv/v1` 两行表头；CLI 旁路观察结构化输出但不改变 Agent 模式判定。每次运行独立保存 summary/targets/findings/coverage，长期 assets/coverage 表在 G25 前只建立表头、不提前归并。Nuclei 原始流量、Interactsh/复现命令/提取内容与 GoPoc 凭据详情不进入历史，URL 用户信息脱敏且查询串/片段不落盘。
- G25 将 Run 目录作为可恢复提交日志：`running` 不归并，`finalizing` 可幂等重放，终态记录 `merge_status=merged`。状态表在跨进程锁下通过同目录临时文件、刷盘和原子替换提交；活动运行由 OS 文件锁隔离，失锁中断运行固定 `interrupted/not_merged`，较旧证据不得覆盖较新状态。首次升级扫描 G24 历史，之后只检查保留 `.active.lock` 的异常 Run，避免启动时间随全部历史线性增长。
- G26 将普通 CLI 收敛为安全 `internal-fast`：默认不自动执行 Nuclei/通用 POC/GoPoc，已有 `-poc/-gp` 视为显式风险操作并全扫。IP/CIDR/IP 范围只有在本地端口覆盖未过期、WorkKey 配置/规则一致、端口检查点可恢复且轻量 TCP 复核完全一致时才复用端口阶段；URL、域名、历史未知/失败/过期/损坏、规则或配置漂移、服务变化及检查点校验失败均完整扫描。单 IP 常用端口复核严格受当前 `-p` 范围约束，避免范围外服务导致无意义的永久回退。
- G27 使用 `argus-local-policy/v1` 的 `argus-data/config.yaml` 管理本地 TTL 与轻量复核预算：默认存活 5m、端口 1h、协议/Web/指纹 6h、显式风险验证 24h，已知存活/服务每次复核。策略首次原子生成，完整字段、单 YAML 文档、常规文件和安全数值均严格校验；策略内容进入 ConfigHash，变化后旧覆盖安全失配。存活探针可使用当前 `-p` 范围外的配置端口判断可达性，但范围外开放不会被当作新扫描服务，不能扩张授权扫描范围。
- G28 仅新增 CLI-only `-force`，不进入 Server/Agent 配置，也不改变 WorkKey。它跳过本地覆盖预复核和 ResumePlan，为全部输入记录 `full/force_full_scan`，但仍保留原目标/端口授权范围、普通扫描 POC-off 和追加式历史；同一 Run 的执行分组 Reset 不清除 force 指令。
- G29 固定 CLI 离线包为 `argus-data/arsenal/arsenal.db`，`ARGUS_HOME` 覆盖时首次从 EXE 同级发行包导入；只接受常规非符号链接 SQLite、完整运行时 schema、安全 POC 分类/风险和安全物化路径。文件 SHA-256 负责变化检测，规则内容语义 SHA-256 作为 WorkKey 规则版本；数据库仅在变化时物化，扫描期读取 `argus-data/arsenal/config` 并关闭 SQLite 句柄。源码构建无外部 DB 时保留内嵌规则回退，CLI 不联网；旧 `data/arsenal.db` 只在固定库缺失且完整校验通过时迁移。
- G30 将每次 Run 的差异作为不可变本地证据写入 `delta.tsv`：新增和变化必须比较归并前状态；实际执行和复用只来自本 Run coverage。资产消失仅在 Run 成功完成、目标为完整扫描、权威发现阶段实际成功且与历史 scope/config/rule 可比、历史资产可证明属于本次目标时确认；其余统一记录 `not_assessed`，不得以“本次没有输出”推断消失。tombstone 保存确认时间和 Run，重现必须来自成功完成、可信且更晚的观察；恢复旧 delta 前重验原状态，不能覆盖较新 Run。差异必须先于长期状态写入并在恢复时原样复用，文本模式只输出简洁摘要，现有 JSONL findings stdout 不混入人类日志。
- G31 只建立可重复、可持久化的性能观测基线，不提前优化扫描链路。计时契约固定为 `argus.timing/v1`：CLI 每个 Run 保存本地 `timing.tsv`；Agent 通过现有结果流上报有界、幂等且不含目标/凭据的准备与阶段区间；Server 以 Attempt 的 tenant/project/Agent 归属重新建立信任并追加保存。Go 运行时及包初始化发生在 `main` 前，完整进程墙钟由外部基线工具记录，进程内事件只描述可真实观测的 bootstrap/rule/context/stage 分段，二者不得混称。
- G32 仅把 gonmap 重型探针解析从 package init 延迟到首次真实 `gonmap.New()`，由 `sync.Once` 完整构建后再发布共享只读知识；CLI help、管理帮助和未进入协议识别阶段的路径不得承担探针解析成本。`SetFilter` 保留首次指定 filter 和后续串行重建对新 Scanner 生效的兼容语义，重建期间以锁保护全局发布，旧 Scanner 继续持有原只读快照；初始化失败不得静默降级或暴露半初始化状态。
- G33 将 `WebTimeout` 固定为规范化 HTTP 目标的总网络预算，而不是单次请求预算；retry、无 Scheme 协议回退、httpx `NextCheckUrl` 跳转和 Pipeline 同源 Location 后续探测只能消费原目标剩余时间。明确 `http://`/`https://` 永不因失败探测另一 Scheme；无 Scheme 保留兼容回退但不得重置 deadline。`ScanContext.Ctx` 必须传入真实请求并让取消后 Runner、请求和回调收敛，不能以提前返回并并发关闭 Runner 冒充取消。
- G34 删除进程级 `GlobalUsedUrl`，URL 是否已调度只能由当前 `ScanContext` 的并发安全集合决定；同一执行内以原子 check-and-mark 去重，不同 Context 永不共享，`Reset()` 开始新的执行分组时清空。httpx 通过窄接口接收状态，不能反向依赖 Engine；包级兼容入口使用调用级私有集合。
- G35 只共享由已验证 Arsenal package hash 与 ruleVersion 绑定的 Fingerprint、Workflow 和目录规则不可变快照；Task Config、结果、URL 状态、HybridMap、Hook、取消器、ResumePlan、POC runner 与凭据永不进入缓存。Agent 必须把“确认规则 → Context 初始化 → 登记运行”纳入同一版本使用窗口，热更新只能供后续 Task 使用；Debug 自定义规则在修改前深拷贝脱离共享快照。
- G36 只对任务私有的 HTTP body/header/banner 响应存储做保守的创建时选择：无目标、`risk_validation` 或不超过 8 个明确 URL/IP:Port/Domain:Port、没有 Provider/子域扩展且目录探测与 HostBind 均明确关闭的任务使用内存；裸 IP/域名、CIDR/IP range、未知输入、搜索 Provider、子域发现、目录探测、HostBind 和超上限任务继续使用磁盘 HybridMap。选择在 Agent 与 CLI 共用，三张 map 使用同一决策，构造失败完整回滚；不改变 `Reset()` 现有生命周期。Nuclei Runner、compiled template、ExecutorOptions、目标、回调、代理、凭据、Interactsh、结果和输入存储均包含任务可变状态，不跨任务缓存；风险验证仍逐次校验精确 POC 文件与内容哈希。
- G37 保留 `argus` 可执行文件名、全部通用扫描参数及 `finger/poc/workflow` 子命令语法，只把用户可见产品名、版本标签、帮助说明统一为 Argus CLI；命令示例继续使用真实的 `argus`。`--version` 在规则准备和扫描初始化前返回。FOFA/Hunter/Quake 已是 Server 项目级资产测绘能力，Standalone CLI 不再执行这些 Provider；旧参数及别名在迁移期由早期守卫识别并返回明确 Server 提示，但不再出现在常规帮助、读取凭据或发起 Provider 请求。Engine/Agent legacy 字段与旧任务兼容代码本 Goal 不删除，G38 的 JSON/非 TTY 输出保持独立。
- G38 保留 `-ot json` 现有逐 finding 流式语义并正式定义为 UTF-8 NDJSON，不改为扫描结束后一次性数组。CLI 使用独立版本化 wire record，不修改 Engine `OutputMessage` 或 Agent protobuf/gRPC payload；每个已开始的扫描在 findings 后恰好输出一个终端 summary。JSON 模式 stdout 只能包含 NDJSON，非 TTY 文本模式保留结果和必要错误但不显示 Banner、ANSI、进度及普通 Info。退出码首版固定为 `0` 成功/help/version、`1` 执行或本地持久化失败、`2` 参数/用法/Provider 迁移拒绝、`130` 取消；不得借机改变扫描阶段、目标授权、POC/EXP 或规则行为。
- Issue #165 描述的 CLI/Agent GoPoc 默认值分裂真实存在，但“普通扫描默认开启弱口令爆破”的原验收与已确认安全策略冲突。统一方向固定为共享默认 `NoPoc=true`、`GolangPoc=false`、`DisableGeneralPoc=true`；CLI 仅通过已有 `-gp` 显式开启 GoPoc，Server/Agent 仍只接受已确认风险验证，不能以一致性修复为由放宽主动探测默认值。
- Issue #164 采用 Server 先行的渐进迁移：I164A 只建立不暴露 HTTP 路由、不写项目资产、不触发扫描的 Server 内部 FOFA 查询核心；凭据由租户边界内调用方显式注入，响应经预算限制、规范化和去重后才返回。CLI/Agent 参数、搜索管线和凭据同步在本 Goal 均不改变，避免在 Server 替代路径验收前制造兼容缺口。
- 网络空间测绘的最终权威边界固定在 Server：Hunter/FOFA/Quake 的查询、凭据、额度、规范化、去重、导出和审计全部从 CLI/Agent 扫描管线剥离；CLI 继续作为完全离线的显式目标扫描器，Agent 只接收 Server 已解析并授权的目标列表。
- Server 测绘 Provider 不以“把 `api-config.yaml` 中所有第三方接口逐个照搬”为目标；优先级按现有 Scanner/Agent 真实调用链、资产覆盖增益、额度成本、稳定性和维护成本评估。第一梯队为 FOFA、Hunter、Quake，随后选择对被动子域和资产补全价值最高的 API；重复、低收益或长期不稳定的接口可以仅保留配置兼容而不进入新执行链。
- Server 增加项目级“测绘笔记本”：用户可从查询结果一键归档有价值的资产或查询上下文，长期整理、标注和导出；从笔记本分发到任务时必须再次校验 tenant/project 归属、目标授权、网络区域和风险策略，并复用任务追加批次的规范化、去重、幂等和审计链路。
- CLI 默认安全增量并进行轻量变化复核；只新增可选 `-force`，不引入必填 workspace/profile 参数。
- Server、Agent、CLI 使用同源版本化 `arsenal.db`；Agent 从 Server 同步，CLI 使用离线规则包。
- 每个阶段一个 `codex/` 分支；每个最小 Goal 一个聚焦提交。Goal 验证通过后自动进入下一项，遇到新歧义、高风险或破坏性操作时暂停询问。

## 状态定义

- `pending`：尚未开始。
- `in_progress`：当前唯一正在实施的 Goal。
- `completed`：验收标准全部满足且验证证据已记录。
- `blocked`：满足阻塞条件，已记录原因和恢复条件。

## Goal Board

### Phase 0：计划落地

| Goal | 状态 | 最小交付物 | 验收 |
| --- | --- | --- | --- |
| G00 | `completed` | 创建本文件，记录决策、Goal、分支、验证、风险和变更日志；调整 Server 阶段分支 | `plan.md` 可独立指导后续实施，Git diff 仅包含计划文件 |

### Phase 1：Server 任务与批次运营

| Goal | 状态 | 最小交付物 | 验收 |
| --- | --- | --- | --- |
| G01 | `completed` | 修复任务表格裁切；详情/结果常驻，其余操作进入状态相关菜单；显示无权原因 | 不改变 API 语义，前端测试覆盖操作入口 |
| G02 | `completed` | 统一 Task/Batch/Attempt 状态机并兼容旧状态别名 | Server 与 UI 使用同一行为矩阵，旧记录仍能展示和操作 |
| G02A | `completed` | 移除 GSAP 页面入场/路由过渡动效和依赖；Canvas 计时改用原生帧循环；登录页改用纯 CSS 保留动态视觉 | 前端不再引用 GSAP，业务页面内容不依赖动画完成后才可见，登录页动态视觉保留，测试、构建和浏览器 smoke 通过 |
| G03 | `completed` | Task 默认删除改为归档；新增任务审计 | 结果不删除，tenant/project/RBAC 与审计测试通过 |
| G04 | `completed` | 新增 TaskConfigRevision，RootTask 指向当前修订 | 新旧批次配置快照可追溯，迁移可重复执行 |
| G05 | `completed` | 新增稳定 TaskBatch；为旧 SubTask 回填批次 | 不丢现有任务，旧 Agent 仍可工作 |
| G06 | `completed` | SubTask 改为追加式 Attempt，记录 Agent、规则、配置和失败信息 | 重试不覆盖旧执行，调度和恢复测试通过 |
| G07 | `completed` | Task 内增加目标/Batch，规范化、去重并扩展 Project Scope/SeedTargets | 重复输入幂等，完成任务追加后重回运行态 |
| G08 | `completed` | Batch 暂停、恢复、停止、重试、归档 API 与 UI | 状态转换、Agent 已领取行为及审计测试通过 |
| G09 | `completed` | Task 暂停、恢复、停止、重试语义和 UI | 暂停不再派发，停止下发取消，显式重试新增 Attempt |
| G10 | `completed` | 零配置创建：项目默认、名称自动、场景/Agent 自动、高级设置折叠 | 用户只输入目标即可生成安全 ScanPlan，POC 默认关闭 |
| G11 | `completed` | POC execution class/risk level 元数据与治理 | 未分类兼容策略、高风险确认和 EXP 隔离有测试 |
| G12 | `completed` | 当前任务指纹的风险验证预览 API/UI | 展示资产、POC、严重性、版本、预计请求量且不执行 |
| G13 | `completed` | 确认后在同 Task 新增 risk_validation Batch | 仅执行预览绑定的 POC，所有对象归属和审计校验通过 |
| G13A | `completed` | 普通资产任务禁止通过高级配置或旧 Agent 直接执行 POC | API、调度领取和 Agent 三层失败关闭，POC 只能来自已确认 risk_validation Batch |

### Phase 2：项目级记忆、Planner 与去重

| Goal | 状态 | 最小交付物 | 验收 |
| --- | --- | --- | --- |
| G14 | `completed` | 定义 Stage、ScanPlan、Coverage、Observation、WorkKey 共享契约 | external-map/internal-fast/internal-server/risk-validation 均可表达 |
| G15 | `completed` | 新增 Observation、Coverage、WorkClaim、CoverageLink 存储 | 追加证据与当前资产视图并存，tenant/project 索引完整 |
| G16 | `completed` | Agent 上报阶段成功、阴性、失败、跳过和内容哈希 | 旧 Agent 缺少覆盖时按 unknown 处理且不误跳过 |
| G17 | `completed` | Server 覆盖归并器，保存规则和配置快照 | 重复事件幂等，失败/部分覆盖不可复用 |
| G18 | `completed` | 有效已完成覆盖跨 Task/Batch 关联复用 | 创建 reused 关联并正确聚合进度，不重复派发 |
| G19 | `completed` | WorkClaim 原子占用和执行中关联 | 并发相同 WorkKey 只派发一次，来源失败后自动重规划 |
| G20 | `completed` | network_zone 隔离策略 | 公网、私网区域和无标签 Agent 的去重边界测试通过 |
| G21A | `completed` | 阶段 TTL、规则/配置/网络区匹配、内容依赖失效与 force 绕过 | 失败/过期/漂移证据不可复用，内容变化只失效依赖覆盖，显式重试产生新证据 |
| G21B1 | `completed` | 单目标阶段检查点契约、Agent 上报和 Server 追加式存储 | 只保存有界派生资产，不保存响应正文；多目标或不可信检查点不参与重放 |
| G21B2 | `completed` | Planner 按缺失阶段与可用检查点计算最小依赖闭包 | 仅在 tenant/project/network zone/WorkKey/TTL 全部有效时生成恢复计划，缺少检查点时安全回退 |
| G21B3 | `completed` | Agent 校验并恢复检查点，按 Server 计划执行阶段子集 | 已覆盖且可重放阶段不重复执行，计划/检查点漂移失败关闭并产生完整阶段证据 |
| G22 | `completed` | UI 展示执行、复用、等待、失效原因和节省量 | 用户能追溯复用来源，不能静默跳过 |

WorkKey 固定包含：

```text
tenant + project + network_zone + normalized_target
+ stage + scope_hash + config_hash + rule_version
```

POC 阶段额外包含排序后的 POC 集合和端点内容哈希。任何覆盖均不得跨 tenant、project 或 network_zone 复用。

### Phase 3：CLI 离线记忆与增量扫描

| Goal | 状态 | 最小交付物 | 验收 |
| --- | --- | --- | --- |
| G23 | `completed` | EXE 同级 `argus-data`，支持 `ARGUS_HOME` | 无必填新参数，路径跨平台且可迁移 |
| G24 | `completed` | `state/assets.tsv`、`state/coverage.tsv` 与每次运行目录 | TSV 可人工读取且包含版本化表头 |
| G25 | `completed` | 独立运行写入、原子归并、中断恢复 | 中断不污染当前状态，损坏行可报告并跳过 |
| G26 | `completed` | CLI 自动 internal-fast 增量 Planner | 新目标全扫，已知目标只做轻量复核和必要补扫 |
| G27 | `completed` | TTL 默认和 `argus-data/config.yaml` | 存活/已知服务每次复核；端口 1h；协议/Web/指纹 6h；POC 24h |
| G28 | `completed` | 可选 `-force` 完整扫描 | 默认命令保持兼容，force 绕过本地覆盖 |
| G29 | `completed` | 版本化离线 `arsenal.db` 包 | 与 Server 构建同源，支持本地替换/导入与版本校验 |
| I165 | `completed` | 统一共享扫描默认值为 POC/GoPoc 安全关闭，保留 CLI `-gp` 显式开启并处置过时 Issue #165 | CLI/Agent 普通扫描默认一致且不自动爆破，显式风险入口和失败关闭不回退 |
| G30 | `completed` | 新增、变化、确认消失、未评估、复用和实际执行的版本化 `delta.tsv` 与文本摘要 | 基于 pre-merge 状态确定性计算；恢复幂等；证据不足不报消失；JSON stdout 保持纯净；历史仅手动清理 |

建议目录：

```text
argus-data/
  config.yaml
  arsenal/arsenal.db
  state/assets.tsv
  state/coverage.tsv
  runs/<run-id>/summary.txt
  runs/<run-id>/targets.tsv
  runs/<run-id>/findings.tsv
  runs/<run-id>/coverage.tsv
  runs/<run-id>/delta.tsv
  runs/<run-id>/timing.tsv
```

#### G30 具体边界与验收（Issue #166）

- 只修改 CLI/localstate/localplanner 的本地证据、归并和展示；不修改 Server、Agent、目标授权范围、POC/EXP 安全默认或必填参数，不上传本地历史，也不自动清理 Run。
- `delta.tsv` 使用版本化严格表头并稳定排序，至少表达 `asset_new`、`service_changed`、`asset_disappeared`、`asset_not_assessed`、`stage_executed`、`stage_reused`；不得保存 HTTP 原始流量、凭据、查询串或 POC 细节。
- Run finalization 在持有跨进程 merge lock 时读取归并前 assets/coverage，先原子写入或校验既有 delta，再更新长期状态；恢复器复用已写 delta，重复 Finish、乱序或崩溃恢复不得改变结论。
- 新增/变化使用本 Run 确定性聚合与 pre-merge 同一 asset key 比较；确认消失需要 completed Run、full 目标、实际成功/阴性权威阶段、相同 scope/config/rule 以及可证明的目标归属。failed/interrupted/pending、incremental、阶段缺失/失败/跳过和任一漂移只产生 `not_assessed`。
- 确认消失的资产在长期 `assets.tsv` 保留 `disappeared` tombstone；重新观察后恢复 `active` 并保留最早 `first_seen`。旧 summary/TSV 仍可读取，G30 新计数作为向后兼容的可选字段。
- 文本模式在成功 Finish 后输出新增/变化/消失/未评估/执行/复用的简洁摘要；`-ot json` 不写该人类摘要到 stdout，稳定机器摘要留给 G38。
- 最小测试覆盖：新增/变化/无变化；确认消失与重新出现；增量复用；规则/配置/范围漂移；failed/interrupted/pending；恢复重放、并发/乱序归并、损坏 delta 和旧 summary 兼容；CLI build 及 `127.0.0.1`、POC-off 本地 smoke。

### Issue #164：Server 资产发现迁移

| Goal | 状态 | 最小交付物 | 验收 |
| --- | --- | --- | --- |
| I164A | `completed` | Server 内部 FOFA 客户端，接收调用方提供的租户凭据和查询，返回有界、规范化、去重的显式目标 | 不新增公开 API、不读取 Agent/CLI 配置、不记录凭据；请求预算、响应上限、错误状态、畸形结果和去重均有测试 |
| I164B | `completed` | 项目授权的 FOFA 查询预览 API，从当前租户已批准的 Server API 配置读取凭据并写专用审计 | operator 及以上且拥有项目访问权才可调用；不返回或审计原始凭据/查询，跨租户、Provider 错误和审计失败均安全关闭；不保存资产、不导出、不创建任务 |
| I164C | `completed` | Server 内部 Hunter 客户端，沿用统一资产结构并实现有界分页、响应预算、规范化和去重 | 不新增公开 API、不读取 Agent/CLI 配置、不记录 API Key 或原始响应；固定 HTTPS 端点、查询/页数/结果/响应/超时边界及 Provider 错误均有测试 |
| I164D | `completed` | 项目授权的 Hunter 查询预览 API，复用当前租户 Approved API 配置与专用资产发现审计 | operator 及以上且拥有项目访问权才可调用；Hunter Key、原始查询和 Provider 响应不返回或落审计，跨租户、Provider 错误和审计失败安全关闭；不保存资产或创建任务 |
| I164E | `completed` | Server 内部 Quake 客户端，使用单次有界查询和统一资产规范化替代旧 Scanner 查询/账户探测耦合 | 不新增公开 API、不读取 Agent/CLI 配置、不请求账户信息、不记录 Token 或原始响应；固定 HTTPS 端点、请求/结果/响应/超时边界及 Provider 错误均有测试 |
| I164F | `completed` | 项目授权的 Quake 查询预览 API，复用当前租户 Approved API 配置与专用资产发现审计 | operator 及以上且拥有项目访问权才可调用；Quake Token、原始查询和 Provider 响应不返回或落审计，跨租户、Provider 错误和审计失败安全关闭；不保存资产或创建任务 |
| I164G | `completed` | 新增项目级测绘查询快照和规范资产项的追加式存储模型与迁移，不接入现有查询 Handler | tenant/project/audit 关联和查询内目标唯一性由 schema 约束；只保存有界查询上下文与规范资产字段，不保存凭据或 Provider 原始响应；迁移可重复执行且不修改现有 assets/audit 数据 |
| I164H | `completed` | FOFA/Hunter/Quake 成功查询在一个事务内写入审计、查询快照和规范资产项 | 成功响应必有完整快照；任一验证或写入失败则回滚成功记录、补写稳定失败审计并隐藏结果；跨租户/项目边界不变，不写现有 assets、不导出、不创建任务 |
| I164I | `completed` | 提供项目级测绘查询页，以及历史列表与单次查询明细的有界只读 API | 前端按项目提供最小 Provider/表达式查询、官方常用语法速查与键盘可用的字段补全、历史筛选和明细分页；补全是提示而非本地白名单，官方新增语法仍可直接输入；viewer 只能读取，operator 才可查询；所有接口仍须拥有项目访问权，响应不包含凭据、配置哈希、查询哈希或 Provider 原始响应，跨租户/项目对象不可读取 |
| I164J | `completed` | 为单个已持久化测绘快照提供 Server 生成的安全 CSV 导出与前端一键下载 | viewer 仍须拥有项目访问权；按 tenant/project/snapshot 读取最多 10000 项并限制编码后 32 MiB，项目授权、快照/资产读取和成功审计共用 10 秒请求级数据库预算；稳定排序、UTF-8 Excel 兼容且防 CSV 公式注入；只导出规范资产公开字段，不含表达式、内部哈希、凭据或 Provider 原始响应；成功导出必须写当前用户的脱敏审计，审计失败不返回文件；不合并项目资产、不归档笔记本、不创建任务 |
| I164K | `completed` | 提供项目级测绘笔记本的批量归档、项目内目标去重、来源关联、只读列表和前端一键操作 | 新增目标条目与来源关联的追加式模型：同 tenant/project/target_hash 只保留一个笔记本目标，不同快照项继续建立可追溯来源；operator 可从单个已授权快照每次选择 1–100 个稳定 item ID 归档，viewer 可有界分页读取，归档项目只读；每项目最多 10000 个目标，请求体 16 KiB、数据库预算 10 秒，成功写入与脱敏审计同事务且失败关闭；前端只对已持久化历史明细开放多选归档并展示笔记本列表；不复制表达式/凭据/Provider 原始响应，不写 assets/Scope/SeedTargets，不创建 Task/Batch/Attempt，也不提前实现标签、备注、移除或任务分发 |
| I164L | `completed` | 提供测绘笔记本选中项分发到现有 Task 的只读预览 API 与前端确认界面 | operator 在 active 项目内选择 1–100 个笔记本条目和同项目未归档 Task；Server 在统一 10 秒预算内重验 tenant/project/task/item 归属、任务状态、当前配置修订和 direct 安全扫描模式，按现有 append 规则规范化并区分新增/任务内重复目标，预估 Scope/SeedTargets 增量与 TaskBatch 分组，返回绑定选集、任务状态、配置/规则版本和现有目标快照的稳定 plan hash；预览不写审计、Scope/SeedTargets、Task/Batch/Attempt，也不触发队列、Agent、POC 或 EXP；前端对 viewer/归档项目隐藏分发入口，并在项目切换时失效旧预览 |
| I164M | `completed` | 建立测绘笔记本分发意图、逐项不可变快照和 Idempotency-Key 内部数据契约，不开放写 API 或物化任务 | additive migration 新增 tenant/project/task 受限的分发意图与逐项快照，冻结 operator、操作域、I164L 预览 schema/plan hash、任务状态、配置/规则版本、规范目标、目标哈希及新增/重复结果；只保存 Idempotency-Key 的 SHA-256，同 tenant/project/operator/operation 下同键同请求原子返回原意图，同键异请求固定冲突。复合外键约束 Task、ConfigRevision、NotebookItem 和 Intent 归属，数量/哈希/状态/目标均有界；内部记录函数任一步失败全部回滚。不得新增 route/handler/UI/审计写入，不得修改 Project Scope/SeedTargets、RootTask、TaskBatch、Attempt 或队列，不得触发 Agent/POC/EXP；intent 不构成目标授权、二次确认或执行凭证 |
| I164N | `completed` | 将笔记本分发预览经显式确认、幂等键和策略复核原子物化到现有 Task | operator 从 I164L 预览确认后，Server 重验 tenant/project/task/item、任务状态、配置/规则和 direct 安全策略；本次确认是将新增目标纳入当前项目范围的明确授权，且不能覆盖任务既有 Agent selector、network zone 隔离或 POC/EXP 风险闸门；同事务记录/重放 I164M intent、写审计、扩展 Scope/SeedTargets 并创建追加式 Batch/Attempt，提交后派发且重放不重复入队；前端确认、结果反馈、真实 API/浏览器 smoke、测试和文档在本 Goal 一次闭环 |

后续方向（按最小 Goal 逐项创建，不提前合并实现）：

1. Server 租户级测绘查询 API、凭据读取、额度和审计。
2. 查询结果导出与项目级测绘笔记本归档。
3. 笔记本筛选、标注、去重，并幂等分发到 Task/Batch。
4. 补齐 Hunter/Quake Provider 后切断 Agent 凭据同步和 Scanner 搜索阶段。
5. CLI 测绘参数退出执行链；按兼容策略提供迁移提示，最终帮助页不再展示。

### Phase 4：扫描性能

| Goal | 状态 | 最小交付物 | 验收 |
| --- | --- | --- | --- |
| G31 | `completed` | 启动、规则、上下文和阶段计时基线 | CLI 与 Server 均可查看耗时，保存前后基准 |
| G32 | `completed` | gonmap `sync.Once` 懒加载 | help/无需协议阶段不加载探针，行为测试通过 |
| G33 | `completed` | HTTP 目标级总预算和明确 Scheme 策略 | 挂起目标不再叠加完整超时，重试共享预算 |
| G34 | `completed` | URL 去重移入并发安全 ScanContext | 无跨任务串扰，race 测试覆盖 |
| G35 | `completed` | 按 Arsenal 哈希共享只读知识库 | 不共享任务可变状态，Agent 上下文准备达标 |
| G36 | `completed` | 小任务内存、大任务 HybridMap；评估 Nuclei 缓存 | 以基准证明收益，无资源泄漏和结果变化 |

#### G31 具体边界与验收（Issue #167）

- 只增加测量、追加式证据、授权展示和基线工具；不修改 gonmap 加载、HTTP 超时/重试/Scheme、URL 去重、规则共享、HybridMap/Nuclei 缓存，也不改变扫描阶段、结果、目标范围、Coverage 复用、任务状态机或 POC/EXP 安全默认。G32–G36 的优化必须继续独立提交并使用 G31 的相同 case 保存前后数据。
- 共享 `argus.timing/v1` 事件只允许 `process_startup`、`rule_prepare`、`context_init` 和规范 `stage` 四类分段，保存 UTC 区间、由进程内单调时钟计算的非负 duration、稳定 event ID 与 success/negative/failed/skipped 结果；不保存 target、阶段 message、配置正文、HTTP 流量、凭据、POC 细节或任意用户字符串。
- CLI 从 `main` 最早可观测位置记录 bootstrap，并分别覆盖离线 Arsenal/旧运行时规则准备、ScanContext 包装及真实执行阶段；事件在 Run 建立后绑定本地 Run ID，严格写入版本化 `timing.tsv`。只有 text 模式输出简洁耗时摘要，JSON/非文本 stdout 不新增人类日志；旧 Run 没有 timing 文件时明确 unavailable，不伪造为 0。
- Agent 对每个 Attempt 记录规则准备、`NewScanContext` 和真实阶段终态；复用或未开始阶段不能伪装为 executed。通过现有 `StreamResult` 使用独立有界 payload，旧 Agent 不上报时仍可完成任务。Server 不接受 Agent 声明 tenant/project，而是用活动 Attempt、已分配 Agent 和 Task 归属校验；同 event ID 同内容幂等，不同内容冲突。
- Server 使用 additive、append-only timing 表保留每次 Attempt 的历史，不复用会被新 WorkKey 覆盖的 `ScanCoverage` 当前视图。现有 Task detail 在 tenant + project + task 对象授权之后返回有界 timing projection；前端按 Attempt 展示准备分段、阶段分段、结果和 unavailable，不暴露内部目标、WorkKey、配置哈希、原始日志或高基数 metrics 标签。
- 提供版本化基线采集工具，区分外部 `process_wall` 与进程内分段，固定记录 case、样本/预热数、min/P50/P95/max、二进制 SHA、Go/OS/Arch、Arsenal/配置身份且不回显命令参数或目标。固定 localhost、POC-off 至少覆盖 `argus -h`、明确 URL 暖扫描及相同 Arsenal 的 Agent context；G31 先保存 before 基线，after 仅代表插桩开销复核而非性能优化。
- 最小测试覆盖共享契约与单调时钟、CLI TSV/旧 Run/失败/JSON 隔离、Agent 阶段/规则/上下文及 stream 重放、Server migration/schema/归属/租户项目隔离/幂等/有界聚合、前端 viewer 展示与缺失状态；运行 Scanner、Server、前端、`make db-verify`、本地 CLI/Agent 安全 smoke 和独立只读 review。

性能门槛：

- `argus -h` 暖启动 P95 ≤ 300ms。
- 本地明确 URL、关闭 POC 的暖扫描 ≤ 1s。
- 挂起 HTTP 目标总耗时 ≤ 配置超时 + 1.5s。
- 相同 Arsenal 下 Agent 新任务上下文准备 P95 ≤ 500ms。

#### G32 具体边界与验收（Issue #168）

- 根因已由 G31 同口径基线和 `GODEBUG=inittrace=1` 双重确认：当前 help 在进入 `main` 前执行 gonmap 探针初始化，单次记录约 318ms、308 MiB 分配和 139 万次 allocation；G31 after help P95 为 478.15ms，未达到 300ms。
- 删除 gonmap 的重型 package `init()`，探针库只在首次 `New()` 或显式 `SetFilter()` 时完整构建；默认首次 `New()` 使用 filter 9。`sync.Once` 必须覆盖完整构建并在成功后发布，多个协议 worker 并发首次调用只能得到同一个完整只读基准快照。
- `Nmap` 实例继续以浅拷贝共享只读 probe/port/match 数据，只修改自己的 timeout、深度探针选择和已用探针状态。`SetFilter` 首次调用直接建立指定 filter，后续串行重建以互斥锁原子替换供新 Scanner 使用的快照，已有 Scanner 不被覆盖；仓库当前无该 API 调用，但不得无说明破坏公开兼容语义。
- 测试必须使用独立进程白盒状态、并发首次 `New()`、`SetFilter` 重建和离线已知 banner，不访问硬编码内网目标；现有 gonmap 网络测试改为无网络的确定性匹配回归。CLI help/管理帮助以新构建二进制和 inittrace/基线证明未解析探针，明确 localhost URL、POC-off 扫描证明协议结果未回归。
- before/after 固定使用同一机器、Go、Arsenal/配置身份、3 次预热和 30 次样本，记录二进制 SHA、min/P50/P95/max；after 的 `argus -h` P95 必须不超过 300ms。首次协议识别变慢是延迟成本的预期位置，必须由计时证据解释，不能通过删除协议探针、减少规则或改变结果换取达标。
- 本 Goal 不修改 HTTP 超时/重试/Scheme（G33）、URL 去重（G34）、Arsenal 共享（G35）、HybridMap/Nuclei 缓存（G36）、IPv6 拆分、扫描范围、阶段顺序或 POC/EXP 默认值。

#### G33 具体边界与验收（Issue #169）

- 当前 `cda69f2` 已用只绑定 loopback 的静默 TCP 靶场复现：明确 `http://127.0.0.1:18081`、`-wto 2 -wt 1 -Pn -nd -npoc -force` 实际墙钟 7634.49ms，超过 3500ms 验收上限。根因是每轮 Runner 固定 `Retries: 1`、请求使用 `context.Background()`，并且 retry、无 Scheme fallback、最多三轮 `NextCheckUrl` 与最多四轮同源 Location 探测都可重新获得完整超时；单目标外层 guard 最低仍为 30s。
- 为每个规范化 HTTP 目标建立独立 deadline，并在同一 HTTP probe session 内复用；多个目标并行时不得共享一个全局 deadline。retry、HTTPS/HTTP fallback、JS/meta 跳转、同源相对/绝对 Location 与默认 HTTP→HTTPS 升级均只能使用来源目标剩余预算，耗尽后不得再创建请求或迟到回调。
- Pipeline 必须把 `ScanContext.Ctx` 传给 HTTP session；父 Context 取消应中断真实请求并等待 Runner 收敛后释放资源。目标自身 deadline 到期是该目标失败，不得被记录为成功 coverage；父取消继续由现有 Pipeline 终态返回。
- 明确 Scheme 输入始终只探测该 Scheme；无 Scheme 调用保持兼容的 HTTPS→HTTP fallback，但两个协议共享同一 deadline。保留 `--web-timeout/-wto` 名称、默认 10s、Agent JSON 配置和 Server Attempt `TimeoutSec` 的既有不同语义，不新增必填参数。
- 当前共享 Phase/Coverage 契约仍是一次执行的阶段粒度：混合目标中任一 HTTP 目标耗尽预算时，成功目标的结果和安全重定向仍继续收集，但整个 HTTP 阶段及依赖阶段保守标记失败，不生成可复用阴性覆盖。逐目标阶段覆盖需要单独修改共享契约，明确留给后续 Goal，不能在 G33 中以错误复用换取更细粒度。
- 本 Goal 只覆盖主 HTTP probe session；HostBind、DirBrute、端口/协议阶段和 POC/EXP 不改变，`GlobalUsedUrl` 迁移仍属于 G34。测试只使用 loopback/离线 fixture，至少覆盖挂起 HTTP/HTTPS、retry/fallback、跳转/重定向 lineage、两个独立目标、父取消、无迟到 callback 和 race。
- 保存相同 Windows/Go/Arsenal/配置、相同 loopback 靶场、相同参数和二进制 SHA 的 before/after min/P50/P95/max；挂起目标 after 墙钟不得超过 `WebTimeout + 1.5s`。根模块及 httpx/engine/CLI/Agent 最小充分测试和安全 smoke 通过，独立只读 review 无 Critical/Important 后才能完成。

#### G34 具体边界与验收（Issue #170）

- 当前 `be03a6b` 已用 loopback 脚本跳转稳定复现跨任务漏扫：两个顺序 `CallHTTPx` 对同一 root→`/next` 链分别得到 2 和 1 次回调；后一个 Session 的 follow-up 被前一任务残留的 `GlobalUsedUrl` 抑制。8 个并发 Session 的 Docker Linux `-race` 明确报告 `RemoveUsedUrl` 读取与 `callHTTPx` append/覆盖 slice 冲突并以 66 退出。
- `ScanContext` 新增只在内存中的 HTTP URL 调度集合，以互斥锁保护原子“首次占用”操作；`NewScanContext` 和 legacy CLI 构造均初始化，`Reset()` 在没有活跃 Pipeline 的既有生命周期边界内清空。不同 Task/Context 对同一 URL 必须各自成功占用，同一 Context 并发占用只能有一个成功。
- httpx 只能依赖一个最小 URL 访问接口，不能 import Engine。Pipeline 创建 `ProbeSession` 时注入当前 Context；既有 `NewProbeSession` 和包级 `CallHTTPx*` 使用每次调用私有集合，保持调用签名兼容但不跨调用共享。
- URL 在进入 Runner 调度前原子占用；JS/meta `NextCheckTargets` 和 Pipeline 同源 Location 的后续 pass 使用同一集合，既不重复执行，也不得丢失 G33 的来源 deadline、父取消和明确 Scheme 约束。进程级 `GlobalUsedUrl` 及 `RemoveUsedUrl` 运行路径必须删除。
- 本 Goal 不改变 HTTP timeout/retry/fallback/redirect 次数、HostBind/DirBrute、端口/协议/指纹结果、POC/EXP、安全授权、Arsenal 或 HybridMap/Nuclei 缓存。测试只使用 loopback/离线 fixture，覆盖顺序隔离、同 Context 并发、跨 Context 并发、Reset、NextCheck/Location 兼容和 Linux race。

#### G35 具体边界与验收（Issue #171）

- 当前 `009a09b` 的 Agent 稳态规则准备不会重复物化 SQLite，但每次 `NewScanContext` 仍读取并解析 `finger.yaml`、`workflow.yaml` 和 `dir.yaml`。同一物化 Arsenal、POC-off、无目标/无网络的 3 次预热、30 次 before 为：min 132.896ms、P50 138.482ms、P95 153.013ms、max 158.321ms；Arsenal 文件 SHA-256 为 `9f2907ff...ce3e`，配置 manifest 文件 SHA-256 为 `5b3726d3...05ec`。
- Engine 仅在 Agent 显式提供已验证 manifest identity 时使用进程内有界缓存；cache key 同时包含 package hash 和 ruleVersion。同一 key 并发首次构建只执行一次、完整成功后才发布；失败不留半成品并允许重试。不同 identity 不复用，淘汰只移除 cache 索引，已被旧 Context 引用的快照继续安全存活。
- 共享快照只含解析后的 Fingerprint、Workflow、Dir 规则及必要只读身份。正常 Pipeline 通过私有快照读取；现有公开 Context map/slice 不得成为共享对象的可变别名。Debug/custom-only 在任何 nil、append 或 map 写入前必须深拷贝 detach；`Reset()` 保留同一只读快照但继续清空所有任务状态，`Close()` 只释放任务资源。
- Agent 在 `rulesMu` 下确认物化 manifest 并捕获 package hash/ruleVersion；在释放锁前登记初始化规则使用者。该使用者必须持续到 Context 已创建且 Task 已进入 `runningTasks`，阻止同步线程在逐文件读取或 POC 目录使用窗口激活新包。risk-validation、ResumePlan、Coverage/timing reporter 均使用捕获版本，不能在任务中途重新读取 `w.ruleVersion`。
- Server 的规则聚合 hash 保持兼容用途，下载响应另以 `X-Arsenal-SHA256` 绑定实际 SQLite 字节；Agent 在持久化前复算并拒绝缺失或不匹配的包。物化 manifest 保存 `package_sha256`，旧 manifest 只会触发一次本地重物化，旧 Agent 可继续忽略新增响应头。
- 当前实现同口径 3 次预热、30 次 after 为：min 40.277ms、P50 42.915ms、P95 45.305ms、max 45.550ms；相对 before 的 P50/P95 分别改善 69.0%/70.4%，满足 500ms 门槛。基线工具在采样前强制实际 `arsenal.db` SHA-256 与 manifest 相等，避免错误身份污染证据。
- G35 不缓存 Nuclei runner/模板执行准备，不共享 POC 可变运行态或 HybridMap，不改变 CLI legacy 全局兼容、扫描阶段/结果/范围、HTTP/Scheme、gonmap、URL 去重及 POC/EXP 安全默认；这些分别留给 G36 或既有边界。
- 测试覆盖同 key 2–32 路 single-build、不同 key、失败重试、有界淘汰、旧引用存活、Context 可变状态隔离、Debug 深拷贝、Agent 热切换窗口、risk-validation/ResumePlan 捕获版本及 Linux race。固定同一环境/Arsenal/配置采集 3/30 after，P95 必须不超过 500ms且不得通过减少规则达标；最终执行 POC-off loopback CLI/Agent smoke。

#### G36 具体边界与验收（Issue #172）

- 当前 `616d96b` 的 Agent 与 CLI Context 都无条件创建三份磁盘 LevelDB HybridMap。固定同一已验证 Arsenal、POC-off、无目标/无网络的 3 次预热、30 次 before 为：min 41.273ms、P50 47.672ms、P95 53.840ms、max 55.306ms；Arsenal SHA-256 为 `9f2907ff...ce3e`，manifest SHA-256 为 `2e1ac871...eff8`。
- G36 新增无循环依赖的任务响应存储 factory，由 Agent `NewScanContext` 和 CLI legacy 初始化共同使用。只有无目标、`risk_validation` 或不超过 8 个明确 URL/IP:Port/Domain:Port、未启用 Hunter/FOFA/Quake/Subdomain 扩展且 `NoDirSearch/NoHostBind` 均为 true 的配置使用 memory；其余输入全部保守回退 disk。目录探测会按规则路径扩展响应，因此不能仅凭入口目标数进入无上限内存。策略判定不会展开 CIDR、IP range、端口范围或访问网络。
- Body/Header/Banner 三张 map 必须绑定同一不可变决策并保持每 Context 私有；第 2/3 张 map 构造失败时关闭此前全部资源，Context 完成或失败仍由既有 owner 关闭。`Reset()` 不清除或更换响应 map，避免暗改 CLI 连续执行语义；运行中动态 spill 与抽象所有消费者的可迁移 store 留给有独立基准证明必要性的后续设计。
- Nuclei Runner、compiled template 和 ExecutorOptions 含任务目标、回调、输出、代理/headers/变量、Interactsh 凭据与缓存、resume、取消和输入 HybridMap；当前全局结果/template cache 重置也不支持跨 Task 安全共享。因此 G36 的评估结论固定为不实施执行态缓存。风险验证继续逐次读取精确模板并校验规则版本、文件名和内容哈希，普通扫描仍 POC-off。
- 修复 Nuclei 非 HTTP 输入辅助 HMap 已创建、后续 HTTP runner 初始化失败时未关闭的错误路径；不改变正常执行、输入去重、模板选择或 Runner Close 所有权。
- 固定同一机器、Go、Arsenal/manifest、3 次预热和 30 次样本保存 after；小任务 P95 不得高于 before 的 110% 且必须 ≤500ms。测试覆盖策略边界、memory/disk 等价读写、部分构造失败回滚、Context 隔离、Windows 文件清理和可运行的 Linux race；最终执行 POC-off loopback CLI 与重建 Agent smoke。不得通过减少扫描阶段、规则或放宽 POC/EXP 安全默认达标。
- 最终同 Arsenal 3/30 after 的 P50/P95 均低于 Windows 计时分辨率，max 为 1.003ms；该零值只作为上界，不解释为零开销。高分辨率 factory 5 次基准中，memory P95 为 14.690µs，保留的 disk 路径 P95 为 52.674ms，生命周期开销下降 99.97%。Linux Docker `-race -count=10` 覆盖 taskstore/engine/common 通过；POC-off loopback CLI 返回 200，新 Agent 成功注册、同步 Arsenal 并建立订阅。
- 独立 review 首轮发现目录探测可把少量入口扩张为无界响应集合，已将 `NoDirSearch/NoHostBind` 同时为 true 固定为内存选择前提并新增回归；修复后复核无 Critical/Important。根模块完整测试中的 Agent timing 抖动、WindowsApps Python 9009、arsenal-sync Windows SQLite 句柄和 symlink 权限失败均为既有环境/测试问题，本 Goal 定向测试、vet、race 和 smoke 通过。

### Phase 5：CLI 兼容性、AI 接口和完整回归

| Goal | 状态 | 最小交付物 | 验收 |
| --- | --- | --- | --- |
| G37 | `completed` | 保留 argus 命令和通用扫描参数，统一 Argus Banner/版本/帮助/示例；已迁至 Server 的测绘参数只提供阶段性迁移提示并最终退出帮助 | 本地扫描旧参数兼容，Server-only 测绘能力不再由 CLI 执行，`--version` 正常且帮助无冲突描述 |
| G38 | `completed` | 稳定 `-ot json` Schema 和退出码 | JSON/非 TTY 无 Banner、颜色和无关日志 |
| G39 | `completed` | Task/Batch/Retry/Risk API Idempotency-Key 和预览绑定；按具体用户操作逐接口闭环 | 重放不重复创建，过期或变更预览被拒绝 |
| G39A | `completed` | 为 `POST /tasks` 和创建任务 UI 建立兼容的 Idempotency-Key 纵向闭环 | 无 Key 的旧客户端保持兼容；同作用域同 Key/同请求只创建并派发一次，同 Key/异请求 409；网络失败可安全重试，数据库/API/UI/真实 smoke 同 Goal 验收 |
| G39B | `completed` | 为 `POST /tasks/:id/append` 和“增加批次”UI 建立兼容的 Idempotency-Key 纵向闭环 | 无 Key 的旧客户端保持兼容；同 Task/操作者/Key 的同规范请求稳定重放首次追加结果且不重复派发，异请求 409；数据库/API/UI/PostgreSQL 并发与真实 smoke 同 Goal 验收 |
| G39C | `completed` | 为 `POST /tasks/:id/retry` 和“重试失败批次”UI 建立兼容的 Idempotency-Key 纵向闭环 | 响应丢失后同 Task/操作者/Key 可重放首次重试结果，不新增第二组 Attempt、审计或主动派发；数据库/API/UI/PostgreSQL 并发与真实 smoke 同 Goal 验收 |
| G39D | `completed` | 为 `POST /tasks/:id/batches/:batch_id/retry` 和单批次重试 UI 建立兼容的 Idempotency-Key 纵向闭环 | 同 Batch/操作者/Key 的同请求只追加一个 Attempt、一次审计和一次主动派发；响应丢失后稳定重放，异请求 409 |
| G39E | `completed` | 为 `POST /tasks/:id/risk-validation` 和风险验证确认 UI 建立 Idempotency-Key 与预览绑定闭环 | 同一已确认计划只创建并派发一次 risk-validation Batch/Attempt；同 Key 异选择冲突，新 Key 陈旧预览失败关闭 |
| G40 | `pending` | **用户暂缓**：AI 不可覆盖的目标、区域、POC、EXP 和预算策略 | 未经用户重新明确授权不创建或实施本 Goal |
| G41 | `completed` | 剩余非 AI 能力一次收口：测绘 Notebook 运营、授权范围内的租户/项目查询、Scanner/Agent Provider 旧链移除、文档与发布检查 | API/UI/迁移与兼容拒绝闭环；CLI/Agent 不持有 Provider 凭据或执行搜索；完整矩阵、PostgreSQL、浏览器和本地 CLI/Agent smoke 通过；独立 review 无 Critical/Important |

#### G41 具体边界与验收（Issue #164，用户授权合并收口）

- G40 及所有 AI Copilot 能力不在本 Goal 内。G41 不新增 AI 接口、模型调用、提示词、向量检索或 AI 驱动扫描策略。
- 已完成的 I164A–I164N 与 G39A–G39E 不重做。G41 只补齐尚未交付的非 AI 缺口：Notebook 的筛选、标签、备注、软移除/恢复与授权运营视图；彻底移除 Scanner/Agent 的 Hunter/FOFA/Quake 执行和凭据同步；同步文档并完成发布级验证。
- Notebook 条目仍以 tenant/project 为强边界，viewer 只读、operator 写入；标签、备注、移除、恢复都写脱敏审计。移除只退出默认列表，不删除来源、历史、分发意图、Task/Batch/Attempt 或结果；跨项目/跨租户对象必须失败关闭。
- 租户级运营读取只能聚合当前用户实际可访问的项目，不得把同租户身份等同所有项目授权；写操作仍绑定显式 project。查询必须有界分页、稳定排序和请求预算，不能暴露 Provider 表达式、凭据或原始响应。
- Server 是 Hunter/FOFA/Quake 的唯一执行与凭据边界。CLI 继续在参数解析早期拒绝旧 Provider flag 并提示迁移；Scanner Engine 不再包含 Provider 搜索阶段，Agent 不接收、读取、同步或持久化 Provider 凭据。遗留任务配置只能被明确拒绝或按兼容字段解码后失败关闭，不能静默发起第三方请求。
- 数据库变更使用追加 migration，保留旧字段/表以便回滚，不在同一 Goal 破坏性删除。API、RBAC、对象授权、CORS、审计和安全默认不得放宽；普通扫描、POC/EXP/风险验证语义不变。
- 验收覆盖 migration/schema、Server/Scanner/Agent、前端 lint/test/build/smoke、真实 PostgreSQL、登录浏览器 Notebook 操作，以及无外网 Provider 调用的 CLI/Agent 最小 smoke。完整回归若遇到平台既有失败，优先修复与当前发布路径有关且安全可控的基线；无法修复的环境限制必须给出可复现证据和替代验证。

#### G37 具体边界与验收（Issue #173）

- 当前 `4d4bfa2` 的 `argus -h/--help/help` 均返回 0，但显示旧 argus ASCII、`argus.version: 2.0.1` 和旧产品描述；`--version/-version` 为未知参数并返回 2，`version` 落入无目标扫描并返回 1。主帮助仍公开 Hunter/FOFA/Quake/低感知/仅 IP:Port 及分页参数，README 仍提供 CLI Provider 查询示例。
- G37 不重命名任何二进制、包、模块、目录或数据文件，不改变通用扫描 flag、目标解析、离线增量、规则管理子命令、扫描阶段、结果格式及 POC/EXP 安全默认。Banner、版本、主帮助和子命令说明统一使用 Argus 品牌，但所有可复制命令仍以真实二进制名 `argus` 展示。
- `argus --version` 必须在 Arsenal、历史目录和 ScanContext 初始化前返回 0；`-h/--help/help` 保持现有成功语义。黑盒测试只断言稳定品牌、版本、关键兼容 flag 和子命令，不冻结易变化的完整帮助快照。
- Standalone CLI 在任何参数位置识别旧 Provider 执行 flag 及长短别名（包括 `--flag=value`），输出项目级 Server“资产测绘”迁移提示并非零退出；这些 flag 从主帮助移除，守卫必须早于规则准备、API 配置读取和 Pipeline，测试不得访问 Provider 或外部网络。Engine/Agent 的旧配置字段和执行路径暂留给旧任务兼容，后续迁移不得借 G37 破坏旧 Agent。
- README 和资产测绘文档移除 CLI Provider 执行示例并说明 Server-only 边界；G38 才处理 JSON Schema、非 TTY Banner/颜色/日志和完整稳定退出码，本 Goal 不提前改变。

#### G38 具体边界与验收（Issue #174）

- 当前源码构建在安全 loopback、POC-off 扫描中返回 0，但 stdout 先写 Argus Banner 再写单条 finding JSON，stderr 含 ANSI、规则准备、Planner 和 HTTP 探测 Info；stdout 整体既不是单 JSON 文档，也不是纯 NDJSON。`-ot` 未严格校验，未知值会落入文本路径；无目标、初始化与执行错误又普遍混为 exit 1。
- `-ot json` 明确定义为 UTF-8 NDJSON。finding 保持流式输出和现有业务字段，但通过 CLI 专用 `argus.cli-output/v1` wire record 增加 `record_type`、单调 `sequence` 与 `finding`；不直接给共享 `OutputMessage` 增加协议字段，不改变 Agent 本地镜像、gRPC `ScanResult` 或 Server 解析。
- 一旦本地 Run 成功开始，扫描无论有无 finding 都必须在 stdout 最后写且只写一条 `run_summary`，至少包含 schema、sequence、run_id、status、exit_code 和 finding/coverage/difference 计数。参数或初始化在 Run 创建前失败时不伪造 summary，只在无 ANSI 的 stderr 输出必要诊断。
- JSON 模式不依赖 TTY，stdout 禁止 Banner、颜色、进度、人类耗时/差异摘要及普通日志。文本模式只在交互 TTY 显示 Banner、颜色和 Info；非 TTY 仍输出发现及必要错误，但不输出装饰与无关 Info。CLI presentation 配置不得全局改变 Agent 进程的日志和传输行为。
- 退出码稳定为：`0` 完成/help/version，`1` 执行或历史持久化失败，`2` flag/目标/输出类型等用法错误及 Server-only Provider 迁移拒绝，`130` 父上下文取消。首版不细分 3/4/70，避免把本 Goal 扩大为所有 Scanner 库 fatal 路径重构。
- 测试必须覆盖 JSON finding/summary 每行独立 decode、无 Banner/ANSI/无关日志、零 finding、非法 `-ot`、无目标、Provider 迁移、非 TTY 文本、结果文件和 stdout 契约一致，以及 Agent/gRPC 结构不变。真实 smoke 只使用 `127.0.0.1` 明确 URL并关闭 POC；独立 review 的 Critical/Important 必须修复后提交。

#### G39A 具体边界与验收（Issue #176）

- 本 Goal 只闭环“创建任务”这一条用户操作。`POST /tasks` 支持可选 `Idempotency-Key`，无请求头的旧客户端保留当前非幂等行为；Web UI 每次新的创建意图自动携带 Key。增加批次、Task retry、Batch retry 和风险验证分别留给后续独立纵向 Goal。
- Key 必须为 1–128 个可见 ASCII 字符，只在内存和请求头中出现；数据库仅保存 SHA-256。唯一作用域固定为 tenant + project + operator + `create_task_v1` + key hash；认证、operator RBAC、项目对象访问和 active 状态始终先于结果重放，Key 不得成为跨对象读取或授权凭证。
- 请求哈希基于版本化的规范语义：显式/项目范围目标来源、规范目标集合、规范安全配置、有效 priority/timeout、selector/rules、名称输入和 `skip_unsupported`；不包含原始 JSON 字节、随机 Task ID、时间、原始 Key、派发结果、凭据或 Provider 数据。同 Key/同规范请求返回首次 Task，同 Key/不同请求返回稳定 409 且零副作用。
- 幂等结果与 RootTask、TaskConfigRevision、TaskBatch、首个 Attempt、Project Scope/SeedTargets 扩展和单条 create 审计在同一数据库事务提交。任一步失败全部回滚且同 Key 可重试；仅首次创建在提交后调用队列，HTTP 重放不得再次主动派发。队列不可用或推送失败继续使用现有 `Dispatching` 恢复语义，不宣称消息 exactly-once。
- 重放响应保留原 Task ID、配置/目标/批次摘要和首次范围增量，并从冻结的首批 Attempt 当前状态重建 `dispatched/dispatch_pending`，避免恢复期间给出错误反馈。不得在幂等表复制目标、配置正文、跳过的原始无效输入或审计敏感数据。
- 前端一次提交生命周期只生成一个 Key：双击由本地锁抑制，网络/超时失败直接重试复用原 Key；成功、明确取消、项目或表单语义变化、409 冲突会使旧意图失效。预校验弹窗和项目切换不得提交陈旧请求；Key 不进入 body、URL、localStorage 或日志。
- 测试覆盖无 Key 兼容、首次创建、串行/并发重放、等价规范输入、同 Key 异请求、tenant/project/operator 隔离、项目失活/配额/审计失败回滚、队列不可用恢复、CORS、前端重试/冲突/陈旧意图。PostgreSQL migration/schema、Server、前端和登录浏览器真实 smoke 必须证明同一创建意图只有 1 个 Task/Batch/Attempt/create 审计；独立 review 的 Critical/Important 必须修复后提交。

#### G39B 具体边界与验收（Issue #178）

- 本 Goal 只闭环现有任务的“增加目标/批次”操作。`POST /tasks/:id/append` 支持可选 `Idempotency-Key`，无请求头的旧客户端继续使用当前 Task 内目标去重语义；Web UI 为每次新的追加意图自动生成 Key。Task retry、Batch retry 和风险验证仍是后续独立纵向 Goal。
- Key 必须为 1–128 个可见 ASCII 字符，只在内存和请求头中出现；数据库仅保存 SHA-256。唯一作用域固定为 tenant + project + task + operator + `append_targets_v1` + key hash。认证、operator RBAC、tenant/task/project 对象授权、归档与项目 active 校验始终保留，Key 不得成为跨对象读取或授权凭证。
- 请求哈希基于版本化语义、Task 身份和按有效 TaskConfigRevision 目标模式规范化、去空、去重、排序后的目标集合；URL 大小写、尾斜杠、目标顺序和重复输入不改变哈希。同 Key/同规范请求重放首次结果，同 Key/不同请求返回稳定 409 且零副作用；重放使用账本冻结的配置版本重新规范化，因此不因后续配置修订、增加批次或任务聚合变化漂移。
- 新增追加专用、不可变幂等账本，冻结首次结果的配置/规则版本、outcome、请求/新增/重复计数、Scope/SeedTargets 增量、追加后的 Task 总计数以及 Batch/Attempt ID。账本与 TaskBatch、首个 Attempt、Project Scope/SeedTargets、RootTask 聚合及单条 `batch_append` 审计在 RootTask → Project 锁顺序下同事务提交；任一步失败全部回滚且原 Key 可重试。原始目标、配置正文、凭据和原始 Key 不复制到账本。
- 只有首次新增在事务提交后调用队列；幂等重放绝不再次主动派发，并从冻结 Attempt 的当前状态反馈 `dispatched/dispatch_pending`。全重复首次请求也记录稳定 `unchanged` 结果，但不创建 Batch/Attempt、不扩展范围、不写 `batch_append` 审计或派发。暂停、完成、停止、归档和队列不可用继续遵守现有 append 生命周期与恢复语义。
- 前端一次追加提交生命周期只生成一个 Key：双击由本地锁抑制，网络/超时失败可直接以同一 Key 和 payload 重试；成功、取消、目标文本变化、切换 Task 或 409 冲突使旧意图失效。Key 不进入 body、URL、localStorage、日志或错误文案，前端不取代 Server 的目标规范化和授权判断。
- 测试覆盖无 Key 兼容、首次追加、全重复 unchanged、串行/并发重放、等价目标集合、同 Key 异请求、tenant/project/task/operator 隔离、暂停/完成/归档、事务失败回滚、派发恢复、CORS 和前端 Key 生命周期。Migration/schema 必须在临时 PostgreSQL apply/verify，并以两连接并发和登录浏览器真实 smoke 证明同一追加意图只有一组 Batch/Attempt、一次审计和一次主动派发；独立 review 的 Critical/Important 必须修复后提交。

#### G39C 具体边界与验收（Issue #179）

- 本 Goal 只闭环 Task 级“重试失败批次”操作。`POST /tasks/:id/retry` 支持可选 `Idempotency-Key`，无请求头的旧客户端保留现有状态机语义；Web UI 为每次新的任务重试意图生成稳定 Key。Batch 单独重试和风险验证继续作为后续独立纵向 Goal。
- 当前实现通常依靠 RootTask 行锁和首次提交后的 `Running` 状态阻止并发重复 Attempt，但首次事务成功、HTTP 响应丢失后，相同请求只会得到 409，无法确认首次结果。这是“缺少稳定 HTTP 重放”而不是“现状必然重复扫描”；实现不得借机改写现有重试选择或扩大扫描范围。
- Key 必须为 1–128 个可见 ASCII 字符，只在内存和请求头中出现；数据库仅保存 SHA-256。唯一作用域固定为 tenant + project + task + operator + `retry_task_v1` + key hash。认证、operator RBAC、tenant/task/project 对象授权和归档检查始终先于结果读取，Key 不是授权凭证。
- v1 请求没有 body 或可调参数；请求哈希绑定版本化 schema、作用域、operation 和固定 `force_retest=true` 语义。首次事务冻结实际创建的 Attempt ID、完成/暂停跳过计数和前后 Task 状态；同 Key 重放这些业务结果，未来若新增重试选项必须升级 operation/schema，不能悄然改变 v1。
- 只有失败、超时或已停止的当前 Batch 追加 `manual_retry` Attempt；成功 Batch、人工暂停或正在停止控制中的 Batch 继续跳过，已停止 Batch 保持可显式重试，risk_validation 规则漂移保护不变。幂等账本、新 Attempt、RootTask 状态和单条 `retry` 审计在同一事务提交，任一步失败全部回滚且原 Key 可重试。
- 只有首次提交后主动派发。重放即使 RootTask 已进入 `Running` 或队列暂不可用也返回首次结果，不再次调用队列或广播；`dispatch_pending` 仅投影首次 Attempt 当前状态，不属于冻结业务结果，也不能触发二次入队。新请求队列不可用仍在提交前失败关闭。
- 前端保留现有确认对话框且不新增参数；一次确认生命周期只生成一个 Key，双击由本地锁抑制，网络/超时后以相同 Task/Key 重试，成功、明确取消、切换 Task、非网络失败或 409 使旧意图失效。Key 不进入 body、URL、localStorage、日志或错误文案。
- 测试覆盖无 Key 兼容、首次/串行/并发重放、Root 已 Running 后重放、无效 Key、tenant/project/task/operator 隔离、完成/暂停/规则漂移、审计与账本失败回滚、队列恢复、CORS 和前端 Key 生命周期。Migration/schema 必须在临时 PostgreSQL apply/verify，并以双连接并发和登录浏览器真实 smoke 证明只有一组新 Attempt、一次审计和一次主动派发；独立 review 的 Critical/Important 必须修复后提交。
- 完成证据：Migration 450 已在全新 PostgreSQL 数据库完成 apply/verify；真实双请求并发只产生一组新 Attempt、一条 `retry` 审计和一条幂等账本。登录浏览器确认重试后 UI 从失败进入运行中并显示新增 1 个失败批次，数据库计数一致，验收任务随后停止并归档。Server/DB 定向测试、前端 129 项全量测试、lint、build、smoke 和独立 review 通过；Server 全量仅保留既有路由数量快照与 Windows `build.sh` 基线失败。

#### G39D 具体边界与验收（Issue #181）

- 本 Goal 只闭环任务详情中的单个 Batch 重试。`POST /tasks/:id/batches/:batch_id/retry` 支持可选 `Idempotency-Key`，无 Key 的旧客户端保留现有状态机；UI 一次确认意图生成并复用稳定 Key。Task 级重试保持 G39C 契约，风险验证执行留给紧随其后的 G39E。
- Key 作用域固定为 tenant + project + task + batch + operator + `retry_task_batch_v1` + key hash，数据库只保存 SHA-256。认证、operator RBAC、tenant/project/task/batch 对象授权与归档检查先于账本读取，Key 不是授权凭证。
- v1 请求没有 body，稳定请求哈希绑定版本化 schema、完整作用域和 `force_retest=true`。账本冻结首次新 Attempt ID/编号、配置版本、规则版本和前后状态；`dispatch_pending` 只投影该 Attempt 当前状态，不属于冻结业务结果，也不得触发二次入队。
- RootTask → TaskBatch → latest Attempt 锁顺序、可重试终态、人工暂停/停止控制、终态 Root 恢复和 risk-validation 规则漂移保护保持不变。幂等账本、新 Attempt、Batch/Root 状态和单条 `batch_retry` 审计同事务提交，任一步失败整体回滚。
- 只有首次提交后主动派发；重放即使 Batch 最新 Attempt 已非终态或队列暂不可用也返回首次结果，绝不再次派发。新请求队列不可用仍在业务写入前失败关闭。
- 前端按 task+batch 隔离 intent 与 in-flight 锁；网络/超时保留同一 Key，成功、取消、明确业务错误或 409 使其失效，旧任务/批次 Promise 不得释放新操作的锁或回写错误详情。
- 完成必须包含 Migration 460/schema、Server/API/DB、前端全量、PostgreSQL 双连接并发、登录浏览器真实失败 Batch smoke、验收数据归档和独立安全 review；不触发 POC/EXP 或真实目标。

#### G39E 具体边界与验收（Issue #180）

- G39D 聚焦提交完成后立即进入本 Goal，不再等待用户再次确认。只闭环风险验证“显式确认并执行”操作；preview 继续只读，普通扫描继续 POC-off，EXP 永不进入 Workflow。
- Execute 支持可选 `Idempotency-Key`。请求哈希完整绑定 tenant/project/task/operator、当前 `plan_hash`、规范化 specified POC、候选选择、授权确认和二次确认；同 Key 改变任一风险语义返回 409。新 Key 的陈旧 preview/config/rule/POC 内容仍须重新预览并失败关闭。
- 同 Key 同请求在对象授权和归档检查后优先读取已提交账本与物化结果，即使 Root 已 Running、规则随后变化或队列暂不可用也只重放首次已授权结果；绝不重新解释计划、创建 Batch/Attempt、写审计或入队。
- 首次执行仍完整重建 preview 并复核 Task/Project 状态、配置/规则/POC 内容、风险等级、二次确认和安全预算；幂等 intent/materialization、精确 risk-validation Batch/Attempt、Root 更新和单条审计同事务提交，提交后才派发。
- 前端一次风险确认生命周期复用同一 Key；网络/超时保留，重新预览、候选或确认变化、成功或冲突使旧意图失效。完成 Migration 470、PostgreSQL 并发、Server/UI/浏览器、独立 review 后将总项 G39 标记 `completed`，不再创建新的 G39 子项。

#### I164N 具体边界与验收（Issue #164）

- 这是 I164L 只读预览与 I164M 不可变意图之后的单条纵向闭环。只新增“确认并分发到现有 Task”操作，不创建新 RootTask，不扩展 Provider、笔记本标签/备注/移除，也不改变 CLI/Agent 的测绘兼容链路。
- 请求必须由 operator 发起并携带 1–128 个可见 ASCII 字符的 `Idempotency-Key`、同项目 Task、1–100 个笔记本 item ID 和当前 `plan_hash`。Server 在统一请求预算内重新读取并校验 project/task/items、当前配置和规则版本、任务可追加状态与 direct 安全模式；operator 的确认明确授权本次新增目标扩展当前项目范围，但不能覆盖任务既有 Agent selector、network zone 隔离或 POC/EXP 风险策略。笔记本存在或旧 intent 均不单独构成授权或确认。
- 事务内重新计算 I164L 计划；任何 item、现有目标、任务状态、配置、规则、项目范围或策略变化使旧 `plan_hash` 返回稳定冲突且零写入。相同 tenant/project/operator/operation/key 的相同请求回放首次结果，不同请求返回冲突；原始 key、Provider 查询/响应、凭据和客户端原始 body 不落库。
- 对 fresh 目标在一个数据库事务内完成：记录/重放 I164M intent 与逐项快照，锁并扩展 Project Scope/SeedTargets，追加稳定 TaskBatch 及首个 Attempt，按现有生命周期更新 RootTask，写含 intent、计数、配置/规则版本和批次 ID 的脱敏 TaskAudit。任一步失败全部回滚；全重复选集返回明确 unchanged 且不产生 Batch/Attempt、Scope 变化或队列派发。
- 事务提交后才派发新 Attempt；推送失败保留 `Dispatching` 供现有恢复器补投。幂等重放不得再次盲目入队，并以已冻结 Attempt 的当前状态重建 `dispatched/pending`，避免队列不可用时把待恢复工作误报为零。暂停任务新增批次保持暂停且不派发；完成任务有 fresh 目标时按现有 append 语义重新进入运行态；POC/GoPoc/EXP 始终关闭且不得借分发改变任务风险模式。
- 前端必须复用 I164L 预览，在预览成功后才开放确认；一次确认生命周期生成并复用同一幂等键，成功/冲突/过期/派发待恢复均给出明确反馈并刷新任务、预览和笔记本状态。viewer、归档项目和无权用户无确认入口。真实 API 与登录浏览器 smoke 必须证明只创建一次批次并可在任务详情看到来源；Server/API/DB、前端、PostgreSQL migration/schema、CORS、RBAC、审计和独立只读 review 同 Goal 完成。

## 接口与数据模型约束

- 新增 `TaskBatch`、`TaskConfigRevision`、`TaskAudit`、`ScanObservation`、`ScanCoverage`、`ScanWorkClaim`、`TaskCoverageLink`。
- `RootTask` 增加当前配置版本和归档时间；`SubTask` 增加 BatchID、AttemptNo、配置版本和规则版本。
- 归档与运行状态分离；归档对象不参与默认列表或进度聚合，但历史和结果保留。
- 保持现有 `POST /tasks`、pause/resume/cancel/delete 兼容；DELETE 改为归档，cancel 作为 stop 兼容别名。
- 新增配置修订、Batch 列表/增加/控制/重试/归档、Attempt 历史及风险验证预览/执行接口。
- 所有写接口校验 tenant、project 及对象归属，支持幂等键并写审计。
- 数据迁移按“新增 → 回填 → 双写验证 → 切换读取”实施；本计划内不删除旧字段，旧 Agent 必须保持兼容。

## Goal 完成规则

每个 Goal 必须同时满足：

1. 实现和验收标准一致，无越界改动。
2. 更新本文件中的状态、验证证据、提交和变更日志。
3. 运行最小充分测试；不能运行的检查记录环境限制与替代证据。
4. 检查 diff 不包含敏感信息、缓存、生成物和无关格式化。
5. 安全敏感 Goal 验证 tenant、project、RBAC、审计、危险操作确认和安全默认值。
6. 每阶段提交或合并前完成独立只读 review，Critical/Important 反馈必须解决或记录取舍。

## 验证矩阵

- Server/API：相关包测试，阶段结束 `cd server && go test ./...`。
- Scanner/Agent/CLI：相关包测试，阶段结束根模块 `go test ./...`。
- Frontend：目标测试；阶段结束运行 lint、全量 test 和 build。
- Schema/migration：`make db-verify`。
- 浏览器：任务创建、管理、风险验证和复用说明真实 smoke。
- 性能：固定本地安全靶场记录 P50/P95，不扫描外部目标，不无故执行 POC/EXP。
- 跨模块或最终阶段：`make ci`。

## 风险与回滚

- TaskBatch/Attempt 迁移先添加表和字段并回填，切换前保留旧读写路径；回滚应用版本时保留新增表，不做破坏性逆迁移。
- 去重只在完整、兼容、未过期覆盖上生效；unknown/failed/partial 一律重新规划。
- Project 目标扩展只允许有管理权限的当前项目成员，并记录原范围、新范围和操作者。
- POC 必须经显式风险验证向导；普通扫描和 Workflow 匹配本身不得触发执行。
- CLI TSV 默认不保存完整敏感响应正文，只保存结构化发现、哈希和必要证据摘要。

## 验证证据

| Goal | 日期 | 结果 | 证据 |
| --- | --- | --- | --- |
| G00 | 2026-08-09 | PASS | UTF-8 读取正常；Markdown 代码围栏成对；G00-G41 完整；`git diff --check` 通过 |
| G01 | 2026-08-09 | PASS | TaskManagement 目标测试 9/9；TypeScript build 通过；目标文件 ESLint 0 error（1 个既有 Hook warning）；登录态浏览器 smoke 成功加载任务页，当前项目无任务行，菜单交互由测试覆盖 |
| G02 | 2026-08-09 | PASS | Server db/api 状态与生命周期测试通过；grpc/server command 编译通过；前端状态与任务测试 18/18；TypeScript build 通过；ESLint 0 error（1 个既有 Hook warning）；浏览器 smoke 通过任务页与 Dashboard |
| G02A | 2026-08-09 | PASS | 全量前端测试 77/77；TypeScript build 与 Vite production build 通过；全量 ESLint 0 error（15 个既有 Hook warning）；源码、manifest 和 lockfile 无 GSAP 引用；浏览器 smoke 通过登录页、任务页与 Dashboard，登录页 CSS 动态视觉截图复核正常 |
| G03 | 2026-08-09 | PASS | Server db/api 归档、审计、状态、RBAC 与统计目标测试通过；PostgreSQL migration apply/verify 通过；前端任务管理测试 11/11、全量测试 79/79、TypeScript 与 Vite build 通过、ESLint 0 error（15 个既有 Hook warning）；新 Server 已本地重启。完整 Server 测试仅有 2 个与本 Goal 无关的既有 Windows 限制失败（临时 arsenal.db 文件锁、build.sh 无法原生执行）；验证浏览器未继承登录会话，登录态 smoke 延后至下个可用会话 |
| G04 | 2026-08-09 | PASS | TaskConfigRevision、配置哈希、v1 创建/回填、配置更新、追加目标、AI 草稿、项目/租户/归档边界和二分重试版本继承测试通过；PostgreSQL migration apply/verify 通过；任务管理目标测试 12/12、全量前端 80/80、TypeScript/Vite build 通过、ESLint 0 error（15 个既有 Hook warning）；新 Server 已重启且 `/health` 200、未认证任务接口 401。完整 Server 测试仅有 2 个既有 Windows 限制失败；验证浏览器可达登录页但未继承会话，配置 UI 的真实登录态 smoke 延后 |
| G05 | 2026-08-09 | PASS | TaskBatch schema/迁移契约、创建/追加双写、Attempt 关联、二分批次、调度/认领/完成状态同步及旧 Agent 兼容目标测试通过；真实 PostgreSQL migration apply/verify 通过；新 Server 已重启且 `/health` 200、未认证任务接口 401、RabbitMQ/gRPC 正常；`go test ./...` 除 2 个已记录的既有 Windows 限制外全部通过 |
| G06 | 2026-08-09 | PASS | 追加式重试、二分重试、超时恢复、Agent 离线/Spot 恢复、最新 Attempt 聚合、详情历史、认领/完成证据及重复重试防护目标测试通过；真实 PostgreSQL migration apply/verify 通过；前端 81/81、TypeScript/Vite build 通过、ESLint 0 error（15 个既有 Hook warning）；新 Server 已运行且主页 200、未认证任务接口 401，登录页 smoke 通过；`go test ./...` 除 2 个既有 Windows 限制外全部通过，因登录令牌轮换，任务历史的已登录浏览器 smoke 延后到重新登录后 |
| G07 | 2026-08-09 | PASS | 目标规范化/校验、同任务去重、完成任务重启、暂停任务保持暂停、项目归属/活动状态、配置版本继承、Project Scope/SeedTargets 扩展及追加审计测试通过；前端全量 82/82、TypeScript/Vite build 通过、ESLint 0 error（15 个既有 Hook warning）；新 Server 已运行且未认证任务接口 401，Agent gRPC 订阅恢复；浏览器确认登录页 Argus 表单、Canvas 和 CSS 动效正常，因当前会话未登录，已登录增加批次 smoke 由新增 UI 测试覆盖；`go test ./...` 仅有 2 个既有 Windows 限制失败（临时 arsenal.db 文件锁、build.sh 无法原生执行） |
| G08 | 2026-08-09 | PASS | Batch 列表、暂停/恢复/立即停止/显式重试/归档、正交控制状态、追加式 Attempt、暂停期间禁用自动恢复、Agent 取消、租户/项目归属、RBAC、审计和归档进度排除的目标测试通过；真实 PostgreSQL migration 330 apply/verify 通过；前端全量 83/83、TypeScript/Vite build 通过、ESLint 0 error（15 个既有 Hook warning）；新 Server 已运行且未认证任务接口 401，Agent gRPC 订阅恢复；浏览器确认登录页 Canvas 与 21 个 CSS 动画元素仍正常，当前会话未登录，批次菜单交互由新增 UI 测试覆盖；`go test ./...` 仅有 2 个既有 Windows 限制失败（临时 arsenal.db 文件锁、build.sh 无法原生执行） |
| G09 | 2026-08-09 | PASS | 任务级暂停/恢复/停止/重试仅作用于未归档 Batch 的最新 Attempt；暂停期间失败保持暂停并在恢复时追加 Attempt，用户单独暂停的 Batch 不被任务恢复覆盖；暂停态可立即停止，停止中的 RootTask 不会回退运行态；显式重试仅追加失败/超时/停止批次并跳过成功批次；`stop` 规范接口与 `cancel` 兼容别名、租户/项目归属、RBAC、审计和 Agent 取消行为目标测试通过；前端全量 84/84、TypeScript/Vite build 通过、ESLint 0 error（15 个既有 Hook warning）；新 Server 已运行且未认证任务接口 401，Agent gRPC 订阅恢复；`go test ./...` 仅有 2 个既有 Windows 限制失败（临时 arsenal.db 文件锁、build.sh 无法原生执行） |
| G10 | 2026-08-09 | PASS | Server 空配置采用安全 `external-map` 档，默认 P1/3600 秒并关闭 POC、通用 POC、子域爆破、目录与密码探测；省略目标时复用已授权 Project SeedTargets/Scope，直接新目标在同一事务扩展项目范围并记录创建审计，显式 P0/零超时仍保留；目标、租户/项目归属与安全默认的目标测试通过。前端仅需目标即可创建，项目自动选择、名称可省略、Agent 自动预览，人工调度/付费测绘源/扫描细项折叠到高级设置；前端全量 85/85、TypeScript/Vite build 通过、ESLint 0 error（15 个既有 Hook warning）。新 Server PID 36356 已运行且未认证任务接口 401；浏览器确认登录页仍有 1 个 Canvas 与 21 个 CSS 动画元素，当前浏览器会话停在登录页，任务弹窗真实 smoke 由认证状态阻塞并以 UI 测试替代；Server 全量 API 仍仅有 2 个既有 Windows 限制失败（临时 arsenal.db 文件锁、build.sh 无法原生执行） |
| G11 | 2026-08-09 | PASS | Server、Agent 导出包与 CLI `arsenal.db` 统一携带 `execution_class/risk_level`；旧 POC 物化为 `detection + unknown`，高风险/未分类规则标记二次确认，POC 中的 `exploit/exp` 分类在保存、审批和 CLI 导入边界被拒绝。定向 DB/API/Scanner 治理测试通过；Server/Scanner 全模块仅编译通过；前端全量 86/86、TypeScript/Vite build 通过、ESLint 0 error（15 个既有 Hook warning）；PostgreSQL 新增迁移 340 apply/verify 通过且已发布迁移保持不可变。完整 Arsenal 包测试的字段断言通过后仍在 Windows 临时 SQLite 文件删除阶段命中既有句柄锁限制。 |
| G12 | 2026-08-09 | PASS | 新增只读风险验证预览 API/UI：按当前任务新旧结果布局合并指纹与资产，仅解析当前租户已审核启用的 Workflow/POC，返回资产/端点/产品/严重性/执行风险、规则与配置版本、POC 内容哈希、请求量上界和稳定计划哈希；测试确认 viewer 可读、项目越权拒绝、其他租户数据隔离，且不创建 Batch/Audit 或执行 POC。API/路由契约目标测试通过，Server 全模块编译通过；前端全量 87/87、TypeScript/Vite build 通过、ESLint 0 error（15 个既有 Hook warning）。完整 Server 测试除临时 arsenal.db Windows 句柄锁及 build.sh 无法原生执行两个既有环境限制外通过；新 Server PID 39792 已运行，未认证预览接口 401；当前浏览器停在登录页，登录页动效保持不变，风险预览交互以新增 UI 测试覆盖。 |
| G13 | 2026-08-09 | PASS | 新增 operator 风险验证执行 API/UI：支持 Workflow 与指定已审核 POC，重新校验计划、租户/项目归属、任务终态、规则/配置版本和确认状态，在原 Task 追加不可变 `risk_validation` Batch/Attempt、关闭自动重试并写审计；Scanner 仅运行精确 Nuclei 映射。Agent v2.4.0 能力门槛、规则版本和实际 POC MD5 三重校验阻止旧节点或内容漂移；规则变更要求重新预览，完成的历史风险批次不会阻塞无关资产批次重试。Server API/gRPC、Scanner Engine/Agent 定向测试通过；前端 19 files/88 tests、TypeScript/Vite build、ESLint 0 error（15 个既有 warning）通过；完整 Server 测试仅两个既有 Windows 环境限制失败。新 Server/Agent 已本地重建并重启，未认证预览/执行接口均为 401；浏览器确认登录页 1 个 Canvas、21 个 CSS 动画元素、0 个 GSAP 脚本。 |
| G13A | 2026-08-09 | PASS | 复核发现普通任务仍能通过 `NoPoc=false`、GoPoc 或模糊 POC 名称绕过确认；现已在任务配置 API 拒绝并从创建 UI 移除 POC 开关，Server Agent 领取阶段会消费并失败关闭旧队列中的未确认 POC，Agent 在 Scanner 初始化前再次拒绝，同时将缺省/`{}` Agent 配置收敛为 POC-off。Server API/gRPC、Scanner Agent 定向测试和前端全量 19 files/88 tests 通过；本地 Server/Agent 重建重启后 Agent 注册及 Arsenal 同步成功，未认证风险预览/执行接口均为 401。 |
| G14 | 2026-08-09 | PASS | 新增无持久化副作用的 `argus.scanplan/v1` 共享 Go 契约，四类场景、12 个稳定 Stage、有向无环 Plan、固定维度 WorkKey、追加式 Observation 和 Coverage 均有验证；风险验证 Plan 只能强制执行独立风险阶段，未知 Scanner Phase 不会静默视为覆盖。共享模块全量测试、Scanner 阶段适配测试和 Server 创建任务目标测试通过，`git diff --check` 通过。 |
| G15 | 2026-08-09 | PASS | 新增 `scan_observations`、`scan_coverages`、`scan_work_claims`、`task_coverage_links` GORM 模型与 additive migration 350；观测可追加且 source event 在租户内幂等，Coverage/Claim/Link 唯一键均显式包含 tenant/project。Server DB 包全量测试通过；真实 PostgreSQL apply + verify 通过。完整 Server 测试除已记录的 Windows 临时 arsenal.db 句柄锁和 build.sh 原生执行限制外通过；新增存储尚未接入调度读取，旧 Agent 不会被误判为已有覆盖。 |
| G16 | 2026-08-09 | PASS | Agent v2.5.0 将 legacy Phase 显式映射为规范 Stage，以现有 StreamResult 的 `coverage_event` 上报分配目标、success/negative/failed/skipped、真实规则版本、配置/内容哈希和阶段时间；内容摘要按输出哈希排序，避免并发到达顺序造成伪变化。Server 校验 schema、外层 task_id、活动 Attempt、已分配 Agent 与目标子集，且不接受 Agent 声明 tenant/project/network zone；旧 Agent 仅有 phase 时保持 unknown。共享契约、Agent reporter/worker、Server gRPC 定向测试通过；Agent 全包另有既有 Windows SQLite 句柄锁和本机 Python scratchpad unavailable 失败。 |
| G17 | 2026-08-09 | PASS | Server 归并器从数据库 Project Scope、配置修订、Attempt/Agent/规则版本重算 WorkKey，按目标派生幂等事件 ID 并在单事务内追加 Observation、维护当前 Coverage；相同事件重放无写入，ID 相同但证据不同被拒绝，旧事件不覆盖新证据。success/negative 仅在快照一致时 complete，failed/skipped 为 incomplete，配置/规则漂移或风险验证缺少 POC/端点内容维度为 invalidated。Server DB 与 gRPC 包全量测试通过，调度尚未读取 Coverage。 |
| G18 | 2026-08-09 | PASS | `ClaimTask` 在确定 tenant-bound Alive Agent 后按完整目标匹配有效 Coverage；全量命中原子完成 Attempt/Batch、ACK 队列且不占 Agent 容量，RootTask 按稳定 Batch 目标聚合完成；部分命中仅返回候选，提交前重新锁定 Root/Batch/Attempt/Project/Coverage 并复核快照，再把剩余目标、Agent 租约和 reused links 同事务提交，避免跨 Agent 私网竞态。手动重试、风险验证、非活动对象、旧不完整配置、过期/失败/失效/跨租户项目网络区及 Scope/Config/规则漂移均不复用。`go test ./internal/db ./internal/grpc -count=1` 通过；`go test ./... -count=1` 仅保留既有 Windows 临时 `arsenal.db` 句柄清理和 `build.sh` 原生执行两项失败。 |
| G19 | 2026-08-09 | PASS | 普通资产 Attempt 对每个剩余目标按 fingerprint WorkKey 规划完整流水线互斥，在最终 Agent 租约事务中排序、原子创建或回收唯一 WorkClaim，并写 `executed` 关联；后续同 WorkKey Attempt 写 `in_flight/waiting` 关联、ACK 队列且不占 Agent 容量。来源完成后等待者重新进入 Coverage Planner，来源失败/超时/停止后也自动重新竞争，不复用失败；队列失败保留 Dispatching，周期恢复收敛非 RPC 终态。手动重试、风险验证、未知旧配置与不同 tenant/project/network zone 固定绕过或隔离。DB、gRPC 和恢复服务目标测试通过；`go vet ./internal/db ./internal/grpc ./internal/api` 通过；`go test ./internal/db ./internal/grpc -count=1` 与恢复目标测试通过。Server API 全量测试仍仅有既有 Windows 临时 `arsenal.db` 句柄清理和 `build.sh` 原生执行两项失败。 |
| G20 | 2026-08-09 | PASS | Server 从数据库 Node 标签和每个规范目标派生 network zone：公网 IP/CIDR/范围及无私网标签的普通 DNS 使用 `public`，私网/特殊地址/split-horizon DNS 使用 `private:<network_zone>`，无标签私网回退 `agent:<agent_id>`；`network_scope=public` 不得提升私网 IP 或保留域名。Observation 归并、Coverage 复用、租约复核与 WorkClaim 使用同一策略；测试覆盖跨 Agent 公网共享、同标签私网共享、不同标签及无标签私网隔离。`go test ./internal/db ./internal/grpc -count=1`、`go vet ./internal/db ./internal/grpc` 和 `git diff --check` 通过。 |
| G21A | 2026-08-09 | PASS | 新完成 Coverage 按阶段写入 Server TTL：存活 5 分钟、端口 1 小时、发现/协议/Web/目录/指纹 6 小时、风险验证 24 小时；失败/跳过/失效证据无有效期且不可复用。Scope、配置、规则和网络区域变化因 WorkKey 不匹配安全补扫；相同 WorkKey 的上游内容变化只失效较旧依赖 Coverage，乱序旧事件不推翻更新证据。`manual_retry` 同时绕过历史复用与 WorkClaim，新 Attempt 仍追加 Observation 并更新当前 Coverage。`go test ./internal/db ./internal/grpc -count=1`、`go vet ./internal/db ./internal/grpc` 和 `git diff --check` 通过；`go test ./... -count=1` 仍仅有既有 Windows 临时 `arsenal.db` 句柄清理与 `build.sh` 原生执行两项失败。 |
| G21B1 | 2026-08-09 | PASS | `argus.checkpoint/v1` 为单目标成功/阴性阶段保存最多 4096 个排序去重的存活 IP、开放端点、协议服务、无凭据 URL 或域名；多目标、失败/跳过、不支持 Stage、越出已分配 IP/CIDR/范围/URL authority/host:port/域名后缀的数据均不接受，域名解析 IP 在没有可信映射前不存储。检查点不含正文/Header/凭据，规范哈希绑定 Event ID 与 Observation evidence；migration 360 仅新增 `checkpoint/checkpoint_hash`，已在本地 PostgreSQL apply + verify。共享契约、Agent reporter/worker coverage、Server DB/gRPC 定向测试及 Server vet 通过；Agent 全包仍有既有 Windows SQLite 句柄清理和 Python scratchpad 环境失败，Agent vet 仍命中既有 protobuf lock-copy 测试告警。 |
| G21B2 | 2026-08-09 | PASS | 新增 `argus.resume-plan/v1` 单目标契约与 Server 最小依赖 Planner：计划把完整阶段顺序严格分为复用前缀和执行后缀，并把检查点绑定 WorkKey、Coverage、Observation 与规范哈希。有效端口检查点可恢复协议阶段，有效协议检查点可恢复 HTTP；HTTP 后续因未保存正文而回退 HTTP，域名链因缺少可信 DNS 映射回退起点。多目标、手动重试、风险验证、来源未完成、失败/过期/漂移 Coverage 及损坏检查点均不跳阶段。共享契约、Server DB/gRPC 测试及 vet 通过；完整 Server 测试仍仅有既有 Windows 临时 `arsenal.db` 句柄清理和 `build.sh` 原生执行两项失败。B2 只生成计划、不改变 Agent 当前完整流水线。 |
| G21B3 | 2026-08-09 | PASS | Server 在最终 Agent 租约事务内锁定并重建恢复计划，只有 v2.6.0+ 且规则版本一致的 Agent 才接收内部恢复信封；旧 Agent 和规则漂移 Agent 保持完整扫描。Agent 独立按实际 Config/目标/规则重建阶段、校验摘要和检查点依赖，恢复端口/协议输入并只执行、上报后缀；复用前缀不会被错误上报为 skipped。计划、TTL、来源或信封篡改均失败关闭。Engine/Agent/Server 定向测试、Server DB/gRPC 全包与 vet 通过；Scanner/Agent 全包仍仅有既有 Windows SQLite 句柄清理和 Python scratchpad 环境失败。 |
| G22 | 2026-08-09 | PASS | 任务详情新增 `argus.task-coverage-explanation/v1`，完整汇总实际执行、历史复用、当前等待来源、失效/过期以及节省的阶段/完整目标，最近 100 条明细可追溯同项目来源 Task/Batch/Attempt；关联、Coverage、Claim 和来源名称查询均重施 tenant/project 边界，不暴露 WorkKey、配置哈希或租约。Server API 定向测试与 vet 通过；前端目标测试 20/20、全量 19 files/89 tests、TypeScript/Vite build、ESLint 0 error（15 个既有 warning）通过。完整 Server API 仍仅有既有 Windows 临时 arsenal.db 句柄清理与 build.sh 原生执行两项失败。浏览器确认登录页 1 个 Canvas、21 个 CSS 动画元素、0 个 GSAP 脚本；当前会话停在登录页，任务详情已登录 smoke 由新增 UI 测试覆盖。 |
| G23 | 2026-08-09 | PASS | 新增 CLI-only `localstate` 根目录解析：默认使用真实可执行文件同级 `argus-data`，`ARGUS_HOME` 支持绝对路径及按启动工作目录解析的相对路径；扫描初始化以 `0700` 幂等创建并保存到 `ScanContext.LocalDataRoot`，已有文件不改写，Agent 不进入该路径。路径、覆盖、缺失基准目录、幂等保留与文件冲突测试通过；CLI/config 编译、localstate 全量测试和 vet 通过。根模块全量测试未出现 G23 回归，仍失败于既有 Windows SQLite 句柄锁、Python WindowsApps 占位运行时、symlink 权限限制。 |
| G24 | 2026-08-09 | PASS | 新增 `argus-tsv/v1` 长期 assets/coverage 表和每次运行独立 summary/targets/findings/coverage；损坏或版本不兼容表头失败关闭且不覆盖，字段转义保持一条物理行，并发输出由运行级互斥串行写入。CLI 输出观察器不改变 Agent 模式；Nuclei 原始请求/响应、packet、Interactsh、复现命令、提取内容以及 GoPoc 凭据/命令详情不落盘，URL 用户信息与查询信息已脱敏。localstate 全量测试、engine 观察器定向测试、CLI/config 编译、相关 vet 和 diff check 通过；关闭 POC 对 `http://127.0.0.1:3000` 的真实 CLI smoke 在 D 盘生成完整六类文件并记录 1 条 Web 发现。根模块全量回归仍仅失败于既有 Windows SQLite 临时句柄、WindowsApps Python 占位运行时和 symlink 权限限制；`-race` 因当前 Go 环境禁用 CGO 未运行。 |
| G25 | 2026-08-09 | PASS | Run summary 和长期 TSV 使用同目录临时文件、文件刷盘与平台原子替换；Windows `MoveFileEx(REPLACE_EXISTING|WRITE_THROUGH)` 和 Linux 非执行交叉编译通过。跨进程状态锁避免并发丢失，运行级 OS 锁阻止恢复器接管活跃 CLI；失锁 `running` 标为 interrupted 且不归并，`finalizing` 与 G24 旧终态可幂等恢复。资产按本地区域/目标折叠并保留最早 first_seen，旧 last_seen/coverage observed_at 不覆盖新证据；损坏/重复/语义无效数据行告警后清理，坏表头继续失败关闭，URL 敏感信息在 coverage 边界失败关闭。故障注入验证替换失败保留旧文件，并发完成、中断不污染、终态恢复、旧历史升级、损坏行、乱序和摘要原子测试全部通过；localstate 全量测试、CLI/config 编译、相关 vet、diff check 通过。真实 CLI smoke 在 D 盘把 G24 旧 Run 升级为 merged，并以新 Run 更新同一 `127.0.0.1:3000` 资产；根模块全量回归仍仅失败于既有 Windows SQLite 句柄、WindowsApps Python 占位运行时和 symlink 权限限制。 |
| G26 | 2026-08-09 | PASS | 新增 CLI-only `internal-fast` Planner、长期状态一致快照、目标 full/incremental 决策、阶段旁路观察和本地 WorkKey 覆盖；普通扫描默认 POC-off，显式 `-poc/-gp` 固定全扫。有效端口覆盖仅在 IP/CIDR/IP 范围、相同配置/规则、TTL 有效、有界端口检查点和 TCP 轻量复核完全一致时恢复，任何未知、过期、失败、变化或校验错误安全回退。Planner/localstate 目标测试连续 5 次、Engine resume/observer 定向测试、相关 vet、CLI build 和 diff check 通过。D 盘真实 CLI 对 `127.0.0.1 -p 3000 -Pn -nd -npoc` 首跑建立覆盖，复跑的 `targets.tsv` 为 `incremental/known_services_revalidated`，端口记录为 `reused` 且协议/Web/指纹为 `executed`；范围外 445 开放不会干扰显式 3000 端口范围。暖运行仍约 5.9 秒，确认启动准备是后续 G31-G36 的独立性能问题。根模块全量回归未出现 G26 新失败，仍失败于既有 Windows SQLite 句柄、WindowsApps Python 9009 和 symlink 权限限制。 |
| G27 | 2026-08-09 | PASS | 首次扫描在本地数据根原子生成 `argus-local-policy/v1` 配置，严格拒绝未知/缺失字段、多 YAML 文档、符号链接、无效 TTL/超时/并发/端点预算/端口。默认 TTL 为 liveness 5m、port 1h、protocol/web/fingerprint 6h、risk validation 24h；已知服务与已知主机每次按 200ms、64 并发、512 端点和 80/443/3389/445/22 复核，范围外存活端口不扩张 `-p` 服务范围。轻量复核写 `tcp_liveness executed`，端口写 `reused`，风险阶段合并 Nuclei/GoPoc 多个 legacy phase 后使用风险 TTL。策略参与 ConfigHash，修改即使旧覆盖失配。localstate/localplanner 连续 5 次测试、Engine POC/风险阶段与恢复定向测试、相关 vet、CLI build、diff check 通过。D 盘真实双跑生成完整配置，第二次目标为 incremental，覆盖包含 5m 存活执行、1h 端口复用和 6h 下游执行。根模块全量回归无 G27 新失败，仍仅受既有 Windows SQLite 句柄、WindowsApps Python 9009 与 symlink 权限限制影响。 |
| G28 | 2026-08-09 | PASS | 新增唯一可选参数 `-force`，经 `common.Flag → config.InitCLI → ScanContext.LocalForceFullScan → localplanner` 的 CLI-only 链路绕过本地 Coverage/ResumePlan；不修改 Scanner Config、WorkKey、目标、端口或 POC 安全默认。Planner 测试确认有效覆盖也不执行预复核且生成 `full/force_full_scan`，Context Reset 保留 force。localplanner/localstate 连续 5 次、common/config 编译、Engine 定向测试、相关 vet 和 diff check 通过。D 盘以已有有效覆盖真实运行 `-force` 后重新出现 Port 输出，Run 覆盖全部为 executed、reused=0，帮助页显示参数且日志继续“跳过漏洞探测”。 |
| G29 | 2026-08-09 | PASS | CLI 正式加载固定离线 `argus-data/arsenal/arsenal.db`，变化后严格校验并原子物化，扫描和 finger/poc/workflow 子命令共享同一 DB；文件/语义双 SHA-256、v1 manifest、最多三份 DB/配置快照支持解释与回滚，损坏替换不会覆盖已物化规则。发行构建从与 Server seed 相同的 `scanner/common/config` 批量生成 9087 指纹、2519 个非空 POC、3048 映射和 57 条主动探针的可复现运行时 DB，两次构建的文件及语义 SHA-256 完全一致，构建从超 120 秒降至约 5 秒；正式 CLI 使用 `noembed` 避免重复 POC，并产出包含 argus.exe 和固定 DB 的压缩包。目标 Go 测试、Engine/Agent 规则同步、Git Bash 语法与真实发行构建通过；D 盘从正式 noembed 压缩包真实启动加载 9087 指纹并继续 POC-off，首次物化约 5.2 秒、复跑约 637ms，`finger count` 返回 9087。Agent/根模块仅余既有 WindowsApps Python 9009、tools/arsenal-sync seed DB 句柄及 symlink 权限失败，本次涉及的 Scanner/Agent `arsenal.db` 句柄锁已消除。 |
| I165 | 2026-08-09 | PASS | 复现确认共享 `DefaultConfig` 与 CLI flag 默认值分裂；按已确认安全边界将共享默认统一为 `NoPoc=true`、`GolangPoc=false`、`DisableGeneralPoc=true`。CLI Planner 测试确认普通扫描安全关闭且显式 `-gp/-poc` 保持风险操作，Agent 测试确认普通任务拒绝未确认 POC，Server API 测试确认风险验证仍可显式开启精确 POC。`scanner/structs`、localplanner、Agent、Engine 和 Server 风险定向测试通过，`git diff --check` 通过；根模块全量仅保留既有 WindowsApps Python 9009、tools/arsenal-sync SQLite 句柄和 Windows symlink 权限失败。Agent vet 仅命中既有 protobuf 测试 copylocks 告警。Issue #165 原“默认开启弱口令爆破”验收因违背当前安全策略按 `not_planned` 处置。 |
| G30 | 2026-08-10 | PASS | 每个 CLI Run 新增严格版本化、稳定排序且先于长期状态写入的 `delta.tsv`，记录新增、可比变化、确认消失、未评估、阶段执行和阶段复用；summary 向后兼容新增计数，文本模式输出简洁摘要，`-ot json` 端到端实测无该人类摘要。消失要求 completed/full、权威 executed success/negative、目标归属和 scope/config/rule 可比；失败、增量、漂移、损坏或不可信基线均失败关闭。tombstone 保存确认时间/Run，失败或延迟旧观察不能重激活；恢复旧 delta 会按 previous status/hash/time/run 重验并跳过已被新 Run 推进的状态。localstate/localplanner/engine/CLI 测试连续 5 次、相关 vet、CLI build、真实 `127.0.0.1:3000 -Pn -nd -npoc` 双跑和 JSON smoke 通过；第二次增量 Run 复用端口且保留首次完整端口基线。独立只读 review 的 2 个 Important 已修复并复核为无 Critical/Important；source-size-check 未新增 G30 超限，仅报告既有基线文件。根模块全量仅保留既有 WindowsApps Python 9009、tools/arsenal-sync SQLite 句柄和 Windows symlink 权限失败；`-race` 因当前 Go 禁用 CGO 未运行。 |
| G31 | 2026-08-10 | PASS | 建立无目标/凭据正文的 `argus.timing/v1` 契约和单调时钟 Recorder；CLI 每个 Run 严格保存 `timing.tsv` 并只在文本模式输出准备/阶段摘要，Agent v2.7.0 经现有结果流上报规则、上下文和真实已启动阶段，Server 重新校验会话、Attempt、Agent、tenant/project 后追加式幂等保存，任务详情及 viewer 可读前端按 Attempt 展示计时和 legacy unavailable。Migration 410 使用 Attempt+Agent 复合外键而不引用可清理的 `nodes`；本地 PostgreSQL apply/verify、共享/CLI/Agent/Server 定向测试、Server vet、前端计时 23/23、TypeScript、production build、2 项 smoke、lint 0 error（15 个既有 warning）及安全 localhost CLI/Agent 实测通过。固定 Windows/Go 1.25.4/同 Arsenal 基线显示 help after P50 406.01ms、P95 478.15ms，明确 URL POC-off P50 754.18ms、P95 850.04ms，Agent context P50 140.27ms、P95 150.00ms；URL 与 Agent 门槛达标，help 300ms 门槛未达并明确留给 G32，不将插桩称为优化。独立只读 review 的未启动阶段取时 Important 已修复，最终无 Critical/Important。根模块全量仅保留既有 `tools/arsenal-sync` Windows SQLite 句柄/symlink 限制；Server 全量仅保留既有临时 Arsenal 句柄和相对 `build.sh` 原生执行失败；前端全量仅有既有 AssetDiscovery 用例在并发负载下偶发失败且单测复跑通过，source-size-check 仍仅命中已有基线。Server/Agent 已用当前实现重建运行；Server 重启使浏览器登录态失效，未绕过认证，登录态计时面板由组件及 API 授权回归覆盖。 |
| G32 | 2026-08-10 | PASS | 移除 gonmap 在 package init 中的重型探针解析，首次 `New()` 通过 `sync.Once` 完整构建并在互斥锁内发布只读快照；并发首次调用共享同一快照，`SetFilter` 首次指定 filter、后续串行重建和旧 Scanner 保留原快照的兼容语义不变。首次构建 panic 不发布快照，后续调用稳定重抛同一根因而不会退化为空指针。独立进程测试覆盖未初始化、32 路并发、重建、离线 SMTP banner 和失败重放，连续 5 次及 Docker Linux `-race` 通过；协议/Engine/CLI/Agent 定向测试和相关 vet 通过。以 `b79e668` 为纯 before、同源码仅叠加 G32 为 after 的 Windows/Go 1.25.4/同 Arsenal 3 次预热、30 次样本显示：help P95 从 466.67ms 降至 104.53ms，明确 URL、POC-off P95 从 869.84ms 降至 544.69ms；inittrace 中 gonmap 从 292ms、308323776 bytes、1390918 allocations 降至 3ms、5748320 bytes、1299 allocations，独立进程状态证明重型探针未加载。最终 CLI 对 `127.0.0.1:3000` 首次协议阶段仍识别为 http 且 POC-off；最终 Agent 已重建、注册并订阅任务。根模块全量除既有 `tools/arsenal-sync` Windows SQLite 句柄和 symlink 权限限制外通过；Agent vet 仍仅命中既有 protobuf 测试 copylocks。两轮独立只读 review 的初始化失败和基线口径 Important 已修复，最终无 Critical/Important。 |
| G33 | 2026-08-10 | PASS | 主 HTTP 探测改为每个规范目标一个总 deadline，并让 retry、无 Scheme fallback、JS/meta 跳转和 Pipeline 同源 Location 复用来源目标剩余预算；明确 Scheme 不再探测另一协议，`ScanContext.Ctx` 可取消真实请求，Runner 同步收敛后再释放资源。超时目标及 HTTP 依赖阶段失败关闭，不生成可复用阴性覆盖；混合目标仍保留成功结果和重定向。固定 Windows/Go 1.25.4/同 Arsenal/配置/loopback fixture 的 3 次预热、30 次样本显示 1 秒预算 P95 从 3.063s 降至 1.416s，低于 2.5s 门槛；2 秒 CLI smoke 墙钟 2.468s、HTTP 阶段 2.046s、POC-off 且无 HTTP/依赖阶段复用覆盖。httpx/runner/Engine/Planner/Agent 定向测试、相关 vet、Docker Linux `-race`、CLI/Agent 本地 smoke 和 `git diff --check` 通过；根模块全量仅保留既有 WindowsApps Python 9009、临时 SQLite 句柄和 symlink 权限限制。嵌套 httpx 模块独立测试因仓库既有 `go-openai` checksum 不一致无法运行，但根工作区定向测试及 Linux race 覆盖相同包。独立只读 review 提出的重定向提前截断和基线 SHA 过期 Important 均已修复，最终无 Critical/Important。 |
| G34 | 2026-08-10 | PASS | 删除进程级 `GlobalUsedUrl`/`RemoveUsedUrl`，由 `ScanContext` 持有互斥保护的 URL 首次占用集合；Pipeline 通过 httpx 窄接口注入当前 Context，legacy CLI 构造和 `Reset()` 明确隔离连续执行，包级兼容入口每次使用私有集合。顺序 loopback 的第二任务回调由 1 恢复为 2（两任务均 root→next 共 2 次），同 Context 64 路原子占用、跨 Context、共享/私有 Session、Reset、typed-nil 和 Runner 构造失败重试均有回归；Docker Linux `-race` 两包最终 10 轮通过，此前核心并发用例 30 轮亦通过。Engine/Planner/Config/CLI 测试、相关 vet、source-size-check、`git diff --check` 和最终 CLI `127.0.0.1:3000 -Pn -nd -npoc -force` smoke 通过；CLI SHA-256 为 `6b2396d4...3154`，最终 Agent SHA-256 为 `92261679...c9f` 并已注册订阅。根模块全量只保留既有 WindowsApps Python 9009、临时 SQLite 句柄和 symlink 权限限制；独立 review 的 Runner 失败占用和 typed-nil 两项 Important 已修复，最终无 Critical/Important。 |
| G35 | 2026-08-10 | PASS | 相同已验证 `package_sha256 + ruleVersion` 的 Agent Context 复用进程内只读 Fingerprint/Workflow/Dir 快照；single-build、失败重试、有界 LRU、旧引用、Debug 深拷贝和任务状态隔离均有回归。规则确认到 `runningTasks` 登记形成完整使用窗口，pending 包只在最后一个初始化/运行使用者退出后激活；risk-validation、ResumePlan 与 Coverage 固定使用捕获版本。Server 以新增 `X-Arsenal-SHA256` 绑定实际下载字节，Agent 复算后才持久化/物化，旧 manifest 安全重物化且旧 Agent 兼容。最终同 Arsenal 3/30 为 P50 42.915ms、P95 45.305ms，较 before 改善 69.0%/70.4%并满足 500ms；基线工具强制文件与 manifest 身份一致。Engine/Arsenal/Agent/perf-baseline 与 Server 导出定向测试、Docker Linux `-race` 10 轮、`git diff --check`、最终 CLI POC-off loopback、Server/Agent 重建运行及未认证导出 401 均通过。根模块全量仍仅受既有 Windows Python 9009、SQLite 句柄和 symlink 限制影响；Server 全量仍有既有相对 `build.sh` Windows 失败；source-size-check 仅报告既有基线超限。独立 review 的基线身份 Important 已修复，最终无 Critical/Important。 |
| G38 | 2026-08-10 | PASS | Standalone CLI 的 `-ot json` 现使用 `argus.cli-output/v1` UTF-8 NDJSON，逐 finding 流式输出并以唯一 `run_summary` 收敛；结果文件与 stdout 成功路径字节一致，任一终态写入失败返回 1，stdout 失败时会把已落盘成功 summary 原位回滚为唯一 `failed/1`。参数、无目标和 Server-only Provider 拒绝返回 2，取消返回 130；JSON 与非 TTY 文本无 Banner、ANSI、进度或普通 Info。显式 CLI presentation 仅抑制本次 GoPoc/Nuclei 终端噪声，Agent/gRPC、扫描阶段和 POC 安全默认不变。CLI/common/ddout/Engine/localstate/GoPoc/Nuclei/structs 定向测试、相关 vet、Docker Linux `-race`、`git diff --check` 和本机 `127.0.0.1:3000 -Pn -nd -npoc` 黑盒通过；最终 CLI SHA-256 为 `07ea8fdaeffd270569ce088eb4dd59574168d28cf1aa7205c8bb77b71957e1b6`。source-size-check 未新增 G38 超限；根模块全量仅保留既有 Agent 时序波动、WindowsApps Python 9009、SQLite 临时句柄和 symlink 权限失败，完整 vet 仍仅有 3 条既有告警。独立 review 的终态文件成功假象 Important 已修复，最终无 Critical/Important。 |
| I164A | 2026-08-09 | PASS | 新增 Server-only FOFA Provider 核心：调用方显式传入凭据，内部固定使用 FOFA HTTPS 端点并拒绝重定向；单次查询限制 30s、1..10000 条、4096 字节表达式和 8 MiB 响应，网络/状态/Provider/畸形响应使用可分类且不含 URL、email、key 或原始响应的错误。结果只保留无凭据规范目标和最小元数据，移除 URL path/query/userinfo，规范 IPv4/IPv6/域名/端口，畸形行跳过、重复项顺序无关归并并稳定排序。包测试连续 10 次和 vet 通过；Server 全量除既有 Windows `arsenal.db` 句柄清理及 `build.sh` 原生执行两项失败外全部通过。未新增 API、数据库、调度或 Agent/CLI 行为。 |
| I164B | 2026-08-09 | PASS | 新增 `POST /api/v1/projects/:id/asset-discovery/fofa/query`：operator 及以上仍须通过项目对象级授权，只读取当前租户 Approved `apiconfig/api-config.yaml`，严格限制请求并返回有界规范资产；查询、凭据、Provider 正文和资产不落审计，专用表只保存 SHA-256 关联摘要、计数、耗时和稳定错误码，审计失败时不返回结果。跨租户、未分配项目、viewer、Draft 配置、超大请求、Provider 错误和审计失败测试连续 10 次通过；相关 `go vet`、`git diff --check` 通过。Server 全量除两个既有 Windows 限制（临时 `arsenal.db` 句柄清理、原生执行 `build.sh`）外通过；Migration 370 使用 Makefile 等价 Go 命令在本地 PostgreSQL apply/verify 成功（Windows 无 `make`）。结果不写项目资产、不导出、不创建任务。 |
| I164C | 2026-08-09 | PASS | 新增 Server-only Hunter Provider：调用方显式传入 API Key，固定使用现有运行时兼容的 HTTPS 查询参数并拒绝重定向；最多 1000 条/10 页、4096 字节表达式，全部分页共享 30 秒和 8 MiB 总预算。响应不接收或返回 banner/剩余额度/原始正文，只规范化 IP、域名、端口、协议、标题、国家、城市、公司和状态码；分页提前结束、总数矛盾、畸形/超限响应和 Provider 错误均失败关闭。FOFA/Hunter 包测试连续 20 次和 vet 通过，Server 全量仅有两个既有 Windows 环境失败。没有真实 Hunter 凭据，未发起外部查询；请求格式由仓库现有 `scanner/internal/uncover` 与 Subfinder Hunter 源双重核对，Hunter 官方帮助入口当前返回 403，后续公开 API Goal 仍需凭据沙箱 smoke。未新增路由、配置读取、数据库或 CLI/Agent 行为。 |
| I164D | 2026-08-09 | PASS | 新增 `POST /api/v1/projects/:id/asset-discovery/hunter/query`，与 FOFA 共用严格 JSON 请求、16 KiB 请求预算、项目对象授权、operator RBAC、当前租户 Approved API 配置和 `asset_discovery_audits`；Hunter 单次预览最多 1000 条，Provider 成功但审计写入失败时不返回结果。配置读取抽成 Provider 通用函数但仍按租户和已批准状态隔离；Key、原始查询、Provider 正文和资产不落审计。真实路由、超大请求、跨租户 Key、Provider 脱敏错误、审计失败、RBAC、路由契约及 FOFA 交叉回归连续 10 次通过；`go vet ./...` 通过。Server 全量仍仅有两个既有 Windows 环境失败；无真实 Hunter 凭据，未发起外部查询。结果不写项目资产、不扩展 Scope、不导出或创建任务。 |
| I164E | 2026-08-09 | PASS | 新增 Server-only Quake Provider：调用方显式传入 `X-QuakeToken`，只调用固定 HTTPS 搜索端点并拒绝重定向；移除旧 Scanner 的 2 秒固定等待和 `/user/info` VIP 预检。单次最多 500 条、表达式 4096 字节、30 秒总超时和 8 MiB 响应预算；显式请求最小字段，高级字段缺失时回退规范 `IP:Port`。每行 URL 最多 32 个，最终资产最多 `limit×4` 且硬上限 2000；Provider code、总数、空数据、畸形/超限响应和错误均脱敏失败关闭。FOFA/Hunter/Quake 包测试连续 20 次和 vet 通过，Server 全量仍仅有两个既有 Windows 环境失败。无真实 Quake Token，未发起外部查询；请求/响应结构由仓库现有 Scanner 与 Subfinder Quake 源双重核对，后续公开 API Goal 仍需凭据沙箱 smoke。未新增路由、配置读取、审计或 CLI/Agent 行为。 |
| I164F | 2026-08-09 | PASS | 新增 `POST /api/v1/projects/:id/asset-discovery/quake/query`，与 FOFA/Hunter 共用严格 JSON、16 KiB 请求预算、项目对象授权、operator RBAC、当前租户 Approved API 配置和专用脱敏审计；单次最多 500 条，Token、原始表达式、Provider 正文和资产不落审计，Provider 成功但审计失败时不返回结果。真实 JWT 路由、超大请求、跨租户 Token、Provider 脱敏错误、审计失败、RBAC、路由契约及三 Provider 交叉回归连续 10 次通过；`go vet ./...`、Markdown 围栏、敏感凭据模式扫描和 `git diff --check` 通过。Server 全量仍仅有两个既有 Windows 环境失败（临时 `arsenal.db` 句柄清理、原生执行相对 `build.sh`）；无真实 Quake Token，未发起外部查询。新 Server PID 37108 已重建启动，`/health` 200，未认证 Quake 接口 401。结果不保存、不导出、不扩展 Scope 或创建任务。 |
| I164G | 2026-08-10 | PASS | 新增版本化 `asset_discovery_snapshots` 与 `asset_discovery_snapshot_items` 模型和 additive migration 380；快照以 tenant/project/audit 复合外键绑定成功审计，资产项以 tenant/project/snapshot 复合外键绑定来源，查询内 `(snapshot_id,target_hash)` 唯一。原始表达式作为项目业务数据保存且限制 4096 字节，但不会进入通用审计/日志；schema 没有凭据或 Provider 原始响应字段，也不写现有 `assets`。DB 模型/迁移/Schema 契约目标测试连续 10 次、DB 全包与 Server vet 通过；本地 PostgreSQL apply/verify 成功，并在回滚事务中真实验证跨项目资产项被外键拒绝、重复目标被唯一约束拒绝。Markdown 围栏、敏感凭据模式扫描和 `git diff --check` 通过；Server 全量仍仅有两个既有 Windows 基线失败。新 Server PID 25880 使用 migration 380 重建启动且 `/health` 200；当前查询 Handler 尚未写快照。 |
| I164H | 2026-08-10 | PASS | FOFA/Hunter/Quake 成功路径统一在一个 10 秒数据库事务内创建成功审计、不可变查询快照和全部规范资产项；持久化边界重新校验 Provider、表达式、摘要、结果数量、目标、来源和最小元数据。事务中任一步失败会回滚成功记录，尝试写 `snapshot_validation_failed` 或 `snapshot_persistence_failed` 审计并隐藏结果；重复目标、畸形摘要、控制字符、资产项表写入失败和空成功结果均有测试。三 Provider/快照定向测试连续 10 次、Server vet、Markdown 围栏、敏感凭据模式扫描和 `git diff --check` 通过；完整 Server 回归仍仅有两个既有 Windows 基线失败。新 Server PID 19320 已重建启动，HTTP 8085 与 gRPC 50051 正常监听，未认证 Provider 和项目接口均为 401；没有真实 Provider 凭据，未发起外部查询。 |
| I164I | 2026-08-10 | PASS | 新增 viewer 可读的项目测绘历史列表/明细 API，列表 100、明细 500 的服务端硬上限和分页溢出保护，所有查询同时绑定 tenant/project/snapshot；跨项目明细 404、跨租户项目 403，响应 `no-store` 且不暴露凭据、配置/查询哈希或 Provider 原始响应。前端新增独立资产测绘页，operator 可直接查询，viewer 只读，归档项目禁用新查询；FOFA/Hunter/Quake 官方语法速查、鼠标/键盘字段补全不限制原始表达式。项目切换会失效旧查询/历史/明细请求，补全不会修改引号内值。Server 定向测试连续 10 次与 `go vet ./...` 通过；前端 21 files/101 tests、ESLint 0 error（15 个既有 warning）、production build、2 项 smoke 通过；完整 Server 回归仅有既有 Windows 临时 `arsenal.db` 句柄清理和相对 `build.sh` 执行两项失败。两轮独立只读 review 的 2 个 Important 已修复，最终无 Critical/Important。新 Server PID 29492 已加载当前 API，未认证列表/明细接口返回 401；登录态浏览器确认页面、项目选择和安全输入可用，未消耗 Provider 额度。 |
| I164J | 2026-08-10 | PASS | 新增 viewer 可用但仍校验项目对象归属的单快照 CSV 导出 API 与历史行一键下载；Server 全量构建后、成功审计写入前不发送响应，最多 10000 项/32 MiB，tenant/project/snapshot 三重过滤，稳定排序、UTF-8 BOM、固定数值文件名和公式注入防护，表达式、内部哈希、凭据及 Provider 原始响应不进入文件。项目授权、快照/资产读取、编码取消检查和成功/失败审计共用请求级 deadline；授权、快照或审计超时均不返回部分 CSV。Server 定向测试连续 3 次、`go vet ./...`、前端 21 files/103 tests、ESLint 0 error（15 个既有 warning）、production build、2 项 smoke 和 `git diff --check` 通过；完整 Server 回归仅有既有 Windows 临时 `arsenal.db` 句柄清理和相对 `build.sh` 执行两项失败，source-size-check 仅命中已有基线文件。独立只读 review 提出的 10 秒预算 Important 已补三类精确回归并最终确认无 Critical/Important。新 Server PID 33996 已监听 HTTP 8085/gRPC 50051，未认证导出接口返回 401，前端页面返回 200；重启使开发 JWT 失效，未绕过认证执行真实登录态下载，下载行为由组件测试覆盖。 |
| I164K | 2026-08-10 | PASS | Migration 390、项目授权归档/列表 API 和前端测绘笔记本形成闭环；项目内规范目标去重、跨快照来源可追溯、重复来源幂等，成功写入与脱敏审计同事务失败关闭，归档项目只读。PostgreSQL apply/verify、后端与 DB 测试、前端 21 files/105 tests、ESLint 0 error（15 个既有 warning）、production build、2 项 smoke 和 `git diff --check` 通过；完整 Server 仅有两个既有 Windows 基线失败，source-size-check 仅命中已有基线文件。独立只读 review 无 Critical/Important。 |
| I164L | 2026-08-10 | PASS | 新增 operator-only、tenant/project/task/item 全量重验的只读分发预览 API/UI；1–100 项、16 KiB 请求、统一 10 秒数据库预算、direct 安全配置、任务内去重、Scope/SeedTargets 增量、批次画像和稳定 plan hash 均有回归，且测试确认不写 Task/Batch/Attempt/Scope/Seed/audit、不触发队列或风险执行。Server 定向测试、路由契约和 `go vet ./...` 通过；完整 Server 除既有 Windows 临时 `arsenal.db` 句柄清理和相对 `build.sh` 两项失败外通过。前端 21 files/110 tests、TypeScript、production build、2 项 smoke、ESLint 0 error（15 个既有 warning）通过；第 101 个任务仍可经分页搜索选择。source-size-check 仅命中既有基线文件，本 Goal 文件未新增超限。独立 review 的任务默认首页 Important 已修复，最终无 Critical/Important。新 Server PID 31240 已监听 HTTP 8085/gRPC 50051，未认证新路由返回 401；Server 重启使浏览器会话失效，未重置密码或绕过认证，登录态页面 smoke 由自动化 UI 回归替代。 |
| I164N | 2026-08-10 | PASS | 新增 operator 显式确认的笔记本分发物化 API/UI：在同一事务重验预览绑定、tenant/project/task/item、任务状态、当前配置/规则与 direct POC-off 安全策略，记录不可变 intent/materialization、扩展 Scope/SeedTargets、创建追加式 TaskBatch/Attempt 并写脱敏审计，提交后才派发；同键重放不重复写入或入队，并按冻结 Attempt 当前状态反馈 dispatched/pending。Server API/DB 定向测试与 vet、Migration 420 的 PostgreSQL apply/verify、前端 22 files/119 tests、TypeScript、production build、2 项 smoke、ESLint 0 error（15 个既有 warning）及 `git diff --check` 通过；完整 Server 回归仅保留既有 Windows 相对 `build.sh` 执行失败。登录浏览器使用暂停任务和保留 `.test` 目标完成“选择 → 预览 → 确认 → 任务详情”真实 smoke，页面与数据库均证明仅有 1 个 Batch、1 个 Attempt、1 条审计且全程未派发；验收夹具随后按精确 ID 事务清理并确认相关 8 类记录均为 0。多轮独立只读 review 的队列恢复、陈旧响应、确认锁和派发反馈 Important 均已修复，最终无 Critical/Important。 |
| G39A | 2026-08-10 | PASS | `POST /tasks` 与创建任务 UI 形成可选 `Idempotency-Key` 纵向闭环：同 tenant/project/operator/operation/key 的同规范请求重放首次 Task，异请求返回 409；幂等账本、RootTask、配置 v1、首批 Batch/Attempt、项目范围扩展和 create 审计同事务提交，原始 Key 只以 SHA-256 保存，重放不再次入队。重放从账本绑定的初始 Attempt/TaskBatch 和配置 v1 重建目标/批次摘要，跳过项稳定排序，后续配置或批次变化不会改写首次创建结果。Migration 430 在临时 PostgreSQL 从 010..430 apply/verify 通过；真实并发两个相同请求返回同一 Task ID 且数据库精确为 1 个 Root/Batch/Attempt/Audit/Ledger，异请求同 Key 为 409。Server 定向 API/DB、`go vet`、前端 22 files/123 tests、TypeScript、production build、2 项 smoke、ESLint 0 error（15 个既有 warning）、CORS 预检和 `git diff --check` 通过。登录浏览器以保留 `.test` 目标完成正常创建并验证任务列表，窄视口 Copilot 浮层遮挡创建按钮的 z-index 阻塞同时修复；验收任务及 Scope/SeedTargets 已精确清理。完整 Server 回归只保留父提交路由计数基线与 Windows 相对 `build.sh` 两项既有失败；独立 review 的重放摘要 Important 已修复，最终无 Critical/Important。 |
| G39B | 2026-08-10 | PASS | `POST /tasks/:id/append` 与“增加批次”UI 形成可选 `Idempotency-Key` 纵向闭环：相同 tenant/project/task/operator/operation/key 的同规范目标重放首次 outcome、业务计数及 Batch/Attempt，异请求返回 409；账本、Batch/Attempt、项目范围、Task 聚合和单条 `batch_append` 审计同事务提交，原始 Key 仅以 SHA-256 保存，重放不再次入队。请求按账本冻结配置的目标模式规范化，等价 URL 与后续配置变化仍可稳定重放；`dispatched/dispatch_pending` 只投影首次 Attempt 当前状态。Migration 440 在临时 PostgreSQL 从 010..440 apply/verify 通过，两连接并发同 Key/同哈希仅写 1 条账本并稳定重放，异哈希冲突。Server API/DB 定向测试、`go vet`、前端相关 29 项测试、production build、2 项 smoke、ESLint 0 error（15 个既有 warning）和 `git diff --check` 通过；前端全量 124/125 仅保留既有 AssetDiscovery 用例失败，Server 全量仅保留父提交路由计数基线和 Windows 相对 `build.sh` 两项既有失败。登录浏览器与真实 HTTP 并发 smoke 证明两次同 Key 返回首次/重放且数据库只有一组追加对象、一次审计；验收任务已归档并从默认列表隐藏。独立 review 的规范化哈希和投递状态契约 Important 均已修复，最终无 Critical/Important。 |
| G39C | 2026-08-10 | PASS | `POST /tasks/:id/retry` 与任务级“重试失败批次”UI 形成可选 `Idempotency-Key` 纵向闭环：幂等账本、新 Attempt、RootTask 状态和单条审计同事务提交，同 Key 同请求稳定重放且不二次派发，同 Key 异请求 409；网络/超时重试复用 Key，跨任务旧请求不会释放新任务锁。Migration 450、PostgreSQL 并发、Server/DB、前端全量、production build、smoke、浏览器与独立 review 完成；原始 Key 只保存 SHA-256，验收任务已停止并归档。 |
| G39D | 2026-08-10 | PASS | `POST /tasks/:id/batches/:batch_id/retry` 与单批次重试 UI 形成可选 `Idempotency-Key` 纵向闭环：作用域包含 tenant/project/task/batch/operator/operation，账本冻结唯一新 Attempt、配置/规则版本和前后状态；同 Key 同请求只追加一次 Attempt、审计和主动派发，异请求 409，重放不依赖队列或可重试状态且只实时投影该 Attempt 的 `dispatch_pending`。Migration 460 在临时 PostgreSQL 010..460 apply/verify 通过；真实 PostgreSQL 并发返回相同 Attempt 且数据库精确为 1 条新增 Attempt、审计和账本。Server/DB 定向测试与 vet、前端相关 34 项、lint、build、smoke、登录浏览器批次重试及独立 review 通过；完整前端仅保留既有 AssetDiscovery 归档用例失败，完整 Server API 仅保留既有路由计数与 Windows 相对 `build.sh` 两项失败。浏览器验收任务已停止归档并移除测试 Scope/SeedTargets；最终无 Critical/Important。 |
| G39E | 2026-08-10 | PASS | `POST /tasks/:id/risk-validation` 与风险验证确认 UI 形成可选 `Idempotency-Key` 纵向闭环：新 Key 重新生成并绑定 preview/config/rule/POC 内容与双重确认，账本、risk-validation Batch/Attempt、RootTask 状态和单条审计同事务提交；同 Key 同请求稳定重放且不再次派发，同 Key 改 plan、指定 POC、候选或确认字段返回 409。Migration 470 在临时 PostgreSQL 010..470 apply/verify 通过；真实 PostgreSQL 双请求并发均返回 202、首次/重放共享同一 Batch/Attempt，数据库只新增 1 组 Batch/Attempt/审计/账本，异请求同 Key 为 409。登录浏览器完成“预览 → 双重确认 → 执行 → 任务详情”真实 smoke，并据此修复空集合返回 `null` 导致页面崩溃的问题；验收任务已归档，测试资产、指纹、Scope/SeedTargets 和自建 POC 已精确清理。Server DB 全包、定向 API、vet、前端 22 files/131 tests、lint、build、2 项 smoke、schema verify 和 `git diff --check` 通过；Server 全量仅保留既有路由计数快照与 Windows 相对 `build.sh` 两项失败，source-size-check 仅报告既有超限基线。后端/DB 与前端独立 review 最终均无 Critical/Important；G39A–G39E 全部完成，不再创建 G39F。 |
| G41 | 2026-08-10 | PASS | 完成全部剩余非 AI 收口：测绘 Notebook 增加授权聚合、筛选、标签、备注、软移除/恢复和对象关联脱敏审计，removed 条目无法进入新分发；Standalone CLI/Scanner/Agent 已切断 Hunter/FOFA/Quake 搜索及凭据同步，Server 对新建、追加、派发和领取的遗留 Provider 配置失败关闭。Migration 480 在 PostgreSQL 010..480 apply/verify 及孤儿数据负向升级验证通过；登录浏览器完成标签/备注/筛选/移除/恢复并精确清理夹具，CLI/Agent 兼容拒绝 smoke、版本化发行包构建与内容检查通过。最终根模块、Server、MCP 全量测试及 vet，前端 24 files/135 tests、lint（0 error、15 个既有 warning）、production build、2 项 smoke、source-size-check 和 `git diff --check` 全部通过；源码体积例外按 branch point `83dc2f...` 收敛为精确零余量 ceiling。三组独立只读 review 提出的 Provider ACK 顺序和体积 ratchet Important 均已修复并复核，最终无 Critical/Important。G40 与所有 AI 工作继续暂缓。 |

## 提交记录

| Goal | 分支 | Commit | 说明 |
| --- | --- | --- | --- |
| G00 | `codex/server-task-lifecycle` | `72b1beb` | 建立动态计划 |
| G01 | `codex/server-task-lifecycle` | `9716eeb` | 固定任务操作列并增加状态菜单和权限原因 |
| G02 | `codex/server-task-lifecycle` | `d9e295b` | 统一任务和尝试状态机并兼容旧状态 |
| G02A | `codex/server-task-lifecycle` | `1af44d8` | 移除 GSAP 全局动效依赖并保留登录页 CSS 动态视觉 |
| G03 | `codex/server-task-lifecycle` | `d1bdf7a` | 将任务删除改为保留结果的归档，并为生命周期操作增加事务审计 |
| G04 | `codex/server-task-lifecycle` | `de79873` | 为任务配置建立不可变递增修订，并让后续批次绑定当前版本 |
| G05 | `codex/server-task-lifecycle` | `e8bcc94` | 建立稳定 TaskBatch，将 SubTask 明确为兼容 Agent 协议的实际 Attempt，并无损回填旧数据 |
| G06 | `codex/server-task-lifecycle` | `6c1fc89` | 将重试、拆分和恢复改为追加新 Attempt，保留旧执行证据，并区分当前批次与 Attempt 历史 |
| G07 | `codex/server-task-lifecycle` | `4a86831` | 规范化并去重追加目标，原子创建 Batch/Attempt，扩展当前项目范围并让完成任务重新运行 |
| G08 | `codex/server-task-lifecycle` | `861c627` | 为稳定 Batch 增加正交控制状态、生命周期 API/UI、追加式重试、Agent 取消与保留历史的归档 |
| G09 | `codex/server-task-lifecycle` | `babf95b` | 将任务控制收敛到最新 Attempt，保留手动暂停批次，新增规范 stop 接口与失败批次追加式重试 |
| G10 | `codex/server-task-lifecycle` | `a603938` | 增加安全零配置创建、项目范围复用/扩展与审计，并将人工调度和扫描参数折叠到高级设置 |
| G11 | `codex/server-task-lifecycle` | `d0dc276` | 增加 POC 执行类别/风险治理、旧规则安全默认、二次确认提示和 EXP 隔离校验 |
| G12 | `codex/server-task-lifecycle` | `d04201b` | 基于当前任务指纹生成只读风险验证预览，绑定规则/配置/POC 内容并估算请求上界 |
| G13 | `codex/server-task-lifecycle` | `cb0ba23` | 经版本绑定和明确确认追加精确 POC 风险验证批次，并在 Server/Agent/Scanner 三层阻止规则漂移 |
| G13A | `codex/server-task-lifecycle` | `4f6bc72` | 普通资产任务在 API、调度领取与 Agent 执行三层禁止未确认 POC，并从创建 UI 移除误导开关 |
| G14 | `codex/server-task-lifecycle` | `01b2dd9` | 建立跨 Server/Agent/CLI 的版本化 ScanPlan、WorkKey、Observation 与 Coverage 契约及旧阶段显式适配器 |
| G15 | `codex/server-task-lifecycle` | `68b43a4` | 增加追加观测、当前覆盖、唯一工作租约和任务覆盖来源关联的租户隔离存储 |
| G16 | `codex/server-task-lifecycle` | `3eafd6f` | Agent 上报规范终态阶段证据，Server 按已领取 Attempt/Agent/目标边界校验且旧 Agent 保持 unknown |
| G17 | `codex/server-task-lifecycle` | `56210f8` | 以 Server 权威范围、配置和规则快照幂等归并 Observation/Coverage，失败与漂移证据不可复用 |
| G18 | `codex/server-task-lifecycle` | `19eb33e` | 领取时按完整目标复用有效项目覆盖，全量不派发，部分复用与 Agent 租约原子提交并记录来源 |
| G19 | `codex/server-task-lifecycle` | `622b0fe` | 原子占用同项目执行中工作，重复 Attempt 挂接等待并在来源终态后自动重新规划 |
| G20 | `codex/server-task-lifecycle` | `bcc8ea1` | 由 Server 按目标派生公网与私网区域，允许安全共享并隔离未知私网 |
| G21A | `codex/server-task-lifecycle` | `b9611b7` | 增加阶段 TTL、依赖内容失效和强制复测的新证据语义 |
| G21B1 | `codex/server-task-lifecycle` | `1e02e3f` | 增加目标绑定的有界阶段检查点契约、Agent 上报与追加式存储 |
| G21B2 | `codex/server-task-lifecycle` | `71df6ba` | 增加检查点感知的单目标最小依赖恢复计划并安全回退不可重放证据 |
| G21B3 | `codex/server-task-lifecycle` | `a17cd77` | 在最终租约复核恢复计划并让兼容 Agent 安全执行、上报阶段后缀 |
| G22 | `codex/server-task-lifecycle` | `e5e17f2` | 在任务详情按租户/项目边界解释实际执行、历史复用、等待来源、失效原因和节省量 |
| G23 | `codex/cli-offline-memory` | `226c637` | 建立可执行文件同级或 ARGUS_HOME 覆盖的 CLI-only 离线数据根目录 |
| G24 | `codex/cli-offline-memory` | `43fe618` | 建立版本化分层 TSV 和每次运行独立的最小证据历史 |
| G25 | `codex/cli-offline-memory` | `efda132` | 以跨进程锁和原子替换归并长期状态，并安全恢复中断或待提交运行 |
| G26 | `codex/cli-offline-memory` | `0d2b1e0` | 接入默认安全的 internal-fast Planner，复核本地端口覆盖并从最早可安全恢复阶段补扫 |
| G27 | `codex/cli-offline-memory` | `57da91c` | 以严格本地策略文件配置阶段 TTL、每次存活/服务复核预算和显式风险覆盖有效期 |
| G28 | `codex/cli-offline-memory` | `c59cbbf` | 增加 CLI-only `-force`，安全绕过本地覆盖并保留普通扫描边界和追加历史 |
| G29 | `codex/cli-offline-memory` | `784de92` | 统一 CLI 离线 Arsenal 包的固定路径、校验物化、语义版本、发行构建与本地回滚 |
| I165 | `codex/cli-offline-memory` | `704de80` | 将 CLI/Agent 普通扫描的 GoPoc/POC 默认统一为安全关闭，并说明 Issue #165 的新验收边界 |
| G30 | `codex/cli-run-diff` | `8fbd05a` | 为 CLI Run 增加可解释、恢复幂等且对消失/重现失败关闭的本地差异证据和文本摘要 |
| G31 | `codex/scanner-performance` | `ff8747f` | 建立 CLI/Agent/Server 追加式计时证据、授权任务展示和可重复性能基线 |
| G31-fix | `codex/scanner-performance` | `b79e668` | 允许合法零时长计时事件，避免极短 Agent 阶段中断结果流和 coverage |
| G32 | `codex/scanner-performance` | `cda69f2` | 延迟 gonmap 重型探针构建并保留并发、筛选器和协议识别兼容语义 |
| G33 | `codex/scanner-performance` | `be03a6b` | 为 HTTP 主探测建立目标级总预算、父取消和明确 Scheme 契约 |
| G34 | `codex/scanner-performance` | `009a09b` | 将 HTTP URL 首次占用隔离到并发安全的任务 ScanContext |
| G35 | `codex/scanner-performance` | `616d96b` | 按已验证 Arsenal 包身份复用只读规则知识并封闭 Agent 热切换窗口 |
| G36 | `codex/scanner-performance` | `4d4bfa2` | 为有界小任务选择内存响应存储并保留大任务磁盘边界 |
| G37 | `codex/cli-compatibility` | `47104f6` | 统一 Argus CLI 品牌、版本和帮助并停止本地 Provider 测绘执行 |
| G38 | `codex/cli-compatibility` | `302d3ae` | 稳定 CLI NDJSON、非 TTY 展示与退出码契约 |
| I164A | `codex/server-asset-discovery` | `91d3d50` | 建立 Server 内部 FOFA 查询、响应限制、目标规范化和去重核心 |
| I164B | `codex/server-asset-discovery` | `71ce42b` | 增加项目授权、租户配置读取、脱敏审计和 FOFA 查询预览 API |
| I164C | `codex/server-asset-discovery` | `5f8d3eb` | 建立 Server 内部 Hunter 有界分页查询、目标规范化和去重核心 |
| I164D | `codex/server-asset-discovery` | `cd3f885` | 将 Hunter 接入项目授权、租户 Approved 配置和脱敏审计查询预览 |
| I164E | `codex/server-asset-discovery` | `3324b66` | 建立 Server 内部 Quake 单次有界查询、目标规范化和去重核心 |
| I164F | `codex/server-asset-discovery` | `13086f0` | 将 Quake 接入项目授权、租户 Approved 配置和脱敏审计查询预览 |
| I164G | `codex/server-asset-discovery` | `6f2ef26` | 建立项目级测绘查询快照和规范资产项的追加式数据库契约 |
| I164H | `codex/server-asset-discovery` | `772f900` | 原子持久化成功查询的脱敏审计、项目快照和规范资产项 |
| I164I | `codex/server-asset-discovery` | `8fadd3f` | 增加项目授权、有界分页的测绘查询 API/历史 API 与前端资产测绘模块 |
| I164J | `codex/server-asset-discovery` | `90d66f8` | 增加项目授权、资源有界、可审计且防公式注入的测绘快照 CSV 导出 |
| I164K | `codex/server-asset-discovery` | `38870d2` | 增加项目级去重、来源可追溯且审计失败关闭的测绘笔记本归档与列表 |
| I164L | `codex/server-asset-discovery` | `acd080c` | 增加项目授权、配置绑定且无副作用的测绘笔记本 TaskBatch 分发预览 |
| I164M | `codex/server-asset-discovery` | `f3ba00f` | 增加分发意图、不可变选中项和按操作者隔离的幂等数据契约，不开放执行入口 |
| I164N | `codex/notebook-distribution` | `a69d96a` | 经显式预览确认将笔记本选中项幂等物化为现有任务的 Batch/Attempt，并完成前端与真实浏览器闭环 |
| G39A | `codex/task-create-idempotency` | `0b98d6c` | 让创建任务网络失败可安全重试，服务端同一意图仅创建、审计和派发一次 |
| G39B | `codex/task-append-idempotency` | `3a3aea1` | 让增加目标/批次的网络失败可安全重试，服务端同一意图仅追加、审计和派发一次 |
| G39C | `codex/task-retry-idempotency` | `796a573` | 让任务级重试在响应丢失后可安全重放，服务端同一意图仅追加一组 Attempt、审计和主动派发一次 |
| G39D | `codex/batch-retry-idempotency` | `a063c13` | 让单批次重试在响应丢失后稳定重放，服务端同一意图仅追加一个 Attempt、审计和主动派发一次 |
| G39E | `codex/risk-validation-idempotency` | （本次提交） | 让同一显式风险验证确认安全重放并严格绑定 preview，不重复创建或派发风险批次 |
| G41 | `codex/g41-non-ai-completion` | （本次提交） | 一次收口剩余非 AI Notebook 运营、Provider 旧链清理和发布级验证 |

## 变更日志

- 2026-08-09：根据用户确认的产品、任务、批次、去重、CLI 离线历史、性能和 AI 安全决策建立初版动态计划。
- 2026-08-09：G00 完成，进入 G01；当前分支为 `codex/server-task-lifecycle`。
- 2026-08-09：G01 完成；任务操作列固定在右侧，管理操作按状态进入“更多”菜单，并为只读用户显示权限原因。进入 G02。
- 2026-08-09：G02 完成；建立 Task/Attempt 规范状态映射和行为矩阵，兼容旧状态别名并统一 Server/UI 判断。进入 G03。
- 2026-08-09：用户反馈引入 GSAP 后产生多处显示问题；在 G03 尚未产生实现改动时插入独立稳定性 Goal G02A，先移除 GSAP 动效和依赖，完成后再继续 G03。
- 2026-08-09：按用户补充要求保留登录页动态视觉，使用纯 CSS 重建浮动 Logo、扫描线、信号环、导轨和表单入场；其余业务页面取消入场/路由动效，Canvas 改用原生帧循环。G02A 完成，继续 G03。
- 2026-08-09：G03 完成；任务归档与运行状态分离，默认列表和统计排除归档任务，历史结果仍可查看；暂停、恢复、停止和归档均在状态事务内记录操作者与前后状态。进入 G04。
- 2026-08-09：G04 完成；任务创建和 AI 草稿原子生成 v1，配置修改追加不可变修订并写审计，旧执行保留旧版本，后续追加批次使用当前配置与 Agent 选择条件；迁移为旧数据幂等回填 v1。进入 G05。
- 2026-08-09：G05 完成；新增稳定 TaskBatch 与版本/选择器快照，新创建和追加任务同时写入 Batch 与 Attempt，调度、Agent 认领和完成同步批次最新状态；迁移将每个旧 SubTask 无损关联为 Attempt 1，旧 Agent 协议保持不变。进入 G06。
- 2026-08-09：G06 完成；普通/超时/拆分/Agent 离线/Spot 恢复均保留原 Attempt 并追加新执行，TaskBatch 原子指向最新 Attempt，任务聚合只读取最新尝试；详情页分离当前批次与完整历史并展示 Agent、触发原因、配置/规则版本、失败原因和时间证据。进入 G07。
- 2026-08-09：G07 完成；追加目标先按场景规范化并在同一任务内幂等去重，事务内原子创建稳定 Batch 与首次 Attempt、继承当前配置和规则版本，同时扩展当前 Project Scope/SeedTargets 并写入审计；完成任务重新进入运行态，暂停任务保留暂停且不派发。进入 G08。
- 2026-08-09：G08 完成；TaskBatch 新增正交 `control_state`，支持暂停、恢复、立即停止、显式重试和归档；未领取 Attempt 恢复时复用原执行，已领取 Attempt 暂停时允许完成但禁用自动重试，失败后恢复或显式重试才追加新 Attempt；停止向 Agent 暴露取消命令，归档保留结果、历史与审计并退出进度聚合。进入 G09。
- 2026-08-09：G09 完成；任务暂停、恢复和停止只操作每个稳定 Batch 的最新 Attempt，暂停期间已领取执行失败后 RootTask 保持暂停，恢复时追加新 Attempt 且不覆盖用户单独暂停的 Batch；停止可从暂停态执行并在全部 Agent 收敛前保持停止中；新增 `/stop` 规范接口并保留 `/cancel`，任务重试只追加失败、超时和停止批次，成功批次保持复用。进入 G10。
- 2026-08-09：G10 完成；Server 零配置统一为安全外网平衡测绘档，项目/名称/Agent/优先级和超时均可自动决策，Project 既有范围可直接成为目标，新直接目标在事务内扩展 Scope/SeedTargets 并记录创建审计；前端主流程只保留项目、可选名称和目标，付费测绘源、人工 Agent 选择器与扫描细项折叠到高级设置，登录页动态视觉保持不变。进入 G11。
- 2026-08-09：G11 完成；Arsenal YAML 新增 POC 执行类别和独立执行风险元数据，Server 检索层、Agent 导出包和 CLI 本地库保持一致；未分类旧规则按 `detection + unknown` 安全兼容，高风险/未分类标记二次确认，任何 `exploit/exp` 分类均被导向独立 EXP 包。新增迁移 340 已在本地 PostgreSQL apply/verify，旧迁移未修改。进入 G12。
- 2026-08-09：G12 完成；风险验证预览只读取当前任务指纹/资产和当前已审核规则，生成带版本、内容哈希、请求量上界和稳定计划哈希的候选清单；viewer 可查看但接口不创建批次、不入队、不执行 POC，高风险/未分类项只显示二次确认提示。进入 G13。
- 2026-08-09：G13 完成；operator 可从 Workflow 或指定已审核 POC 生成并确认计划，在同一 Task 追加关闭自动重试的 `risk_validation` Batch。Server 重新校验对象归属、终态、版本与确认并写审计；旧 Agent、规则版本漂移或 POC 实际内容哈希漂移均不能执行，Scanner 只运行预览绑定的精确 Nuclei 映射。登录页继续保留纯 CSS 动效，其余页面保持无 GSAP。进入 G14。
- 2026-08-09：G14 契约盘点发现普通任务高级配置仍可直接开启 POC，与“所有 POC 必须经风险验证确认”冲突；插入 G13A 并完成 API、领取和 Agent 三层失败关闭，创建 UI 改为仅说明风险验证入口。安全补强单独提交后恢复 G14。
- 2026-08-09：G14 完成；新增版本化共享契约表达外网测绘、CLI 内网快扫、Server 内网扫描和独立风险验证，固定 WorkKey 的租户/项目/网络区域/目标/阶段/配置/范围/规则维度，并明确失败、跳过和未知阶段不可形成可复用覆盖。进入 G15。
- 2026-08-09：G15 完成；PostgreSQL 新增追加式阶段观测、WorkKey 当前覆盖、唯一执行租约和任务来源关联四类存储，保留现有 Asset/Fingerprint/Vulnerability 当前视图且不提前改变调度。所有查询维度显式保存 tenant/project/network zone，迁移 350 已真实 apply/verify。进入 G16。
- 2026-08-09：G16 完成；Agent v2.5.0 从真实阶段生命周期生成终态覆盖事件，失败与跳过始终携带原因，内容仅上传顺序无关摘要哈希。Server 从活动 Attempt 重新确认 Agent 和目标，不信任 Agent 提供对象边界；旧 Agent 没有事件时不会生成推断覆盖。进入 G17。
- 2026-08-09：G17 完成；Server 使用数据库权威对象边界、项目 Scope、配置修订与 Attempt 规则版本生成 WorkKey，事件按目标幂等追加并只维护最新 Coverage。失败、跳过、版本漂移和未知风险验证维度均保持不可复用；当前网络区保守隔离到 Agent，且调度尚不读取覆盖。进入 G18。
- 2026-08-09：G18 完成；Agent 领取前开始读取项目 Coverage。只有完整目标的全部必要阶段有效时才跳过；全量复用不占 Agent，部分复用的剩余目标与来源关联在最终租约事务内提交并二次复核覆盖快照。手动重试和风险验证固定绕过，G20 前不跨 Agent 复用。进入 G19。
- 2026-08-09：G19 完成；普通任务按完整目标以 fingerprint WorkKey 原子占用唯一 WorkClaim，相同项目工作执行中只保留一个 Agent 租约，后续 Attempt 记录来源后等待且不占容量。来源成功后重新走历史覆盖复用，失败、超时或停止后自动重新规划；队列失败与非 RPC 终态由恢复守护兜底。显式重试和风险验证继续绕过。进入 G20。
- 2026-08-09：G20 完成；Server 不信任 Agent 覆盖事件声明网络边界，而是从已注册 Node 标签和每个目标派生。公网工作可跨 Agent 关联，同一 `network_zone` 的私网工作可安全共享，不同区域和无标签私网保持隔离；私网/保留目标不能被 `network_scope=public` 提升。进入 G21。
- 2026-08-09：G21 盘点发现当前 Coverage 虽按 Stage 保存，但 Agent 未保存可重放的端口、协议和 HTTP 中间检查点；直接跳到下游 Stage 会丢失输入并造成漏扫。为保持准确性，将 G21 拆为 G21A（失效/TTL/force 语义）与 G21B（最小依赖闭包和检查点重放），先进入 G21A。
- 2026-08-09：G21A 完成；Server 为完整覆盖设置有界 TTL，WorkKey 漂移与过期证据固定补扫，上游内容变化仅失效较旧依赖阶段，乱序事件不能推翻更新证据；手动重试继续绕过复用/合并并形成新证据。进入 G21B。
- 2026-08-09：为保持提交和验证边界最小，将 G21B 细分为 B1 检查点契约/存储、B2 Planner 最小依赖闭包、B3 Agent 恢复执行。检查点只保存端点等派生资产，不保存 HTTP 响应正文；先进入 G21B1。
- 2026-08-09：G21B1 完成；单目标 Agent 可上报经排序去重、数量限制和目标归属校验的派生检查点，Server 将规范 JSON/哈希追加到 Observation。多目标和无法证明域名到 IP 归属的数据不产生检查点，且 B1 不改变当前调度。Migration 360 已真实 apply/verify，进入 G21B2。
- 2026-08-09：G21B2 完成；Server 为单目标按有效 Coverage 与检查点计算严格的“复用前缀 + 执行后缀”。端口可恢复协议、协议可恢复 HTTP；HTTP 正文和域名 DNS 映射不可重放时回退到最早必要阶段，任何过期、漂移、损坏、来源未完成、多目标或 force 场景均不跳扫。B2 尚不下发或执行计划，进入 G21B3 完成最终租约复核与 Agent 子阶段执行。
- 2026-08-09：G21B3 完成；Server 只向 v2.6.0+ 且规则一致的 Agent 下发经最终租约事务重建复核的恢复计划，并原子保存复用来源。Agent 独立验证目标、配置阶段、规则、计划摘要和检查点依赖，恢复端口/协议派生输入后仅执行和上报计划后缀；旧 Agent 完整扫描，任何篡改或漂移失败关闭。进入 G22 补齐 UI 复用解释与节省量。
- 2026-08-09：G22 完成；任务详情将 CoverageLink、Coverage、WorkClaim 和失效记录聚合为稳定只读解释，展示实际执行、历史复用、仍在等待的来源、失效/过期、节省阶段和完整目标，并可追溯同项目来源 Task/Batch/Attempt。大任务只返回最近 100 条明细但保留完整计数，内部 WorkKey/配置哈希/租约不出 API。Phase 2 完成，进入 Phase 3 的 G23 CLI 离线文本历史目录。
- 2026-08-09：Phase 3 开始；切换到 `codex/cli-offline-memory`，G23 先只建立跨平台的 `argus-data` 根目录解析和 `ARGUS_HOME` 覆盖，不提前引入 TSV 状态语义或新必填参数。
- 2026-08-09：G23 完成；CLI 扫描初始化会幂等建立私有 `argus-data` 根目录，默认跟随真实可执行文件，`ARGUS_HOME` 可迁移到其他磁盘并支持相对路径。根目录绝对路径只保存在本地 ScanContext，Agent 不使用且不上传；进入 G24 定义版本化 TSV 表头和每次运行目录。
- 2026-08-09：G24 完成；CLI 每次扫描在唯一 Run 目录中保存版本化目标、结构化发现、覆盖占位和运行摘要，长期 assets/coverage 表先建立严格表头。观察器与 Agent 输出通道正交，敏感 POC 原始流量、凭据和命令详情不落盘；进入 G25 实现临时文件原子替换、状态归并和中断恢复。
- 2026-08-09：G25 完成；Run 目录成为可恢复提交日志，状态归并在跨进程锁内使用平台原子替换，重复和乱序证据幂等收敛。恢复器跳过仍活跃 CLI，中断运行不污染状态，待提交终态和 G24 旧历史可安全补归并；首次升级后仅检查异常锁标记，避免全历史启动开销。进入 G26，把 `internal-fast` 计划、轻量复核和阶段覆盖真正接到 CLI。
- 2026-08-09：G26 完成；CLI 普通扫描默认关闭风险探测并按本地 WorkKey 规划。新目标或不可证明覆盖全扫；有效 IP 类端口覆盖先按当前端口范围轻量复核，稳定后复用端口检查点并从协议阶段补扫，变化或任何漂移立即回退。独立 Run 明确记录 full/incremental、executed/reused 与来源证据；进入 G27，将当前内置 TTL 和轻量复核预算迁入 `argus-data/config.yaml`，并补齐每次存活复核策略。
- 2026-08-09：G27 完成；CLI 自动生成并严格加载版本化本地策略，TTL 与复核预算可在不增加命令参数的前提下调整。默认每次轻量复核已知主机与服务并独立记录 liveness，策略漂移通过 ConfigHash 使旧覆盖失配；显式风险阶段按 24h 记录但普通扫描仍不会自动启动 POC。进入 G28，仅增加兼容的 `-force` 绕过本地复用。
- 2026-08-09：G28 完成；`-force` 只在 CLI 本地上下文生效，跳过覆盖复核与恢复计划并完整执行当前授权范围，结果继续追加且不打开 POC。默认命令和旧参数不变；进入 G29，统一离线 CLI 的版本化 Arsenal 包来源、替换/导入与校验链路。
- 2026-08-09：G29 完成；CLI 扫描不再忽略本地数据库弹药库，正式发行包携带与 Server/Agent 同源的运行时 `arsenal.db`，固定目录替换后自动校验、物化和版本失效，管理子命令也迁到同一目录。数据库损坏、EXP 分类或路径逃逸均失败关闭，普通扫描仍不自动执行 POC；进入 G30，补齐每次本地扫描的新增、变化、消失、复用和实际执行差异摘要。
- 2026-08-09：按用户要求暂停 G30 并改为一次只推进一个具体 Goal；I165 已完成。复现确认主线共享 `DefaultConfig` 默认开启 GoPoc、CLI 默认关闭的分裂，但原 Issue 要求默认爆破已被当前安全决策取代；共享默认已统一安全关闭，已有 `-gp/-poc` 显式入口、Server 风险验证和 Agent 失败关闭均保留。下一 Goal 尚未创建。
- 2026-08-10：创建 G30 并关联 Issue #166；切换到 `codex/cli-run-diff`。本 Goal 只为 CLI 本地 Run 增加版本化差异证据和文本摘要；新增/变化基于归并前状态，执行/复用来自本 Run coverage，确认消失必须同时满足成功完整扫描、权威阶段、目标归属及 scope/config/rule 可比条件，证据不足统一 `not_assessed`。delta 先于长期状态原子写入并由恢复器复用，不改变 JSON findings stdout、Server/Agent 或 POC/EXP 安全边界。
- 2026-08-10：G30 完成；CLI 每个 Run 都保留版本化 delta 与向后兼容计数，文本输出可直接区分新增、变化、确认消失、未评估、实际执行和复用。消失/重现同时绑定完成状态、可信历史、阶段证据与观察时序；失败 Run、延迟旧观察和 stale recovery 均不能撤销较新状态。真实 POC-off 双跑确认增量复用不覆盖完整端口基线，JSON 模式不输出人类摘要；独立复核无 Critical/Important。下一 Goal 尚未创建。
- 2026-08-10：创建 G31 并关联 Issue #167；Phase 4 切换到 `codex/scanner-performance`。当前基线复测显示 `argus -h` 10 次暖样本 P50 403.26ms、P95 515.06ms，明确 localhost URL、POC-off 的首轮 1263.89ms、后续约 743–766ms，但现有链路无法区分进程、规则、上下文和阶段成本。本 Goal 仅建立 `argus.timing/v1`、CLI 本地 timing、Agent→Server 追加证据、授权任务展示和可重复基线工具；不提前实施 G32–G36 优化。
- 2026-08-10：G31 完成；CLI Run、Agent Attempt、Server 追加历史和任务详情 UI 已统一使用有界计时契约，旧 Agent/旧 Run 明确 unavailable，计时不含目标、配置正文、凭据或扫描响应。当前环境的 URL POC-off 与 Agent context 门槛达标，`argus -h` 暖 P95 478.15ms 仍高于 300ms，因此仅把可重复证据留给 G32，未在本 Goal 混入懒加载优化。Migration 410 不绑定可被清理的 Node，仍以 Attempt+Agent 归属和实时会话校验防止伪造；独立复核最终无 Critical/Important。下一 Goal 尚未创建。
- 2026-08-10：创建 G32 并关联 Issue #168；复现确认 gonmap package init 在 help 前解析完整探针，inittrace 单次约 318ms、308 MiB 分配/139 万次 allocation，补充 3/30 release 样本 P95 482.49ms 与 G31 源码基线趋势一致。本 Goal 只把探针库延迟到首次协议识别并保持并发安全、`SetFilter` 快照兼容和协议结果一致；不混入 G33–G36 或扫描策略变更。
- 2026-08-10：G32 完整回归发现 G31 的零时长 Builder 会把极短阶段误判为无效区间并中断 Agent 结果流；以独立提交 `b79e668` 修复并在 #167 留证。零时长仍是合法单调时钟证据，非零 Duration 和显式 FinishedAt 语义不变，Agent 全包及连续定向回归通过，独立复核无 Critical/Important。
- 2026-08-10：G32 完成；gonmap 探针只在首次真实协议识别时构建，help 和空闲 Agent 不再承担约 292ms/308 MiB 的解析成本，最终 3/30 help P95 为 104.53ms，明确 URL、POC-off P95 为 544.69ms。并发初始化、`SetFilter` 新旧快照、首次失败稳定重放、离线 banner、Docker race 和 localhost 协议 smoke 均通过；最终复核无 Critical/Important。下一 Goal 尚未创建。
- 2026-08-10：创建 G33 并关联 Issue #169；当前版本在 loopback 静默服务上以 `-wto 2` 扫描明确 HTTP URL 仍耗时 7634.49ms，确认 retry/backoff 和多轮调用把请求级 timeout 叠加成目标总耗时。G33 只建立 HTTP 目标级 deadline、父取消和显式 Scheme 契约，不提前迁移 G34 全局 URL 去重，也不改变目录、HostBind、POC/EXP 或 Server Attempt 超时语义。
- 2026-08-10：G33 完成；主 HTTP 探测的 retry、兼容 fallback、脚本/meta 跳转和同源重定向现在共享每目标总预算，明确 Scheme 不再探测替代协议，父取消会进入真实请求并等待 Runner 收敛。最终同口径 3/30 基线的 1 秒预算 P95 为 1.416s，2 秒 CLI smoke 墙钟 2.468s；超时证据不会成为可复用阴性覆盖，混合目标仍保留成功结果。两项独立 review Important 已修复，最终无 Critical/Important；下一 Goal 尚未创建。
- 2026-08-10：创建 G34 并关联 Issue #170；顺序 loopback 复现确认前一 Session 会让后一任务丢失脚本 follow-up，Docker Linux race 确认进程级 `GlobalUsedUrl` 存在真实读写竞争。当前 Goal 只把 URL 调度集合迁入 `ScanContext` 并通过窄接口注入 httpx，保留 G33 deadline/Scheme/取消和全部扫描安全边界，不提前实施 G35/G36。
- 2026-08-10：G34 完成；HTTP URL 去重成为当前任务 Context 的原子首次占用状态，包级入口和不同任务不再互相抑制，CLI 连续执行由 `Reset()` 隔离。顺序漏扫复现、Windows 回归、最终 Linux race、POC-off CLI 和重建 Agent smoke 均通过；独立 review 的两项 Important 已修复并复核为无 Critical/Important。下一 Goal 尚未创建。
- 2026-08-10：创建 G35 并关联 Issue #171；同 Arsenal 3/30 before P95 为 153.013ms，确认每个 Agent Context 仍重复解析完整规则。审计同时发现规则确认与 `runningTasks` 登记之间存在热切换窗口，因此本 Goal 将缓存与任务版本捕获一起完成；只共享 Fingerprint/Workflow/Dir 不可变快照，不提前缓存 Nuclei/HybridMap 或改变扫描安全策略。
- 2026-08-10：G35 完成；Agent 以实际 Arsenal SQLite SHA-256 与规则版本共享只读知识快照，任务配置、结果、URL、Hook、取消器、ResumePlan、POC runner 和 HybridMap 保持隔离，热更新等待初始化与运行使用者全部退出。最终 Agent Context P95 为 45.305ms，Docker Linux race、POC-off CLI、重建 Server/Agent 与认证失败关闭 smoke 均通过；独立 review 的基线身份 Important 已修复并复核为无 Critical/Important。下一 Goal 尚未创建。
- 2026-08-10：创建 G36 并关联 Issue #172；当前同 Arsenal 3/30 无目标 Context before P95 为 53.840ms，源码确认每个 Agent/CLI Context 仍无条件创建三份磁盘 LevelDB。当前 Goal 只用保守、无需展开目标的策略让可证明有界的小任务使用内存，范围未知或可扩展任务继续落盘；Nuclei 执行态含目标、凭据、回调、输出与风险验证哈希边界，评估结论固定为不跨任务缓存。不会改 CLI 参数、扫描范围、阶段、Coverage、HTTP/URL/规则缓存或 POC/EXP 安全默认。
- 2026-08-10：G36 完成；Agent 与 CLI 通过统一 factory 仅为无扩张的有界任务创建内存响应存储，目录探测、HostBind、Provider、子域、裸主机、范围和大任务继续使用磁盘 HybridMap，三张 map 保持任务私有并在部分失败时完整回滚。Nuclei 执行态缓存经审计判定不安全而未实施，仅修复初始化失败的临时 HMap 泄漏。最终 memory factory P95 为 14.690µs、disk P95 为 52.674ms，Docker Linux race、POC-off CLI 和重建 Agent smoke 通过；独立 review 的无界目录探测 Important 已修复并复核为无 Critical/Important。下一 Goal 尚未创建。
- 2026-08-10：创建 G37 并关联 Issue #173，Phase 5 切换到 `codex/cli-compatibility`。真实 CLI 复现确认主帮助和 Banner 仍是 argus 品牌、`--version` 不存在，并继续公开/执行已迁到 Server 的 FOFA/Hunter/Quake 参数。当前 Goal 保留 `argus` 及全部通用扫描兼容，只统一 Argus 用户可见文案和版本入口，并在任何本地 Provider 网络或凭据访问前返回明确迁移提示；Engine/Agent legacy 与 G38 机器输出不混入。
- 2026-08-10：G37 完成；发行命令和 94 个通用帮助 flag 保持兼容，旧版 108 个帮助 flag 的差集精确等于 14 个 Server-only Provider flag/别名且无意外增删。`--version`、主帮助和三个规则子命令统一为 Argus CLI，17 种 Provider 参数写法均在初始化前返回 2、给出项目“资产测绘”迁移提示且不创建 `ARGUS_HOME`。最终 CLI SHA-256 为 `2b85c6a706601bedf86bcdfec840b5d69edcb5634763349ce3fff7507d0d79a0`；帮助/版本 3 次预热、30 次采样 P95 分别为 132.879ms/132.839ms，本机 UI 显式 URL 的 `-npoc` 扫描返回 200。G37 包测试和 Docker Linux race 各连续 10 轮、定向 vet、本 Goal 文件源码体积检查与 `git diff --check` 通过；全仓源码检查仍只有既有超限文件，根模块全量仅命中既有 Agent 时序波动、Windows Python 9009、SQLite 临时句柄和符号链接权限基线，完整 vet 仅有 3 条既有告警。独立只读 review 最终无 Critical/Important；下一 Goal 尚未创建。
- 2026-08-10：创建 G38 并关联 Issue #174；安全 loopback 复现确认当前 `-ot json` stdout 被 Banner 污染、stderr 含 ANSI 和普通扫描日志，finding 又缺少版本与终端完整性记录，`-ot` 非法值和失败退出码也未形成契约。当前 Goal 保留逐 finding 流式兼容并正式定义版本化 NDJSON，只治理 Standalone CLI 的机器/非 TTY 表现和 0/1/2/130 退出码；Agent/gRPC、扫描阶段、规则、授权及 POC/EXP 安全默认不变。
- 2026-08-10：G38 完成；CLI 机器输出成为版本化 UTF-8 NDJSON，成功、零发现、usage、非 TTY 文本和结果文件一致性均由真实本机黑盒覆盖，GoPoc/Nuclei 的 CLI 专用展示不会改变 Agent 默认。终态双写在 stdout 失败时回滚文件中的成功状态，输出/代理错误也不回显凭据。最终 CLI SHA-256 为 `07ea8fdaeffd270569ce088eb4dd59574168d28cf1aa7205c8bb77b71957e1b6`；定向测试、vet、Docker Linux race 和 diff check 通过，独立 review 的 Important 已修复并复核无 Critical/Important。下一 Goal 尚未创建。
- 2026-08-10：曾创建 G39A/Issue #175 作为五类任务变更共用的横向幂等基础；用户指出大量底层提交不易判断实际价值并要求后续按独立纵向 Goal 完成，因此未提交的 G39A schema/helper 已撤销，不计为完成。Issue #175 已说明原因并以 `not planned` 关闭；G39 后续按创建、追加、Task retry、Batch retry、风险验证五条用户操作分别闭环。
- 2026-08-10：创建 I164N 并继续关联 Issue #164；优先完成用户可见的“测绘笔记本确认并分发到现有任务”闭环。该 Goal 同时包含预览过期校验、专用 intent 幂等、授权/网络/风险复核、Scope/SeedTargets、TaskBatch/Attempt、审计、提交后派发、前端确认和真实 smoke，不再把同一能力按数据层、API、前端或测试拆成多个 Goal。
- 2026-08-10：I164N 的后端、前端、Migration 420、文档和自动化验证已收敛；补充审计发现幂等重放曾把仍处于 `Dispatching` 的恢复任务反馈为零，现改为从同一 tenant/project/task 的冻结 Attempt 重建派发状态并补成功/待恢复重放测试。独立 completion audit 无 Critical/Important；当前仅等待 Server 重启后的登录态真实浏览器 smoke，Goal 仍保持 `in_progress` 且不创建后续 Goal。
- 2026-08-10：I164N 连续第三个 Goal 回合仍停留在登录页，无法在不绕过认证的前提下完成强制真实浏览器 smoke，因此按阻塞规则标记 `blocked`。本地暂停任务与 `.invalid` 目标验收夹具保留且不会派发；未提交当前 diff，也未创建后续 Goal。恢复条件：用户在当前 Argus 页面登录并回复“已登录”。
- 2026-08-10：用户明确授权使用本地测试账号后登录成功，I164N 从 `blocked` 恢复为 `in_progress`；继续只对暂停验收任务执行真实 UI smoke，不读取浏览器存储、不触发真实扫描。
- 2026-08-10：I164N 完成。登录浏览器真实执行“笔记本选中 → 只读预览 → 显式确认 → 任务详情”，确认暂停任务仅产生 1 个暂停 Batch、1 个暂停 Attempt 和 1 条“测绘笔记本分发”审计，Scope/SeedTargets/OriginalTargets 均为保留 `.test` 目标且没有 Agent 派发；数据库计数、自动化幂等重放、PostgreSQL migration/schema、前端全量检查和最终独立 review 通过，临时项目、任务及所有关联证据已事务清理。I164N 标记 `completed`，不在本 Goal 内创建后续任务。
- 2026-08-10：创建独立纵向 G39A 并关联 Issue #176，分支切换为 `codex/task-create-idempotency`。源码复现确认 `POST /tasks` 当前忽略 `Idempotency-Key`，相同请求会生成不同 Task ID 并重复写 RootTask/Batch/Attempt/审计和派发。当前 Goal 仅让任务创建可安全重试：旧客户端请求头可选、Web UI 自动携带稳定 Key、同请求重放只返回首次任务、异请求冲突失败关闭；增加批次、Task/Batch retry 和风险验证不混入本次实现。
- 2026-08-10：G39A 完成。创建任务 UI 在一次提交意图内稳定复用 Key，网络失败可直接安全重试；Server 在认证、RBAC 和项目对象授权后，以同一事务原子记录幂等账本与首次任务全部对象，同请求重放首次 Task 且不再次派发，异请求 409。真实 PostgreSQL 并发、登录浏览器创建、前端全量、Migration 430、Server 定向测试和独立 review 均通过；审查发现的重放摘要漂移已改为从冻结首批 Attempt/TaskBatch 与配置 v1 重建。验收数据已清理，本 Goal 不自动创建增加批次、Task/Batch retry 或风险验证的后续 Goal。
- 2026-08-10：创建独立纵向 G39B 并关联 Issue #178，分支切换为 `codex/task-append-idempotency`。源码与既有回归确认当前 append 会按 Task 内目标自然去重，但不识别 `Idempotency-Key`，因此丢失首次响应后无法稳定重放首次批次/计数，同 Key 改成其他目标也不会冲突。当前 Goal 仅让“增加目标/批次”可安全重试并冻结首次结果；Task retry、Batch retry 和风险验证不混入本次实现。
- 2026-08-10：G39B 完成。增加批次 UI 在一次提交意图内稳定复用 Key，网络失败可直接安全重试；Server 在认证、RBAC、tenant/task/project 对象授权和 RootTask → Project 锁后，按首次冻结配置规范化目标，在同一事务记录账本、追加 Batch/Attempt、扩展项目范围、更新 Task 聚合并写审计，同请求重放不再次入队，异请求 409。真实 PostgreSQL 并发、登录浏览器与 HTTP 并发、Migration 440、Server/DB、前端、文档和最终独立 review 均完成；审查发现的等价 URL 哈希与投递状态契约问题已修复。验收任务已归档，本 Goal 不自动创建 Task retry、Batch retry 或风险验证的后续 Goal。
- 2026-08-10：创建独立纵向 G39C 并关联 Issue #179，分支切换为 `codex/task-retry-idempotency`。源码和既有回归确认当前 RootTask 行锁通常能防止并发重复 Attempt，但接口忽略 `Idempotency-Key`，首次事务成功而响应丢失后，相同请求会因任务已转 `Running` 返回 409，无法重放首次结果。当前 Goal 只让 Task 级“重试失败批次”可安全重放；Batch 单独重试和风险验证不混入本次实现。
- 2026-08-10：G39C 完成。任务级重试现在以 tenant/project/task/operator/operation/Key-hash 为唯一作用域，将幂等账本、新 Attempt、RootTask 状态和单条审计原子提交；同请求重放冻结业务结果且不再次派发，异请求 409，无 Key 客户端保持兼容。前端网络失败保留同一 Key，跨任务旧请求不能释放新任务锁；真实 PostgreSQL 并发、登录浏览器、Migration 450、Server/DB、前端全量、文档和最终独立 review 均完成，审查发现的 Key 哈希文档歧义已修复。验收任务已停止并归档，本 Goal 不自动创建 Batch retry 或风险验证的后续 Goal。
- 2026-08-10：用户明确要求本轮完整收尾整个 G39，不再逐项询问。创建 G39D/Issue #181 与 G39E/Issue #180；先在 `codex/batch-retry-idempotency` 完成单批次重试闭环并聚焦提交，再连续切换 `codex/risk-validation-idempotency` 完成风险验证执行闭环，最终将 G39 标记完成，不再新增 G39F。
- 2026-08-10：G39D 完成。单批次重试现在在 RootTask → TaskBatch → latest Attempt 锁内优先读取按 tenant/project/task/batch/operator 隔离的幂等账本；首次写入把新 Attempt、状态更新、单条审计和账本原子提交，提交后才派发，重放不再次入队。Migration 460、真实 PostgreSQL 同 Key 并发、登录浏览器、Server/DB、前端及独立 review 完成；前端审查发现的旧详情请求覆盖新任务配置/加载状态问题已修复。下一步按用户要求直接进入 G39E，不暂停询问。
- 2026-08-10：创建 G39E 并切换到 `codex/risk-validation-idempotency`。本 Goal 只闭环已存在的风险验证 preview → 显式确认 → execute 操作：新 Key 必须重新验证 plan/config/rule/POC 内容和双重确认；已提交的同 Key 同请求在当前对象仍可访问且未归档时稳定重放，不重复创建风险 Batch/Attempt、审计或派发。完成后直接将总项 G39 标记完成，不再创建 G39F。
- 2026-08-10：G39E 与总项 G39 完成。风险验证确认现在与 preview/config/rule/POC 内容、候选集合和双重确认共同绑定到稳定 Key；首次业务写、审计和账本原子提交，重放不再次派发，变更或陈旧计划失败关闭。Migration 470、真实 PostgreSQL 同 Key 并发、登录浏览器、Server/DB、前端全量、文档及两轮独立 review 完成；浏览器暴露的空集合 `null` 崩溃已修复，验收夹具已归档并精确清理。G39A–G39E 五条用户操作链全部闭环，不再新增 G39F；下一 Goal 尚未创建。
- 2026-08-10：用户明确要求暂不做 AI 相关工作。G40 保持 `pending` 且标记为暂缓，不创建 Goal、不切分支、不实施代码；下一非 AI 候选为 G41 文档、完整回归和发布检查，但同样不会在用户确认前自动开始。
- 2026-08-10：用户要求把除 AI 外的全部剩余工作合并为一个 Goal 完成。创建 G41 并切换到 `codex/g41-non-ai-completion`：以 Issue #164 的 Server-only 测绘边界为主线，补齐 Notebook 筛选/标签/备注/软移除与授权运营视图，彻底切断 Scanner/Agent Provider 搜索和凭据链，并统一完成文档、数据库/API/UI、兼容拒绝、完整回归、浏览器及 CLI/Agent smoke。G40 继续暂缓且不进入本 Goal。
- 2026-08-09：创建 I164A，按 Issue #164 建议先实现 Server FOFA 资产发现核心。该最小 Goal 不改变 CLI/Agent 行为、不暴露外部接口，也不把凭据写入任务或日志；完成后再创建下一迁移 Goal。
- 2026-08-09：用户确认将核心测绘逻辑从 CLI/Agent 完整剥离到 Server，并增加查询、导出和项目级测绘笔记本；有价值结果可一键归档，之后经授权、去重、幂等和审计统一分发为任务批次。I164A 范围保持不变，后续能力逐个创建最小 Goal。
- 2026-08-09：I164A 完成；Server 已具备不依赖 Scanner 的 FOFA 查询、响应预算、目标规范化和去重核心，且凭据不进入结果或错误。当前没有公开入口和持久化副作用，#164 保持开放；下一 Goal 尚未创建。
- 2026-08-09：创建 I164B；只新增项目授权的 FOFA 查询预览 API，使用当前租户已批准的 Server API 配置并记录不含原始查询/凭据/响应的专用审计。结果不保存、不导出、不进入笔记本或 Task/Batch；这些能力必须在 I164B 验收后逐项创建新 Goal。
- 2026-08-09：用户补充测绘迁移不应局限于 FOFA，也不要求一次实现全部第三方 API。后续先从现有 CLI/Agent 运行时调用链建立 Provider 优先级，优先迁移 Hunter、Quake 和高价值被动资产 API；I164B 继续作为统一授权、凭据隔离、预算、错误和审计基线，范围不扩张。
- 2026-08-09：I164B 完成；FOFA 查询现已具备项目授权、operator RBAC、租户 Approved 配置、请求预算、脱敏错误和失败关闭审计，且仍不持久化结果或触发扫描。Issue #164 保持开放；完成聚焦提交后再创建下一个 Provider 优先级 Goal。
- 2026-08-09：创建 I164C；源码盘点确认直接测绘执行链的一等 Provider 是 Hunter/FOFA/Quake，其中低感知模式明确优先 Hunter，因此先实现 Server 内部 Hunter 核心。当前 Goal 只建立可测试的有界分页 Provider，不新增路由、不读取配置，也不改变 CLI/Agent；Quake 和被动子域 API 后续逐项评估。
- 2026-08-09：I164C 完成；Hunter 已迁入 Server 内部有界 Provider 核心，移除旧实现的逐页固定等待、隐式重试和 banner 扫描状态耦合，以一次总超时/总响应预算返回统一规范资产。它尚未开放路由或读取租户凭据；完成聚焦提交后再创建下一 Goal。
- 2026-08-09：创建 I164D；先让 Hunter 复用 FOFA 已验证的项目授权、租户 Approved 配置和失败关闭审计，形成可用 Server 查询入口，再继续增加 Quake。当前 Goal 不持久化查询结果，不进入导出、笔记本或任务分发。
- 2026-08-09：I164D 完成；Hunter 已具备与 FOFA 同等级的项目授权、operator RBAC、租户 Approved 凭据、请求预算、脱敏错误和失败关闭审计入口。两个 Provider 仍只返回本次预览，不保存资产或触发扫描；完成聚焦提交后再创建下一 Goal。
- 2026-08-09：创建 I164E；直接测绘一等 Provider 中仅剩 Quake。当前 Goal 只实现 Server 内部单次有界查询，去掉旧实现查询前固定等待和额外账户 VIP 探测；使用显式最小结果字段并允许缺少高级字段时回退 IP:Port，不新增路由或改变 CLI/Agent。
- 2026-08-09：I164E 完成；FOFA/Hunter/Quake 三个直接测绘 Provider 均已有独立 Server 核心。Quake 现在单次有界查询并安全收敛结果展开，不再为每次查询预先访问账户接口；它尚未开放路由或读取租户 Token，完成聚焦提交后再创建下一 Goal。
- 2026-08-09：创建 I164F；将 Quake 接入与 FOFA/Hunter 相同的项目授权、operator RBAC、当前租户 Approved 配置和失败关闭审计。当前 Goal 仍只返回一次查询预览，不保存资产、不导出、不进入笔记本或任务分发。
- 2026-08-09：I164F 完成；FOFA/Hunter/Quake 三个第一梯队 Provider 均已具备 Server 项目授权查询预览，统一使用当前租户 Approved 配置、请求预算、脱敏错误和失败关闭审计。完成聚焦提交后再按价值优先建立结果持久化/导出/笔记本方向的下一最小 Goal，不继续机械增加 Provider。
- 2026-08-09：创建 I164G；先为一次成功测绘建立项目级查询快照和规范资产项的追加式 schema，作为后续历史查询、导出和笔记本归档的共同来源。当前 Goal 不接入 FOFA/Hunter/Quake Handler、不改变 API 响应、不写现有 `assets`，也不提前实现导出、笔记本或任务分发。
- 2026-08-10：I164G 完成；Migration 380 建立按 tenant/project 复合外键隔离的不可变测绘查询快照与规范资产项，查询内目标唯一，凭据和 Provider 原始响应无存储字段。迁移已在本地 PostgreSQL apply/verify，并以事务内负向写入验证跨项目挂接和重复目标均失败；完成聚焦提交后再创建原子写入快照的下一 Goal。
- 2026-08-10：创建 I164H；把三个 Provider 的成功收敛路径统一为审计、快照和资产项原子事务，并在持久化边界重新校验 Provider、数量、目标和最小元数据。当前 Goal 不新增查询历史/导出 API，不改当前 `assets`，也不进入笔记本或任务分发。
- 2026-08-10：I164H 完成；三个 Provider 只有在成功审计、查询快照和全部规范资产项同事务提交后才返回结果，校验或写入失败会完整回滚并隐藏结果。完成聚焦提交后再按价值优先创建项目级测绘查询历史读取 API，不把历史、导出和笔记本混入同一 Goal。
- 2026-08-10：创建 I164I；只开放项目内成功查询快照的历史列表和单次明细读取，列表与资产项分别有界分页，viewer 仍须通过项目对象授权。当前 Goal 不实现导出、笔记本写入、项目资产合并或 TaskBatch 分发。
- 2026-08-10：用户指出仅实现后端不足以形成可用模块；I164I 在提交前扩展为前后端闭环，新增独立“资产测绘”页面，operator 使用项目、Provider 和表达式即可查询，viewer 可筛选历史并查看分页明细。仍不把导出、笔记本和任务分发混入本 Goal，登录页动效保持不变。
- 2026-08-10：用户要求页面内直接提供官方语法并支持补全；I164I 增加按 Provider 切换的官方常用字段、逻辑符和安全示例速查，链接 FOFA、Hunter、Quake 官方帮助，并提供鼠标与键盘均可操作的字段补全。Server 继续原样转交表达式，补全目录不作为语法白名单，避免官方语法升级后被前端错误拦截。
- 2026-08-10：I164I 完成；项目成员可在独立页面查询并查看有界历史快照，viewer/operator 权限和 tenant/project/snapshot 对象边界保持一致。独立 review 发现的项目切换竞态和引号内误补全已补测试修复；导出、测绘笔记本、项目资产合并和任务分发仍留给后续独立 Goal，当前不自动创建下一 Goal。
- 2026-08-10：创建 I164J；下一项先补齐单个查询快照的 CSV 导出。Server 必须在同一 tenant/project/snapshot 边界内读取全部规范资产，施加 10000 行、32 MiB 和 10 秒预算，防 CSV 公式注入并在成功前写脱敏导出审计；前端只增加历史快照一键下载。查询表达式、内部哈希、凭据和 Provider 原始响应不进入文件，笔记本、项目资产合并和 Task/Batch 分发继续保持独立 Goal。
- 2026-08-10：I164J 完成；项目历史快照现在可由 Server 安全导出完整 CSV，viewer 仍须通过项目对象授权，导出成功必须先写当前用户脱敏审计。独立 review 发现的项目授权与审计未共用 10 秒预算、快照超时分类不一致均已补测试修复，最终无 Critical/Important；下一最小 Goal 未自动创建。
- 2026-08-10：创建 I164K；下一项只建立项目级测绘笔记本的归档与列表闭环。项目内同一规范目标只保存一次，但每个被选择的快照项都建立来源关联，后续可解释重复发现；operator 才能写入，viewer 可读取，归档项目保持只读。归档与脱敏审计在同一事务内失败关闭，且不把测绘命中直接并入项目资产、授权范围或任务队列；标签、备注、移除及 TaskBatch 分发继续拆为后续 Goal。
- 2026-08-10：I164K 完成；Migration 390、项目授权归档/列表 API 和前端测绘笔记本已形成闭环，同一项目按规范目标去重并保留跨快照来源，重复来源幂等，审计失败回滚，归档项目只读。PostgreSQL apply/verify、后端目标测试、DB 全包、前端 21 文件 105 测试、lint（0 error，15 个既有 warning）、build 与 smoke 均通过，新 Server 已在 8085/50051 运行；全量 Server 只剩既有 Windows SQLite 文件句柄清理与相对 `build.sh` 两项失败，source-size 也仅报告既有基线超限。独立只读 review 无 Critical/Important。浏览器真实登录后页面 smoke 因 Server 重启后的会话回到登录页而未绕过认证；下一 Goal 尚未创建。
- 2026-08-10：创建 I164L；本 Goal 只建立笔记本选中项到现有任务的只读分发预览。operator 必须显式选择同一 active 项目的现有任务，Server 重新校验项目、Task、笔记本条目和当前配置修订，只接受普通 direct 安全扫描任务，并复用 append 的规范化、任务内去重和分批规则，返回新增/重复目标、Scope/SeedTargets 预计增量、批次画像和稳定 plan hash。前端提供批量选择、任务选择和预览说明；不写任何业务表、不触发队列或 Agent。实际幂等物化、Idempotency-Key、分发意图审计和任务派发留给完成本 Goal 后创建的独立 Goal。
- 2026-08-10：I164L 完成；operator 可在项目测绘笔记本中选择 1–100 个候选资产和任意分页中的同项目可追加任务，查看任务内新增/重复、Scope/SeedTargets 预计增量、分批画像与版本绑定计划哈希。Server 全程只读并重新校验 tenant/project/task/item、生命周期、配置和规则版本，viewer 与归档项目无操作入口。独立 review 发现的默认只加载前 20 个任务问题已改为逐页读取、按 ID 去重和可搜索选择并补第 101 项回归，最终无 Critical/Important。实际物化、Idempotency-Key、分发意图/审计、授权确认和队列派发仍未实现；下一 Goal 尚未创建。
- 2026-08-10：创建 I164M；先建立未来确认接口所需的分发意图、逐项冻结快照和按 tenant/project/operator/operation 隔离的 Idempotency-Key 哈希契约，并提供仅数据库内部使用的原子记录/重放/冲突语义。本 Goal 不新增任何 HTTP/UI 入口，不把 intent 当成扫描授权或确认，不创建 TaskBatch/Attempt、不扩展 Scope/SeedTargets、不写 TaskAudit、不入队；实际授权复核、network zone/risk policy 校验、业务审计与物化继续留给后续独立 Goal。
- 2026-08-10：I164M 完成；Migration 400 已建立 tenant/project/task/config/notebook 复合约束的分发意图和逐项不可变快照，内部记录函数只保存 Idempotency-Key SHA-256，并在同作用域、操作者和操作域内实现同请求重放、异请求冲突及逐项写入失败全事务回滚。PostgreSQL apply/verify、真实回滚事务中的正向写入与跨项目/配置/幂等/哈希约束、DB 全包和 `go vet ./...` 均通过；全量 Server 仅保留既有 Windows `arsenal.db` 临时文件句柄和相对 `build.sh` 两项失败，source-size 仅报告既有基线超限。独立只读 review 无 Critical/Important。此 Goal 没有 HTTP/UI 行为，因此未运行前端与浏览器测试；实际授权确认、审计、TaskBatch/Attempt 原子物化和派发仍留给下一独立 Goal，当前未创建下一 Goal。
