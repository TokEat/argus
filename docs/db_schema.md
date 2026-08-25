# Argus 数据库设计总览

本文档按当前项目整体架构整理 PostgreSQL 中的核心数据模型，覆盖控制面调度、结果聚合、规则治理、系统配置四条主链路。

当前以以下实现为准：

- `deploy/db/init/001_init.sql`：版本重启（v001）后的最小基线 DDL，由 `deploy/db-init.sh` 纯 SQL 导入
- `server/internal/db/schema_verify.go`：启动后表/列/索引契约
- `server/internal/db/schema_version.go`：启动期 schema 版本校验（`RequiredSchemaVersion`）
- `server/internal/db/db.go`
- `server/internal/db/rule_catalog.go`
- `server/internal/db/task_lifecycle.go`

> 注：
> - 本文覆盖控制面主链路的核心表，**不是全部表的穷举清单**；完整权威来源是 `deploy/db/init/*.sql` 与 `schema_verify.go`。文中字段为节选，未列出的列以 DDL 为准。
> - 数据库初始化与项目启动已分离：`deploy/db-init.sh`（psql 纯 SQL 导入，不依赖二进制）负责建库/建角色/基线导入/种子/自检；`argus-server` 启动时只做连接重试 + 版本校验 + 结构契约校验，不再执行任何迁移。
> - 历史上 010..570 的嵌入式增量迁移已随 v001 版本重启退役（git 历史可查）；存量旧终态库由 `deploy/db/legacy/900_cutover_from_010_570.sql` 一次性切换。v001 起的版本演进规则：新增 `deploy/db/init/NNN_xxx.sql`（文件末尾自记 `schema_migrations` 版本），并同步推进 `RequiredSchemaVersion` 与 `schema_verify.go` 契约（当前已有 002 被动子域、003 CDN 标记两个增量）。
> - v001 收敛时删除了历史废弃对象：`cron_tasks`、`notification_rules`、`asset_change_logs` 表、`tenant_quota` 兼容视图与 `root_tasks.cron_task_id` 列（均无业务代码引用）。
> - 文中出现的 “Migration 4xx/5xx” 编号指 v001 之前的历史增量，仅作演进背景说明。
> - 规则资产不在 SQL 里，使用 `deploy/arsenal_seed.db` 和 `--seed-from-db`。

---

## 1. 架构边界与建模约定

### 1.1 存储分层

| 组件 | 职责 | 是否在本文覆盖 |
|------|------|----------------|
| PostgreSQL | 控制面元数据、任务状态、结果聚合、规则治理、系统配置 | 是 |
| RabbitMQ / 队列 | 任务排队、Pending/ACK、死任务打捞 | 否 |
| 对象存储 / 文件系统 | 报表文件、构建产物、规则源文件 | 仅覆盖元数据表 |
| Agent 本地磁盘 | Manifest、增量同步缓存、扫描中间文件 | 否 |

### 1.2 通用设计原则

- 多租户隔离使用 `tenant_id`，项目级聚合使用 `project_id`。
- 控制面主实体多使用字符串主键；高基数流水类表多使用自增整型主键。
- 结果表通过联合唯一索引 + `ON CONFLICT` Upsert 保证幂等写入。
- 扫描结果统一做 `target` 归一化，避免 URL / Host / IP 多种写法导致重复资产。
- 为保证吞吐，当前模型基本不依赖物理外键，而是通过应用层逻辑关联 `project_id`、`root_task_id`、`agent_id` 等业务主键。测绘证据链是例外：查询快照、笔记本来源及分发意图使用 tenant/project 复合外键绑定审计、资产项、任务配置和选中项，防止后续历史、导出、归档或分发链路产生跨项目挂接。
- 灵活结构统一使用 `jsonb` 或 `text(JSON)` 存储，例如标签、任务配置、节点选择器、规则详情。
- 误删风险高的实体使用软删除：当前包括 `projects`、`credentials`。

### 1.3 当前状态字段约定

| 领域 | 当前主链路会出现的状态 |
|------|------------------------|
| `root_tasks.status` | `Created`、`Queued`、`Running`、`PartialDone`、`FINISHED`、`Failed`、`Timeout`、`Cancelled` |
| `sub_tasks.status` | `Pending`、`Dispatching`、`Recovered`、`Running`、`CancelPending`、`DONE`、`FAILED`、`TIMEOUT`、`CANCELLED` |
| `nodes.status` | `Alive`、`Offline` |
| `arsenals.state` | `Draft`、`Approved` |
| `vulnerabilities.status` | `open`、`resolved` 等业务修复态 |

> 说明：任务状态在旧链路与新链路之间仍存在大小写并存的兼容情况，服务端比较时会先归一化；文档按当前实际兼容集列出。

---

## 2. 关系总览

核心数据关系可以概括为：

- `projects` 是项目隔离的顶层容器，向下关联 `project_members`、`root_tasks`、`domains`、`assets`、`credentials`、`fingerprint_hits`、`vulnerabilities`、`reports`。
- `root_tasks` 表示一次用户发起的巡航任务，向下包含稳定的 `task_batches`，每个批次以追加式 `sub_tasks` 保存真实 Attempt。
- `sub_tasks` 由 `nodes` 认领执行，并驱动结果写入 `domains`、`assets`、`fingerprint_hits`、`vulnerabilities`；阶段级证据另以 `scan_observations` 追加保存。
- `scan_coverages` 保存一个 WorkKey 的当前覆盖状态，`scan_work_claims` 为并发相同工作提供唯一占用槽，`task_coverage_links` 记录任务实际执行、历史复用或执行中挂接的来源。
- `asset_discovery_audits` 保存 Server 网络空间测绘查询、导出和笔记本归档的项目级脱敏审计；只记录查询/配置哈希、计数、状态与耗时，不保存原始表达式、凭据或 Provider 响应。`asset_discovery_snapshots` 与 `asset_discovery_snapshot_items` 是查询历史、导出和笔记本的追加式来源；`asset_discovery_notebook_items` 与 `asset_discovery_notebook_sources` 分离项目内去重目标和每次快照来源；`asset_discovery_notebook_distribution_intents` 及其 item 表冻结分发确认的幂等请求快照，`asset_discovery_notebook_distribution_materializations` 冻结确认后的 typed 结果。intent 单独存在不代表授权或执行。
- `nodes` 维护在线 Agent 的会话、容量、心跳和运行任务信息；`agent_logs` 记录节点侧黑匣子日志。
- `arsenals` 是规则文件真相源；`fingerprint_rules`、`poc_rules`、`workflow_rules`、`dir_rules` 是由 `arsenals` 物化出的结构化检索层，`rule_catalog_bootstraps` 记录物化状态。
- `system_configs` 承载全局配置与 `mcp_*` 类型的 API Key。

---

## 3. 当前落地 Schema

### 3.1 组织、租户与访问控制

#### `projects`

| 字段 | 类型 | 说明 | 约束 / 索引 |
|------|------|------|-------------|
| `id` | string | 项目主键 | PK |
| `tenant_id` | string | 租户隔离键 | Index, Default:`default` |
| `name` | string | 项目名称 | Index |
| `description` | text | 项目描述 | - |
| `tags` | jsonb | 业务标签 | - |
| `seed_targets` | jsonb | 初始目标集 | - |
| `scope` | jsonb | 授权扫描边界 / 黑白名单 | - |
| `default_config` | jsonb | 项目级默认扫描配置 | - |
| `node_affinity` | jsonb | 节点亲和性策略 | - |
| `status` | string | `active` / `disabled` | Index, Default:`active` |
| `created_at` / `updated_at` / `deleted_at` | timestamp | 审计时间与软删除时间 | `deleted_at` Index |

操作员向未归档任务增加批次时，Server 会在同一事务中锁定 Task 与 Project，将规范化后的新目标稳定并集到 `seed_targets` 和授权 `scope`。重复目标只返回 `unchanged`，不会新建 TaskBatch；实际新增目标、Scope 变化和操作者写入 `task_audits`。

#### `project_members`

| 字段 | 类型 | 说明 | 约束 / 索引 |
|------|------|------|-------------|
| `project_id` | string | 项目 ID | PK(复合) |
| `user_id` | string | 用户 ID | PK(复合) |
| `role` | string | 项目内角色 | Default:`operator` |
| `created_at` | timestamp | 加入时间 | - |

#### `users`

| 字段 | 类型 | 说明 | 约束 / 索引 |
|------|------|------|-------------|
| `id` | uint | 用户主键 | PK |
| `tenant_id` | string | 所属租户 | Index |
| `username` | string | 登录名 | Unique Index |
| `password_hash` | string | bcrypt 哈希 | - |
| `role` | string | `admin` / `operator` / `viewer` | Default:`viewer` |
| `status` | string | `active` / `disabled` | Default:`active` |
| `created_at` / `updated_at` | timestamp | 审计时间 | - |

#### `system_configs`

| 字段 | 类型 | 说明 | 约束 / 索引 |
|------|------|------|-------------|
| `key` | string | 配置键 | PK |
| `value` | text | 配置值 | - |
| `updated_at` | timestamp | 最后更新时间 | - |

典型用途：

- `rule_version`
- `mcp_fofa`
- `mcp_hunter`
- `mcp_quake`
- `mcp_openai`

---

### 3.2 调度控制面

> `cron_tasks`（定时任务）与 `notification_rules`（通知规则）自 v001 起已随历史功能下线一并移除；定时触发能力由外部调度（cron/systemd timer）直接调用 API 承担。

#### `root_tasks`

| 字段 | 类型 | 说明 | 约束 / 索引 |
|------|------|------|-------------|
| `id` | string | 根任务 ID | PK |
| `tenant_id` | string | 租户隔离键 | Index |
| `project_id` | string | 所属项目 | Index |
| `user_id` | string | 发起用户 | Index |
| `name` | string | 任务名称 | - |
| `original_targets` | text | 原始输入目标列表 | Text |
| `status` | string | 根任务聚合状态 | Index |
| `total_chunks` | int | 当前拆分出的子任务总数 | - |
| `completed_chunks` | int | 已完成子任务数 | - |
| `total_targets` | int | 原始目标总数 | - |
| `completed_targets` | int | 已完成目标总数 | - |
| `config` | text | 实际下发的扫描配置 JSON | Text |
| `priority` | int | 优先级 | - |
| `timeout_sec` | int | 单批次超时秒数 | - |
| `rule_version` | string | 任务运行时规则版本 | - |
| `current_config_version` | int | 当前配置修订版本；新批次读取该版本 | Default:`1` |
| `created_at` / `updated_at` | timestamp | 创建与更新时间 | - |
| `archived_at` | timestamp | 归档时间；为空表示当前任务 | Index |

#### `task_batches`

`task_batches` 是任务下稳定、可管理的扫描单元。批次身份不会因执行失败或重试改变，实际执行记录由 `sub_tasks`（Attempt）追加保存。

| 字段 | 类型 | 说明 | 约束 / 索引 |
|------|------|------|-------------|
| `id` | string | 稳定批次 ID | PK |
| `tenant_id` / `project_id` | string | 租户与项目归属 | Index |
| `root_task_id` | string | 所属根任务 | Index，与 `sequence` 唯一 |
| `sequence` | int | 任务内稳定顺序号 | Unique(`root_task_id`, `sequence`) |
| `kind` / `target_type` | string | 批次场景与目标类型 | Index |
| `targets` / `target_count` | text / int | 规范化目标快照及数量 | Text |
| `status` | string | 最新 Attempt 的镜像状态 | Index |
| `control_state` | string | 与执行状态正交的批次控制意图：`active` / `paused` / `stopping` / `stopped` | Index, Default:`active` |
| `config_version` / `rule_version` | int / string | 创建批次时绑定的配置与规则版本 | - |
| `priority` / `timeout_sec` | int | 调度参数快照 | - |
| `agent_selector` / `agent_selector_rules` | text | Agent 选择条件快照 | Text(JSON) |
| `current_attempt_no` / `attempt_count` | int | 当前尝试序号与累计尝试数 | Default:`1` |
| `latest_attempt_id` | string | 最新实际执行记录 | Index |
| `created_by` | string | 创建操作者 | Index |
| `created_at` / `updated_at` / `archived_at` | timestamp | 生命周期时间 | `archived_at` Index |

#### `sub_tasks`（Attempt）

| 字段 | 类型 | 说明 | 约束 / 索引 |
|------|------|------|-------------|
| `id` | string | 实际执行 / Attempt ID | PK |
| `tenant_id` | string | 租户隔离键 | Index |
| `project_id` | string | 所属项目 | Index |
| `root_task_id` | string | 关联根任务 | Index |
| `batch_id` | string | 关联稳定批次 | Index |
| `attempt_no` | int | 批次内尝试序号 | Default:`1` |
| `parent_attempt_id` | string | 触发本次执行的上一 Attempt | Index |
| `trigger` | string | `initial` / 自动、超时、拆分、掉线、Spot 或手动重试来源 | Index |
| `chunk_targets` | text | 当前批次目标列表 JSON | Text |
| `status` | string | 子任务状态机 | Index |
| `agent_id` | string | 实际执行节点；终态后保留 | Index |
| `failure_reason` | text | Agent 或恢复链路记录的失败原因摘要 | Text |
| `config` | text | 当前批次配置 JSON | Text |
| `stream_msg_id` | string | 队列消息句柄 / MQ 消息标识 | - |
| `priority` | int | 调度优先级，默认 `1` | Index, Default:`1` |
| `agent_selector` | text | 节点标签选择器 JSON | Text |
| `timeout_sec` | int | 批次超时秒数 | - |
| `retry_count` | int | 当前重试次数 | - |
| `max_retry` | int | 最大重试次数 | Default:`3` |
| `config_version` | int | 此执行记录使用的不可变配置版本 | Default:`1` |
| `rule_version` | string | 此执行使用的规则版本 | - |
| `started_at` / `finished_at` | timestamp | 实际开始和终态时间；未发生时为空 | Index |
| `created_at` / `updated_at` | timestamp | 审计时间 | - |

设计要点：

- 任务创建后初始进入 `Dispatching` 或 `Pending`。
- 失败 / 超时时允许进入 `Recovered` 或进行二分拆分重试。
- 用户取消走 `CancelPending -> Cancelled` 两段式收敛。
- 普通删除只设置 `root_tasks.archived_at`，不会删除 `sub_tasks` 或扫描结果；活动任务必须先停止到终态再归档。
- `root_tasks.config/priority/timeout_sec` 继续镜像当前修订以兼容旧 Agent；已创建 `sub_tasks` 保留自己的 `config` 与 `config_version`，不会被后续任务配置修改覆盖。
- 迁移为每条旧 `sub_tasks` 记录回填一个同 ID 的稳定批次，并将旧记录关联为 Attempt 1；Agent 协议仍使用不透明的 Attempt ID，因此旧 Agent 无须同时升级。
- 重试、超时恢复、Agent 掉线和 Spot 回收不会把原 Attempt 改回待执行态；原记录保留 Agent、配置/规则版本、时间和失败原因，并在同一批次下追加新 Attempt。RootTask 进度只聚合每个 TaskBatch 的 `latest_attempt_id`。
- 增加批次先按目标类型规范化，再在 RootTask 行锁内与历史批次和 `original_targets` 去重；完成态任务有真实新目标时回到 `Running`，暂停任务新增的 Attempt 保持 `Paused`，不会绕过暂停直接派发。
- 携带 `Idempotency-Key` 的增加批次请求在相同 RootTask 行锁内查询或写入追加专用账本；同 Task/操作者/Key 的同一请求返回首次结果，异请求冲突。全重复请求可冻结 `unchanged`，但不创建 Batch/Attempt、范围变化或业务审计。
- 批次暂停只修改 `control_state`；未领取 Attempt 同时进入 `Paused`，已领取 Attempt 允许完成。暂停期间失败、超时、Agent 掉线或 Spot 回收只收敛当前 Attempt，不自动追加重试。恢复或显式重试通过新 Attempt 保留历史证据。
- 批次归档只设置 `task_batches.archived_at`。归档批次退出默认列表和 RootTask 进度聚合，但 Attempt、资产、指纹、漏洞和审计记录均保留。

#### `task_config_revisions`

| 字段 | 类型 | 说明 | 约束 / 索引 |
|------|------|------|-------------|
| `id` | bigint | 修订记录 ID | PK |
| `tenant_id` / `project_id` | string | 租户与项目归属 | Index |
| `root_task_id` | string | 根任务 ID | Index，与 `version` 唯一 |
| `version` | int | 从 1 递增的任务内版本号 | Unique(`root_task_id`, `version`) |
| `config` | text | 规范化扫描配置 JSON | Text |
| `config_hash` | string | 配置、优先级、超时和 Agent 选择条件的 SHA-256 | Index |
| `priority` / `timeout_sec` | int | 此版本调度参数 | - |
| `agent_selector` / `agent_selector_rules` | text | 用户指定的 Agent 选择条件，不含按目标类型自动合并的条件 | Text(JSON) |
| `created_by` | string | 创建修订的操作者 | Index |
| `change_note` | text | 可选变更说明 | Text |
| `created_at` | timestamp | 修订创建时间 | - |

新建任务在同一事务中写入 v1；配置更新锁定根任务、追加下一版本、更新兼容镜像并写入 `config_update` 审计。迁移为旧任务和旧子任务回填 v1，重复执行不会产生重复修订。

#### `task_audits`

| 字段 | 类型 | 说明 | 约束 / 索引 |
|------|------|------|-------------|
| `id` | bigint | 审计记录 ID | PK |
| `tenant_id` | string | 租户隔离键 | Index |
| `project_id` | string | 所属项目 | Index |
| `root_task_id` | string | 根任务 ID | Index |
| `batch_id` / `attempt_id` | string | 后续批次与尝试审计关联位 | Index |
| `operator_id` | string | 操作者用户 ID | Index |
| `action` | string | `pause` / `resume` / `stop` / `retry` / `archive` 等任务级动作及 `batch_*` 批次动作 | Index |
| `before_status` / `after_status` | string | 操作前后任务状态 | - |
| `details` | jsonb | 不含目标正文和扫描配置的动作摘要 | Default:`{}` |
| `created_at` | timestamp | 操作时间 | Index |

任务状态变更与对应 `task_audits` 记录在同一数据库事务内提交。归档状态与运行状态分离，默认任务列表、Dashboard 任务数和项目任务数不统计已归档任务，但任务详情和历史结果仍可按 ID 访问。

#### `asset_discovery_audits`

| 字段 | 类型 | 说明 | 约束 / 索引 |
|------|------|------|-------------|
| `id` | bigint | 测绘查询审计 ID | PK |
| `tenant_id` / `project_id` | string | 租户与项目隔离键 | Index |
| `provider` / `action` | string | Provider 与 `query_preview` / `export_snapshot` / `notebook_archive` / `notebook_update` / `notebook_remove` / `notebook_restore` 动作 | Index |
| `notebook_item_id` | bigint nullable | Notebook 操作关联的项目级条目；普通查询/导出为空 | Index, tenant/project 复合 FK, RESTRICT |
| `operator_id` | string | 发起查询的用户 ID | Index |
| `query_hash` | string | 规范化查询表达式 SHA-256；不保存原文 | Index |
| `config_version` / `config_hash` | int / string | 租户 API 配置版本与语义 SHA-256 | - |
| `requested_limit` | int | 请求结果上限 | - |
| `provider_total` / `returned_count` / `skipped_rows` | int | Provider 总量与规范化计数 | - |
| `truncated` | bool | 是否因预算截断 | - |
| `status` / `error_code` | string | `success` / `failed` 与稳定脱敏错误码 | Index |
| `duration_ms` / `created_at` | bigint / timestamp | 耗时与审计时间 | `created_at` Index |

该表不包含原始查询、email、API key、请求 URL、Provider 响应正文或资产结果。项目访问校验失败时不调用 Provider，也不创建可能泄露项目存在性的审计；通过访问校验后的查询必须先完成审计写入才会向调用者返回结果。

#### `asset_discovery_snapshots` / `asset_discovery_snapshot_items`

| 表 | 角色 | 关键字段 / 约束 |
|------|------|-----------------|
| `asset_discovery_snapshots` | 一次成功 Provider 查询的不可变项目快照 | `schema_version`、tenant/project/audit、Provider、原始表达式与查询哈希、配置版本/哈希、请求及结果计数；一个审计最多关联一个快照 |
| `asset_discovery_snapshot_items` | 快照内按返回顺序保存的规范资产候选 | tenant/project/snapshot、规范目标与 SHA-256、IP/域名/端口/协议及最小展示元数据；`(snapshot_id, target_hash)` 唯一 |

原始表达式属于受 tenant/project 对象权限保护的项目业务数据，用于项目查询历史；它不会复制到通用审计或日志。两张表不包含 Provider 凭据或原始响应字段，也不写入当前 `assets` 视图。快照通过 `(tenant_id, project_id, audit_id)` 复合外键绑定审计，资产项通过 `(tenant_id, project_id, snapshot_id)` 复合外键绑定快照，避免跨租户或跨项目挂接。FOFA/Hunter/Quake 成功路径在一个数据库事务内创建成功审计、快照和全部资产项；任一写入失败均回滚完整成功记录并隐藏结果。历史列表、单次资产读取和 CSV 导出都强制使用 tenant/project/snapshot 过滤并受数量、时间与响应大小约束，公开 DTO 和导出文件不包含查询、配置或目标哈希；成功导出另写 `action=export_snapshot` 的脱敏审计，审计失败不返回文件。

#### `asset_discovery_notebook_items` / `asset_discovery_notebook_sources`

| 表 | 角色 | 关键字段 / 约束 |
|------|------|-----------------|
| `asset_discovery_notebook_items` | 项目级规范候选目标与运营状态 | tenant/project、规范目标、目标 SHA-256、创建/更新人、备注、软移除时间/操作者；`(tenant_id, project_id, target_hash)` 唯一，每项目由应用层限制 10000 条 |
| `asset_discovery_notebook_sources` | 笔记本目标的不可变快照来源 | tenant/project、notebook item、snapshot/item、归档审计与操作者；`(tenant_id, project_id, snapshot_id, snapshot_item_id)` 唯一 |
| `asset_discovery_notebook_tags` | 项目内规范标签 | tenant/project/name 唯一；名称 1–64 字节，复合 FK 绑定项目 |
| `asset_discovery_notebook_item_tags` | 条目与标签的项目内关联 | tenant/project/item/tag 唯一；两个复合 FK 均 `ON DELETE RESTRICT` |

来源表以 tenant/project 复合外键分别绑定笔记本目标、快照资产项和脱敏审计，避免跨项目挂接。Migration 480 为条目补充标签、备注和软移除状态，并把项目、标签、关联和 Notebook 操作审计全部纳入复合 FK；启动时 schema verify 同时检查新增列与索引。归档或运营写入都在锁定项目/条目后写脱敏审计，失败会回滚。操作审计保存 item ID、目标哈希和不含标签/备注正文的变更摘要哈希。笔记本不复制原始表达式、Provider 凭据或响应，不写入 `assets`；只有另行确认的分发事务可扩展 Scope/SeedTargets 或创建 TaskBatch。

#### `asset_discovery_notebook_distribution_intents` / `asset_discovery_notebook_distribution_intent_items` / `asset_discovery_notebook_distribution_materializations`

| 表 | 角色 | 关键字段 / 约束 |
|------|------|-----------------|
| `asset_discovery_notebook_distribution_intents` | 内部、不可变的笔记本分发请求快照 | tenant/project/task/operator/operation、Idempotency-Key SHA-256、请求/预览/配置哈希、预览与配置/规则版本、任务状态、计数和 `recorded` 状态；`(tenant_id, project_id, operator_id, operation, idempotency_key_hash)` 唯一 |
| `asset_discovery_notebook_distribution_intent_items` | 一次意图中的有序选中项快照 | tenant/project/intent/notebook item、0 起始位置、规范目标、目标 SHA-256 与 `new`/`duplicate` 判定；同一 intent 内位置、条目和目标哈希分别唯一 |
| `asset_discovery_notebook_distribution_materializations` | 一次已确认意图的不可变 typed 结果 | tenant/project/intent/task、`materialized`/`unchanged`、提交后的任务状态以及有界 Batch/Attempt ID 数组；每个 intent 唯一 |

意图通过 tenant/project 复合外键绑定 RootTask 与对应 TaskConfigRevision；逐项快照同样绑定 Intent 和 NotebookItem，materialization 绑定 Intent 与 RootTask，全部使用 `ON DELETE RESTRICT`。确认接口把 intent/items、materialization、Project Scope/SeedTargets、RootTask、TaskBatch/Attempt 和 `notebook_distribution_materialize` TaskAudit 放入同一事务；提交后才派发。相同幂等键与相同确认返回该不可变结果，不同确认冲突，原始幂等键不落库。三张表都没有 Provider 凭据、原始查询或响应字段；intent 单独存在不构成扫描授权。

#### `nodes`

| 字段 | 类型 | 说明 | 约束 / 索引 |
|------|------|------|-------------|
| `agent_id` | string | Agent 唯一标识 | PK |
| `tenant_id` | string | 所属租户 | Index, Default:`default` |
| `ip` | string | 节点出口 IP | - |
| `status` | string | 当前节点状态 | - |
| `token` | string | 注册时签发的会话令牌 | - |
| `tags` | text | 节点标签 JSON | - |
| `version` | string | Agent 版本 | - |
| `capacity` | int | 并发容量 | Default:`1` |
| `running_tasks` | int | 正在运行的任务数 | Default:`0` |
| `running_task_ids` | text | 正在运行的子任务 ID 数组 JSON | Text |
| `rule_version` | string | Agent 当前规则版本 | - |
| `os` / `arch` | string | 操作系统 / 架构 | - |
| `cpu_usage` / `mem_usage` | float | 资源占用率 | - |
| `last_beat` | int64 | 最近心跳时间戳（ms） | - |
| `created_at` | timestamp | 注册时间 | - |

#### `agent_logs`

| 字段 | 类型 | 说明 | 约束 / 索引 |
|------|------|------|-------------|
| `id` | uint | 日志主键 | PK |
| `agent_id` | string | 来源节点 | Index |
| `level` | string | `INFO` / `WARN` / `ERROR` | - |
| `message` | text | 日志正文 | Text |
| `timestamp` | int64 | Agent 侧原始时间戳 | Index |
| `created_at` | timestamp | 服务端入库时间 | - |

---

#### 幂等账本（五张同构表）

| 表（Migration） | `operation` | 额外唯一维度 | 绑定的业务对象 | 额外保存的业务结果 |
|---|---|---|---|---|
| `task_creation_idempotencies`（430） | `create_task_v1` | - | RootTask、配置修订、首个 TaskBatch/Attempt | 首次 Project Scope/SeedTargets 增量 |
| `task_append_idempotencies`（440） | `append_targets_v1` | `root_task_id` | 新增 TaskBatch/Attempt、Scope/SeedTargets、RootTask 聚合 | 首次 outcome、目标/范围增量、提交后任务总计数；全重复 `unchanged` 只写账本 |
| `task_retry_idempotencies`（450） | `retry_task_v1` | `root_task_id` | 新增 Attempt、RootTask 状态 | 重试前后状态、首次跳过的完成/暂停批次数；Attempt 列表必须非空 |
| `task_batch_retry_idempotencies`（460） | `retry_task_batch_v1` | `root_task_id` + `batch_id` | 稳定 TaskBatch 下的新 Attempt 与 Task/Batch 状态 | 前后状态、新 Attempt 编号/配置版本/规则版本 |
| `risk_validation_execution_idempotencies`（470） | `execute_risk_validation_v1` | `root_task_id` | 配置修订、risk-validation Batch 与 Attempt（deferred/RESTRICT 复合外键） | preview plan、POC/端点集合哈希、候选/请求计数、二次确认要求、前后状态 |

五张账本均为内部不可变表，唯一键统一为 `(tenant_id, project_id[, root_task_id[, batch_id]], operator_id, operation, idempotency_key_hash)`，只保存原始 Key 和规范请求的 SHA-256，不落原始 Key、目标、配置或规则正文。账本与业务写入和单条审计在同一事务提交，失败整体回滚；只有首次提交后派发，重放返回首次冻结结果且不会再次入队。账本不是授权凭证：认证、operator RBAC、项目/任务/批次对象授权与归档校验始终先于重放；风险验证的新 Key 仍须重新验证 preview、配置、规则和 POC 内容哈希。

#### `subdomain_passive_cache` / `subdomain_passive_jobs`

Migration 002（v001 基线后的增量）支撑 Server 端被动子域收集。`subdomain_passive_cache` 按 `domain` 主键缓存已验证的被动收集结果（`subdomains`/`sources` 为 jsonb 数组，`expires_at` 判定新鲜度）；CT/被动 DNS 为公共历史数据，缓存全局共享、不含租户语义。`subdomain_passive_jobs` 记录派发前持有：开启被动子域发现且存在 `passive_server=v1` 能力 Agent 时，域名批次 Attempt 初始停留 `Queued` 并写入 `pending` 任务行；后台 collector 逐域收集（先查缓存）、把结果密封进 Attempt 配置（`SubdomainPassiveResults`，全覆盖时同时置 `NoSubFinder=true`）后释放入队。收集超时（默认 8 分钟）或全部数据源失败时不密封直接释放，Agent 回退原有端内被动收集；任务行兼作重启恢复凭证（`running` 超时自动回退 `pending`），每次终态迁移写入 `task_audits`（`passive_subdomain_<state>`）。`ARGUS_SERVER_PASSIVE_SUBDOMAIN=off` 可整体关闭该特性。

### 3.3 资产、结果与报表

#### 扫描记忆与覆盖存储

这组表使用 `argus.scanplan/v1` 契约，但不会替代现有资产结果表。G17 已接入新 Agent 阶段事件的幂等归并；G18 已在 Agent 领取前读取有效覆盖并按完整目标复用；G19 已接入执行中 WorkClaim 唯一占用和等待关联。旧 Agent 未上报阶段事件时不会生成覆盖，因此仍按未知并继续扫描。

| 表 | 角色 | 关键字段 / 约束 |
|------|------|-----------------|
| `scan_observations` | 追加式阶段证据；成功、阴性、失败、跳过均保留，后续事件不覆盖旧记录 | `tenant_id/project_id/network_zone`、完整 WorkKey 维度、来源 Task/Batch/Attempt/Agent、结果与证据哈希；可选 `checkpoint/checkpoint_hash` 只保存单目标阶段的有界派生资产；`(tenant_id, source_event_id)` 在事件 ID 非空时唯一 |
| `scan_coverages` | 每个规范 WorkKey 的当前覆盖状态，指向不可变来源观测 | `(tenant_id, project_id, work_key_hash)` 唯一；保存 `complete/incomplete/invalidated`、有效期、修订号与失效原因 |
| `scan_work_claims` | 相同工作并发合并所需的唯一租约槽 | `(tenant_id, project_id, work_key_hash)` 唯一；保存 owner Task/Batch/Attempt/Agent、租约哈希、到期时间和错误摘要 |
| `task_coverage_links` | 解释目标任务的工作是实际执行、历史复用还是挂接执行中来源 | 目标 Task/Batch/Attempt + WorkKey + link type 唯一；保存 Coverage/Claim 及来源 Task/Batch/Attempt |

四张表均显式保存 `tenant_id` 与 `project_id`，任何读取或写入仍须由应用层验证当前用户对项目和任务的对象级权限；WorkKey 哈希不能替代租户条件，网络区域、Scope/Config、规则版本与风险验证内容哈希均作为独立列保留。

归并规则：Observation 只追加，同一租户内重复事件按目标派生幂等键；Coverage 只接受不早于当前来源的事件并递增修订号——配置/规则快照一致的成功或阴性形成 `complete`，失败或跳过形成 `incomplete`，版本漂移或缺少风险验证内容维度形成 `invalidated`。Server 为新完成 Coverage 设置有效期：存活证据 5 分钟、端口 1 小时、搜索/子域/CDN/协议/Web/Host 绑定/目录/指纹 6 小时、显式风险验证 24 小时；失效或不完整 Coverage 的 `valid_until` 为空且不可复用。Scope、配置、规则和网络区域是 WorkKey 维度，变化后不会命中旧行；上游内容变化会把较旧的依赖 Coverage 置为 `invalidated`（原因 `upstream_content_changed:<stage>`）。

检查点使用 `argus.checkpoint/v1`，只接收单目标成功/阴性事件的最多 4096 个存活 IP、开放端点、协议服务、URL 或域名，不保存响应正文、Header、凭据或任意错误文本；Coverage 通过 `source_observation_id` 引用检查点，不复制 payload。网络区域由 Server 按目标和 Node 标签派生（公网 `public`、私网 `private:<network_zone>`、无标签私网回退 `agent:<agent_id>`），归并、复用与 WorkClaim 共用同一派生器。`scan_work_claims.status` 约束为运行期 `active` 与终态 `completed/failed`，相同唯一键的后续真实执行复用同一行并递增 `revision`；`task_coverage_links` 使用 `executed/active` 表示 Claim 所有者、`in_flight/waiting` 表示挂接者，来源结束后转为 `resolved` 或 `source_failed`。等待 Attempt 不写 Agent，以 `workclaim:<digest>` 作内部标记，所有依赖结束后才以 CAS 转为 `Dispatching`；显式手动重试与 `risk_validation` 绕过 WorkClaim 和历史覆盖。

#### `scan_timing_events`

G31 新增的 additive、append-only 表，保存 `argus.timing/v1` 的已校验计时证据，不改变 `scan_coverages`、任务状态或扫描结果。字段为 schema、tenant/project/root task/batch/attempt/agent、源 event ID、kind、stage、outcome、UTC 起止时间、非负 `duration_ns`、配置版本、规则版本和创建时间；不保存 target、配置正文、message、HTTP 流量、凭据、POC 细节或原始日志。`duration_ns` 是生产者单调时钟的权威区间，允许为 0；它与 UTC 时间用于展示和排序，但事件总和不表示进程 wall time。

写入前 Server 以活动 Attempt 的分配 Agent、会话和 tenant/project/task 归属重建边界，不接受 Agent 自行声明 tenant 或 project。`(tenant_id, source_event_id)` 唯一：同 ID 且所有受保存字段相同的重放返回已有记录，不同内容视为冲突；历史事件不更新或删除。索引 `idx_scan_timing_events_scope_created` 供已授权任务详情按 tenant/project/task 读取，`idx_scan_timing_events_attempt_created` 供 Attempt 历史排序。租户、项目、任务、批次、Attempt 与 Agent 归属通过不可变 Attempt 复合外键并使用 `ON DELETE RESTRICT`；计时表不外键到可清理的 `nodes` 行，因此不会阻断既有离线 Agent 清理。

任务详情只在已完成 tenant + project + task 对象授权后构建有界 projection：按 Attempt 返回 `available` 和 `kind/stage/outcome/duration/start/finish`，最多 5000 条，超出时置 `truncated`。旧 Agent 没有事件时保持 unavailable，不以 0 代替；投影不返回 Agent 会话、target、WorkKey、事件 ID、配置/规则哈希或原始日志。

#### `domains`

| 字段 | 类型 | 说明 | 约束 / 索引 |
|------|------|------|-------------|
| `id` | uint | 域名主键 | PK |
| `tenant_id` | string | 租户隔离键 | Unique Index `idx_domain_dedupe` |
| `project_id` | string | 所属项目 | Unique Index `idx_domain_dedupe` |
| `name` | string | 域名 | Unique Index `idx_domain_dedupe` |
| `task_id` | string | 最近更新此域名的任务 | Index |
| `tags` | jsonb | 域名标签 | - |
| `records` | jsonb | DNS 解析记录 | - |
| `icp` | string | 备案信息摘要 | - |
| `whois` | jsonb | Whois 数据 | - |
| `status` | string | `alive` / `dead` 等 | Index, Default:`alive` |
| `created_at` / `updated_at` | timestamp | 审计时间 | - |

联合唯一约束：`(tenant_id, project_id, name)`。

#### `assets`

| 字段 | 类型 | 说明 | 约束 / 索引 |
|------|------|------|-------------|
| `id` | uint | 资产主键 | PK |
| `tenant_id` | string | 租户隔离键 | Index |
| `project_id` | string | 所属项目 | Unique Index `idx_asset_dedupe` |
| `task_id` | string | 最近更新此资产的子任务 | Index |
| `target` | string | 归一化目标 | Unique Index `idx_asset_dedupe` |
| `protocol` | string | 结果类型 / 协议维度 | Unique Index `idx_asset_dedupe` |
| `port` | int | 端口号 | - |
| `url` | text | 原始 URL / 原始 payload 语义字段 | Text |
| `title` | string | Web 标题 | - |
| `service` | string | 服务名称 / 状态摘要 | - |
| `cert_subject` | string | TLS 证书主体 | - |
| `cert_expiry` | timestamp | TLS 证书过期时间 | - |
| `cdn` | boolean | 是否疑似 CDN 资产（Migration 003，`tag=cdn` 探测与 CDN-Domain 记录置 true） | Not Null, Default:`false` |
| `tags` | jsonb | 资产标签 | - |
| `status` | string | `alive` / `inactive` 等 | Index, Default:`alive` |
| `owner_id` | string | 责任人 | Index |
| `cred_id` | string | 关联凭证 | Index |
| `created_at` / `updated_at` | timestamp | 审计时间 | - |

联合唯一约束：`(project_id, target, protocol)`。

#### `credentials`

| 字段 | 类型 | 说明 | 约束 / 索引 |
|------|------|------|-------------|
| `id` | string | 凭证主键 | PK |
| `project_id` | string | 所属项目 | Index |
| `name` | string | 凭证名称 | - |
| `type` | string | 凭证类型 | Index |
| `content` | text | 加密后的凭证正文 | Text |
| `created_at` / `updated_at` / `deleted_at` | timestamp | 审计时间与软删除时间 | `deleted_at` Index |

#### `fingerprint_hits`

| 字段 | 类型 | 说明 | 约束 / 索引 |
|------|------|------|-------------|
| `id` | uint | 指纹命中主键 | PK |
| `tenant_id` | string | 租户隔离键 | Index |
| `project_id` | string | 所属项目 | Unique Index `idx_fp_dedupe` |
| `task_id` | string | 最近更新此指纹的子任务 | Index |
| `target` | string | 归一化目标 | Unique Index `idx_fp_dedupe` |
| `product_name` | string | 识别出的产品名 | Unique Index `idx_fp_dedupe` |
| `rule_name` | string | 命中规则名 | - |
| `evidence` | text | 原始证据 / 命中片段 | Text |
| `created_at` / `updated_at` | timestamp | 审计时间 | - |

联合唯一约束：`(project_id, target, product_name)`。

#### `vulnerabilities`

| 字段 | 类型 | 说明 | 约束 / 索引 |
|------|------|------|-------------|
| `id` | uint | 漏洞主键 | PK |
| `tenant_id` | string | 租户隔离键 | Index |
| `project_id` | string | 所属项目 | Unique Index `idx_vuln_new_dedupe` |
| `task_id` | string | 最近发现 / 更新此漏洞的子任务 | Index |
| `target` | string | 归一化目标 | Unique Index `idx_vuln_new_dedupe` |
| `plugin` | string | 漏洞插件 / 模板 / POC 名称 | Unique Index `idx_vuln_new_dedupe` |
| `severity` | string | 严重度 | - |
| `status` | string | 修复跟踪状态 | Index, Default:`open` |
| `assignee` | string | 负责人 | Index |
| `ignore_reason` | text | 忽略原因 | Text |
| `verify_task_id` | string | 复测任务 ID | Index |
| `payload` | text | 原始结果 JSON | Text |
| `request` | text | 请求报文 | Text |
| `response` | text | 响应报文 | Text |
| `description` | text | 漏洞描述 | Text |
| `reference` | text | 参考链接 JSON 数组 | Text |
| `matched_at` | text | 匹配位置 / URL | Text |
| `created_at` / `updated_at` | timestamp | 审计时间 | - |

联合唯一约束：`(project_id, target, plugin)`。

#### `reports`

| 字段 | 类型 | 说明 | 约束 / 索引 |
|------|------|------|-------------|
| `id` | string | 报表主键 | PK |
| `project_id` | string | 所属项目 | Index |
| `name` | string | 报表名称 | - |
| `type` | string | 报表类型 | Index |
| `format` | string | 输出格式，如 `csv` / `html` | - |
| `file_url` | text | 文件地址或对象存储 URL | Text |
| `status` | string | `pending` / `ready` / `failed` | Default:`pending` |
| `created_by` | string | 生成人 | Index |
| `created_at` | timestamp | 创建时间 | - |

说明：报表二进制文件不直接存 PostgreSQL，本表只保存元数据与地址。

---

### 3.4 规则中心与治理层

#### `arsenals`

| 字段 | 类型 | 说明 | 约束 / 索引 |
|------|------|------|-------------|
| `id` | string | 规则文件唯一 ID | PK |
| `tenant_id` | string | 租户隔离键 | Index, Default:`default` |
| `type` | string | 规则类型，规范值为 `poc` / `finger` / `workflow` / `dir` / `apiconfig` | Index |
| `file_name` | string | 相对路径或文件名 | Index |
| `content` | text | 原始规则正文 | Text |
| `hash` | string | 当前正文哈希 | - |
| `previous_hash` | string | 上一版本哈希 | - |
| `previous_content` | text | 上一版本正文，用于回滚 | Text |
| `version` | int | 自增版本号 | Default:`1` |
| `state` | string | 审批态 | Index, Default:`Draft` |
| `created_at` / `updated_at` | timestamp | 审计时间 | - |

说明：

- `arsenals` 是 Agent 同步的原始真相源。
- 启动时会规范化历史类型别名：`fingerprint -> finger`，`dirprobe -> dir`。

#### `rule_catalog_bootstraps`

| 字段 | 类型 | 说明 | 约束 / 索引 |
|------|------|------|-------------|
| `key` | string | 启动状态主键 | PK |
| `schema_version` | int | 当前物化 schema 版本 | - |
| `source` | string | 物化来源，当前为 `arsenals` | - |
| `status` | string | `ready` / `partial` / `empty` | Index |
| `aggregate_hash` | string | 全量规则聚合哈希 | Index |
| `arsenal_count` | int | 源规则文件数量 | - |
| `fingerprint_count` | int | 指纹条目数量 | - |
| `workflow_count` | int | workflow 条目数量 | - |
| `dir_probe_count` | int | 主动探测目录条目数量 | - |
| `poc_count` | int | POC 条目数量 | - |
| `last_error` | text | 最近物化错误摘要 | Text |
| `last_seeded_at` | timestamp | 最近一次成功回填时间 | - |
| `created_at` / `updated_at` | timestamp | 审计时间 | - |

#### `fingerprint_rules`

| 字段 | 类型 | 说明 | 约束 / 索引 |
|------|------|------|-------------|
| `id` | uint | 主键 | PK |
| `tenant_id` | string | 租户隔离键 | Unique Index `idx_fp_rule_unique` |
| `artifact_id` | string | 来源 `arsenals.id` | Index |
| `source_file` | string | 来源文件 | Index |
| `product_name` | string | 产品名 | Index, Unique Index `idx_fp_rule_unique` |
| `rule_expr` | text | 指纹表达式 | Unique Index `idx_fp_rule_unique` |
| `category` | string | 分类，默认 `web` | Index |
| `content_hash` | string | 内容哈希 | Index |
| `version` | int | 版本号 | Default:`1` |
| `state` | string | 规则状态 | Index |
| `enabled` | bool | 是否启用 | Index, Default:`true` |
| `created_at` / `updated_at` | timestamp | 审计时间 | - |

联合唯一约束：`(tenant_id, product_name, rule_expr)`。

#### `poc_rules`

| 字段 | 类型 | 说明 | 约束 / 索引 |
|------|------|------|-------------|
| `id` | uint | 主键 | PK |
| `tenant_id` | string | 租户隔离键 | Index |
| `artifact_id` | string | 来源 `arsenals.id` | Index |
| `source_file` | string | 来源文件 | Unique Index `idx_poc_rule_unique` |
| `name` | string | 模板名 | Index |
| `content_hash` | string | 内容哈希 | Index |
| `severity` | string | 严重度 | Index, Default:`info` |
| `execution_class` | string | POC 执行类别：`detection` / `verification`；`exploit` / `exp` 必须使用独立 EXP 包 | Index, Default:`detection` |
| `risk_level` | string | 执行风险：`unknown` / `low` / `medium` / `high`；旧规则回填为 `unknown` | Index, Default:`unknown` |
| `tags` | text | 标签串 | Text |
| `author` | string | 作者 | - |
| `description` | text | 描述 | Text |
| `version` | int | 版本号 | Default:`1` |
| `state` | string | 规则状态 | Index |
| `enabled` | bool | 是否启用 | Index, Default:`true` |
| `created_at` / `updated_at` | timestamp | 审计时间 | - |

联合唯一约束：`(tenant_id, source_file)`。

`severity` 表示漏洞严重度，不能替代执行风险。所有 POC 仅能在显式风险验证流程确认后执行；`high` 和 `unknown` 需要二次确认。`arsenals` 中的 Nuclei YAML 仍是权威来源，治理字段来自 `info.metadata.argus-execution-class` 与 `info.metadata.argus-risk-level`，`poc_rules` 和 Agent `arsenal.db` 仅作为派生检索与分发层。

#### `arsenal_ai_reviews`

| 字段 | 类型 | 说明 | 约束 / 索引 |
|------|------|------|-------------|
| `id` | uint | 主键 | PK |
| `tenant_id` | string | 租户隔离键 | Index |
| `type` | string | 规则类型，当前支持 `poc` | Index |
| `file_name` | string | 分析时的文件名 | Index |
| `content_hash` | string | 被分析内容哈希 | Index, Cache Index |
| `suggestion` | string | AI 建议：Approve / Revise / Reject | Index |
| `confidence` | float | 置信度 | - |
| `summary` / `reason` | text | 摘要与原因 | Text |
| `issues` | jsonb | 静态检查与模型问题列表 | JSONB |
| `duplicate_candidates` | jsonb | 重复候选列表 | JSONB |
| `raw_response` | jsonb | LLM 原始 JSON 响应 | JSONB |
| `provider` / `model` | string | 模型来源与名称 | - |
| `created_by` | string | 触发分析的用户 | Index |
| `created_at` | timestamp | 审计时间 | - |

缓存索引：`(tenant_id, type, content_hash, created_at DESC)`。

#### `workflow_rules`

| 字段 | 类型 | 说明 | 约束 / 索引 |
|------|------|------|-------------|
| `id` | uint | 主键 | PK |
| `tenant_id` | string | 租户隔离键 | Unique Index `idx_workflow_rule_unique` |
| `artifact_id` | string | 来源 `arsenals.id` | Index |
| `source_file` | string | 来源文件 | Index |
| `product_name` | string | 产品名 | Index, Unique Index `idx_workflow_rule_unique` |
| `poc_name` | string | 关联 POC 名称 | Index, Unique Index `idx_workflow_rule_unique` |
| `match_type` | string | 匹配方式 | Index, Unique Index `idx_workflow_rule_unique` |
| `content_hash` | string | 内容哈希 | Index |
| `version` | int | 版本号 | Default:`1` |
| `state` | string | 规则状态 | Index |
| `enabled` | bool | 是否启用 | Index, Default:`true` |
| `created_at` / `updated_at` | timestamp | 审计时间 | - |

联合唯一约束：`(tenant_id, product_name, poc_name, match_type)`。

#### `dir_rules`

| 字段 | 类型 | 说明 | 约束 / 索引 |
|------|------|------|-------------|
| `id` | uint | 主键 | PK |
| `tenant_id` | string | 租户隔离键 | Unique Index `idx_dir_rule_unique` |
| `artifact_id` | string | 来源 `arsenals.id` | Index |
| `source_file` | string | 来源文件 | Index |
| `path` | string | 探测路径 | Index, Unique Index `idx_dir_rule_unique` |
| `product_name` | string | 关联产品 | Index, Unique Index `idx_dir_rule_unique` |
| `content_hash` | string | 内容哈希 | Index |
| `version` | int | 版本号 | Default:`1` |
| `state` | string | 规则状态 | Index |
| `enabled` | bool | 是否启用 | Index, Default:`true` |
| `created_at` / `updated_at` | timestamp | 审计时间 | - |

联合唯一约束：`(tenant_id, path, product_name)`。

---

## 4. 关键索引与入库策略

### 4.1 结果去重键

| 表 | 联合唯一键 | 作用 |
|----|------------|------|
| `domains` | `(tenant_id, project_id, name)` | 防止同项目域名重复 |
| `assets` | `(project_id, target, protocol)` | 资产画像按目标与协议幂等 |
| `fingerprint_hits` | `(project_id, target, product_name)` | 同目标同产品指纹去重 |
| `vulnerabilities` | `(project_id, target, plugin)` | 同目标同插件漏洞去重 |

### 4.2 `target` 归一化规则

| 输入 | 归一化结果 |
|------|------------|
| `192.168.1.1` | `192.168.1.1` |
| `192.168.1.1:80` | `192.168.1.1:80` |
| `https://example.com` | `https://example.com:443` |
| `http://example.com/admin` | `http://example.com:80` |
| `example.com` | `example.com` |

### 4.3 BatchWriter Upsert 策略

| 表 | 冲突键 | 冲突后更新字段 |
|----|--------|----------------|
| `assets` | `(project_id, target, protocol)` | `task_id`、`port`、`url`、`title`、`service`、`cert_subject`、`cert_expiry`、`status`、`updated_at` |
| `fingerprint_hits` | `(project_id, target, product_name)` | `task_id`、`rule_name`、`evidence`、`updated_at` |
| `vulnerabilities` | `(project_id, target, plugin)` | `task_id`、`severity`、`payload`、`request`、`response`、`description`、`reference`、`matched_at`、`status`、`updated_at` |

---

## 5. 云资源编排

> 云资源编排表已落地，对应 GORM 模型在 `server/internal/db/cloud_models.go`；建表 DDL 已并入 `deploy/db/init/001_init.sql`。

#### `cloud_accounts`

| 字段 | 类型 | 说明 | 约束 / 索引 |
|------|------|------|-------------|
| `id` | string | 凭证主键 | PK |
| `tenant_id` | string | 租户隔离键 | Index, Default:`default` |
| `owner_user_id` | string | 凭证所有者用户 ID | Index |
| `name` | string | 凭证名称 | - |
| `provider` | string | 云厂商标识 (aliyun/aws/tencent) | Index |
| `access_key_id` | string | AES-256-GCM 加密的 AccessKey ID | - |
| `access_key_secret` | string | AES-256-GCM 加密的 AccessKey Secret | - |
| `region` | string | 默认区域 | - |
| `default_image_id` | string | 默认镜像 ID | - |
| `default_instance_type` | string | 默认实例规格 | - |
| `default_security_group` | string | 默认安全组 ID | - |
| `default_v_switch` | string | 默认虚拟交换机 ID | - |
| `status` | string | 凭证状态 (active/disabled) | Index, Default:`active` |
| `oss_bucket` | string | OSS Bucket 名称（Agent 分发） | - |
| `oss_endpoint` | string | OSS Endpoint | - |
| `created_at` / `updated_at` | timestamp | 时间戳 | - |

#### `cloud_account_bindings`

| 字段 | 类型 | 说明 | 约束 / 索引 |
|------|------|------|-------------|
| `id` | uint | 绑定记录主键 | PK |
| `tenant_id` | string | 租户隔离键 | Unique Index `idx_cloud_account_binding_unique` |
| `cloud_account_id` | string | 关联 CloudAccount | Unique Index `idx_cloud_account_binding_unique` |
| `user_id` | string | 可使用该 AK/SK 的用户 ID | Unique Index `idx_cloud_account_binding_unique` |
| `access_type` | string | `owner` / `bound` | Default:`bound` |
| `created_at` / `updated_at` | timestamp | 时间戳 | - |

#### `cloud_scaling_policies`

| 字段 | 类型 | 说明 | 约束 / 索引 |
|------|------|------|-------------|
| `id` | string | 策略主键 | PK |
| `tenant_id` | string | 租户隔离键 | Index, Default:`default` |
| `cloud_account_id` | string | 关联 CloudAccount | Index |
| `name` | string | 策略名称 | - |
| `enabled` | boolean | 是否启用 | Index, Default:`false` |
| `min_instances` | integer | 最小实例数 | Default:`0` |
| `max_instances` | integer | 最大实例数（硬上限） | Default:`5` |
| `scale_up_threshold` | integer | 扩容队列阈值 | Default:`50` |
| `scale_down_threshold` | integer | 缩容空闲阈值 | Default:`3` |
| `cooldown_seconds` | integer | 冷却时间（秒） | Default:`300` |
| `instance_ttl_minutes` | integer | 实例最大存活时间（分钟） | Default:`120` |
| `spot_strategy` | string | 竞价策略 | Default:`NoSpot` |
| `max_spot_price` | float64 | 竞价最高价 | - |
| `user_data_template` | text | Cloud-Init 模板 | - |
| `last_scale_action` | timestamp | 最近伸缩操作时间 | Nullable |
| `created_at` / `updated_at` | timestamp | 时间戳 | - |

#### `cloud_instances`

| 字段 | 类型 | 说明 | 约束 / 索引 |
|------|------|------|-------------|
| `id` | string | 实例主键 | PK |
| `tenant_id` | string | 租户隔离键 | Index, Default:`default` |
| `cloud_account_id` | string | 关联 CloudAccount | Index |
| `policy_id` | string | 关联 CloudScalingPolicy | Index |
| `provider_instance_id` | string | 云厂商侧实例 ID | Index |
| `agent_id` | string | 对应的 Argus Agent ID | Index |
| `ip` | string | 实例 IP | - |
| `region` | string | 实例区域 | - |
| `status` | string | 实例状态 | Index, Default:`Provisioning` |
| `spot` | boolean | 是否竞价实例 | Default:`false` |
| `error_message` | text | 错误信息 | - |
| `reboot_count` | integer | 重启计数（梯度容错：<2 重启，>=2 销毁） | Default:`0` |
| `launched_at` / `ready_at` / `terminated_at` | timestamp | 生命周期时间戳 | Nullable |
| `created_at` / `updated_at` | timestamp | 记录时间戳 | - |
| `deleted_at` | timestamp | 软删除 | Index, Nullable |

> `cloud_instances.status` 状态机：`Provisioning` → `WaitingReady` → `Running` → `Rebooting` / `Terminating` → `WaitingReady` / `Terminated`，异常时为 `Error`。其中 `WaitingReady` 只表示 OS 已 ready，仍需等待 Agent 成功注册后才进入 `Running`。

---

## 附录 A：项目隔离与资产入库演进背景

Argus 早期结果入库以 `task_id` 为主要关联键，适合一次性扫描；当前 schema 已将长期资产、域名、指纹、漏洞统一沉淀到 `project_id` 维度，并保留 `task_id` 作为本次扫描来源。核心设计判断：

- `projects` 是长期业务容器，承载授权边界、默认配置、初始目标、成员和后续巡航任务；`root_tasks` / `sub_tasks` 只描述一次执行。
- `domains`、`assets`、`fingerprint_hits`、`vulnerabilities` 使用 `project_id + target + 业务键` 去重，避免同一项目多次扫描产生重复资产。
- 误删影响大的实体（`projects`、`credentials`）使用软删除；凭证必须加密存储，不使用 JSONB 明文查询。

## 附录 B：规则库 PostgreSQL 初始化流程

控制面将规则数据拆成两层：

- `arsenals`：原始规则文件仓库，直接服务于 Agent 的增量/全量同步。
- 结构化规则表：由 `arsenals` 物化生成，便于统计、检索、审批、AI 工具理解和后续治理。

启动 `argus-server` 时的初始化流程：

1. 规范化历史 `arsenals.type`，将 `fingerprint -> finger`、`dirprobe -> dir` 等旧别名迁移到标准类型。
2. 如果 `arsenals` 为空，则从 `scanner/common/config` 首次导入 `finger.yaml`、`workflow.yaml`、`dir.yaml`、`pocs/*.yaml`。
3. 计算当前 `arsenals` 的聚合哈希。
4. 如果聚合哈希未变化，则跳过结构化回填。
5. 如果聚合哈希变化，则重建 `rule_catalog_bootstraps`、`fingerprint_rules`、`poc_rules`、`workflow_rules`、`dir_rules`。

设计约束：

- `arsenals` 是规则同步的唯一原始来源，不引入第二套真相源。
- 结构化规则表只作为查询和治理视图，由原始规则物化生成。
- 保存、审批、删除、回滚规则后，都会重新同步结构化规则表。
- 字典编辑接口对 `finger.yaml` / `workflow.yaml` 的修改，也会联动刷新结构化表。
- Agent 侧同步仍使用 `poc` / `finger` / `workflow` / `dir` 四类。
- 仓库内 `scanner/common/config` 是构建和 Git 审查用的规则基线，不由 Server 后台自动回写；需要同步 DB 治理结果时，下载或生成 `arsenal_seed.db` 后运行 `tools/arsenal-sync diff/export/apply`，只把 Approved 规则显式还原到本地文件并通过 PR 合并。
- `api-config.yaml` 不进入 DB 同步或回写链路；`socket.yaml` 当前不在扫描加载链路中，也不纳入 `tools/arsenal-sync` 的受管覆盖范围。
