# Argus 数据库设计总览

本文档按当前项目整体架构整理 PostgreSQL 中的核心数据模型，覆盖控制面调度、结果聚合、规则治理、系统配置四条主链路。

当前以以下实现为准：

- `server/internal/db/db.go`
- `server/internal/db/rule_catalog.go`
- `server/internal/db/task_lifecycle.go`

> 注：
> - 本文描述的是“当前主链路实际需要的完整 schema”。
> - `server/deploy/postgres/sql/010-schema.sql` 仍保留部分历史初始化结构，字段完整性已落后于 GORM 模型；若重新梳理初始化脚本，应以本文和 `db.go` 为准。

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
- 为保证吞吐，当前模型基本不依赖物理外键，而是通过应用层逻辑关联 `project_id`、`root_task_id`、`agent_id` 等业务主键。
- 灵活结构统一使用 `jsonb` 或 `text(JSON)` 存储，例如标签、任务配置、节点选择器、规则详情。
- 误删风险高的实体使用软删除：当前包括 `projects`、`cron_tasks`、`credentials`。

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

- `projects` 是项目隔离的顶层容器，向下关联 `project_members`、`cron_tasks`、`root_tasks`、`notification_rules`、`domains`、`assets`、`credentials`、`fingerprint_hits`、`vulnerabilities`、`asset_change_logs`、`reports`。
- `root_tasks` 表示一次用户发起或定时触发的巡航任务，向下切分为多个 `sub_tasks`。
- `sub_tasks` 由 `nodes` 认领执行，并驱动结果写入 `domains`、`assets`、`fingerprint_hits`、`vulnerabilities`。
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

#### `cron_tasks`

| 字段 | 类型 | 说明 | 约束 / 索引 |
|------|------|------|-------------|
| `id` | string | 定时任务主键 | PK |
| `project_id` | string | 所属项目 | Index |
| `name` | string | 定时任务名称 | - |
| `cron_expr` | string | Cron 表达式 | Index |
| `targets` | jsonb | 定时目标集 | - |
| `config` | jsonb | 定时任务扫描配置 | - |
| `next_run_at` | timestamp | 下次执行时间 | Index |
| `status` | string | `active` / `disabled` | Index, Default:`active` |
| `created_at` / `updated_at` / `deleted_at` | timestamp | 审计时间与软删除时间 | `deleted_at` Index |

#### `root_tasks`

| 字段 | 类型 | 说明 | 约束 / 索引 |
|------|------|------|-------------|
| `id` | string | 根任务 ID | PK |
| `tenant_id` | string | 租户隔离键 | Index |
| `project_id` | string | 所属项目 | Index |
| `cron_task_id` | string | 来源定时任务 | Index |
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
| `created_at` / `updated_at` | timestamp | 审计时间 | - |

#### `sub_tasks`

| 字段 | 类型 | 说明 | 约束 / 索引 |
|------|------|------|-------------|
| `id` | string | 子任务 / 批次 ID | PK |
| `tenant_id` | string | 租户隔离键 | Index |
| `project_id` | string | 所属项目 | Index |
| `root_task_id` | string | 关联根任务 | Index |
| `chunk_targets` | text | 当前批次目标列表 JSON | Text |
| `status` | string | 子任务状态机 | Index |
| `agent_id` | string | 当前认领节点 | Index |
| `config` | text | 当前批次配置 JSON | Text |
| `stream_msg_id` | string | 队列消息句柄 / MQ 消息标识 | - |
| `priority` | int | 调度优先级，默认 `1` | Index, Default:`1` |
| `agent_selector` | text | 节点标签选择器 JSON | Text |
| `timeout_sec` | int | 批次超时秒数 | - |
| `retry_count` | int | 当前重试次数 | - |
| `max_retry` | int | 最大重试次数 | Default:`3` |
| `created_at` / `updated_at` | timestamp | 审计时间 | - |

设计要点：

- 任务创建后初始进入 `Dispatching` 或 `Pending`。
- 失败 / 超时时允许进入 `Recovered` 或进行二分拆分重试。
- 用户取消走 `CancelPending -> Cancelled` 两段式收敛。

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

#### `notification_rules`

| 字段 | 类型 | 说明 | 约束 / 索引 |
|------|------|------|-------------|
| `id` | uint | 规则主键 | PK |
| `project_id` | string | 所属项目 | Index |
| `event` | string | 触发事件类型 | Index |
| `channel` | string | 通知渠道 | - |
| `config` | jsonb | 渠道配置 | - |
| `status` | string | `enabled` / `disabled` | Default:`enabled` |
| `created_at` | timestamp | 创建时间 | - |

---

### 3.3 资产、结果与报表

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

#### `asset_change_logs`

| 字段 | 类型 | 说明 | 约束 / 索引 |
|------|------|------|-------------|
| `id` | uint | 变更主键 | PK |
| `project_id` | string | 所属项目 | Index |
| `task_id` | string | 触发变更的任务 | Index |
| `entity_type` | string | 变更对象类型 | Index |
| `entity_id` | uint | 变更对象主键 | Index |
| `change_type` | string | 变更类型 | Index |
| `details` | jsonb | 变更详情 | - |
| `created_at` | timestamp | 记录时间 | - |

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
| `tags` | text | 标签串 | Text |
| `author` | string | 作者 | - |
| `description` | text | 描述 | Text |
| `version` | int | 版本号 | Default:`1` |
| `state` | string | 规则状态 | Index |
| `enabled` | bool | 是否启用 | Index, Default:`true` |
| `created_at` / `updated_at` | timestamp | 审计时间 | - |

联合唯一约束：`(tenant_id, source_file)`。

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

## 5. 相比旧文档本次补齐的重点

- 补全 `project_members`、`cron_tasks`、`notification_rules`、`domains`、`credentials`、`asset_change_logs`、`reports`。
- 补全规则治理层的 `rule_catalog_bootstraps`、`fingerprint_rules`、`poc_rules`、`workflow_rules`、`dir_rules`。
- 补全 `nodes` 的会话令牌、容量、运行任务列表、OS/Arch、资源使用率等字段。
- 补全 `users` 的密码哈希、状态字段，以及 `system_configs` 对 `mcp_*` API Key 的承载方式。
- 修正任务状态机，明确 `PartialDone`、`Dispatching`、`Recovered`、`CancelPending` 等中间态。
- 明确 PostgreSQL 只保存报表元数据，不直接保存报表文件本体。

---

## 6. 结合整体架构，后续建议预留但当前尚未落地的表

下列能力已在架构文档或实现状态文档中明确为缺口，但当前数据库尚未正式建模，可作为后续 schema 扩展候选：

| 能力域 | 建议表 | 原因 |
|--------|--------|------|
| 云资源编排 | `cloud_accounts`、`cloud_scaling_policies`、`cloud_instances` | 当前 Cloud 管理仍主要是 mock，缺少凭证、策略、实例生命周期持久化 |
| 租户治理 | `tenant_quotas`、`tenant_usage_snapshots` | 任务配额、并发额度、租户级资源限制尚未落库 |
| 角色权限矩阵 | `roles`、`permissions`、`role_bindings` | 现阶段仅有用户角色字段，没有可管理的权限矩阵 |
| 构建与发布 | `build_jobs`、`build_artifacts` | 当前客户端构建接口只返回 `accepted`，缺少任务状态跟踪 |

这些建议表不属于当前已落地 schema，单独列出是为了避免后续架构扩展继续走“接口先行、数据模型缺位”的老路。
