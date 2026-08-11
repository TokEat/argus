# Server 资产发现

Argus 已将 Hunter、FOFA、Quake 的用户查询入口完整迁移到 Server 控制面。Server 负责凭据、查询预算、结果规范化、审计、后续导出与任务分发；CLI 只接受显式扫描目标，Scanner 与 Agent 会在任何规则、存储或网络初始化前拒绝旧 Provider 配置。Agent 不再下载、读取或落盘 Provider 凭据，旧队列中的 Provider Attempt 会由 Server 失败关闭而不会下发。

## CLI 迁移提示

`dddd` 不再执行 Hunter、FOFA 或 Quake 查询，不读取 Provider 凭据，也不会发起 Provider 网络请求。旧有 Provider flag 仅作为迁移期提示被识别：CLI 会返回非零状态并提示在当前项目的“资产测绘”页面发起查询。请改用 Server 的项目级入口；显式目标的本地扫描继续使用 `dddd -t <target>`。

## 当前能力

当前开放项目级 FOFA、Hunter 与 Quake 查询：

```text
POST /api/v1/projects/{project_id}/asset-discovery/fofa/query
POST /api/v1/projects/{project_id}/asset-discovery/hunter/query
POST /api/v1/projects/{project_id}/asset-discovery/quake/query
```

成功查询可通过项目级只读历史接口检索：

```text
GET /api/v1/projects/{project_id}/asset-discovery/queries
GET /api/v1/projects/{project_id}/asset-discovery/queries/{snapshot_id}
GET /api/v1/projects/{project_id}/asset-discovery/queries/{snapshot_id}/export
GET /api/v1/projects/{project_id}/asset-discovery/notebook-items
GET /api/v1/asset-discovery/notebook-items
PATCH /api/v1/projects/{project_id}/asset-discovery/notebook-items/{item_id}
POST /api/v1/projects/{project_id}/asset-discovery/notebook-items/{item_id}/remove
POST /api/v1/projects/{project_id}/asset-discovery/notebook-items/{item_id}/restore
POST /api/v1/projects/{project_id}/asset-discovery/queries/{snapshot_id}/notebook-items
POST /api/v1/projects/{project_id}/asset-discovery/notebook-distributions/preview
POST /api/v1/projects/{project_id}/asset-discovery/notebook-distributions
```

请求体是单个严格 JSON 对象：

```json
{
  "expression": "domain=\"example.com\"",
  "limit": 100
}
```

- `expression` 必填，去除首尾空白后最多 4096 字节，不能包含换行或 NUL。
- `limit` 可省略；默认 100。FOFA 范围为 1–10000，Hunter 范围为 1–1000，Quake 范围为 1–500。
- 未声明字段、多 JSON 文档或超过 16 KiB 的请求体会被拒绝。

查询成功响应使用 `argus.asset-discovery-query-preview/v1`，包含项目 ID、审计 ID、Provider 计数和规范化资产。它不会回显查询表达式、配置版本、配置哈希或 Provider 凭据；同一事务还会保存不可变查询快照，供历史、导出和笔记本使用。

## 权限与配置

- 调用者必须通过 JWT 认证，角色至少为 `operator`，并且拥有目标项目的对象级访问权。
- Provider 凭据只从当前租户已批准的 `apiconfig/api-config.yaml` 读取；FOFA 沿用兼容格式 `email:key`，Hunter 使用单个 API Key 字符串，Quake 使用单个 Token 字符串。
- Server 不会回退到其他租户、Agent 文件或 CLI 本地配置；找不到有效当前租户配置时返回 `503`。
- Provider 拒绝、不可用或畸形响应统一映射为脱敏错误；上游 URL、响应正文、email、key 和 token 不进入 API 响应。

## 审计与数据语义

每个通过项目访问校验的查询尝试都会写入 `asset_discovery_audits`。审计只保存：

- tenant/project/operator、Provider 和动作；
- 查询表达式 SHA-256、API 配置语义 SHA-256 和配置版本；
- 请求条数、Provider 总数、返回/跳过数、截断标记、耗时和稳定错误分类。

审计不保存原始表达式、凭据、请求 URL、Provider 原始响应或结果正文。Provider 成功后，成功审计、查询快照和全部规范资产项在同一事务内写入；任一校验或写入失败都会回滚成功记录、尝试写入稳定失败审计并隐藏查询结果。

Provider 查询、历史读取、导出、笔记本归档和分发预览都不会写入 `assets`，也不会自动扩展 Project Scope/SeedTargets 或创建 Task、Batch、Attempt。只有 operator 在分发预览后显式确认，才会将预览中的新增 direct 目标追加到所选任务与项目范围。

Migration 380 建立追加式 `asset_discovery_snapshots` 与 `asset_discovery_snapshot_items` 契约，三个预览入口已原子写入该快照。快照将原始表达式视为受 tenant/project 对象权限保护的项目业务数据，审计表仍只保留表达式哈希；快照和资产项均没有凭据或 Provider 原始响应字段。

## 查询历史

- 历史列表默认每页 20 条、最多 100 条，可使用 `provider=<name>` 精确过滤；按查询时间和 ID 倒序返回。
- 单次查询明细的资产默认每页 100 条、最多 500 条；按原始规范化顺序返回。
- 两个接口均使用 `argus.asset-discovery-query-history/v1`，要求 viewer 及以上角色并再次验证当前 tenant/project 对象访问权。
- 列表可返回受项目权限保护的原始表达式、配置版本、计数和操作者；不会返回 Provider 凭据、配置哈希、查询哈希、目标哈希或 Provider 原始响应。
- 历史响应使用 `Cache-Control: no-store`，避免包含原始表达式的项目数据被中间缓存保存。
- 历史接口严格只读，不写 `assets`、不扩展项目范围，也不会创建任务或批次。

单次快照导出由 Server 生成 UTF-8 CSV，而不是拼接前端当前页。导出最多读取 10000 个规范资产，编码后不得超过 32 MiB；项目授权、快照与资产读取以及成功审计共用一个 10 秒请求级数据库预算。资产按原始位置稳定排序。CSV 对可能被表格软件解释为公式的字符串加文本前缀，文件名只使用数值快照 ID。文件不包含查询表达式、tenant/project 内部字段、查询/配置/目标哈希、凭据或 Provider 原始响应。只有脱敏 `export_snapshot` 审计成功写入后才返回文件；审计失败或预算耗尽都会中止下载。

## 测绘笔记本

- operator 可从一条已持久化快照中选择 1–100 个资产项归档；请求只接受稳定的 `item_ids`，不会信任客户端提交的目标或哈希。viewer 可分页读取笔记本，默认每页 50 条、最多 100 条。
- 每个 tenant/project 以规范目标 SHA-256 去重，最多保存 10000 个笔记本目标。同一目标再次出现在其他快照中时不会复制目标，但会增加一条可追溯来源；重复归档同一快照项是幂等操作。
- 项目、快照和快照项均按 tenant/project 重新校验。归档项目保留只读列表，但不能新增笔记本来源。
- 笔记本目标、来源和 `notebook_archive` 脱敏审计在一个 10 秒数据库事务内提交；审计或任一关联写入失败时全部回滚。公开列表不返回目标哈希、查询表达式、配置哈希、凭据或 Provider 原始响应。
- 单个归档请求体上限为 16 KiB。笔记本只是候选目标集合，不代表扫描授权已通过，也不会自动触发 Agent、POC 或任务队列。
- 项目列表和“可访问项目”聚合列表支持 `q`、`tag`、`state=active|removed|all` 与稳定分页；跨项目聚合只查询 `scopedProjectsQuery` 已授权的项目，不提供跨项目编辑或分发入口。
- operator 可为条目维护最多 20 个规范化标签（每个最多 64 字节）和最多 4096 字节备注，并可软移除或恢复。viewer 只能读取。写操作会在事务内重验 tenant/project/item、项目非归档状态并写入关联具体 item 的脱敏审计；审计失败时全部回滚。
- 软移除不会删除规范目标、不可变来源、既有分发意图或任务历史；默认列表与新的分发预览会排除已移除条目，恢复后才可重新选择。

前端在 `/asset-discovery` 提供独立“资产测绘”模块：自动使用当前项目，operator 只需选择 Provider 并输入表达式即可查询，结果即时展示并进入历史；viewer 可以查看项目历史、分页明细、笔记本并一键导出完整快照 CSV。operator 可在已持久化历史明细中多选最多 100 条归档到笔记本，预览结果不能直接归档。归档项目保留历史、导出和笔记本读取入口，但页面不允许发起新查询或归档。高级查询预算继续使用 Server 安全默认值，不要求用户手动选择扫描参数。

### 笔记本分发预览

- operator 可从当前项目笔记本选择 1–100 个条目，并选择同项目的现有任务生成只读分发预览。归档项目、归档任务、不可追加状态或使用旧网络搜索模式的任务不能生成预览。
- Server 不信任客户端提交目标：它会按 tenant/project 重新读取全部笔记本条目和任务当前配置修订，再使用任务追加批次相同的 direct 目标规范化、任务内去重和分批规则，展示实际新增、任务内重复、预计批次数以及 Project Scope/SeedTargets 的预计增量。
- 响应中的 `plan_hash` 绑定当前选集、任务状态、配置/规则版本、任务已有目标和项目范围快照，供后续幂等物化接口检测陈旧预览。它是状态摘要，不是授权令牌；实际执行仍须显式确认并再次校验全部对象和策略。
- 预览共用 10 秒请求级数据库预算，使用 `Cache-Control: no-store`，不会写审计、Project Scope/SeedTargets、Task、Batch 或 Attempt，也不会触发队列、Agent、POC 或 EXP。

### 分发意图数据契约

- Migration 400 新增内部使用的分发意图与逐项不可变快照。意图固定 tenant/project/task、操作者、操作域、预览 schema 与 `plan_hash`、任务状态、配置/规则版本和新增/重复计数；逐项快照固定笔记本条目、规范目标、目标哈希和预览判定。
- 原始 `Idempotency-Key` 不落库，只保存 SHA-256。同一 tenant/project/operator/operation 下，同键同请求原子返回已有意图，同键异请求返回固定冲突；父记录与全部选中项在同一事务内写入，任一步失败都会回滚。
- Task、ConfigRevision、NotebookItem 和 Intent 均由 tenant/project 复合外键约束，禁止跨租户或跨项目挂接。该意图不是业务审计、扫描授权、风险确认或执行凭证。
- 意图本身不是授权或执行凭证；只有下述确认接口可以在同一事务中创建意图、不可变执行结果和任务变更。原始幂等键、Provider 查询及响应不会进入意图、业务审计或公开响应。

### 确认并分发到任务

- operator 在有效预览后显式确认，调用 `POST /api/v1/projects/{project_id}/asset-discovery/notebook-distributions`。请求必须携带 1–128 个可见 ASCII 字符的 `Idempotency-Key`，严格 JSON 只接受 `task_id`、1–100 个 `item_ids` 和当前 `plan_hash`。
- Server 不信任客户端的目标或预览计数。新请求会在统一 10 秒预算内重新校验 tenant/project/task/item 归属、项目与任务生命周期、当前配置修订、规则版本、全部现有目标和项目范围，并重新计算 `plan_hash`。只接受普通 direct 安全任务；POC、GoPoc 或 EXP 配置不能借此扩展目标。
- operator 的确认是将本次新增 direct 目标纳入当前项目授权范围的明确动作。事务只沿用任务既有 Agent selector 和网络区域策略，不允许请求覆盖 selector 或 network zone；后续调度与覆盖复用仍按 Server 的公网/私网区域隔离规则执行。
- 同一数据库事务创建或重放分发意图与 typed materialization 结果，扩展 Project Scope/SeedTargets 和 RootTask 原始目标，创建追加式 TaskBatch/Attempt，并写 `notebook_distribution_materialize` 脱敏审计。任一写入失败都会完整回滚。
- 事务提交后才派发新 Attempt。暂停任务新增 Paused 批次且不派发；完成任务存在新增目标时恢复 Running。全部目标已在任务中时返回 `outcome=unchanged`，只保留确认意图和不可变结果，不修改任务、项目范围或审计，也不进入队列。
- 同一作用域、操作者和 `Idempotency-Key` 的同一确认返回第一次提交的稳定结果，不重新计算可变预览、不重复创建批次或入队；同键不同确认返回 `409`。队列发布失败时 Attempt 保持 `Dispatching`，由现有恢复器补投。

查询区随 Provider 显示常用字段、运算符、安全示例和官方帮助入口：[FOFA API](https://fofa.info/api)、[Hunter 帮助中心](https://hunter.qianxin.com/home/helpCenter)、[Quake 帮助中心](https://quake.360.net/quake/#/help)。输入字段前缀后可使用方向键与 Enter 完成字段及连接符，字段和示例按钮也可直接写入表达式。补全目录只提供输入提示，Server 仍将用户表达式原样交给对应 Provider，不用前端目录限制厂商支持的其他语法。

## 内部 Provider 状态

Server 已具备 FOFA、Hunter 与 Quake 三个相互独立的 Provider 核心和项目授权入口。Hunter 核心沿用统一规范资产结构，以租户隔离配置中的 API Key 和用户查询工作；分页共享一次 30 秒总超时、最多 10 页/1000 条和 8 MiB 总响应预算。它只提取 IP、域名、端口、协议、标题、国家、城市、公司和状态码，不保存或返回 Hunter banner、剩余额度、原始查询、原始响应或 API Key。

Quake 核心只执行一次最多 500 条的有界 POST，不再沿用旧 Scanner 的查询前固定等待和 `/user/info` VIP 探测。Token 仅放在 `X-QuakeToken` Header，结果字段显式收窄；高级字段不可用时回退为规范 `IP:Port`。单行最多处理 32 个 URL，最终资产数还受查询条数派生上限和 2000 条硬上限约束。

三个查询入口都要求 operator 及以上角色和项目对象级访问权，Provider 成功但审计或快照写入失败时均不返回结果。当前已持久化不可变查询快照，并开放项目内历史读取、CSV 导出、项目级测绘笔记本运营、TaskBatch 分发预览和显式确认物化；确认链路使用不可变 intent/result 保证重放不会重复创建或派发。Scanner/Agent 的旧 Provider 执行、Agent 凭据同步与 Subfinder Provider 配置读取均已移除或失败关闭。

## 后续边界

测绘命中、笔记本条目、intent 或旧预览都不能直接触发扫描；只有当前 operator 对未过期预览的显式确认可以扩展该项目范围并创建任务批次。Server 查询额度策略与查询级幂等键仍可在后续按独立产品需求扩展。

## 回滚

应用回滚时可关闭笔记本运营与分发确认路由，并保留追加式审计、快照、笔记本、标签、来源、分发意图及其不可变 materialization 结果。Migration 370/380/390/400/420/480 只新增表、列、约束和索引，不修改或删除现有扫描数据；回滚应用版本无需删除新对象，删除前应先独立备份项目查询历史、笔记本来源、标签、分发意图和物化结果。
