# Changelog

## [Platform] 2026-07-05 — 日志、分页、扫描策略与文档工具整理

### Server 与 API

| 变更 | 文件 | 说明 |
|------|------|------|
| Agent 日志查询修复 | `server/internal/api/router.go` | 节点存在性检查按 `agent_id` 查询，避免查询不存在的 `id` 字段导致日志接口 404 |
| Agent 日志空数组返回 | `server/internal/api/router.go` | 日志 summary、告警规则、告警事件等空结果返回空数组 |
| JSON/text 请求体 UTF-8 校验 | `server/internal/api/router.go` | 对 JSON、text、form 写接口校验 UTF-8；二进制请求体不受影响 |
| 扫描结果分页 | `server/internal/api/router.go` | `/vulns`、`/assets`、`/fingerprints` 支持 `page`、`page_size` 和分页响应 |
| 规则目录后台同步 | `server/cmd/dddd-server/main.go` | Server 启动后后台执行规则目录索引同步，避免阻塞启动流程 |
| Arsenal lite 响应瘦身 | `server/internal/api/router.go` | `lite=1` 查询返回前清空 `Content` 和 `PreviousContent` |
| 默认端口补齐 | `server/internal/api/task_input.go` | Server 任务默认端口补入 `2379`、`5236`、`54321` |

### Scanner

| 变更 | 文件 | 说明 |
|------|------|------|
| Agent 模式存活探测策略 | `scanner/internal/engine/pipeline.go` | Agent 扫描小网段直接端口扫描，大网段先做存活探测；无存活结果时保留原始目标继续扫描 |
| Safedog/WAF 标题跳过 | `scanner/internal/engine/pipeline.go` | 页面标题包含“当前网络访问异常”或“请验证是否真人访问”时跳过对应目标的 Nuclei 映射 |
| Web 服务跳过 GoPoc 弱口令 | `scanner/gopocs/scanner.go` | 协议识别为 `http`、`https`、`ssl/http` 的服务不进入弱口令 GoPoc 计划 |
| ViewState 触发规则 | `scanner/gopocs/scanner.go` | `yongyou_u9_viewstate` Nuclei 命中和 `viewstate` 指纹命中触发 ViewState key 检测 |
| 指纹解析防护 | `scanner/common/flag.go` | 单条指纹规则解析 panic 时记录日志并跳过，不影响整体指纹库加载 |
| 默认端口补齐 | `scanner/structs/defaults.go`、`scanner/common/flag.go` | CLI 默认端口补入 `2379`、`5236`、`54321` |
| GoPoc 调度测试 | `scanner/gopocs/scanner_test.go` | 覆盖 Web 服务跳过 GoPoc 和 ViewState 触发条件 |

### Frontend

| 变更 | 文件 | 说明 |
|------|------|------|
| Agent 日志页面空值兼容 | `server-ui/src/pages/AgentLogs.tsx` | API 返回 `null` 时归一化为空数组 |
| 扫描结果服务端分页 | `server-ui/src/pages/TaskResults.tsx` | 漏洞、资产、指纹 Tab 独立维护分页状态并请求服务端分页数据 |
| 结果 API 兼容层 | `server-ui/src/services/api.ts` | 结果接口兼容旧数组调用和新分页对象调用 |

### Docs 与 Tools

| 变更 | 文件 | 说明 |
|------|------|------|
| 文档目录去重 | `docs/*.md` | 文档统一放在 `docs/` 根目录，移除重复的 `docs/docs/` 嵌套目录 |
| 文档空白清理 | `docs/argus-technical-whitepaper.md`、`docs/cloud-resource-scheduling.md` | 清理文档行尾空白 |
| 离线转换工具 | `tools/convert_arsenal.go`、`tools/import_dict.go` | 增加 arsenal 和 dict 离线转换工具 |
| Tools build tag | `tools/convert_arsenal.go`、`tools/import_dict.go` | 增加 `//go:build tools`，默认测试不编译离线工具 |

---

## [Scanner] 2026-07-04 — GoPoc 稳定性修复、WAF 配置与扫描优化

修复 GoPoc 调度、数据库连接和指纹识别相关问题，新增 WAF 绕过配置和扫描优化。

### 关键 Bug 修复

| Bug | 文件 | 修复 |
|-----|------|------|
| PluginList 缺失 5 个模块 | `scanner/gopocs/base.go` | 补上 VNC-Scan / Rsync-Scan / DM-Scan / kingbase-Scan / ViewState-Key-Crack 注册 |
| DM 密码 URL 编码缺失 | `scanner/gopocs/dm.go` | DSN 拼接改为 `url.QueryEscape(user)` + `url.QueryEscape(pass)` |
| RSYNC 误报风险 | `scanner/gopocs/rsync.go` | `strings.Contains(line, "OK")` 改为 `strings.HasPrefix(line, "@RSYNCD: OK")` |
| Kingbase nil 指针 panic | `scanner/gopocs/kingbase.go` | `err.Error()` 前加 `if err == nil { continue }` |
| PostgreSQL 指纹缺失 | `scanner/common/config/finger.yaml` | 规则增加 `protocol="postgresql"` 和 `port="5432"` 兜底匹配 |

### 缺陷修复

| 缺陷 | 文件 | 修复 |
|------|------|------|
| MySQL Access denied 中断扫描 | `scanner/gopocs/mysql.go` | auth 错误（err 1045）改为 continue 而非 return |
| PostgreSQL 密码特殊字符 | `scanner/gopocs/postgres.go` | 连接参数增加 URL 编码处理并细化错误分类 |
| 默认端口缺 etcd | `server/internal/api/task_input.go`、`scanner/structs/defaults.go`、`scanner/common/flag.go` | 默认端口列表加 `2379` |

### WAF 绕过新增

| 功能 | 文件 | 说明 |
|------|------|------|
| WAF 指纹阈值过滤 | `scanner/internal/vuln/mapper/mapper.go` | 指纹 > 10 个 → 标记疑似 WAF，跳过 Nuclei，可通过配置关闭 |
| IP 欺骗 Headers | `scanner/common/callnuclei/callnuclei.go` | 默认注入 `X-Forwarded-For`/`X-Real-IP` 等 6 个内网 IP 头，可通过配置关闭 |

### PostgreSQL 表名展示

| 文件 | 说明 |
|------|------|
| `scanner/gopocs/table_list.go` | 新增，支持 PG/MySQL/MSSQL/Oracle/DM/Kingbase 表名查询 |
| `scanner/gopocs/postgres.go` | 爆破成功后显示 `DBs: postgres,dddd`，限制 5 个 |

## [Server] 2026-07-03 — Server 分页/索引/摘要优化 + UTF-8 校验

### 新增

| 功能 | 文件 | 说明 |
|------|------|------|
| 分页基础设施 | `server/internal/api/pagination.go` | `page`/`page_size` 通用分页，所有列表 API 支持分页 |
| Gzip 压缩 | `server/internal/api/middleware_gzip.go` | API 响应自动 Gzip |
| 物化摘要表 | `server/internal/db/rule_catalog.go` | `workflow_product_summaries` 预聚合表，指纹/Workflow 从解析 YAML 改为直接查表 |
| 性能索引 | `server/internal/db/migrations/260_rule_governance_perf.sql` | 30+ pg_trgm / B-tree 索引和 workflow summary 表 |
| 单条查询 | `server/internal/api/router.go` | `GET /arsenals/:type/:filename` |
| UTF-8 校验 | `server/internal/api/router.go` | JSON/text/form 写接口含非法 UTF-8 字节直接返回 400 |

### 修改

| 文件 | 变更 |
|------|------|
| `server/cmd/dddd-server/main.go` | 规则目录同步改为后台 goroutine 异步执行，避免阻塞启动 |
| `server/internal/api/router.go` | `getArsenals` 支持 `page`/`page_size`/`q` 查询参数；`lite=1` 返回前清空 `Content` 和 `PreviousContent` |
| `server/internal/api/handler_dictionary.go` | 指纹/Workflow 字典支持分页模式（`lite=1`+`page`+`page_size`），从物化摘要表查询 |
| `server/internal/api/handler_exploits.go` | 添加分页支持 |
| `server/internal/api/handler_poc_rules.go` | 添加分页支持 |
| `server/internal/db/migrate.go` | 迁移路径使用固定 `/` 分隔，兼容 embedded FS 路径规则 |

---

## [Scanner] 2026-07-03 — 规则数据与 Agent 构建整理

### 规则与字典数据

| 类别 | 数量 | 说明 |
|------|:--:|------|
| POC YAML 模板 | +92 个（2506 total） | 扩充 nuclei POC 模板库 |
| Wordlists（新） | 10 个文件 | 新增 POC helper wordlists |
| Payloads | +4 个 | 新增 POC helper payloads |
| 中心字典（新） | 12 个文件 | 新增中心字典文件 |
| GoPoc 字典更新 | 9 个文件显著扩充 | oracle +8.4x, smb +2x, postgresql +2x, mssql, rdp, ssh 等 |
| socket.yaml（新） | 302 规则 | 新增 socket 指纹规则 |

### 修改文件

| 文件 | 变更 |
|------|------|
| `scanner/gopocs/scanner.go` | 移除 `nuclei/v3` 直接依赖，定义 `NucleiResult` 本地类型 |
| `scanner/internal/vuln/gopoc/dispatcher.go` | 使用 `gopocs.NucleiResult` 替代 `output.ResultEvent` |
| `scanner/internal/engine/pipeline.go` | Nuclei 相关代码提取到 `pipeline_nuclei.go`；GoPoc `Dispatch` 接受 `[]NucleiResult` |
| `server/internal/api/task_input.go` | 默认端口列表追加 5236(DM) 和 54321(Kingbase) |

### Bug 修复

| 问题 | 修复 |
|------|------|
| 数据库中文乱码 | `router.go` 添加 JSON/text/form 写接口 UTF-8 校验，非法字节返回 400 |
| 指纹/Workflow 加载失败 | `listArsenals` 默认 `lite=true`，Content 正确清空 |
| embedded FS 迁移路径不兼容 | 使用固定 `/` 分隔迁移路径 |

---

## [Scanner] 2026-07-02 — Go POC 模块集成

新增 5 个 Go POC 模块至 Argus 扫描引擎。

### 新增 POC 模块

| POC | 名称 | 功能 |
|-----|------|------|
| `DM-Scan` | 达梦数据库弱口令检测 | 国产数据库 DM 的密码爆破，支持空密码探测 |
| `kingbase-Scan` | 人大金仓弱口令检测 | 国产数据库 Kingbase 的密码爆破，复用 PostgreSQL 协议 |
| `VNC-Scan` | VNC 弱口令及未授权检测 | VNC 空密码 + 字典爆破，移除 Exclusive 模式兼容更多服务 |
| `Rsync-Scan` | RSYNC 弱口令及未授权检测 | RSYNC 模块枚举 + 未授权访问 + 密码爆破 |
| `ViewState-Key-Crack` | ASP.NET ViewState 密钥爆破 | 从页面提取 `__VIEWSTATE` 后 HMAC-SHA512/384/256/SHA1/MD5 碰撞 |

### 调度触发规则

| POC | 触发条件 |
|-----|---------|
| DM-Scan | 协议识别为 `dm` 或端口 5236 |
| kingbase-Scan | 协议识别为 `kingbase` 或端口 54321 |
| VNC-Scan | 协议识别为 `vnc` 或端口 5900 |
| Rsync-Scan | 协议识别为 `rsync` 或端口 873 |
| ViewState-Key-Crack | 指纹匹配 `viewstate` 或 Nuclei 模板 `yongyou_u9_viewstate` 命中 |

### 新增字典文件

| 文件 | 用途 |
|------|------|
| `gopocs/dict/dm.txt` | 达梦数据库爆破字典 |
| `gopocs/dict/kingbase.txt` | 人大金仓爆破字典 |
| `gopocs/dict/vnc.txt` | VNC 密码字典 |
| `gopocs/dict/machineKeys.txt` | ASP.NET ViewState 机器密钥字典 |

### 新增依赖

- `gitee.com/chunanyong/dm` v1.8.23 — 达梦数据库 Go 驱动
- `github.com/mitchellh/go-vnc` v0.0.0 — VNC 客户端

### 集成说明

- **结果写入**: 使用 `writeResult(info, ...)` 回调模式
- **配置访问**: 使用 `info.*` HostInfo 字段
- **TCP 工具**: 使用 `utils.WrapperTcpWithTimeout`

### 修改文件

| 文件 | 变更 |
|------|------|
| `scanner/gopocs/base.go` | PluginList 注册 5 个新 POC；initDic 添加 kingbase 字典加载 |
| `scanner/gopocs/scanner.go` | buildScanPlan 添加 VNC/RSYNC/DM/Kingbase 调度；Dispatch 添加 ViewState 指纹/Nuclei 触发 |
| `go.mod` / `go.sum` | 新增 dm、go-vnc 依赖 |
