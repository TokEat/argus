# Argus CLI 结构化输出

## NDJSON 契约

`argus -ot json` 输出 UTF-8 NDJSON。每一行都是完整 JSON 记录，适合边扫描边消费；stdout 不包含 Banner、颜色、进度和普通运行日志。

Schema 固定为 `argus.cli-output/v1`。记录公共字段：

| 字段 | 含义 |
| --- | --- |
| `schema_version` | 固定 `argus.cli-output/v1` |
| `record_type` | `finding` 或 `run_summary` |
| `sequence` | 当前 Run 内从 1 开始、严格递增 |
| `run_id` | 本地 Run 标识 |

发现记录示例：

```json
{"schema_version":"argus.cli-output/v1","record_type":"finding","sequence":1,"run_id":"20260810T030901Z-example","finding":{"type":"Web","web":{"status":"200","title":"Argus"},"uri":"http://127.0.0.1:3000"}}
```

扫描开始后，无论发现数量是否为零，stdout 最后一行都是唯一的终端记录：

```json
{"schema_version":"argus.cli-output/v1","record_type":"run_summary","sequence":2,"run_id":"20260810T030901Z-example","summary":{"status":"completed","exit_code":0,"counts":{"targets":1,"findings":1,"coverage":2,"assets_new":0,"services_changed":0,"assets_disappeared":0,"assets_not_assessed":0,"stages_executed":2,"stages_reused":0,"targets_full":0,"targets_incremental":0,"targets_partial":1,"targets_skipped":0,"assets_planned":253,"assets_history_skipped":3}}}
```

`finding` 的稳定字段为 `type`、`ip`、`ips`、`port`、`protocol`、`product`、`version`、`transport`、`web`、`finger`、`domain`、`go_poc`、`uri`、`city`、`am` 和 `nuclei`；空的 `web`、`go_poc`、`product`、`version`、`transport` 不输出。`product` / `version` 来自协议识别阶段的服务画像，不是 Web CMS 指纹。文本把传输层和服务名写在同一行：`[Port] [tcp] 10.0.0.8:445 smb`、`[Port] [udp] 10.0.0.8:53 dns`，HTTP/HTTPS 端口标 `[web]`。单独执行 `argus -tr <目标>` 时另有 `[Path] dest hops=N hop1 -> hop2` 和收成网段的 `[Topo]`，不进入复用目标。文本模式下 Web 探测和指纹会先攒在一起，指纹识别结束后按同源（协议+主机+端口）只打一条 `[WEB]` 分组块；同站 302 和落地页合成一块，子行是 `[Finger]`、`[Certificates]`、`[Code]`、`[Size]`、`[Redirect]`、`[Title]`。命中的 Nuclei/GoPoc 紧跟其后写成 `[POC] ...`，包含 info 级探测模板。Nuclei 模板 runtime/syntax 告警默认进审计，不占终端。JSON 仍按到达顺序分别写 `web`、`finger`、`nuclei`/`go_poc`。Workflow 只消费正式指纹阶段的 ResultMap，不消费展示用即时指纹。发现由并发阶段产生，不承诺目标排序；`sequence` 只表示实际写出顺序。

`run_summary.counts` 中的 `targets_full`、`targets_partial`、`targets_skipped` 描述原始输入的 datas 历史差集决策；`assets_planned` 与 `assets_history_skipped` 描述 CIDR/IP 范围展开后的地址数量。扫描记忆只读取已完成目录的 `result.txt`，不依赖 TSV；因此历史中没有 finding 的地址仍会再次扫描。

JSON 模式下，默认 `result.txt` 与 stdout 使用相同 NDJSON 记录。新版 `finding` 和旧版顶层 Finger JSON 均可继续作为 CLI 的历史指纹输入；`run_summary` 会被安全忽略。

## Argus HTML 扫描报告

每个 CLI Run 在结果目录生成一份自包含的 Argus HTML 报告；可用 `-ho` 指定文件名。报告直接消费与 `result.txt` 相同的结构化发现流，不再从文本结果反向解析，也不再单独生成 `*_assets.html`。单页按资产、服务与协议、Web、指纹、漏洞证据和其他记录分区，支持本地搜索及严重度筛选。指纹区按“规范化服务边界（scheme、host、port）+ 产品名”归并：同一产品只显示和计数一次，卡片展开后分别列出被动命中、主动确认及 `dir-fallback` 路径推断证据；不同协议或端口不会错误合并。路径推断明确标为疑似，不冒充经过产品规则复核的确认结果。

`result.txt` 仍是实时持久化的原始结果，生成 HTML 不会读取、改写或删除它。由于 JSON 结果与 HTML 都可能包含认证 Cookie、成功口令验证和原始收发包，两者新建时均采用私有权限：Unix 使用 `0600`，Windows 使用仅当前进程用户可访问的受保护 DACL。HTML 在 Run 收敛后以不覆盖既有文件的原子方式发布；若报告写入失败，CLI 返回非零退出码，不会把不完整临时文件当作权威报告。此时已经采集的分类证据 spool 会保留在报告目录，并通过 stderr 给出恢复路径。

HTML 中的“扫描执行状态”只描述扫描、本地历史与报告准备阶段；stdout 或 `result.txt` 的最终写入仍可能在报告发布后失败。跨输出介质无法提供单一文件系统事务，因此进程退出码和 JSON `run_summary` 是 CLI 全流程终态的权威来源，报告页会明确显示这一边界，避免把扫描完成误读为所有输出通道均已成功终结。

Nuclei 的全部多步骤 packet/request/response、独立 request/response、OAST interaction 和复现命令都会保留并进行 HTML 转义；超过 21 步的模板不再被固定上限截断。HTTP 文本按原始多行展示，Network/TCP 每一步的实际收发字节使用可恢复的 hex-dump，避免非法 UTF-8 在 JSON 中被替换。GoPoc 的 `InfoLeft`、`InfoRight` 与 `ShowMsg` 继续作为验证摘要保留；凡扫描器能够直接取得实际网络字节的成功验证，都会提供结构化 `go_poc.exchanges` 原始证据，即使未开启审计也会进入 JSON 和 HTML。使用第三方协议客户端且 Argus 无法取得原始帧的插件仅展示真实可得的验证摘要，不会把摘要或推测内容冒充网络包。页面不加载 CDN、远程脚本或字体。

`-nopoc` 只关闭 Nuclei，不影响资产、服务、Web、指纹和 GoPoc 进入 HTML。此时漏洞区若没有 Nuclei 证据，不能解释成目标不存在漏洞。`-nopoc` 与 `-poc` 同时使用会返回参数错误。关掉 GoPoc 用 `-nogpoc`。

参数或初始化在 Run 建立前失败时不会伪造 `run_summary`。必要诊断写入无 ANSI 的 stderr，stderr 不属于 NDJSON 数据通道。

## 非 TTY 文本输出

默认 `-ot text` 在交互终端保留 Argus Banner、颜色和运行提示。stdout 被重定向或通过管道消费时，只保留扫描结果；Banner、ANSI、进度、耗时和差异摘要不会进入 stdout/stderr。必要错误仍写 stderr。

## 退出码

| 退出码 | 含义 |
| --- | --- |
| `0` | 扫描完成，或 help/version 成功 |
| `1` | 执行、输出或本地历史持久化失败 |
| `2` | 参数、目标或输出类型错误 |
| `130` | 扫描收到中断并完成取消收敛 |

机器调用方应同时检查进程退出码和最后一条 `run_summary`。Run 建立前的错误只有进程退出码和 stderr。

## 从旧 JSON 迁移

旧版 `-ot json` 直接逐行输出 finding，且可能被 Banner 污染。v1 保留流式 NDJSON，但把 finding 放入版本化记录：

```text
旧：{"type":"Web","uri":"http://127.0.0.1:3000"}
新：{"schema_version":"argus.cli-output/v1","record_type":"finding",...,"finding":{"type":"Web","uri":"http://127.0.0.1:3000"}}
```

消费者先校验 `schema_version` 和 `record_type`，再读取 `finding` 或 `summary`；不要依赖并发 finding 的顺序，也不要把 stderr 当作 JSON 输入。
