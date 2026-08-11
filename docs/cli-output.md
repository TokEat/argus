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
{"schema_version":"argus.cli-output/v1","record_type":"run_summary","sequence":2,"run_id":"20260810T030901Z-example","summary":{"status":"completed","exit_code":0,"counts":{"targets":1,"findings":1,"coverage":2,"assets_new":1,"services_changed":0,"assets_disappeared":0,"assets_not_assessed":0,"stages_executed":2,"stages_reused":0,"targets_full":1,"targets_incremental":0}}}
```

`finding` 的稳定字段为 `type`、`ip`、`ips`、`port`、`protocol`、`web`、`finger`、`domain`、`go_poc`、`uri`、`city`、`am` 和 `nuclei`；空的 `web`、`go_poc` 不输出。发现由并发阶段产生，不承诺目标排序；`sequence` 只表示实际写出顺序。

JSON 模式下，默认 `result.txt` 与 stdout 使用相同 NDJSON 记录。新版 `finding` 和旧版顶层 Finger JSON 均可继续作为 CLI 的历史指纹输入；`run_summary` 会被安全忽略。

参数或初始化在 Run 建立前失败时不会伪造 `run_summary`。必要诊断写入无 ANSI 的 stderr，stderr 不属于 NDJSON 数据通道。

## 非 TTY 文本输出

默认 `-ot text` 在交互终端保留 Argus Banner、颜色和运行提示。stdout 被重定向或通过管道消费时，只保留扫描结果；Banner、ANSI、进度、耗时和差异摘要不会进入 stdout/stderr。必要错误仍写 stderr。

## 退出码

| 退出码 | 含义 |
| --- | --- |
| `0` | 扫描完成，或 help/version 成功 |
| `1` | 执行、输出或本地历史持久化失败 |
| `2` | 参数、目标或输出类型错误；Standalone Provider 参数已迁移到 Server |
| `130` | 扫描收到中断并完成取消收敛 |

机器调用方应同时检查进程退出码和最后一条 `run_summary`。Run 建立前的错误只有进程退出码和 stderr。

## 从旧 JSON 迁移

旧版 `-ot json` 直接逐行输出 finding，且可能被 Banner 污染。v1 保留流式 NDJSON，但把 finding 放入版本化记录：

```text
旧：{"type":"Web","uri":"http://127.0.0.1:3000"}
新：{"schema_version":"argus.cli-output/v1","record_type":"finding",...,"finding":{"type":"Web","uri":"http://127.0.0.1:3000"}}
```

消费者先校验 `schema_version` 和 `record_type`，再读取 `finding` 或 `summary`；不要依赖并发 finding 的顺序，也不要把 stderr 当作 JSON 输入。
