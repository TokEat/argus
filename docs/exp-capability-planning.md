# Argus EXP 能力规划

Argus EXP 当前采用 Python-only 实现。旧的 EXP YAML 包、Nuclei runtime、Starlark runtime 和声明式 HTTP EXP 路径已经退役，后续开发以 Python EXP 为唯一主线。

## 能力边界

EXP 用于授权范围内的受控利用验证，和 POC 扫描链路分离：

- POC 负责发现和验证漏洞信号。
- EXP 负责在人工授权、风险确认和 Agent 能力约束下做更强的利用验证。
- EXP 可关联 POC，但不复用 POC 的执行器。

## Python EXP 格式

每个 EXP 是一个 `.py` 文件，内容保存于 `arsenals(type=exp).content`。

必须包含：

- `ARGUS_EXP` dict 元数据。
- `run(ctx)` 或 `main()` 执行入口。

推荐包含：

- `argparse` 参数定义，作为本地 CLI 和平台参数推断的主合同。
- `cleanup(ctx)`，用于清理写入、创建或状态修改类副作用。
- `requirements`，所有第三方依赖必须固定版本并携带 hash。
- `policy.capabilities`，仅作为 UI 展示和审核辅助元数据；不作为运行时能力管控边界。

## 执行器

核心实现位于：

- `shared/proto/pyexp`：Python EXP 解析、校验、参数推断和 requirements 规则校验。
- `scanner/internal/exploit`：Python-only EXP engine、Python runner、兼容 ctx SDK 和 HTTP trace。
- `scanner/cmd/exp-debug`：本地 Python EXP 调试 CLI。

Agent 通过本地 Python 子进程执行 EXP。运行时会写入临时工作目录，注入 `argus_sdk.py`、`runner.py`、`context.json` 和 EXP 脚本。脚本可以直接使用原生 Python 标准库、系统 API 和已声明依赖；`ctx` 只保留 `params`、`target`、`evidence`、`result`、`cleanup` 作为结构化回传入口。

## Capability 展示元数据

`policy.capabilities` 保留给 UI 展示和审核讨论，常见取值包括：

- `evidence.write`
- `cleanup.defer`
- `result.write`

执行器不再根据该字段拦截能力，也不限制原生 Python 网络或系统调用。运行时仍保留 timeout guard：按 EXP policy 或调用方 timeout 截断。

## Server 管理链路

- `saveArsenal(type=exp)`：只接受 `.py` 文件，并做基础 Python EXP 校验。
- `approveArsenal` / EXP 审核：执行严格元数据校验，包括 requirements 规则；不再做 Python 符号 deny-list 或 capability 扫描拦截。
- `materializeExploitRule`：从 Python EXP 解析元数据并写入 `exploit_rules`。
- `dry-run`：解析 Python EXP 并返回执行计划、参数归一化结果和 requirements 信息。
- `debug`：将 Python EXP 下发到支持 `python_exp=true` 的在线 Agent。
- `exploit-runs`：正式执行仍受审批状态、风险确认、Agent 能力、requirements 预检和并发控制约束。

## 数据模型

`exploit_rules` 是 Python EXP 的可检索物化表，关键字段包括：

- `artifact_id`
- `source_file`
- `rule_id`
- `name`
- `description`
- `target_product`
- `risk_level`
- `requires_auth`
- `side_effects`
- `cleanup_supported`
- `cleanup_required`
- `dry_run_supported`
- `capabilities`
- `linked_pocs`
- `params_schema`
- `requirements`
- `requirements_hash`
- `sandbox_profile`
- `timeout_sec`
- `runtime_engine`

`runtime_engine` 固定为 `python`，`sandbox_profile` 默认 `local-python`。

## AI 与 Builder

AI Copilot 和前端 Builder 只生成 Python EXP：

- 输出必须是 fenced `python`。
- 前端应用前做轻量 Python EXP 结构校验。
- 后端保存和审核继续以 `pyexp.Validate` 为准。
- 不再生成或应用 EXP YAML。
- 不再使用 EXP 专属结构化补丁。

## 后续方向

- 保持 Python EXP 的原生自由度，持续改进 ctx SDK 的兼容便利能力。
- 增强 requirements 安装、缓存和哈希治理。
- 增强 HTTP trace、证据脱敏和执行审计。
- 完善 Agent 能力上报和 Python runtime 健康检查。
- 持续补充 Python EXP fixture 和端到端调试用例。
