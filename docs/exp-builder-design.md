# EXP Builder 设计

当前 EXP Builder 只面向 Python EXP。旧的 Argus EXP YAML、Nuclei runtime、Starlark runtime 和结构化补丁链路已经退役，不再作为实现或规划依据。

## 当前目标

Builder 的职责是帮助用户把漏洞理解材料整理给 AI Copilot，并生成可审核的单文件 Python EXP。最终保存、审核、调试和执行的唯一内容来源是 `arsenals(type=exp).content` 中的 `.py` 内容。

## Python EXP 合同

每个 EXP 是一个 Python 文件，必须包含：

- `ARGUS_EXP` dict：声明 `id`、`name`、`risk_level`、`policy`、`params`、`requirements` 等元数据。
- `run(ctx)` 或 `main()`：执行入口。
- `cleanup(ctx)`：可选清理入口；`cleanup_required=True` 时必须存在。
- `argparse` 参数定义：推荐作为 CLI-first 参数主合同，平台会推断参数 schema。
- `main()`：推荐保留本地 CLI 验证入口。

`policy.capabilities` 仅作为 UI 展示和审核辅助元数据，不作为运行时能力管控边界。常见展示值包括：

- `evidence.write`
- `cleanup.defer`
- `result.write`

## AI 生成链路

1. 用户在 EXP 页面新建或编辑 `.py` 文件。
2. 点击 `AI 生成 Python`，前端向 Copilot 提供当前 Python 草稿、文件名、基础元信息、产品候选和用户材料。
3. Copilot 只返回 fenced `python` 代码块。
4. 前端执行轻量 Python EXP 校验，通过后应用到 Monaco Python 编辑器。
5. 用户保存草稿，后端通过 `pyexp.Validate` 做最终保存/审核校验。

AI 输出不再接受 EXP YAML，也不再接受 EXP 专属结构化补丁。

## 前端边界

- 新增 EXP 文件名必须是 `.py`。
- 编辑器语言固定为 Python。
- `canApplyContent` 只接受带 `ARGUS_EXP` 且定义 `run(ctx)` 或 `main()` 的 Python 内容。
- YAML 或其他非 Python 内容不做专门语义识别，会按缺少 `ARGUS_EXP` 或入口函数的普通 Python EXP 校验失败处理。

## 后端边界

- `saveArsenal(type=exp)` 要求文件名以 `.py` 结尾，并调用 `validateExpPackage(content, false)`。
- `approveArsenal` 和 EXP 审核调用严格校验 `validateExpPackage(content, true)`。
- `materializeExploitRule` 只通过 `pyexp.ParseTemplate` 解析 Python EXP 元数据。
- `exploit.Engine` 只执行 Python EXP，并通过 Agent 本地 Python 子进程运行。

## 数据模型

`exploit_rules` 是从 Python EXP 物化出的检索表。核心字段包括：

- `rule_id`
- `name`
- `risk_level`
- `target_product`
- `params_schema`
- `requirements`
- `requirements_hash`
- `sandbox_profile`
- `runtime_engine = python`

原始 Python 文件始终保存在 `arsenals(type=exp).content`，用于版本回滚、导出迁移和审核。

## 维护原则

- EXP 主链路不再新增 YAML 分支。
- 新能力应优先扩展 `pyexp` 元数据、Python SDK 或 Agent Python 执行器。
- 旧 YAML fixture、Nuclei/Starlark 执行器和相关 UI 状态不应重新引入到 EXP 主路径。
