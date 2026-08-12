# Yaksha 纵向开发目标

## Goal

建立两条相互衔接的纵向闭环：第一条由 Yaksha 完成 EXP 的解析、校验、执行和诊断；第二条由 Argus MCP 与一个通用 MCP App 为 AI 提供远端 EXP 编写、测试、调试和发布控制面。AI 不接触 Server/Yaksha 文件系统。

## 核心模型

- 一个 EXP 的权威形态是“少量治理元数据 + 一个带版本的 Yak 源码”。
- Yak 源码同时包含官方 `cli.*` 参数声明和执行逻辑，不增加 Manifest、文件树或自定义包格式。
- AI 不接触 Server/Yaksha 文件系统，也不直接连接 Yaksha；唯一入口是 MCP。
- Published Revision 不可变；测试、调试和执行始终绑定确定的 Revision 与源码哈希。
- 复杂能力通过锁定版本的子 EXP 编排；大型 Payload、字典和样本通过 Asset ID 引用。
- 保持 Yaklang 原生语言能力，安全边界由远端运行环境的权限、网络和资源隔离承担。
- 网络授权与出口分离：`network_targets` 决定允许访问的精确目标，调用方为单次运行显式选择 `disabled/direct/socks5`；未来 Agent 通过原生 TCP relay 提供节点出口，不充当 SOCKS5 服务。

## EXP V1 结构

EXP 是 Server 中的逻辑对象，不是 AI 可见的文件目录。其概念结构如下：

```text
Exp
├── metadata                 # id、tenant、名称、描述、风险等级和状态
├── revisions
│   └── <revision>
│       └── main.yak         # 唯一权威源码
├── dependencies             # 锁定到子 EXP 的确定 Revision
├── asset_refs               # Payload、字典和样本的逻辑 ID
├── test_cases               # Server 管理的 Fixture/验收用例
└── runs                     # 执行、调试和审计记录
```

V1 不定义 Manifest、多文件源码目录或 `.yakexp` 包。`main.yak` 是唯一源码；上述其他内容均由 Server 作为结构化数据管理。Yaklang 仍保留 `include` 等语言能力，但可发布 EXP 不依赖宿主本地文件；复杂源码通过子 EXP 编排，外部数据通过 Asset 引用。

## main.yak 标准

源码按“参数声明 → `cli.check()` → 函数与执行逻辑 → 结构化结果”组织：

```yak
target = cli.String(
    "target",
    cli.setVerboseName("目标地址"),
    cli.setHelp("授权测试目标"),
    cli.setRequired(true),
)

timeout = cli.Int(
    "timeout",
    cli.setDefault(10),
    cli.setCliGroup("执行配置"),
)

verifyOnly = cli.Bool(
    "verify_only",
    cli.setDefault(true),
)

cli.check()

// EXP logic
yaksha.result({
    "vulnerable": false,
    "message": "not vulnerable",
})
```

约定：

- 参数使用官方 `cli.String/Text/Int/Integer/Float/Bool/StringSlice` 声明；UI 信息使用 `setRequired/setDefault/setHelp/setVerboseName/setCliGroup/setSelectOption/setMultipleSelect`。
- CLI 声明位于顶层并使用字面量配置，`cli.check()` 只出现一次，使远端 `inspect` 可以稳定生成 UI Schema。
- 协议状态表示脚本是否成功执行；业务判断统一由 `yaksha.result` 返回对象表达，漏洞类 EXP 至少包含布尔字段 `vulnerable`。
- 过程证据写入 `yaksha.evidence`，诊断信息写入 `yaksha.log`，不要把凭据、Cookie 或完整敏感响应写入结果和日志。
- 子 EXP 使用 `yaksha.call(exp_id, revision, params)`，必须锁定 Revision；资源使用 `yaksha.asset(asset_id)`，不接受宿主文件路径。
- 发布后的 Revision 不可修改；AI 修改源码时生成新 Revision，并重新执行 inspect、测试和调试。

## 第一条纵向闭环：Yaksha EXP Runtime

1. `inspect`：解析 Yak 源码，返回语法诊断、官方 `cli.*` 参数 Schema 和源码摘要。
2. `validate`：校验参数、运行时能力、依赖引用和执行限制，不产生真实副作用。
3. `run`：输入源码、参数、执行上下文和资源限制，返回结构化结果、日志、Evidence 与 Trace。
4. `debug`：对单个 Yaklang EXP 及一组参数做诊断执行，返回结果、日志、Evidence、错误及 HTTP/TCP Trace，供 AI 修改源码后重试；不设计语言级断点会话。
5. `test`：使用调用方提供的 Fixture 和断言运行 EXP，返回逐用例结果与可复现诊断。

扩展边界：

- `compose`：通过受控 Resolver 调用锁定版本的子 EXP，不由 Yaksha 管理 Revision。
- `asset`：通过受控 Resolver 读取 Asset 内容，不向脚本暴露宿主路径。
- `exp_id`、Revision 和源码哈希仅作为执行上下文与 Trace 标识传入；其存储、状态、权限和发布由 Server 管理。

当前闭环已完成：常驻 HTTP Daemon、预热 Worker、每请求全新 VM/CLI/Session、密封依赖与 Asset Resolver、调用树、Fixture-only test、未脱敏 debug Trace、精确目标授权、统一原始 TCP Connector、每请求 disabled/direct/SOCKS5 出口、预留 relay 契约、Worker 回收和 OCI 运行隔离。默认禁网、出口故障不回退、SOCKS5 Raw URL 不进入 Worker 或输出。Server 中的 Revision 存储、权限、审计和发布仍未接入。

## 第二条纵向闭环：MCP EXP Workspace

- Argus MCP 使用 Go SDK `v1.7.0` 和 MCP `2026-07-28` Stateless/Sessionless 协议，对外提供 EXP 的读取、创建 Revision、inspect、Fixture 测试、debug、run 和发布工具。
- 第一阶段由 MCP 通过 `ARGUS_YAKSHA_URL` 调用常驻 Yaksha HTTP Daemon；Daemon 复用 Worker，但每次执行创建全新 VM。MCP 不改 Server，也不把宿主路径暴露给 AI。
- 第一阶段已支持可选的 `exp_id + Revision + source_sha256` 成组绑定；Yaksha 按实际源码复算哈希并在全部响应中返回执行上下文，防止 MCP App 把已编辑源码误当作原 Revision 执行。
- 第二阶段再把相同 Tool 契约绑定到 Server 管理的 EXP、Revision、TestCase 和 Run；发布仍只针对确定 Revision 并要求人工确认。
- 提供一个通用 `ui://argus/exp-console` MCP App，不为每个 EXP 创建独立 App；它根据 Yaksha 返回的 CLI Schema 渲染参数表单，并展示源码、诊断、日志、Evidence、Trace 和结构化结果。
- AI 通过 MCP Tool 读写 EXP 逻辑对象，MCP App 通过同一组受控 Tool 完成交互；两者都不获得 Server/Yaksha 文件路径或任意文件系统能力。
- 每次修改生成新的 Draft Revision；测试、调试、比较和发布都携带 `exp_id`、Revision 与源码哈希，避免覆盖已发布源码或调试错版本。
- 不支持 MCP Apps 的客户端仍通过 Tool 的文本与 `structuredContent` 完成相同闭环；MCP App 只增强交互，不成为执行和治理的权威来源。
- MCP 层保留租户隔离、对象级授权、草稿优先、发布确认和审计；Yaksha 只负责语言运行时，不承担用户身份与治理状态。
- MCP Tool 与 EXP Console 可携带密封依赖、Asset、精确网络目标和本次 `disabled/direct/socks5` 出口；SOCKS5 Raw URL 为 write-only，只用于 Daemon 连接，不进入 Yaklang Worker、调用树或调试输出，也不由 App 回填。
- 后续 Agent 原生出口使用独立多路复用 gRPC 双向流，不复用任务 `Subscribe`，也不套 SOCKS5。Server 绑定租户、Agent、deadline、目标和预算后签发单次 `route_id`；Yaksha 只接收内部 `relay + route_id`，Agent 在自己的网络环境解析并固定目标 IP。当前切片不修改 Server、Agent 或 shared proto。

## 验收目标

AI 能仅通过 MCP/MCP App 完成：创建单文件 EXP → 解析并渲染 CLI UI → 修复语法问题 → Fixture 测试 → 交互调试 → 执行验证 → 查看结构化结果 → 生成新 Revision → 人工确认发布。整个流程不依赖 AI 可见的本地文件系统，也不需要多文件 EXP 包。
