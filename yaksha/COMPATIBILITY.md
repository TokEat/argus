# Yaksha EXP Runtime 兼容矩阵

本文件记录 Yaksha 在当前锁定 Yaklang 版本上的实际测试边界。只有进入自动化测试的行为才标记为“已验证”；Yaklang 上游文档声明但当前依赖未实现或 Yaksha 尚未测试的能力，不视为已验证契约。

## 已验证的 Yaklang 语法

| 类别 | 场景 |
| --- | --- |
| 基础表达式 | 整数、浮点、布尔、`nil`、算术、比较、逻辑和运算符优先级 |
| 控制流 | `if/else`、经典 `for`、`range`、`break`、`continue`、`switch/case/default` |
| 数据结构 | 动态数组、负数索引、Map、成员访问、类型化 Slice/Map 字面量 |
| 函数 | `func/fn`、闭包、高阶函数、箭头函数（声明式 + 函数体）、递归、返回值、`go` 异步调用 |
| 异常 | `try/catch/finally`、`panic`；运行错误和编译错误转换为结构化失败 |
| 字符串 | Unicode、字符串遍历、模板字符串、拼接 |
| 代码组织 | `include` 本地 Yak 文件、`eval` 动态代码 |
| 开发与反射 | `yakfmt`、`yakfmtWithError`、`getScopeInspects`、`getFromScope` |
| 输入输出 | `params` 注入、`yaksha.result`、有界日志和 evidence |

`double` 等类型关键字属于保留字，不能作为脚本变量名；兼容测试会固定这一解析行为。

## 已验证的能力函数

| 能力 | 已覆盖场景 |
| --- | --- |
| HTTP GET | 状态码、响应正文、执行超时取消、1 MiB 正文上限 |
| TCP dial | 本地成功连接、连接失败返回脚本可处理的错误 |
| Base64 | 编解码、非法输入错误 |
| 摘要 | MD5、SHA-256 十六进制输出 |
| JSON | 编解码和非法 JSON 错误 |
| 正则 | 正常匹配和非法表达式错误 |
| 协议 | JSON Lines、多请求复用、畸形请求后恢复、ID 关联、请求/响应大小上限 |
| 生命周期 | VM 超时、HTTP 取消、单进程连续处理多条请求、畸形请求后继续服务 |
| 声明式执行 | 同一源码 `inspect → validate → run`、独立 `CliApp`、JSON 参数到官方 CLI 类型绑定 |
| EXP 调试 | 单次诊断执行、结果、日志、Evidence、错误及完整 HTTP/TCP 事件 |
| Fixture 测试 | 多用例参数、HTTP/TCP Fixture、状态/结果/Evidence/日志/错误断言、批次总超时 |
| Resolver | 字面量依赖/Asset 提取、哈希、缺失/重复/未引用、环、base64、大小与调用预算 |
| Compose | 独立子 VM、嵌套成功/失败、父级错误处理、调用树、日志/Evidence 隔离 |
| 常驻 Daemon | HTTP 健康/就绪、预热 Worker、顺序复用、平滑回收、请求/响应边界 |
| 多出口 Egress | 默认 disabled、显式 direct/SOCKS5、模式互斥、固定 IP、特殊地址拒绝、重定向复检、无自动回退、relay 未配置错误 |

## 已验证的声明式 CLI inspect

`inspect` 是纯语法树路径，不执行 EXP 源码。自动化测试已经固定以下行为：

| 类别 | 已验证范围 |
| --- | --- |
| 参数类型 | `cli.String`、`Text`、`Int`、`Integer`、`Float`、`Bool`、`StringSlice` |
| UI 元数据 | `setRequired`、`setDefault`、`setHelp`、`setVerboseName`、`setCliGroup` |
| 选择控件 | `setSelectOption`、`setMultipleSelect`，且只允许用于 `StringSlice` |
| 静态约束 | 顶层字面量声明、声明位于 `cli.check()` 之前、唯一顶层 `cli.check()`、参数名去重、默认值类型检查 |
| 诊断 | Yak 语法错误、非字面量配置、V1 未支持类型/选项、行列位置 |
| 无副作用 | 被检查源码包含 `panic` 仍可完成 inspect，证明该路径未执行源码 |

V1 有意不解析上游所有 CLI 控件。未列出的参数类型、`cli.UI` 联动规则和其他 `cli.set*` 选项会返回明确的不兼容诊断，而不是静默丢失后交给 Server 错误渲染。

## 已验证的 validate 与 run 绑定

- `validate` 不执行源码，校验必填参数、未知参数、字符串、文本、整数、浮点数、布尔值、字符串列表和选择项范围。
- 校验诊断关联参数字段，但不回显参数值；源码诊断继续保留行列位置。
- `run` 在启动 VM 前强制执行相同校验，校验失败的脚本逻辑不会运行。
- 每次 `run` 创建独立的上游 `CliApp`，只暴露 V1 参数和 UI 选项，不使用 Yaklang 全局默认 CLI 实例。
- `cli.Bool` 的声明默认值由 Yaksha 参数绑定层落实，以弥补当前上游 `Bool` 不读取 `setDefault` 的行为差异。
- `StringSlice` 请求值接受逗号分隔字符串或 JSON 字符串数组；源码默认值遵循上游 CLI 约定，使用逗号分隔字符串。

## 已验证的 EXP debug

- `debug` 对单个 EXP 做一次完整诊断执行，沿用 `Succeeded/Failed/Timeout`、结构化结果、日志和 Evidence。
- 调试运行与普通 run 使用相同的 inspect、参数校验、独立 `CliApp` 和超时边界，不允许绕过发布契约。
- HTTP/TCP 调试事件保留完整目标、状态码和原始错误，不做脱敏或字段截断，避免遗漏排障依据。
- Trace 只限制事件数量和协议响应总大小；访问控制、审计与敏感信息治理由后续 Server/MCP 层承担。
- 修复与重试通过新的源码请求完成，不保留远端 VM 会话。

## 已验证的 Fixture test

- 单次请求可针对同一份源码顺序执行多组参数，每个用例返回状态、结果、日志、Evidence、Trace 和断言失败列表。
- 断言支持预期状态、完整 JSON 结果、Evidence 指定字段、日志子串和错误子串；数字比较经过 JSON 归一化。
- HTTP GET Fixture 可模拟状态码、正文和失败；TCP Fixture 可模拟连接成功、远端地址和失败。
- test 一律 fail closed：Fixture 缺失或目标不匹配时返回明确错误，不会访问真实网络。
- 用例 ID、数量、参数大小、Fixture 数量/正文、重复路由和期望状态均在执行前校验。
- 整批用例共享 `timeout_ms` 总预算，后续用例只能使用剩余时间。

## Yaklang 原生能力原则

Yaksha 不在源码入口对 Yaklang 原生语法和上下文内建函数做主动封禁。当前已通过自动化测试确认：

- `include` 可以加载本地 Yak 文件。
- `go` 与 `waitAllAsyncCallFinish` 可以执行并等待异步任务。
- `eval` 可以在当前作用域动态执行代码。
- `yakfmt`、`yakfmtWithError` 可以格式化和检查源码。
- `getScopeInspects`、`getFromScope` 可以检查和动态读取作用域。

当前锁定的 Yaklang `v1.4.8-beta9` 存在一个上游兼容缺口：Lexer 和上游 README 声明了 `importmod`，但实际 `antlr4yak` Parser 不接受该语句。它不是 Yaksha 策略关闭项，需要通过依赖升级或上游修复恢复。

未注入的完整 Yaklang 标准库、安全库和系统库属于尚未接线的宿主能力，不视为语言禁用。后续应建立实际 EXP 脚本语料库，按兼容需求补齐，而不是按安全理由逐项关闭。

## 当前仍未完成

以下项目不能仅靠语言级测试宣称完成，需要后续切片实现和独立验收：

- OCI 配置已覆盖内存、CPU、文件描述符、PID、capabilities、只读根文件系统、无宿主挂载和临时目录；仍需在目标 Linux amd64/arm64 发布环境持续验证实际 seccomp 与 cgroup 行为。
- 当前每请求 `disabled/direct/socks5`、write-only SOCKS5 URL 和内部 `relay` 占位契约已完成；Agent 原生多路复用 TCP Egress、Server 单次 Route 授权、租户绑定和 Agent 在线状态仍待后续切片接入。Agent 不提供 SOCKS5 服务。
- 完整 HTTP 请求：方法、Header、Body、Cookie、重定向策略、TLS 策略和原始报文证据。
- TCP 收发、二进制载荷、分段读取、半关闭和 UDP；当前 `dial` 只验证连接可达性。
- AES/RSA/HMAC、Hex、URL 编解码、字节数组转换等常见 EXP 辅助能力。
- Server 适配和治理审计仍未完成；HTTP Context 取消已能回收 Worker，但尚无独立业务 Cancel ID API。
- V1 不提供语言级断点、step-in、step-over、变量修改或长期暂停 VM；这些不属于当前 EXP 调试目标。
- Worker 池、进程级 kill、100 次复用上限和健康检查已完成；多租户公平调度与持续失败指数退避仍待 Server 接入阶段设计。
- Yaklang 版本升级兼容矩阵、脚本版本声明和弃用策略。
- Linux amd64/arm64、macOS arm64 和 Windows 的 CGO/PCRE2 构建与运行验证。

## 回归入口

```bash
cd yaksha
GOWORK=off go test ./...
```
