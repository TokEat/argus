# Yaksha

Yaksha 是致敬并基于 Yaklang 语言核心构建的独立 EXP Runtime。它以内嵌 `antlr4yak` 解析器和 `yakvm` 虚拟机的常驻 Daemon 运行，预热 Worker 并为每次请求创建全新的 Engine、CliApp、Session 和 Resolver 上下文，同时通过 `yaksha.*` 扩展产品侧 EXP 能力。

Yaksha 不在语言层主动封禁 `include`、`go`、`eval`、格式化或作用域能力。Docker 运行配置提供非 root、只读根文件系统、无宿主挂载和资源限制；脚本网络能力只通过 Daemon Egress Connector，并同时要求精确目标授权与本次请求显式选择的出口。Agent 原生出口通过 Server 签发的单次 Route 和私有 Gateway 接入。

本模块为独立 Go module，**不加入 go.work**，避免 Yaklang 依赖图污染 Server/Scanner 模块（工作区会统一 `quic-go` 等共享依赖版本，导致 Yaklang 内部 HTTP/3 代码编译失败）。构建与测试需在 `GOWORK=off` 下进行。源码保持独立，生产发布包将 Yaksha 构建成独立 OCI 镜像并随 Compose 分发，不链接进 Server 或 Agent 二进制。

## 命名约定

| 对象 | 约定 |
| --- | --- |
| 产品与组件名 | `Yaksha` |
| 目录、Go module 末段、二进制 | `yaksha` |
| Yaklang 脚本能力命名空间 | `yaksha.*` |
| MCP 运行时地址 | `ARGUS_YAKSHA_URL` |

`EXP` 用于描述业务能力，`sidecar` 用于描述进程部署模式，不作为组件专有名称。Yaksha 不使用 `Argus` 作为脚本能力命名空间，以保持运行时边界独立。

## 构建

```bash
cd yaksha
GOWORK=off go build -o bin/yaksha ./cmd/yaksha
```

要求：Go 1.25+；依赖 CGO（PCRE2 via `go-pcre2-lite`），linux 构建需在带 gcc 的容器或环境执行：

```bash
docker run --rm -v "$PWD":/src -w /src golang:1.25-bookworm sh -c 'go build -ldflags="-s -w" -o bin/yaksha ./cmd/yaksha'
```

## 测试

```bash
cd yaksha
GOWORK=off go test ./...
```

`TestMain` 会先构建真实二进制再跑协议级集成测试（首次较慢，之后走构建缓存）。

## 常驻 Docker Runtime

```bash
docker compose -f yaksha/compose.yaml up -d --build
curl -fsS http://127.0.0.1:8790/readyz
```

官方 Compose 使用 host network，但 Yaksha 仍只监听 `127.0.0.1:8790`。这样容器可访问同机
Server 仅监听回环的 Egress Gateway，同时 Yaksha 和 Gateway 都不会发布到公网；非 Linux
Docker Desktop 环境只用于本地 Runtime smoke，Agent relay 的生产拓扑应使用 Linux 主机。

容器使用 host network，但进程只监听宿主回环的 `8790`；默认预热 2 个 Worker、队列 32，每个 Worker 处理 100 次请求后先补充新 Worker 再平滑退出。容器使用非 root、只读根文件系统、`cap-drop=ALL`、`no-new-privileges`、64 PIDs、2 CPUs、1 GiB 内存、128 文件描述符和 32 MiB `noexec/nosuid/nodev` tmpfs，且没有宿主目录挂载。

已验证语法、运行时、协议和待补能力见 [COMPATIBILITY.md](./COMPATIBILITY.md)。该矩阵以当前锁定的 Yaklang 版本和 Yaksha 测试为准，不把 Yaklang 文档声明直接等同于当前依赖版本已经实现。

## 协议

控制面使用 `POST /v1/execute`，健康检查使用 `GET /healthz` 和 `GET /readyz`。请求上限 4 MiB、响应上限 2 MiB；队列满返回 HTTP 429，Daemon 不自动重试 EXP。MCP 取消 HTTP 请求或请求超时后，Daemon 会终止并补充对应 Worker。

内部 Worker 和无参数诊断模式继续使用一行一个 JSON 对象的 stdin/stdout 协议。`action` 支持 `inspect`、`validate`、`run`、`debug` 和 `test`；省略时保持兼容并按 `run` 处理：

```json
{"id":"exec-1","action":"run","script":"target = cli.String(\"target\", cli.setRequired(true)); cli.check(); yaksha.result(target)","params":{"target":"authorized.invalid"},"timeout_ms":15000,"exp_id":"exp-demo","revision":3,"source_sha256":"<main.yak 的小写 SHA-256>"}
{"id":"exec-1","action":"run","status":"Succeeded","context":{"exp_id":"exp-demo","revision":3,"source_sha256":"<实际源码 SHA-256>"},"result":"authorized.invalid","validation":{"valid":true,"source_sha256":"...","checks":["source","parameters","execution_limits"],"diagnostics":[]},"logs":[]}
```

状态：`Succeeded` / `Failed` / `Timeout` / `Canceled` / `InternalError`。Yaksha 负责 VM 超时；MCP 在该超时之外增加 5 秒 HTTP 控制器兜底并通过 Context 取消请求。

### Resolver、Compose 与 Asset

- `inspect` 静态提取字面量 `yaksha.call("exp-id", revision, params)` 与 `yaksha.asset("asset-id")`；动态引用作为契约诊断返回。
- `validate/run/debug/test` 接收扁平化依赖闭包 `dependencies[]` 与 `assets[]`，在执行前验证缺失、重复、未引用、哈希、Revision、环、大小和调用预算。
- `yaksha.call` 为子 EXP 创建独立 VM 与 CLI 参数，返回 `result, error`；完整结果、Validation、日志、Evidence、错误和嵌套调用保存在父响应 `calls[]` 对应节点中，不自动并入父节点。
- `yaksha.asset` 返回按 `utf8|base64` 解码后的内容，SHA-256 针对解码后的原始内容计算。
- 固定上限：16 个依赖、32 个 Asset、单项 1 MiB、深度 8、顶层请求最多 32 次子调用。

### 网络出口

`network_targets[]` 是精确的 `http://host:port`、`https://host:port` 或 `tcp://host:port` 授权；路径和 Query 不参与授权。出口是单次顶层 `run/debug` 的运行上下文，不进入 EXP Revision；未传 `egress` 等同于 `disabled`：

```json
{"egress":{"mode":"disabled"}}
{"egress":{"mode":"direct"}}
{"egress":{"mode":"socks5","socks5_proxy":"socks5://user:password@proxy.example:1080"}}
```

`relay + route_id` 是可信控制面专用的 Yaksha 内部契约；未配置 Provider 时明确返回 `Agent Egress Unavailable`，MCP/MCP App 不直接暴露该模式。不同模式互斥，出口失败不自动回退到 direct、SOCKS5 或其他节点，也不存在 Daemon 默认代理环境变量。

Daemon 的统一原始 TCP Connector 为 direct 与 SOCKS5 解析目标 DNS、拒绝 unspecified、multicast、loopback、link-local 和已知云元数据地址，并把允许的解析 IP 固定到本次连接；精确声明的普通私网地址可用。HTTP、TLS、重定向复检、正文边界和未脱敏 Trace 仍由 Yaksha 管理。每次 HTTP 重定向都重新检查 `network_targets` 并建立连接；子 EXP 共享顶层出口、目标、deadline 和连接预算。

`socks5_proxy` 是 write-only 传输秘密：Daemon 在进入 Worker 前删除，响应、Trace、日志和错误不回显 Raw URL。每个顶层请求最多建立 32 次原始连接，子 EXP 与 HTTP 重定向共享该预算。`inspect` 只分析源码，`validate` 只校验出口形状，只有 `run/debug` 可能建立真实连接；`test` 无条件断网，Fixture 未匹配即失败。

`exp_id`、`revision`、`source_sha256` 是可选的不可变 Revision 绑定，出现任意一个时必须三者同时提供。Yaksha 会重新计算当前 `script` 的 SHA-256；不匹配时拒绝执行。只要请求包含源码，响应的 `context.source_sha256` 都来自实际源码，即使请求校验失败也可用于定位版本。未绑定的内存源码仍可直接 inspect、validate、test、debug 和 run。

### 静态 inspect

`inspect` 只使用 Yaklang ANTLR 语法树读取源码，不编译或执行脚本。它返回源码 SHA-256、字节数、行数、参数 Schema 和带位置的诊断，供后续 Server/MCP App 渲染声明式参数 UI：

```json
{"id":"inspect-1","action":"inspect","script":"target = cli.String(\"target\", cli.setRequired(true)); cli.check()"}
{"id":"inspect-1","action":"inspect","status":"Succeeded","inspection":{"valid":true,"source_sha256":"...","source_bytes":65,"source_lines":1,"parameters":[{"name":"target","type":"string","required":true,"has_default":false}],"diagnostics":[]}}
```

V1 inspect 契约：

- 参数类型：`cli.String/Text/Int/Integer/Float/Bool/StringSlice`。
- UI 选项：`cli.setRequired/setDefault/setHelp/setVerboseName/setCliGroup/setSelectOption/setMultipleSelect`。
- 参数名和 UI 配置必须是字面量；参数声明必须位于顶层、处于唯一的顶层 `cli.check()` 之前。
- 语法或契约不合格时，请求本身仍返回 `Succeeded`，由 `inspection.valid=false` 和 `diagnostics` 表达源码问题；协议或运行时自身故障才使用错误状态。

### validate 与参数绑定

`validate` 对同一份源码执行 inspect 契约检查，再验证请求参数的必填项、未知字段、数据类型和下拉选项，同时检查协议资源限制，不启动 VM：

```json
{"id":"validate-1","action":"validate","script":"target = cli.String(\"target\", cli.setRequired(true)); cli.check()","params":{}}
{"id":"validate-1","action":"validate","status":"Succeeded","validation":{"valid":false,"source_sha256":"...","checks":["source","parameters","execution_limits"],"diagnostics":[{"severity":"error","code":"missing_required_parameter","message":"required parameter \"target\" is missing","field":"target"}]}}
```

校验响应不会回显参数值。`run` 会强制执行相同预检，失败时不进入 VM；通过后为该请求创建独立的官方 Yaklang `CliApp`，把 JSON 参数转换为 CLI 参数并只注入 V1 白名单函数。这样同一份 `main.yak` 已形成 `inspect → validate → run` 闭环，且不存在全局 CLI 参数跨请求泄漏。

### debug

`debug` 用来测试、排查一份 Yaklang EXP。它复用 run 的预检、CLI 参数绑定和超时边界，但额外采集能力调用 Trace：

```json
{"id":"debug-1","action":"debug","script":"target = cli.String(\"target\"); cli.check(); yaksha.log(target); yaksha.result(false)","params":{"target":"authorized.invalid"}}
```

调试响应继续使用普通 `result`、`logs`、`evidence`、`error` 和状态字段；`debug.events` 额外记录：

- `yaksha.httpGet` 与 `yaksha.dial` 的有界事件，包括完整目标、耗时、HTTP 状态码和原始错误。
- debug 不做内容脱敏或字段截断，避免排障时遗漏 Query、地址或错误细节；只限制事件数量和协议响应总大小。

V1 不实现 Yaklang 语言级断点、单步、变量修改或暂停 VM。AI 查看一次 EXP 调试执行的结果、日志和 Trace，修改源码后以新源码哈希重新发起 validate/debug，即构成远端 EXP 调试闭环。

debug 结果可能包含敏感请求信息，后续 Server/MCP 必须通过租户授权、对象级权限和审计控制访问；Yaksha 不在诊断数据中猜测并删除内容。

### test

`test` 对同一份 Yaklang EXP 顺序执行最多 32 个用例。每个用例包含独立参数、可选 HTTP/TCP Fixture 和结构化期望：

```json
{
  "id": "test-1",
  "action": "test",
  "script": "target = cli.String(\"target\"); cli.check(); value, err = yaksha.httpGet(target); if err != nil { panic(err) }; yaksha.result(value)",
  "test_cases": [
    {
      "id": "fixture-success",
      "params": {"target": "http://fixture.invalid/probe"},
      "fixture": {"http": [{"method": "GET", "url": "http://fixture.invalid/probe", "status_code": 200, "body": "ok"}]},
      "expect": {"status": "Succeeded", "result": "200 ok"}
    }
  ]
}
```

断言支持状态、完整 JSON 结果、Evidence 子集、日志包含文本和错误包含文本。顶层响应表示测试请求是否被正确处理；每个用例用 `passed` 和 `assertion_failures` 表示验收结果。

test 始终启用 Fixture 模式：没有匹配 Fixture 的 HTTP/TCP 调用直接失败，不会回退访问真实网络。`timeout_ms` 是整批用例共享的总预算，避免用例数放大执行时间。Fixture 运行同样返回完整 Trace，不做 debug 内容脱敏。

## Argus MCP 直连

部署侧通过 `ARGUS_YAKSHA_URL` 指向 Yaksha Daemon，默认 `http://127.0.0.1:8790`。MCP 启动时检查 `/readyz`，运行时直接 POST `/v1/execute`，不启动子进程也不自动重试。`argus_yaksha_exp` Tool 接收 `script`、`params`、`test_cases`、密封 Resolver、网络目标与本次 `disabled|direct|socks5|agent` 出口；可选携带必须成组出现的 `exp_id`、`revision`、`source_sha256`。SOCKS5 密码输入不会由 MCP App 回填。
Tool 不接受二进制路径、命令参数或宿主文件路径。`agent` 模式只允许 `run/debug`，要求明确 `agent_id` 与 `risk_confirmed=true`；MCP 向 Server 申请单次 Route 后只把内部 `relay + route_id` 交给 Yaksha，结束时撤销 Route，不自动重试或回退。

Agent 原生出口使用独立 `EgressTunnel` 双向流，不复用任务 `Subscribe`，也不运行 SOCKS5 服务。Server 私有 Gateway 通过 `ARGUS_EGRESS_GATEWAY_LISTEN` 与必填 `ARGUS_EGRESS_GATEWAY_TOKEN` 启用；Yaksha 使用 `YAKSHA_RELAY_ADDR` 与 `YAKSHA_RELAY_TOKEN` 连接。Token 仅存在于 Server/Yaksha Daemon，不进入 Worker、脚本、日志或 Trace。

支持 MCP Apps 的 Host 可读取 `ui://argus/exp-console`；不支持的 Host 仍能从
Tool 的文本结果和 `structuredContent` 获得相同数据。debug 的完整 Trace 原样
返回，不在 MCP 层增加脱敏或字段截断。EXP Console 会展示当前绑定身份，并在交互调用中继续携带该身份；若用户编辑了绑定源码而未生成新哈希，Yaksha 将拒绝以旧 Revision 身份执行。

## 注入函数（第一版最少集，`yaksha.*` 命名空间）

| 函数 | 说明 |
| --- | --- |
| `log(v)` | 追加日志行 |
| `result(v)` | 设置最终结果 |
| `evidence(key, v)` | 写入 evidence |
| `toString(v)` | 任意值转字符串 |
| `echo(v)` | 原样返回（调试） |
| `httpGet(url)` | GET，返回 `状态码 响应体` |
| `dial(address)` | 通过 Daemon 校验目标并经本次显式出口执行 TCP CONNECT |
| `call(exp_id, revision, params)` | 调用密封包中锁定 Revision 的子 EXP |
| `asset(asset_id)` | 读取密封包中按哈希校验的逻辑 Asset |
| `b64encode(s)` / `b64decode(s)` | Base64 |
| `md5(s)` / `sha256(s)` | 摘要（hex） |
| `jsonDumps(v)` / `jsonLoads(s)` | JSON 编解码 |
| `regexMatch(pattern, s)` | 正则匹配 |

## 路线

- 切片 A：语言核心、五动作、Resolver、Compose、Asset、调用树和 Fixture test 已完成。
- 切片 B：常驻 Daemon、预热 Worker、HTTP MCP/MCP App、统一 Egress Connector、disabled/direct/SOCKS5 与 OCI 隔离已完成，不改 Server。
- 切片 C1：Agent 原生 TCP Egress 已接入。Server 校验租户、EXP 权限、风险确认和在线 Tunnel 后签发单次 `route_id`；Yaksha 只消费内部 relay 契约，出口无自动回退。
- 切片 C2：Server Revision 存储、Asset、Fixture、权限、审计和发布已完成，生产对象存储为私有 MinIO。
- 切片 D：Server Web UI 与 MCP App Workspace 已完成，旧 EXP 双栈产品路径已原子移除，AI 生成单文件 Yaklang EXP。
