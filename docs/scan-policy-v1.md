# 扫描策略 V1

`argus.scan-policy/v1` 是 Web、MCP、Copilot、Server 与 Agent 之间唯一的用户扫描配置契约。它只表达扫描意图，不暴露 Scanner 文件路径、反向布尔开关或任意 JSON。

## 预设

| 预设 | 端口 | 识别范围 | 自动风险验证 |
| --- | --- | --- | --- |
| `quick` | 常用协议端口集（common-100） | 被动子域、基础识别；安全行为探针关闭 | 关闭 |
| `standard` | Top1000 端口集（top-1000） | 被动子域、完整协议/Web/指纹；安全行为探针开启 | 开启 |
| `deep` | 1-65535 | 子域字典爆破（默认 2 层）、Host Binding、安全行为探针、主动路径指纹 | 开启 |

`common-100` 保持原 wire 名称，但内置集合已补入审核过的中间件与工控协议默认端口；`top-1000` 保持官方 Top1000 表不额外改写。预设的端口、扫描方式和强度不可局部覆盖；需要调整这些专家参数时使用 `custom`。能力清单可在预设默认值上显式开关，因此弱口令可在任一预设中主动开启。TCP 是默认方式，SYN 只有在 Agent 上报 `scan_syn=v1`（内置 Linux raw SYN）时可调度，并且严格使用策略中的端口集合。

## 端口扫描节奏（打散规避）

`pacing` 是可选的低调速（low-and-slow）选项，默认关闭；开启后同一目标两次端口探测保持最小时间间隔，把单个目标的端口探测摊到时间轴上，规避按 IP 速率阈值自动封禁的安全设备。它是与能力清单同级的显式用户选择，可在任一预设上叠加。

- `pacing.enabled`：开关；未设置或 `enabled=false` 时行为与现状完全一致。
- `pacing.interval_millis`：同一目标两次探测的最小间隔，范围 50–5000，缺省 500。TCP 方式下由 Agent 对每次连接尝试做精确 per-IP 间隔控制；SYN 方式下无原生 per-IP 节奏，按 `目标数×1000/间隔` 折算为 masscan 全局 `--rate` 并受原 SYN 速率上限约束。
- 吞吐预期：单目标扫完 N 个端口约需 N×间隔（500ms×100 端口 ≈ 50 秒/目标），多目标由不同执行流天然交错，聚合速率不降。
- 节奏参数纳入 resume/reuse 的配置哈希：同一目标在旧节奏下的历史覆盖不会被当作新节奏任务的可复用结果。

## 子域与 Web 指纹

子域发现分为默认开启的被动来源收集和可选的字典爆破。项目字典只能包含单层 DNS 标签，并以项目级不可变 Revision 与 SHA-256 绑定；执行时始终使用 `Scanner 内置字典 ∪ 项目增量字典 ∪ Agent 管理字典`，项目内容不能替换内置内容，也不能传入 Agent 文件路径。

字典爆破深度为 1–4 层，深度预设默认 2 层。第 1 层对根域爆破；后续层只对上一层真实解析成功的子域继续爆破，不会预先生成完整笛卡尔树。深度大于 1 的任务只会调度给声明 `subdomain_depth=v1` 的 Agent；绑定项目字典时还要求 `subdomain_dictionary=v1`。

Web 指纹分为响应指纹、安全行为探针和主动路径指纹，三者不能因为都使用 HTTP 请求而混用：普通响应的 Header、Body、Title 或状态即可识别的产品必须写入被动规则；访问确定的静态特征路径即可识别的产品必须写入路径探针；只有普通响应和静态路径都无法识别、必须构造一个安全输入并观察产品特有行为时，才允许写入行为探针。漏洞是否存在的验证始终属于 POC，不属于指纹识别。

行为探针在 HTTP 探测后运行，每个规范化 HTTP 服务端点对每条密封规则最多发送一次请求；它使用独立的 `active-fingerprints/*.yaml` Nuclei 模板，命中后产出 `Active-Finger`，不会直接创建漏洞。快速预设默认关闭，标准与深度默认开启。主动路径指纹仍由 `dir.yaml` 定义产品特征路径，不等同于向站点广播通用目录字典。路径是提问：命中必须靠与探测路径无关的标题、Cookie、产品 Header 或独特正文；被动 `finger.yaml` 里以路径字符串为证据的条款不得单独确认一次目录探测。有独立内容证据的目录命中写入 ResultMap 供 Workflow/POC 使用，但展示上不与自然页被动命中同等写成「已识别」。`dir-fallback` 只表示该路径值得看，不标记已识别、不调度 POC。

行为探针可以作为后续受控验证的精确信号，但不能直接挂载任意 POC。只有共享 GoPoc 治理目录中已审核、已启用并明确声明该 Nuclei 模板 ID 的漏洞检查，才会在已授权的风险验证阶段生成密封目标。例如 `shiro-detect` 命中后只记录 `APACHE-Shiro` 产品指纹，并可触发 `Shiro-Key-Crack`；它不会把 RuoYi、EasyReport 或 OneBlog 等产品专用 POC 泛化绑定到所有 Shiro 站点。

行为探针必须声明 `argus-behavior-kind: cookie|header|query`，并在对应 Cookie、自定义 `X-*` Header 或 Query 参数值中实际使用 `{{randstr}}`。缺少随机行为刺激的普通根路径或固定路径请求会被拒绝保存为行为探针，而不是降级为 `controlled`。这个机械校验只证明请求确实包含刺激；Admin 审核仍须确认该行为对识别产品是必要的，不能把已有被动或路径指纹重复搬入行为探针。

只有 Server 重新分类为自动安全的 HTTP/HTTPS 单请求 GET/HEAD 模板能进入普通任务：无 Body、Raw、Payload/Fuzz、OAST、Headless/Code、跨源跳转或危险 Header。具有有效行为刺激但超出自动安全范围的模板可以归类为 `controlled`，只允许在授权目标上显式调试。任务绑定规则版本、文件 SHA-256 和产品名；Agent 在执行前重新解析并核对，任何漂移都会失败关闭。每租户最多启用 8 条自动安全探针，Agent 必须声明 `behavior_probe=v1`。行为探针与 POC 开关相互独立，不会触发旧的通用 Shiro POC Workflow。

弹药库的“产品规则”页把 `finger.yaml`、`active-fingerprints/*.yaml`、`dir.yaml` 和 Workflow/POC 关联分开维护。每个行为探针是独立 Artifact，保存后进入 Draft；发布、废弃和回滚由 Admin 执行并记录精确版本、哈希和操作者。符合上述行为语义的完整 HTTP/HTTPS Nuclei YAML 可以保存并在授权目标上调试，但分类为 `controlled` 的模板必须显式确认风险，且永远不会因普通任务开启行为探针而被批量执行。旧自定义 Artifact 若缺少行为类型或随机刺激，将从可执行目录中失败关闭，须由维护者重新归类或修订；未修改的内置 Shiro 探针会自动升级。MCP 使用 `rule_type=behavior_probe` 走同一套读取、调试、保存和生命周期边界。

## 验证阶段

资产发现、风险验证和弱口令验证是同一 Root Task 下的独立阶段。后两者只消费资产发现产生的精确端点，不重新执行端口、协议或指纹扫描。

- 风险验证仅执行指纹 Workflow 绑定的、创建任务时已审核启用且哈希未漂移的规则。
- 弱口令验证仅接受 `host:port + service + credential plugin + observation hash` 的密封计划；HTTP/HTTPS 和非认证插件会被拒绝。
- POC 或弱口令任一开启时，策略必须包含一次统一的 `validation_confirmed=true`。

POC 与弱口令可以并行，但 Server 会从同一 Root 策略预算中切分目标并发和请求速率；两个阶段的分配之和不会超过预览中的总额度。风险验证按密封 Workflow 的请求估算设置硬上限，Agent 在下一次 HTTP/DNS 请求发出前拒绝超额执行，并关闭隐式重试。弱口令阶段的所有目标共享凭据尝试速率门和组合上限，不能因拆成多个目标而分别获得完整速率。

## 凭据字典

项目用户名本和密码本使用不可变 Revision 与 SHA-256 引用。Server 生成的增量组合与 Scanner 内置的服务字典取并集，用户内容不能关闭、覆盖或替换内置字典。每个服务目标默认最多 50,000 个组合，平台硬上限为 100,000。

Agent 不接受用户文件路径。弱口令任务只能由同时具备 `credential_validation=v1` 和 Server 认证的 `transport_tls=verified` 能力的 Agent 领取；Agent 本地也会拒绝在明文 gRPC 连接上执行该阶段。

Server 可保留原有明文端口供旧 Agent 执行资产扫描，并通过以下配置启用独立 TLS 监听：

```text
ARGUS_GRPC_TLS_PORT=50053
ARGUS_GRPC_TLS_CERT=/etc/argus/tls/agent-server.crt
ARGUS_GRPC_TLS_KEY=/etc/argus/tls/agent-server.key
```

Agent 使用 CA 校验连接：

```text
argus-agent --server server.example.internal:50053 \
  --grpc-ca /etc/argus/tls/agent-ca.crt \
  --grpc-server-name server.example.internal
```

TLS 只保护传输，既有 PSK、注册会话 Token、租户归属和任务授权检查仍然必须保留。

## Server 控制面

`POST /api/v1/tasks/plan-preview` 是唯一的语义策略编译入口。响应返回归一化策略、阶段 DAG、端口数、目标分类、发现/POC/弱口令各阶段的 Agent 容量、规则版本、请求估算和 `plan_hash`。创建任务时必须向 `POST /api/v1/tasks` 原样提交策略和 `plan_hash`；Server 会重新编译，任何目标、字典 Revision、规则版本或 Agent 约束变化都会返回 `scan_plan_changed`，不会执行陈旧授权。

项目字典接口只返回名称、类型、Revision、SHA-256 和数量。字典正文、生成的增量组合以及成功命中的完整证据均使用用途隔离的 AEAD 密钥保存：

```text
ARGUS_CREDENTIAL_ENCRYPT_KEY=<独立的 Base64 32 字节密钥>
```

生产模式缺少该密钥时 Server 拒绝启动。任务配置、队列与审计仅保存一次性 Bundle 的引用、哈希和数量；Agent 必须同时通过 CA 校验的 TLS、注册会话、Attempt 归属、有效期和一次消费检查后才能获取正文。普通任务结果接口仅返回遮罩用户名；只有 Admin 可调用显式 reveal 接口，且必须先成功写入揭示审计。

Agent 日志中的用户名和密码始终遮罩。成功凭据及会话证据只允许通过已认证 TLS 结果流送达 Server；凭据阶段不会把 GoPoc 展示文本镜像到 Agent 控制台或日志流。该日志策略不改变本地 CLI 的结果模型：CLI 的 JSON/HTML 报告仍保留完整的成功凭据，避免授权测试报告失去验证价值。

资产批次终结后，Server 持久化并幂等派生 `risk_validation` 与 `credential_validation` 子批次。重启时会重新协调仍为 pending 的 Intent；重复完成通知不会重复创建阶段。规则内容漂移时风险验证阶段安全跳过，不把创建任务之后的新规则扩入既有授权。失败的部分资产不阻止成功资产进入验证阶段，Root Task 最终以 `PartialDone` 表达未覆盖范围。

在最终 Web/MCP 产品入口切换前，历史 raw Scanner Config 和手动风险验证接口仅作为兼容路径保留；新语义任务的权威数据始终是 `argus.scan-policy/v1` Intent 和派生记录。
