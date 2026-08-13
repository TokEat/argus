# 扫描策略 V1

`argus.scan-policy/v1` 是 Web、MCP、Copilot、Server 与 Agent 之间唯一的用户扫描配置契约。它只表达扫描意图，不暴露 Scanner 文件路径、反向布尔开关或任意 JSON。

## 预设

| 预设 | 端口 | 识别范围 | 自动风险验证 |
| --- | --- | --- | --- |
| `quick` | 常用 100 | 被动子域、基础识别 | 关闭 |
| `standard` | Nmap TCP Top 1000 | 被动子域、完整协议/Web/指纹 | 开启 |
| `deep` | 1-65535 | 子域字典爆破（默认 2 层）、Host Binding、主动路径指纹 | 开启 |

预设的端口、扫描方式和强度不可局部覆盖；需要调整这些专家参数时使用 `custom`。能力清单可在预设默认值上显式开关，因此弱口令可在任一预设中主动开启。TCP 是默认方式，SYN 只有在 Agent 上报 `scan_syn=v1` 时可调度，并且严格使用策略中的端口集合。

## 子域与 Web 指纹

子域发现分为默认开启的被动来源收集和可选的字典爆破。项目字典只能包含单层 DNS 标签，并以项目级不可变 Revision 与 SHA-256 绑定；执行时始终使用 `Scanner 内置字典 ∪ 项目增量字典 ∪ Agent 管理字典`，项目内容不能替换内置内容，也不能传入 Agent 文件路径。

字典爆破深度为 1–4 层，深度预设默认 2 层。第 1 层对根域爆破；后续层只对上一层真实解析成功的子域继续爆破，不会预先生成完整笛卡尔树。深度大于 1 的任务只会调度给声明 `subdomain_depth=v1` 的 Agent；绑定项目字典时还要求 `subdomain_dictionary=v1`。

Web 指纹分为默认的响应指纹识别和可选的主动路径指纹。后者请求规则定义的产品特征路径并产出 `Active-Finger`，不等同于向站点广播通用目录字典。

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
