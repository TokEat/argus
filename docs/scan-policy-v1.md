# 扫描策略 V1

`argus.scan-policy/v1` 是 Web、MCP、Copilot、Server 与 Agent 之间唯一的用户扫描配置契约。它只表达扫描意图，不暴露 Scanner 文件路径、反向布尔开关或任意 JSON。

## 预设

| 预设 | 端口 | 识别范围 | 自动风险验证 |
| --- | --- | --- | --- |
| `quick` | 常用 100 | 被动子域、基础识别 | 关闭 |
| `standard` | Nmap TCP Top 1000 | 被动子域、完整协议/Web/指纹 | 开启 |
| `deep` | 1-65535 | 子域爆破、Host Binding、目录探测 | 开启 |

预设的端口、扫描方式和强度不可局部覆盖；需要调整这些专家参数时使用 `custom`。能力清单可在预设默认值上显式开关，因此弱口令可在任一预设中主动开启。TCP 是默认方式，SYN 只有在 Agent 上报 `scan_syn=v1` 时可调度，并且严格使用策略中的端口集合。

## 验证阶段

资产发现、风险验证和弱口令验证是同一 Root Task 下的独立阶段。后两者只消费资产发现产生的精确端点，不重新执行端口、协议或指纹扫描。

- 风险验证仅执行指纹 Workflow 绑定的、创建任务时已审核启用且哈希未漂移的规则。
- 弱口令验证仅接受 `host:port + service + credential plugin + observation hash` 的密封计划；HTTP/HTTPS 和非认证插件会被拒绝。
- POC 或弱口令任一开启时，策略必须包含一次统一的 `validation_confirmed=true`。

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
