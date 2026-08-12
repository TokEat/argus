# Argus Dev Startup Scripts

These scripts run the local development server, agent, and MCP process outside of a Codex session. Logs and PID files are written under `runtime/`.

## Common Flow

```bash
./scripts/start-server.sh
./scripts/start-agent.sh
./scripts/start-yaksha.sh
./scripts/start-mcp.sh
./scripts/status-dev.sh
```

Stop everything:

```bash
./scripts/stop-dev.sh
```

## Defaults

- Server: `http://127.0.0.1:8085`, gRPC `127.0.0.1:50051`
- Agent ID: `agent-mcp-dev`
- MCP HTTP address: `127.0.0.1:8787`
- Yaksha runtime: Docker 常驻 Daemon `http://127.0.0.1:8790`，默认预热 2 个 Worker
- Logs: `runtime/logs/*.log`
- PID files: `runtime/pids/*.pid`

`start-mcp.sh` tries to log in to the local dev server with `admin/admin123` and writes a JWT to `runtime/argus-token.jwt`. Set `ARGUS_TOKEN` or `ARGUS_TOKEN_FILE` to use a different token.
HTTP/SSE 传输还必须设置独立的 `ARGUS_MCP_AUTH_TOKEN`（或
`ARGUS_MCP_AUTH_TOKEN_FILE`）供 MCP 客户端使用 Bearer 认证；stdio 不需要该入站 Token。

## Useful Overrides

```bash
ARGUS_REBUILD=1 ./scripts/start-server.sh
ARGUS_AGENT_ID=agent-local-2 ARGUS_AGENT_WORKERS=4 ./scripts/start-agent.sh
ARGUS_MCP_HTTP_ADDR=127.0.0.1:8788 ./scripts/start-mcp.sh
ARGUS_YAKSHA_URL=http://127.0.0.1:8790 ./scripts/start-mcp.sh
ARGUS_API_URL=http://127.0.0.1:8085 ARGUS_GRPC_ADDR=127.0.0.1:50051 ./scripts/start-agent.sh
```

For extra binary arguments:

```bash
ARGUS_SERVER_EXTRA_ARGS='--api :8086 --grpc 50052' ./scripts/start-server.sh
ARGUS_AGENT_EXTRA_ARGS='--tags tenant_id=default' ./scripts/start-agent.sh
```

MCP 暴露 `argus_yaksha_exp`，支持 `inspect/validate/test/debug/run`。调用通过 HTTP 复用
Yaksha Daemon，并可传密封依赖、Asset、精确网络目标和本次
`egress.mode=disabled|direct|socks5`。SOCKS5 模式同时传一次性的 write-only
`egress.socks5_proxy`；Daemon 没有默认代理，请求未选择出口时网络 fail-closed，
Fixture test 始终断网。未来 Agent 使用平台原生 TCP relay，不提供 SOCKS5 端点。

真实进程验收必须从 MCP module 执行：

```bash
cd mcp
ARGUS_MCP_TEST_BIN=../bin/argus-mcp \
ARGUS_YAKSHA_TEST_BIN=../bin/yaksha \
go test ./internal/mcp -run 'TestMCPToRealYakshaVerticalLoop|TestArgusMCPProcessCallsRealYaksha' -count=1 -v
```
