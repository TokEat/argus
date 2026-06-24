# Argus Dev Startup Scripts

These scripts run the local development server, agent, and MCP process outside of a Codex session. Logs and PID files are written under `runtime/`.

## Common Flow

```bash
./scripts/start-server.sh
./scripts/start-agent.sh
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
- Logs: `runtime/logs/*.log`
- PID files: `runtime/pids/*.pid`

`start-mcp.sh` tries to log in to the local dev server with `admin/admin123` and writes a JWT to `runtime/argus-token.jwt`. Set `ARGUS_TOKEN` or `ARGUS_TOKEN_FILE` to use a different token.

## Useful Overrides

```bash
ARGUS_REBUILD=1 ./scripts/start-server.sh
ARGUS_AGENT_ID=agent-local-2 ARGUS_AGENT_WORKERS=4 ./scripts/start-agent.sh
ARGUS_MCP_HTTP_ADDR=127.0.0.1:8788 ./scripts/start-mcp.sh
ARGUS_API_URL=http://127.0.0.1:8085 ARGUS_GRPC_ADDR=127.0.0.1:50051 ./scripts/start-agent.sh
```

For extra binary arguments:

```bash
ARGUS_SERVER_EXTRA_ARGS='--api :8086 --grpc 50052' ./scripts/start-server.sh
ARGUS_AGENT_EXTRA_ARGS='--tags tenant_id=default' ./scripts/start-agent.sh
```
