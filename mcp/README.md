# Argus MCP

生产环境通过 stdio 或带 `ARGUS_MCP_AUTH_TOKEN` 的 Streamable HTTP 暴露 MCP；EXP 的唯一用户身份、租户、RBAC 和审计权威仍是 Argus Server。

## EXP Studio 浏览器宿主（仅开发）

本地调试 MCP App 时可显式启用同进程浏览器宿主：

```bash
ARGUS_MCP_TRANSPORT=http \
ARGUS_MCP_HTTP_ADDR=127.0.0.1:8787 \
ARGUS_MCP_AUTH_TOKEN=local-mcp-token \
ARGUS_MCP_APP_DEV_HOST=true \
go run ./cmd/argus-mcp
```

访问 `http://127.0.0.1:8787/__dev/exp-studio`。宿主只允许 `argus_yaksha_exp`、`argus_exp_workspace` 与用于在线 Agent 选择的只读 `argus_agents`，通过进程内 Client 转发真实调用；浏览器不接收 Server Token。该入口必须绑定 loopback，且默认关闭，不能作为生产 MCP Host。
