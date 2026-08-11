# Argus 项目结构与文档入口

## 顶层结构

```text
.
├── scanner/
│   ├── cmd/
│   │   ├── cli/             # dddd CLI entrypoint
│   │   └── agent/           # dddd-agent entrypoint
│   ├── internal/            # scan runtime and pipeline (module-private)
│   ├── common/              # legacy compatibility layer + embedded config
│   ├── gopocs/              # go-native poc engine
│   ├── lib/                 # vendored/forked upstream engines (nuclei/httpx/subfinder/...)
│   ├── ddout/               # unified output sink abstraction
│   ├── structs/             # shared runtime models
│   └── utils/               # scanner utility functions
├── server/                  # controller/api/grpc service (module: github.com/user/dddd-server)
├── server-ui/               # React/Vite management console
├── mcp/                     # standalone MCP proxy and typed protocol clients
├── deploy/                  # production/local deployment templates and release scripts
├── tools/                   # repository maintenance and Arsenal sync tools
├── scripts/                 # local development, MCP and release helpers
├── config/                  # scanner dictionaries and POC/runtime configuration
└── shared/
    └── proto/               # protobuf definitions + generated stubs (module: github.com/user/dddd-proto)
```

## 职责边界

- `scanner/cmd/*` only contains executable bootstrap and argument wiring.
- `scanner/internal/*` holds orchestration and task runtime, and remains reusable by both CLI and agent.
- `server` is the independent control-plane/runtime concern.
- `server-ui` is the React/Vite management console and consumes the `/api/v1` control-plane API.
- `mcp` is the standalone MCP proxy; its protocol clients are kept separate from the server HTTP handlers.
- `deploy` contains deployment templates, production configuration examples and release packaging scripts; it is not the runtime source of truth for business logic.
- `tools` contains repository-side utilities such as `tools/arsenal-sync`, which writes source rule baselines only through an explicit local workflow and Git review.
- `shared/proto` is the protocol contract shared by scanner agent and server.
- `scanner/common/*` is treated as legacy compatibility surface while migration to `scanner/internal/*` continues.

## 运行与构建入口

- CLI：`scanner/cmd/cli/main.go`
- Agent：`scanner/cmd/agent/main.go`
- Server：`server/cmd/dddd-server/main.go`
- MCP：`mcp/cmd/argus-mcp`
- Web：`server-ui/`
- Proto：`shared/proto/proto/scan/agent.proto`
- 构建：`Makefile`、`build.sh`、`compile.sh`、`deploy/build-bundle.sh`

## 当前迁移状态

- CLI main moved from root `main.go` to `scanner/cmd/cli/main.go`.
- Agent main moved from `cmd/dddd-agent/main.go` to `scanner/cmd/agent/main.go`.
- Scanner runtime packages were consolidated under `scanner/`.
- `dddd-server` moved to `server`.
- `dddd-proto` moved to `shared/proto`.
- `go.work`, root `go.mod`, and `server/go.mod` path mappings were updated accordingly.
- Build entrypoints were updated in `Makefile`, `build.sh`, and `compile.sh`.
- `server/internal/adapters/httpapi`、`server/internal/adapters/grpcagent`、`server/internal/core/usecase` 已存在，但仍是 Clean Architecture 迁移 scaffold，尚未承接主业务。
- `server/internal/api/router.go` 已收敛为路由装配入口；任务、云资源、MCP、构建、日志等领域处理已拆分到独立 handler/service 文件，当前主链路仍由同一个 `/api/v1` Router 注册。
- `server/internal/cloud/` 提供 Provider、ResourceManager、AutoScaler、Cloud-Init 和 OSS 分发能力；真实云厂商调用仍通过 Provider 抽象隔离。

## 相关文档

- [实现状态与接口清单](implementation-status.md)
- [数据库设计总览](db_schema.md)
- [分布式扫描架构](distributed-scan-architecture.md)
- [ScanPlan 与覆盖契约](scanplan-contract.md)
- [云资源动态调度](cloud-resource-scheduling.md)
- [EXP 能力规划](exp-capability-planning.md)
- [AI Copilot 架构](ai_copilot_architecture.md)
- [技术白皮书](argus-technical-whitepaper.md)
