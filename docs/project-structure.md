# Argus 项目结构与文档入口

## 顶层结构

目录树只列 git 跟踪的顶层布局；运行期生成物（`bin/`、`datas/`、`release/`、`data/`、`runtime/` 等）与本地配置不列出。

```text
.
├── scanner/
│   ├── cmd/
│   │   ├── cli/             # argus CLI entrypoint
│   │   ├── agent/           # argus-agent entrypoint
│   │   ├── perf-baseline/   # external process-wall baseline capture tool
│   │   ├── arsenal-package/ # arsenal.db packaging for release bundles
│   │   └── protocol-smoke/  # protocol smoke helper
│   ├── internal/            # scan runtime and pipeline (module-private)
│   ├── common/              # legacy compatibility layer + embedded config
│   ├── gopocs/              # go-native poc engine
│   ├── lib/                 # vendored/forked upstream engines (nuclei/httpx/subfinder/...)
│   ├── ddout/               # unified output sink abstraction
│   ├── embed/               # embedded Nuclei/resources wiring
│   ├── structs/             # shared runtime models
│   └── utils/               # scanner utility functions
├── server/                  # controller/api/grpc service (module: github.com/P0lar1ght/argus/server)
├── server-ui/               # React/Vite management console
├── mcp/                     # standalone MCP proxy and typed protocol clients
├── yaksha/                  # persistent isolated Yaklang EXP runtime daemon
├── exp-lab/                 # local smoke/canary test environment for Agent and Yaksha
├── deploy/                  # production/local deployment templates and release scripts
├── tools/                   # repository maintenance and Arsenal sync tools
├── scripts/                 # local development, MCP and release helpers
├── config/                  # scanner dictionaries and POC/runtime configuration
└── shared/
    └── proto/               # protobuf definitions + generated stubs (module: github.com/P0lar1ght/argus/shared/proto)
```

## 职责边界

- `scanner/cmd/*` only contains executable bootstrap and argument wiring.
- `scanner/internal/*` holds orchestration and task runtime, and remains reusable by both CLI and agent.
- `server` is the independent control-plane/runtime concern.
- `server-ui` is the React/Vite management console and consumes the `/api/v1` control-plane API.
- `mcp` is the standalone MCP proxy; its protocol clients are kept separate from the server HTTP handlers.
- `yaksha` is an independent language runtime. Its Docker daemon supervises pre-warmed JSON-lines workers, while MCP calls the bounded loopback HTTP API; it is not embedded in Server.
- `deploy` contains deployment templates, production configuration examples and release packaging scripts; it is not the runtime source of truth for business logic.
- `tools` contains repository-side utilities such as `tools/arsenal-sync`, which writes source rule baselines only through an explicit local workflow and Git review.
- `shared/proto` is the protocol contract shared by scanner agent and server.
- `scanner/common/*` is treated as legacy compatibility surface while migration to `scanner/internal/*` continues.

## 运行与构建入口

- CLI：`scanner/cmd/cli/main.go`
- Agent：`scanner/cmd/agent/main.go`
- Server：`server/cmd/argus-server/main.go`
- MCP：`mcp/cmd/argus-mcp`
- Web：`server-ui/`
- Proto：`shared/proto/proto/scan/agent.proto`
- 构建：`Makefile`、`build.sh`、`deploy/build-bundle.sh`

## 架构现状

- 控制面主链路是 `server/internal/api`、`grpc`、`db`、`scheduler`；`/api/v1` 保持兼容，没有 `/api/v2`。
- `server/internal/api/router.go` 已收敛为路由装配入口；任务、云资源、MCP、构建、日志等领域处理已拆分到独立 handler/service 文件。
- `server/internal/cloud/` 提供 Provider、ResourceManager、AutoScaler、Cloud-Init 和 OSS 分发能力；真实云厂商调用仍通过 Provider 抽象隔离。

## 相关文档

- [实现状态与接口清单](implementation-status.md)
- [数据库设计总览](db_schema.md)
- [分布式扫描架构](distributed-scan-architecture.md)
- [ScanPlan 与覆盖契约](scanplan-contract.md)
- [云资源动态调度](cloud-resource-scheduling.md)
- [Yaksha EXP](yaksha-exp.md)
- [AI Copilot 架构](ai_copilot_architecture.md)
- [技术白皮书](argus-technical-whitepaper.md)

## 本地与阿里云同步

开发机（Mac）与阿里云工作区按需 rsync 对齐时，见 [local-aliyun-sync.md](local-aliyun-sync.md)。代理指令见根目录 `AGENTS.md`「Local ↔ Aliyun sync」。
