# Project Structure (v2)

## Top-Level Layout

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
└── shared/
    └── proto/               # protobuf definitions + generated stubs (module: github.com/user/dddd-proto)
```

## Responsibility Boundaries

- `scanner/cmd/*` only contains executable bootstrap and argument wiring.
- `scanner/internal/*` holds orchestration and task runtime, and remains reusable by both CLI and agent.
- `server` is the independent control-plane/runtime concern.
- `shared/proto` is the protocol contract shared by scanner agent and server.
- `scanner/common/*` is treated as legacy compatibility surface while migration to `scanner/internal/*` continues.

## Migration Notes

- CLI main moved from root `main.go` to `scanner/cmd/cli/main.go`.
- Agent main moved from `cmd/dddd-agent/main.go` to `scanner/cmd/agent/main.go`.
- Scanner runtime packages were consolidated under `scanner/`.
- `dddd-server` moved to `server`.
- `dddd-proto` moved to `shared/proto`.
- `go.work`, root `go.mod`, and `server/go.mod` path mappings were updated accordingly.
- Build entrypoints were updated in `Makefile`, `build.sh`, and `compile.sh`.

## Related Documents

- [Architecture Overview](distributed-scan-architecture.md)
- [Agent Workflow](agent_scan_flow.md)
- [Agent Pull Model](agent-pull-architecture.md)
- [Implementation Status](implementation-status.md)
- [Interface Implementations](interface-implementations.md)
