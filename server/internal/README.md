# Server Internal Layout

控制面主链路：

- `api` — REST `/api/v1`（Gin）
- `grpc` — Agent gRPC
- `db` — PostgreSQL 模型与查询
- `scheduler` — 任务队列
- `cloud` / `storage` / `egress` — 云资源、对象存储、出站

入口在 `server/cmd/argus-server/main.go`。
