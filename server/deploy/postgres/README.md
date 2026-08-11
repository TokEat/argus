# PostgreSQL 初始化

当前目录提供一套可重复执行的 PostgreSQL 初始化资产：

- `sql/001-bootstrap.sql`
  创建或更新应用数据库用户，并确保目标数据库存在。
- `sql/010-schema.sql`
  历史 schema 快照，仅用于兼容排查或复现旧库，不再作为新环境初始化入口。
- `000-init-db.sh`
  统一 bootstrap 入口脚本，可直接手工执行，也可由 Docker 官方 `postgres` 镜像在首次初始化时自动执行。

## 默认约定

- 数据库名：`argus`
- 用户名：`postgres`
- 密码：`root`
- 端口：`5432`

这些默认值与 [docker-compose.yml](/Users/polar/Desktop/ProJect/argus/server/deploy/docker-compose.yml:1) 保持一致。

## 手工执行

```bash
make infra-up
make db-init
make db-migrate
make db-verify
```

也可以直接一键完成：

```bash
bash server/deploy/setup-local.sh
```

需要做一遍完整本地冒烟校验时，可执行：

```bash
make smoke-local
```

如果你只想单独执行 PostgreSQL bootstrap，则使用：

```bash
bash server/deploy/postgres/000-init-db.sh
./argus-server --migrate-only
```

也可以通过环境变量覆盖：

```bash
DB_HOST=127.0.0.1 \
DB_PORT=5432 \
DB_SUPERUSER=postgres \
DB_SUPERPASSWORD=root \
APP_DB_NAME=argus \
APP_DB_USER=postgres \
APP_DB_PASSWORD=root \
bash server/deploy/postgres/000-init-db.sh
```

## Docker 自动执行

`server/deploy/docker-compose.yml` 已将 `server/deploy/postgres` 挂载到 `/docker-entrypoint-initdb.d`。
当 PostgreSQL 数据目录是全新目录时，容器启动会自动执行初始化脚本。

如果 `server/deploy/data/postgres/` 已经存在旧数据，官方镜像不会重复执行这些初始化脚本。此时直接运行 `argus-server` 即可自动完成增量迁移；如果数据库或角色尚未创建，再手工执行 `000-init-db.sh`。

## 现行初始化职责

- `000-init-db.sh`
  只负责建库和建用户。
- `argus-server --migrate-only`
  负责创建 / 升级业务表、列、索引，并执行 schema 校验。
- 正常启动 `argus-server`
  会执行 migrations、schema verify，然后再做规则 bootstrap。

## 历史 schema 文件

`sql/010-schema.sql` 保留为历史快照，便于复现旧版数据库结构或验证升级路径。  
新环境不要再直接执行它来初始化主库。
