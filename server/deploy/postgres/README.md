# PostgreSQL 初始化

当前目录提供一套可重复执行的 PostgreSQL 初始化资产：

- `sql/001-bootstrap.sql`
  创建或更新应用数据库用户，并确保目标数据库存在。
- `sql/010-schema.sql`
  创建 `dddd-server` 所需的全部表与索引。
- `000-init-db.sh`
  统一入口脚本，可直接手工执行，也可由 Docker 官方 `postgres` 镜像在首次初始化时自动执行。

## 默认约定

- 数据库名：`dddd`
- 用户名：`postgres`
- 密码：`root`
- 端口：`5432`

这些默认值与 [docker-compose.yml](/Users/polar/Desktop/ProJect/argus/server/deploy/docker-compose.yml:1) 保持一致。

## 手工执行

```bash
bash server/deploy/postgres/000-init-db.sh
```

也可以通过环境变量覆盖：

```bash
DB_HOST=127.0.0.1 \
DB_PORT=5432 \
DB_SUPERUSER=postgres \
DB_SUPERPASSWORD=root \
APP_DB_NAME=dddd \
APP_DB_USER=postgres \
APP_DB_PASSWORD=root \
bash server/deploy/postgres/000-init-db.sh
```

## Docker 自动执行

`server/deploy/docker-compose.yml` 已将 `server/deploy/postgres` 挂载到 `/docker-entrypoint-initdb.d`。  
当 PostgreSQL 数据目录是全新目录时，容器启动会自动执行初始化脚本。

如果 `server/deploy/data/postgres/` 已经存在旧数据，官方镜像不会重复执行这些初始化脚本。此时请手工执行 `000-init-db.sh`，或清空旧的数据卷后再重建。
