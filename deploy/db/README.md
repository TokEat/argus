# Argus 数据库初始化（纯 SQL）

本目录是数据库 schema 的唯一权威来源。初始化/升级由 `deploy/db-init.sh` 用
`psql` 直接导入，**不依赖 argus-server 二进制**；`argus-server` 启动时只做
校验（连接重试 + `schema_migrations` 版本 + 表/列/索引契约），失败即拒绝启动
并提示运行本脚本。导入与运行两个阶段各自独立维护。

## 目录结构

```
deploy/db/
├── bootstrap/001-bootstrap.sql        # 建角色/建库（幂等 \gexec，需连接 postgres 库执行）
├── init/001_init.sql                  # v001 最小基线（权威 DDL，pg_dump 物化生成）
├── init/seed_admin.sql                # 默认管理员种子（幂等；生产首次登录后必须改密）
├── legacy/versions.txt                # 旧 010..570（无 510）终态版本清单（cutover 检测用）
└── legacy/900_cutover_from_010_570.sql# 存量旧库一次性切换到 v001
```

## 使用

```bash
# 手动部署（需 psql；可选环境变量 POSTGRES_HOST/PORT/DB/USER/PASSWORD、ARGUS_ADMIN_POSTGRES_PASSWORD）
deploy/db-init.sh

# 开发环境（宿主机无 psql 时自动在 postgres 容器内执行）
make db-setup

# 校验（SQL 导入到目标库后跑 server 启动期同款校验测试）
make db-verify
```

> ⚠️ `db-init.sh` / `make db-setup` / `make db-verify` 会对目标库执行导入和种子写入，
> 只能指向专用（开发/CI/新装）数据库；不要把 `DB_DSN` 指向共享或生产库运行。
> 生产升级走 `deploy/upgrade-server.sh`（自带备份与回滚）。`make db-setup` 开发
> 快捷路径跳过 cutover 备份；手动 `deploy/db-init.sh` 在检测到存量旧库时会先
> 自动 `pg_dump` 到 `deploy/backup/`（该目录已 gitignore）。

`db-init.sh` 按目标库状态自动分派：

| 状态 | 行为 |
|------|------|
| 全新空库 | 依次导入 `init/[0-9]*.sql` + 种子，自检 |
| 旧 010..570 终态 | 先 `pg_dump` 备份（`--no-backup` 跳过）→ 执行 cutover（清理废弃对象 + 重写版本记录）→ 补齐缺失 init 文件 |
| 新版本体系（有 001+ 记录） | 只补导 `schema_migrations` 未记录的 init 文件 |
| 其它未知状态 | 拒绝操作，提示人工处理 |

## 新增 schema 变更（v001 起的维护政策）

1. 新增 `init/NNN_<描述>.sql`（NNN 为下一个三位递增号，如 `002_add_xxx.sql`），
   只写增量 DDL；文件末尾追加版本自记：
   ```sql
   INSERT INTO public.schema_migrations (version, name, checksum, applied_at)
   VALUES ('NNN', '<描述>', 'psql-managed', now())
   ON CONFLICT (version) DO NOTHING;
   ```
2. 同步推进 `server/internal/db/schema_version.go` 的 `RequiredSchemaVersion` 到 `NNN`。
3. 同步更新 `server/internal/db/schema_verify.go` 的表/列/索引契约（启动校验依据）。
4. GORM 模型（`server/internal/db/db.go` 等）与 `schema_contract_test.go` 映射同步更新。
5. 验证：`make db-setup && make db-verify`，并跑 `cd server && go test ./...`。
6. 已发布到环境的 init 文件不可再改写；修正历史错误用新的递增文件表达。

## v001 版本重启说明

- v001 基线由旧 010..570 全量增量在空库物化后 `pg_dump --schema-only` 收敛生成，
  并删除了确认无业务引用的历史对象：`cron_tasks`、`notification_rules`、
  `asset_change_logs` 表、`tenant_quota` 兼容视图、`root_tasks.cron_task_id` 列。
- 旧增量文件已从仓库移除（git 历史可查）；已部署的旧终态库通过
  `legacy/900_cutover_from_010_570.sql` 一次性切换，切换前自动备份。
- `schema_migrations.checksum` 统一记为 `psql-managed`（纯 SQL 流程不计算哈希）。
