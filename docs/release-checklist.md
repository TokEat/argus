# Argus v0.1.0 发布检查清单

本文档用于首个发布候选版本的人工验收。未执行的项目需要在 Release Notes 中明确标注。

## 1. 代码与质量门禁

- [ ] `git status --short --ignored` 确认只有预期改动，`deploy/argus-release-*.tar.gz`、`deploy/arsenal_seed.db`、`server/build_seed_db` 为 ignored 生成物。
- [ ] `git diff --check` 无空白错误。
- [ ] `make ci` 通过，包含根模块 Go test、`server` 子模块 Go test、`server-ui` lint/test/build 和 smoke。
- [ ] 在临时 PostgreSQL 库执行 `make db-migrate DB_MIGRATION_MODE=apply` 和 `make db-verify`，并确认升级前 Notebook 数据不含无对应项目的孤儿行。

## 2. 发行包构建

- [ ] 执行 `make release-artifacts VERSION=vX.Y.Z`（或等价的 `./deploy/build-bundle.sh vX.Y.Z`）。
- [ ] 发行包生成在 `deploy/argus-release-vX.Y.Z-linux-amd64.tar.gz`，且版本与 tag、Release Notes 一致。
- [ ] 解包后确认以下文件存在：
  - `bin/argus-server-linux-amd64`
  - `bin/argus-agent-linux-amd64`
  - `server-ui/dist`
  - `deploy/docker-compose.yml`
  - `deploy/setup-server.sh`
  - `deploy/uninstall-server.sh`
  - `deploy/production.env.example`
  - `deploy/arsenal_seed.db`

## 3. 部署 smoke

- [ ] 升级既有环境时保留原有显式 `DATABASE_URL`/DSN；默认数据库名变更只适用于新安装，禁止在升级时静默连接到空库。
- [ ] 使用 `deploy/upgrade-server.sh` 验证原地升级；在新服务启动前注入一次失败，确认脚本恢复原 systemd unit、重新加载 unit 并启动升级前二进制；已成功应用的数据库 migration 不会由该应用回滚自动逆转。
- [ ] 升级前暂停新任务并排空旧队列，升级后确认 `argus.tasks.*` 队列正常消费；不要依赖新版本消费旧命名空间中的遗留消息。
- [ ] 启用云端自动扩容前，确认 OSS 中已存在与当前版本匹配的 `argus/agent/argus-agent-linux-amd64`，再恢复调度。
- [ ] 在干净 Linux 目录解包并运行 `sudo ./deploy/setup-server.sh --public-ip <ip>`。
- [ ] Server 启动成功，数据库 migration 完成。
- [ ] `deploy/arsenal_seed.db` 导入成功；导入失败必须终止安装。
- [ ] 使用生产密钥和管理员账号登录控制台。
- [ ] Agent 使用输出的 PSK 注册成功。

## 4. 产品 smoke

- [ ] Dashboard 可打开并展示统计数据。
- [ ] 节点管理可看到已注册 Agent。
- [ ] 规则同步、任务创建、任务结果查看可用。
- [ ] 漏洞 CSV 可导出。
- [ ] Agent 日志页面可筛选并导出日志。
- [ ] BuildJob 列表可查看，已存在构建产物可下载。
- [ ] 资产测绘仅由 Server 以当前租户已批准凭据执行；CLI/Agent 不会向第三方 Provider 发起请求。
- [ ] 测绘 Notebook 的筛选、标签、备注、移除/恢复只在当前用户有项目访问权的范围内可用；跨项目/跨租户请求失败关闭并留有脱敏审计。

## 5. Beta 边界

- [ ] 若未使用真实云账号完成弹容、回收和 OSS 上传 smoke，Release Notes 必须标注 CloudManagement/OSS 自动弹容为 beta。
- [ ] 若发行包未做签名，Release Notes 必须标注当前版本未提供制品签名。
