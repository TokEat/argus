# Argus v0.1.0 发布检查清单

本文档用于首个发布候选版本的人工验收。未执行的项目需要在 Release Notes 中明确标注。

## 1. 代码与质量门禁

- [ ] `git status --short --ignored` 确认只有预期改动，`deploy/argus-release-*.tar.gz`、`deploy/arsenal_seed.db`、`server/build_seed_db` 为 ignored 生成物。
- [ ] `git diff --check` 无空白错误。
- [ ] `make ci` 通过，包含根模块 Go test、`server` 子模块 Go test、`server-ui` lint/test/build 和 smoke。

## 2. 发行包构建

- [ ] 执行 `./deploy/build-bundle.sh v0.1.0`。
- [ ] 发行包生成在 `deploy/argus-release-v0.1.0-linux-amd64.tar.gz`。
- [ ] 解包后确认以下文件存在：
  - `bin/dddd-server-linux-amd64`
  - `bin/dddd-agent-linux-amd64`
  - `server-ui/dist`
  - `deploy/docker-compose.yml`
  - `deploy/setup-server.sh`
  - `deploy/uninstall-server.sh`
  - `deploy/production.env.example`
  - `deploy/arsenal_seed.db`

## 3. 部署 smoke

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

## 5. Beta 边界

- [ ] 若未使用真实云账号完成弹容、回收和 OSS 上传 smoke，Release Notes 必须标注 CloudManagement/OSS 自动弹容为 beta。
- [ ] 若发行包未做签名，Release Notes 必须标注当前版本未提供制品签名。
