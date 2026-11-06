# 本地 Mac ↔ 阿里云按需同步

本文说明 Argus 开发树在本机与阿里云之间的同步方式。代理指令见根目录 [AGENTS.md](../AGENTS.md) 的「Local ↔ Aliyun sync」一节。

## 为什么这样设计

- **不经 GitHub**：两边工作区直接对齐，不依赖远程托管仓库做中转。
- **不新增公网攻击面**：只复用已有 SSH Host `aliyun`（密钥认证 + SSH 加密），不开 git daemon / smart HTTP，不在公网挂私有裸库。
- **按需、显式方向**：`push` 或 `pull` 由人（或代理在用户要求下）主动执行；先 `diff` / `--dry-run` 再写入。

## 路径与身份

| 侧 | 路径 / 身份 |
| --- | --- |
| 本地 | 本仓库根目录（Mac） |
| 远端 | `aliyun:/home/claudex/workspace/project/argus-main` |
| SSH | `~/.ssh/config` 中 Host `aliyun`（当前为密钥登录） |
| 远端写文件 | `rsync` 经 `--rsync-path='sudo -u claudex rsync'`，避免 root 属主 |

可用环境变量覆盖：

- `ARGUS_SYNC_SSH`（默认 `aliyun`）
- `ARGUS_SYNC_REMOTE`（默认远端路径）
- `ARGUS_SYNC_RSYNC_PATH`（默认 `sudo -u claudex rsync`）

## 命令

```bash
./scripts/sync-aliyun.sh diff
./scripts/sync-aliyun.sh push --dry-run
./scripts/sync-aliyun.sh push
./scripts/sync-aliyun.sh pull --dry-run
./scripts/sync-aliyun.sh pull
```

实现文件：

- `scripts/sync-aliyun.sh`
- `scripts/sync-aliyun.excludes`

## 排除项（摘要）

默认不同步（完整列表见 excludes）：

- `.git/`、IDE/缓存、`node_modules/`、`bin/`、日志与二进制
- 根目录运行时 `config/`、`data/`
- `server/deploy/data/`、Postgres/RabbitMQ/MinIO 数据
- `server/internal/api/data/` 等报告/对象存储落地文件

源码侧规则仍以仓库内 `scanner/common/config/` 等受版本管理的路径为准；本地 arsenal 物化目录不要当权威源互相同步。

## 冲突与安全注意

- `push`/`pull` 带 `--delete`：目标侧多余文件会被删掉，等同单向镜像。
- 同一文件两边都改过时：先备份，再选一侧覆盖；不要假设脚本会做三路合并。
- 不要把真实凭据、客户目标、未脱敏日志同步进仓库树；遵守 `AGENTS.md` / `SECURITY.md`。
- 公网 SSH 加固（关密码登录等）需用户明确授权后再做，本同步方案不依赖改 sshd。
