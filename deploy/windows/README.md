# Argus Windows 单机部署指南

面向在 **Windows 机器上一键部署完整 Argus 控制端**（控制台 + 后端 + 数据库 + 消息队列 + 对象存储 + EXP 运行时）。
数据面基础设施跑在 Docker Desktop 容器里，计算面（argus-server / yaksha）以原生 Windows 进程运行，扫描节点可用同一包内的 `argus-agent.exe` 接入本机或其他 Windows/Linux 机器。

---

## 1. 快速开始

### 1.1 生成部署包（开发机，一次性）

在仓库根目录执行（产物：`release\argus-windows-amd64-v0.1.0.zip`）：

```powershell
.\deploy\windows\build-windows-bundle.ps1 -Version v0.1.0
```

参数：`-SkipFrontend` 复用已构建的 `server-ui/dist`；`-Version` 需满足 `vX.Y.Z`。

### 1.2 部署（目标 Windows 机器）

前置：安装并启动 [Docker Desktop](https://www.docker.com/products/docker-desktop/)（WSL2 后端）。无需管理员权限（全部绑定高端口）。

```powershell
# 1. 解压到任意目录，例如 C:\argus
Expand-Archive argus-windows-amd64-v0.1.0.zip -DestinationPath C:\argus
cd C:\argus\argus-windows-amd64-v0.1.0

# 2. 一键部署：密钥生成 -> 容器启动 -> POC 导入 -> 服务启动
deploy\setup.ps1
```

完成后控制台输出访问信息。浏览器打开 `http://127.0.0.1:8085`，默认账号 `admin`（**首次登录后请立即修改密码**）。

---

## 2. 目录结构

```
argus-windows-amd64-v0.1.0/
├─ bin/
│  ├─ argus-server.exe        # 控制端后端（API :8085 / Agent gRPC :50051）
│  ├─ argus-agent.exe         # 扫描节点（本机或其他机器接入）
│  ├─ argus.exe               # 独立 CLI（扫描/指纹识别）
│  └─ argus-data/arsenal/arsenal.db   # CLI 离线弹药库（首启自动导入）
├─ config/                    # 规则配置（finger.yaml / dir.yaml / workflow.yaml / pocs / dict）
├─ server-ui/dist/            # 前端控制台（server 直接托管）
├─ release/                   # Agent 二进制分发目录（/release 静态路由）
├─ deploy/
│  ├─ docker-compose.yml      # PostgreSQL / RabbitMQ / MinIO / minio-init / yaksha
│  ├─ setup.ps1               # 一键部署 / -Stop / -SeedOnly / -SkipSeed
│  ├─ uninstall.ps1           # 卸载 / -Purge 清数据 / -ComposeDown
│  ├─ arsenal_seed.db         # 预编译规则资产库（POC/指纹/工作流）
│  ├─ images/argus-yaksha.tar # yaksha OCI 镜像（Linux-only 运行时，容器方式运行）
│  └─ db-init/                # 数据库初始化 SQL（001..006,580..604,seed_admin）
├─ data/                      # 运行时生成：postgres / rabbitmq / minio / logs
└─ secrets.env                # 全部密钥（setup.ps1 自动生成，仅当前用户可读）
```

> **yaksha 说明**：EXP 沙箱运行时依赖 cgo libpcre2，官方仅发布 Linux 二进制，
> 因此 Windows 上以容器方式随 compose 一起运行（`argus-yaksha:local` 镜像，
> 监听 `127.0.0.1:8790`），由 `setup.ps1` 自动加载启动，无需手工干预。

---

## 3. POC / 规则导入

Argus 的 POC、指纹、工作流统一存放在**规则资产库**中，部署时有三种载体：

| 载体 | 说明 | 何时导入 |
| --- | --- | --- |
| `deploy\arsenal_seed.db` | 预编译 SQLite 单文件（数千条规则） | `setup.ps1` 步骤 [4/5] 自动执行 |
| `bin\argus-data\arsenal\arsenal.db` | CLI 离线弹药库 | 首次运行 `argus.exe` 自动导入本机规则目录 |
| `config\pocs\`、`config\finger.yaml` 等 | 规则源文件 | 由 `build_seed_db` 在打包阶段编译进 seed DB |

**首次部署**：无需任何手工操作，`setup.ps1` 执行：
```powershell
bin\argus-server.exe --db "<DSN>" --seed-from-db deploy\arsenal_seed.db
```
该命令为幂等 upsert（按规则 ID 冲突更新 `content/hash/state`），重复运行只更新有变化的规则，安全随时重跑。

**更新规则后重新导入**（例如替换了打包时外的 `arsenal_seed.db`）：
```powershell
deploy\setup.ps1 -SeedOnly
```

**自定义 POC**：把 YAML POC 放入 `config\pocs\`、指纹放入 `config\active-fingerprints\`，然后在开发机重新生成 seed DB 并重新打包分发；或直接在生产环境替换 `arsenal_seed.db` 后执行 `-SeedOnly`。

> 验证导入结果：登录控制台查看规则总数，或查询数据库
> `docker compose --env-file ..\secrets.env -f deploy\docker-compose.yml exec postgres psql -U postgres -d argus -c "SELECT count(*) FROM arsenals;"`

---

## 4. 容器管理

基础设施容器由 `deploy\docker-compose.yml` 定义，**首次启动时 PostgreSQL 自动按字母序执行 `deploy\db-init\*.sql` 完成建库与全部迁移**（001→006→580→…→604→seed_admin），无需安装 psql 客户端。

```powershell
# 启动 / 停止容器（数据保留在 data\）
cd deploy
docker compose --env-file ..\secrets.env -f docker-compose.yml up -d
docker compose --env-file ..\secrets.env -f docker-compose.yml stop

# 查看日志 / 状态
docker compose --env-file ..\secrets.env -f docker-compose.yml logs -f postgres
docker compose --env-file ..\secrets.env -f docker-compose.yml ps

# RabbitMQ 管理台: http://127.0.0.1:15672（账号密码见 secrets.env）
# MinIO 控制台:   http://127.0.0.1:9001
```

**重置数据库**（危险，清空全部数据）：`setup.ps1 -Stop` → `docker compose ... down` → 删除 `data\postgres` → 重新 `setup.ps1`。

**重新初始化后不需要手工导 POC**：`setup.ps1` 会再次自动执行 seed 导入。

---

## 5. 服务管理（argus-server / yaksha）

`setup.ps1` 默认以后台进程方式托管（PID 记录在 `data\argus-services.json`，日志在 `data\logs\`）。

```powershell
deploy\setup.ps1              # 启动（重复执行自动重启旧实例）
deploy\setup.ps1 -Stop        # 停止
deploy\uninstall.ps1          # 停服务 + 停容器（保留数据）
deploy\uninstall.ps1 -Purge   # 额外删除 data\（需输入 DELETE 确认）
```

### 注册为 Windows 服务（推荐生产使用）

借助 [NSSM](https://nssm.cc/)：

```powershell
nssm install argus-server "C:\argus\bin\argus-server.exe" `
  "--db `"host=127.0.0.1 user=postgres password=<PG密码> dbname=argus port=5432 sslmode=disable`" --config-dir C:\argus\config --amqp amqp://argus:<MQ密码>@127.0.0.1:5672/ --api :8085 --grpc :50051 --deploy-mode intranet"
nssm set argus-server AppDirectory C:\argus
nssm set argus-server AppEnvironmentExtra `
  ARGUS_JWT_SECRET=<secrets.env值> ARGUS_AGENT_PSK=<secrets.env值> ARGUS_CREDENTIAL_ENCRYPT_KEY=<secrets.env值> `
  ARGUS_EXP_MINIO_ENDPOINT=127.0.0.1:9000 ARGUS_EXP_MINIO_ACCESS_KEY=<值> ARGUS_EXP_MINIO_SECRET_KEY=<值> ARGUS_EXP_MINIO_BUCKET=argus-exp ARGUS_YAKSHA_URL=http://127.0.0.1:8790
nssm set argus-server AppStdout C:\argus\data\logs\argus-server.log
nssm set argus-server AppStderr C:\argus\data\logs\argus-server.err.log
nssm start argus-server
```
yaksha 已由 compose 托管（容器），无需 NSSM。
`uninstall.ps1` 会自动检测并移除上述 NSSM 服务。

---

## 6. 扫描节点接入

同包内的 `bin\argus-agent.exe` 可直接作为节点注册到本机控制端：

```powershell
bin\argus-agent.exe -server <本机局域网IP>:50051 -api http://<本机局域网IP>:8085 `
  -psk <secrets.env 中的 ARGUS_AGENT_PSK> -id win-node-01 -tags os=windows
```

- 防火墙：控制端机器需放行 **入站** TCP `50051`（Agent gRPC）与 `8085`（HTTP）；Agent 侧无需开放入站。
- 其他 Windows/Linux 机器作节点：把 `bin\argus-agent.exe`（或 release\ 下的分发文件）单独拷贝过去即可。
- 内网模式：本部署包默认以 `--deploy-mode intranet` 运行（关闭云自动伸缩/egress 链路）；如需对接真实云账号弹容，去掉该参数并补齐 `ARGUS_ENCRYPT_KEY` 与云 AK/SK 环境变量。

---

## 7. 安全基线与备份

- `secrets.env` 是全部密钥的唯一事实来源，保持仅当前用户可读；泄露任一键请更新该文件并重启服务/容器。
- 生产环境必须修改默认 `admin` 密码；请勿将 `:8085`/`:50051` 直接暴露公网，置于 VPN / 反向代理之后。
- 备份 = 停机后复制 `data\` 整个目录 + `secrets.env`；恢复时放回原位重新 `setup.ps1` 即可（seed 导入幂等）。
