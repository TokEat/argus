# Argus Server 生产环境一键部署指南

本目录包含了 Argus 控制端的完整自动化部署方案。通过执行打包与部署脚本，您可以快速在一台全新纯净的 Linux 服务器（推荐 Ubuntu 22.04 / 24.04）上拉起整套控制端应用，包含：前端控制台、后端接口服务、PostgreSQL 数据库、RabbitMQ 消息队列，并自动完成 2000+ 安全规则的导入。

---

## 🛠 一、打包与分发 (开发侧)

在将环境部署到云主机之前，您需要先在开发机上生成**一键部署发行包**。

在项目根目录下执行以下命令：

```bash
./deploy/build-bundle.sh v0.1.0
```
*(版本号为可选参数，默认不传即为 `v0.1.0`)*

**构建脚本将自动执行：**
1. 构建最新版本的后端 `argus-server`、节点守护进程 `argus-agent` 与独立 Yaksha OCI 镜像（Linux amd64）。
2. 构建最新版本的前端控制台（基于 Node + Vite，生成 `server-ui/dist`）。
3. 预编译数千个散乱的 YAML 漏洞模板，生成紧凑的单文件本地库 `arsenal_seed.db`。
4. 附带 `production.env.example`、部署/卸载脚本和 Docker 编排文件。
5. 附带 Yaksha host-network Compose；Runtime 只监听 `127.0.0.1:8790`，私有 Egress Gateway 只监听配置的可信地址。
6. 将所有必要文件打包为 `argus-release-[版本号]-linux-amd64.tar.gz`。

---

## 🚀 二、快速部署 (运维/服务器侧)

### 1. 准备环境
获取生成的 `argus-release-v0.1.0-linux-amd64.tar.gz`，通过 `scp` 或 `sftp` 上传至目标云服务器（如 `/root` 或 `/home/user` 目录）。

### 2. 解压安装包
```bash
tar -xzf argus-release-v0.1.0-linux-amd64.tar.gz
cd argus-release-v0.1.0
```

### 3. 一键安装
部署脚本采用**就地绿色安装**模式：安装目录固定为发布包根目录（`deploy/` 的父目录），并以规范化后的绝对路径写入 `argus-server.service` 的 `WorkingDirectory`。脚本**不会**默认把文件复制到 `/opt/argus` 等固定目录。

执行以下命令（需具备 `sudo` 或 `root` 权限）：

```bash
sudo ./deploy/setup-server.sh
```

**该脚本支持全自动配置，如无特殊定制需求，无需添加任何参数。它将自动：**
1. 检查并安装 `Docker` 和 `docker-compose-plugin`。
2. 使用 `docker-compose.yml` 启动内置的 PostgreSQL 14 和 RabbitMQ 3。
3. 等待数据库启动并由 `deploy/db-init.sh`（psql 纯 SQL）完成建库与 schema 初始化；`argus-server` 启动时只做校验，不再执行迁移。存量旧版库会在备份后自动执行一次性 cutover。
4. 从 `arsenal_seed.db` 导入所有核心规则资产；该文件是必需部署资产，导入失败会终止安装。
5. 将 `argus-server` 注册为系统级守护进程 (`systemd`)。

#### 可选：自定义安装参数
如果您需要固定各种密钥与配置以配合现有基建，可携带以下参数覆盖默认生成的随机值：

```bash
sudo ./deploy/setup-server.sh \
  --public-ip 1.1.1.1 \
  --db-password "MySuperSecureDBPass" \
  --psk "my-agent-auth-psk" \
  --jwt-secret "my-jwt-login-secret-key" \
  --encrypt-key "base64-32-byte-secret-key"
```

发布包内的 `deploy/production.env.example` 提供了数据库、RabbitMQ、HTTP/gRPC 端口、Agent PSK、JWT Secret、加密密钥、管理员账号、AI Key 与云 AK/SK 的最小生产模板。生产环境必须显式设置强密钥和管理员密码，开发默认值不得直接用于公网部署。

---

## 💡 三、安装完成后的使用

安装成功后，终端将输出一组环境配置信息，类似于：

```text
================================================
       Argus Server 一键部署                    
================================================
  公网 IP:    1.2.3.4
  API 端口:   8085
  gRPC 端口:  50051
  Agent PSK:  <生成的随机通信密钥>
================================================
```

### 访问控制台
打开浏览器，访问 `http://<公网IP>:8085` 即可进入 Argus 安全编排控制台。

### Agent 节点接入
当您在其它机器上启动扫描子节点时，需将分配给您的 `Agent PSK` 配置在目标机器节点中，节点即可通过上述的 gRPC 或 API 端口主动连接母体。

CloudManagement、OSS 自动弹容和真实云资源回收在未完成真实云账号 smoke 前按 beta 能力发布。发布前验收步骤见 [发布检查清单](../docs/release-checklist.md)。

---

## 🔧 四、运维管理指令

本套件注册了标准的 `systemd` 服务名 `argus-server`，您可以使用以下常规系统指令进行管理：

- **查看服务状态**：`systemctl status argus-server`
- **查看运行日志**：`journalctl -fu argus-server`
- **重启服务**：`systemctl restart argus-server`
- **停止服务**：`systemctl stop argus-server`

---

## 🗑 五、安全卸载

如需清除这套环境（**注意：这会永久删除包含数据库的所有监控与任务数据**），只需执行同目录下的卸载脚本：

```bash
sudo ./deploy/uninstall-server.sh
```

卸载脚本会先从 `argus-server.service` 的 `WorkingDirectory` 解析真实安装目录，并校验该服务的 `ExecStart` 位于同一目录，然后才显示确认提示并执行清理。它不会使用 `/opt/argus` 等默认回退路径；无法确认目录时会直接退出，不会删除任何目录。

如果 systemd 服务文件已丢失，但安装目录仍完整，可显式指定目录。该目录必须是绝对路径，且至少包含 `bin/argus-server` 和 `deploy/docker-compose.yml`，否则脚本会 fail closed：

```bash
sudo ./deploy/uninstall-server.sh --install-dir /path/to/argus-release-v0.1.0
```

当 service 仍存在时，`--install-dir` 必须与其 `WorkingDirectory` 完全一致。卸载脚本将停止 systemd 服务、停止并清理配套 Docker 容器和数据卷，并仅删除上述已验证的安装目录。
