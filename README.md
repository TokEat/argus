<p align="center">
  <img src="server-ui/src/assets/brand/argus-logo-icon.svg" width="112" alt="Argus logo">
  <h1 align="center">Argus</h1>
  <p align="center">
    <b>分布式攻击面管理、漏洞巡航与 AI 辅助运营平台</b>
  </p>
  <p align="center">
    <a href="server-ui/src/assets/brand/argus-logo-animation.mp4">
      <img src="server-ui/src/assets/brand/argus-logo-animation.gif" width="720" alt="Argus logo animation">
    </a>
  </p>
  <p align="center">
    <a href="#快速开始">快速开始</a> •
    <a href="#能力地图">能力地图</a> •
    <a href="#架构概览">架构</a> •
    <a href="#部署模式">部署</a> •
    <a href="#文档">文档</a> •
    <a href="#贡献与协作">协作</a>
  </p>
</p>

---

## 简介

**Argus** 是一个企业级分布式攻击面管理 (ASM)、漏洞巡航、规则治理、EXP 验证与 AI Copilot 辅助运营平台，由 [dddd](https://github.com/SleepingBag945/dddd) 项目演进而来。

项目形成了清晰的 **控制面 (Control Plane)** 与 **数据面 (Data Plane)** 架构分层，同时保留开箱即用的单机 CLI 模式。它既能作为一线安全测试工具快速使用，也能横向扩展为多节点分布式巡航集群，并通过 Web Console、云资源调度和 AI Copilot 承接持续化运营。

当前主线已覆盖：

- 单机 CLI、Server 控制面、Agent 数据面、Web Console 四类入口
- POC / Fingerprint / Workflow / Dir / EXP 弹药库治理
- 多租户、RBAC、项目分发、节点管理、任务编排和实时结果回传
- AI Copilot、Prompt Registry、工具/动作白名单、低风险草稿动作确认与审计
- EXP Builder、Nuclei/Starlark 双模式执行、调试请求/响应 Trace、cleanup 与取消链路
- 阿里云 ECS / OSS 动态 Agent 分发、AutoScaler、Spot 回收和云实例对账

## 特性

### 🔍 扫描引擎
- 自动识别输入类型（IP / CIDR / URL / 域名），无需手动分类
- 完整扫描流水线：`存活探测 → 端口扫描 → 协议识别 → Web 探测 → 指纹识别 → 漏洞检测`
- 支持复杂 **与/或/非/括号** 逻辑运算的指纹规则，人类友好
- 集成 Nuclei v3 引擎 + 原生 GoPoc 漏洞探测引擎
- 指纹-漏洞映射数据库，避免无效发包
- 高效子域名枚举/爆破，精准泛解析过滤

### 🌐 分布式架构
- **Server (控制面)**：任务编排、节点管理、规则中心、结果聚合、多租户隔离
- **Agent (数据面)**：轻量游击型探针，即插即用、弹性扩缩
- **RabbitMQ** 三级优先队列调度：手动 ACK/Nack、超时回收、死节点任务打捞、Channel 自动重建
- **gRPC** 双向通信：节点注册、心跳、任务派发、流式结果回传、远程终止
- **Agent 鉴权**：生产模式强制使用 PSK 完成接入鉴权，注册后通过 Agent session token 保护后续内部调用
- 规则库热更新：Server 使用 `arsenal.db` 作为传输包，Agent 同步后物化为本地 `config/` 规则目录再执行扫描
- JWT 认证 + 多租户隔离中间件

### 🤖 AI Copilot 与智能化
- 全局 **AI Copilot**：跨页面上下文感知，支持多轮对话与流式推理展示
- **动态工具链 (Tool Calling)**：内置引擎诊断、平台知识检索、节点状态查询等大模型执行工具
- **智能 POC 审查与辅助生成**：自动审查漏洞规则误报风险，流式优化 YAML 模板
- 多模型接入，兼容 OpenAI / DeepSeek 等协议体系，附带连通性探测

### 📊 数据与运营
- 结构化三层数据模型：**资产画像** / **指纹组件** / **漏洞**
- 异步 BatchWriter 防洪落库，支撑多 Agent 高并发回传
- Argus 自包含 HTML 扫描报告：资产、服务、Web、指纹与漏洞证据统一展示，并保留 POC 引擎实际提供的请求/响应详情
- CSV 资产导出
- 审计日志，敏感环境必备

### 🔗 资源整合
- 项目级“资产测绘”模块集成 Hunter / FOFA / Quake 查询、历史、导出、可授权聚合的笔记本运营和幂等任务分发
- 规则传输包使用纯 Go SQLite 驱动；发行构建使用 `CGO_ENABLED=0`，支持多平台交叉编译

---

## 架构概览

```
                          ┌─────────────────────────────┐
                          │      Web Console / API       │
                          └──────────────┬──────────────┘
                                         │
                 ┌───────────────────────────────────────────────┐
                 │            Control  Plane  (Server)           │
                 │                                               │
                 │  ┌──────────┐ ┌──────────┐ ┌───────────────┐ │
                 │  │ API GW   │ │ Task     │ │ Rule Center / │ │
                 │  │ (Gin)    │ │ Scheduler│ │ Arsenal       │ │
                 │  └──────────┘ └──────────┘ └───────────────┘ │
                 │  ┌──────────┐ ┌──────────┐ ┌───────────────┐ │
                 │  │ gRPC     │ │ Node     │ │ Result        │ │
                 │  │ Service  │ │ Registry │ │ Aggregator    │ │
                 │  └──────────┘ └──────────┘ └───────────────┘ │
                 └──────────┬──────────┬──────────┬─────────────┘
                            │          │          │
                   ┌────────┘    ┌─────┘    ┌─────┘
                   ▼             ▼          ▼
              ┌──────────┐  ┌──────────┐ ┌────────┐
              │PostgreSQL│  │RabbitMQ  │ │ Object │
              │          │  │ Priority │ │ Store  │
              │          │  │ Queues   │ │        │
              └──────────┘  └──────────┘ └────────┘
                   ▲             ▲
                   │    gRPC     │
          ┌────────┴─────────────┴────────┐
          │     Data  Plane  (Agents)      │
          │                                │
          │  ┌──────────────────────────┐  │
          │  │ Agent Supervisor         │  │
          │  │  ├─ Heartbeat            │  │
          │  │  ├─ Rule Sync            │  │
          │  │  └─ Command Listener     │  │
          │  ├──────────────────────────┤  │
          │  │ Scanner Engine           │  │
          │  │  存活→端口→协议→Web→     │  │
          │  │  指纹→Workflow→Nuclei/   │  │
          │  │  GoPoc                   │  │
          │  └──────────────────────────┘  │
          │       ... × N Agents ...       │
          └────────────────────────────────┘
```

---

## 部署模式

Argus 支持三种运行模式：

| 模式 | 组件 | 适用场景 |
|------|------|----------|
| **单机 CLI** | `argus` | 红队打点、安服测试、快速验证 |
| **分布式集群** | `argus-server` + N × `argus-agent` | 企业级 ASM 巡航、大规模资产扫描 |
| **Agent 单节点** | `argus-agent` (对接远端 Server) | 云端弹性扩展节点 |

---

## 快速开始

### 安装

从 [Releases](https://github.com/P0lar1ght/argus/releases) 下载对应平台的二进制文件，直接命令行运行即可。

> **提示**：发行版 CLI 会内嵌 Fingerprint、Workflow、Dir 和 POC 规则，可以独立于 `config/` 目录运行。Agent 采用 `noembed` 构建，通过 Server 下载 `arsenal.db` 后物化为本地 `config/` 目录，不在扫描任务中直接查询 DB。

### 从源码构建

```bash
# 构建全部组件
make all

# 或单独构建
make cli        # 单机版 CLI
make agent      # Agent 探针节点
make server     # Server 控制面
make mcp        # MCP 代理

# 全平台交叉编译 (Linux/macOS/Windows)
./build.sh

# 启用 UPX 压缩
./build.sh pack
```

产物输出在 `bin/`（make）或 `release/`（build.sh）目录。

`build.sh` 默认使用 `CGO_ENABLED=0`、`-trimpath` 和 `-ldflags="-s -w"` 构建发行产物；CLI 内嵌规则，Agent 自动使用 `noembed`。UPX 是可选压缩步骤，未安装、目标平台不支持或压缩失败时会跳过，不影响未压缩产物。

### 单机模式

```bash
# 查看 Argus CLI 版本和帮助
argus --version
argus -h

# 扫描 IP
argus -a 192.168.0.1

# 扫描网段
argus -a 192.168.0.1/24
argus -a 192.168.0.0-192.168.0.12

# 扫描网站
argus -a http://test.com
```

单机 CLI 的扫描结果统一保存在当前工作目录的 `datas/<目标_时间>/` 下。普通运行只保留实时 `result.txt`、一份权威 HTML 报告和小型 `summary.txt`；不会再为了扫描记忆额外创建 `argus-data/state`、`argus-data/runs` 或 targets/findings/coverage/timing TSV。

把上次的结果目录或 `result.txt` 交给 `-a`，会复用 `[Alive]` / `[Port]`：有存活就跳过探活去做端口，有端口就直接做协议/Web/POC。
`-ss` 才会跳过 `datas` 里已经出现过的 IP，默认关闭；与 `-f` 一起用时仍完整扫描。

成功完成时，交互文本输出会给出执行阶段数、完整/部分/全跳过输入数，以及本次计划与历史跳过资产数。`-ot json` 使用版本化 UTF-8 NDJSON：每个 finding 独占一行，最后一行是唯一 `run_summary`；stdout 不包含 Banner、ANSI、进度或普通日志。重定向的文本模式同样只保留扫描结果和必要错误。完整 Schema、退出码和迁移示例见 [Argus CLI 结构化输出](docs/cli-output.md)。

普通 CLI 扫描默认执行资产发现、Nuclei 与 GoPoc（含口令爆破），请在授权目标上使用。用 `-nopoc` 只关 Nuclei，用 `-nogpoc` 关全部 GoPoc，用 `-nobr` 只关服务口令爆破。只做发现时写 `-nopoc -nogpoc`；要跳过 `datas` 历史已见 IP 还需显式 `-ss`。`-pwda` / `-usea` 在内置用户本、密码本上追加；`-up` / `-upf` 是整本替换。Server 创建任务的默认值仍是关 POC，不跟 CLI 手感走。

需要忽略未过期历史并重新执行完整资产流水线时，只增加可选 `-force`：

```bash
argus -a 192.168.0.1 -force
```

`-force` 不会扩大目标或端口范围，不会开启 POC/GoPoc，也不会删除或覆盖旧结果；本次完整执行仍会写入新的 `datas/<目标_时间>/` 目录。默认命令和其他现有参数保持不变。

`datas/` 可能包含授权目标、资产名称、发现摘要以及 HTML 中的验证证据，应按敏感测试数据保护；它不会上传 Server，也不会自动清理，只能由操作者手动清理。

### 分布式模式

#### 基础设施

```bash
# 一键启动 RabbitMQ、PostgreSQL，并完成数据库初始化（纯 SQL 导入）
make setup-local
```

如果你想拆步执行：

```bash
# 1. 启动基础设施
make infra-up

# 2. 数据库初始化（建库/建角色 + 最小基线导入 + 种子 + 自检，psql 纯 SQL，
#    宿主机没有 psql 时自动在 postgres 容器内执行）
make db-setup

# 3. 校验：SQL 导入后跑 server 启动期同款版本/契约校验
make db-verify

# 4. 做一遍本地搭建冒烟校验（可选）
make smoke-local
```

> 数据库初始化与 server 启动已解耦：`argus-server` 启动时只校验数据库
> （版本 + 表/列/索引契约），不再执行任何迁移；未初始化/版本不匹配会拒绝
> 启动并提示运行 `deploy/db-init.sh`（或 `make db-setup`）。维护政策见
> `deploy/db/README.md`。

#### 安全配置

分布式部署**必须**配置以下环境变量（缺失将拒绝启动）：

| 环境变量 | 说明 | 示例 |
|---------|------|------|
| `ARGUS_AGENT_PSK` | Agent 接入认证预共享密钥 | `openssl rand -hex 32` |
| `ARGUS_JWT_SECRET` | Web API JWT 签名密钥 | `openssl rand -hex 32` |
| `ARGUS_ENCRYPT_KEY` | 云账号等敏感配置的 AES-256 加密密钥 | `openssl rand -base64 32` |
| `ARGUS_EGRESS_GATEWAY_LISTEN` | Yaksha 私有 Egress Gateway 监听地址，不得发布公网 | `127.0.0.1:50052` |
| `ARGUS_EGRESS_GATEWAY_TOKEN` | Yaksha Gateway 独立共享密钥 | `openssl rand -hex 32` |
| `YAKSHA_RELAY_ADDR` | Yaksha 连接的私有 Gateway 地址 | `127.0.0.1:50052` |
| `YAKSHA_RELAY_TOKEN` | 与 Gateway Token 相同，仅注入 Yaksha Daemon | `openssl rand -hex 32` |
| `ARGUS_MCP_AUTH_TOKEN` | MCP HTTP/SSE 入站 Bearer Token，与 Server API Token 分离 | `openssl rand -hex 32` |

> **安全约束**：生产模式下前三个基础密钥必须设置，否则 Server 会直接退出。Agent 原生 Egress 启用时，Gateway 地址和 Token 必须成对配置；Gateway 与 Yaksha Token 必须一致，监听端口不得发布公网。MCP 使用 HTTP/SSE 时必须配置独立入站 Token，否则拒绝启动；stdio 不需要该 Token。开发环境可通过 `--dev` flag 跳过基础启动检查；`--dev` 不得用于生产环境。

#### 生产部署

```bash
# 1. 在开发机或构建机生成发行包
VERSION=v0.1.0
./deploy/build-bundle.sh "$VERSION"

# 2. 上传到目标 Linux 服务器后解包
tar -xzf "argus-release-${VERSION}-linux-amd64.tar.gz"
cd "argus-release-${VERSION}"

# 3. 使用公网 IP 一键安装控制端
sudo ./deploy/setup-server.sh --public-ip <ip>
```

发布包会包含 `argus-server`、`argus-agent`、`server-ui/dist`、Docker 编排、部署/卸载脚本、生产配置模板和必需规则资产库 `deploy/arsenal_seed.db`。规则资产导入失败会终止安装。

生产环境必须按 `deploy/production.env.example` 显式设置数据库、RabbitMQ、`ARGUS_AGENT_PSK`、`ARGUS_JWT_SECRET`、`ARGUS_ENCRYPT_KEY`、管理员账号、AI Key 和云 AK/SK。默认密码或开发密钥只允许本地开发使用。

#### 生产升级

已安装环境不要通过卸载重装升级。生成新版发布包并上传到服务器后，在新版解压目录执行：

```bash
tar -xzf argus-release-v0.1.1-linux-amd64.tar.gz
cd argus-release-v0.1.1
sudo ./deploy/upgrade-server.sh
```

升级脚本会复用现有 `argus-server.service` 的安装目录和数据库连接，先创建 `backups/upgrade-<时间>` 备份，再替换二进制、Agent 分发文件和前端资源，执行数据库迁移与规则资产同步，最后重启服务。不要删除旧安装目录下的 `data/`，PostgreSQL 和 RabbitMQ 的持久化数据都在那里。

安装完成后登录控制台，按页面提示接入 Agent，然后创建第一个扫描任务。CloudManagement、OSS 自动弹容和真实云回收必须按发布检查清单完成真实云账号 smoke；未验证的能力应在对应 Release Notes 中标记为 beta。

#### 开发模式

```bash
# 跳过安全检查（仅限开发/测试）
./argus-server --dev
./argus-agent --server 127.0.0.1:50051
```

#### Server 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--db` | 空（内置 PostgreSQL 默认 DSN） | PostgreSQL 数据库 DSN。启动时仅校验（版本+契约），初始化/升级请用 `deploy/db-init.sh` |
| `--amqp` | `amqp://guest:guest@localhost:5672/` | RabbitMQ 地址，空则回退内存队列 |
| `--grpc` | `50051` | gRPC 监听端口 |
| `--api` | `:8085` | HTTP API 监听地址 |
| `--config-dir` | 空 | 预留的规则目录参数；批量导入预编译规则请使用 `--seed-from-db` |
| `--agent-psk` | 空 | Agent PSK（也可通过 `ARGUS_AGENT_PSK` 设置） |
| `--seed-from-db` | 空 | 从指定 SQLite seed DB 导入规则到 PostgreSQL 后退出 |
| `--dev` | `false` | 开发模式，跳过安全检查 |

#### Agent 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--server` | `127.0.0.1:50051` | Server gRPC 地址 |
| `--api` | `http://127.0.0.1:8085` | Server REST API 地址 |
| `--id` | `agent-<hostname>-<pid>` | Agent 唯一标识 |
| `--workers` | `0` | 并发 worker 数；`0` 表示按 CPU 自动计算 |
| `--tags` | 空 | 节点标签 `key1=val1,key2=val2`；私网增量复用建议设置 `network_zone=corp-a`，无标签私网仅在当前 Agent 内复用；带私网区域标签但只扫描公网 DNS 时可显式增加 `network_scope=public` |
| `--psk` | 空 | PSK 密钥（也可通过 `ARGUS_AGENT_PSK` 设置） |

### 应用场景速查

```bash
# 红队外网 - 子域名枚举
argus -a xxx.com -sd

# 红队内网（默认含 Nuclei 与 GoPoc）
argus -a 172.16.100.0/24

# 绕过本地增量覆盖，完整复测授权范围
argus -a 172.16.100.0/24 -force

# 安服测试 - 开启审计日志
argus -a 172.16.100.1 -ad

# 只做资产发现
argus -a http://www.xxx.com -nopoc -nogpoc
argus -a 172.16.100.11 -nopoc -nogpoc
argus -a 172.16.120.11:3307 -nopoc -nogpoc
```

### 输出文件

| 类型 | 默认文件 | 参数 |
|------|----------|------|
| 原始结果 | `result.txt` | `-o` 更改文件名，`-ot json` 切换格式 |
| Argus HTML 扫描报告 | `<timestamp>.html` | `-ho` 更改文件名；资产、服务、Web、指纹和漏洞证据均在同一页面 |
| 审计日志 | `audit_YYYYMMDD_HHMMSS.log`（需 `-a` 开启） | `-alf` 更改文件名 |

> 每次 CLI 运行只生成一份权威 HTML，不再拆分为当前目录的漏洞页和 `datas/` 下的资产页。`result.txt` 仍会实时持久化；HTML 在运行收敛后原子写入。报告按“服务边界 + 产品”归并重复指纹，同一产品只计数一次，展开后仍保留被动命中、主动确认和较低置信度的路径推断来源；原始 `Finger` / `Active-Finger` 事件继续保留在 `result.txt`。Nuclei 的全部 HTTP/Network 多步骤 packet/request/response 会保留，二进制 TCP 证据以可恢复的 hex-dump 展示；GoPoc 的 `InfoLeft`、`InfoRight`、`ShowMsg` 继续作为摘要保留，扫描器能够直接观测到的成功验证收发包会以结构化 `go_poc.exchanges` 同时写入 JSON 和 HTML。使用第三方协议客户端且 Argus 无法取得原始帧的插件只展示真实可得的验证摘要，不会把摘要或推测内容冒充网络包。普通 POC-off 扫描也会生成报告，但漏洞区为空且不会暗示已完成漏洞验证。

---

## 项目结构

```
argus/
├── scanner/                   # 数据面 - 扫描引擎核心
│   ├── cmd/
│   │   ├── cli/               # argus 单机 CLI 入口
│   │   └── agent/             # argus-agent 分布式探针入口
│   ├── internal/              # 引擎运行时 (module-private)
│   │   ├── agent/             # Agent 生命周期管理
│   │   ├── engine/            # 扫描流水线编排
│   │   ├── finger/            # 指纹识别引擎
│   │   ├── vuln/              # 漏洞映射与检测
│   │   ├── scanner/           # 端口/协议扫描
│   │   ├── arsenal/           # 规则库管理
│   │   ├── config/            # 运行时配置
│   │   ├── output/            # 结果输出
│   ├── gopocs/                # Go 原生 POC 引擎
│   ├── lib/                   # 集成上游引擎 (nuclei/httpx/subfinder/...)
│   ├── common/                # 兼容层 + 嵌入配置
│   ├── embed/                 # 嵌入资源
│   ├── ddout/                 # 统一输出抽象
│   ├── structs/               # 共享运行时模型
│   └── utils/                 # 工具函数
│
├── server/                    # 控制面 - 调度与管理服务
│   ├── cmd/argus-server/       # Server 入口
│   ├── internal/
│   │   ├── api/               # REST API (Gin)
│   │   ├── grpc/              # gRPC Agent 通信服务
│   │   ├── scheduler/         # RabbitMQ 多优先级任务调度
│   │   ├── db/                # PostgreSQL 数据层
│   │   ├── bootstrap/         # 依赖装配
│   │   ├── config/            # 服务端配置
│   │   ├── core/              # 领域模型与用例
│   │   ├── adapters/          # 端口适配器 (HTTP/gRPC/持久层/队列)
│   │   ├── cloud/             # 云端集成
│   │   └── shared/            # 通用工具
│   └── deploy/                # 部署配置 (docker-compose)
│
├── shared/
│   └── proto/                 # Protobuf 定义 + 生成桩代码
│
├── data/                      # Agent 规则传输包缓存、hash 与备份
├── docs/                      # 架构与设计文档
├── Makefile                   # 构建入口
├── build.sh                   # 全平台交叉编译脚本
└── go.work                    # Go workspace
```

详细的组件职责说明参见 [docs/project-structure.md](docs/project-structure.md)。

---

## 文档

| 文档 | 说明 |
|------|------|
| [贡献与协作指南](CONTRIBUTING.md) | Issue 闭环、分支模型、验证矩阵、PR 阻断条件、发布与 Hotfix 流程 |
| [AI/Codex 代理指令](AGENTS.md) | Codex/AI 协作硬约束、Definition of Done 和验证要求 |
| [安全策略](SECURITY.md) | 漏洞报告方式、支持版本、安全范围和安全港原则 |
| [生产部署指南](deploy/README.md) | v0.1.0 发行包构建、服务器安装、Agent 接入和卸载流程 |
| [发布检查清单](docs/release-checklist.md) | `make ci`、打包、解包、部署 smoke 和 beta 边界验收 |
| [项目结构](docs/project-structure.md) | 目录结构与组件职责 |
| [实现状态与接口清单](docs/implementation-status.md) | 当前实现程度、主要缺口、`/api/v1` / WebSocket / gRPC 主链路接口 |
| [Server 资产发现](docs/asset-discovery.md) | FOFA/Hunter/Quake 查询、项目级历史、安全 CSV 导出、去重且可追溯的测绘笔记本、Provider 预算、租户凭据、脱敏审计及后续任务分发边界 |
| [租户隔离与角色权限划分](docs/tenant-rbac.md) | 当前租户边界、三档角色和后端接口权限矩阵 |
| [数据库设计总览](docs/db_schema.md) | 当前 schema、索引策略、项目隔离演进与规则库初始化机制 |
| [分布式扫描架构](docs/distributed-scan-architecture.md) | 控制面 / 数据面架构、Agent-Pull 调度与 Agent 扫描流水线 |
| [ScanPlan 与覆盖契约](docs/scanplan-contract.md) | 场景、阶段、Plan、WorkKey、Observation 与 Coverage 的跨组件稳定语义 |
| [扫描策略 V1](docs/scan-policy-v1.md) | 语义化预设、自动验证阶段、增量凭据字典和 Agent TLS 能力边界 |
| [性能基线采集](docs/performance-baseline.md) | CLI/Agent 计时证据与可重复的外部 process-wall 基线采集方式 |
| [CLI 参数说明](CLI.md) | Standalone CLI 扫描参数、默认值和常用例子 |
| [CLI 结构化输出](docs/cli-output.md) | `-ot json` NDJSON Schema、终端摘要、非 TTY 行为和稳定退出码 |
| [CLI 离线弹药库](docs/cli-offline-arsenal.md) | 发行包内 `arsenal.db` 的校验、物化与本地替换/导入 |
| [云资源动态调度](docs/cloud-resource-scheduling.md) | AutoScaler、云实例生命周期、Spot 回收与未来演进 |
| [Yaksha EXP](docs/yaksha-exp.md) | 单文件 Yaklang EXP 权威模型、利用族组织、五种动作与测试调试发布流程 |
| [AI Copilot 架构](docs/ai_copilot_architecture.md) | 全局 Copilot、工具调用、POC AI 审查和后续路线 |
| [技术白皮书](docs/argus-technical-whitepaper.md) | 对外技术定位、核心闭环、典型场景与演进路线 |

---

## 贡献与协作

团队协作建议采用：

- `main` 作为唯一稳定主线
- 所有开发从 `feat/*`、`fix/*`、`refactor/*` 等短生命周期分支发起
- 非平凡改动先建 Issue，并在 PR 中关联闭环
- PR 必须记录验证结果、风险、回滚方式和安全检查
- 仅在需要版本冻结时创建 `release/*`
- 线上紧急修复使用 `hotfix/*`

详细规则见 [CONTRIBUTING.md](CONTRIBUTING.md)。使用 Codex 或其他 AI 代理协作时，还必须遵守 [AGENTS.md](AGENTS.md)。

---

## 技术栈

| 领域 | 技术 |
|------|------|
| 语言 | Go 1.25+ |
| 通信 | gRPC + Protobuf |
| Web 框架 | Gin |
| 数据库 | PostgreSQL (GORM) |
| 消息队列 | RabbitMQ (内置内存 Fallback) |
| 漏洞引擎 | Nuclei v3 / GoPoc |
| 指纹识别 | 自研引擎 (ddfinger) |
| DNS | dnsx / subfinder |
| HTTP 探测 | httpx |
| 认证 | JWT + PSK (gRPC) |

---

## 参考项目

- [fscan](https://github.com/shadow1ng/fscan)
- [kscan](https://github.com/lcvvvv/kscan)
- [gonmap](https://github.com/lcvvvv/gonmap)
- [nuclei](https://github.com/projectdiscovery/nuclei)
- [subfinder](https://github.com/projectdiscovery/subfinder)
- [httpx](https://github.com/projectdiscovery/httpx)
- [naabu](https://github.com/projectdiscovery/naabu)
- [gogo](https://github.com/chainreactors/gogo)
- [afrog](https://github.com/zan8in/afrog)

---

## 免责声明

本工具仅面向**合法授权**的企业安全建设行为，如您需要测试本工具的可用性，请自行搭建靶机环境。

在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。**请勿对非授权目标进行扫描。**

如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。

在安装并使用本工具前，请您**务必审慎阅读、充分理解各条款内容**，限制、免责条款或者其他涉及您重大权益的条款可能会以加粗、加下划线等形式提示您重点注意。除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要安装并使用本工具。您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。

---

## 许可证

[MIT License](LICENSE)

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=P0lar1ght/argus&type=Date)](https://star-history.com/#P0lar1ght/argus&Date)
