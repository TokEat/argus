<p align="center">
  <h1 align="center">Argus</h1>
  <p align="center">
    <b>分布式攻击面管理与漏洞巡航平台</b>
  </p>
  <p align="center">
    <a href="#快速开始">快速开始</a> •
    <a href="#架构概览">架构</a> •
    <a href="#部署模式">部署</a> •
    <a href="#文档">文档</a> •
    <a href="#贡献与协作">协作</a>
  </p>
</p>

---

## 简介

**Argus** 是一个企业级分布式攻击面管理 (ASM) 与漏洞巡航平台，由 [dddd](https://github.com/SleepingBag945/dddd) 项目演进而来。

项目形成了清晰的 **控制面 (Control Plane)** 与 **数据面 (Data Plane)** 架构分层，同时保留了开箱即用的单机 CLI 模式，既可作为一线工具快速使用，也可横向扩展为多节点分布式巡航集群。

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
- **PSK 预共享密钥鉴权**：生产模式强制 Agent 双向认证
- 规则库热更新：支持 POC / 指纹 / Workflow 版本化同步
- JWT 认证 + 多租户隔离中间件

### 📊 数据与运营
- 结构化三层数据模型：**资产画像** / **指纹组件** / **漏洞**
- 异步 BatchWriter 防洪落库，支撑多 Agent 高并发回传
- HTML 漏洞报表（含请求响应详情）
- CSV 资产导出
- 审计日志，敏感环境必备

### 🔗 资源整合
- Hunter / Fofa / Quake 空间引擎集成
- Hunter 低感知模式
- 零 CGO 依赖（纯 Go SQLite），多平台开箱即用

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
| **单机 CLI** | `dddd` | 红队打点、安服测试、快速验证 |
| **分布式集群** | `dddd-server` + N × `dddd-agent` | 企业级 ASM 巡航、大规模资产扫描 |
| **Agent 单节点** | `dddd-agent` (对接远端 Server) | 云端弹性扩展节点 |

---

## 快速开始

### 安装

从 [Releases](https://github.com/P0lar1ght/argus/releases) 下载对应平台的二进制文件，直接命令行运行即可。

> **提示**：v2.0 起可以独立于 config 文件夹运行。

### 从源码构建

```bash
# 构建全部组件
make all

# 或单独构建
make cli        # 单机版 CLI
make agent      # Agent 探针节点
make server     # Server 控制面

# 全平台交叉编译 (Linux/macOS/Windows)
./build.sh

# 启用 UPX 压缩
./build.sh pack
```

产物输出在 `bin/`（make）或 `release/`（build.sh）目录。

### 单机模式

```bash
# 扫描 IP
dddd -t 192.168.0.1

# 扫描网段
dddd -t 192.168.0.1/24
dddd -t 192.168.0.0-192.168.0.12

# 扫描网站
dddd -t http://test.com
```

### 分布式模式

#### 基础设施

```bash
# 一键启动 RabbitMQ、PostgreSQL，并完成建库/建用户/migration
make setup-local
```

如果你想拆步执行：

```bash
# 1. 启动基础设施
make infra-up

# 2. 初始化数据库角色与数据库
make db-init

# 3. 执行业务 schema migration
make db-migrate
```

#### 安全配置

分布式部署**必须**配置以下环境变量（缺失将拒绝启动）：

| 环境变量 | 说明 | 示例 |
|---------|------|------|
| `ARGUS_AGENT_PSK` | Agent-Server 双向认证预共享密钥 | `openssl rand -hex 32` |
| `ARGUS_JWT_SECRET` | Web API JWT 签名密钥 | `openssl rand -hex 32` |

> **安全约束**：生产模式下两个环境变量必须设置，否则 Server 会直接 Fatal 退出。开发环境可通过 `--dev` flag 跳过。

#### 生产部署

```bash
# 2. 启动 Server 控制面
export ARGUS_AGENT_PSK="$(openssl rand -hex 32)"
export ARGUS_JWT_SECRET="$(openssl rand -hex 32)"
./dddd-server --grpc 50051 --api :8085

# 3. 启动 Agent 数据面 (可在多台机器上部署，PSK 必须与 Server 端一致)
export ARGUS_AGENT_PSK="<与 Server 相同的密钥>"
./dddd-agent --server <server_addr>:50051 --id agent-1 --workers 4
```

#### 开发模式

```bash
# 跳过安全检查（仅限开发/测试）
./dddd-server --dev
./dddd-agent --server 127.0.0.1:50051
```

#### Server 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--db` | 空（内置 PostgreSQL 默认 DSN） | PostgreSQL 数据库 DSN |
| `--migrate-only` | `false` | 只执行数据库 migration 和 schema verify，然后退出 |
| `--db-migration-mode` | `apply` | 数据库迁移模式：`apply` / `verify` / `dev-auto` |
| `--amqp` | `amqp://guest:guest@localhost:5672/` | RabbitMQ 地址，空则回退内存队列 |
| `--grpc` | `50051` | gRPC 监听端口 |
| `--api` | `:8085` | HTTP API 监听地址 |
| `--agent-psk` | 空 | Agent PSK（也可通过 `ARGUS_AGENT_PSK` 设置） |
| `--dev` | `false` | 开发模式，跳过安全检查 |

#### Agent 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--server` | `127.0.0.1:50051` | Server gRPC 地址 |
| `--api` | `http://127.0.0.1:8085` | Server REST API 地址 |
| `--id` | `agent-local-1` | Agent 唯一标识 |
| `--workers` | `1` | 并发 worker 数 |
| `--tags` | 空 | 节点标签 `key1=val1,key2=val2` |
| `--psk` | 空 | PSK 密钥（也可通过 `ARGUS_AGENT_PSK` 设置） |

### 应用场景速查

```bash
# 红队外网 - Hunter 查询备案
dddd -t 'icp.name="xxxx有限公司"' -hunter -oip

# 红队外网 - Hunter + Fofa 联合
dddd -t 'icp.name="xxxx有限公司"' -hunter -fofa -oip

# 红队外网 - 子域名枚举
dddd -t xxx.com -sd

# 红队内网
dddd -t 172.16.100.0/24

# 安服测试 - 开启审计日志
dddd -t 172.16.100.1 -a

# 仅指纹识别 (不跑 POC)
dddd -t http://www.xxx.com -npoc
dddd -t 172.16.100.11 -npoc
dddd -t 172.16.120.11:3307 -npoc
```

### 输出文件

| 类型 | 默认文件 | 参数 |
|------|----------|------|
| 文本结果 | `result.txt` | `-o` 更改路径，`-ot json` 切换格式 |
| HTML 报表 | `<timestamp>.html` | `-ho` 更改路径 |
| 审计日志 | `audit.log`（需 `-a` 开启） | — |

> 扫描可随时终止，结果实时持久化到文件。

---

## 项目结构

```
argus/
├── scanner/                   # 数据面 - 扫描引擎核心
│   ├── cmd/
│   │   ├── cli/               # dddd 单机 CLI 入口
│   │   └── agent/             # dddd-agent 分布式探针入口
│   ├── internal/              # 引擎运行时 (module-private)
│   │   ├── agent/             # Agent 生命周期管理
│   │   ├── engine/            # 扫描流水线编排
│   │   ├── finger/            # 指纹识别引擎
│   │   ├── vuln/              # 漏洞映射与检测
│   │   ├── scanner/           # 端口/协议扫描
│   │   ├── arsenal/           # 规则库管理
│   │   ├── config/            # 运行时配置
│   │   ├── output/            # 结果输出
│   │   └── uncover/           # 空间引擎集成
│   ├── gopocs/                # Go 原生 POC 引擎
│   ├── lib/                   # 集成上游引擎 (nuclei/httpx/subfinder/...)
│   ├── common/                # 兼容层 + 嵌入配置
│   ├── embed/                 # 嵌入资源
│   ├── ddout/                 # 统一输出抽象
│   ├── structs/               # 共享运行时模型
│   └── utils/                 # 工具函数
│
├── server/                    # 控制面 - 调度与管理服务
│   ├── cmd/dddd-server/       # Server 入口
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
├── data/                      # 规则库数据 (arsenal.db)
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
| [贡献与协作指南](CONTRIBUTING.md) | 分支模型、命名规范、PR 与发布流程 |
| [项目结构](docs/project-structure.md) | 目录结构与组件职责 |
| [实现状态总览](docs/implementation-status.md) | 当前代码实现程度与主要缺口 |
| [接口实现清单](docs/interface-implementations.md) | 当前 `/api/v1`、WebSocket、gRPC 主链路接口 |
| [分布式架构现状](docs/distributed-scan-architecture.md) | 当前控制面 / 数据面架构与未闭环点 |
| [规则库初始化](docs/rule-catalog-init.md) | Arsenal 与结构化规则表初始化机制 |
| [白皮书规划稿](docs/whitepaper-plan.md) | 正式技术白皮书的定位、目录与写作方案 |

---

## 贡献与协作

团队协作建议采用：

- `main` 作为唯一稳定主线
- 所有开发从 `feat/*`、`fix/*`、`refactor/*` 等短生命周期分支发起
- 仅在需要版本冻结时创建 `release/*`
- 线上紧急修复使用 `hotfix/*`

详细规则见 [CONTRIBUTING.md](CONTRIBUTING.md)。

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
