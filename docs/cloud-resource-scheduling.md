# Argus 云资源动态调度 (Cloud Resource Scheduling)

本文档专门记录 Argus 平台从静态 Docker/节点接入向云原生弹性伸缩架构（云资源动态调度）演进的设计理念、架构细节与实现状态。

## 1. 架构目标

随着分布式扫描的推进，单靠静态配置的 Agent 节点难以应对以下场景：
1. **突发高并发任务**：遇到十万级目标时，固定节点处理过慢。
2. **成本控制**：任务空闲时，大量闲置计算节点浪费云资源。
3. **红队规避封禁**：单一出口 IP 极易被目标安全设备拦截，需要动态切换大量分散的公网 IP。

**目标**：实现一个高度自治的 **AutoScaler (自动伸缩引擎)**，根据队列深度、伸缩策略，自动向云厂商 (如阿里云、AWS) 申请竞价实例 (Spot Instances)，自动注入配置并拉起 Agent，并在任务空闲或实例生命周期到达后自动销毁，实现算力的**按需分配与随用随弃**。

---

## 2. 核心架构设计

### 2.1 模块构成

云资源调度逻辑集中在 `server/internal/cloud/`，由以下核心模块组成：

| 模块 | 职责 | 实现文件 |
|------|------|----------|
| **AutoScaler** | 核心调度引擎，负责 30s 一次的评估决策（扩缩容判定）、实例对账、孤儿回收。 | `autoscaler.go` |
| **Provider Factory** | 注册表模式工厂，提供各云厂商实现的创建入口，打破包循环依赖。 | `provider_factory.go` |
| **CloudProvider** | 屏蔽底层云厂商差异的抽象接口（定义 `Provision` / `Terminate` / `List`）。 | `provider.go` |
| **Aliyun ECS** | 阿里云的具体 Provider 实现，负责调用阿里云 SDK 执行实例生命周期。 | `aliyun/ecs.go` |
| **ResourceManager** | 实例级管理器，桥接 Provider API 与 PostgreSQL 数据库状态同步。 | `manager.go` |
| **Cloud-Init** | 实例初始化模板引擎，使用 Base64 注入带参启动脚本 (AgentID/TenantID/PSK/Addr)。 | `cloudinit.go` |
| **Crypto** | AES-256-GCM 凭证加解密层，保护云厂商 AccessKey 落库安全。 | `crypto.go` |

### 2.2 数据库模型

数据模型存储在 `server/internal/db/cloud_models.go` 中，分为三层：

1. **`CloudAccount` (云账号)**：存储不同云厂商的访问凭证 (AK/SK 加密存储)。
2. **`CloudScalingPolicy` (伸缩策略)**：配置扩缩容阈值 (`scale_up_threshold`, `scale_down_threshold`)、最大最小实例数、竞价策略、TTL 以及基础模板（如镜像、安全组）。
3. **`CloudInstance` (云实例)**：映射真实的云主机，维护其从 `Provisioning` 到 `Running` 再到 `Terminated` 的状态机，并与 `AgentID` 绑定。

---

## 3. 核心流转机制

### 3.1 自动扩缩容决策 (30s 评估循环)

AutoScaler 作为一个守护协程，每 30 秒执行一次全局评估：

- **Scale Up (扩容)**：
  - 条件：`queue_depth > scale_up_threshold` 且 `running_instances < max_instances`。
  - 动作：计算所需实例数（每实例承载约 256 个目标），并发调用 Provider 创建实例，并向新实例写入 Cloud-Init UserData。
- **Scale Down (缩容)**：
  - 条件：`queue_depth <= scale_down_threshold` 且存在空闲实例（关联的 Node.RunningTasks == 0，且运行时长 > 10 分钟）。
  - 动作：向云厂商发起 Terminate 请求，销毁底层实例。

### 3.2 实例状态收敛与双保险兜底

为了防止因为网络异常导致云端计费流失，设计了两套兜底协程：
1. **Reconciler (实例对账 - 5min)**：查询数据库中标记为 `Running` 的实例，向云厂商拉取真实列表；若云端已不存在，则修正数据库状态为 `Terminated`。
2. **OrphanSweeper (孤儿回收 - 10min)**：扫描存活时间超过策略设定的 `instance_ttl_minutes` 的实例，强制进行销毁，防止异常实例无限计费。

### 3.3 Spot 竞价实例回收感知

- **Agent 侧**：启动时检测到环境变量 `ARGUS_SPOT=1` 或 `cloud` 标签时，激活 `StartSpotTerminationListener`。
- **中断响应**：Agent 通过内部 HTTP 元数据接口感知到云厂商（如阿里云提前 5 分钟）的回收警告。
- **自救动作**：立即触发 `EmergencyDump` 将当前处理进度回落，并放弃拉取新任务，优雅等待被系统销毁。

---

## 4. API 设计 (14 个端点)

云管控的 REST API 均在 `server/internal/api/handler_cloud.go` 中实现：

| 领域 | 动作 | API 路径 | 备注 |
|------|------|----------|------|
| **凭证** | CRUD | `/cloud/accounts` | 存储加密，返回脱敏 |
| **凭证** | Test | `/cloud/accounts/:id/test` | 测试云端连通性 |
| **策略** | CRUD | `/cloud/policies` | - |
| **策略** | Toggle | `/cloud/policies/:id/toggle` | 动态启停伸缩策略 |
| **实例** | List | `/cloud/instances` | 实例列表查询 |
| **实例** | Create | `/cloud/instances` | 人工手动弹容 |
| **实例** | Delete | `/cloud/instances/:id` | 人工强制缩容 |
| **大屏** | Dashboard | `/cloud/dashboard` | 活跃账号数、实例统计与最新事件 |

---

## 5. 开发里程碑与现状

> 相关提交：`feat(cloud): implement dynamic cloud resource scheduling` (Phase 1-7)

✅ **Phase 1-7 (已完成)**
- 完成底层所有基础设施：DB 迁移、凭证加密、AutoScaler 核心算法。
- 完成阿里云 ECS 的 Provider 接入，实现 Cloud-Init 的无缝拉起。
- 替换所有的 mock HTTP 接口为真实调度逻辑。
- 将 AutoScaler 与守护协程注入 `main.go` 并与 API 层绑定。
- 采用 Provider 注册表模式（`init()` 自注册）打通包循环依赖。

⏳ **Phase 8 (待实施)**
- **前端对接**：当前 Server-UI (`CloudManagement` 页面) 仍使用占位数据，需全面对接这 14 个已落地的后端 API。
- **多云扩展**：基于已有的 `CloudProvider` 抽象，横向补充 AWS EC2、腾讯云 CVM 等实现。
