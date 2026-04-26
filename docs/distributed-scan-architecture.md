# 分布式扫描架构现状

本文档描述当前仓库已经接入主链路的分布式扫描架构，以及还没有闭环的关键缺口。

## 1. 总体结构

Argus 当前采用典型的 `Control Plane + Data Plane` 结构：

- 控制面 `server/`
  - 负责任务创建、任务拆分、队列调度、节点注册、规则管理、结果聚合、系统管理
- 数据面 `scanner/`
  - 负责节点注册、拉取任务、执行扫描流水线、流式回传结果
- 协议层 `shared/proto/`
  - 负责定义 Agent 与 Server 之间的 gRPC 协议
- 前端 `server-ui/`
  - 负责展示任务、节点、结果、规则和部分系统配置

## 2. 控制面当前职责

### API 层

当前主链路全部走 `server/internal/api/router.go`。

已接入能力：

- JWT 登录与租户识别
- RBAC 中间件
- 任务创建 / 删除 / 取消 / 追加目标
- 结果查询与融合画像
- Arsenal CRUD / 审批 / Manifest / 回滚
- 用户管理、MCP Key 管理
- 云实例 mock 管理、构建产物列表
- 统计接口与 Agent 日志查询

当前问题：

- HTTP 业务逻辑仍集中在 `router.go`
- `core/usecase` 和 `/api/v2` 适配器仍未接线

### 调度层

当前调度器位于 `server/internal/scheduler/queue.go`，已实现：

- RabbitMQ 多优先级队列
- 内存 fallback
- Dead-Letter 回收
- 旧队列迁移
- 队列深度 / Pending 统计

当前问题：

- 高级调度仍未完全打通
- 任务创建接口未暴露 `agent_selector`
- Agent 容量无法上报，导致服务端视角的容量仍固定为 `1`

### gRPC 层

当前 gRPC 服务位于 `server/internal/grpc/server.go`，已实现：

- `Register`
- `Heartbeat`
- `FetchTask`
- `StreamResult`
- `TaskComplete`
- `EmergencyDump`
- `StreamLogs`

当前问题：

- `Register` 返回的是占位 token，而不是可用于后续 REST 鉴权的真实令牌
- `TaskComplete` 对 `DONE` 场景聚合较完整，但 `FAILED / CANCELLED / TIMEOUT` 的根任务状态收敛仍不完整

### 结果存储层

当前数据库模型位于 `server/internal/db/db.go`，采用三层结果模型：

- `Asset`
- `FingerprintHit`
- `Vulnerability`

已接入能力：

- PostgreSQL migration runner + schema verify
- BatchWriter 异步防洪落库
- 趋势 / 严重度 / 任务结果统计
- 漏洞 CSV 导出

当前问题：

- 虽然 `Asset` 模型已有 `CertSubject / CertExpiry` 字段，但当前主链路未看到完整证书采集闭环
- 统计接口已完成，Dashboard 仍未完全消费这些真实聚合结果

## 3. 数据面当前职责

### Agent 生命周期

当前 Agent 位于 `scanner/internal/agent/worker.go`，已接入：

- 启动后 `Register`
- 周期性 `Heartbeat`
- `FetchTask` 拉取任务
- 本地执行扫描流水线
- 通过 `StreamResult` 流式回传结果
- 通过 `TaskComplete` 上报完成状态

### 规则同步

当前 Agent 已具备：

- 本地 `.manifest.json`
- 服务端 `manifest` 拉取
- 基于哈希的差异下载
- 全量同步降级逻辑

当前问题：

- Agent 通过裸 `http.Get` 访问 `/api/v1/arsenals/manifest` 和 `/api/v1/agents/:id/commands`
- 这些接口位于 JWT 中间件之后
- `Register` 返回 token 未被 Agent 保存和使用

结论：

- “增量同步框架”已经存在
- “规则热同步主链路”还没有真正闭环

### 取消与中断

当前 Agent 已实现：

- `commandLoop` 轮询控制指令
- `context.Cancel` 中断正在执行的扫描任务

当前问题：

- 轮询控制接口同样受 JWT 保护，但 Agent 未携带鉴权

### 并发执行

当前 Agent 已具备 Worker Pool 与引擎并发上限协同控制框架。

当前问题：

- Agent 启动参数虽然支持 `-workers`
- 但服务端节点容量固定为 `1`
- 因此调度端并不能真正利用多 worker 能力

### Spot 回收

当前已有 `StartSpotTerminationListener` 实现，并已在 Agent 启动链路中激活。

- 环境变量 `ARGUS_SPOT=1` 或 `--tags` 包含 `cloud` 标签时自动启用
- 检测到竞价实例回收通知后，触发 `EmergencyDump` 并通过心跳将任务状态重置回队列

## 4. 任务流转现状

当前真实任务链路如下：

1. 前端或 API 调用 `POST /api/v1/tasks`
2. 服务端规范化目标与配置
3. 服务端生成 `RootTask`
4. 服务端按 256 个目标切分为多个 `SubTask`
5. 服务端将 `SubTask` 序列化后写入 RabbitMQ 优先级队列
6. Agent 通过 gRPC `FetchTask` 拉取任务
7. 服务端将命中的 `SubTask` 状态改为 `Running`
8. Agent 执行扫描流水线
9. Agent 通过 `StreamResult` 连续回传结果
10. 服务端异步写入结果表
11. Agent 调用 `TaskComplete`
12. 服务端聚合 RootTask 进度，并在需要时 ACK 队列消息

补充链路：

- 死节点恢复：由 `server/cmd/dddd-server/main.go` 周期扫描掉线节点并重入队
- 超时重试：由 `StartTaskTimeoutDaemon` 扫描 `timeout_sec`，可重试则重入队，不可重试则标记 `Timeout`

当前问题：

- `DONE` 之外的终态收敛还不完整
- 根任务状态机仍偏粗

## 5. 规则中心现状

当前规则中心由 `arsenals` 与结构化规则表共同组成：

- `arsenals`
  - 作为原始规则仓库
  - 直接服务 Agent 同步
- 结构化规则表
  - 作为检索、统计、治理层

当前已接入：

- POC / Finger / Workflow / Dir 四类规则管理
- 审批状态 `Draft / Approved`
- `hash` / `previous_hash`
- `manifest`
- 回滚接口
- 启动时结构化回填

当前问题：

- AI 审查仍是 mock
- GoPoc / EXP 还没有动态元数据中心

## 6. 云资源编排现状

当前云资源编排代码位于：

- `server/internal/cloud/provider.go` — CloudProvider 抽象接口 + InstanceConfig
- `server/internal/cloud/provider_factory.go` — Provider 注册表模式工厂（打破循环导入）
- `server/internal/cloud/autoscaler.go` — AutoScaler 自动伸缩引擎
- `server/internal/cloud/manager.go` — ResourceManager 实例生命周期管理（含 DB 持久化）
- `server/internal/cloud/cloudinit.go` — Cloud-Init 模板引擎
- `server/internal/cloud/crypto.go` — AES-256-GCM 凭证加解密
- `server/internal/cloud/aliyun/ecs.go` — 阿里云 ECS Provider（已 init 自注册）

### 已实现并接入主链路

- **AutoScaler 决策循环**：在 `main.go` 中启动，每 30 秒评估队列深度与伸缩策略
  - Scale Up：队列积压 > threshold 且 实例数 < max → 创建 ECS 实例
  - Scale Down：队列空闲 且 存在闲置实例 且 实例数 > min → 销毁实例
  - 冷却期机制防止扩缩容震荡
- **实例对账协程**：每 5 分钟对比 DB 中 Running 实例与云端实际状态
- **孤儿回收协程**：每 10 分钟清理超过策略 TTL 的实例
- **数据库持久化**：`cloud_accounts`、`cloud_scaling_policies`、`cloud_instances` 三表
- **凭证安全**：AES-256-GCM 加密存储 AccessKey，API 返回脱敏
- **Cloud-Init 自动化**：Go template 渲染 Agent 启动脚本，注入 Server 地址、AgentID、PSK
- **14 个 REST API 端点**：凭证 CRUD + 连通性测试、策略 CRUD + 开关、实例列表/创建/销毁、仪表盘
- **Provider 注册表模式**：aliyun 包在 `init()` 中自注册，`cloud` 包不直接导入 Provider 子包
- **Spot 实例支持**：Agent 启动时自动激活 `StartSpotTerminationListener`（检测 `ARGUS_SPOT=1` 或 cloud 标签）

### 当前限制

- 前端 CloudManagement 页面尚未对接新 API（仍使用占位数据）
- 仅实现阿里云 ECS Provider，AWS/腾讯云需通过注册表扩展
- 未实现人工审批流（扩容直接执行）

## 7. 前端现状

### 已基本可用

- Login
- Dashboard
- NodeManagement
- TaskManagement
- TaskResults
- ProfilesView
- POC / Workflow / Dir 配置页
- UserManagement
- McpConfig

### 仍有明显断点

- Dashboard 的 WebSocket 鉴权方式与服务端不一致
- Dashboard 仍有部分前端静态推算图表
- CloudManagement 中的凭证与策略链路未闭环
- ClientBuild 只能看到产物列表，不能真正触发构建闭环
- 遥测日志已有后端接口，但没有前端页面入口
- RoleManagement 还是静态展示页

## 8. 当前最关键的缺口

如果只看主链路，当前最需要优先解决的是：

1. Agent 鉴权链路
   - 让 Agent 能够合法访问受 JWT 保护的 REST 接口
2. RootTask 终态收敛
   - 补齐 `FAILED / CANCELLED / TIMEOUT` 的聚合逻辑
3. 节点容量与标签调度
   - 让调度真正利用多 worker 和节点路由
4. CloudManagement 前端对接
   - 前端页面接入已完成的 14 个云资源 API 端点

## 9. 建议阅读顺序

如果要继续推进分布式能力，建议按下面顺序阅读文档：

1. `docs/project-structure.md`
2. `docs/implementation-status.md`
3. `docs/interface-implementations.md`
4. 本文档
5. `docs/rule-catalog-init.md`
