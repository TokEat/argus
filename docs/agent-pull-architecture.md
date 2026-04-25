# Argus 分布式扫描引擎调度架构：Agent-Pull 模式

> 相关文档：[project-structure.md](project-structure.md) | [distributed-scan-architecture.md](distributed-scan-architecture.md)

本文档详细记录了 Argus 分布式扫描引擎从早期的“Server 强管控下推”演进到“Agent 按需拉取 (Agent-Pull)”的核心架构设计。该设计旨在解决长连接风暴、跨网络 NAT 穿透以及复杂故障恢复机制带来的痛点，实现天然的解耦、高可靠性与极致的横向扩展能力。

## 1. 架构核心思想

在新版的架构中，Server 不再作为“任务分配的决策者”去硬性追踪和派发任务，而是转变为**“任务池的维护者”与“事件通知器”**。Agent 作为主动方，根据自身的计算能力（并发槽）来主动认领并消费任务。

### 核心解耦点
- **拒绝 Server 端容量拦截**：Server 不再维护 Agent 的 `running_tasks` 与 `capacity` 的强耦合计算，彻底交由 Agent 本地的 semaphore (信号量) 自主决策。
- **双保险容错**：队列层通过 RabbitMQ 的未确认投递和 `ACK/NACK` 机制保障消息可回收，数据库层继续负责死节点识别与运行中任务的补投，避免单点状态漂移。

---

## 2. 核心调度流程

完整的任务流转过程如下：

### 第一步：任务创建与广播通知 (Notification)
1. **任务入队**：用户在 Server 端创建扫描任务。Server 会将任务切割为多个 SubTask，并**按优先级入队到 RabbitMQ 的 `urgent / normal / low` 队列**。
2. **事件广播**：入队完成后，Server 层通过内置的 `NotifyHub` 模块，向所有维持了 `Subscribe`（双向流）长连接的在线 Agent 发送 `TaskNotify` 广播：“队列里有新任务了，有空闲的来认领”。

### 第二步：主动认领任务 (ClaimTask)
1. **并发决策**：Agent 接收到通知后，会检查本地的并发池（通过 Go Channel Semaphore 控制）。如果本地计算资源已满，它会忽略通知；如果**有空余**，则立刻向 Server 发起单次 `ClaimTask` (或 `FetchTask`) 的 gRPC 请求。
2. **原子领取防重**：Server 接收到 `ClaimTask` 后，会按优先级顺序调用 RabbitMQ `basic.get` 拉取消息，并将该投递记录到服务端的 pending 集合中。单条消息在未确认前只会被一个 Agent 持有，**不会出现多 Agent 重复领取的问题**。
3. **标签匹配与重试**：弹出的任务如果与该请求的 Agent 标签 (Tags) 不匹配，Server 会立刻触发 `returnTaskHook` 对该消息执行 `NACK requeue`，并在同一次请求中自动继续尝试下一个任务，直到找到匹配的任务交还给 Agent。

### 第三步：任务消费与实时回传 (Execution & StreamResult)
1. Agent 获取到任务后，剥离出一个 Worker 协程开始执行底层扫描引擎。
2. 扫描过程中发现的漏洞、指纹、端口等中间结果，通过挂载的 `StreamResult` 实时单向流速推回 Server，保障哪怕扫描未全部完成也能及时呈现阶段性成果。

### 第四步：任务完成与 ACK (TaskComplete)
1. 任务彻底执行完毕后，Agent 触发 `TaskComplete` 接口通知 Server。
2. **ACK 确认**：Server 在数据库中更新此 SubTask 的状态，并**立刻调用 `ACK` 告知 RabbitMQ 该任务已被彻底消费**，可以从未确认投递集合中安全移除。
3. **防闲置连带通知**：为了保证资源的极限利用，在处理完 `TaskComplete` 后，Server 会立即顺手查一下队列深度（`queueDepth`）。如果队列里还有任务，Server 会在当前这一步**主动再次通知**该 Agent（通过 `NotifyHub`），督促它立刻发起下一次 `ClaimTask`。这保证了没有任何在线空闲的 Agent 会被遗漏。

---

## 3. 容错与高可用设计

在分布式场景下，Agent 面临着网络波动、断电、被 OOM Kill 或竞价实例被云厂商回收的诸多突发风险。基于 Agent-Pull 与 RabbitMQ 的容错流程如下：

- 当 Agent 通过 `ClaimTask` 从 RabbitMQ 取走任务时，任务并不会立刻删除，而是保持在“已投递未确认”状态。
- 如果 Agent 顺利执行完毕并走完 `TaskComplete`，Server 对对应消息执行 `ACK`，该任务才会被真正消费。
- **宕机异常情况**：如果 Agent 中途挂掉，永远不发回完成信号，这条消息会一直处于未确认状态。
- **守护拯救机制 (staleSalvage)**：Server 的调度器底层包含一个轻量级的抢救协程，定期扫描本进程持有但长时间未确认的投递；若超过阈值（例如 30 分钟），则执行 `NACK requeue`，让消息回到队列中重新分发。
- **死节点恢复机制**：除了队列层回收外，控制面还会根据心跳将 Agent 标记为 `Offline`，并把数据库中仍处于 `Running / CancelPending` 的子任务重新标记并补投到高优先级队列，形成额外兜底。

通过“队列层未 ACK 回收 + 数据库层死节点补投”两套机制叠加，Server 可以在不牺牲吞吐的前提下稳住任务恢复链路。

## 4. 总结

全新的 **Agent-Pull 模式 + RabbitMQ 手动 ACK 调度** 架构，实现了如下工业级指标：

1. **极致横向扩展**：Agent 只要有凭证即可接入，只需关心本地的并发限制，连上就疯狂拉取，部署无需关心任何跨网映射。
2. **天然容错**：基于 `ACK/NACK`、超时回收和死节点补投，完美处理节点异常掉线、网络闪断，且无任何重试风暴。
3. **高吞吐抗压**：Server 的职责被弱化到了极致的“无脑转发”，高并发分发压力被缓冲到 RabbitMQ 多优先级队列。
4. **资源零闲置**：依靠 `Subscribe` 实时通知机制与 `TaskComplete` 时的深度校验防饥饿兜底，保障了系统整体吞吐率始终维系在最高水位。
