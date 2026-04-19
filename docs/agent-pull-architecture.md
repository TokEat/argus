# Argus 分布式扫描引擎调度架构：Agent-Pull 模式

本文档详细记录了 Argus 分布式扫描引擎从早期的“Server 强管控下推”演进到“Agent 按需拉取 (Agent-Pull)”的核心架构设计。该设计旨在解决长连接风暴、跨网络 NAT 穿透以及复杂故障恢复机制带来的痛点，实现天然的解耦、高可靠性与极致的横向扩展能力。

## 1. 架构核心思想

在新版的架构中，Server 不再作为“任务分配的决策者”去硬性追踪和派发任务，而是转变为**“任务池的维护者”与“事件通知器”**。Agent 作为主动方，根据自身的计算能力（并发槽）来主动认领并消费任务。

### 核心解耦点
- **拒绝 Server 端容量拦截**：Server 不再维护 Agent 的 `running_tasks` 与 `capacity` 的强耦合计算，彻底交由 Agent 本地的 semaphore (信号量) 自主决策。
- **纯粹的可用性容错**：废除了数据库层面的“扫描 60 秒死节点并强制抢救任务”的业务代码。所有的容错与状态回收，完全交由底层的 Redis Stream (消息队列) 的 `Visibility Timeout` (不可见超时) 和 `ACK` (确认) 机制原生保障。

---

## 2. 核心调度流程

完整的任务流转过程如下：

### 第一步：任务创建与广播通知 (Notification)
1. **任务入队**：用户在 Server 端创建扫描任务。Server 会将任务切割为多个 SubTask，并**按优先级入队到 Redis Stream**。
2. **事件广播**：入队完成后，Server 层通过内置的 `NotifyHub` 模块，向所有维持了 `Subscribe`（双向流）长连接的在线 Agent 发送 `TaskNotify` 广播：“队列里有新任务了，有空闲的来认领”。

### 第二步：主动认领任务 (ClaimTask)
1. **并发决策**：Agent 接收到通知后，会检查本地的并发池（通过 Go Channel Semaphore 控制）。如果本地计算资源已满，它会忽略通知；如果**有空余**，则立刻向 Server 发起单次 `ClaimTask` (或 `FetchTask`) 的 gRPC 请求。
2. **原子领取防重**：Server 接收到 `ClaimTask` 后，调用底层的 Redis `XREADGROUP`。由于使用了 Redis 的**消费者组 (Consumer Group)** 特性，`XREADGROUP` 具有**天然的原子性**，保证了同一个任务只会被弹出一个在线的 Agent 领走，**绝对不会出现多 Agent 重复领取的问题**。
3. **标签匹配与重试**：弹出的任务如果与该请求的 Agent 标签 (Tags) 不匹配，Server 会立刻触发 `returnTaskHook` 将任务按原优先级退回，并在同一次请求中自动继续弹下一个任务，直到找到匹配的任务交还给 Agent。

### 第三步：任务消费与实时回传 (Execution & StreamResult)
1. Agent 获取到任务后，剥离出一个 Worker 协程开始执行底层扫描引擎。
2. 扫描过程中发现的漏洞、指纹、端口等中间结果，通过挂载的 `StreamResult` 实时单向流速推回 Server，保障哪怕扫描未全部完成也能及时呈现阶段性成果。

### 第四步：任务完成与 ACK (TaskComplete)
1. 任务彻底执行完毕后，Agent 触发 `TaskComplete` 接口通知 Server。
2. **ACK 确认**：Server 在数据库中更新此 SubTask 的状态，并**立刻调用 `XACK` 告知 Redis Stream 该任务已被彻底消费**，可以从 Pending 列表中安全移除。
3. **防闲置连带通知**：为了保证资源的极限利用，在处理完 `TaskComplete` 后，Server 会立即顺手查一下队列深度（`queueDepth`）。如果队列里还有任务，Server 会在当前这一步**主动再次通知**该 Agent（通过 `NotifyHub`），督促它立刻发起下一次 `ClaimTask`。这保证了没有任何在线空闲的 Agent 会被遗漏。

---

## 3. 容错与高可用设计 (Visibility Timeout)

在分布式场景下，Agent 面临着网络波动、断电、被 OOM Kill 或竞价实例被云厂商回收的诸多突发风险。基于 Agent-Pull 与 Redis Stream 的天然容错流程如下：

- 当 Agent 通过 `ClaimTask` 从 Redis Stream 取走任务时，任务并未被删除，而是进入了 Redis 的 **Pending Entries List (PEL)**。
- 此时任务处于“执行中”状态，带有 `Idle Time` (空闲时间) 计时。
- 如果 Agent 顺利执行完毕并走完 `TaskComplete`，发送 `XACK`，任务才会从 PEL 中彻底移除。
- **宕机异常情况**：如果 Agent 中途挂掉，永远不发回 `XACK`，它所持有的任务的 `Idle Time` 就会持续增加。
- **守护拯救机制 (daemonSalvage)**：Server 的调度器底层包含一个轻量级的抢救协程，每 5 分钟遍历一次 PEL。若发现某个任务的 `Idle Time` 超过了阈值（例如 30 分钟没有被 ACK），它会触发 `XCLAIM` 将任务回收，并**强制将其提升塞入最高优先级的 `Urgent` 队列**，等待其他存活的 Agent 第一时间认领。

通过此机制，Server 完全不需要去猜测或定时 ping 每个 Agent 来决定要不要剥夺它的任务，彻底避免了“脑裂”或“误抢救”的问题。

## 4. 总结

全新的 **Agent-Pull 模式 + Redis Consumer Group (PEL)** 架构，实现了如下工业级指标：

1. **极致横向扩展**：Agent 只要有凭证即可接入，只需关心本地的并发限制，连上就疯狂拉取，部署无需关心任何跨网映射。
2. **天然容错**：基于 Visibility Timeout 和 ACK，完美处理节点异常掉线、网络闪断，且无任何重试风暴。
3. **高吞吐抗压**：Server 的职责被弱化到了极致的“无脑转发”，高并发分发压力全部被下沉、缓冲到 Redis Stream。
4. **资源零闲置**：依靠 `Subscribe` 实时通知机制与 `TaskComplete` 时的深度校验防饥饿兜底，保障了系统整体吞吐率始终维系在最高水位。
