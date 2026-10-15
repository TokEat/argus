# Argus 技术白皮书

> 本文只描述产品定位与价值主张，不维护能力清单、接口数量、进度勾选或路线图日期；架构、状态与演进的权威信息见文末文档地图。

## 1. 背景与定位

传统单机扫描工具（Nuclei、Xray 等）在单点检测中表现出色，但面对大规模、高频次的攻击面管理需求存在明显边界：单机带宽与 CPU 的性能瓶颈、缺乏中心化任务管理与断点恢复、扫描结果碎片化难以形成持续资产画像、规则集各自维护难以统一治理。

Argus 是一个分布式攻击面管理（ASM）与漏洞巡航平台。它保留单机 CLI 的高效扫描能力，核心价值在于**平台化、分布式、规则中心化与结果聚合化**：将孤立的扫描节点转变为可治理、可调度、可扩展的统一控制面。

### 核心能力

- **可横向扩展的数据面**：Scanner Agent 节点按需接入，容量感知并主动认领任务。
- **中心化控制面**：Web UI 与 `/api/v1` API 统一下发任务、回收结果、治理规则。
- **统一弹药库**：POC / 指纹 / Workflow / Dir 规则中心化审批、版本化分发与回滚。
- **实时结果感知**：结果流式回传、防洪落库，自动构建资产画像。

## 2. 架构概览

Argus 采用控制面（Control Plane）与数据面（Data Plane）分离的结构：

- 控制面 `server/`：Gin REST API、RabbitMQ 多优先级调度队列（urgent/normal/low，手动 ACK/NACK 与死信回收）、gRPC 服务（注册/心跳/认领/流式结果/日志）、PostgreSQL 唯一事实源。
- 数据面 `scanner/`：Agent 通过 gRPC 认领子任务，执行探活、端口、协议、指纹到 POC 的完整流水线，结果实时回传；Agent 无状态、用后即抛，节点异常时任务由队列回收与数据库恢复兜底。
- 结果采用资产 / 指纹 / 漏洞三层建模，BatchWriter 批量落库保护 PostgreSQL 写入稳定性。

调度采用 Agent-Pull 模型：Server 维护任务池并广播通知，Agent 根据本地并发槽位发起 `ClaimTask`，标签匹配发生在领取阶段。详细架构见 [分布式扫描架构](distributed-scan-architecture.md)。

## 3. 典型场景

| 场景 | 说明 |
| --- | --- |
| 红队外网资产高频巡航 | 多地多出口 Agent 分散 IP 承接高并发切片任务，规避单点封禁；可结合云资源弹性调度按需扩容 |
| 企业周期性基线排查 | 各网段部署内部 Agent，中央下发高危漏洞专项任务，结果汇聚统一面板 |
| 漏洞规则统一治理 | POC 入库审核后一键分发全量 Agent，实现"一处更新，全网具备检测能力" |

## 4. 文档地图

| 主题 | 文档 |
| --- | --- |
| 项目结构与入口 | [project-structure.md](project-structure.md) |
| 实现状态与接口清单 | [implementation-status.md](implementation-status.md) |
| 分布式架构、Agent-Pull 调度与扫描流水线 | [distributed-scan-architecture.md](distributed-scan-architecture.md) |
| 数据库设计 | [db_schema.md](db_schema.md) |
| 租户隔离与 RBAC | [tenant-rbac.md](tenant-rbac.md) |
| 云资源弹性调度 | [cloud-resource-scheduling.md](cloud-resource-scheduling.md) |
| 扫描策略契约 | [scan-policy-v1.md](scan-policy-v1.md) |
| Yaksha EXP | [yaksha-exp.md](yaksha-exp.md) |
| AI Copilot | [ai_copilot_architecture.md](ai_copilot_architecture.md) |
| 发布验收 | [release-checklist.md](release-checklist.md) |

> Argus 致力成为企业安全资产与漏洞管理的基石，用技术消除安全运营过程中的重复劳动与盲区。
