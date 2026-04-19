# dddd v2.0 分布式体系架构与演进总结白皮书

## 一、项目概述

`dddd` 已经彻底结束了其作为"单兵轻量便携漏扫 CLI"的旧时代定位，成功脱胎换骨为一个**企业级、高并发、支持公有云弹性调度的分布式 ASM (Attack Surface Management) 与漏洞巡航平台**。

通过本次系统性重构，整个项目形成了清晰的 `Control Plane (控制面)` 与 `Data Plane (数据面)` 界限：
- **控制面 (`server` 目录)**：负责 HTTP Rest 通信、可视化数据聚合、审批墙构建、多租户分流、AI 审查介入以及 Redis 队列分发。
- **数据面 (`scanner` 目录)**：全面退化为轻量、"即插即毁"且接受"云端指命斩首"的游击型 Agent 探针模块，彻底释放了平行扩展的能力。

---

## 二、核心架构演进路径 (Phase 1 -> 3)

> [!NOTE]
> 标注说明：✅ = 已实现 | ⚠️ = 部分实现/骨架代码 | ❌ = 未实现

### Phase 1：数据异构化与管道防洪 (Data Modeling & Surge Protection)
打破了旧版单张 `Vuln(漏洞)` 表粗暴堆叠的所有逻辑。
1. ✅ **数据切面隔离**：将其拆解为 `Asset(资产画像)`、`FingerprintHit(指纹组件)` 与 `Vulnerability(致命漏洞)` 三大纵深业务实体库。
2. ✅ **防洪缓冲区**：由于多台 Agent 并发狂暴打点会击穿中心数据库，我们引入了由 `BatchWriter` 和 `泛型 Channel` 编织的三级异步消费防洪闸门，成功实现了数据库无锁顺滑落库。

### Phase 2：强一致性调度与"全球鹰"斩首 (Robust Scheduling & Context Kill-Switch)
颠覆了旧版随缘下发的"瞎子调度"，做到了对云端分布式任务和游荡计算资源的绝对掌控。
1. ✅ **可靠性革命**：调度内核由 Redis List 的 `Lpush` 机制直接进化为了 **Redis Streams** 协议。依靠 `XADD` 与 `XREADGROUP`，所有推送出去的资产块将被标记为 Pending In-Flight (飞行中)，必须等到 Agent 在 gRPC 完成时显式回传 `TaskComplete` (XACK)，任务才算安全落地。
2. ✅ **云端终止令**：由于 Agent 承载了极其深重的 Nuclei 扫包执行链，我们在工作线程中注入了基于 `context.Context` 的生命周期陷阱，并在 Agent 开辟了 `commandLoop` 轮询指令栈。此时 Server 端只要对一条长任务下达撤销指令，正在泥潭里挣扎的子 Agent 会立即通过 select 并发原语主动触发中断抛弃现行作业，让云架构资源回收如臂使指。

### Phase 3：运营管控堡垒与 AI 化预留 (Operation Hub & Multitenancy AI)
让平台开始从工具转向服务 (SaaS) 和智能化 (AI-Driven)。
1. ✅ **SaaS化网关**：挂载了全局 `TenantMiddleware` 拦截器，利用 JWT Authorization Header 对整个系统的 API 输入（任务投递、规则入库、导出）强行烙下并过滤所属机构的 Tenant ID，打造出完美的天然多租户环境。
2. ✅ **原生电子战报引擎**：内嵌无依赖 `encoding/csv` 流式文件组装模块（`/api/v1/reports/export/vulns`），实现百万级异构探测数据的光速导出打包服务。
3. ⚠️ **安全大模型审校桩**：上线了基于风控文本碰撞伪造的 AI 评审阻断接口 (`/api/v1/arsenals/ai/analyze`)，针对上传库的规则进行自动置信度反向审查拦截。**当前为 Mock 实现（硬编码关键词匹配），未对接真实 LLM API。**

---

## 三、代码工程全景鸟瞰

### 1. 服务端主心骨（Server Control Plane）
- ✅ **`cmd/dddd-server/main.go`**：中心网关，启动 gRPC（对接底层 Agent 流）、Gin API（对接 Web）、BatchWriter 携程簇。
- ✅ **`internal/scheduler/queue.go`**：Redis Streams 高可用调度中心，掌管拆分块向 Agent 派发与 ACK 确认的核心逻辑。含 Dead-Letter 死信回收守护协程。
- ✅ **`internal/grpc/server.go`**：负责节点握手、心跳管理以及把任务池打散成分区数据通过 Protobuf 分配。
- ✅ **`internal/api/router.go`**：面向外部业务层的 API 控制面，统辖任务取消、规则管理审核池、多租户识别与 CSV 资产画像导出。
- ✅ **`internal/db/db.go`**：PostgreSQL 联接模型，实现了以 `TenantID` 层级展开的 GORM ORM 结构。
- ⚠️ **`internal/core/`**：Clean Architecture 领域层骨架代码（TaskOrchestrator / TaskScheduler / NodeRegistry / RuleCenter / ResultAggregator / DashboardQuery），**均为 `ErrNotImplemented` 桩代码，尚未接入实际路由。**
- ⚠️ **`internal/cloud/`**：云资源编排层。接口 `CloudProvider` + `ResourceManager` 已定义，阿里云 ECS 和 Docker Provider 已有完整实现，**但未被 main.go 挂载调用。**
- ⚠️ **`internal/adapters/`**：适配器层已建好目录结构（grpcagent / httpapi / persistence / queue / ws），**但均为空壳目录，未放入实际代码。**

### 2. 数据巡航者（Scanner Agent Plane）
- ✅ **`cmd/agent/main.go`**：Agent 端主入口，持有拨测任务所需要的各种指纹和 nuclei 的本地数据实体。
- ✅ **`internal/agent/worker.go`**：拥有心跳维持器、规则中心版本热同步协程（POC/Finger/Workflow/Dir 四类）以及"全球指令监听阵列 (Kill Switch)"，把控着整个 `engine` 的生与死。
- ✅ **`internal/agent/signal.go`**：竞价实例 Spot 中断检测与紧急数据回传。
- ✅ **`internal/engine/pipeline.go`**：纯正的业务黑盒，继续执行着诸如 `存活探测 -> 端口扫描 -> Web爬取 -> Nuclei/GoPoc 探测` 的链条动作。

### 3. 前端 Web Console（server-ui）
- ✅ **登录页**：JWT 认证登录。
- ✅ **Dashboard 首页**：统计概览（任务/节点/资产/指纹/漏洞数量）。
- ✅ **节点管理**：Agent 在线状态查看。
- ✅ **任务管理**：任务创建、查看、取消、删除。
- ✅ **任务结果**：漏洞/资产/指纹分 Tab 查看。
- ✅ **融合画像**：多维度资产-指纹-漏洞聚合视图。
- ✅ **弹药库管理**：POC / 指纹 / Workflow 可视化 CRUD 管理。
- ⚠️ **实例配置 (CloudManagement)**：页面已创建，**内容为占位符。**
- ⚠️ **客户端生成 (ClientBuild)**：页面已创建，**内容为占位符。**
- ⚠️ **用户管理 (UserManagement)**：页面已创建，**内容为占位符。**
- ⚠️ **角色管理 (RoleManagement)**：页面已创建，**内容为占位符。**
- ⚠️ **MCP 配置 (McpConfig)**：页面已创建，**内容为占位符。**

---

## 四、未来展望 (The Road Ahead)

从宏架构上看，底层的发动机不仅没有被抛弃，反而被挂接在了两台推进器（流数据调度器 + 多租户防洪控制面）上。接下来的潜力挖掘极具想象空间：
- ⚠️ **容器化弹性伸缩**：Agent 目前是以协程或进程的形式执行，未来可以让 `Task Runner` 直连 K8s API，每一个任务碎片自动创建 Docker Pod 跑完即毁，做到终极资源隔离。**（Docker/阿里云 Provider 代码已写，但未集成到任务调度链路中。）**
- ✅ **前端 SPA 立项**：服务端既然已拥有了强大的战报输出、资产画像连表、规则审核与 AI 控制流能效，完全能够基于 Web 技术 (如 Vite + React) 把这些 JSON 数据呈现为极具黑客科技感的流光 Web 大屏。**（server-ui 已实现，基于 React + Ant Design + Vite。）**
- ⚠️ **大预言模型 (LLM) 落地**：目前规则库审批风控中的 Mock 代码已就位，只需要填入企业密钥（OpenAI/Deepseek），真正的自动化 AI 漏洞鉴伪将即刻启动。**（仍为 Mock 实现。）**
