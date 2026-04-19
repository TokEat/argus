# Argus 项目实现状态总览

> 本文档汇总 docs/ 下架构设计中描述的所有功能模块的当前实现状态。
>
> 标注说明：✅ = 已实现 | ⚠️ = 部分实现/骨架代码 | ❌ = 未实现
>
> 接口清单另见：`docs/interface-implementations.md`

---

## 一、总体完成度

| 阶段 | 状态 | 完成度 |
|------|------|--------|
| Phase 1：数据异构化与管道防洪 | ✅ 已完成 | ~95% |
| Phase 2：强一致性调度与云端斩首 | ✅ 已完成 | ~90% |
| Phase 3：运营管控堡垒与 AI 化 | ⚠️ 部分完成 | ~45% |

---

## 二、已实现功能清单 (✅)

### 控制面 (Server)
| 模块 | 功能 | 文件 |
|------|------|------|
| API Gateway | Gin REST API 全套路由 | `server/internal/api/router.go` |
| JWT 认证 | 多租户 JWT 签发与校验中间件 | `server/internal/api/router.go` |
| 任务管理 | 任务创建/查看/删除/取消 + RootTask→SubTask 拆分 | `server/internal/api/router.go` |
| gRPC 服务 | Register/Heartbeat/FetchTask/StreamResult/TaskComplete/EmergencyDump | `server/internal/grpc/server.go` |
| Redis Streams | XADD/XREADGROUP/XACK 消费组队列 + 内存 fallback | `server/internal/scheduler/queue.go` |
| Dead-Letter | 死信回收守护协程 (XPENDING/XCLAIM) | `server/internal/scheduler/queue.go` |
| 死节点扫描 | 30s 轮询标记掉线+僵尸任务重入队 | `server/cmd/dddd-server/main.go` |
| 数据库 | PostgreSQL GORM AutoMigrate 全模型 | `server/internal/db/db.go` |
| 防洪 BatchWriter | 泛型 Channel 三级异步缓冲消费 | `server/internal/db/db.go` |
| 三层结果存储 | Asset / FingerprintHit / Vulnerability 分类落库 | `server/internal/db/db.go` |
| Arsenal 管理 | POC/Finger/Workflow/Dir 的 CRUD + 审批 + Hash | `server/internal/api/router.go` |
| Dictionary API | Workflow / Fingerprint 结构化 CRUD | `server/internal/api/handler_dictionary.go` |
| Arsenal Seed | 首次启动从磁盘导入规则到 PostgreSQL | `server/internal/db/seed.go` |
| 热更新触发 | GlobalArsenalReloadCounter 全局计数器 | `server/internal/api/router.go` |
| WebSocket 推送 | 结果批量入库后 WS 广播通知 | `server/internal/api/ws.go` |
| CSV 导出 | 漏洞数据流式 CSV 导出 | `server/internal/api/router.go` |
| 融合画像 | 资产+指纹+漏洞聚合查询 | `server/internal/api/router.go` |
| Dashboard 统计 | 五维度计数 (任务/节点/资产/指纹/漏洞) | `server/internal/api/router.go` |

### 数据面 (Agent)
| 模块 | 功能 | 文件 |
|------|------|------|
| Worker 生命周期 | 注册/心跳/任务领取/执行/完成上报 | `scanner/internal/agent/worker.go` |
| 规则热同步 | POC/Finger/Workflow/Dir 四类全量同步 | `scanner/internal/agent/worker.go` |
| 指令监听 | commandLoop 轮询取消指令 + 规则重载信号 | `scanner/internal/agent/worker.go` |
| Kill Switch | context.Cancel 注入 + select 中断 | `scanner/internal/agent/worker.go` |
| Spot 检测 | 竞价实例中断元数据轮询 + EmergencyDump | `scanner/internal/agent/signal.go` |
| Scanner Engine | 完整扫描流水线 | `scanner/internal/engine/pipeline.go` |
| gRPC Stream 回传 | OutputHook → StreamResult 实时上报 | `scanner/internal/agent/worker.go` |

### 扫描引擎
| 模块 | 功能 |
|------|------|
| 空间搜索引擎 | Fofa / Hunter / Quake 三引擎集成 |
| 子域名枚举 | subfinder + 自定义爆破 |
| 存活探测 | ICMP + TCP Ping |
| 端口扫描 | TCP / SYN (Masscan) |
| 协议识别 | 全协议 Banner 抓取 |
| Web 探测 | httpx 批量 HTTP 探测 |
| 指纹识别 | 被动 + 主动目录指纹 |
| Workflow 映射 | 指纹→POC 路由 |
| 漏洞检测 | Nuclei v3 + GoPoc |

### 前端 (server-ui)
| 页面 | 功能 |
|------|------|
| Login | JWT 登录认证 |
| Dashboard | 统计概览 + 数据大屏 |
| NodeManagement | Agent 节点状态展示 |
| TaskManagement | 任务创建/查看/取消/删除 |
| TaskResults | 漏洞/资产/指纹分 Tab 结果查看 |
| ProfilesView | 融合画像多维度聚合 |
| ConfigLayout + POC/Workflow/Dir | 弹药库可视化 CRUD 管理 |

---

## 三、部分实现 / 骨架代码 (⚠️)

| 模块 | 现状 | 缺失部分 |
|------|------|----------|
| Clean Architecture 领域层 | `core/usecase/` 下全部 usecase 为 `ErrNotImplemented` 桩 | 全部业务逻辑未实现 |
| 适配器层 (Adapters) | 目录结构已创建 (grpcagent/httpapi/persistence/queue/ws) | 全部为空壳目录 |
| 云资源编排 | `CloudProvider` 接口 + 阿里云 ECS / Docker Provider 已实现 | 未被 main.go 挂载调用 |
| AI 规则审查 | Mock 实现 (关键词匹配) | 未对接真实 LLM API |
| 任务模型字段 | `priority / timeout_sec / retry_count / rule_version` 字段已添加 | 业务逻辑未使用 |
| 节点模型字段 | `tags` 字段存在 | 注册/调度未使用 |
| Agent 并发 | Worker Pool 框架存在 | 硬编码为 maxWorkers=1 |
| 规则版本管理 | Arsenal 表 Hash 字段存在 | Agent 端未做本地 Hash 比对 |
| gRPC StreamLogs | 遥测日志上传方法已写，代码被注释 | 未生成对应 proto stub |
| 前端占位页面 | CloudManagement / ClientBuild / UserManagement / RoleManagement / McpConfig | 仅为占位符组件 |

---

## 四、未实现功能清单 (❌)

| 类别 | 未实现功能 |
|------|-----------|
| **调度策略** | 任务优先级调度、节点标签路由、节点容量限额 |
| **任务增强** | 完整任务状态机 (Dispatching/PartialDone/Timeout)、基于 timeout_sec 的超时终止、retry_count 自动重试、任务类型字段 |
| **规则治理** | 显式版本号机制、增量规则同步、规则回滚、多级审批流程 |
| **节点管理** | 节点版本存储、能力标签、容量统计、running_tasks 跟踪 |
| **容器化** | 每任务容器隔离执行、网络代理/CPU/内存限制 |
| **数据增强** | 证书信息采集、task_result 聚合统计表 |
| **报表展示** | 漏洞趋势图、专题报告导出、可视化大屏组件 |
| **LLM 落地** | 真实 AI 辅助规则审查（当前 Mock） |
| **系统管理** | 用户管理 CRUD、角色权限 RBAC、MCP 配置、客户端自动构建 |
| **对象存储** | 独立文件/对象存储层（POC 包、规则包、报告文件） |
| **EXP 管理** | GoPoc/EXP 元数据动态管理 |
| **租户配额** | 租户级别的任务配额限制 |

---

## 五、下一步建议优先级

| 优先级 | 功能 | 说明 |
|--------|------|------|
| P0 | 激活任务字段 | 让 priority / timeout_sec / retry_count 在创建和调度中生效 |
| P0 | 节点版本存储 | Register 时将 version 写入 Node 模型 |
| P1 | 完善前端占位页面 | CloudManagement / UserManagement 等核心管理页面 |
| P1 | 集成容器化 Runner | 将现有 Docker/阿里云 Provider 挂载到任务调度链路 |
| P1 | 规则增量同步 | Agent 本地 Hash 比对，仅拉取变更规则 |
| P2 | Clean Architecture 迁移 | 将 router.go 中的业务逻辑迁移到 core/usecase |
| P2 | 高级调度策略 | 节点标签路由 + 优先级调度 |
| P3 | 真实 LLM 对接 | AI 规则审查 Mock 替换为 OpenAI/DeepSeek API |
| P3 | RBAC 权限系统 | 用户管理 + 角色权限 + 多级审批 |
