# Server Internal Layout

当前 `server/internal` 同时保留两套结构：

1. 旧结构
   - `api`
   - `grpc`
   - `db`
   - `scheduler`
2. 新结构
   - `bootstrap`
   - `config`
   - `core`
   - `adapters`
   - `shared`

这样做的目的不是重复造轮子，而是为后续迁移建立稳定骨架，避免继续把任务、节点、规则、结果、调度逻辑堆在同一个包里。

## 分层约束

- `bootstrap`
  - 只负责装配依赖
  - 不写业务逻辑
- `config`
  - 只放服务端运行配置
  - 不直接依赖 HTTP / gRPC 细节
- `core/domain`
  - 只放领域模型和领域接口
  - 不依赖 Gin / gRPC / GORM / 具体消息队列实现
- `core/usecase`
  - 只放控制面的业务编排
  - 依赖 `core/domain` 接口，不依赖具体适配器
- `adapters/httpapi`
  - 只放 HTTP handler / router
  - 不写任务拆分、规则发布等核心业务细节
- `adapters/grpcagent`
  - 只放 Agent gRPC 适配层
- `adapters/persistence`
  - 只放数据库模型映射和仓储实现
- `adapters/queue`
  - 只放任务队列适配实现
- `adapters/ws`
  - 只放实时广播适配
- `shared`
  - 放通用错误、常量、辅助类型

## 迁移原则

后续迁移请遵守：

1. 新功能优先放到新结构里。
2. 旧包只做兼容和过渡，不继续扩展复杂业务。
3. 用例层先稳定，再迁移传输层和持久层。
4. 任何跨模块能力，优先通过 `core/domain` 接口解耦。
