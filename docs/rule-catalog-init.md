# 规则库 PostgreSQL 初始化设计

> 相关架构文档：[db_schema.md](db_schema.md) | [project-schema-design.md](project-schema-design.md) | [agent-pull-architecture.md](agent-pull-architecture.md)

当前控制面将规则数据拆成两层：

- `arsenals`
  作为原始规则文件仓库，直接服务于 Agent 的增量/全量同步。
- 结构化规则表
  作为数据库初始化后的查询层，便于统计、检索、后续审批与治理。

## 结构化表

新增以下表：

- `rule_catalog_bootstraps`
  记录规则目录初始化状态、源哈希、初始化时间与错误信息。
- `fingerprint_rules`
  每条指纹表达式一行，字段包含产品名、规则表达式、来源文件、版本、状态。
- `poc_rules`
  每个 POC 模板一行，字段包含模板名、文件名、严重度、作者、描述、哈希、状态。
- `workflow_rules`
  每个 `product -> poc -> match_type` 映射一行。
- `dir_rules`
  每个主动探测路径一行。

## 初始化流程

启动 `dddd-server` 时执行：

1. 规范化历史 `arsenals.type`
   将旧类型别名统一为：
   - `fingerprint -> finger`
   - `dirprobe -> dir`
2. 如果 `arsenals` 为空，则从 `scanner/common/config` 首次导入：
   - `finger.yaml`
   - `workflow.yaml`
   - `dir.yaml`
   - `pocs/*.yaml`
3. 计算当前 `arsenals` 的聚合哈希。
4. 如果聚合哈希未变化，则跳过结构化回填。
5. 如果聚合哈希变化，则重建结构化规则表。

## 设计原则

- `arsenals` 仍然是 Agent 下发的原始来源，不改变现有同步协议。
- 结构化表由 `arsenals` 物化生成，避免出现两套独立真相源。
- 保存、审批、删除、回滚规则后，都会重新同步结构化规则表。
- 字典编辑接口对 `finger.yaml` / `workflow.yaml` 的修改，也会联动刷新结构化表。

## 兼容性

- 旧库中已经存在的 `fingerprint_finger.yaml`、`dirprobe_dir.yaml` 等历史类型，会在启动时自动迁移到规范类型。
- Agent 侧同步仍使用 `poc` / `finger` / `workflow` / `dir` 四类。

