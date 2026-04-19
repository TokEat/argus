# 贡献与协作指南

本项目推荐使用 `main + 短生命周期任务分支 + 可选 release/hotfix` 的分支模型。

目标很简单：

- `main` 始终保持可构建、可发布
- 所有功能开发和问题修复都通过独立分支完成
- 通过 PR 做代码评审、CI 校验和合并控制

## 分支模型

### 长期分支

| 分支 | 用途 | 说明 |
|------|------|------|
| `main` | 稳定主线 | 默认分支，禁止直接提交，任何变更都通过 PR 合并 |
| `release/*` | 版本冻结分支 | 仅在需要提测、预发布、版本冻结时创建，不作为日常开发主线 |

说明：

- 默认不引入 `develop`
- 对当前项目规模，`develop` 往往只会增加合并成本和分支漂移风险
- 当团队后续出现“长周期并行版本开发 + 严格预发冻结”的明确需求时，再考虑是否引入额外长期分支

### 短生命周期分支

| 类型 | 示例 | 用途 |
|------|------|------|
| `feat/*` | `feat/node-heartbeat-timeout` | 新功能 |
| `fix/*` | `fix/grpc-stream-reconnect` | 缺陷修复 |
| `refactor/*` | `refactor/scheduler-queue-model` | 重构，不改变外部行为 |
| `chore/*` | `chore/upgrade-gorm` | 构建、依赖、脚本、工程维护 |
| `docs/*` | `docs/update-deploy-guide` | 文档更新 |
| `hotfix/*` | `hotfix/login-token-expiry` | 线上紧急修复 |

命名建议：

- 使用英文小写
- 单词之间使用 `-`
- 一条分支只做一件事
- 分支名尽量体现模块和目的，避免 `feat/test`、`fix/bug` 这类无信息名称

## 推荐工作流

### 1. 从最新 `main` 创建任务分支

```bash
git switch main
git pull origin main
git switch -c feat/your-change
```

### 2. 在任务分支内完成开发和自测

建议在提交前至少完成：

- 相关模块构建通过
- 相关测试执行通过
- 必要的接口或页面自测通过

### 3. 推送分支并创建 PR

```bash
git push -u origin feat/your-change
```

PR 标题建议直接说明改动结果，例如：

- `feat: 支持节点超时自动剔除`
- `fix: 修复任务队列重复确认问题`

### 4. 通过评审后合并回 `main`

合并建议：

- 优先使用 `Squash and merge`
- 保持 `main` 历史干净，避免大量零碎提交进入主线
- 分支合并后及时删除远端和本地任务分支

## 发布流程

### 日常发布

如果团队规模不大、发布节奏较快，直接从 `main` 打 tag 即可：

```bash
git switch main
git pull origin main
git tag v1.0.0
git push origin v1.0.0
```

适用场景：

- 开发和测试节奏紧密
- `main` 已经受 PR 和 CI 保护
- 不需要单独维护“待发布版本”

### 冻结发布

当某个版本需要集中提测、修缺陷、控制变更范围时，再创建 `release/*`：

```bash
git switch main
git pull origin main
git switch -c release/v1.0.0
git push -u origin release/v1.0.0
```

规则：

- `release/*` 只接收发布相关修复，不继续堆新功能
- 发布完成后，将必要修复同步回 `main`
- 版本最终以 tag 作为发布标识

## Hotfix 流程

线上紧急问题使用 `hotfix/*`：

```bash
git switch main
git pull origin main
git switch -c hotfix/your-fix
```

处理完成后：

- 先通过 PR 合并回 `main`
- 如果当前存在未结束的 `release/*` 分支，需要把同样修复同步到对应 `release/*`

## 对 `main` 的保护建议

建议在代码托管平台开启以下规则：

- 禁止直接 push 到 `main`
- 必须通过 PR 合并
- 至少 1 位 reviewer 批准
- CI 通过后才能合并
- 合并前要求分支同步最新 `main`
- 禁止使用 rebase/merge commit 直灌主线时，可优先保留 squash merge

## 团队协作约束

- 一个分支只处理一个需求或一个缺陷
- 一个 PR 只解决一类问题，避免把功能、重构、格式化混在一起
- 分支尽量短命，建议在 1 到 3 天内完成合并
- 不要长期滞留未合并分支，否则冲突成本会快速上升
- 发版以 tag 为准，不建议用 `test`、`staging` 这类环境分支代替发布管理

## 适用于当前项目的最小分支集合

当前仓库建议至少使用以下分支类型：

- `main`
- `feat/*`
- `fix/*`
- `refactor/*`
- `chore/*`
- `docs/*`
- `hotfix/*`

以下分支按需启用：

- `release/*`

这套模型足够支持多人并行开发，同时不会把分支体系搞得过重。
