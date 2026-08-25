# Yaksha EXP

Argus EXP 的唯一产品实现是 Yaksha。每个 EXP 的唯一权威源码是单个 `main.yak`，同时承载官方 `cli.*` 参数声明与执行逻辑；复杂逻辑通过锁定 Revision 的子 EXP 组合，Payload、字典和样本通过哈希绑定的 Asset 引用，不引入宿主文件路径、多文件 include 或可变源码包。

## 权威模型

```text
Exp
├── metadata
├── revisions/<revision>/main.yak
├── dependencies
├── asset_refs
├── test_cases
└── runs
```

- 修改源码只创建递增 Draft Revision，不覆盖旧版本。
- Published Revision 不可变，发布要求 inspect、validate 和 Fixture 验收通过。
- 发布由 Admin 使用预期源码哈希人工确认；回滚只切换活动 Published Revision 并写审计。
- 上图为治理层逻辑模型；物理对象存储按内容寻址（如 `exp/sources/<sha256>/main.yak`），Revision 是绑定内容哈希的治理引用，不代表目录路径。
- 生产对象存储为私有 MinIO；LocalStore 只允许显式开发模式。
- Debug Trace 完整未脱敏，正文按保留期删除，摘要和审计永久保留。

## 产品与漏洞利用族

EXP 库按“产品 → 漏洞 EXP → 利用分支”组织。一个漏洞利用族包含一个根 EXP 和零到多个子 EXP：

```text
Apache Shiro
└── CVE-2016-4437
    ├── main.yak
    ├── dnslog.yak
    ├── command.yak
    └── memshell.yak
```

- 根 EXP 的源码在界面中固定显示为 `main.yak`，负责公共前置检查和选择利用方式。
- 每个子 Yak 在存储和执行模型中仍是独立 EXP，通过 `parent_exp_id + variant_key` 归入同一漏洞；拥有独立 Revision、CLI Schema、Fixture、风险级别、发布状态和审计记录。
- 根 Revision 使用确定 Revision 与源码哈希的 `yaksha.call` 锁定子 EXP。界面层级不是运行时授权，不会自动发布或授权子分支。
- 父子关系只允许两层且必须同租户、同产品；旧 EXP 自动归入“未分类”。
- “删除 EXP”是保留治理证据的软删除：状态变为 `deprecated` 并默认隐藏。删除根 EXP 会在同一事务内同步废弃全部利用分支并逐项记录审计。

## 源码标准

```yak
target = cli.String("target", cli.setVerboseName("目标地址"), cli.setRequired(true))
cli.check()

yaksha.result({"vulnerable": false, "target": target})
```

- 顶层声明参数并只调用一次 `cli.check()`。
- 业务结果用 `yaksha.result`，过程证据用 `yaksha.evidence`，诊断用 `yaksha.log`。
- 子 EXP 使用字面量 `yaksha.call(exp_id, revision, params)`；数据使用 `yaksha.asset(asset_id)`。
- 不引用宿主文件，不把凭据或对象存储信息写入源码。

## 五种动作与执行边界

- `inspect`：只分析源码，生成官方 `cli.*` Schema，并提取字面量 `yaksha.call` / `yaksha.asset` 引用。
- `validate`：校验密封包、参数和出口合同，不运行 VM。
- `test`：使用 Server Fixture 验收，永久离线；无论请求内容如何都不会联网。
- `debug`：运行源码并返回完整未脱敏 HTTP/TCP Trace、日志、Evidence 和调用树。
- `run`：执行一次已授权操作并写入运行审计，不自动重试。

Yaksha 是容器中的常驻 Daemon，Worker 长期复用，但每个请求创建全新 Engine、CLI、Session 和 Resolver 上下文。默认禁网；`run/debug` 可显式选择 direct、单次 write-only SOCKS5 或指定 Agent 的原生 TCP relay（不套 SOCKS5）。网络目标必须精确声明，失败不自动回退或重试。临时内存源码只能用于 inspect、validate 和离线 Fixture test；真实 debug/run 必须绑定 Server Draft Revision，并由 Server 在执行前创建 Run 审计后编排 Yaksha。源码、依赖、Asset 或 Fixture 变更后旧 Revision 绑定立即解除。

## 测试、调试与发布流程

1. 在 Server Web UI 或 MCP App 创建 EXP 元数据，在内存中编辑 `main.yak`。
2. Studio 实时执行无副作用 inspect，根据 CLI Schema 渲染参数和静态控制流；contract validate 不运行 VM。
3. 创建 Fixture 并运行永久离线 test；未通过不能保存 Revision。
4. 完整内存包通过 Fixture test 后，Server 才签发与源码、依赖、Asset、Fixture 哈希绑定的短时一次性凭据；用户携带凭据显式保存不可变 Draft Revision，Debug / Run 不会隐式保存。
5. 对授权目标选择出口方式进行 debug；修复后继续实时 inspect、validate 或 test，修改本身不制造 Revision。
6. Admin 使用确定 Revision 的源码 SHA-256 人工确认发布；回滚只切换活动 Published Revision。

## 存储与访问

生产环境使用私有 MinIO 保存 `main.yak`、Asset、Trace、Evidence 和调用树；PostgreSQL 只保存治理数据、对象键、大小、哈希和审计。Server Web UI 与 `argus_exp_workspace` 管理 EXP、Revision、Asset、Fixture、发布、回滚和历史；`argus_yaksha_exp` 允许临时 Draft 做 inspect、validate 和离线 Fixture test，debug/run 只执行绑定 `exp_id + revision + source_sha256` 的 Server 密封 Revision。Web UI 和 MCP App 都只是 Server 权威 API/Tool 的交互层：AI 只通过 MCP Tool 操作逻辑对象，客户端不能覆盖 Published Revision、伪造 Fixture 验收、绕过租户/RBAC/EXP 授权或直接访问 MinIO/Yaksha/Agent。
