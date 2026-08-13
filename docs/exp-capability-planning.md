# Yaksha EXP 能力边界

Argus EXP 的唯一产品实现是 Yaksha。每个 EXP 的唯一权威源码是单个 `main.yak`；复杂逻辑通过锁定 Revision 的子 EXP 组合，Payload、字典和样本通过哈希绑定的 Asset 引用，不引入多文件源码包。

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
- 发布由 Admin 使用预期源码哈希人工确认；回滚只切换活动版本并写审计。
- 生产对象存储为私有 MinIO；LocalStore 只允许显式开发模式。
- Debug Trace 完整未脱敏，正文按保留期删除，摘要和审计永久保留。

## 运行与出口

Yaksha 是容器中的常驻 Daemon，Worker 长期复用，但每个请求创建全新 Engine、CLI、Session 和 Resolver 上下文。默认禁网；`test` 永久离线；`run/debug` 可显式选择 direct、单次 write-only SOCKS5 或指定 Agent 的原生 TCP relay。网络目标必须精确声明，失败不自动回退或重试。

## 控制面

Server Web UI 与 `argus_exp_workspace` 管理 EXP、Revision、Asset、Fixture、发布、回滚和历史；`argus_yaksha_exp` 允许临时 Draft 做 inspect、validate 和离线 Fixture test，debug/run 只执行绑定 `exp_id + revision + source_sha256` 的 Server 密封 Revision。MCP App 使用相同 Tool，不接触文件系统或对象存储内部信息。
