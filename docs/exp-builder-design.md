# Yaksha EXP Workspace 设计

Workspace 帮助人和 AI 编写、测试、调试和发布单文件 Yaklang EXP。`main.yak` 同时承载官方 `cli.*` 参数声明与执行逻辑，Server 根据 inspect 结果渲染声明式 UI。

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
- 每个子 Yak 在存储和执行模型中仍是独立 EXP，只是通过 `parent_exp_id + variant_key` 归入同一漏洞；它拥有独立 Revision、CLI Schema、Fixture、风险级别、发布状态和审计记录。
- 根 Revision 使用确定 Revision 与源码哈希的 `yaksha.call` 锁定子 EXP。界面层级不是运行时授权，也不会自动发布或授权子分支。
- 父子关系只允许两层且必须同租户、同产品；旧 EXP 自动归入“未分类”。
- “删除 EXP”是保留治理证据的软删除：状态变为 `deprecated`，默认从产品库隐藏，但可通过“显示已删除”查看。删除根 EXP 会在同一事务内同步废弃全部利用分支并逐项记录审计。

该结构保持“每个可执行单元只有一个权威 Yak 源码”的约束，不引入宿主文件路径、多文件 include 或可变源码包。

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

## 工作流

创建 EXP → 内存编辑与实时 inspect → contract validate → 永久离线 Fixture test → 显式保存不可变 Draft Revision → debug/run → Admin 按源码哈希发布 → 必要时切换到旧 Published Revision。

编辑、实时 UI 和 Fixture 调整都不创建 Revision。Server 只在完整内存包通过 Fixture test 后签发与源码、依赖、Asset、Fixture 哈希绑定的短时一次性凭据；用户携带该凭据显式保存，Debug / Run 不会隐式保存。发布与 Active 切换永远不会自动执行。

Web UI 和 MCP App 都只是 Server 权威 API/Tool 的交互层。客户端不能覆盖 Published Revision、伪造 Fixture 验收、绕过租户/RBAC/EXP 授权或直接访问 MinIO/Yaksha/Agent。
