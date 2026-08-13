# Yaksha EXP Workspace 设计

Workspace 帮助人和 AI 编写、测试、调试和发布单文件 Yaklang EXP。`main.yak` 同时承载官方 `cli.*` 参数声明与执行逻辑，Server 根据 inspect 结果渲染声明式 UI。

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

创建 EXP → 创建不可变 Draft Revision → inspect → validate → Fixture test → debug/run → Admin 按源码哈希发布 → 必要时切换到旧 Published Revision。

Web UI 和 MCP App 都只是 Server 权威 API/Tool 的交互层。客户端不能覆盖 Published Revision、伪造 Fixture 验收、绕过租户/RBAC/EXP 授权或直接访问 MinIO/Yaksha/Agent。
