# EXP 调试模块

EXP 调试模块用于验证当前 Python EXP 是否能被实际执行器消费。调试链路不替代审核、授权、风险确认和正式执行链路，只用于开发和授权测试目标验证。

## 调试入口

- 本地 CLI：适合开发者快速验证 Python EXP 文件和执行器行为。
- 前后端调试：适合在 EXP 管理页选择已保存 EXP、Agent、目标和参数后发起一次非正式调试。

## 本地 CLI

```bash
go run ./scanner/cmd/exp-debug \
  -file scanner/internal/exploit/testdata/http_check_cleanup.py \
  -target http://127.0.0.1:8080 \
  -params '{"path":"/","expect_status":200}' \
  -timeout 30
```

| 参数 | 说明 |
| --- | --- |
| `-file` | Python EXP `.py` 文件路径 |
| `-target` | 授权测试目标 URL |
| `-params` | EXP 参数 JSON |
| `-timeout` | 超时时间，单位秒 |
| `-proxy` | 可选代理 |
| `-cleanup` | run 成功后执行 cleanup |
| `-cleanup-only` | 只执行 cleanup |

输出为 JSON，包含 `template_id`、`engine`、`target`、`mode`、`result`、`cleanup_ok` 和 `error`。

## 前后端调试

```http
POST /api/v1/exploits/:id/debug
Content-Type: application/json

{
  "agent_id": "agent-001",
  "target_url": "http://127.0.0.1:8080",
  "params": {
    "path": "/",
    "expect_status": 200
  },
  "timeout_sec": 30,
  "proxy": "",
  "action": "run"
}
```

`action` 可选：

- `run`：执行 EXP 主逻辑。
- `cleanup`：只执行 cleanup。

接口会读取已保存的 Python EXP，校验基础结构、目标 URL、代理、参数 schema 和 Agent 状态，然后通过 Agent 调试通道下发 `start_exp_debug` 或 `cleanup_exp_debug`。调试结果以 WebSocket `debug_log`、`debug_result`、`debug_complete` 事件返回，不创建 `ExploitRun`，也不会写入正式执行历史。

## 当前样例

当前 Python EXP 样例位于 `scanner/internal/exploit/testdata/http_check_cleanup.py`。样例展示：

- `ARGUS_EXP` 元数据声明。
- `argparse` 参数合同。
- `run(ctx)` 主逻辑。
- `cleanup(ctx)` 清理入口。
- 本地 CLI `main()` 入口。

## 推荐流程

1. Builder 或 AI Copilot 生成 Python EXP。
2. 使用 `exp-debug` 或前端 EXP 调试抽屉对授权测试目标进行验证。
3. 确认参数、证据、风险声明和 cleanup 行为。
4. 保存为草稿并走审核流程。
5. 正式运行时由 Server 创建 EXP Run，并下发 Agent 执行。

## 安全边界

- 调试入口要求登录态、租户隔离和在线 Agent。
- 调试目标必须是 HTTP/HTTPS URL，不能是空目标或非法 URL。
- Agent 必须声明 `python_exp=true`，且版本支持 EXP 调试。
- Python EXP 使用 Agent 当前 Python 原生执行；网络、加解密、文件和系统调用使用原生 Python 或已声明依赖。
- `ctx` 只提供 `params`、`target`、`result`、`evidence`、`cleanup`；请求/响应调试信息由脚本主动写入 `ctx.evidence` 摘要。
- Python EXP 仍受 timeout、requirements 预检和审核校验约束。
- 正式执行仍受 Server 的 EXP 授权、风险确认、Agent 能力和并发限制控制。
