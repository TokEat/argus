# EXP 调试模块

## 目标

EXP 调试模块用于验证 Builder 或 AI Copilot 生成的 EXP YAML 是否能被实际执行器消费。它不替代审核、授权、风险确认和正式执行链路，只用于开发和授权测试目标调试。

当前提供两类入口：

- 本地 CLI：适合开发者快速验证 YAML 和执行器行为。
- 前后端调试：适合在 EXP 管理页选择已保存 EXP、Agent、目标和参数后发起一次非正式调试。

## 本地 CLI

调试入口位于：

```bash
go run ./scanner/cmd/exp-debug \
  -file scanner/internal/exploit/testdata/builder_nuclei_post_cleanup.yaml \
  -target http://127.0.0.1:8080 \
  -params '{"marker":"demo"}'
```

常用参数：

| 参数 | 说明 |
|------|------|
| `-file` | EXP YAML 文件路径 |
| `-target` | 授权调试目标 URL |
| `-params` | EXP 参数 JSON |
| `-timeout` | 执行超时，默认 60 秒 |
| `-proxy` | 可选代理 |
| `-cleanup` | run 成功后执行 cleanup |
| `-cleanup-only` | 只执行 cleanup |

CLI 输出 JSON，包含模板 ID、执行引擎、目标、执行结果、证据、cleanup 结果和错误信息。

## 前后端调试

后端入口：

```http
POST /api/v1/exploits/:id/debug
```

请求体：

```json
{
  "agent_id": "agent-1",
  "target_url": "http://127.0.0.1:8080",
  "params": { "marker": "demo" },
  "proxy": "",
  "timeout_sec": 60,
  "action": "run"
}
```

`action` 支持：

| action | 说明 |
|--------|------|
| `run` | 执行 EXP 主逻辑 |
| `cleanup` | 只执行 cleanup 逻辑 |

接口会读取已保存的 EXP YAML，校验基础结构、目标 URL、代理、参数 schema 和 Agent 状态，然后通过 Agent 调试通道下发 `start_exp_debug` 或 `cleanup_exp_debug`。调试结果以 WebSocket `debug_log`、`debug_result`、`debug_complete` 事件返回，不创建 `ExploitRun`，也不会写入正式执行历史。

前端入口：

- EXP 列表操作列新增“调试”。
- 抽屉内可选择在线 Agent、目标 URL、代理、超时、run/cleanup 动作和 EXP 参数。
- 结果区展示实时日志、状态、证据、side effects 和原始事件 payload。

## 已覆盖样例

当前测试样例位于 `scanner/internal/exploit/testdata/`：

- `tomcat_manager_weak_password.yaml`
  - 真实 Tomcat Manager 弱口令/管理接口暴露场景。
  - 覆盖 Basic Authorization 参数、`/manager/text/list` 访问、status/word matcher、regex evidence 提取。

- `builder_nuclei_post_cleanup.yaml`
  - Nuclei HTTP 模式。
  - 覆盖 POST JSON body、`{{marker}}` 参数、`{{Host}}` / `{{Port}}` 内置占位符、status/word matcher、JSON extractor、HTTP cleanup。

- `builder_starlark_login_cleanup.yaml`
  - Starlark 多步模式。
  - 覆盖登录请求、token 提取、携带 token 验证、证据写入、`cleanup.defer` 和 cleanup 脚本。

这些样例由 `scanner/internal/exploit/engine_test.go` 使用本地 `httptest` server 真执行，保证 EXP YAML 不是只通过解析，而是能完成请求、匹配、提取和清理。

## Docker 真实靶场验证

本地可使用已有的 `vulhub/tomcat:8.5.19` 镜像验证 Tomcat Manager 弱口令 EXP。由于 Tomcat Manager 默认限制远程地址访问，测试前需要在授权靶场容器内配置测试用户并放开 Manager 的本地访问限制。

启动靶场：

```bash
docker run --rm -d --name argus-exp-test-tomcat-18081 -p 18081:8080 vulhub/tomcat:8.5.19
```

配置测试用户和 Manager 访问限制后，确认靶场：

```bash
curl -i -u tomcat:tomcat http://127.0.0.1:18081/manager/text/list
```

运行正向 EXP：

```bash
go run ./scanner/cmd/exp-debug \
  -file scanner/internal/exploit/testdata/tomcat_manager_weak_password.yaml \
  -target http://127.0.0.1:18081 \
  -params '{"basic_auth":"dG9tY2F0OnRvbWNhdA=="}' \
  -timeout 10
```

预期结果：

- `status` 为 `Succeeded`。
- evidence 包含 `status_code: 200`。
- evidence 包含 `manager_app: manager`。

负向验证：

```bash
go run ./scanner/cmd/exp-debug \
  -file scanner/internal/exploit/testdata/tomcat_manager_weak_password.yaml \
  -target http://127.0.0.1:18081 \
  -params '{"basic_auth":"d3Jvbmc6d3Jvbmc="}' \
  -timeout 10
```

预期结果为 `Failed`，错误信息为 matcher 未命中，避免弱口令 EXP 误报。

## 与正式闭环的关系

开发调试顺序建议：

1. Builder 或 AI Copilot 生成 EXP YAML。
2. 使用 `exp-debug` 或前端 EXP 调试抽屉对授权测试目标进行验证。
3. 保存到 Arsenal，进入 Draft。
4. 审核时执行严格校验。
5. 正式运行时由 Server 创建 EXP Run，并下发 Agent 执行。
6. Agent 返回结果，Server 更新运行状态、证据、cleanup 状态。

## 注意事项

- 调试模块会真实访问 `-target`，只允许用于授权目标。
- v1 不自动脱敏请求包或参数，避免影响 AI 和执行器对字段结构的识别精度。
- 正式执行仍受 Server 的 EXP 授权、风险确认、target guard、capability guard 和并发限制控制。
