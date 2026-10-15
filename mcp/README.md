# Argus MCP

Argus MCP 让外部 AI（Claude、其他 MCP Client）接入 Argus 的能力：查规则库、调试着 POC、发起扫描、操作 Yaksha EXP，以及**读回扫描结果**（爬取关联资产候选 + 敏感信息候选）。

它是**网关而不是权威**：每个工具调用都通过 MCP Server 持有的 Bearer Token 转发到 Argus Server 的 `/api/v1/...` REST 端点。身份、租户、RBAC、审计的唯一权威仍是 Argus Server——MCP 层不落地任何权限决策。

## 构建

```bash
make mcp        # 产出 bin/argus-mcp
```

## 传输方式

### stdio（默认，本地 AI 客户端）

AI 客户端直接拉起进程、通过标准输入输出通信。只需 Server 地址与 Token：

```bash
ARGUS_BASE_URL=http://127.0.0.1:8085 \
ARGUS_TOKEN=<argus-api-token> \
./bin/argus-mcp
```

### Streamable HTTP（多客户端/远程）

MCP 以 HTTP 服务暴露，**必须**设置 `ARGUS_MCP_AUTH_TOKEN` 作为 MCP 客户端接入本服务的口令：

```bash
ARGUS_MCP_TRANSPORT=http \
ARGUS_MCP_HTTP_ADDR=127.0.0.1:8787 \
ARGUS_MCP_AUTH_TOKEN=<mcp-client-shared-secret> \
ARGUS_BASE_URL=http://127.0.0.1:8085 \
ARGUS_TOKEN=<argus-api-token> \
./bin/argus-mcp
```

客户端连接 `http://127.0.0.1:8787/mcp`。

### EXP Studio 浏览器宿主（仅开发）

本地调试 MCP App 时可显式启用同进程浏览器宿主：

```bash
ARGUS_MCP_TRANSPORT=http \
ARGUS_MCP_HTTP_ADDR=127.0.0.1:8787 \
ARGUS_MCP_AUTH_TOKEN=local-mcp-token \
ARGUS_MCP_APP_DEV_HOST=true \
go run ./cmd/argus-mcp
```

访问 `http://127.0.0.1:8787/__dev/exp-studio`。宿主只允许 `argus_yaksha_exp`、`argus_exp_workspace` 与用于在线 Agent 选择的只读 `argus_agents`，通过进程内 Client 转发真实调用；浏览器不接收 Server Token。该入口必须绑定 loopback，且默认关闭，不能作为生产 MCP Host。

## 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `ARGUS_BASE_URL` | — | Argus Server 地址（必填） |
| `ARGUS_TOKEN` | — | 访问 Argus Server 的 API Token（与 `ARGUS_TOKEN_FILE` 二选一） |
| `ARGUS_TOKEN_FILE` | — | 从文件读取 Token（trim 空白） |
| `ARGUS_YAKSHA_URL` | `http://127.0.0.1:8790` | Yaksha EXP 运行时地址 |
| `ARGUS_MCP_TRANSPORT` | `stdio` | `stdio` 或 `http`（Streamable HTTP） |
| `ARGUS_MCP_HTTP_ADDR` | `127.0.0.1:8787` | HTTP 模式监听地址 |
| `ARGUS_MCP_AUTH_TOKEN` / `ARGUS_MCP_AUTH_TOKEN_FILE` | — | HTTP 模式必填：MCP 客户端接入口令 |
| `ARGUS_MCP_APP_DEV_HOST` | 关闭 | 开发用 EXP Studio 浏览器宿主（仅 loopback） |

两层口令职责不同：`ARGUS_TOKEN` 是 Argus Server 颁发的 API Token（决定能看到哪些项目/能做什么）；`ARGUS_MCP_AUTH_TOKEN` 只是保护 MCP HTTP 端点本身的接入口令。

## 客户端配置示例

### Claude Code

```bash
claude mcp add argus \
  -e ARGUS_BASE_URL=http://127.0.0.1:8085 \
  -e ARGUS_TOKEN=<argus-api-token> \
  -- /path/to/argus-main/bin/argus-mcp
```

### Claude Desktop（`claude_desktop_config.json`）

```json
{
  "mcpServers": {
    "argus": {
      "command": "/path/to/argus-main/bin/argus-mcp",
      "env": {
        "ARGUS_BASE_URL": "http://127.0.0.1:8085",
        "ARGUS_TOKEN": "<argus-api-token>"
      }
    }
  }
}
```

### 远程 Streamable HTTP（如 Cline / Cursor）

```json
{
  "mcpServers": {
    "argus": {
      "url": "http://127.0.0.1:8787/mcp",
      "headers": { "Authorization": "Bearer <mcp-client-shared-secret>" }
    }
  }
}
```

## 工具一览

| 工具 | 只读 | 说明 |
|---|---|---|
| `argus_help` | ✓ | 入门手册（先调这个） |
| `argus_resource` | ✓ | 按 URI 拉取规范/模板 |
| `argus_agents` | ✓ | 在线 Agent 列表 |
| `argus_coverage` | ✓ | 指纹与 POC 覆盖 |
| `argus_rule_get` / `argus_rule_list` | ✓ | 读取/列出规则 |
| `argus_findings` | ✓ | 扫描结果查询：爬取站点候选 + 敏感信息（见下） |
| `argus_results` | ✓ | 扫描核心结果：漏洞（含请求/响应证据）/资产/指纹命中（见下） |
| `argus_debug_*` | | 经授权 Agent 在线调试（指纹/目录/POC/workflow/行为探针） |
| `argus_save_*` | | 保存规则草稿（Draft），返回 stable_ref |
| `argus_rule_apply` | | 管理员发布/下线/回滚（hash/version 守卫） |
| `argus_yaksha_exp` | | Yaklang EXP 运行（inspect/validate/test/debug/run） |
| `argus_exp_workspace` | | EXP 工作区（修订/资产/夹具/运行历史） |
| `argus_scan_preview` / `argus_scan_create` | | 预览/创建扫描任务（Server 编译 scan-policy） |

写工具（debug/save/apply/exp/scan）都由 Server 做租户鉴权、风险确认与审计；MCP 只转发。

## argus_findings：读回扫描结果

外部 AI 以前能发起扫描却读不到"扫到了什么"。`argus_findings` 补齐这个闭环，直接消费内容分析管线的产物：

- `action=summary`：两个候选集的计数聚合——`crawl_sites.by_site_type`（`path_app`/`hidden_path`/`port_or_subdomain`）、`by_ai_status`；`sensitive.by_kind`（`email/phone/idcard/account/username/apikey/token/secret/...`）、`by_ai_status`。`total` 是 Server 精确计数，`sampled` 是实际参与聚合的窗口行数（>200 时 `truncated=true`）。
- `action=crawl_sites`：爬取关联资产候选行，支持 `site_type`/`ai_status`/`search` 过滤。
- `action=sensitive`：敏感信息候选行，支持 `kind`/`ai_status`/`search` 过滤。

公共过滤：`project_id`（缺省跨所有可访问项目）、`task_id`（自动展开子任务）、`page`/`page_size`（最大 200）。所有过滤在 Server 端 RBAC 收敛后执行，MCP 不做额外权限裁决。

调用示例（AI 视角）：

```
argus_findings({"action": "summary", "project_id": "proj-1"})
→ 敏感信息里 apikey=12 / token=5 / username=3，其中 confirmed=15 pending=5；
  爬取候选 path_app=4 hidden_path=2，全部 confirmed → 已回流资产库。

argus_findings({"action": "sensitive", "project_id": "proj-1", "kind": "apikey", "ai_status": "confirmed"})
→ 逐条 AKIA… / ghp_… 值 + snippet + context（含 AI 归纳的 username_convention）。
```

## argus_results：扫描核心结果

外部 AI 用 `argus_scan_preview` + `argus_scan_create` 发起扫描后，用 `argus_results` 读回主结果——漏洞 POC 证据、资产清单、指纹命中，形成完整闭环。

- `action=summary`：三结果集计数聚合——`vulns.by_severity`/`by_status`、`assets.by_protocol`、`fingerprints.by_product`（top 20）。`total` 是 Server 精确计数，>200 时 `truncated=true`。
- `action=vulns`：漏洞列表，支持 `search`（target 模糊）、`sort`（severity/created_at/updated_at）、`order`；每行自带 `Request`/`Response` 证据包与 AI 研判字段。
- `action=vuln_detail`：单条漏洞全证据，`{id, project_id}` 必填——`vulnerability`（**含 Request/Response 原文**）+ `ai_review`（AI 误报研判 + reviews）+ `lineage`（资产血缘链）。
- `action=assets` / `action=fingerprints`：资产 / 指纹命中列表，`search` 分别匹配 target / product_name+target，fingerprints 支持 `group_by=product`。

调用示例（AI 视角）：

```
argus_results({"action": "summary", "project_id": "proj-1"})
→ 高危漏洞 3 / 中危 12；http 资产 46 / tcp 8；Shiro×5、Nginx×12。

argus_results({"action": "vulns", "project_id": "proj-1", "search": "admin", "sort": "severity"})
→ 命中 2 条，逐条带 Request/Response。

argus_results({"action": "vuln_detail", "project_id": "proj-1", "id": "42"})
→ POC 证据包（原始请求/响应）+ AI 研判 confirmed + 资产血缘 input→target→vulnerability。
```

## 安全说明

- MCP Server 不校验、不存储项目权限；它只把调用方的 Token 转发给 Argus Server，由 Server 逐请求鉴权 + 审计。
- `ARGUS_TOKEN` 应按最小权限颁发（绑定具体租户/项目/角色）。
- HTTP 传输必须设置 `ARGUS_MCP_AUTH_TOKEN`，且生产环境应通过反向代理再加一层 TLS。
- EXP 调试/运行、受控探针、扫描创建都需要显式 `risk_confirmed=true` 或 Server 侧风险豁免，MCP 层无法绕过。
