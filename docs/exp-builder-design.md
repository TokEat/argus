# EXP Builder 设计方案

Builder as AI Context Collector —— 简化 Builder 收集漏洞理解材料，AI 直接生成 Argus EXP YAML，YAML 编辑器承接最终内容

## 1. 目标

降低 EXP 编写门槛，让用户专注于「漏洞如何触发、如何利用、如何证明成功」而非「YAML 怎么写」。Builder 不再承担完整执行流程的可视化编辑职责，而是作为结构化上下文收集器，把漏洞理解材料交给 Copilot，由 AI 按 Argus EXP v1 规范直接生成完整 YAML。

当前实现状态（2026-05-07）：

- ✅ Builder 主 UI 已简化：只保留规则 ID、名称、风险等级、目标产品、CVE、漏洞与触发条件、完整利用过程、成功证据与判定、关键 HTTP 请求包样例、参数化提示、安全边界/副作用/cleanup 要求。
- ✅ Builder 不再展示或维护参数表格、请求包解析、Matcher/Extractor、Nuclei Cleanup、Starlark 高级流程、Code Escape Hatch、Capabilities 手工选择等复杂执行表单。
- ✅ AI 入口统一为一处 `AI 生成 YAML`，点击后直接打开 Copilot，输入框强制替换为最新 Builder 内容生成的完整任务 prompt。
- ✅ AI 不再输出 `builder_patch`；EXP 页面不再注册 `applyBuilderPatch/summarizeBuilderPatch`。Copilot 返回 fenced YAML 后走已有“应用到 EXP”能力。
- ✅ prompt 内嵌 Argus EXP v1 设计约束，明确顶层 schema、Nuclei/Starlark 模式边界、capabilities、params、http/matcher/extractor/cleanup 字段和 Starlark 可用 API，避免 AI 按原生 Nuclei 或臆造字段写 YAML。
- ✅ Builder 内容保存为 YAML 顶层 `builder:` 存档块，重新编辑时优先从 `builder:` 回填；`info.description` 只保存漏洞概要。
- ✅ YAML 编辑器保留为最终内容审核和手工修改入口；保存草稿仍以 YAML 内容为唯一执行来源。
- ✅ 运行时不再由用户在新增时手工选择。AI 根据利用复杂度生成 `runtime.engine: nuclei` 或 `runtime.engine: starlark`；页面标题根据当前 YAML 的 engine 展示 `YAML · Nuclei/Starlark`。
- ✅ 目标产品支持已入库候选搜索：新增/编辑 EXP 时优先选择已有 EXP、Fingerprint、Workflow、Dir 产品名，输入新产品保存入库后进入下次候选。
- ⚠️ 旧的可视化步骤 Builder、Builder Patch 协议、表单实时生成 YAML 设计已退役，本文后续章节中相关内容仅作为历史规划参考，不代表当前实现。

| 目标 | 衡量标准 |
|------|----------|
| 新手 5 分钟内写出第一个 EXP | 从零到保存草稿的时间 |
| 简单 EXP 不需要手写 YAML | Builder 收集流程后 AI 直接生成可审核 YAML |
| 复杂 EXP 不离开编辑器 | AI 生成 Starlark YAML，YAML 编辑器承接修改 |
| 生成的 YAML 与系统执行器一致 | prompt 内嵌 Argus EXP v1 schema 和执行约束 |

## 2. 核心原则

1. **YAML 是唯一执行来源**。保存、审核、执行都以 `arsenals(type=exp).content` 中的 Argus EXP YAML 为准。
2. **Builder 是 AI 上下文，不是执行 DSL**。Builder 字段用于让 AI 理解漏洞，不直接表达完整请求、matcher、cleanup 或脚本。
3. **AI 直接生成完整 YAML**。前端不再合并 JSON patch，也不再从复杂表单生成 YAML。
4. **系统约束前置给 AI**。prompt 必须包含 Argus EXP v1 schema、Nuclei/Starlark 选择规则、受控 API 和 capability 约束。
5. **可回填但不反解析复杂逻辑**。`builder:` 块负责回填用户填写的漏洞材料；复杂执行逻辑由 YAML 编辑器查看和修改。

## 3. 当前架构

```
┌─────────────────────────────────────────────────────────────┐
│                 Simplified EXP Builder                       │
│                                                             │
│  基础信息: ID / 名称 / 风险 / 产品 / CVE                    │
│  漏洞描述: 触发条件 / 完整利用过程 / 成功证据               │
│  辅助材料: 关键 HTTP 请求包样例 / 参数化提示 / cleanup 要求 │
│                                                             │
│                 [AI 生成 YAML]                              │
└───────────────────────────┬─────────────────────────────────┘
                            │ structured context + prompt
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                         Copilot                              │
│  读取 Builder 材料 + 当前 YAML 草稿 + Argus EXP v1 设计约束   │
│  直接输出 fenced YAML                                       │
└───────────────────────────┬─────────────────────────────────┘
                            │ apply fenced YAML
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                       YAML Editor                            │
│  最终审核、手工修改、保存草稿、提交审核、调试执行             │
└─────────────────────────────────────────────────────────────┘
```

保存时，前端会把 Builder 输入同步到 YAML 顶层 `builder:` 块：

```yaml
builder:
  version: 1
  vulnerability_overview: |
    Tongweb 反序列化漏洞
  exploit_flow: |
    1. 发送包含序列化 payload 的请求触发漏洞。
    2. 再访问验证入口观察响应证据。
  verification_plan: |
    访问内存马入口，响应头出现 Access-Control-Allow-Origin 即为成功。
  raw_request: |
    POST /ejbserver/ejb HTTP/1.1
    Content-Type: application/x-www-form-urlencoded

    {{des}}
  parameter_hints: |
    des: 序列化 payload，建议由操作者提供 base64/hex 编码内容。
  safety_notes: |
    说明副作用和 cleanup 要求。
  needs_cleanup: false
```

`builder:` 块是前端上下文存档，不参与 Agent 执行；执行器只读取 `policy/runtime/http/steps/cleanup/scripts` 等字段。

## 4. 历史架构（已退役）

以下内容描述早期“可视化步骤表单 + Live YAML + Code Escape Hatch”的规划。当前实现不再使用该交互，但保留该章节作为后续若要恢复可视化流程编辑时的参考。

```
┌─────────────────────────────────────────────────────────────┐
│                      EXP Builder UI                          │
│                                                              │
│  ┌─ 基本信息 ───────────────────────────────────────────┐    │
│  │  表单填写: ID / 名称 / 风险 / 产品 / CVE / 描述       │    │
│  └───────────────────────────────────────────────────────┘    │
│                                                              │
│  ┌─ 参数定义 ───────────────────────────────────────────┐    │
│  │  动态表单: name / type / required / description       │    │
│  └───────────────────────────────────────────────────────┘    │
│                                                              │
│  ┌─ 验证步骤 (管线) ────────────────────────────────────┐    │
│  │  ① [HTTP] POST /api/exploit  ──→ 提取 resp.data.id   │    │
│  │  ② [条件] resp.status == 200                         │    │
│  │  ③ [证据] proof_id = resp.data.id                    │    │
│  │  [+ 添加步骤]  [添加条件分支]                          │    │
│  └───────────────────────────────────────────────────────┘    │
│                                                              │
│  ┌─ 清理步骤 ───────────────────────────────────────────┐    │
│  │  ① [HTTP] DELETE /api/proof/{{proof_id}}             │    │
│  └───────────────────────────────────────────────────────┘    │
│                                                              │
│  ┌─ 自动推导 (只读) ────────────────────────────────────┐    │
│  │  engine: nuclei / starlark                            │    │
│  │  capabilities: http.request, evidence.write, ...      │    │
│  │  cleanup_required: true                               │    │
│  └───────────────────────────────────────────────────────┘    │
│                                                              │
│  [预览 YAML]  [保存草稿]  [Dry-Run]  [提交审核]              │
└─────────────────────────────────────────────────────────────┘
                        │ 实时同步
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  Live YAML Preview (Monaco Editor, 只读 ↔ 可编辑切换)       │
│                                                              │
│  kind: argus-exp/v1                                          │
│  id: exp-rce-verify                                          │
│  info:                                                       │
│    name: RCE 命令回显验证                                     │
│    risk_level: medium                                        │
│    target_product: Apache Struts                             │
│  policy:                                                     │
│    capabilities: [http.request, evidence.write, ...]         │
│    cleanup_required: true                                    │
│  runtime:                                                    │
│    engine: nuclei                                            │
│  steps:                                                      │
│    - type: http                                              │
│      method: POST                                            │
│      path: ["{{BaseURL}}/api/cmd"]                           │
│      ...                                                     │
└─────────────────────────────────────────────────────────────┘
```

## 4. Step 类型

### 4.1 Phase 1 — 基础步骤

| Step 类型 | 表单字段 | 覆盖场景 |
|-----------|----------|----------|
| **HttpStep** | method, path, headers, body, timeout | HTTP 验证（90% 场景） |
| **ExtractStep** | source, type (json/regex/header), expression, varName | 证据提取 |
| **EvidenceStep** | key, source | 写入证据记录 |
| **MatcherStep** | source, type (status/contains/regex), expected | 成功/失败判断 |

### 4.2 Phase 2 — 进阶步骤

| Step 类型 | 表单字段 | 覆盖场景 |
|-----------|----------|----------|
| **ConditionStep** | left, op, right, trueBranch, falseBranch | 条件分支 |
| **TcpStep** | host, port, readPattern, timeout | TCP 探测（当前导出为 Starlark `tcp.connect`，不导出声明式 TCP） |
| **LoopStep** | type (retry/iterate/until), maxCount, interval, body | 重试/遍历 |

### 4.3 Phase 3 — 代码降级

| Step 类型 | 说明 |
|-----------|------|
| **CodeStep** | Monaco 代码编辑框，直接写 Starlark 片段 |

当表单步骤无法表达时，用户点击「切换为代码」，该步骤变成 Starlark 代码块。

## 5. 自动推导规则

系统从步骤管线自动推导，用户无需手动声明：

### 5.1 Engine 推导

```
所有步骤都是 HttpStep/MatcherStep/ExtractStep  → engine: nuclei
任何步骤包含 TcpStep/ConditionStep/LoopStep/CodeStep  → engine: starlark
```

### 5.2 Capabilities 推导

```
HttpStep          → http.request
TcpStep           → tcp.connect（通过 Starlark 支持）
ExtractStep       → extract.match
EvidenceStep      → evidence.write
Cleanup 步骤存在  → cleanup.defer
任何步骤 → result.write (隐式)
```

### 5.3 Cleanup 推导

```
用户添加清理步骤  → cleanup_supported: true, cleanup_required: true
用户勾选"需要清理"但未写步骤 → 标记警告
无清理步骤       → cleanup_required: false
```

### 5.4 Risk 推导（辅助提示）

```
包含命令执行类操作 → 建议 risk_level: high
包含文件写入操作  → 建议 risk_level: medium
纯 HTTP 读取     → 建议 risk_level: low
```

## 6. Code Escape Hatch

### 6.1 触发方式

- 步骤卡片右上角「...」菜单 → 「切换为代码」
- 添加步骤时选择「自定义代码」类型
- AI 辅助生成后用户手动编辑

### 6.2 交互

```
┌─ Step 2: 自定义代码 ──────────────────────────────────┐
│  模式: [代码] ← 点击可切回 [表单]（如果能解析的话）     │
│                                                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │ # 用 Starlark 编写                                │  │
│  │ resp = http.request(                              │  │
│  │     method="POST",                                │  │
│  │     url=ctx.target.url + "/api/cmd",              │  │
│  │     body={"cmd": ctx.params.cmd},                 │  │
│  │ )                                                 │  │
│  │ if resp.status_code != 200:                       │  │
│  │     return result.failure("exploit failed")       │  │
│  │ data = extract.json(resp.body, "data")            │  │
│  │ evidence.add("output", data.get("output"))        │  │
│  └──────────────────────────────────────────────────┘  │
│                                                        │
│  已识别的 API 调用: http.request, extract.json,        │
│                     evidence.add, result.failure        │
│  自动添加 capability: http.request, extract.match,     │
│                       evidence.write, result.write      │
└────────────────────────────────────────────────────────┘
```

### 6.3 表单 ↔ 代码转换

- **表单 → 代码**：始终可转换，生成 Starlark 代码
- **代码 → 表单**：仅当代码结构可被解析时允许（简单线性逻辑），否则保持代码模式并提示「此代码块无法转为表单」

## 7. AI Copilot 集成

当前实现采用「Builder 收集上下文 → Copilot 直接生成 YAML → 前端应用 YAML」的单一链路。

### 7.1 唯一入口

EXP Drawer 中只保留一个主操作：`AI 生成 YAML`。点击后不再打开二次填表弹窗，而是直接基于当前 Builder 表单内容生成完整 prompt，并打开全局 Copilot。

全局 Copilot 收到 `suggested_prompt_replace=true` 和新的 `suggested_prompt_nonce` 时，会强制替换输入框内容，避免上一次残留 prompt 导致 AI 仍按默认模板生成。

### 7.2 Prompt 内容

prompt 由以下几部分组成：

1. 任务说明：从利用流程生成完整 Argus EXP YAML，而不是把 raw HTTP 请求机械转换成单请求模板。
2. Builder 基础信息：文件名、规则 ID、名称、风险等级、目标产品、CVE、漏洞概要、产品候选。
3. 用户填写的漏洞理解材料：漏洞与触发条件、完整利用过程、成功证据与判定、关键 HTTP 请求包样例、参数化提示、安全边界和 cleanup 要求。
4. 当前 YAML 草稿：仅作为参考，不作为权威来源；默认模板中的 `/api/proof`、`marker`、`HTTP EXP` 不能覆盖用户填写内容。
5. Argus EXP v1 设计约束：顶层字段、`runtime.engine` 选择、Nuclei/Starlark 字段边界、capability 白名单、Starlark 宿主 API、cleanup 和 evidence 约束。
6. 请求保真要求：HTTP 请求应尽量复用用户提供的正常业务/浏览器请求样例，不主动添加 `Argus`、`Scanner`、`PoC`、`Exploit` 等工具特征头或特征 User-Agent。

### 7.3 输出与应用

AI 必须只输出一个 fenced YAML 代码块：

```yaml
kind: argus-exp/v1
id: exp-product-vuln-verify
info:
  name: 产品漏洞验证 EXP
runtime:
  engine: nuclei # 或 starlark，由利用复杂度决定
```

EXP 页面不再注册 `applyBuilderPatch/summarizeBuilderPatch`，也不再接受 EXP 专属 `builder_patch`。全局 Copilot 仍可保留 `builder_patch` 类型能力给未来其他页面使用，但 EXP 编辑只走已有 fenced YAML 提取和“应用到 EXP”能力。

Starlark 场景下，prompt 必须提供可照抄的脚本模板和 API 合同，避免模型臆造不存在的方法：

```python
def run(ctx):
    resp = http.request(
        method="GET",
        url=target.url + "/path",
        headers={"User-Agent": "..."},
        body="optional text",
    )
    proof = resp.headers.get("Access-Control-Allow-Origin", "")
    if resp.status_code == 200 and proof != "":
        evidence.add(key="access_control_allow_origin", value=proof)
        return result.success(msg="verified")
    return result.failure(msg="not matched")
```

当前响应对象只承诺 `status_code/body/headers/success`，未声明的 `body_encoding`、`base64_decode`、`requests`、`socket` 等能力不能生成。

应用后，前端更新 `editorContent`，并尽量从 YAML 的 `info` 和顶层 `builder:` 块回填简化 Builder。保存草稿仍以 `editorContent` 为唯一执行来源。

### 7.4 命名规范

Builder 中的规则 ID、名称、文件名是给 AI 的初始线索，不是最终锁死值。AI 应根据目标产品、CVE、漏洞类型和验证动作重新整理命名：

- `id` 建议格式：`exp-产品-漏洞-验证方式`，使用稳定、可检索、无空格的小写标识。
- `info.name` 是给人看的展示名，应包含产品、漏洞和验证动作。
- 目标产品优先使用已入库候选的规范名。
- 当用户明确填写 CVE 时，文件名和 ID 可优先包含 CVE；没有 CVE 时使用产品和漏洞名。

### 7.5 Nuclei 与 Starlark 的区分

前端不再要求用户先选择 Nuclei/Starlark。AI 根据利用复杂度选择：

| 场景 | 推荐 runtime |
|------|--------------|
| 单请求或少量固定 HTTP 请求、无复杂状态传递 | `runtime.engine: nuclei` |
| 需要登录、Token 传递、条件分支、循环等待、TCP 探测、复杂编码/解码、内存马二次验证或复杂 cleanup | `runtime.engine: starlark` |

页面标题从当前 YAML 的 `runtime.engine` 派生展示 `YAML · Nuclei` 或 `YAML · Starlark`。

## 8. YAML 同步与保存

当前不再做完整「表单 ↔ YAML」双向同步。同步边界如下：

| 方向 | 当前策略 |
|------|----------|
| Builder → YAML | 切换到 YAML 或保存时，使用 YAML parser 更新基础信息和顶层 `builder:` 上下文存档块，保留 `policy/params/runtime/http/steps/scripts/cleanup` 等执行字段 |
| YAML → Builder | 编辑已有 EXP 时只回填 `id/info` 基础字段和 `builder:` 中的漏洞材料 |
| AI YAML → 编辑器 | Copilot fenced YAML 通过结构化校验后替换 `editorContent`，并切换到 YAML 标签页审核 |
| 复杂执行逻辑回填 | 不尝试把 `http/steps/scripts/cleanup` 反解析成 Builder 表单 |

这意味着 YAML 编辑器是最终审核入口。Builder 负责保存“AI 需要理解漏洞”的材料，复杂执行逻辑由 AI 生成并由 YAML 编辑器承接。

### 8.1 Builder 存档块

保存草稿时，如果用户在 Builder 标签页编辑过材料，前端会将这些材料写入：

```yaml
builder:
  version: 1
  vulnerability_overview: ...
  exploit_flow: ...
  verification_plan: ...
  raw_request: ...
  parameter_hints: ...
  safety_notes: ...
  needs_cleanup: false
  cleanup_request: ...
  cleanup_instruction: ...
```

`builder:` 是前端上下文存档，不参与后端物化、审核或 Agent 执行。执行器只读取正式 EXP 字段。

### 8.2 保存语义

保存草稿时：

1. 若当前在 Builder 标签页，先把基础字段和 Builder 材料同步到 YAML；如果 YAML 无法解析，则提示修复，不静默覆盖。
2. 再以同步后的 `editorContent` 调用 Arsenal 保存接口。
3. 若当前在 YAML 标签页，则保存用户正在查看和编辑的 YAML 内容。
4. 保存成功后，后续编辑从 YAML 中的 `info` 和 `builder:` 回填 Builder。

### 8.3 AI YAML 应用前校验

前端应用 Copilot fenced YAML 前会做轻量结构校验：`kind`、`id`、`info.risk_level`、`policy.capabilities`、`runtime.engine` 必填；engine 只能是 `nuclei` 或 `starlark`；capability 必须在当前白名单内；Nuclei 必须有 `http` 或 `steps` 且不能使用声明式 TCP；Starlark 必须有入口脚本；`cleanup_required=true` 时必须提供 `cleanup` 或 `scripts.cleanup`。

该校验只保证 YAML 与当前执行模型兼容，不替代人工审核和后端严格校验。

## 9. 当前前端数据模型

```typescript
interface ExpAIGenerationFormState {
  vulnerabilityOverview: string;
  exploitFlow: string;
  verificationPlan: string;
  rawRequest: string;
  parameterHints: string;
  safetyNotes: string;
  needsCleanup: boolean;
  cleanupRequest: string;
  cleanupInstruction: string;
}
```

该状态只表示“漏洞理解材料”，不表示完整执行管线。历史 `BuilderFormState` 中的 HTTP 请求、matcher、extractor、cleanup、advanced steps 等字段不再主导 UI。

## 10. 工程细节

### 10.1 读取当前表单内容

`AI 生成 YAML` 在生成 prompt 前会读取当前 DOM textarea/input 的最新值，避免 React state 防抖或未触发 blur 导致 prompt 仍使用旧默认值。

### 10.2 已有 YAML 导入

编辑已有 EXP 时，前端解析：

1. 顶层 `id`、`info.name`、`info.description`、`info.risk_level`、`info.target_product`、`info.cve`。
2. 顶层 `builder:` 的漏洞材料。
3. `runtime.engine` 只用于页面标题和标签提示，不强制切换 Builder 结构。

无法解析或不属于 Builder 存档的执行逻辑保持在 YAML 编辑器中。

## 11. 安全设计

Builder 不是安全边界。它只收集材料、生成 prompt 和存档上下文；真正的安全边界仍在 YAML 校验、审核、授权和 Agent 执行沙箱。

| 位置 | 安全职责 |
|------|----------|
| Builder prompt | 要求 AI 最小化证据、声明副作用和 cleanup，不臆造路径/凭据/payload |
| YAML 应用 | 只应用 fenced YAML；不执行 AI 输出；不再合并 JSON patch |
| 保存草稿 | 复用 Arsenal 保存和 EXP 包基础校验 |
| 审核/执行 | 复用 `validateExpPackage`、capability 白名单、Starlark 禁用符号扫描、运行前授权和风险确认 |
| Agent | 按 `policy.capabilities` 注入宿主 API，限制 HTTP/TCP 目标范围和 cleanup 生命周期 |

AI 生成的内容必须经人工审核。prompt 会明确禁止 AI 在未得到用户明确说明时生成破坏性风险、跳过 TLS 校验、反连监听、任意命令执行或保存敏感 evidence。

## 12. 用户旅程

### 12.1 创建流程

```
用户点击「新增 EXP」
  → 在 Builder 填写基础信息和漏洞利用材料
  → 点击「AI 生成 YAML」
  → Copilot 输入框预填完整结构化 prompt
  → AI 返回 fenced YAML
  → 用户点击「应用到 EXP」
  → 在 YAML 标签页审核和手工修正
  → 保存草稿 / 提交审核
```

### 12.2 编辑流程

```
用户点击「编辑 EXP」
  → 前端从 YAML 顶层 id/info/builder 回填 Builder
  → 用户可继续补充利用流程并重新让 AI 生成 YAML
  → 或直接在 YAML 标签页修改最终内容
  → 保存时以 YAML 编辑器内容为准
```

### 12.3 错误恢复

| 错误场景 | 恢复方式 |
|----------|----------|
| AI 生成不符合预期 | 不应用 YAML，继续修改 Builder 材料或 prompt |
| AI 输出非 YAML | Copilot 不显示“应用到 EXP”，用户可要求重新输出 fenced YAML |
| YAML 语法错误 | Monaco 标记错误，保存时后端校验兜底 |
| Builder 材料未保存 | Builder 标签页保存前同步到顶层 `builder:` 块 |
| 当前 YAML 是复杂 Starlark | Builder 只回填上下文材料，不反解析脚本 |

## 13. 键盘与入口

| 入口 | 功能 |
|------|------|
| Builder/YAML 分段 | 在材料收集和最终 YAML 审核之间切换 |
| `AI 生成 YAML` | 唯一 AI 主入口，基于 Builder 当前内容打开 Copilot |
| 保存草稿 | 保存当前 `editorContent`，Builder 标签页会先同步上下文块 |

## 14. 测试策略

| 层级 | 测试内容 |
|------|----------|
| 前端构建 | `npm run build` 应通过 |
| Prompt 生成 | 修改 Builder textarea 后立即点击 AI，Copilot prompt 必须包含最新内容 |
| YAML 应用 | AI 返回 fenced YAML 后能出现“应用到 EXP”，应用后 YAML 标签页更新 |
| 保存回填 | 保存后重新编辑，`builder:` 中的完整利用过程、成功判定、请求包、参数提示能回填 |
| 运行时区分 | 单请求生成 Nuclei；登录/多步/二次验证/cleanup/TCP 场景生成 Starlark |
| 旧数据兼容 | 无 `builder:` 的旧 EXP 至少能回填 id/name/description/risk/product/cve |

## 15. 实施状态

当前已落地的方向是“AI Context Builder”：

- ✅ 简化 Builder 主 UI，删除复杂执行表单展示。
- ✅ EXP 不再使用 `builder_patch`。
- ✅ 单一 `AI 生成 YAML` 入口。
- ✅ prompt 包含 Builder 全量材料和 Argus EXP v1 设计约束。
- ✅ 保存时把 Builder 材料写入顶层 `builder:`。
- ✅ 编辑已有 EXP 时优先从 `builder:` 回填。
- ✅ YAML 编辑器继续作为最终内容源。

早期“可视化步骤 Builder + Live YAML + Code Escape Hatch”已经退役，后续若要恢复，应作为独立高级编辑器重新设计，而不应混入当前简化 Builder。

## 16. 与现有系统的关系

```
┌──────────────────────────────────────────────────────────┐
│              Simplified Builder                           │
│  收集漏洞材料 + 存档 builder: + 触发 Copilot                │
└──────────────────────────┬───────────────────────────────┘
                           │ AI fenced YAML
                           ▼
┌──────────────────────────────────────────────────────────┐
│              YAML Editor                                  │
│  editorContent 是保存、审核、执行的唯一内容来源             │
└──────────────────────────┬───────────────────────────────┘
                           │ arsenal.content
                           ▼
┌──────────────────────────────────────────────────────────┐
│              现有 EXP 后端链路                             │
│  validateExpPackage → materializeExploitRule → approve     │
│  Nuclei / Starlark 执行器 → cleanup / evidence / audit      │
└──────────────────────────────────────────────────────────┘
```

顶层 `builder:` 只用于前端回填和后续 AI 再生成，不参与后端执行。生成的 YAML 与手写 YAML 结构一致，复用现有保存、审核、物化、执行和清理链路。

## 17. 技术选型

| 组件 | 选型 | 理由 |
|------|------|------|
| 表单组件 | Ant Design | 项目已使用 |
| YAML 编辑 | Monaco Editor | 项目已集成，适合最终审核 |
| AI 集成 | 现有 Global Copilot | 复用已有抽屉、消息和 YAML 应用能力 |
| YAML 存档 | 顶层 `builder:` 块 | 与执行字段分离，便于回填 |
| 状态管理 | React state + 保存前同步 | 表单状态轻量，无需独立状态库 |

## 18. 风险与缓解

| 风险 | 影响 | 缓解 |
|------|------|------|
| AI 仍使用默认模板 | 生成与用户材料不符 | 生成 prompt 前读取最新 DOM 值，并用 `suggested_prompt_replace` 强制替换 Copilot 输入 |
| AI 不理解系统 YAML 格式 | 生成原生 Nuclei 或臆造字段 | prompt 内嵌 Argus EXP v1 设计约束和禁用字段 |
| Builder 材料丢失 | 重新编辑时无法继续生成 | 保存时同步顶层 `builder:` 块 |
| YAML 与 Builder 显示不完全一致 | 用户误以为 Builder 是执行内容 | UI 文案强调 YAML 为准，Builder 只收集上下文 |
| 复杂 EXP 难以回填成表单 | 编辑体验割裂 | 不反解析复杂执行逻辑，直接由 YAML 编辑器承接 |

## 19. 变更记录

| 日期 | 阶段 | 内容 |
|------|------|------|
| 2026-05-07 | Builder as AI Context Collector | Builder 简化为漏洞理解材料收集器；删除复杂执行表单展示；AI 直接生成完整 Argus EXP YAML；EXP 页面停止使用 `builder_patch`；保存时用顶层 `builder:` 存档上下文；运行时由 AI 在 `nuclei` 与 `starlark` 间选择 |
| 2026-05-06 | Builder Phase 1 | 历史实现：HTTP Builder 表单化维护基础信息、参数、请求、Matcher、Extractor、Cleanup，并实时生成 YAML |
| 2026-05-06 | Builder Phase 2/3 | 历史实现：高级线性步骤、Starlark 自动导出、Code Escape Hatch、AI 步骤/cleanup/全文生成入口 |
| 2026-05-06 | AI Builder Patch | 历史实现：AI 输出 `builder_patch`，前端合并 Builder 状态后再统一生成 YAML；该链路已从 EXP 页面移除 |
| 2026-05-06 | EXP Debug Module | 增加 `scanner/cmd/exp-debug` 本地调试 CLI 和 Nuclei/Starlark fixture，用真实 httptest 服务验证 EXP YAML 可被执行器消费 |
