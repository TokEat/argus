# EXP Builder 设计方案

Form + Live YAML + Code Escape Hatch —— 可视化表单构建 + AI 辅助 + 代码降级

## 1. 目标

降低 EXP 编写门槛，让用户专注于「验证什么」而非「YAML 怎么写」。

当前实现状态（2026-05-06）：

- ✅ Phase 1 首版已落地在 `server-ui/src/pages/config/ExploitConfig.tsx`：HTTP/Nuclei EXP 默认进入 Builder 表单，支持基础信息、策略、参数、HTTP 请求、Matcher、Extractor、Cleanup。
- ✅ 表单修改实时生成标准 EXP YAML，保存仍复用 `arsenals(type=exp)`、物化、审核、执行、cleanup 既有链路。
- ✅ YAML 模式保留为高级逃生口；AI 回填后会按 `runtime.engine` 自动回到 Builder 或 YAML。
- ✅ Phase 2/3 首版已落地：高级步骤支持 HTTP、TCP、条件、循环、证据、代码块；添加高级步骤后自动导出为 Starlark。
- ✅ Code Escape Hatch 已集成：可将表单转换为 Starlark 代码，可直接维护 `run/cleanup` 代码，并提供 AI 步骤填充、AI cleanup 建议、AI 全文生成入口。
- ✅ YAML 编辑器接入 EXP schema 诊断配置和 Starlark API 补全提示。
- ✅ Builder 体验已收敛：常用字段默认展示，高级元数据折叠；生成 YAML 会省略空 CVE、空产品、空列表和 false policy 字段，减少维护噪音。
- ✅ Starlark Builder 不再只面向 TCP：支持认证流、多步 HTTP、TCP+HTTP、变量提取、条件、循环、证据、cleanup 注册、显式返回和自定义代码，并提供场景模板一键填充。
- ⚠️ 声明式 TCP 仍不进入后端 steps 执行器，Builder 通过 Starlark `tcp.connect` 导出 TCP EXP。
- ⚠️ 当前高级流程为轻量线性管线；可视化分支树、拖拽排序、注释无损保留、复杂代码反解析属于后续优化。

| 目标 | 衡量标准 |
|------|----------|
| 新手 5 分钟内写出第一个 EXP | 从零到保存草稿的时间 |
| 简单 EXP 不需要手写 YAML | 表单覆盖 80% 场景 |
| 复杂 EXP 不离开编辑器 | Code Escape Hatch 处理剩余 20% |
| 生成的 YAML 与手写一致 | 复用现有校验/物化/执行链路，后端零改动 |

## 2. 核心原则

1. **表单是 YAML 的另一种视图**，不是新格式。底层始终是 `arsenal.content` 字段。
2. **自动推导 > 手动声明**。capabilities、engine、cleanup_required 从步骤自动推导。
3. **渐进式交付**。每个 Phase 独立可用，不依赖后续 Phase。
4. **Code Escape Hatch**。表单表达不了的，切到代码块，同一个编辑器内完成。

## 3. 架构

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

### 7.1 AI 填充单步（最高价值）

用户在某一步骤的表单中点击「AI 填充」，描述意图：

```
用户输入: "POST /api/proof 提交 JSON body，包含 marker 参数"

AI 填充:
  method: POST
  path: /api/proof
  headers: Content-Type: application/json
  body: {"marker": "{{params.marker}}"}
```

上下文窗口小、约束明确，生成质量远高于生成整个 EXP。

### 7.2 AI 生成清理步骤

根据验证步骤自动建议清理逻辑：

```
验证步骤: POST /api/proof  →  body: {"marker": "{{marker}}"}
AI 建议: DELETE /api/proof/{{marker}}  (反向操作)
用户确认或修改
```

### 7.3 AI 全文生成（降级方案）

用户输入自然语言描述 → AI 生成完整 EXP YAML → 导入到 Builder → 用户在表单中微调。

```
用户: "验证 CVE-2024-1234 的 RCE，目标 /api/upload，
      POST 上传文件触发命令执行，需要清理上传的文件"

AI → 完整 YAML → Builder 解析为步骤管线 → 用户微调参数
```

### 7.4 AI 辅助定位

在 Code Escape Hatch 模式下，用户选中代码行 → Ctrl+K 描述意图 → AI 修改选中片段。

## 8. YAML 双向同步

表单和 YAML 预览始终保持同步：

```
表单修改 → 实时生成 YAML (单向，简单)
YAML 手动编辑 → 解析回表单 (双向，复杂)
```

### 8.1 同步策略

| 场景 | 策略 |
|------|------|
| 表单 → YAML | 实时生成，无损 |
| YAML → 表单 | 尝试解析，成功则更新表单 |
| YAML 无法解析为表单 | 保持 YAML 编辑模式，表单显示「手动编辑中，切换回表单将覆盖 YAML 修改」 |
| YAML 语法错误 | 红色波浪线标记，阻止保存 |

### 8.2 模式切换

```
[表单模式] ←→ [YAML 模式]

切换到 YAML: 表单当前状态序列化为 YAML，打开 Monaco 编辑器
切换到表单: 解析 YAML，成功则恢复表单；失败则提示确认覆盖
```

## 9. 数据模型

### 9.1 前端 Step 数据结构

```typescript
interface ExpStep {
  id: string;              // 唯一 ID
  type: 'http' | 'tcp' | 'extract' | 'evidence' | 'matcher' 
      | 'condition' | 'loop' | 'code';
  label: string;           // 用户可见的步骤名
  config: HttpStepConfig | TcpStepConfig | ExtractStepConfig 
        | EvidenceStepConfig | MatcherStepConfig 
        | ConditionStepConfig | LoopStepConfig | CodeStepConfig;
  outputVar?: string;      // 输出变量名
}

interface HttpStepConfig {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  path: string;            // 支持 {{BaseURL}} 和 {{params.*}} 模板
  headers: Record<string, string>;
  body?: string;           // JSON string 或 raw
  bodyType: 'none' | 'json' | 'form' | 'raw';
  timeout?: number;
}

interface ExpPipeline {
  info: ExpInfo;
  params: ExpParam[];
  steps: ExpStep[];        // 验证步骤管线
  cleanup: ExpStep[];      // 清理步骤
  mode: 'form' | 'yaml';  // 当前编辑模式
}
```

### 9.2 Pipeline → YAML 转换

```typescript
function pipelineToYAML(pipeline: ExpPipeline): string {
  const engine = inferEngine(pipeline.steps);
  const capabilities = inferCapabilities(pipeline.steps, pipeline.cleanup);
  
  if (engine === 'nuclei') {
    return generateNucleiYAML(pipeline, capabilities);
  } else {
    return generateStarlarkYAML(pipeline, capabilities);
  }
}
```

### 9.3 YAML → Pipeline 解析

```typescript
function yamlToPipeline(yaml: string): ExpPipeline | null {
  const parsed = parseYAML(yaml);
  if (!parsed) return null;  // 解析失败，保持 YAML 模式
  
  return {
    info: extractInfo(parsed),
    params: extractParams(parsed),
    steps: extractSteps(parsed),
    cleanup: extractCleanup(parsed),
    mode: 'form',
  };
}
```

## 10. 工程细节

### 10.1 撤销/重做

表单编辑维护操作历史栈：

```typescript
interface EditorHistory {
  past: ExpPipeline[];      // 撤销栈
  present: ExpPipeline;     // 当前状态
  future: ExpPipeline[];    // 重做栈
}
```

- Ctrl+Z 撤销，Ctrl+Shift+Z 重做
- 每次表单 onChange 入栈，防抖 500ms 合并连续输入
- 最大历史深度 50 步
- YAML 编辑模式使用 Monaco 内置 undo，不与表单历史共享

### 10.2 自动保存

```
表单修改 → 防抖 2s → 保存到 localStorage (草稿)
                → 调用 saveArsenal API (已登录时)
```

- localStorage 保存最近一次完整 YAML，刷新页面可恢复
- 保存时产生 content hash，避免无变更重复写入
- 冲突检测：如果后端内容 hash 与本地不一致，提示「内容已被他人修改，是否覆盖」

### 10.3 已有 YAML 导入

用户可以在 Builder 中导入已有的手写 EXP YAML：

```
[导入 YAML] → 解析 → 成功 → 加载到表单
                   → 失败 → 提示「无法解析为表单，已加载到 YAML 模式」
```

解析策略：

1. 基本信息（info/policy/params）→ 总是能解析
2. Nuclei http/steps → 映射为 HttpStep/MatcherStep/ExtractStep
3. Starlark scripts → 映射为 CodeStep（整段代码块，不拆分）；TCP 能力保持为 Starlark 模式
4. 复杂 Starlark（多函数/条件/循环）→ 保持 CodeStep，不尝试拆解

不能完全映射的 YAML 保持 YAML 模式编辑，表单显示只读摘要。

### 10.4 步骤变量依赖管理

每个 Step 的输出绑定变量名，后续 Step 通过 `{{var}}` 引用。

删除 Step 时的处理：

```
删除 Step 2 (输出变量: resp)
  → 检查后续步骤是否引用 resp
  → 有引用: 弹出警告「Step 3/5 引用了 resp，删除后将清除这些引用」
  → 用户确认 → 清除引用 → 删除
  → 用户取消 → 保留
```

变量面板显示当前管线所有可用变量：

```
┌─ 可用变量 ────────────────────────┐
│  params.cmd     = string          │
│  params.marker  = string          │
│  resp           = HTTP Response   │ ← Step 1 输出
│  proof_id       = string          │ ← Step 2 提取
│  output         = string          │ ← Step 3 提取
└───────────────────────────────────┘
```

### 10.5 Cleanup 步骤关联

Cleanup 步骤与验证步骤的关联方式：

- **自动关联**：用户在某验证步骤上点击「添加清理」，该 cleanup 步骤标记为对应验证步骤的反向操作
- **显式关联**：cleanup 步骤的 `params` 引用验证步骤的输出变量
- **独立清理**：cleanup 步骤不关联特定验证步骤，执行时全部运行

YAML 中不体现关联关系（cleanup 是独立 section），关联仅用于 Builder UI 的视觉提示。

### 10.6 YAML 注释保留

- Builder 生成的 YAML 默认不包含注释
- 如果用户在 YAML 模式下添加了注释，切换到表单模式时注释丢失，需提示
- 可选方案：用 `yaml.Document` 的 comment API 保留头部注释（描述/作者/变更记录）

### 10.7 EXP 版本管理

Builder 修改 EXP 后的行为：

- 保存草稿：不递增版本号，覆盖 `arsenal.content`
- 提交审核：递增版本号，`ExploitRule.Version = arsenal.Version`
- 版本历史：通过 `arsenal.PreviousContent` / `arsenal.PreviousHash` 回滚
- Builder 不引入额外的版本系统，复用现有 Arsenal 版本机制

### 10.8 实时校验

表单填写时即时反馈：

| 校验项 | 时机 | 反馈方式 |
|--------|------|----------|
| ID 格式 | 输入时 | 红色提示「仅允许小写字母、数字、连字符」 |
| 必填字段 | 失焦时 | 红色边框 + 提示文字 |
| 路径模板语法 | 输入时 | 检查 `{{}}` 配对 |
| JSON body 格式 | 输入时 | JSON parse 校验 |
| capabilities 一致性 | 步骤变更时 | 自动推导并显示差异 |
| cleanup 完整性 | 保存时 | cleanup_required 但无步骤 → 警告 |
| YAML 语法 | 切换模式时 | Monaco 内置校验 |

### 10.9 性能优化

- YAML 生成：防抖 300ms，避免每次 keystroke 触发
- 步骤列表：虚拟滚动（>20 步时启用）
- Monaco 预览：diff 模式更新，不全量替换
- AI 调用：debounce 500ms + loading 状态 + 取消机制

## 11. 安全设计

### 11.1 Capabilities 自动推导审计

自动推导的结果必须展示给用户确认：

```
┌─ 自动推导结果 ──────────────────────────┐
│  根据您的步骤配置，自动推导以下能力:       │
│                                          │
│  ✓ http.request  (来自 Step 1: HTTP 请求)│
│  ✓ evidence.write (来自 Step 3: 证据)    │
│  ✓ cleanup.defer  (来自清理步骤)          │
│                                          │
│  您可以手动调整:                          │
│  [ ] tcp.connect    ← 未使用，保持关闭    │
│  [ ] extract.match  ← 未使用，保持关闭    │
│                                          │
│  [确认]  [手动调整]                       │
└──────────────────────────────────────────┘
```

原则：推导结果只增不减（不会自动移除用户手动添加的 capability）。

### 11.2 危险组合拦截

Builder 在保存前检查：

| 组合 | 拦截方式 |
|------|----------|
| risk_level=destructive + 无 cleanup | 阻止保存，提示必须提供清理步骤 |
| 未获得 EXP 授权的用户 | 阻止访问 Builder 的保存、干跑和执行入口 |
| risk_level=high/destructive + 已授权 operator/admin | 执行前提示风险确认 |
| insecure_tls=true + 外网目标 | 警告「跳过 TLS 验证仅建议用于内网自签名目标」 |
| 未声明的 capability 被代码块使用 | 阻止保存，提示需要声明 |
| cleanup_required=true 但无 cleanup 步骤 | 阻止保存 |

### 11.3 AI 生成内容安全

- AI 生成的步骤自动经过 `scanScriptForForbiddenSymbols` 校验
- AI 生成的 YAML 自动经过 `validateExpPackage` 校验
- 不合格内容标记为「AI 生成，请人工审核」，不自动保存
- AI 不会生成 `insecure_tls: true` 或 `risk_level: destructive`，除非用户显式要求

### 11.4 XSS / 注入防护

- 表单输入字段全部转义后再渲染
- YAML 模板中的 `{{params.*}}` 渲染时参数化，不直接拼接到 HTTP 请求
- CodeStep 中的用户代码在 Agent 侧 Starlark 沙箱执行，不经过 Builder

## 12. 用户旅程

### 12.1 发现入口

| 入口 | 场景 |
|------|------|
| 弹药库管理 → EXP 验证库 → 新建 | 主入口，创建新 EXP |
| 漏洞详情页 → EXP 候选 → 定制 | 从漏洞上下文创建，自动填充产品/CVE |
| 扫描报告 → 修复验证 → 创建 EXP | 从扫描结果创建 |
| EXP 列表 → 编辑 | 修改已有 EXP |

### 12.2 创建流程

```
用户点击「新建 EXP」
  → 弹出模式选择: [表单构建] [YAML 编辑] [从模板创建]
  → 选择「表单构建」
  → 进入 Builder，默认加载空模板
  → 填写基本信息（30 秒）
  → 添加第一个 HTTP 步骤（1 分钟）
  → 配置 matcher（30 秒）
  → 系统自动推导 capabilities（即时）
  → 预览 YAML（即时）
  → 保存草稿（Ctrl+S）
  → Dry-Run 验证（可选）
  → 提交审核
```

### 12.3 编辑流程

```
用户点击 EXP 列表的「编辑」
  → 检测 YAML 是否可解析为表单
  → 可解析 → 打开 Builder 表单模式
  → 不可解析 → 打开 YAML 编辑模式，顶部提示「此 EXP 包含复杂脚本，已切换为 YAML 模式」
  → 用户编辑
  → 保存
```

### 12.4 错误恢复

| 错误场景 | 恢复方式 |
|----------|----------|
| 表单填写错误 | 实时校验提示，不阻止编辑 |
| YAML 语法错误 | Monaco 红色标记，阻止保存但不丢失内容 |
| 网络断开 | localStorage 自动保存，恢复连接后同步 |
| AI 生成失败 | 提示重试，不影响当前编辑状态 |
| 切换模式丢失数据 | 二次确认弹窗 |
| 浏览器崩溃 | localStorage 恢复最近草稿 |

## 13. 键盘快捷键

| 快捷键 | 功能 |
|--------|------|
| Ctrl+S | 保存草稿 |
| Ctrl+Z | 撤销 |
| Ctrl+Shift+Z | 重做 |
| Ctrl+Enter | 提交审核 |
| Tab | 切换到下一个表单字段 |
| Ctrl+↑ / Ctrl+↓ | 上移/下移当前步骤 |
| Ctrl+D | 复制当前步骤 |
| Delete | 删除当前步骤（需确认） |
| Ctrl+K | AI 填充当前步骤 |
| Ctrl+P | 预览 YAML |

## 14. 测试策略

| 层级 | 测试内容 | 工具 |
|------|----------|------|
| 单元测试 | pipelineToYAML / yamlToPipeline 转换函数 | Jest |
| 组件测试 | 每种 Step 表单的渲染和交互 | React Testing Library |
| 集成测试 | 表单 → YAML → 保存 → 加载 → 表单 完整链路 | Cypress |
| E2E 测试 | Builder 创建 EXP → 审核 → 执行 → 查看结果 | Cypress |
| 回归测试 | 已有手写 YAML 能正确加载到 Builder | 快照对比 |

## 15. 实施阶段

### Phase 1：表单基础 + HTTP 步骤（2 周）

- ✅ 基本信息表单（ID / 名称 / 风险 / 产品 / CVE / 描述）
- ✅ 参数定义表单（name / type / required / description）
- ✅ HttpStep 表单（method / path / headers / body）
- ✅ MatcherStep 表单（status / word / regex）
- ✅ ExtractStep 表单（json path / regex）
- ✅ Cleanup HttpStep 表单
- ✅ 自动推导 engine / capabilities / cleanup_required
- ✅ Live YAML：通过 Builder / YAML 分段切换查看和编辑同一份内容
- ✅ 保存草稿：复用现有 Arsenal 保存入口
- ✅ EvidenceStep：Starlark Builder 中提供独立证据写入步骤
- ⚠️ YAML → 表单为轻量解析，只保证 Builder 生成的 HTTP EXP 和常见手写 HTTP EXP 能稳定回填

交付物：用户可通过表单创建简单 HTTP 验证 EXP，无需手写 YAML。

### Phase 2：进阶步骤 + AI 辅助（2 周）

- ✅ ConditionStep 表单（Starlark 条件表达式）
- ✅ TcpStep 表单（导出为 Starlark `tcp.connect`）
- ✅ LoopStep 表单（循环/重试代码块）
- ✅ YAML → 表单反向解析（支持基础字段、HTTP/Nuclei、Starlark `scripts.run/cleanup` 回填）
- ✅ AI 填充单步（通过当前 YAML 上下文生成完整可应用 YAML）
- ✅ AI 生成清理步骤建议
- ✅ Monaco YAML schema 实时校验配置

交付物：支持带条件分支的复杂 EXP，AI 辅助减少重复劳动。

### Phase 3：Code Escape Hatch + AI 全文生成（2 周）

- ✅ CodeStep 类型（Starlark 代码块）
- ✅ 表单 → 代码单向转换
- ✅ 代码 → 表单尝试解析（完整 `def run/cleanup` 保留在 Code Escape Hatch）
- ✅ AI 全文生成 → 导入 Builder
- ✅ 代码块内 API 自动补全提示（Monaco YAML 补全 `http.request/tcp.connect/extract/result` 等）
- ✅ AI 代码片段编辑入口（复用当前 EXP 编辑目标）

交付物：任意复杂度的 EXP 都能在 Builder 中完成。

### Phase 4：模板库 + 示例（1 周）

- 按场景分类的 EXP 模板库（RCE / SQLi / 文件读取 / 认证绕过 / ...）
- 模板一键导入到 Builder
- 社区模板分享机制（导出/导入 YAML）

交付物：新手从模板开始，30 秒创建第一个 EXP。

## 16. 与现有系统的关系

```
┌──────────────────────────────────────────────────────────┐
│                    EXP Builder (新增)                      │
│  表单编辑 → YAML 生成 → 保存草稿                           │
└──────────────────────────┬───────────────────────────────┘
                           │ 输出标准 YAML
                           ▼
┌──────────────────────────────────────────────────────────┐
│              现有弹药库管理 (不变)                          │
│  arsenal.content ← YAML 存储                              │
│  validateExpPackage() ← 校验                              │
│  materializeExploitRule() ← 物化                          │
│  approve/deprecate/delete ← 生命周期                      │
└──────────────────────────┬───────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────┐
│              现有执行引擎 (不变)                            │
│  ExploitTemplate ← 解析 YAML                             │
│  Nuclei / Starlark 引擎执行                               │
│  cleanup 派发                                             │
└──────────────────────────────────────────────────────────┘
```

Builder 只是 YAML 的可视化编辑层，不改变后端任何逻辑。生成的 YAML 与手写 YAML 结构完全一致，复用全部现有校验/物化/执行/清理链路。当前实现直接挂载在 EXP 验证库的新增/编辑 Drawer 内，降低入口复杂度，不额外引入独立 Builder 页面。

## 17. 技术选型

| 组件 | 选型 | 理由 |
|------|------|------|
| 表单组件 | Ant Design Form | 项目已使用 Ant Design |
| 拖拽排序 | @dnd-kit/sortable | 轻量、React 原生、不依赖 jQuery |
| YAML 编辑 | Monaco Editor | 项目已集成，支持自定义 schema |
| YAML 生成 | yaml (npm) | 标准 YAML 库，支持注释保留 |
| AI 集成 | 现有 AI Copilot API | 复用已有基础设施 |
| 状态管理 | React useState/useReducer | 管线状态不复杂，无需 Redux |

## 18. 风险与缓解

| 风险 | 影响 | 缓解 |
|------|------|------|
| YAML ↔ 表单双向同步丢失信息 | 用户修改被覆盖 | 仅在结构可解析时允许双向，否则提示 |
| Code Escape Hatch 后无法切回表单 | 用户被困在代码模式 | 明确提示；提供「从 YAML 重建表单」按钮 |
| 自动推导 capabilities 不准确 | 校验失败或权限过大 | 推导结果展示给用户确认，允许手动调整 |
| AI 生成步骤质量不稳定 | 生成无效 YAML | 生成后自动校验，不合格则提示用户修改 |
| 步骤类型过多导致表单复杂 | 反而比 YAML 更难用 | Phase 1 只做 4 种步骤，覆盖 90% 场景 |

## 19. 变更记录

| 日期 | 阶段 | 内容 |
|------|------|------|
| 2026-05-06 | Builder Phase 1 | EXP 验证库新增 HTTP Builder：表单化维护基础信息、策略、参数、HTTP 请求、Matcher、Extractor、Cleanup；实时生成 YAML；Starlark/TCP 保持 YAML 模式；AI 回填按 engine 自动选择编辑模式 |
| 2026-05-06 | Builder Phase 2/3 | Builder 增加高级线性步骤（HTTP/TCP/条件/循环/证据/代码）、Starlark 自动导出、Code Escape Hatch、表单转代码、Starlark 脚本回填、AI 步骤/cleanup/全文生成入口、YAML schema 与 API 补全 |
| 2026-05-06 | Builder UX Simplification | Nuclei/Starlark Builder 默认隐藏低频元数据，生成 YAML 省略空字段；Starlark Builder 增加认证流、TCP+HTTP、多步提取、自定义代码场景模板，并补齐 extract/cleanup/result 步骤类型 |
