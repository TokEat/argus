package ai

import (
	"context"
	"encoding/json"
	"strings"
)

// QueryArgusDocsTool 检索 Argus 平台特有的 POC 编写规范和弹药库约束。
// LLM 已经了解 Nuclei YAML 语法，这个工具只提供 Argus 项目特有的知识。
type QueryArgusDocsTool struct{}

func (t *QueryArgusDocsTool) Name() string {
	return "QueryArgusDocs"
}

func (t *QueryArgusDocsTool) Description() string {
	return "查询 Argus 平台特有的 POC 编写规范、弹药库约束和 Workflow 挂载机制。注意：你已经了解 Nuclei YAML 语法，此工具只提供 Argus 项目特有的规范（命名约定、审批流程、Workflow 挂载格式、安全红线等）。仅在需要了解 Argus 平台规则时调用，不要用它查询通用 Nuclei 语法。"
}

func (t *QueryArgusDocsTool) InputSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"topic": map[string]interface{}{
				"type":        "string",
				"description": "查询主题: naming(命名规范)、approval(审批流程)、workflow(挂载机制)、safety(安全红线)、arsenal(弹药库结构)。留空返回全部摘要。",
				"enum":        []string{"naming", "approval", "workflow", "safety", "arsenal", ""},
			},
		},
	}
}

func (t *QueryArgusDocsTool) Execute(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var args struct {
		Topic string `json:"topic"`
	}
	if err := json.Unmarshal(input, &args); err != nil {
		return nil, err
	}

	topic := strings.ToLower(strings.TrimSpace(args.Topic))
	sections := getArgusDocSections(topic)

	return map[string]interface{}{
		"topic":          args.Topic,
		"matched_topics": len(sections),
		"docs":           sections,
	}, nil
}

func getArgusDocSections(topic string) []map[string]string {
	all := []struct {
		key     string
		topic   string
		content string
	}{
		{
			key:   "naming",
			topic: "POC 命名与元数据规范",
			content: `## Argus POC 命名规范

### id 命名
- 格式: CVE编号-产品名-漏洞类型，全小写连字符分隔
- 无 CVE 时: 产品名-漏洞类型（如 tongweb-rce、shiro-deserialization）
- id 会被存储为 PocRule.Name，也是 Workflow 挂载时 poc_name 的引用标识
- 禁止使用中文、空格、特殊字符

### severity 标准
- critical: RCE、任意文件上传可 getshell、认证绕过+管理权限
- high: SQLi（可读敏感数据）、SSRF（可达内网）、任意文件读取（含敏感信息）
- medium: 存储型 XSS、信息泄露（含凭证/配置）、越权
- low: 反射型 XSS、路径遍历（不含敏感文件）
- info: 版本探测、指纹识别、接口枚举（不算漏洞，仅信息收集）

### tags 要求
- 必须包含产品名（小写）— Workflow 可按 tag 匹配
- 必须包含漏洞类型: rce/sqli/xss/ssrf/lfi/upload/deserialization/auth-bypass 等
- 有 CVE 时加: cve,cveYYYY
- 示例: tags: cve,cve2024,rce,tongweb

### source_file
- Argus 用 source_file（即文件名）作为唯一标识，格式: id.yaml
- 示例: CVE-2024-1234-tongweb-rce.yaml`,
		},
		{
			key:   "approval",
			topic: "审批与状态流程",
			content: `## POC 审批状态流程

### State 生命周期
Draft → Pending → Approved
         ↓
       Rejected

- **Draft**: 新建或修改后的初始状态，不会分发到 Agent
- **Pending**: 提交审核后的状态
- **Approved**: 审核通过，Agent 下次同步时会拉取该 POC
- 只有 State=Approved 且 Enabled=true 的 POC 才会被 Agent 执行

### 关键行为
- 每次保存内容会更新 content_hash 和 version（自增）
- Agent 通过 rule_version 对比判断是否需要重新同步弹药库
- AI 生成/修改的 POC 只能保存为 Draft，不会自动审批
- 前端有"应用到编辑器"→"保存草稿"两步确认流程

### 审查维度
平台会对 POC 进行静态检查：
1. 危险 payload 检测（rm -rf、DROP TABLE、shutdown 等）
2. 重复候选匹配（基于 id 和 tags 查找已有类似 POC）
3. Workflow 挂载建议（检查是否有产品指纹可以关联）`,
		},
		{
			key:   "workflow",
			topic: "Workflow 挂载机制",
			content: `## Argus Workflow 挂载机制

### 核心原理
扫描流程: 指纹识别 → 匹配产品 → 通过 Workflow 触发关联 POC
不挂载 Workflow 的 POC = 永远不会被自动执行的 POC

### Workflow YAML 格式（Argus 私有格式，非 Nuclei 标准）
` + "```yaml" + `
# 文件名: workflow-tongweb.yaml
TongWeb:                    # 产品名（必须与指纹 product_name 一致）
  type:
    - product               # 匹配方式: product（精确）/ regex（正则）/ tag（按POC标签）
  pocs:
    - CVE-2024-1234-tongweb-rce    # poc_name，对应 POC 的 id 字段
    - tongweb-info-disclosure
` + "```" + `

### DB 存储结构 (WorkflowRule)
每条规则存储一行：
| 字段 | 说明 |
|------|------|
| product_name | 产品名，需与指纹识别结果精确匹配 |
| poc_name | POC 的 id 值，或 source_file 文件名 |
| match_type | product / regex / tag |

唯一约束: tenant_id + product_name + poc_name + match_type

### 触发阶段（Scanner 侧）
- Root: 端口扫描后立即执行（不依赖路径发现）
- Base: 基础探测后执行（已获取 BaseURL）
- Dir: 目录探测后执行（已发现特定路径）
- Dir-Fallback: 目录探测未命中时的降级

### 指纹关联
指纹文件格式（Argus 私有）：
` + "```yaml" + `
# 文件名: finger-tongweb.yaml
TongWeb:                    # product_name，Workflow 中要精确引用这个名字
  - "body=\"TongWeb\"&&status=\"200\""
  - "header=\"TongWeb\""
` + "```" + `

### 常见错误
1. Workflow 中 product_name 与指纹中的 product_name 大小写不一致
2. poc_name 拼写错误导致指向不存在的 POC
3. 未给 POC 设置 Approved 状态导致 Workflow 挂载了但不执行`,
		},
		{
			key:   "safety",
			topic: "安全红线",
			content: `## Argus POC 安全红线

### 强制禁止（违反则直接 Rejected）
1. 破坏性命令: rm -rf、DROP TABLE、FORMAT、shutdown、reboot
2. 写入 Webshell 或持久化后门
3. 创建用户、修改密码、修改系统配置
4. 大规模数据导出（SELECT * FROM users 等）
5. DoS 类验证（发送海量请求、触发资源耗尽）

### 推荐验证方式
| 漏洞类型 | 推荐方式 |
|---------|---------|
| RCE | expr 数学运算（expr 41312+12389）或 echo 唯一字符串 |
| SSRF | {{interactsh-url}} OOB 回调 |
| SQLi | 时间盲注(sleep) 或 数学运算 |
| XXE | {{interactsh-url}} OOB 或读 /etc/hostname |
| 文件读取 | 读 /etc/passwd 或 win.ini（只读不写） |
| 信息泄露 | 精确匹配关键字段 |

### 误报控制要求
- 禁止只用单一通用字符串（"success"、"ok"、"error"）作为唯一 matcher
- 推荐: matchers-condition: and + 至少 2 个独立条件
- severity: info 的 POC 不标记为漏洞，仅收集信息
- 对版本号使用精确正则，避免过宽匹配

### 性能要求
- max-request metadata 必须准确反映实际请求数
- 单个 POC 不超过 5 个请求步骤
- 超时默认 10s，特殊场景（盲注）不超过 30s`,
		},
		{
			key:   "arsenal",
			topic: "弹药库结构总览",
			content: `## Argus 弹药库（Arsenal）体系

### 四种弹药类型
| 类型 | DB类型 | 说明 | 格式 |
|------|--------|------|------|
| POC | poc | 漏洞验证模板 | Nuclei YAML |
| 指纹 | finger | 产品识别规则 | Argus 私有 YAML: {产品名: [表达式]} |
| Workflow | workflow | 产品→POC 挂载 | Argus 私有 YAML: {产品名: {type: [], pocs: []}} |
| 目录探测 | dir | 路径字典 | Argus 私有 YAML: {产品名: [路径]} |

### 存储结构
所有弹药原始内容存储在 arsenals 表（id, tenant_id, type, file_name, content, hash, state, version）。
结构化元数据自动拆分到:
- poc_rules（Name, Severity, Tags, Author...）
- fingerprint_rules（ProductName, RuleExpr...）
- workflow_rules（ProductName, PocName, MatchType...）
- dir_rules（ProductName, Path...）

### 多租户隔离
- 所有规则表都有 tenant_id 字段
- 默认租户为 "default"
- 规则的 Enabled 由 State=Approved 控制

### 分发机制
1. 管理员在 Web UI 编辑/上传弹药 → 保存到 arsenals 表
2. 审批通过（State=Approved）→ 同步到结构化规则表
3. Agent 定时心跳比对 rule_version → 发现变更时拉取 SQLite 快照
4. Agent 本地加载规则 → 扫描时按 Workflow 触发相应 POC`,
		},
	}

	if topic == "" {
		// 返回所有章节的精简摘要
		var sections []map[string]string
		for _, doc := range all {
			sections = append(sections, map[string]string{
				"topic":   doc.topic,
				"content": doc.content,
			})
		}
		return sections
	}

	// 按 topic key 精确匹配
	for _, doc := range all {
		if doc.key == topic {
			return []map[string]string{
				{"topic": doc.topic, "content": doc.content},
			}
		}
	}

	// 未匹配到时返回全部
	var sections []map[string]string
	for _, doc := range all {
		sections = append(sections, map[string]string{
			"topic":   doc.topic,
			"content": doc.content,
		})
	}
	return sections
}
