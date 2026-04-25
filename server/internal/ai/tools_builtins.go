package ai

import (
	"context"
	"encoding/json"
	"strings"
)

// QueryArgusDocsTool 检索 Argus 平台 POC 编写规范和 Nuclei YAML 最佳实践
type QueryArgusDocsTool struct{}

func (t *QueryArgusDocsTool) Name() string {
	return "QueryArgusDocs"
}

func (t *QueryArgusDocsTool) Description() string {
	return "查询 Argus 平台的 POC 编写规范和 Nuclei YAML 语法最佳实践。支持按主题检索：basic（基础结构）、matchers（匹配器）、extractors（提取器）、flow（多步骤）、variables（变量与表达式）、protocols（协议支持）、safety（安全规范）、workflow（工作流挂载）。传入 query 后会按关键词智能匹配最相关的章节返回。"
}

func (t *QueryArgusDocsTool) InputSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"query": map[string]interface{}{
				"type":        "string",
				"description": "查询的问题或主题关键词，例如 'matchers 多条件组合'、'多步骤请求'、'变量提取' 等",
			},
		},
		"required": []string{"query"},
	}
}

func (t *QueryArgusDocsTool) Execute(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var args struct {
		Query string `json:"query"`
	}
	if err := json.Unmarshal(input, &args); err != nil {
		return nil, err
	}

	query := strings.ToLower(args.Query)
	sections := matchDocSections(query)

	return map[string]interface{}{
		"query":          args.Query,
		"matched_topics": len(sections),
		"docs":           sections,
	}, nil
}

// matchDocSections 根据 query 关键词匹配相关文档章节
func matchDocSections(query string) []map[string]string {
	type docEntry struct {
		Topic    string
		Keywords []string
		Content  string
	}

	docs := []docEntry{
		{
			Topic:    "基础结构",
			Keywords: []string{"basic", "基础", "结构", "模板", "template", "id", "info", "metadata", "severity", "tags", "入门"},
			Content: `# Argus POC 基础结构

每个 POC 必须包含 id 和 info 块：

` + "```yaml" + `
id: CVE-2024-XXXX-product-rce

info:
  name: ProductName - Remote Code Execution
  author: your-name
  severity: critical          # critical / high / medium / low / info / unknown
  description: |
    ProductName X.Y.Z 存在远程代码执行漏洞。
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2024-XXXX
    - https://example.com/advisory
  tags: cve,cve2024,rce,productname
  metadata:
    max-request: 1
    verified: true
    shodan-query: http.title:"ProductName"
` + "```" + `

## 命名规范
- id 格式: CVE编号-产品名-漏洞类型（全小写，用连字符分隔）
- severity 必须准确反映真实影响
- tags 至少包含：漏洞类型(rce/sqli/xss/ssrf 等)、产品名
- 无 CVE 时使用: productname-vuln-type 格式`,
		},
		{
			Topic:    "HTTP 请求",
			Keywords: []string{"http", "request", "请求", "method", "path", "header", "body", "post", "get", "raw", "cookie"},
			Content: `# HTTP 请求配置

## 基本请求
` + "```yaml" + `
http:
  - method: GET
    path:
      - "{{BaseURL}}/api/v1/version"
    headers:
      User-Agent: "Mozilla/5.0"
      Accept: "application/json"
` + "```" + `

## POST 请求
` + "```yaml" + `
http:
  - method: POST
    path:
      - "{{BaseURL}}/api/login"
    headers:
      Content-Type: "application/json"
    body: '{"username":"admin","password":"admin"}'
` + "```" + `

## Raw 请求（精确控制）
` + "```yaml" + `
http:
  - raw:
      - |
        GET /path HTTP/1.1
        Host: {{Hostname}}
        Authorization: Bearer {{token}}
` + "```" + `

## 重定向与连接控制
- redirects: true/false — 是否跟随重定向
- max-redirects: 3
- cookie-reuse: true — 跨请求保持 Cookie
- host-redirects: true — 允许跨域重定向`,
		},
		{
			Topic:    "匹配器 (Matchers)",
			Keywords: []string{"matcher", "匹配", "status", "word", "regex", "binary", "dsl", "condition", "and", "or", "算命中", "命中", "判断"},
			Content: `# Matchers 匹配器

## 类型一览
| 类型 | 说明 | 示例 |
|------|------|------|
| status | HTTP 状态码 | status: [200] |
| word | 关键字包含（默认 body） | words: ["success"] |
| regex | 正则匹配 | regex: ["version[:\s]+\d+\.\d+"] |
| binary | 二进制匹配 | binary: ["504b0304"] |
| dsl | DSL 表达式 | dsl: ["status_code == 200 && contains(body, 'ok')"] |
| size | 响应体大小 | size: [1234] |
| xpath | XPath 匹配 | xpath: ["//title[contains(text(),'Admin')]"] |

## 多条件组合
` + "```yaml" + `
matchers-condition: and    # 所有 matcher 都必须命中（默认 or）

matchers:
  - type: status
    status:
      - 200

  - type: word
    part: body             # 匹配范围: body / header / all / interactsh_protocol 等
    words:
      - "administrator"
      - "dashboard"
    condition: or          # 组内条件: or = 任一匹配; and = 全部匹配
` + "```" + `

## 两个请求都必须命中
当 POC 包含多个 HTTP 请求时，每个请求可有独立 matcher，通过请求级 matchers-condition 控制：
` + "```yaml" + `
http:
  - method: GET
    path:
      - "{{BaseURL}}/step1"
    matchers:
      - type: word
        words:
          - "token_abc"
        internal: true       # internal=true 表示仅做内部校验，不作为最终结果

  - method: POST
    path:
      - "{{BaseURL}}/step2"
    body: 'token={{token_abc}}'
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "success"
` + "```" + `

## 反向匹配
` + "```yaml" + `
matchers:
  - type: word
    words:
      - "error"
    negative: true    # 反向：如果包含该关键字则不命中
` + "```" + `

## 关键提示
- matchers-condition: and 放在请求块级别（与 matchers 同级）
- condition: and/or 放在单个 matcher 内部（控制同一 matcher 的多个 words/regex 之间的关系）
- part 可选: body / header / all / response / interactsh_protocol / interactsh_request`,
		},
		{
			Topic:    "提取器 (Extractors)",
			Keywords: []string{"extractor", "提取", "extract", "变量", "capture", "regex_group", "json", "kval", "xpath"},
			Content: `# Extractors 提取器

## 正则提取
` + "```yaml" + `
extractors:
  - type: regex
    name: token
    part: body
    group: 1                 # 提取第一个捕获组
    regex:
      - '"token"\s*:\s*"([^"]+)"'
    internal: true           # true=仅供后续步骤使用，不输出到结果
` + "```" + `

## JSON 提取
` + "```yaml" + `
extractors:
  - type: json
    name: user_id
    part: body
    json:
      - '.data.user.id'     # JQ 语法
    internal: true
` + "```" + `

## KVal 提取（键值对）
` + "```yaml" + `
extractors:
  - type: kval
    name: session
    kval:
      - "set-cookie"        # 从 header 提取
    part: header
    internal: true
` + "```" + `

## XPath 提取
` + "```yaml" + `
extractors:
  - type: xpath
    name: page_title
    xpath:
      - "//title/text()"
    internal: true
` + "```" + `

## 跨请求变量传递
提取出的值通过 {{变量名}} 在后续请求中引用：
` + "```yaml" + `
http:
  - method: GET
    path:
      - "{{BaseURL}}/api/csrf"
    extractors:
      - type: regex
        name: csrf_token
        regex:
          - 'csrf_token=([a-f0-9]+)'
        group: 1
        internal: true

  - method: POST
    path:
      - "{{BaseURL}}/api/action"
    body: 'csrf={{csrf_token}}&cmd=id'
` + "```",
		},
		{
			Topic:    "多步骤请求与 Flow 控制",
			Keywords: []string{"flow", "多步骤", "multi", "step", "chain", "req", "iterate", "循环", "条件执行", "两个请求"},
			Content: `# 多步骤请求与 Flow 控制

## 顺序多请求（默认行为）
多个请求块按顺序执行，提取的变量自动向下传递：
` + "```yaml" + `
http:
  - method: GET
    path:
      - "{{BaseURL}}/login"
    extractors:
      - type: regex
        name: csrf
        regex:
          - 'name="csrf" value="([^"]+)"'
        group: 1
        internal: true

  - method: POST
    path:
      - "{{BaseURL}}/login"
    body: 'user=admin&pass=admin&csrf={{csrf}}'
    redirects: true
    cookie-reuse: true
    matchers:
      - type: word
        words:
          - "Welcome, admin"
` + "```" + `

## Flow 控制（高级）
使用 flow 字段实现条件执行和循环：
` + "```yaml" + `
flow: |
  http(1)
  if resp.StatusCode == 200 {
    set("found", true)
    http(2)
  }
` + "```" + `

## 使用 iterate 进行批量检测
` + "```yaml" + `
variables:
  paths:
    - "/admin"
    - "/manager"
    - "/console"

flow: |
  for path in iterate(paths) {
    set("fuzz_path", path)
    http(1)
  }

http:
  - method: GET
    path:
      - "{{BaseURL}}{{fuzz_path}}"
` + "```" + `

## 关键原则
- 默认多个 http 块按序执行，不需要 flow
- flow 仅在需要条件分支或循环时使用
- req(N) 或 http(N) 引用第 N 个请求块（1-indexed）
- cookie-reuse: true 可在多步骤间保持会话`,
		},
		{
			Topic:    "变量与 DSL 表达式",
			Keywords: []string{"variable", "变量", "dsl", "expression", "表达式", "helper", "函数", "payload", "rand", "base64", "md5", "interactsh"},
			Content: `# 变量与 DSL 表达式

## 内置变量
| 变量 | 说明 |
|------|------|
| {{BaseURL}} | 完整目标 URL (含协议和端口) |
| {{RootURL}} | 根 URL（不含路径） |
| {{Hostname}} | 主机名 |
| {{Host}} | 主机名:端口 |
| {{Port}} | 端口号 |
| {{Path}} | URL 路径部分 |
| {{Scheme}} | 协议 http/https |
| {{interactsh-url}} | OOB 交互地址 |

## 自定义变量
` + "```yaml" + `
variables:
  auth_token: "admin_token_123"
  encoded: '{{base64("admin:admin")}}'
  random: '{{rand_int(10000, 99999)}}'
` + "```" + `

## 常用 DSL 函数
| 函数 | 说明 | 示例 |
|------|------|------|
| base64(str) | Base64 编码 | {{base64("hello")}} |
| base64_decode(str) | Base64 解码 | {{base64_decode("aGVsbG8=")}} |
| url_encode(str) | URL 编码 | {{url_encode("a=1&b=2")}} |
| md5(str) | MD5 哈希 | {{md5("password")}} |
| sha256(str) | SHA256 哈希 | {{sha256("data")}} |
| contains(str, sub) | 是否包含 | contains(body, "admin") |
| rand_int(min, max) | 随机整数 | {{rand_int(1000, 9999)}} |
| rand_text_alpha(n) | 随机字母 | {{rand_text_alpha(8)}} |
| to_lower(str) | 转小写 | to_lower(header) |
| len(str) | 字符串长度 | len(body) > 100 |
| regex(pattern, str) | 正则匹配 | regex("v\d+", body) |
| replace(str, old, new) | 替换 | replace(body, " ", "") |
| trim(str) | 去空白 | trim(header) |
| concat(a, b, ...) | 拼接 | concat(path, "/api") |
| generate_java_gadget | Java 反序列化 | 高级利用 |

## Payloads（字典）
` + "```yaml" + `
payloads:
  username:
    - admin
    - root
    - test
  password:
    - admin
    - 123456
    - password

attack: clusterbomb   # 或 pitchfork、sniper
` + "```",
		},
		{
			Topic:    "协议支持",
			Keywords: []string{"protocol", "协议", "tcp", "network", "dns", "headless", "websocket", "ssl", "javascript", "code"},
			Content: `# 协议支持

## TCP / Network 协议
` + "```yaml" + `
tcp:
  - inputs:
      - data: "GET / HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n"
    host:
      - "{{Hostname}}"
    port: "8080"
    read-size: 2048
    matchers:
      - type: word
        words:
          - "Apache"
` + "```" + `

## DNS 协议
` + "```yaml" + `
dns:
  - name: "{{FQDN}}"
    type: A
    class: inet
    recursion: true
    matchers:
      - type: word
        words:
          - "127.0.0.1"
` + "```" + `

## Headless（浏览器模式）
` + "```yaml" + `
headless:
  - steps:
      - action: navigate
        args:
          url: "{{BaseURL}}/login"
      - action: waitload
      - action: type
        args:
          element: "#username"
          value: "admin"
      - action: click
        args:
          element: "#submit"
      - action: waitload
    matchers:
      - type: word
        part: body
        words:
          - "Dashboard"
` + "```" + `

## JavaScript / Code 协议
` + "```yaml" + `
code:
  - engine:
      - node
    source: |
      const http = require('http');
      // custom logic
      console.log(JSON.stringify({matched: true}));
    matchers:
      - type: word
        words:
          - '"matched":true'
` + "```",
		},
		{
			Topic:    "安全规范",
			Keywords: []string{"safety", "安全", "规范", "危险", "禁止", "无害", "验证", "destructive", "best practice", "最佳实践"},
			Content: `# 安全编写规范

## 强制要求
1. **严禁破坏性操作**：不得使用 rm -rf、DROP TABLE、格式化等命令
2. **无害验证优先**：RCE 漏洞使用 whoami/id/hostname 或数学运算（expr 1234+5678）验证
3. **OOB 检测**：优先使用 {{interactsh-url}} 进行带外验证，避免写文件
4. **不修改目标状态**：不创建用户、不写文件、不修改配置
5. **最小请求原则**：能用 1 个请求验证的不用 2 个

## 推荐验证方式
| 漏洞类型 | 推荐验证方式 |
|---------|-------------|
| RCE | expr 数学运算、echo 唯一字符串、whoami |
| SSRF | {{interactsh-url}} OOB 回调 |
| SQLi | 时间盲注(sleep)、数学运算、UNION 查已知表 |
| XXE | {{interactsh-url}} OOB 或读取 /etc/hostname |
| 文件读取 | 读 /etc/passwd 或 win.ini（只读不写） |
| XSS | 反射检测唯一字符串 |
| 信息泄露 | 精确匹配关键字 |

## 误报控制
- matcher 不要只匹配通用字符串（如 "error"、"success"）
- 至少使用 2 个独立条件组合（matchers-condition: and）
- 对版本号匹配使用精确正则，避免过宽匹配
- severity 为 info 的 POC 只做信息收集，不应标记为漏洞`,
		},
		{
			Topic:    "Workflow 与 Argus 挂载",
			Keywords: []string{"workflow", "工作流", "挂载", "trigger", "stage", "fingerprint", "产品", "指纹", "关联"},
			Content: `# Argus Workflow 挂载机制

## 核心概念
Argus 使用 Workflow 将 POC 与产品指纹关联：
- 扫描时先识别指纹 → 匹配产品 → 触发挂载的 POC
- 避免对所有目标盲目执行全部 POC

## Workflow 规则结构
| 字段 | 说明 |
|------|------|
| product_name | 指纹产品名（精确匹配或正则） |
| poc_name | 要触发的 POC 名称（对应 poc 的 id 或 source_file） |
| match_type | 匹配方式: product / regex / tag |
| trigger_stage | 触发阶段: Root / Base / Dir / Dir-Fallback |

## 触发阶段说明
- **Root**: 最早执行，适合不依赖路径的检测（如端口级漏洞）
- **Base**: 基础路径探测后执行（已获取 BaseURL）
- **Dir**: 目录探测阶段执行（已发现特定路径）
- **Dir-Fallback**: 目录探测未命中时的降级执行

## POC 编写时的挂载建议
1. POC 的 tags 应包含产品名，方便 Workflow 按 tag 匹配
2. 如果 POC 依赖特定路径，trigger_stage 应设为 Dir
3. 通用探测型 POC（如版本信息）适合 Root 阶段
4. 一个 POC 可被多个 Workflow 规则引用`,
		},
	}

	var matched []map[string]string
	matchedSet := make(map[int]bool)

	// 按关键词匹配
	for idx, doc := range docs {
		for _, kw := range doc.Keywords {
			if strings.Contains(query, kw) {
				if !matchedSet[idx] {
					matchedSet[idx] = true
					matched = append(matched, map[string]string{
						"topic":   doc.Topic,
						"content": doc.Content,
					})
				}
				break
			}
		}
	}

	// 如果没有命中任何关键词，返回基础 + 安全 + 匹配器（最常用的三个）
	if len(matched) == 0 {
		for _, idx := range []int{0, 2, 7} {
			if idx < len(docs) {
				matched = append(matched, map[string]string{
					"topic":   docs[idx].Topic,
					"content": docs[idx].Content,
				})
			}
		}
	}

	// 最多返回 3 个章节，避免 context 过长
	if len(matched) > 3 {
		matched = matched[:3]
	}

	return matched
}
