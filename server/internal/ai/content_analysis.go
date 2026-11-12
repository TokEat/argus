package ai

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/TokEat/argus/server/internal/db"
	"gorm.io/gorm"
)

// AI 内容分析（主动爬取关联资产 + 敏感信息）的开关与决策常量。
const (
	ContentAnalysisConfigKeyEnabled = "ai_content_analysis_enabled"

	// CrawlSite 候选的 AI 研判结论。
	CrawlSiteDecisionConfirmed  = "confirmed"  // 值得收录为资产
	CrawlSiteDecisionDuplicate  = "duplicate"  // 项目已有覆盖 / 冗余
	CrawlSiteDecisionRejected   = "rejected"   // 价值低 / 无关
	// SensitiveFinding 的 AI 研判结论。
	SensitiveDecisionConfirmed = "confirmed"
	SensitiveDecisionRejected  = "rejected"
)

// CrawlSiteDecision 是 AI 对一个关联站点候选的研判结论。
type CrawlSiteDecision struct {
	Decision   string  `json:"decision"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
}

// SensitiveVerdict 是 AI 对单条敏感信息候选的结构化提取 + 研判结论（按输入下标对齐）。
type SensitiveVerdict struct {
	Index      int     `json:"index"`
	Decision   string  `json:"decision"` // confirmed | rejected
	Value      string  `json:"value,omitempty"`
	Kind       string  `json:"kind,omitempty"`    // 重分类：仅 allowlist 内的值才回写 kind 列
	Context    string  `json:"context,omitempty"` // 结构化提取结果（json 文本）
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason,omitempty"`
}

// sensitiveKindAllowlist 允许 AI 回写的 kind 词表；之外的原样忽略（防脏数据）。
var sensitiveKindAllowlist = map[string]bool{
	"email": true, "phone": true, "idcard": true, "account": true,
	"username": true, "apikey": true, "token": true, "secret": true,
	"keyword": true, "custom": true,
}

type sensitiveExtractionResult struct {
	Verdicts []SensitiveVerdict `json:"verdicts"`
}

// LoadContentAnalysisEnabled reports whether the content-analysis worker runs (default true).
func LoadContentAnalysisEnabled(store *gorm.DB) bool {
	return loadTriageBool(store, ContentAnalysisConfigKeyEnabled, true)
}

// buildCrawlSiteDecisionMessages 组装"关联站点候选是否值得收录"的研判请求。
// existingHosts 传入项目已收录资产的目标（host:port / URL），供 AI 判重。
func buildCrawlSiteDecisionMessages(cand db.CrawlSiteCandidate, existingHosts []string) []ChatMessage {
	context := strings.TrimSpace(cand.LinkContext)
	if context == "" {
		context = "（无链接上下文）"
	}
	known := strings.Join(existingHosts, "\n")
	if known == "" {
		known = "（项目暂无可比资产）"
	}
	siteType := cand.SiteType
	if siteType == "" {
		siteType = "（端口/子域站点）"
	}
	user := fmt.Sprintf(`安全扫描平台在主动爬取目标站点时，从页面/JS 链接中发现了一个"同主机下的不同站点"候选。请判断是否值得把它收录为项目资产。

候选站点 URL: %s
协议: %s
主机: %s
端口: %d
候选类型: %s
发现来源页面: %s
链接上下文: %s

项目已收录的资产目标（用于判重）:
%s

请重点判断:
- 该候选是否是一个真实、独立、有价值的站点（而非当前页面的锚点/跳转/静态资源镜像）
- 是否与项目已收录资产重复（同 host:port 或同站点）
- 价值是否足以作为独立资产保留（开发/测试/管理后台/独立服务通常值得保留；纯跳转、CDN、重复入口不值得）
- 路径前缀候选说明: 带路径前缀（如 host/app1）的候选是按路径反代到不同后端系统的独立应用。若候选类型为 path_app 且有独立标题/自包含站内链接，倾向 confirmed；若为 hidden_path 但只是同站 API 端点而非独立系统，可判 duplicate/rejected；纯静态目录（/static、/assets 等）不值得收录。`,
		cand.URL, cand.Scheme, cand.Host, cand.Port, siteType, cand.SourceURL, context, known)

	system := "你是安全扫描平台的资产研判助手。\n" +
		"先输出简要分析，最后输出一个放在 ```json 代码块中的 JSON 对象。\n" +
		"JSON 字段必须包含:\n" +
		"decision: \"confirmed\" | \"duplicate\" | \"rejected\"\n" +
		"confidence: 0 到 1 的数字\n" +
		"reason: 一句话说明判断依据\n" +
		"判定标准: confirmed=真实独立且有收录价值; duplicate=与已有资产/候选重复; rejected=价值低或明显无关。拿不准就保守判 rejected。"
	return []ChatMessage{
		{Role: "system", Content: system},
		{Role: "user", Content: user},
	}
}

func parseCrawlSiteDecision(raw string) (CrawlSiteDecision, error) {
	raw = stripJSONFences(raw)
	var dec CrawlSiteDecision
	if err := json.Unmarshal([]byte(raw), &dec); err != nil {
		return CrawlSiteDecision{}, err
	}
	dec.Decision = strings.TrimSpace(dec.Decision)
	if dec.Decision != CrawlSiteDecisionConfirmed &&
		dec.Decision != CrawlSiteDecisionDuplicate &&
		dec.Decision != CrawlSiteDecisionRejected {
		return CrawlSiteDecision{}, errors.New("invalid crawl site decision: " + dec.Decision)
	}
	dec.Confidence = clampConfidence(dec.Confidence)
	if dec.Reason == "" {
		dec.Reason = "模型未返回理由。"
	}
	return dec, nil
}

// buildSensitiveExtractionMessages 把一批敏感信息候选（同主机）交给 AI 做结构化提取与研判。
// AI 按输入下标逐条返回结论，命中正则的原始值可被规范化、补充钓鱼上下文。
func buildSensitiveExtractionMessages(items []db.SensitiveFinding) []ChatMessage {
	var b strings.Builder
	for i, it := range items {
		snippet := it.Snippet
		if len(snippet) > 400 {
			snippet = snippet[:400] + "…"
		}
		fmt.Fprintf(&b, "[%d] 类型=%s 值=%s\n片段: %s\n\n", i, it.Kind, it.Value, snippet)
	}
	host := ""
	if len(items) > 0 {
		host = items[0].Host
	}
	user := fmt.Sprintf(`安全扫描平台从目标站点 %s 的页面/JS 中通过正则预筛出以下敏感信息候选（可能含误报）。请逐条研判:
1) 是否为真实敏感信息（剔除误报，如示例值/占位符/普通数字被误判）。
2) 将值规范化（如统一邮箱/电话格式）。
3) 补充可用于钓鱼暴露面分析的上下文（所属人员/部门/用途线索），写入 context。
4) 若候选含 username，归纳该主机用户名的命名规律（如 firstname.lastname / 姓名全拼 / 工号 / u+数字），在其 context 中附加 username_convention 字段说明规律。

候选列表（下标从 0 开始）:
%s
请对每一条给出结论，verdicts 数组长度与输入一致、用 index 对齐。`,
		host, b.String())

	system := "你是安全扫描平台的敏感信息分析助手，服务于钓鱼暴露面研判。\n" +
		"先输出简要分析，最后输出一个放在 ```json 代码块中的 JSON 对象。\n" +
		"JSON 结构: {\"verdicts\":[{\"index\":0,\"decision\":\"confirmed\",\"value\":\"规范化后的值\",\"kind\":\"重分类类型\",\"context\":\"结构化上下文(json)\",\"confidence\":0.0,\"reason\":\"依据\"}]}\n" +
		"decision 只能取 \"confirmed\" | \"rejected\"（rejected=正则误报/无价值）。confidence 0 到 1。不要遗漏任何输入下标。\n" +
		"kind 只能取以下词表内的值，用于把预筛类型校正为更精确的类型（仅在明显不当时才改，不确定就保留原值）：\n" +
		"email=邮箱; phone=手机号/座机; idcard=身份证号; username=用户名/登录账号名（非密钥）; " +
		"account=账号或口令（password/passwd 赋值）; apikey=API 密钥（AKIA/AIza/sk- 等前缀）; " +
		"token=访问令牌/会话凭证（JWT/ghp_/xox- 等）; secret=密钥/私钥/客户端机密; keyword=敏感关键词; custom=以上都不符合。"
	return []ChatMessage{
		{Role: "system", Content: system},
		{Role: "user", Content: user},
	}
}

// parseSensitiveExtraction 解析批量提取结果；返回按输入下标对齐的结论。
func parseSensitiveExtraction(raw string) ([]SensitiveVerdict, error) {
	raw = stripJSONFences(raw)
	var res sensitiveExtractionResult
	if err := json.Unmarshal([]byte(raw), &res); err != nil {
		return nil, err
	}
	out := make([]SensitiveVerdict, 0, len(res.Verdicts))
	for _, v := range res.Verdicts {
		v.Decision = strings.TrimSpace(v.Decision)
		if v.Decision != SensitiveDecisionConfirmed && v.Decision != SensitiveDecisionRejected {
			continue
		}
		v.Confidence = clampConfidence(v.Confidence)
		if v.Reason == "" {
			v.Reason = "模型未返回理由。"
		}
		out = append(out, v)
	}
	return out, nil
}
