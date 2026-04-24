package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/user/dddd-server/internal/db"
	"gorm.io/gorm"
)

var (
	ErrUnsupportedType = errors.New("unsupported arsenal type")
	ErrEmptyContent    = errors.New("content is required")
)

type Analyzer struct {
	DB     *gorm.DB
	Client ChatClient
	Now    func() time.Time
}

func (a *Analyzer) Analyze(ctx context.Context, req AnalyzeRequest) (*AnalysisResponse, error) {
	if a.DB == nil {
		return nil, fmt.Errorf("database is required")
	}
	req.Type = strings.ToLower(strings.TrimSpace(req.Type))
	if req.Type == "" {
		req.Type = ArsenalTypePOC
	}
	if req.Type != ArsenalTypePOC {
		return nil, ErrUnsupportedType
	}
	if strings.TrimSpace(req.Content) == "" {
		return nil, ErrEmptyContent
	}
	if strings.TrimSpace(req.TenantID) == "" {
		req.TenantID = "default"
	}

	hash := contentMD5(req.Content)
	if !req.Force {
		if cached, err := a.cachedReview(ctx, req.TenantID, req.Type, hash); err == nil {
			cached.Cached = true
			return cached, nil
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
	}

	cfg, err := LoadConfig(a.DB)
	if err != nil {
		return nil, err
	}

	static := runStaticChecks(ctx, a.DB, req.TenantID, req.FileName, req.Content, hash)
	if blockingStatic(static.Issues) {
		resp := staticOnlyResponse(static, hash)
		if err := a.storeReview(ctx, req, resp, `{"static_only":true}`); err != nil {
			return nil, err
		}
		return resp, nil
	}

	client := a.Client
	if client == nil {
		client = &HTTPClient{}
	}
	raw, err := client.CompleteJSON(ctx, cfg, buildMessages(req, static))
	if err != nil {
		return nil, err
	}
	parsed, err := parseLLMAnalysis(raw)
	if err != nil {
		return nil, err
	}

	resp := &AnalysisResponse{
		Suggestion:          normalizeSuggestion(parsed.Suggestion),
		Confidence:          clampConfidence(parsed.Confidence),
		Summary:             strings.TrimSpace(parsed.Summary),
		Reason:              strings.TrimSpace(parsed.Reason),
		Issues:              append(static.Issues, parsed.Issues...),
		DuplicateCandidates: static.DuplicateCandidates,
		ContentHash:         hash,
		Provider:            "openai-compatible",
		Model:               cfg.Model,
	}
	applyStaticOverrides(resp)
	if resp.Summary == "" {
		resp.Summary = "AI 已完成 POC 结构、检测逻辑和运营风险分析。"
	}
	if resp.Reason == "" {
		resp.Reason = "模型未返回详细原因，请结合问题列表人工复核。"
	}

	if err := a.storeReview(ctx, req, resp, stripJSONFences(raw)); err != nil {
		return nil, err
	}
	return resp, nil
}

func (a *Analyzer) cachedReview(ctx context.Context, tenantID, typ, hash string) (*AnalysisResponse, error) {
	var review db.ArsenalAIReview
	if err := a.DB.WithContext(ctx).
		Where("tenant_id = ? AND type = ? AND content_hash = ?", tenantID, typ, hash).
		Order("created_at DESC, id DESC").
		First(&review).Error; err != nil {
		return nil, err
	}
	return reviewToResponse(review)
}

func (a *Analyzer) storeReview(ctx context.Context, req AnalyzeRequest, resp *AnalysisResponse, raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = "{}"
	}
	issues, err := json.Marshal(resp.Issues)
	if err != nil {
		return err
	}
	duplicates, err := json.Marshal(resp.DuplicateCandidates)
	if err != nil {
		return err
	}
	now := time.Now()
	if a.Now != nil {
		now = a.Now()
	}
	review := db.ArsenalAIReview{
		TenantID:            req.TenantID,
		Type:                req.Type,
		FileName:            req.FileName,
		ContentHash:         resp.ContentHash,
		Suggestion:          resp.Suggestion,
		Confidence:          resp.Confidence,
		Summary:             resp.Summary,
		Reason:              resp.Reason,
		Issues:              string(issues),
		DuplicateCandidates: string(duplicates),
		RawResponse:         strings.TrimSpace(raw),
		Provider:            resp.Provider,
		Model:               resp.Model,
		CreatedBy:           req.UserID,
		CreatedAt:           now,
	}
	return a.DB.WithContext(ctx).Create(&review).Error
}

func reviewToResponse(review db.ArsenalAIReview) (*AnalysisResponse, error) {
	var issues []Issue
	if strings.TrimSpace(review.Issues) != "" {
		if err := json.Unmarshal([]byte(review.Issues), &issues); err != nil {
			return nil, err
		}
	}
	var duplicates []DuplicateCandidate
	if strings.TrimSpace(review.DuplicateCandidates) != "" {
		if err := json.Unmarshal([]byte(review.DuplicateCandidates), &duplicates); err != nil {
			return nil, err
		}
	}
	return &AnalysisResponse{
		Suggestion:          review.Suggestion,
		Confidence:          review.Confidence,
		Summary:             review.Summary,
		Reason:              review.Reason,
		Issues:              issues,
		DuplicateCandidates: duplicates,
		ContentHash:         review.ContentHash,
		Provider:            review.Provider,
		Model:               review.Model,
	}, nil
}

func buildMessages(req AnalyzeRequest, static staticResult) []ChatMessage {
	staticJSON, _ := json.Marshal(static.Issues)
	duplicateJSON, _ := json.Marshal(static.DuplicateCandidates)
	content := req.Content
	if len(content) > 30000 {
		content = content[:30000] + "\n# ... truncated for AI analysis ..."
	}
	user := fmt.Sprintf(`请审查下面的 Nuclei POC YAML。

文件名：%s
静态检查问题：%s
重复候选：%s

POC 内容：
%s`, req.FileName, string(staticJSON), string(duplicateJSON), content)

	system := `你是安全扫描平台的 POC 审核助手。只输出一个 JSON 对象，不要输出 Markdown。
JSON 字段必须包含：
suggestion: "Approve" | "Revise" | "Reject"
confidence: 0 到 1 的数字
summary: 一句话概括该 POC 的检测目标和主要逻辑
reason: 给出审核建议的核心原因
issues: 数组，每项包含 severity、category、message、suggestion，可选 line
审查重点：YAML/Nuclei 结构、检测条件是否可靠、误报风险、破坏性或外连副作用、是否需要人工复核。`
	return []ChatMessage{
		{Role: "system", Content: system},
		{Role: "user", Content: user},
	}
}

func parseLLMAnalysis(raw string) (llmAnalysis, error) {
	raw = stripJSONFences(strings.TrimSpace(raw))
	var parsed llmAnalysis
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return parsed, fmt.Errorf("parse llm json: %w", err)
	}
	parsed.Suggestion = normalizeSuggestion(parsed.Suggestion)
	parsed.Confidence = clampConfidence(parsed.Confidence)
	return parsed, nil
}

func stripJSONFences(raw string) string {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "```") {
		return raw
	}
	raw = strings.TrimPrefix(raw, "```json")
	raw = strings.TrimPrefix(raw, "```")
	raw = strings.TrimSuffix(raw, "```")
	return strings.TrimSpace(raw)
}

func blockingStatic(issues []Issue) bool {
	for _, issue := range issues {
		if issue.Severity == "critical" || issue.Severity == "error" {
			return true
		}
	}
	return false
}

func staticOnlyResponse(static staticResult, hash string) *AnalysisResponse {
	suggestion := SuggestionRevise
	reason := "静态检查发现需要修复的问题。"
	confidence := 0.84
	for _, issue := range static.Issues {
		if issue.Severity == "critical" {
			suggestion = SuggestionReject
			reason = "静态检查发现高风险或可能具有破坏性的 payload。"
			confidence = 0.9
			break
		}
	}
	return &AnalysisResponse{
		Suggestion:          suggestion,
		Confidence:          confidence,
		Summary:             "静态检查已完成，模板需要先修复后再进入 AI 深度分析。",
		Reason:              reason,
		Issues:              static.Issues,
		DuplicateCandidates: static.DuplicateCandidates,
		ContentHash:         hash,
		Provider:            "static",
		Model:               "",
	}
}

func applyStaticOverrides(resp *AnalysisResponse) {
	exactDuplicate := false
	for _, candidate := range resp.DuplicateCandidates {
		if candidate.Score >= 1 {
			exactDuplicate = true
			break
		}
	}
	if exactDuplicate && resp.Suggestion == SuggestionApprove {
		resp.Suggestion = SuggestionRevise
		resp.Reason = strings.TrimSpace(resp.Reason + " 存在内容完全一致的 POC 候选，建议人工确认是否重复。")
	}
	for _, issue := range resp.Issues {
		if issue.Severity == "critical" {
			resp.Suggestion = SuggestionReject
			return
		}
		if issue.Severity == "error" && resp.Suggestion == SuggestionApprove {
			resp.Suggestion = SuggestionRevise
		}
	}
}

func clampConfidence(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 1 {
		return 1
	}
	if value == 0 {
		return 0.5
	}
	return value
}
