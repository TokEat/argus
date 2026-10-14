package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"gorm.io/gorm"
)

// AI 漏洞研判 verdict 取值。AI 是 advisor 不是 executor：默认只回写标记，
// 不改 vulnerabilities.status；仅当开启自动抑制且高置信误报时才置 false_positive。
const (
	VerdictConfirmed  = "confirmed"
	VerdictLikelyFP   = "likely_false_positive"
	VerdictUncertain  = "uncertain"
	verdictProviderLLM    = "openai-compatible"
	verdictProviderStatic = "static"
)

// 研判开关存储在 db.SystemConfig。
const (
	TriageConfigKeyEnabled           = "ai_triage_enabled"
	TriageConfigKeyAutoSuppress      = "ai_triage_auto_suppress"
	TriageConfigKeySuppressThreshold = "ai_triage_confidence_threshold"
)

const defaultSuppressThreshold = 0.85

// TriageAnalyzer judges whether a vulnerability finding is a false positive.
type TriageAnalyzer struct {
	DB     *gorm.DB
	Client ChatClient
	Now    func() time.Time
}

// TriageOptions controls a single Triage invocation.
type TriageOptions struct {
	Force bool // 忽略缓存重新调 LLM
}

// TriageVerdict is the outcome for one vulnerability.
type TriageVerdict struct {
	Verdict    string  `json:"verdict"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
	ReviewID   uint    `json:"review_id"`
	Cached     bool    `json:"cached"`
	Model      string  `json:"model"`
}

type llmTriage struct {
	Verdict    string  `json:"verdict"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
}

func evidenceHashFor(vuln db.Vulnerability) string {
	return contentMD5(vuln.Target + "|" + vuln.Plugin + "|" + vuln.Response)
}

// Triage produces (and persists) an AI verdict for one vulnerability.
//
// Ordering matters: static pre-checks run before LoadConfig so they work even
// when no LLM is configured. Any LLM failure returns an error WITHOUT marking
// ai_triaged_at, so the worker retries next tick.
func (a *TriageAnalyzer) Triage(ctx context.Context, vuln db.Vulnerability, opts TriageOptions) (*TriageVerdict, error) {
	if a.DB == nil {
		return nil, fmt.Errorf("database is required")
	}
	evidenceHash := evidenceHashFor(vuln)

	if !opts.Force {
		var cached db.AIFindingReview
		err := a.DB.WithContext(ctx).
			Where("evidence_hash = ? AND override_verdict = ''", evidenceHash).
			Order("created_at DESC, id DESC").
			First(&cached).Error
		if err == nil {
			v := &TriageVerdict{
				Verdict:    cached.Verdict,
				Confidence: cached.Confidence,
				Reason:     cached.Reason,
				ReviewID:   cached.ID,
				Cached:     true,
				Model:      cached.Model,
			}
			if err := a.applyVerdict(ctx, vuln, cached.ID, v, cached.Provider, cached.Model); err != nil {
				return nil, err
			}
			log.Printf("[AI] triage cache hit: vuln=%d hash=%s verdict=%s", vuln.ID, evidenceHash, v.Verdict)
			return v, nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
	}

	// 静态预检：无响应证据或 info 级信息收集，直接判 uncertain，不调 LLM。
	if verdict, reason, skip := staticTriagePreCheck(vuln); skip {
		v := &TriageVerdict{Verdict: verdict, Confidence: 0.5, Reason: reason, Cached: false, Model: ""}
		reviewID, err := a.persistReview(ctx, vuln, evidenceHash, v, verdictProviderStatic, "", `{}`)
		if err != nil {
			return nil, err
		}
		v.ReviewID = reviewID
		if err := a.applyVerdict(ctx, vuln, reviewID, v, verdictProviderStatic, ""); err != nil {
			return nil, err
		}
		return v, nil
	}

	cfg, err := LoadConfig(a.DB)
	if err != nil {
		return nil, err
	}

	client := a.Client
	if client == nil {
		client = &HTTPClient{}
	}
	raw, err := client.CompleteJSON(ctx, cfg, buildTriageMessages(vuln))
	if err != nil {
		return nil, err
	}
	parsed, err := parseTriageVerdict(raw)
	if err != nil {
		return nil, err
	}
	v := &TriageVerdict{
		Verdict:    parsed.Verdict,
		Confidence: parsed.Confidence,
		Reason:     parsed.Reason,
		Cached:     false,
		Model:      cfg.Model,
	}
	if v.Reason == "" {
		v.Reason = "模型未返回详细理由，请人工复核。"
	}
	reviewID, err := a.persistReview(ctx, vuln, evidenceHash, v, verdictProviderLLM, cfg.Model, raw)
	if err != nil {
		return nil, err
	}
	v.ReviewID = reviewID
	if err := a.applyVerdict(ctx, vuln, reviewID, v, verdictProviderLLM, cfg.Model); err != nil {
		return nil, err
	}
	log.Printf("[AI] triage done: vuln=%d verdict=%s confidence=%.2f", vuln.ID, v.Verdict, v.Confidence)
	return v, nil
}

// staticTriagePreCheck short-circuits findings that cannot benefit from an LLM call.
func staticTriagePreCheck(vuln db.Vulnerability) (verdict, reason string, skip bool) {
	if strings.TrimSpace(vuln.Response) == "" {
		return VerdictUncertain, "无 HTTP 响应证据，无法进行 AI 研判，留待人工复核。", true
	}
	if strings.EqualFold(vuln.Severity, "info") {
		return VerdictUncertain, "info 级为信息收集而非漏洞，无需深度研判。", true
	}
	return "", "", false
}

func (a *TriageAnalyzer) persistReview(ctx context.Context, vuln db.Vulnerability, evidenceHash string, v *TriageVerdict, provider, model, raw string) (uint, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = "{}"
	}
	now := time.Now()
	if a.Now != nil {
		now = a.Now()
	}
	review := db.AIFindingReview{
		TenantID:        vuln.TenantID,
		VulnerabilityID: vuln.ID,
		RootTaskID:      vuln.RootTaskID,
		ProjectID:       vuln.ProjectID,
		Plugin:          vuln.Plugin,
		Severity:        vuln.Severity,
		Target:          vuln.Target,
		EvidenceHash:    evidenceHash,
		Verdict:         v.Verdict,
		Confidence:      v.Confidence,
		Reason:          v.Reason,
		RawResponse:     raw,
		Provider:        provider,
		Model:           model,
		CreatedBy:       "ai-worker",
		CreatedAt:       now,
	}
	if err := a.DB.WithContext(ctx).Create(&review).Error; err != nil {
		return 0, err
	}
	return review.ID, nil
}

// applyVerdict writes the AI columns back onto the vulnerability, optionally
// auto-suppresses a high-confidence false positive, and records an audit row.
// AI only ever narrows (marks/suppresses) — it never widens attack surface.
func (a *TriageAnalyzer) applyVerdict(ctx context.Context, vuln db.Vulnerability, reviewID uint, v *TriageVerdict, provider, model string) error {
	now := time.Now()
	if a.Now != nil {
		now = a.Now()
	}
	suppress := shouldAutoSuppress(a.DB, v.Verdict, v.Confidence)
	return a.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		updates := map[string]interface{}{
			"ai_status":     v.Verdict,
			"ai_confidence": v.Confidence,
			"ai_reason":     v.Reason,
			"ai_triaged_at": now,
			"ai_review_id":  reviewID,
		}
		if suppress {
			updates["status"] = "false_positive"
		}
		if err := tx.Model(&db.Vulnerability{}).Where("id = ?", vuln.ID).Updates(updates).Error; err != nil {
			return err
		}
		details, err := json.Marshal(map[string]interface{}{
			"vulnerability_id": vuln.ID,
			"plugin":           vuln.Plugin,
			"target":           vuln.Target,
			"verdict":          v.Verdict,
			"confidence":       v.Confidence,
			"provider":         provider,
			"model":            model,
			"cached":           v.Cached,
			"auto_suppressed":  suppress,
		})
		if err != nil {
			return err
		}
		afterStatus := vuln.Status
		if suppress {
			afterStatus = "false_positive"
		}
		audit := db.TaskAudit{
			TenantID:     vuln.TenantID,
			ProjectID:    vuln.ProjectID,
			RootTaskID:   vuln.RootTaskID,
			OperatorID:   "ai-worker",
			Action:       "ai_triage",
			BeforeStatus: vuln.Status,
			AfterStatus:  afterStatus,
			Details:      string(details),
			CreatedAt:    now,
		}
		return tx.Create(&audit).Error
	})
}

// shouldAutoSuppress reports whether a verdict should flip the vulnerability
// status to false_positive. Gated by the ai_triage_auto_suppress switch (default
// off) and a confidence threshold (default 0.85).
func shouldAutoSuppress(store *gorm.DB, verdict string, confidence float64) bool {
	if verdict != VerdictLikelyFP {
		return false
	}
	if !loadTriageBool(store, TriageConfigKeyAutoSuppress, false) {
		return false
	}
	return confidence >= loadTriageThreshold(store)
}

func loadTriageBool(store *gorm.DB, key string, def bool) bool {
	var row db.SystemConfig
	if err := store.Where("key = ?", key).First(&row).Error; err != nil {
		return def
	}
	parsed, err := strconv.ParseBool(strings.TrimSpace(row.Value))
	if err != nil {
		return def
	}
	return parsed
}

func loadTriageThreshold(store *gorm.DB) float64 {
	var row db.SystemConfig
	if err := store.Where("key = ?", TriageConfigKeySuppressThreshold).First(&row).Error; err != nil {
		return defaultSuppressThreshold
	}
	parsed, err := strconv.ParseFloat(strings.TrimSpace(row.Value), 64)
	if err != nil || parsed <= 0 || parsed > 1 {
		return defaultSuppressThreshold
	}
	return parsed
}

// LoadTriageEnabled reports whether the background triage worker should run.
func LoadTriageEnabled(store *gorm.DB) bool {
	return loadTriageBool(store, TriageConfigKeyEnabled, true)
}

func buildTriageMessages(vuln db.Vulnerability) []ChatMessage {
	request := vuln.Request
	if len(request) > 4000 {
		request = request[:4000] + "\n# ... request truncated ...\n"
	}
	response := vuln.Response
	if len(response) > 12000 {
		response = response[:12000] + "\n# ... response truncated ...\n"
	}
	user := fmt.Sprintf(`请研判下面这条扫描命中的漏洞是否为误报。

检测插件: %s
严重级别: %s
目标: %s
匹配位置: %s
漏洞描述: %s

HTTP 请求:
%s

HTTP 响应:
%s

请判断该命中是否真实反映了所述漏洞。重点考虑: 响应内容是否真的证明了漏洞存在；是否只是正常页面/登录页/默认页/错误页；matcher 条件是否可能过宽导致误匹配；证据是否充分。`,
		vuln.Plugin, vuln.Severity, vuln.Target, vuln.MatchedAt, vuln.Description, request, response)

	system := "你是安全扫描平台的漏洞研判助手。\n" +
		"请先输出你的研判思考过程，最后输出一个包含结构化结论的 JSON 对象。\n" +
		"务必将最终的 JSON 放在 ```json 和 ``` 包裹的代码块中。\n" +
		"JSON 字段必须包含:\n" +
		"verdict: \"confirmed\" | \"likely_false_positive\" | \"uncertain\"\n" +
		"confidence: 0 到 1 的数字\n" +
		"reason: 一句话给出研判理由\n" +
		"判定标准: confirmed=响应证据充分证明漏洞真实存在; likely_false_positive=响应更像正常页面/误匹配/证据明显不足; uncertain=证据不充分无法判断。"
	return []ChatMessage{
		{Role: "system", Content: system},
		{Role: "user", Content: user},
	}
}

func parseTriageVerdict(raw string) (llmTriage, error) {
	raw = stripJSONFences(strings.TrimSpace(raw))
	var parsed llmTriage
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return parsed, fmt.Errorf("parse triage json: %w", err)
	}
	parsed.Verdict = normalizeVerdict(parsed.Verdict)
	parsed.Confidence = clampConfidence(parsed.Confidence)
	return parsed, nil
}

func normalizeVerdict(raw string) string {
	switch raw {
	case VerdictConfirmed, VerdictLikelyFP, VerdictUncertain:
		return raw
	default:
		return VerdictUncertain
	}
}
