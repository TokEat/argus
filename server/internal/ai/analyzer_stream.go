package ai

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"gorm.io/gorm"
)

// AnalyzeStream provides a Server-Sent Events (SSE) friendly streaming interface for the AI analysis process.
// It accepts callbacks for phase transitions (onStatus), LLM token chunks (onToken), and the final result (onResult).
func (a *Analyzer) AnalyzeStream(
	ctx context.Context,
	req AnalyzeRequest,
	onStatus func(phase, message string),
	onToken func(content string),
	onResult func(result *AnalysisResponse),
) error {
	if a.DB == nil {
		return fmt.Errorf("database is required")
	}
	req.Type = strings.ToLower(strings.TrimSpace(req.Type))
	if req.Type == "" {
		req.Type = ArsenalTypePOC
	}
	if req.Type != ArsenalTypePOC {
		return ErrUnsupportedType
	}
	if strings.TrimSpace(req.Content) == "" {
		return ErrEmptyContent
	}
	if strings.TrimSpace(req.TenantID) == "" {
		req.TenantID = "default"
	}

	hash := contentMD5(req.Content)
	log.Printf("[AI-Stream] analyze start: tenant=%s file=%s type=%s hash=%s force=%v", req.TenantID, req.FileName, req.Type, hash, req.Force)

	onStatus("cache", "正在检查历史分析缓存...")
	if !req.Force {
		if cached, err := a.cachedReview(ctx, req.TenantID, req.Type, hash); err == nil {
			cached.Cached = true
			log.Printf("[AI-Stream] cache hit: hash=%s", hash)
			onResult(cached)
			return nil
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			log.Printf("[AI-Stream] cache lookup error: %v", err)
			return err
		}
	}

	onStatus("config", "正在加载 AI 模型配置...")
	cfg, err := LoadConfig(a.DB)
	if err != nil {
		log.Printf("[AI-Stream] config load failed: %v", err)
		return err
	}

	onStatus("static", "执行基础静态检查与去重匹配...")
	start := time.Now()
	static := runStaticChecks(ctx, a.DB, req.TenantID, req.FileName, req.Content, hash)

	if blockingStatic(static.Issues) {
		resp := staticOnlyResponse(static, hash)
		log.Printf("[AI-Stream] static blocking (skipping LLM)")
		if err := a.storeReview(ctx, req, resp, `{"static_only":true}`); err != nil {
			return err
		}
		onResult(resp)
		return nil
	}

	client := a.Client
	if client == nil {
		client = &HTTPClient{}
	}

	// Wait! We need to ensure client is HTTPClient to call StreamComplete.
	// Since ChatClient interface does not have StreamComplete, we will do a type assertion
	httpClient, ok := client.(*HTTPClient)
	if !ok {
		// Fallback to blocking CompleteJSON if client doesn't support streaming
		onStatus("llm", "调用大语言模型进行深度分析 (非流式回退)...")
		raw, err := client.CompleteJSON(ctx, cfg, buildMessages(req, static))
		if err != nil {
			return err
		}
		return a.processRawLLMResult(ctx, req, cfg, hash, static, start, raw, onResult)
	}

	onStatus("llm", fmt.Sprintf("调用大语言模型进行深度分析 [%s]...", cfg.Model))
	raw, err := httpClient.StreamComplete(ctx, cfg, buildMessages(req, static), onToken)
	if err != nil {
		return err
	}
	
	onStatus("parse", "解析 LLM 响应结果...")
	return a.processRawLLMResult(ctx, req, cfg, hash, static, start, raw, onResult)
}

func (a *Analyzer) processRawLLMResult(
	ctx context.Context, 
	req AnalyzeRequest, 
	cfg Config, 
	hash string, 
	static staticResult, 
	start time.Time, 
	raw string, 
	onResult func(result *AnalysisResponse),
) error {
	parsed, err := parseLLMAnalysis(raw)
	if err != nil {
		log.Printf("[AI-Stream] LLM JSON parse failed: %v | raw: %.500s", err, raw)
		return err
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
		return err
	}
	log.Printf("[AI-Stream] analyze complete: elapsed=%s", time.Since(start))
	onResult(resp)
	return nil
}
