package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	aipkg "github.com/P0lar1ght/argus/server/internal/ai"
	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/gin-gonic/gin"
)

func getAIConfig(c *gin.Context) {
	cfg, err := aipkg.PublicConfigFromStore(db.DB)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, cfg)
}

func saveAIConfig(c *gin.Context) {
	var req aipkg.Config
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := aipkg.SaveConfig(db.DB, req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	cfg, err := aipkg.PublicConfigFromStore(db.DB)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, cfg)
}

func analyzeArsenalWithAI(c *gin.Context) {
	var req aipkg.AnalyzeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	analyzer := aipkg.Analyzer{DB: db.DB}
	resp, err := analyzer.Analyze(c.Request.Context(), aipkg.AnalyzeRequest{
		TenantID: currentTenantID(c),
		UserID:   c.GetString("user_id"),
		Action:   req.Action,
		Type:     req.Type,
		FileName: req.FileName,
		Content:  req.Content,
		Force:    req.Force,
		Context:  req.Context,
	})
	if err != nil {
		writeAIAnalyzeError(c, err)
		return
	}
	c.JSON(http.StatusOK, resp)
}

// aiAnalyzeArsenal keeps the legacy endpoint used by older UI builds.
func aiAnalyzeArsenal(c *gin.Context) {
	var req aipkg.AnalyzeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	analyzer := aipkg.Analyzer{DB: db.DB}
	resp, err := analyzer.Analyze(c.Request.Context(), aipkg.AnalyzeRequest{
		TenantID: currentTenantID(c),
		UserID:   c.GetString("user_id"),
		Action:   req.Action,
		Type:     req.Type,
		FileName: req.FileName,
		Content:  req.Content,
		Force:    req.Force,
		Context:  req.Context,
	})
	if err != nil {
		writeAIAnalyzeError(c, err)
		return
	}
	c.JSON(http.StatusOK, resp)
}

func writeAIAnalyzeError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, aipkg.ErrMissingConfig):
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "AI config is incomplete; configure ai_api_key and ai_model first"})
	case errors.Is(err, aipkg.ErrUnsupportedType), errors.Is(err, aipkg.ErrEmptyContent):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	default:
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
	}
}

// analyzeArsenalStream handles SSE stream processing for structured POC AI analysis.
func analyzeArsenalStream(c *gin.Context) {
	var req aipkg.AnalyzeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters: " + err.Error()})
		return
	}

	if userID := c.GetString("user_id"); userID != "" {
		req.UserID = userID
	}
	req.TenantID = currentTenantID(c)

	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("Transfer-Encoding", "chunked")
	c.Writer.Flush()

	sendSSE := func(event string, data interface{}) {
		b, _ := json.Marshal(data)
		fmt.Fprintf(c.Writer, "event: %s\ndata: %s\n\n", event, string(b))
		c.Writer.Flush()
	}

	analyzer := &aipkg.Analyzer{DB: db.DB}
	err := analyzer.AnalyzeStream(c.Request.Context(), req,
		func(phase, message string) {
			sendSSE("status", gin.H{"phase": phase, "message": message})
		},
		func(content string) {
			sendSSE("token", gin.H{"content": content})
		},
		func(result *aipkg.AnalysisResponse) {
			sendSSE("result", result)
		},
	)
	if err != nil {
		sendSSE("error", gin.H{"message": err.Error()})
	}
}

// listAIModels proxies GET {base_url}/models to fetch available models.
// Supports optional query params ?base_url=...&api_key=... to probe before saving.
func listAIModels(c *gin.Context) {
	cfg, cfgErr := aipkg.LoadConfig(db.DB)

	// Allow query-param overrides for probing unsaved configs
	if qURL := c.Query("base_url"); qURL != "" {
		cfg.BaseURL = qURL
	}
	if qKey := c.Query("api_key"); qKey != "" {
		cfg.APIKey = qKey
	}

	if cfg.BaseURL == "" || cfg.APIKey == "" {
		if cfgErr != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "AI config is incomplete; provide base_url and api_key"})
			return
		}
	}

	models, err := aipkg.ListModels(c.Request.Context(), cfg)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"models": models})
}

// testAIConnection sends a minimal prompt to verify LLM connectivity and model availability.
func testAIConnection(c *gin.Context) {
	cfg, err := aipkg.LoadConfig(db.DB)
	if err != nil {
		log.Printf("[AI-Test] config load failed: %v", err)
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "AI config is incomplete; configure api_key and model first"})
		return
	}

	log.Printf("[AI-Test] testing connection: base_url=%s model=%s", cfg.BaseURL, cfg.Model)
	start := time.Now()

	client := &aipkg.HTTPClient{}
	messages := []aipkg.ChatMessage{
		{Role: "system", Content: "Reply with a JSON object: {\"status\":\"ok\",\"message\":\"hello\"}"},
		{Role: "user", Content: "ping"},
	}
	raw, err := client.CompleteJSON(c.Request.Context(), cfg, messages)
	elapsed := time.Since(start)

	if err != nil {
		log.Printf("[AI-Test] connection failed after %s: %v", elapsed, err)
		c.JSON(http.StatusBadGateway, gin.H{
			"success":    false,
			"error":      err.Error(),
			"elapsed_ms": elapsed.Milliseconds(),
			"base_url":   cfg.BaseURL,
			"model":      cfg.Model,
		})
		return
	}

	log.Printf("[AI-Test] connection OK: elapsed=%s raw_len=%d", elapsed, len(raw))
	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"response":   raw,
		"elapsed_ms": elapsed.Milliseconds(),
		"base_url":   cfg.BaseURL,
		"model":      cfg.Model,
	})
}

// GlobalChatRequest represents a generic multi-domain conversational request
type GlobalChatRequest struct {
	Messages    []aipkg.ChatMessage    `json:"messages"`
	PageContext map[string]interface{} `json:"page_context"`
}

type copilotProfile struct {
	SystemPrompt string
	Tools        []string
	MaxTurns     int
}

// globalAIChat handles generic AI queries across the entire platform
func globalAIChat(c *gin.Context) {
	var req GlobalChatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters: " + err.Error()})
		return
	}

	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("Transfer-Encoding", "chunked")
	c.Writer.Flush()

	sendSSE := func(event string, data interface{}) {
		b, _ := json.Marshal(data)
		fmt.Fprintf(c.Writer, "event: %s\ndata: %s\n\n", event, string(b))
		c.Writer.Flush()
	}

	cfg, cfgErr := aipkg.LoadConfig(db.DB)
	if cfgErr != nil {
		sendSSE("error", gin.H{"message": cfgErr.Error()})
		return
	}

	agent := aipkg.NewAgent(&aipkg.HTTPClient{})
	pageContext := compactPageContext(req.PageContext)
	module := resolveCopilotModule(pageContext)
	profile := resolveCopilotProfile(module)
	registerCopilotTools(agent, profile.Tools, AIToolAuditContext{
		TenantID: currentTenantID(c),
		UserID:   c.GetString("user_id"),
		Module:   module,
	})

	// Prepend System Prompt
	finalMessages := []aipkg.ChatMessage{
		{Role: "system", Content: profile.SystemPrompt},
	}

	// Inject layered context into system messages
	if pageContext != nil {
		injectCopilotContext(&finalMessages, pageContext)
	}

	finalMessages = append(finalMessages, req.Messages...)

	answer, err := agent.QueryEngine(c.Request.Context(), cfg, finalMessages, profile.MaxTurns, func(event string, data interface{}) {
		sendSSE(event, data)
	})

	if err != nil {
		sendSSE("error", gin.H{"message": err.Error()})
	} else {
		for _, action := range extractPendingActions(answer) {
			sendSSE("pending_action", action)
		}
		sendSSE("result", gin.H{"summary": "Conversation ended."})
	}
}

func resolveCopilotModule(pageContext map[string]interface{}) string {
	if pageContext == nil {
		return "global"
	}
	// New layered format: check _focus.module first
	if focus, ok := pageContext["_focus"].(map[string]interface{}); ok {
		if module, ok := focus["module"].(string); ok && strings.TrimSpace(module) != "" {
			return strings.TrimSpace(module)
		}
	}
	// Legacy flat format: check module directly
	if module, ok := pageContext["module"].(string); ok && strings.TrimSpace(module) != "" {
		return strings.TrimSpace(module)
	}
	return "global"
}

func registerCopilotTools(agent *aipkg.Agent, toolNames []string, audit AIToolAuditContext) {
	for _, name := range toolNames {
		switch name {
		case "argus_docs":
			agent.RegisterTool(auditedCopilotTool(&aipkg.QueryArgusDocsTool{}, audit))
		case "sandbox_debug":
			agent.RegisterTool(auditedCopilotTool(&RunSandboxDebugTool{TenantID: audit.TenantID}, audit))
		case "asset_search":
			agent.RegisterTool(auditedCopilotTool(&SearchAssetsTool{TenantID: audit.TenantID}, audit))
		case "task_insight":
			agent.RegisterTool(auditedCopilotTool(&GetTaskInsightTool{TenantID: audit.TenantID}, audit))
		case "workflow_recommend":
			agent.RegisterTool(auditedCopilotTool(&RecommendWorkflowRulesTool{TenantID: audit.TenantID}, audit))
		case "vulnerability_explain":
			agent.RegisterTool(auditedCopilotTool(&ExplainVulnerabilityTool{TenantID: audit.TenantID}, audit))
		case "node_capacity":
			agent.RegisterTool(auditedCopilotTool(&AnalyzeNodeCapacityTool{TenantID: audit.TenantID}, audit))
		case "dict_strategy":
			agent.RegisterTool(auditedCopilotTool(&SuggestDictionaryStrategyTool{TenantID: audit.TenantID}, audit))
		case "workflow_conflicts":
			agent.RegisterTool(auditedCopilotTool(&DetectWorkflowConflictsTool{TenantID: audit.TenantID}, audit))
		}
	}
}

// compactPageContext applies priority-aware compression to the page context.
// It handles both the new layered format and the legacy flat format.
func compactPageContext(input map[string]interface{}) map[string]interface{} {
	if input == nil {
		return nil
	}

	// Detect new layered format (has _identity or _focus keys)
	_, hasIdentity := input["_identity"]
	_, hasFocus := input["_focus"]
	if hasIdentity || hasFocus {
		return compactLayeredContext(input)
	}

	// Legacy flat format — use the old compaction logic
	return compactLegacyContext(input)
}

// compactLayeredContext handles the new structured context format.
// identity + focus + ambient are kept fully (small); data is smartly compressed.
func compactLayeredContext(input map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	// identity: keep fully (small, ~200 bytes)
	if v, ok := input["_identity"]; ok {
		result["_identity"] = redactSensitive(v)
	}

	// focus: keep fully (small, ~300 bytes)
	if v, ok := input["_focus"]; ok {
		result["_focus"] = redactSensitive(v)
	}

	// data: smart truncation — this is where page-level data lives
	if v, ok := input["data"].(map[string]interface{}); ok && len(v) > 0 {
		result["data"] = compactDataLayer(v)
	} else if v, ok := input["_data"].(map[string]interface{}); ok && len(v) > 0 {
		result["_data"] = compactDataLayer(v)
	}

	// Also pass through any legacy flat keys (from useAutoContext) that aren't
	// part of the layered structure — these come from pages that haven't migrated yet
	for k, v := range input {
		if k == "_identity" || k == "_focus" || k == "_ambient" || k == "data" || k == "_data" {
			continue
		}
		result[k] = compactAIValue(v, 0)
	}

	// ambient: keep fully (already curated, ~1KB)
	if v, ok := input["_ambient"]; ok {
		result["_ambient"] = v
	}

	// Final size check
	data, err := json.Marshal(result)
	if err != nil {
		return result
	}
	if len(data) > 16000 {
		// If still too large, aggressively truncate data layer
		if d, ok := result["data"].(map[string]interface{}); ok {
			result["data"] = truncateMapValues(d, 500)
		}
		if d, ok := result["_data"].(map[string]interface{}); ok {
			result["_data"] = truncateMapValues(d, 500)
		}
		// Re-check after truncation
		data2, _ := json.Marshal(result)
		if len(data2) > 16000 {
			result["_truncated"] = true
		}
	}

	return result
}

// compactLegacyContext handles the old flat page_context format.
func compactLegacyContext(input map[string]interface{}) map[string]interface{} {
	compact, ok := compactAIValue(input, 0).(map[string]interface{})
	if !ok {
		return nil
	}
	data, err := json.Marshal(compact)
	if err != nil || len(data) <= 24000 {
		return compact
	}
	compact["_truncated"] = true
	compact["_note"] = "page context was truncated before sending to LLM"
	delete(compact, "raw_data")
	delete(compact, "request")
	delete(compact, "response")
	return compact
}

// compactDataLayer compresses the data layer by limiting array lengths and string sizes.
func compactDataLayer(data map[string]interface{}) map[string]interface{} {
	compact, ok := compactAIValue(data, 0).(map[string]interface{})
	if !ok {
		return nil
	}
	return compact
}

// redactSensitive removes token/secret/password fields from context.
func redactSensitive(value interface{}) interface{} {
	return compactAIValue(value, 0)
}

// truncateMapValues truncates all string values in a map to maxLen characters.
func truncateMapValues(m map[string]interface{}, maxLen int) map[string]interface{} {
	result := make(map[string]interface{}, len(m))
	for k, v := range m {
		if s, ok := v.(string); ok && len(s) > maxLen {
			result[k] = s[:maxLen] + "…[truncated]"
		} else {
			result[k] = v
		}
	}
	return result
}

func isExpPythonGenerationContext(data map[string]interface{}) bool {
	if data == nil {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(stringParam(data, "module")), "exp_builder") ||
		strings.EqualFold(strings.TrimSpace(stringParam(data, "action")), "generate_exp_python") {
		return true
	}
	if nested, ok := data["builder_context"].(map[string]interface{}); ok && len(nested) > 0 {
		return strings.EqualFold(strings.TrimSpace(stringParam(nested, "action")), "generate_exp_python")
	}
	return false
}

// injectCopilotContext builds structured system messages from the layered context.
func injectCopilotContext(messages *[]aipkg.ChatMessage, pageContext map[string]interface{}) {
	// Check for new layered format
	_, hasIdentity := pageContext["_identity"]
	_, hasFocus := pageContext["_focus"]

	if hasIdentity || hasFocus {
		// New layered format: inject each layer as a separate system message
		// for clearer LLM comprehension

		if identity, ok := pageContext["_identity"]; ok {
			if identityMap, ok := identity.(map[string]interface{}); ok && len(identityMap) > 0 {
				b, _ := json.MarshalIndent(identityMap, "", "  ")
				*messages = append(*messages, aipkg.ChatMessage{
					Role:    "system",
					Content: fmt.Sprintf("【用户身份】当前用户信息：\n%s", string(b)),
				})
			}
		}

		if focus, ok := pageContext["_focus"]; ok {
			if focusMap, ok := focus.(map[string]interface{}); ok && len(focusMap) > 0 {
				b, _ := json.MarshalIndent(focusMap, "", "  ")
				*messages = append(*messages, aipkg.ChatMessage{
					Role:    "system",
					Content: fmt.Sprintf("【页面焦点】用户当前正在查看的页面与实体：\n%s", string(b)),
				})
			}
		}

		// Inject data layer (page-level data from useAutoContext)
		dataLayer := make(map[string]interface{})
		for k, v := range pageContext {
			if k == "_identity" || k == "_focus" || k == "_ambient" || k == "data" || k == "_data" {
				continue
			}
			dataLayer[k] = v
		}
		// Also include explicit data/_data key
		if d, ok := pageContext["data"]; ok {
			if dMap, ok := d.(map[string]interface{}); ok {
				for k, v := range dMap {
					dataLayer[k] = v
				}
			}
		}
		if d, ok := pageContext["_data"]; ok {
			if dMap, ok := d.(map[string]interface{}); ok {
				for k, v := range dMap {
					dataLayer[k] = v
				}
			}
		}
		if isExpPythonGenerationContext(dataLayer) {
			*messages = append(*messages, aipkg.ChatMessage{
				Role:    "system",
				Content: "【EXP Python 专用约束】你是 EXP Python 草稿助手。请根据 raw HTTP 请求包、响应片段、判断线索和 cleanup 要求输出完整 fenced python EXP；采用 CLI-first 标准脚本结构：文件头 CLI 用法说明、import argparse、ARGUS_EXP、build_arg_parser()、run(ctx)、cleanup(ctx)、main() 和 if __name__ == \"__main__\"；argparse.add_argument 是参数主合同，让脚本本地可通过 -h/--help 查看参数，ARGUS_EXP.params 默认可为空，仅用于 pattern/sensitive/min/max/enum/example 等额外校验/展示；flag 使用 kebab-case 时参数名使用 snake_case；run(ctx) 可通过 ctx.params.<name> 读取平台参数，也可以按普通 Python 脚本方式使用 urllib、requests、socket、subprocess、os、ctypes 和已声明依赖；ctx 不提供 HTTP/TCP helper 属性；请求、响应、状态码、matcher、关键错误等调试信息需要脚本主动通过 ctx.evidence.add 写入摘要并注意脱敏；不要设置执行目标、用户授权、agent_id、project_id、risk_confirmed 等执行字段。若缺少成功判断或参数化依据，先说明需要用户补充什么，再给最小可用 Python。",
			})
		}
		if len(dataLayer) > 0 {
			b, _ := json.MarshalIndent(dataLayer, "", "  ")
			*messages = append(*messages, aipkg.ChatMessage{
				Role:    "system",
				Content: fmt.Sprintf("【页面数据】用户当前页面的实时数据状态：\n%s", string(b)),
			})
		}

		if ambient, ok := pageContext["_ambient"]; ok {
			if ambientMap, ok := ambient.(map[string]interface{}); ok && len(ambientMap) > 0 {
				b, _ := json.MarshalIndent(ambientMap, "", "  ")
				*messages = append(*messages, aipkg.ChatMessage{
					Role:    "system",
					Content: fmt.Sprintf("【全局态势】平台实时运行状态（每 30 秒更新）：\n%s", string(b)),
				})
			}
		}
	} else {
		// Legacy flat format: inject as before
		ambient, hasAmbient := pageContext["_ambient"]
		pageOnly := make(map[string]interface{}, len(pageContext))
		for k, v := range pageContext {
			if k != "_ambient" {
				pageOnly[k] = v
			}
		}
		if len(pageOnly) > 0 {
			if isExpPythonGenerationContext(pageOnly) {
				*messages = append(*messages, aipkg.ChatMessage{
					Role:    "system",
					Content: "【EXP Python 专用约束】优先根据用户提供的请求包和判断线索输出 fenced python；采用 CLI-first 标准脚本结构：文件头 CLI 用法说明、import argparse、ARGUS_EXP、build_arg_parser()、run(ctx)、cleanup(ctx)、main() 和 if __name__ == \"__main__\"；以 argparse.add_argument 作为参数主合同，ARGUS_EXP.params 默认可为空；不要编造事实，不要设置执行/授权字段。缺少依据时先说明需要用户补充什么。",
				})
			}
			ctxBytes, _ := json.MarshalIndent(pageOnly, "", "  ")
			*messages = append(*messages, aipkg.ChatMessage{
				Role:    "system",
				Content: fmt.Sprintf("【内部上下文，用户当前不可见】用户当前的页面环境与数据状态如下：\n%s", string(ctxBytes)),
			})
		}
		if hasAmbient {
			if ambientMap, ok := ambient.(map[string]interface{}); ok && len(ambientMap) > 0 {
				ambientBytes, _ := json.MarshalIndent(ambientMap, "", "  ")
				*messages = append(*messages, aipkg.ChatMessage{
					Role:    "system",
					Content: fmt.Sprintf("【全局常驻上下文】以下是平台的实时运行状态，不依赖于用户当前所在页面：\n%s", string(ambientBytes)),
				})
			}
		}
	}
}

func compactAIValue(value interface{}, depth int) interface{} {
	if depth >= 5 {
		return "[truncated]"
	}
	switch v := value.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(v))
		for key, val := range v {
			lower := strings.ToLower(key)
			if strings.Contains(lower, "token") || strings.Contains(lower, "secret") || strings.Contains(lower, "password") || strings.Contains(lower, "api_key") || strings.Contains(lower, "authorization") {
				out[key] = "[redacted]"
				continue
			}
			out[key] = compactAIValue(val, depth+1)
		}
		return out
	case []interface{}:
		limit := len(v)
		if limit > 20 {
			limit = 20
		}
		out := make([]interface{}, 0, limit+1)
		for i := 0; i < limit; i++ {
			out = append(out, compactAIValue(v[i], depth+1))
		}
		if len(v) > limit {
			out = append(out, fmt.Sprintf("[truncated %d items]", len(v)-limit))
		}
		return out
	case string:
		if len(v) > 6000 {
			return v[:6000] + "\n[truncated]"
		}
		return v
	default:
		return v
	}
}
