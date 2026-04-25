package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	aipkg "github.com/user/dddd-server/internal/ai"
	"github.com/user/dddd-server/internal/db"
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

	// Inject contextual state if available
	if pageContext != nil {
		// Separate ambient context from page context for clearer LLM understanding
		ambient, hasAmbient := pageContext["_ambient"]
		pageOnly := make(map[string]interface{}, len(pageContext))
		for k, v := range pageContext {
			if k != "_ambient" {
				pageOnly[k] = v
			}
		}
		if len(pageOnly) > 0 {
			ctxBytes, _ := json.MarshalIndent(pageOnly, "", "  ")
			finalMessages = append(finalMessages, aipkg.ChatMessage{
				Role:    "system",
				Content: fmt.Sprintf("【内部上下文，用户当前不可见】用户当前的页面环境与数据状态如下：\n%s", string(ctxBytes)),
			})
		}
		if hasAmbient {
			if ambientMap, ok := ambient.(map[string]interface{}); ok && len(ambientMap) > 0 {
				ambientBytes, _ := json.MarshalIndent(ambientMap, "", "  ")
				finalMessages = append(finalMessages, aipkg.ChatMessage{
					Role:    "system",
					Content: fmt.Sprintf("【全局常驻上下文】以下是平台的实时运行状态，不依赖于用户当前所在页面：\n%s", string(ambientBytes)),
				})
			}
		}
	}

	finalMessages = append(finalMessages, req.Messages...)

	_, err := agent.QueryEngine(c.Request.Context(), cfg, finalMessages, profile.MaxTurns, func(event string, data interface{}) {
		sendSSE(event, data)
	})

	if err != nil {
		sendSSE("error", gin.H{"message": err.Error()})
	} else {
		sendSSE("result", gin.H{"summary": "Conversation ended."})
	}
}

func resolveCopilotModule(pageContext map[string]interface{}) string {
	if pageContext == nil {
		return "global"
	}
	if module, ok := pageContext["module"].(string); ok && strings.TrimSpace(module) != "" {
		return strings.TrimSpace(module)
	}
	return "global"
}

func resolveCopilotProfile(module string) copilotProfile {
	base := "你是 Argus 平台的全局安全智能助手 (Argus Copilot)。你需要基于当前页面上下文协助用户分析资产、任务、漏洞和规则配置。回答要克制、准确，涉及平台动作时先说明风险和前置条件，不要虚构已经执行的操作。全局常驻上下文中包含实时 Agent 节点数据，用户可能随时询问节点状态，请直接基于上下文回答。"
	profile := copilotProfile{
		SystemPrompt: base,
		MaxTurns:     4,
		Tools:        []string{"node_capacity"}, // 全局默认可查节点
	}

	switch module {
	case "poc_list", "poc_inline":
		profile.Tools = []string{"argus_docs", "sandbox_debug", "workflow_recommend", "node_capacity"}
		profile.MaxTurns = 8
		profile.SystemPrompt = base + " 用户当前正在处理 POC。优先关注 Nuclei YAML 结构、误报风险、无害验证和 Workflow 挂载关系。只有在上下文提供 agent_id、target_url 和完整 poc_content 时，才可以调用 RunSandboxDebug；修改 POC 后应建议或执行沙箱验证。如果用户要求生成、修复、重写或优化 POC，请输出完整的更新后 POC，并放在单独的 ```yaml 代码块中；不要声称已经保存，前端会让用户确认后应用到当前编辑器。"
	case "task_results":
		profile.Tools = []string{"task_insight", "vulnerability_explain", "node_capacity"}
		profile.SystemPrompt = base + " 用户当前正在查看扫描结果。请重点解释漏洞证据、请求响应、影响范围、复现条件和处置建议；不要编造未出现在上下文中的报文。"
	case "task_list":
		profile.Tools = []string{"task_insight", "node_capacity"}
		profile.SystemPrompt = base + " 用户当前正在查看任务列表。请重点分析失败、超时、取消、重试和节点负载导致的问题，并给出可执行的排查顺序。"
	case "node_list":
		profile.Tools = []string{"node_capacity"}
		profile.SystemPrompt = base + " 用户当前正在查看 Agent 节点。请重点关注在线率、容量、运行中任务、版本兼容性和资源瓶颈。"
	case "asset_list":
		profile.Tools = []string{"asset_search", "dict_strategy", "vulnerability_explain", "node_capacity"}
		profile.SystemPrompt = base + " 用户当前正在查看资产。请重点关注资产暴露面、指纹、开放端口、协议识别和下一步探测策略。"
	case "workflow_list", "fingerprint_list":
		profile.Tools = []string{"argus_docs", "workflow_recommend", "workflow_conflicts", "dict_strategy", "node_capacity"}
		profile.SystemPrompt = base + " 用户当前正在维护弹药库配置。请帮助用户理清 Workflow、指纹、目录探测和 POC 之间的挂载关系，优先给出小步、可回滚的配置建议。"
	case "dir_list", "dict_list":
		profile.Tools = []string{"argus_docs", "dict_strategy", "node_capacity"}
		profile.SystemPrompt = base + " 用户当前正在维护弹药库配置。请帮助用户理清 Workflow、指纹、目录探测和 POC 之间的挂载关系，优先给出小步、可回滚的配置建议。"
	case "dashboard":
		profile.Tools = []string{"task_insight", "node_capacity"}
		profile.SystemPrompt = base + " 用户当前处于控制台总览。请从趋势、风险集中度、任务健康度和近期高危事件角度做归纳，不要替代具体页面的细粒度分析。"
	}

	if len(profile.Tools) == 0 {
		profile.SystemPrompt += " 当前模块没有启用工具，请仅基于上下文和通用安全知识回答。"
	}
	return profile
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

func compactPageContext(input map[string]interface{}) map[string]interface{} {
	if input == nil {
		return nil
	}
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
