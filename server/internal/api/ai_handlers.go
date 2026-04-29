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

func resolveCopilotProfile(module string) copilotProfile {
	base := `你是 Argus 平台的全局安全智能助手 (Argus Copilot)。

## 上下文结构
你会收到以下分层上下文信息：
- 【用户身份】：当前用户的角色、租户、活跃项目。基于此判断用户权限，不要建议超出其角色的操作。
- 【页面焦点】：用户当前正在查看的页面模块和聚焦实体。据此调整回答的深度和侧重点。
- 【页面数据】：用户当前页面的实时数据（如任务列表、漏洞详情、资产信息）。优先基于这些数据直接回答，避免让用户去页面上看。
- 【全局态势】：平台实时运行状态（Agent 节点、队列深度、活跃扫描）。用户可能随时询问系统状态，请直接基于此回答。

## 回答原则
1. 克制、准确，不编造未出现在上下文中的数据
2. 涉及平台动作（创建任务、修改规则、操作云资源）时先说明风险和前置条件
3. 不要虚构已经执行的操作——AI 只能分析和建议，写操作只能输出待确认动作，由用户确认后平台执行
4. 优先给出可执行的下一步建议，而非泛泛而谈
5. 如果上下文中有用户正在查看的实体数据，直接引用具体字段回答，不要说"请查看页面"

## 待确认动作协议
当用户明确要求生成并保存低风险草稿时，可以在回答末尾附加一个独立的 ` + "```pending_action" + ` 代码块。模型不能直接执行动作，也不能声称已经保存。
当前只允许两类动作：
1. create_poc_draft：保存 POC 草稿，params 必须包含 file_name 和 content。
2. upsert_workflow_draft：保存 Workflow 草稿，params 必须包含 product、type、pocs。
动作 JSON 必须包含 action_type、title、summary、risk_level、params、preview、required_role、confirm_label。
不要为删除、审核、发布、任务下发、云资源变更输出 pending_action。`

	profile := copilotProfile{
		SystemPrompt: base,
		MaxTurns:     4,
		Tools:        []string{"node_capacity"}, // 全局默认可查节点
	}

	switch module {
	case "poc_list", "poc_inline":
		profile.Tools = []string{"argus_docs", "sandbox_debug", "workflow_recommend", "node_capacity"}
		profile.MaxTurns = 8
		profile.SystemPrompt = base + `

## POC 编辑模式
用户当前正在处理 POC 规则。优先关注：
- Nuclei YAML 结构的正确性（id、info、requests 匹配器）
- 误报风险和无害验证方式
- Workflow 挂载关系（poc_name 是否已被 Workflow 引用）
- severity 与实际危害的匹配度

只有在上下文提供 agent_id、target_url 和完整 poc_content 时，才调用 RunSandboxDebug。
修改 POC 后应建议或执行沙箱验证。
如果用户要求生成、修复、重写或优化 POC，请输出完整的更新后 POC，放在单独的 ` + "```yaml" + ` 代码块中。
如果用户明确要求保存为草稿，可以同时输出 create_poc_draft 的 pending_action；否则只给出可应用 YAML。
不要声称已经保存——前端会让用户确认后应用到编辑器。`

	case "task_results":
		profile.Tools = []string{"task_insight", "vulnerability_explain", "node_capacity"}
		profile.SystemPrompt = base + `

## 扫描结果分析模式
用户当前正在查看扫描结果。请重点：
- 解释漏洞证据：请求报文、响应报文、匹配条件
- 评估影响范围：受影响资产数量、暴露面、严重度分布
- 给出处置建议：修复优先级、复现条件、临时缓解措施
- 如果上下文中包含具体漏洞详情（selected_vuln），直接引用其字段回答
- 不要编造未出现在上下文中的报文内容`

	case "task_list":
		profile.Tools = []string{"task_insight", "node_capacity"}
		profile.SystemPrompt = base + `

## 任务管理模式
用户当前正在查看任务列表。请重点：
- 分析失败/超时/取消任务的原因
- 识别节点负载导致的任务堆积
- 给出可执行的排查顺序：先检查节点状态，再检查队列深度，最后检查任务配置
- 如果上下文中有 viewing_task_detail，深入分析该任务的执行状况`

	case "node_list":
		profile.Tools = []string{"node_capacity"}
		profile.SystemPrompt = base + `

## 节点管理模式
用户当前正在查看 Agent 节点。请重点关注：
- 在线率和离线节点的原因分析
- 容量利用：运行中任务数 vs 容量上限
- 版本兼容性：是否有过旧版本需要升级
- 资源瓶颈：CPU/内存使用率高的节点
- 如果用户询问特定节点，使用 AnalyzeNodeCapacity 获取详细信息`

	case "asset_list":
		profile.Tools = []string{"asset_search", "dict_strategy", "vulnerability_explain", "node_capacity"}
		profile.SystemPrompt = base + `

## 资产分析模式
用户当前正在查看资产。请重点关注：
- 资产暴露面：开放端口、运行服务、Web 应用
- 指纹识别结果：已识别的产品和版本
- 关联漏洞：该资产上的已知漏洞
- 下一步探测策略：建议追加的目录探测或 POC 验证`

	case "workflow_list", "fingerprint_list":
		profile.Tools = []string{"argus_docs", "workflow_recommend", "workflow_conflicts", "dict_strategy", "node_capacity"}
		profile.SystemPrompt = base + `

## 弹药库配置模式
用户当前正在维护 Workflow/指纹配置。请帮助：
- 理清 Workflow、指纹、目录探测和 POC 之间的挂载关系
- 检测配置冲突（同一产品重复挂载、无效 POC 引用）
- 优先给出小步、可回滚的配置建议
- 确保 product_name 在指纹和 Workflow 之间保持一致
- 如果用户明确要求创建或更新 Workflow 草稿，可以输出 upsert_workflow_draft 的 pending_action`

	case "dir_list", "dict_list":
		profile.Tools = []string{"argus_docs", "dict_strategy", "node_capacity"}
		profile.SystemPrompt = base + `

## 目录探测配置模式
用户当前正在维护目录探测规则。请帮助：
- 优化路径字典的覆盖度和精准度
- 避免过于宽泛的路径导致大量无效请求
- 结合已识别的指纹产品，建议关联的目录探测规则`

	case "dashboard":
		profile.Tools = []string{"task_insight", "node_capacity"}
		profile.SystemPrompt = base + `

## 控制台总览模式
用户当前处于 Dashboard。请从以下角度归纳：
- 趋势：近期任务完成率、漏洞发现趋势
- 风险集中度：哪些项目/资产的高危漏洞最多
- 任务健康度：失败率、超时率、队列积压情况
- 近期高危事件：最近发现的 critical/high 漏洞
- 不要替代具体页面的细粒度分析，给出概要和下一步建议即可`

	case "arsenal_debug":
		profile.Tools = []string{"argus_docs", "sandbox_debug", "node_capacity"}
		profile.MaxTurns = 8
		profile.SystemPrompt = base + `

## 弹药库调试模式
用户当前正在使用调试功能测试规则。请帮助：
- 分析调试结果中的指纹命中和漏洞检测情况
- 解释自定义规则的匹配逻辑
- 建议规则优化方向`
	}

	if len(profile.Tools) == 0 {
		profile.SystemPrompt += "\n\n当前模块没有启用工具，请仅基于上下文和通用安全知识回答。"
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
