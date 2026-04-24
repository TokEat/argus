package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
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
	var req struct {
		Type     string `json:"type"`
		FileName string `json:"file_name"`
		Content  string `json:"content" binding:"required"`
		Force    bool   `json:"force"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	analyzer := aipkg.Analyzer{DB: db.DB}
	resp, err := analyzer.Analyze(c.Request.Context(), aipkg.AnalyzeRequest{
		TenantID: currentTenantID(c),
		UserID:   c.GetString("user_id"),
		Type:     req.Type,
		FileName: req.FileName,
		Content:  req.Content,
		Force:    req.Force,
	})
	if err != nil {
		writeAIAnalyzeError(c, err)
		return
	}
	c.JSON(http.StatusOK, resp)
}

// aiAnalyzeArsenal keeps the legacy endpoint used by older UI builds.
func aiAnalyzeArsenal(c *gin.Context) {
	var req struct {
		Content  string `json:"content" binding:"required"`
		FileName string `json:"file_name"`
		Type     string `json:"type"`
		Force    bool   `json:"force"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	analyzer := aipkg.Analyzer{DB: db.DB}
	resp, err := analyzer.Analyze(c.Request.Context(), aipkg.AnalyzeRequest{
		TenantID: currentTenantID(c),
		UserID:   c.GetString("user_id"),
		Type:     req.Type,
		FileName: req.FileName,
		Content:  req.Content,
		Force:    req.Force,
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

// analyzeArsenalStream handles SSE stream processing for AI analysis
func analyzeArsenalStream(c *gin.Context) {
	var req aipkg.AnalyzeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters: " + err.Error()})
		return
	}

	userID := c.GetString("user_id")
	if userID != "" {
		req.UserID = userID
	}

	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("Transfer-Encoding", "chunked")
	// Flush headers immediately
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
