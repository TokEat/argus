package api

import (
	"errors"
	"net/http"

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
