package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	aipkg "github.com/P0lar1ght/argus/server/internal/ai"
	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// aiTriageChatClient is replaceable in tests; nil uses the real HTTPClient.
var aiTriageChatClient aipkg.ChatClient

// getVulnAIReview returns the AI triage verdicts for one vulnerability, newest
// first, alongside the vulnerability's current AI columns.
func getVulnAIReview(c *gin.Context) {
	vuln, ok := loadTriageVuln(c)
	if !ok {
		return
	}
	var reviews []db.AIFindingReview
	if err := db.DB.Where("vulnerability_id = ?", vuln.ID).
		Order("created_at DESC, id DESC").
		Find(&reviews).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"vulnerability_id": vuln.ID,
		"ai_status":        vuln.AIStatus,
		"ai_confidence":    vuln.AIConfidence,
		"ai_reason":        vuln.AIReason,
		"ai_triaged_at":    vuln.AITriagedAt,
		"reviews":          reviews,
	})
}

// retriggerVulnAIReview forces a fresh LLM triage for one vulnerability,
// ignoring the evidence cache.
func retriggerVulnAIReview(c *gin.Context) {
	vuln, ok := loadTriageVuln(c)
	if !ok {
		return
	}
	analyzer := aipkg.TriageAnalyzer{DB: db.DB, Client: aiTriageChatClient}
	verdict, err := analyzer.Triage(c.Request.Context(), *vuln, aipkg.TriageOptions{Force: true})
	if err != nil {
		writeAITriageError(c, err)
		return
	}
	c.JSON(http.StatusOK, verdict)
}

// overrideVulnAIReview records a human verdict that wins over the AI one.
// Overriding to confirmed restores an AI-suppressed (false_positive) row to open.
func overrideVulnAIReview(c *gin.Context) {
	vuln, ok := loadTriageVuln(c)
	if !ok {
		return
	}
	var req struct {
		Verdict string `json:"verdict"`
		Reason  string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	verdict := normalizeOverrideVerdict(req.Verdict)
	if verdict == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "verdict must be one of confirmed / likely_false_positive / uncertain"})
		return
	}

	userID := c.GetString("user_id")
	var latest db.AIFindingReview
	err := db.DB.Where("vulnerability_id = ?", vuln.ID).
		Order("created_at DESC, id DESC").First(&latest).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "no AI review for this vulnerability yet"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	now := time.Now()
	details, _ := json.Marshal(map[string]interface{}{
		"vulnerability_id": vuln.ID,
		"plugin":           vuln.Plugin,
		"previous_verdict": latest.Verdict,
		"override_verdict": verdict,
		"reason":           req.Reason,
	})
	err = db.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&db.AIFindingReview{}).Where("id = ?", latest.ID).Updates(map[string]interface{}{
			"override_verdict": verdict,
			"overridden_by":    userID,
		}).Error; err != nil {
			return err
		}
		updates := map[string]interface{}{
			"ai_status":     verdict,
			"ai_triaged_at": now,
		}
		if req.Reason != "" {
			updates["ai_reason"] = req.Reason
		}
		// A human confirming a real vulnerability rescinds an AI auto-suppression.
		if verdict == aipkg.VerdictConfirmed && vuln.Status == "false_positive" {
			updates["status"] = "open"
		}
		if err := tx.Model(&db.Vulnerability{}).Where("id = ?", vuln.ID).Updates(updates).Error; err != nil {
			return err
		}
		audit := db.TaskAudit{
			TenantID:     vuln.TenantID,
			ProjectID:    vuln.ProjectID,
			RootTaskID:   vuln.RootTaskID,
			OperatorID:   userID,
			Action:       "ai_triage_override",
			BeforeStatus: vuln.AIStatus,
			AfterStatus:  verdict,
			Details:      string(details),
			CreatedAt:    now,
		}
		return tx.Create(&audit).Error
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"vulnerability_id": vuln.ID,
		"ai_status":        verdict,
		"override_applied": true,
	})
}

func getAITriageConfig(c *gin.Context) {
	c.JSON(http.StatusOK, readAITriageConfig())
}

func saveAITriageConfig(c *gin.Context) {
	var req struct {
		Enabled            *bool    `json:"enabled"`
		AutoSuppress       *bool    `json:"auto_suppress"`
		ConfidenceThreshold *float64 `json:"confidence_threshold"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.ConfidenceThreshold != nil && (*req.ConfidenceThreshold <= 0 || *req.ConfidenceThreshold > 1) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "confidence_threshold must be in (0, 1]"})
		return
	}
	now := time.Now()
	write := func(key, value string) {
		db.DB.Save(&db.SystemConfig{Key: key, Value: value, UpdatedAt: now})
	}
	if req.Enabled != nil {
		write(aipkg.TriageConfigKeyEnabled, strconv.FormatBool(*req.Enabled))
	}
	if req.AutoSuppress != nil {
		write(aipkg.TriageConfigKeyAutoSuppress, strconv.FormatBool(*req.AutoSuppress))
	}
	if req.ConfidenceThreshold != nil {
		write(aipkg.TriageConfigKeySuppressThreshold, strconv.FormatFloat(*req.ConfidenceThreshold, 'f', -1, 64))
	}
	c.JSON(http.StatusOK, readAITriageConfig())
}

func readAITriageConfig() gin.H {
	return gin.H{
		"enabled":             aipkg.LoadTriageEnabled(db.DB),
		"auto_suppress":       loadTriageSystemBool(aipkg.TriageConfigKeyAutoSuppress, false),
		"confidence_threshold": loadTriageThresholdValue(),
	}
}

func loadTriageSystemBool(key string, def bool) bool {
	var row db.SystemConfig
	if err := db.DB.Where("key = ?", key).First(&row).Error; err != nil {
		return def
	}
	parsed, err := strconv.ParseBool(row.Value)
	if err != nil {
		return def
	}
	return parsed
}

func loadTriageThresholdValue() float64 {
	var row db.SystemConfig
	if err := db.DB.Where("key = ?", aipkg.TriageConfigKeySuppressThreshold).First(&row).Error; err != nil {
		return 0.85
	}
	parsed, err := strconv.ParseFloat(row.Value, 64)
	if err != nil || parsed <= 0 || parsed > 1 {
		return 0.85
	}
	return parsed
}

func loadTriageVuln(c *gin.Context) (*db.Vulnerability, bool) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid vulnerability id"})
		return nil, false
	}
	var vuln db.Vulnerability
	if err := db.DB.Where("id = ? AND tenant_id = ?", id, currentTenantID(c)).First(&vuln).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "vulnerability not found"})
			return nil, false
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return nil, false
	}
	return &vuln, true
}

func normalizeOverrideVerdict(raw string) string {
	switch raw {
	case aipkg.VerdictConfirmed, aipkg.VerdictLikelyFP, aipkg.VerdictUncertain:
		return raw
	default:
		return ""
	}
}

func writeAITriageError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, aipkg.ErrMissingConfig):
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "AI config is incomplete; configure ai_api_key and ai_model first"})
	default:
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
	}
}
