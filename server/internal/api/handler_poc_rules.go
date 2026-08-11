package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/gin-gonic/gin"
)

type pocRuleResponse struct {
	ID                         uint   `json:"id"`
	TenantID                   string `json:"tenant_id"`
	ArtifactID                 string `json:"artifact_id"`
	SourceFile                 string `json:"source_file"`
	Name                       string `json:"name"`
	TargetProduct              string `json:"target_product"`
	CVE                        string `json:"cve"`
	CompatibilityStatus        string `json:"compatibility_status"`
	SourceVersion              string `json:"source_version"`
	ContentHash                string `json:"content_hash"`
	Severity                   string `json:"severity"`
	ExecutionClass             string `json:"execution_class"`
	RiskLevel                  string `json:"risk_level"`
	RequiresConfirmation       bool   `json:"requires_confirmation"`
	RequiresSecondConfirmation bool   `json:"requires_second_confirmation"`
	Tags                       string `json:"tags"`
	Author                     string `json:"author"`
	Description                string `json:"description"`
	Version                    int    `json:"version"`
	State                      string `json:"state"`
	Enabled                    bool   `json:"enabled"`
	CreatedAt                  string `json:"created_at"`
	UpdatedAt                  string `json:"updated_at"`
}

func listPocRules(c *gin.Context) {
	tenantID := currentTenantID(c)
	query := db.DB.Model(&db.PocRule{}).Where("tenant_id = ?", tenantID)

	if c.Query("all") != "1" {
		query = query.Where("enabled = ?", true)
	}
	if severity := strings.ToLower(strings.TrimSpace(c.Query("severity"))); severity != "" {
		query = query.Where("severity = ?", severity)
	}
	if executionClass := strings.ToLower(strings.TrimSpace(c.Query("execution_class"))); executionClass != "" {
		query = query.Where("execution_class = ?", executionClass)
	}
	if riskLevel := strings.ToLower(strings.TrimSpace(c.Query("risk_level"))); riskLevel != "" {
		query = query.Where("risk_level = ?", riskLevel)
	}
	if product := strings.TrimSpace(c.Query("product")); product != "" {
		query = query.Where("LOWER(target_product) LIKE ?", "%"+strings.ToLower(product)+"%")
	}
	if cve := strings.TrimSpace(c.Query("cve")); cve != "" {
		query = query.Where("LOWER(cve) LIKE ?", "%"+strings.ToLower(cve)+"%")
	}
	if status := strings.TrimSpace(c.Query("compatibility_status")); status != "" {
		query = query.Where("compatibility_status = ?", status)
	}
	if q := strings.TrimSpace(c.Query("q")); q != "" {
		like := "%" + strings.ToLower(q) + "%"
		query = query.Where(
			"LOWER(name) LIKE ? OR LOWER(source_file) LIKE ? OR LOWER(target_product) LIKE ? OR LOWER(cve) LIKE ? OR LOWER(tags) LIKE ? OR LOWER(execution_class) LIKE ? OR LOWER(risk_level) LIKE ?",
			like, like, like, like, like, like, like,
		)
	}

	if c.Query("page") != "" || c.Query("page_size") != "" || c.Query("lite") == "1" {
		page, pageSize := parsePagination(c, 50, 200)
		var total int64
		if err := query.Count(&total).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		var rules []db.PocRule
		if err := query.Order("updated_at DESC, id DESC").Limit(pageSize).Offset((page - 1) * pageSize).Find(&rules).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		resp := make([]pocRuleResponse, 0, len(rules))
		for _, rule := range rules {
			resp = append(resp, pocRuleToResponse(rule))
		}
		c.JSON(http.StatusOK, pagedResponse(resp, total, page, pageSize, currentRuleVersion()))
		return
	}

	var rules []db.PocRule
	if err := query.Order("updated_at DESC, id DESC").Find(&rules).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	resp := make([]pocRuleResponse, 0, len(rules))
	for _, rule := range rules {
		resp = append(resp, pocRuleToResponse(rule))
	}
	c.JSON(http.StatusOK, resp)
}

func pocRuleToResponse(rule db.PocRule) pocRuleResponse {
	executionClass, err := db.NormalizePocExecutionClass(rule.ExecutionClass)
	if err != nil {
		executionClass = db.PocExecutionClassDetection
	}
	riskLevel, err := db.NormalizePocRiskLevel(rule.RiskLevel)
	if err != nil {
		riskLevel = db.PocRiskLevelUnknown
	}
	return pocRuleResponse{
		ID:                         rule.ID,
		TenantID:                   rule.TenantID,
		ArtifactID:                 rule.ArtifactID,
		SourceFile:                 rule.SourceFile,
		Name:                       rule.Name,
		TargetProduct:              rule.TargetProduct,
		CVE:                        rule.CVE,
		CompatibilityStatus:        rule.CompatibilityStatus,
		SourceVersion:              rule.SourceVersion,
		ContentHash:                rule.ContentHash,
		Severity:                   rule.Severity,
		ExecutionClass:             executionClass,
		RiskLevel:                  riskLevel,
		RequiresConfirmation:       true,
		RequiresSecondConfirmation: db.PocRequiresSecondConfirmation(riskLevel),
		Tags:                       rule.Tags,
		Author:                     rule.Author,
		Description:                rule.Description,
		Version:                    rule.Version,
		State:                      rule.State,
		Enabled:                    rule.Enabled,
		CreatedAt:                  formatPocRuleTime(rule.CreatedAt),
		UpdatedAt:                  formatPocRuleTime(rule.UpdatedAt),
	}
}

func formatPocRuleTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(timeFormatRFC3339())
}
