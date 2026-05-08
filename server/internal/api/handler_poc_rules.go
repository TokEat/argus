package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/user/dddd-server/internal/db"
)

type pocRuleResponse struct {
	ID                  uint   `json:"id"`
	TenantID            string `json:"tenant_id"`
	ArtifactID          string `json:"artifact_id"`
	SourceFile          string `json:"source_file"`
	Name                string `json:"name"`
	TargetProduct       string `json:"target_product"`
	CVE                 string `json:"cve"`
	CompatibilityStatus string `json:"compatibility_status"`
	SourceVersion       string `json:"source_version"`
	ContentHash         string `json:"content_hash"`
	Severity            string `json:"severity"`
	Tags                string `json:"tags"`
	Author              string `json:"author"`
	Description         string `json:"description"`
	Version             int    `json:"version"`
	State               string `json:"state"`
	Enabled             bool   `json:"enabled"`
	CreatedAt           string `json:"created_at"`
	UpdatedAt           string `json:"updated_at"`
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
			"LOWER(name) LIKE ? OR LOWER(source_file) LIKE ? OR LOWER(target_product) LIKE ? OR LOWER(cve) LIKE ? OR LOWER(tags) LIKE ?",
			like, like, like, like, like,
		)
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
	return pocRuleResponse{
		ID:                  rule.ID,
		TenantID:            rule.TenantID,
		ArtifactID:          rule.ArtifactID,
		SourceFile:          rule.SourceFile,
		Name:                rule.Name,
		TargetProduct:       rule.TargetProduct,
		CVE:                 rule.CVE,
		CompatibilityStatus: rule.CompatibilityStatus,
		SourceVersion:       rule.SourceVersion,
		ContentHash:         rule.ContentHash,
		Severity:            rule.Severity,
		Tags:                rule.Tags,
		Author:              rule.Author,
		Description:         rule.Description,
		Version:             rule.Version,
		State:               rule.State,
		Enabled:             rule.Enabled,
		CreatedAt:           formatPocRuleTime(rule.CreatedAt),
		UpdatedAt:           formatPocRuleTime(rule.UpdatedAt),
	}
}

func formatPocRuleTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(timeFormatRFC3339())
}
