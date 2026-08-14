package api

import (
	"net/http"
	"strings"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/P0lar1ght/argus/shared/proto/go/activefingerprint"
	"github.com/P0lar1ght/argus/shared/proto/go/scanpolicy"
	"github.com/gin-gonic/gin"
)

type activeFingerprintRuleResponse struct {
	db.ActiveFingerprintRule
	DownstreamValidations []string `json:"DownstreamValidations"`
}

func getActiveFingerprintRules(c *gin.Context) {
	query := db.DB.Where("tenant_id = ?", currentTenantID(c))
	if c.Query("all") != "1" {
		query = query.Where("state = ? AND enabled = ?", "Approved", true)
	}
	if q := strings.TrimSpace(c.Query("q")); q != "" {
		like := "%" + strings.ToLower(q) + "%"
		query = query.Where("LOWER(name) LIKE ? OR LOWER(product_name) LIKE ? OR LOWER(source_file) LIKE ?", like, like, like)
	}
	var rows []db.ActiveFingerprintRule
	if err := query.Order("updated_at DESC, source_file ASC").Find(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	responses := make([]activeFingerprintRuleResponse, 0, len(rows))
	for _, row := range rows {
		responses = append(responses, activeFingerprintRuleResponse{
			ActiveFingerprintRule: row,
			DownstreamValidations: activeFingerprintDownstreamValidations(row.Name),
		})
	}
	c.JSON(http.StatusOK, responses)
}

func activeFingerprintDownstreamValidations(templateID string) []string {
	result := make([]string, 0)
	for _, descriptor := range scanpolicy.GoPocDescriptors() {
		if descriptor.Capability == scanpolicy.GoPocVulnerabilityCheck && descriptor.Reviewed && descriptor.Enabled && containsFold(descriptor.NucleiTemplates, templateID) {
			result = append(result, descriptor.Plugin)
		}
	}
	return result
}

func inspectActiveFingerprint(c *gin.Context) {
	var req struct {
		FileName string `json:"file_name"`
		Content  string `json:"content"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	classification, err := activefingerprint.Inspect(strings.TrimSpace(req.FileName), []byte(req.Content))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, classification)
}
