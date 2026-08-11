package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/user/dddd-server/internal/db"
)

func TestSavePocRejectsExploitExecutionClassWithoutPersistingDraft(t *testing.T) {
	store := setupAITestDB(t)
	c, w := newTenantContextWithRole(http.MethodPost, "/arsenals/poc/exploit.yaml", "admin", "1")
	c.Params = gin.Params{{Key: "type", Value: "poc"}, {Key: "filename", Value: "exploit.yaml"}}
	c.Request = httptest.NewRequest(http.MethodPost, "/arsenals/poc/exploit.yaml", strings.NewReader(`{
		"content":"id: exploit\ninfo:\n  name: Exploit\n  severity: high\n  metadata:\n    argus-execution-class: exploit\n    argus-risk-level: high\n"
	}`))
	c.Request.Header.Set("Content-Type", "application/json")

	saveArsenal(c)

	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "separate EXP package") {
		t.Fatalf("expected exploit-class POC rejection, got %d (%s)", w.Code, w.Body.String())
	}
	var count int64
	store.Model(&db.Arsenal{}).Where("tenant_id = ? AND type = ? AND file_name = ?", "default", "poc", "exploit.yaml").Count(&count)
	if count != 0 {
		t.Fatalf("invalid POC draft must not be persisted, count=%d", count)
	}
}

func TestSaveLegacyPocMaterializesSafeGovernanceDefaults(t *testing.T) {
	store := setupAITestDB(t)
	c, w := newTenantContextWithRole(http.MethodPost, "/arsenals/poc/legacy.yaml", "admin", "1")
	c.Params = gin.Params{{Key: "type", Value: "poc"}, {Key: "filename", Value: "legacy.yaml"}}
	c.Request = httptest.NewRequest(http.MethodPost, "/arsenals/poc/legacy.yaml", strings.NewReader(`{
		"content":"id: legacy\ninfo:\n  name: Legacy\n  severity: info\n"
	}`))
	c.Request.Header.Set("Content-Type", "application/json")

	saveArsenal(c)

	if w.Code != http.StatusOK {
		t.Fatalf("expected legacy POC draft compatibility, got %d (%s)", w.Code, w.Body.String())
	}
	var rule db.PocRule
	if err := store.Where("tenant_id = ? AND source_file = ?", "default", "legacy.yaml").First(&rule).Error; err != nil {
		t.Fatalf("load materialized legacy POC: %v", err)
	}
	if rule.ExecutionClass != db.PocExecutionClassDetection || rule.RiskLevel != db.PocRiskLevelUnknown || rule.Enabled {
		t.Fatalf("unexpected legacy POC governance defaults: %+v", rule)
	}
}
