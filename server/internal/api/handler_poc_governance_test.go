package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/gin-gonic/gin"
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

func TestSaveActiveFingerprintValidatesBeforePersistAndRecordsRevision(t *testing.T) {
	store := setupAITestDB(t)
	invalid := "id: dns-probe\ninfo:\n  metadata:\n    argus-rule-kind: active-fingerprint\n    argus-product: DNS\ndns:\n  - name: '{{FQDN}}'\n"
	c, w := newTenantContextWithRole(http.MethodPost, "/arsenals/active_fingerprint/dns.yaml", "admin", "user-1")
	c.Params = gin.Params{{Key: "type", Value: "active_fingerprint"}, {Key: "filename", Value: "dns.yaml"}}
	c.Request = httptest.NewRequest(http.MethodPost, c.Request.URL.Path, strings.NewReader(`{"content":`+fmt.Sprintf("%q", invalid)+`}`))
	c.Request.Header.Set("Content-Type", "application/json")
	saveArsenal(c)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected non-HTTP behavior probe rejection, got %d (%s)", w.Code, w.Body.String())
	}
	var count int64
	store.Model(&db.Arsenal{}).Where("type = ?", "active_fingerprint").Count(&count)
	if count != 0 {
		t.Fatalf("invalid behavior probe persisted, count=%d", count)
	}

	ordinary := "id: ordinary-response\ninfo:\n  name: Ordinary Response\n  severity: info\n  metadata:\n    argus-rule-kind: active-fingerprint\n    argus-product: OrdinaryProduct\n    max-request: 1\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}']\n    matchers:\n      - type: status\n        status: [200]\n"
	c, w = newTenantContextWithRole(http.MethodPost, "/arsenals/active_fingerprint/ordinary.yaml", "admin", "user-1")
	c.Params = gin.Params{{Key: "type", Value: "active_fingerprint"}, {Key: "filename", Value: "ordinary.yaml"}}
	c.Request = httptest.NewRequest(http.MethodPost, c.Request.URL.Path, strings.NewReader(`{"content":`+fmt.Sprintf("%q", ordinary)+`}`))
	c.Request.Header.Set("Content-Type", "application/json")
	saveArsenal(c)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "argus-behavior-kind") {
		t.Fatalf("expected ordinary HTTP fingerprint rejection, got %d (%s)", w.Code, w.Body.String())
	}

	valid := "id: safe-probe\ninfo:\n  name: Safe\n  severity: info\n  metadata:\n    argus-rule-kind: active-fingerprint\n    argus-product: SafeProduct\n    argus-behavior-kind: header\n    max-request: 1\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}']\n    headers: {X-Argus-Probe: '{{randstr}}'}\n    matchers:\n      - type: status\n        status: [200]\n"
	c, w = newTenantContextWithRole(http.MethodPost, "/arsenals/active_fingerprint/safe.yaml", "admin", "user-1")
	c.Params = gin.Params{{Key: "type", Value: "active_fingerprint"}, {Key: "filename", Value: "safe.yaml"}}
	c.Request = httptest.NewRequest(http.MethodPost, c.Request.URL.Path, strings.NewReader(`{"content":`+fmt.Sprintf("%q", valid)+`}`))
	c.Request.Header.Set("Content-Type", "application/json")
	saveArsenal(c)
	if w.Code != http.StatusOK {
		t.Fatalf("expected valid behavior probe draft, got %d (%s)", w.Code, w.Body.String())
	}
	var event db.ArsenalEvent
	if err := store.Where("action = ? AND actor_id = ?", "saved", "user-1").First(&event).Error; err != nil {
		t.Fatalf("expected immutable revision event: %v", err)
	}
	if event.Content != valid || event.State != "Draft" || event.Version != 1 {
		t.Fatalf("unexpected revision event: %+v", event)
	}
}
