package api

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/TokEat/argus/server/internal/assetdiscovery"
	"github.com/TokEat/argus/server/internal/db"
)

func TestBuildAssetDiscoverySnapshotRejectsInvalidPersistenceBoundaryValues(t *testing.T) {
	validAudit := func() *db.AssetDiscoveryAudit {
		return &db.AssetDiscoveryAudit{
			TenantID:      "default",
			ProjectID:     "project-1",
			Provider:      "fofa",
			OperatorID:    "operator-1",
			QueryHash:     strings.Repeat("a", 64),
			ConfigVersion: 1,
			ConfigHash:    strings.Repeat("b", 64),
		}
	}
	validResult := func() assetdiscovery.Result {
		return assetdiscovery.Result{Provider: "fofa", Assets: []assetdiscovery.Asset{{
			Target: "https://example.invalid:443", Domain: "example.invalid", Port: 443, Protocol: "https", Source: "fofa",
		}}}
	}

	tests := []struct {
		name   string
		mutate func(*db.AssetDiscoveryAudit, *projectDiscoveryQueryRequest, *assetdiscovery.Result)
	}{
		{
			name: "expression control character",
			mutate: func(_ *db.AssetDiscoveryAudit, request *projectDiscoveryQueryRequest, _ *assetdiscovery.Result) {
				request.Expression = "domain=example.invalid\rhidden"
			},
		},
		{
			name: "non-hex query digest",
			mutate: func(audit *db.AssetDiscoveryAudit, _ *projectDiscoveryQueryRequest, _ *assetdiscovery.Result) {
				audit.QueryHash = strings.Repeat("g", 64)
			},
		},
		{
			name: "target control character",
			mutate: func(_ *db.AssetDiscoveryAudit, _ *projectDiscoveryQueryRequest, result *assetdiscovery.Result) {
				result.Assets[0].Target = "https://example.invalid:443\nother"
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			audit := validAudit()
			request := projectDiscoveryQueryRequest{Expression: "domain=example.invalid", Limit: 100}
			result := validResult()
			test.mutate(audit, &request, &result)
			if _, _, err := buildAssetDiscoverySnapshot(audit, request, result, time.Now()); !errors.Is(err, errInvalidAssetDiscoverySnapshot) {
				t.Fatalf("buildAssetDiscoverySnapshot() error = %v, want invalid snapshot", err)
			}
		})
	}
}

func TestAssetDiscoverySnapshotPersistenceRollsBackSuccessAndHidesResult(t *testing.T) {
	store := setupAssetDiscoveryTestDB(t)
	project, _ := seedFOFAProjectAndConfig(t, "default", "default", "Approved")
	provider := &fakeFOFAQueryProvider{result: assetdiscovery.Result{
		Provider: "fofa",
		Assets: []assetdiscovery.Asset{{
			Target: "https://private.example.invalid:443", Domain: "private.example.invalid", Port: 443, Protocol: "https", Source: "fofa",
		}},
	}}
	installFakeFOFAProvider(t, provider)
	if err := store.Migrator().DropTable(&db.AssetDiscoverySnapshotItem{}); err != nil {
		t.Fatalf("drop snapshot item table: %v", err)
	}

	recorder, _ := invokeFOFAPreview(t, project.ID, `{"expression":"domain=example.invalid"}`, "default", "operator", "9")
	if recorder.Code != http.StatusInternalServerError || provider.calls != 1 || strings.Contains(recorder.Body.String(), "private.example.invalid") {
		t.Fatalf("snapshot failure was not fail-closed: status=%d calls=%d body=%s", recorder.Code, provider.calls, recorder.Body.String())
	}
	var audits []db.AssetDiscoveryAudit
	if err := store.Find(&audits).Error; err != nil {
		t.Fatalf("load audits: %v", err)
	}
	if len(audits) != 1 || audits[0].Status != "failed" || audits[0].ErrorCode != "snapshot_persistence_failed" || audits[0].ReturnedCount != 0 {
		t.Fatalf("unexpected persistence failure audit: %+v", audits)
	}
	var snapshots int64
	if err := store.Model(&db.AssetDiscoverySnapshot{}).Count(&snapshots).Error; err != nil {
		t.Fatalf("count snapshots: %v", err)
	}
	if snapshots != 0 {
		t.Fatalf("successful snapshot escaped rolled-back item write: %d", snapshots)
	}
}

func TestAssetDiscoverySnapshotPersistenceRejectsDuplicateProviderTargets(t *testing.T) {
	store := setupAssetDiscoveryTestDB(t)
	project, _ := seedFOFAProjectAndConfig(t, "default", "default", "Approved")
	asset := assetdiscovery.Asset{
		Target: "https://duplicate.example.invalid:443", Domain: "duplicate.example.invalid", Port: 443, Protocol: "https", Source: "fofa",
	}
	provider := &fakeFOFAQueryProvider{result: assetdiscovery.Result{Provider: "fofa", Assets: []assetdiscovery.Asset{asset, asset}}}
	installFakeFOFAProvider(t, provider)

	recorder, _ := invokeFOFAPreview(t, project.ID, `{"expression":"domain=example.invalid"}`, "default", "operator", "9")
	if recorder.Code != http.StatusInternalServerError || provider.calls != 1 || strings.Contains(recorder.Body.String(), "duplicate.example.invalid") {
		t.Fatalf("invalid provider result was not fail-closed: status=%d calls=%d body=%s", recorder.Code, provider.calls, recorder.Body.String())
	}
	var audit db.AssetDiscoveryAudit
	if err := store.First(&audit).Error; err != nil {
		t.Fatalf("load validation failure audit: %v", err)
	}
	if audit.Status != "failed" || audit.ErrorCode != "snapshot_validation_failed" || audit.ReturnedCount != 0 {
		t.Fatalf("unexpected validation failure audit: %+v", audit)
	}
	var snapshots, items int64
	if err := store.Model(&db.AssetDiscoverySnapshot{}).Count(&snapshots).Error; err != nil {
		t.Fatalf("count snapshots: %v", err)
	}
	if err := store.Model(&db.AssetDiscoverySnapshotItem{}).Count(&items).Error; err != nil {
		t.Fatalf("count snapshot items: %v", err)
	}
	if snapshots != 0 || items != 0 {
		t.Fatalf("invalid provider result was partially persisted: snapshots=%d items=%d", snapshots, items)
	}
}

func TestAssetDiscoverySnapshotPersistenceKeepsEmptySuccessfulQuery(t *testing.T) {
	store := setupAssetDiscoveryTestDB(t)
	project, _ := seedFOFAProjectAndConfig(t, "default", "default", "Approved")
	provider := &fakeFOFAQueryProvider{result: assetdiscovery.Result{Provider: "fofa", Assets: []assetdiscovery.Asset{}}}
	installFakeFOFAProvider(t, provider)

	recorder, _ := invokeFOFAPreview(t, project.ID, `{"expression":"domain=empty.example.invalid"}`, "default", "operator", "9")
	if recorder.Code != http.StatusOK || provider.calls != 1 {
		t.Fatalf("empty query snapshot failed: status=%d calls=%d body=%s", recorder.Code, provider.calls, recorder.Body.String())
	}
	var snapshot db.AssetDiscoverySnapshot
	if err := store.First(&snapshot).Error; err != nil {
		t.Fatalf("load empty snapshot: %v", err)
	}
	if snapshot.ReturnedCount != 0 || snapshot.Expression != "domain=empty.example.invalid" {
		t.Fatalf("unexpected empty snapshot: %+v", snapshot)
	}
	var items int64
	if err := store.Model(&db.AssetDiscoverySnapshotItem{}).Count(&items).Error; err != nil {
		t.Fatalf("count empty snapshot items: %v", err)
	}
	if items != 0 {
		t.Fatalf("empty query stored %d items", items)
	}
}
