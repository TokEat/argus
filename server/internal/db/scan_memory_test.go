package db

import (
	"fmt"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func openScanMemoryTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	store, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrate(&ScanObservation{}, &ScanCoverage{}, &ScanWorkClaim{}, &TaskCoverageLink{}); err != nil {
		t.Fatalf("migrate scan memory models: %v", err)
	}
	return store
}

func TestScanObservationsAreAppendOnlyAndEventIdempotentPerTenant(t *testing.T) {
	store := openScanMemoryTestDB(t)
	now := time.Now().UTC()
	eventOne := "agent-a:event-1"
	eventTwo := "agent-a:event-2"
	base := ScanObservation{
		SchemaVersion: "argus.scanplan/v1", TenantID: "tenant-a", ProjectID: "project-a", NetworkZone: "public",
		NormalizedTarget: "https://example.test", TargetHash: "target-a", Stage: "http_probe", WorkKeyHash: "work-a",
		ScopeHash: "scope-a", ConfigHash: "config-a", RuleVersion: "rules-a", RootTaskID: "task-a", BatchID: "batch-a",
		AttemptID: "attempt-a", AgentID: "agent-a", Outcome: "success", ObservedAt: now, SourceEventID: &eventOne,
	}
	if err := store.Create(&base).Error; err != nil {
		t.Fatalf("create first observation: %v", err)
	}
	second := base
	second.ID = 0
	second.SourceEventID = &eventTwo
	second.Outcome = "negative"
	if err := store.Create(&second).Error; err != nil {
		t.Fatalf("append second observation: %v", err)
	}
	var count int64
	if err := store.Model(&ScanObservation{}).Where("tenant_id = ? AND work_key_hash = ?", "tenant-a", "work-a").Count(&count).Error; err != nil || count != 2 {
		t.Fatalf("observation count=%d err=%v, want 2", count, err)
	}
	duplicate := base
	duplicate.ID = 0
	if err := store.Create(&duplicate).Error; err == nil {
		t.Fatal("duplicate source event was accepted in the same tenant")
	}
	otherTenant := base
	otherTenant.ID = 0
	otherTenant.TenantID = "tenant-b"
	otherTenant.ProjectID = "project-b"
	if err := store.Create(&otherTenant).Error; err != nil {
		t.Fatalf("same source event should remain isolated across tenants: %v", err)
	}
}

func TestScanMemoryCurrentRowsAndLinksHaveTenantScopedUniqueness(t *testing.T) {
	store := openScanMemoryTestDB(t)
	now := time.Now().UTC()
	coverage := ScanCoverage{
		SchemaVersion: "argus.scanplan/v1", TenantID: "tenant-a", ProjectID: "project-a", NetworkZone: "public",
		NormalizedTarget: "https://example.test", TargetHash: "target-a", Stage: "http_probe", WorkKeyHash: "work-a",
		ScopeHash: "scope-a", ConfigHash: "config-a", RuleVersion: "rules-a", Status: "complete", Outcome: "success",
		StartedAt: now.Add(-time.Second), FinishedAt: now, Revision: 1,
	}
	if err := store.Create(&coverage).Error; err != nil {
		t.Fatalf("create coverage: %v", err)
	}
	duplicateCoverage := coverage
	duplicateCoverage.ID = 0
	if err := store.Create(&duplicateCoverage).Error; err == nil {
		t.Fatal("duplicate current coverage was accepted for one tenant/project/work key")
	}
	otherTenantCoverage := coverage
	otherTenantCoverage.ID = 0
	otherTenantCoverage.TenantID = "tenant-b"
	otherTenantCoverage.ProjectID = "project-b"
	if err := store.Create(&otherTenantCoverage).Error; err != nil {
		t.Fatalf("coverage work key should remain isolated across tenants: %v", err)
	}

	claim := ScanWorkClaim{
		SchemaVersion: "argus.scanplan/v1", TenantID: "tenant-a", ProjectID: "project-a", NetworkZone: "public", NormalizedTarget: "https://example.test",
		TargetHash: "target-a", Stage: "http_probe", WorkKeyHash: "work-a", ScopeHash: "scope-a", ConfigHash: "config-a",
		RuleVersion: "rules-a", Status: "claimed", OwnerTaskID: "task-a", OwnerBatchID: "batch-a", OwnerAttemptID: "attempt-a", ClaimedAt: now,
	}
	if err := store.Create(&claim).Error; err != nil {
		t.Fatalf("create work claim: %v", err)
	}
	duplicateClaim := claim
	duplicateClaim.ID = 0
	if err := store.Create(&duplicateClaim).Error; err == nil {
		t.Fatal("duplicate work claim was accepted for one tenant/project/work key")
	}

	link := TaskCoverageLink{
		SchemaVersion: "argus.scanplan/v1", TenantID: "tenant-a", ProjectID: "project-a", RootTaskID: "task-a", BatchID: "batch-a", AttemptID: "attempt-a",
		WorkKeyHash: "work-a", LinkType: "executed", Status: "active", CoverageID: coverage.ID,
	}
	if err := store.Create(&link).Error; err != nil {
		t.Fatalf("create task coverage link: %v", err)
	}
	duplicateLink := link
	duplicateLink.ID = 0
	if err := store.Create(&duplicateLink).Error; err == nil {
		t.Fatal("duplicate destination coverage link was accepted")
	}
	reusedLink := link
	reusedLink.ID = 0
	reusedLink.LinkType = "reused"
	if err := store.Create(&reusedLink).Error; err != nil {
		t.Fatalf("different link types must remain separately explainable: %v", err)
	}
}
