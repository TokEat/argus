package expworkspace

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/P0lar1ght/argus/server/internal/storage"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func newTestService(t *testing.T) (*Service, *gorm.DB) {
	t.Helper()
	database, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "exp.db")), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.AutoMigrate(&db.Exp{}, &db.ExpRevision{}, &db.ExpDependency{}, &db.ExpAsset{}, &db.ExpAssetRef{}, &db.ExpTestCase{}, &db.ExpRun{}, &db.ExpAudit{}, &db.ExpRiskWaiver{}); err != nil {
		t.Fatal(err)
	}
	objects, err := storage.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(database, objects, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return service, database
}

func TestRevisionAndAssetBuildSealedPackage(t *testing.T) {
	service, _ := newTestService(t)
	ctx := context.Background()
	asset, err := service.PutAsset(ctx, "tenant-a", "actor", "payload", "application/octet-stream", []byte{0, 1, 2})
	if err != nil {
		t.Fatal(err)
	}
	grandchild, err := service.CreateExp(ctx, "tenant-a", "actor", "grandchild", "", "low")
	if err != nil {
		t.Fatal(err)
	}
	grandchildRevision, err := service.CreateRevision(ctx, "tenant-a", "actor", grandchild.ID, CreateRevisionInput{Source: "cli.check(); yaksha.result(1)"})
	if err != nil {
		t.Fatal(err)
	}
	child, err := service.CreateExp(ctx, "tenant-a", "actor", "child", "", "low")
	if err != nil {
		t.Fatal(err)
	}
	childRevision, err := service.CreateRevision(ctx, "tenant-a", "actor", child.ID, CreateRevisionInput{
		Source:       "cli.check(); yaksha.call(\"" + grandchild.ID + "\", 1, {})",
		Dependencies: []DependencyInput{{ExpID: grandchild.ID, Revision: 1, SourceSHA256: grandchildRevision.SourceSHA256}},
	})
	if err != nil {
		t.Fatal(err)
	}
	root, err := service.CreateExp(ctx, "tenant-a", "actor", "root", "", "high")
	if err != nil {
		t.Fatal(err)
	}
	rootRevision, err := service.CreateRevision(ctx, "tenant-a", "actor", root.ID, CreateRevisionInput{
		Source:       "cli.check(); yaksha.call(\"" + child.ID + "\", 1, {})",
		Dependencies: []DependencyInput{{ExpID: child.ID, Revision: 1, SourceSHA256: childRevision.SourceSHA256}},
		Assets:       []AssetRefInput{{AssetID: asset.AssetID, Version: asset.Version, SHA256: asset.SHA256}},
	})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := service.BuildSealedPackage(ctx, "tenant-a", root.ID, rootRevision.Revision, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed.Dependencies) != 2 {
		t.Fatalf("unexpected dependencies: %#v", sealed.Dependencies)
	}
	if len(sealed.DependencyRefs) != 1 || sealed.DependencyRefs[0].ExpID != child.ID || sealed.DependencyRefs[0].SourceSHA256 != childRevision.SourceSHA256 {
		t.Fatalf("unexpected direct dependency refs: %#v", sealed.DependencyRefs)
	}
	if len(sealed.Assets) != 1 || sealed.Assets[0].Encoding != "base64" || sealed.Assets[0].Content != "AAEC" {
		t.Fatalf("unexpected assets: %#v", sealed.Assets)
	}
	if len(sealed.AssetRefs) != 1 || sealed.AssetRefs[0].AssetID != asset.AssetID || sealed.AssetRefs[0].Version != asset.Version || sealed.AssetRefs[0].SHA256 != asset.SHA256 {
		t.Fatalf("unexpected direct asset refs: %#v", sealed.AssetRefs)
	}
	if _, err := service.BuildSealedPackage(ctx, "tenant-b", root.ID, 1, false); err == nil {
		t.Fatal("cross-tenant sealed package should fail")
	}
	if strings.Contains(rootRevision.SourceObjectKey, "tenant-a") || !strings.Contains(rootRevision.SourceObjectKey, rootRevision.SourceSHA256) {
		t.Fatalf("object key should contain opaque tenant prefix and content hash: %s", rootRevision.SourceObjectKey)
	}
}

func TestRevisionIsImmutableAndRequiresExactResolverHashes(t *testing.T) {
	service, _ := newTestService(t)
	ctx := context.Background()
	item, err := service.CreateExp(ctx, "tenant-a", "actor", "immutable", "", "medium")
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.CreateRevision(ctx, "tenant-a", "actor", item.ID, CreateRevisionInput{Source: "cli.check()"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.CreateRevision(ctx, "tenant-a", "actor", item.ID, CreateRevisionInput{Source: "cli.check(); yaksha.result(2)"})
	if err != nil {
		t.Fatal(err)
	}
	if first.Revision != 1 || second.Revision != 2 || first.SourceSHA256 == second.SourceSHA256 {
		t.Fatalf("unexpected revisions: %#v %#v", first, second)
	}
	root, _ := service.CreateExp(ctx, "tenant-a", "actor", "bad-dependency", "", "low")
	_, err = service.CreateRevision(ctx, "tenant-a", "actor", root.ID, CreateRevisionInput{Source: "cli.check()", Dependencies: []DependencyInput{{ExpID: item.ID, Revision: 1, SourceSHA256: strings.Repeat("0", 64)}}})
	if err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("expected hash mismatch, got %v", err)
	}
}

func TestConcurrentRevisionCreationAllocatesUniqueMonotonicNumbers(t *testing.T) {
	service, database := newTestService(t)
	sqlDB, err := database.DB()
	if err != nil {
		t.Fatal(err)
	}
	// SQLite has no row-level SELECT FOR UPDATE. A single pooled connection
	// gives this unit test the same serialized transaction boundary that the
	// production PostgreSQL root-row lock provides.
	sqlDB.SetMaxOpenConns(1)
	exp, err := service.CreateExp(context.Background(), "tenant-a", "operator", "concurrent", "", "medium")
	if err != nil {
		t.Fatal(err)
	}

	const count = 8
	revisions := make(chan int, count)
	errorsCh := make(chan error, count)
	var wait sync.WaitGroup
	for index := 0; index < count; index++ {
		index := index
		wait.Add(1)
		go func() {
			defer wait.Done()
			created, createErr := service.CreateRevision(context.Background(), "tenant-a", "operator", exp.ID, CreateRevisionInput{Source: fmt.Sprintf("cli.check(); yaksha.result(%d)", index)})
			if createErr != nil {
				errorsCh <- createErr
				return
			}
			revisions <- created.Revision
		}()
	}
	wait.Wait()
	close(revisions)
	close(errorsCh)
	for createErr := range errorsCh {
		t.Fatalf("concurrent revision creation failed: %v", createErr)
	}
	got := make([]int, 0, count)
	for revision := range revisions {
		got = append(got, revision)
	}
	sort.Ints(got)
	for index, revision := range got {
		if want := index + 1; revision != want {
			t.Fatalf("revision sequence = %v, want 1..%d", got, count)
		}
	}
}

func TestPublishGateAndFixtureMutationInvalidation(t *testing.T) {
	service, database := newTestService(t)
	ctx := context.Background()
	item, _ := service.CreateExp(ctx, "tenant-a", "admin", "publish", "", "high")
	revision, err := service.CreateRevision(ctx, "tenant-a", "admin", item.ID, CreateRevisionInput{Source: "cli.check(); yaksha.result(true)"})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Publish(ctx, "tenant-a", "admin", item.ID, revision.Revision, revision.SourceSHA256); err == nil {
		t.Fatal("publish should require all gates")
	}
	now := time.Now().UTC()
	inspect := `{"status":"Succeeded","inspection":{"valid":true}}`
	validate := `{"status":"Succeeded","validation":{"valid":true}}`
	if err := database.Model(&db.ExpRevision{}).Where("exp_id = ? AND revision = ?", item.ID, 1).Updates(map[string]any{"inspect_summary": inspect, "validate_summary": validate, "tests_passed_at": now}).Error; err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateTestCase(ctx, "tenant-a", "admin", item.ID, 1, TestCaseInput{Name: "fixture", Params: json.RawMessage(`{}`), Fixture: json.RawMessage(`{}`), Expect: json.RawMessage(`{"result":true}`)})
	if err != nil {
		t.Fatal(err)
	}
	var refreshed db.ExpRevision
	if err := database.Where("exp_id = ? AND revision = ?", item.ID, 1).First(&refreshed).Error; err != nil {
		t.Fatal(err)
	}
	if refreshed.TestsPassedAt != nil {
		t.Fatal("Fixture mutation must invalidate prior test acceptance")
	}
	_, casesHash, err := service.sealedTestCasesWithDB(ctx, database, "tenant-a", item.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Model(&refreshed).Updates(map[string]any{"tests_passed_at": now, "test_cases_sha256": casesHash}).Error; err != nil {
		t.Fatal(err)
	}
	if err := service.Publish(ctx, "tenant-a", "admin", item.ID, 1, revision.SourceSHA256); err != nil {
		t.Fatal(err)
	}
	if _, err := service.UpdateTestCase(ctx, "tenant-a", item.ID, created.ID, TestCaseInput{Name: "changed"}); err == nil {
		t.Fatal("published revision Fixture must be immutable")
	}
}

func TestAssetContentAndRiskWaiverRemainTenantScoped(t *testing.T) {
	service, database := newTestService(t)
	ctx := context.Background()
	asset, err := service.PutAsset(ctx, "tenant-a", "operator", "dictionary", "text/plain", []byte("one\ntwo\n"))
	if err != nil {
		t.Fatal(err)
	}
	metadata, content, err := service.GetAssetContent(ctx, "tenant-a", asset.AssetID, asset.Version)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.ObjectKey == "" || content.Encoding != "utf8" || content.Content != "one\ntwo\n" {
		t.Fatalf("unexpected controlled Asset content: %#v %#v", metadata, content)
	}
	if _, _, err := service.GetAssetContent(ctx, "tenant-b", asset.AssetID, asset.Version); err == nil {
		t.Fatal("cross-tenant Asset content read should fail")
	}

	exp, err := service.CreateExp(ctx, "tenant-a", "operator", "waived", "", "critical")
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(time.Hour)
	waiver, err := service.UpsertRiskWaiver(ctx, "tenant-a", "admin", exp.ID, RiskWaiverInput{Reason: "approved maintenance", ExpiresAt: &expires})
	if err != nil {
		t.Fatal(err)
	}
	if waiver.GrantedBy != "admin" || waiver.Reason != "approved maintenance" {
		t.Fatalf("unexpected waiver: %#v", waiver)
	}
	if _, err := service.GetRiskWaiver(ctx, "tenant-b", exp.ID); err == nil {
		t.Fatal("cross-tenant waiver read should fail")
	}
	var auditCount int64
	if err := database.Model(&db.ExpAudit{}).Where("tenant_id = ? AND exp_id = ? AND action = ?", "tenant-a", exp.ID, "risk_waiver_upsert").Count(&auditCount).Error; err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("risk waiver audit count = %d", auditCount)
	}
}

func TestMaintenanceExpiresArtifactsAndDeletesOnlyOldOrphans(t *testing.T) {
	root := t.TempDir()
	database, err := gorm.Open(sqlite.Open(filepath.Join(root, "exp.db")), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.AutoMigrate(&db.Exp{}, &db.ExpRevision{}, &db.ExpDependency{}, &db.ExpAsset{}, &db.ExpAssetRef{}, &db.ExpTestCase{}, &db.ExpRun{}, &db.ExpAudit{}, &db.ExpRiskWaiver{}); err != nil {
		t.Fatal(err)
	}
	objectRoot := filepath.Join(root, "objects")
	objects, err := storage.NewLocalStore(objectRoot)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(database, objects, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	asset, err := service.PutAsset(ctx, "tenant-a", "operator", "kept", "text/plain", []byte("kept"))
	if err != nil {
		t.Fatal(err)
	}
	orphanKey := tenantObjectPrefix("tenant-a") + "/exp/assets/" + strings.Repeat("f", 64)
	if _, err := objects.Put(ctx, orphanKey, bytes.NewReader([]byte("orphan"))); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Add(25 * time.Hour)
	deleted, err := service.CleanupOrphanObjects(ctx, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 {
		t.Fatalf("deleted orphan count = %d", deleted)
	}
	if _, exists, err := objects.Exists(ctx, asset.ObjectKey); err != nil || !exists {
		t.Fatalf("referenced Asset was deleted: exists=%v err=%v", exists, err)
	}

	artifact := []byte(`{"status":"Succeeded"}`)
	hash := contentHash(artifact)
	runID := "run-maintenance"
	artifactKey := artifactObjectKey("tenant-a", runID, hash)
	if err := service.putImmutable(ctx, artifactKey, artifact, hash); err != nil {
		t.Fatal(err)
	}
	expired := time.Now().UTC().Add(-time.Minute)
	run := db.ExpRun{ID: runID, TenantID: "tenant-a", ExpID: "exp", Revision: 1, SourceSHA256: strings.Repeat("a", 64), Action: "debug", OperatorID: "operator", EgressMode: "disabled", Status: "Succeeded", Provenance: "server", Attested: true, ResultSummary: `{}`, ArtifactObjectKey: artifactKey, ArtifactSHA256: hash, ArtifactExpiresAt: &expired, StartedAt: expired, FinishedAt: &expired}
	if err := database.Create(&run).Error; err != nil {
		t.Fatal(err)
	}
	expiredCount, err := service.ExpireRunArtifacts(ctx, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if expiredCount != 1 {
		t.Fatalf("expired artifact count = %d", expiredCount)
	}
	var refreshed db.ExpRun
	if err := database.First(&refreshed, "id = ?", runID).Error; err != nil {
		t.Fatal(err)
	}
	if refreshed.ArtifactObjectKey != "" || refreshed.ResultSummary != `{}` {
		t.Fatalf("artifact body should expire while summary remains: %#v", refreshed)
	}
}

func TestStatusDetailsTreatsMissingErrorAsEmpty(t *testing.T) {
	details := statusDetails(RuntimeResponse{"status": "Succeeded"})
	if details["status"] != "Succeeded" || details["has_error"] != false {
		t.Fatalf("unexpected status details: %#v", details)
	}
	if got := stringValue(nil, "mode"); got != "" {
		t.Fatalf("missing string value = %q", got)
	}
}

func TestExecutionRejectsMismatchedSourceIdentity(t *testing.T) {
	service, _ := newTestService(t)
	ctx := context.Background()
	exp, err := service.CreateExp(ctx, "tenant-a", "operator", "untrusted-report", "", "high")
	if err != nil {
		t.Fatal(err)
	}
	revision, err := service.CreateRevision(ctx, "tenant-a", "operator", exp.ID, CreateRevisionInput{Source: "cli.check()"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Execute(ctx, "tenant-a", "operator", exp.ID, revision.Revision, RunInput{Action: "debug", SourceSHA256: "wrong", RiskConfirmed: true}, map[string]any{"mode": "disabled"}); err == nil || !strings.Contains(err.Error(), "source_sha256") {
		t.Fatalf("mismatched execution identity should fail before Runtime: %v", err)
	}
}

func TestExecutionCreatesRunBeforeCallingRuntime(t *testing.T) {
	service, database := newTestService(t)
	runtime, err := NewRuntimeClient("http://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	service.runtime = runtime
	ctx := context.Background()
	exp, err := service.CreateExp(ctx, "tenant-a", "operator", "pre-audited-run", "", "low")
	if err != nil {
		t.Fatal(err)
	}
	revision, err := service.CreateRevision(ctx, "tenant-a", "operator", exp.ID, CreateRevisionInput{Source: "cli.check()"})
	if err != nil {
		t.Fatal(err)
	}
	_, runErr := service.Execute(ctx, "tenant-a", "operator", exp.ID, revision.Revision, RunInput{Action: "run", SourceSHA256: revision.SourceSHA256}, map[string]any{"mode": "disabled"})
	if runErr == nil {
		t.Fatal("unavailable Runtime should fail execution")
	}
	var runs []db.ExpRun
	if err := database.Where("tenant_id = ? AND exp_id = ?", "tenant-a", exp.ID).Find(&runs).Error; err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].Status == "running" || runs[0].FinishedAt == nil {
		t.Fatalf("Runtime failure must leave a terminal pre-created run record: %+v", runs)
	}
}

func TestServerOrchestratedTestAndDebugPersistTrustedUnredactedArtifacts(t *testing.T) {
	runtimeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/execute" {
			http.NotFound(w, r)
			return
		}
		var request RuntimeRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		switch request.Action {
		case "test":
			if stringValue(request.Egress, "mode") != "disabled" || len(request.NetworkTargets) != 0 || len(request.TestCases) != 1 {
				t.Fatalf("Fixture test was not sealed offline: %#v", request)
			}
			_, _ = w.Write([]byte(`{"status":"Succeeded","test":{"failed":0}}`))
		case "debug":
			_, _ = w.Write([]byte(`{"status":"Succeeded","debug":{"events":[{"kind":"http","body":"credential=unredacted"}]}}`))
		default:
			t.Fatalf("unexpected action %q", request.Action)
		}
	}))
	defer runtimeServer.Close()

	service, database := newTestService(t)
	runtime, err := NewRuntimeClient(runtimeServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	service.runtime = runtime
	ctx := context.Background()
	exp, _ := service.CreateExp(ctx, "tenant-a", "operator", "trusted-runtime", "", "high")
	revision, err := service.CreateRevision(ctx, "tenant-a", "operator", exp.ID, CreateRevisionInput{Source: "cli.check()"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateTestCase(ctx, "tenant-a", "operator", exp.ID, revision.Revision, TestCaseInput{Name: "offline", Params: json.RawMessage(`{}`), Fixture: json.RawMessage(`{}`), Expect: json.RawMessage(`{}`)}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Execute(ctx, "tenant-a", "operator", exp.ID, revision.Revision, RunInput{Action: "test", SourceSHA256: revision.SourceSHA256, Egress: EgressInput{Mode: "disabled"}}, map[string]any{"mode": "disabled"}); err != nil {
		t.Fatal(err)
	}
	var refreshed db.ExpRevision
	if err := database.Where("exp_id = ? AND revision = ?", exp.ID, revision.Revision).First(&refreshed).Error; err != nil {
		t.Fatal(err)
	}
	if refreshed.TestsPassedAt == nil {
		t.Fatal("Server-orchestrated Fixture test should satisfy the publish gate")
	}

	debug, err := service.Execute(ctx, "tenant-a", "operator", exp.ID, revision.Revision, RunInput{Action: "debug", SourceSHA256: revision.SourceSHA256, RiskConfirmed: true, Egress: EgressInput{Mode: "disabled"}}, map[string]any{"mode": "disabled"})
	if err != nil {
		t.Fatal(err)
	}
	_, artifact, err := service.GetRun(ctx, "tenant-a", debug.RunID, true)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(artifact)
	if !bytes.Contains(raw, []byte("credential=unredacted")) {
		t.Fatalf("debug artifact was redacted or truncated: %s", raw)
	}
	stored, _, err := service.GetRun(ctx, "tenant-a", debug.RunID, false)
	if err != nil {
		t.Fatal(err)
	}
	if !stored.Attested || stored.Provenance != "server" {
		t.Fatalf("Server run must be attested: %#v", stored)
	}
}

func TestExecutionPolicyRejectsDeprecatedAndRequiresHighRiskConfirmation(t *testing.T) {
	service, _ := newTestService(t)
	ctx := context.Background()
	exp, err := service.CreateExp(ctx, "tenant-a", "operator", "dangerous", "", "critical")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CheckExecutionAllowed(ctx, "tenant-a", exp.ID, 0, "debug", false); err == nil || !strings.Contains(err.Error(), "risk_confirmed") {
		t.Fatalf("critical EXP should require confirmation: %v", err)
	}
	if _, err := service.CheckExecutionAllowed(ctx, "tenant-a", exp.ID, 0, "debug", true); err != nil {
		t.Fatalf("explicit confirmation should allow execution: %v", err)
	}
	expires := time.Now().UTC().Add(time.Hour)
	if _, err := service.UpsertRiskWaiver(ctx, "tenant-a", "admin", exp.ID, RiskWaiverInput{Reason: "approved window", ExpiresAt: &expires}); err != nil {
		t.Fatal(err)
	}
	waiverUsed, err := service.CheckExecutionAllowed(ctx, "tenant-a", exp.ID, 0, "run", false)
	if err != nil || !waiverUsed {
		t.Fatalf("active waiver should allow execution: used=%v err=%v", waiverUsed, err)
	}
	if err := service.DeprecateExp(ctx, "tenant-a", "admin", exp.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.CheckExecutionAllowed(ctx, "tenant-a", exp.ID, 0, "test", true); err == nil || !strings.Contains(err.Error(), "deprecated") {
		t.Fatalf("deprecated EXP should never execute: %v", err)
	}
}

func TestOnlyAdminMayLowerEXPRisk(t *testing.T) {
	service, _ := newTestService(t)
	exp, _ := service.CreateExp(context.Background(), "tenant-a", "operator", "governed-risk", "", "critical")
	if _, err := service.UpdateExp(context.Background(), "tenant-a", "operator", exp.ID, "", "", "low", false); err == nil || !strings.Contains(err.Error(), "Admin") {
		t.Fatalf("operator risk downgrade should fail: %v", err)
	}
	updated, err := service.UpdateExp(context.Background(), "tenant-a", "admin", exp.ID, "", "", "low", true)
	if err != nil || updated.RiskLevel != "low" {
		t.Fatalf("Admin risk downgrade failed: %#v err=%v", updated, err)
	}
}

func TestExecutionPolicyCoversDependencyClosure(t *testing.T) {
	service, _ := newTestService(t)
	ctx := context.Background()
	child, _ := service.CreateExp(ctx, "tenant-a", "operator", "critical-child", "", "critical")
	childRevision, err := service.CreateRevision(ctx, "tenant-a", "operator", child.ID, CreateRevisionInput{Source: "cli.check()"})
	if err != nil {
		t.Fatal(err)
	}
	root, _ := service.CreateExp(ctx, "tenant-a", "operator", "low-wrapper", "", "low")
	rootRevision, err := service.CreateRevision(ctx, "tenant-a", "operator", root.ID, CreateRevisionInput{Source: "cli.check()", Dependencies: []DependencyInput{{ExpID: child.ID, Revision: childRevision.Revision, SourceSHA256: childRevision.SourceSHA256}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CheckExecutionAllowed(ctx, "tenant-a", root.ID, rootRevision.Revision, "run", false); err == nil || !strings.Contains(err.Error(), "risk_confirmed") {
		t.Fatalf("critical dependency should require confirmation: %v", err)
	}
	sealed, err := service.BuildSealedPackage(ctx, "tenant-a", root.ID, rootRevision.Revision, false)
	if err != nil || !sealed.RequiresRiskConfirmation {
		t.Fatalf("sealed governance did not include dependency risk: %#v err=%v", sealed, err)
	}
	if err := service.DeprecateExp(ctx, "tenant-a", "admin", child.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.CheckExecutionAllowed(ctx, "tenant-a", root.ID, rootRevision.Revision, "test", true); err == nil || !strings.Contains(err.Error(), "deprecated") {
		t.Fatalf("deprecated dependency should block execution: %v", err)
	}
	sealed, err = service.BuildSealedPackage(ctx, "tenant-a", root.ID, rootRevision.Revision, false)
	if err != nil || sealed.DeprecatedDependency != child.ID {
		t.Fatalf("sealed governance did not include deprecated dependency: %#v err=%v", sealed, err)
	}
}

func TestFixtureAcceptanceIsBoundToExactCaseSnapshot(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	runtimeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"Succeeded","test":{"failed":0}}`))
	}))
	defer runtimeServer.Close()

	service, database := newTestService(t)
	runtime, err := NewRuntimeClient(runtimeServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	service.runtime = runtime
	ctx := context.Background()
	exp, _ := service.CreateExp(ctx, "tenant-a", "operator", "fixture-snapshot", "", "medium")
	revision, _ := service.CreateRevision(ctx, "tenant-a", "operator", exp.ID, CreateRevisionInput{Source: "cli.check()"})
	testCase, err := service.CreateTestCase(ctx, "tenant-a", "operator", exp.ID, revision.Revision, TestCaseInput{Name: "before", Params: json.RawMessage(`{}`), Fixture: json.RawMessage(`{}`), Expect: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	executeErr := make(chan error, 1)
	go func() {
		_, runErr := service.Execute(ctx, "tenant-a", "operator", exp.ID, revision.Revision, RunInput{Action: "test", SourceSHA256: revision.SourceSHA256}, map[string]any{"mode": "disabled"})
		executeErr <- runErr
	}()
	<-started
	if _, err := service.UpdateTestCase(ctx, "tenant-a", exp.ID, testCase.ID, TestCaseInput{Expect: json.RawMessage(`{"result":true}`)}); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-executeErr; err == nil || !strings.Contains(err.Error(), "changed during execution") {
		t.Fatalf("stale Fixture result should be rejected: %v", err)
	}
	var refreshed db.ExpRevision
	if err := database.Where("exp_id = ? AND revision = ?", exp.ID, revision.Revision).First(&refreshed).Error; err != nil {
		t.Fatal(err)
	}
	if refreshed.TestsPassedAt != nil || refreshed.TestCasesSHA256 != "" {
		t.Fatalf("stale Fixture result was recorded: %#v", refreshed)
	}
	var run db.ExpRun
	if err := database.Where("exp_id = ?", exp.ID).First(&run).Error; err != nil {
		t.Fatal(err)
	}
	if run.Status != "Rejected" || run.ErrorCode != "fixture_snapshot_changed" || run.FinishedAt == nil {
		t.Fatalf("stale Fixture run must reach a terminal state: %#v", run)
	}
}
