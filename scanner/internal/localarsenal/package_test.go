package localarsenal

import (
	"os"
	"path/filepath"
	"testing"

	"dddd/scanner/internal/arsenal"
)

func TestPrepareMaterializesAndReusesFixedPackage(t *testing.T) {
	home := t.TempDir()
	layout := ResolveLayout(home)
	createLocalPackage(t, layout.DBPath, "Demo")

	first, err := prepareLocked(layout, nil)
	if err != nil {
		t.Fatalf("prepare first: %v", err)
	}
	if !first.Active || first.RuleVersion == "" || first.FileHash == "" {
		t.Fatalf("unexpected activation: %+v", first)
	}
	manifest, err := arsenal.ReadRulePackageManifest(layout.ConfigDir)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if manifest.SchemaVersion != arsenal.RulePackageSchemaVersion || manifest.RuleVersion != first.RuleVersion {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}

	second, err := prepareLocked(layout, nil)
	if err != nil {
		t.Fatalf("prepare second: %v", err)
	}
	if second.RuleVersion != first.RuleVersion || second.FileHash != first.FileHash {
		t.Fatalf("package identity changed: first=%+v second=%+v", first, second)
	}
}

func TestPrepareRejectsReplacementWithoutOverwritingMaterializedRules(t *testing.T) {
	home := t.TempDir()
	layout := ResolveLayout(home)
	createLocalPackage(t, layout.DBPath, "SafeProduct")
	if _, err := prepareLocked(layout, nil); err != nil {
		t.Fatalf("prepare valid package: %v", err)
	}
	fingerPath := filepath.Join(layout.ConfigDir, "finger.yaml")
	before, err := os.ReadFile(fingerPath)
	if err != nil {
		t.Fatalf("read materialized finger: %v", err)
	}
	if err := os.WriteFile(layout.DBPath, []byte("not sqlite"), 0o600); err != nil {
		t.Fatalf("replace package: %v", err)
	}
	if _, err := prepareLocked(layout, nil); err == nil {
		t.Fatal("expected invalid replacement to fail")
	}
	after, err := os.ReadFile(fingerPath)
	if err != nil {
		t.Fatalf("read preserved finger: %v", err)
	}
	if string(after) != string(before) {
		t.Fatal("invalid package changed the active materialized rules")
	}
}

func TestPrepareImportsValidatedReleasePackage(t *testing.T) {
	home := t.TempDir()
	layout := ResolveLayout(home)
	candidate := filepath.Join(t.TempDir(), "argus-data", "arsenal", "arsenal.db")
	createLocalPackage(t, candidate, "ImportedProduct")

	activation, err := prepareLocked(layout, []packageCandidate{{path: candidate, failIfInvalid: true}})
	if err != nil {
		t.Fatalf("prepare imported package: %v", err)
	}
	if !activation.Active || !samePath(activation.ImportedFrom, candidate) {
		t.Fatalf("expected imported activation, got %+v", activation)
	}
	if _, err := os.Stat(layout.DBPath); err != nil {
		t.Fatalf("expected fixed package copy: %v", err)
	}
}

func TestPrepareRejectsInvalidShippedPackageButSkipsInvalidLegacyPackage(t *testing.T) {
	invalid := filepath.Join(t.TempDir(), "arsenal.db")
	if err := os.WriteFile(invalid, []byte("invalid"), 0o600); err != nil {
		t.Fatalf("write invalid package: %v", err)
	}

	requiredLayout := ResolveLayout(t.TempDir())
	if _, err := prepareLocked(requiredLayout, []packageCandidate{{path: invalid, failIfInvalid: true}}); err == nil {
		t.Fatal("expected invalid shipped package to fail closed")
	}

	legacyLayout := ResolveLayout(t.TempDir())
	activation, err := prepareLocked(legacyLayout, []packageCandidate{{path: invalid}})
	if err != nil {
		t.Fatalf("optional invalid legacy package should be skipped: %v", err)
	}
	if activation.Active {
		t.Fatalf("invalid legacy package unexpectedly activated: %+v", activation)
	}
}

func createLocalPackage(t *testing.T, path, product string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir package: %v", err)
	}
	if err := arsenal.OpenDB(path); err != nil {
		t.Fatalf("open package: %v", err)
	}
	rows := []any{
		&arsenal.Fingerprint{ProductName: product, RuleExpr: `body="demo"`, Category: "web", Enabled: true},
		&arsenal.Workflow{ProductName: product, PocName: "demo.yaml", MatchType: "root", Enabled: true},
		&arsenal.DirProbe{ProductName: product, Path: "/demo", Enabled: true},
		&arsenal.Poc{Name: "demo", FileName: "demo.yaml", Content: "id: demo\n", Severity: "info", ExecutionClass: "detection", RiskLevel: "unknown", Enabled: true},
	}
	for _, row := range rows {
		if err := arsenal.DB.Create(row).Error; err != nil {
			t.Fatalf("create package row: %v", err)
		}
	}
	if err := arsenal.CloseDB(); err != nil {
		t.Fatalf("close package: %v", err)
	}
}
