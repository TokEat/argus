package arsenal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestMaterializeRulePackageWritesCLIConfigAndPreservesUnmanagedFiles(t *testing.T) {
	root := t.TempDir()
	dbPath := filepath.Join(root, "arsenal.db")
	createMaterializeTestDB(t, dbPath, "demo-poc.yaml")

	configDir := filepath.Join(root, "config")
	mustWriteFile(t, filepath.Join(configDir, "api-config.yaml"), []byte("fofa: {}\n"))
	mustWriteFile(t, filepath.Join(configDir, "dict", "mysql.txt"), []byte("old:old\n"))
	mustWriteFile(t, filepath.Join(configDir, "pocs", "old.yaml"), []byte("id: old\n"))

	backupRoot := filepath.Join(root, "data", "arsenal", "backups")
	if err := MaterializeRulePackage(MaterializeOptions{
		DBPath:      dbPath,
		ConfigDir:   configDir,
		BackupRoot:  backupRoot,
		Hash:        "hash-1",
		RuleVersion: "v1",
		BackupLimit: 3,
	}); err != nil {
		t.Fatalf("materialize rule package: %v", err)
	}

	assertYAMLFile(t, filepath.Join(configDir, "finger.yaml"))
	assertYAMLFile(t, filepath.Join(configDir, "workflow.yaml"))
	assertYAMLFile(t, filepath.Join(configDir, "dir.yaml"))

	if _, err := os.Stat(filepath.Join(configDir, "pocs", "demo-poc.yaml")); err != nil {
		t.Fatalf("expected materialized poc: %v", err)
	}
	if _, err := os.Stat(filepath.Join(configDir, "pocs", "helpers", "payloads", "demo.txt")); err != nil {
		t.Fatalf("expected materialized poc asset: %v", err)
	}
	if _, err := os.Stat(filepath.Join(configDir, "pocs", "old.yaml")); !os.IsNotExist(err) {
		t.Fatalf("expected managed pocs directory to be replaced, stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(configDir, "api-config.yaml")); err != nil {
		t.Fatalf("expected unmanaged api-config.yaml to be preserved: %v", err)
	}
	assertFileContent(t, filepath.Join(configDir, "dict", "mysql.txt"), "synced:mysql\n")
	assertFileContent(t, filepath.Join(configDir, "subdomains.txt"), "www\napi\n")

	var manifest RulePackageManifest
	data, err := os.ReadFile(filepath.Join(configDir, ".argus-arsenal.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	if manifest.Hash != "hash-1" || manifest.RuleVersion != "v1" {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}
	if manifestContains := slicesContains(manifest.ManagedFiles, "dict/") && slicesContains(manifest.ManagedFiles, "subdomains.txt"); !manifestContains {
		t.Fatalf("expected manifest to list managed config assets, got %+v", manifest.ManagedFiles)
	}

	backups, err := os.ReadDir(backupRoot)
	if err != nil {
		t.Fatalf("read backup root: %v", err)
	}
	if len(backups) != 1 {
		t.Fatalf("expected one backup, got %d", len(backups))
	}
	backupConfig := filepath.Join(backupRoot, backups[0].Name(), "config")
	if _, err := os.Stat(filepath.Join(backupConfig, "pocs", "old.yaml")); err != nil {
		t.Fatalf("expected old config backup: %v", err)
	}
	assertFileContent(t, filepath.Join(backupConfig, "dict", "mysql.txt"), "old:old\n")
}

func TestMaterializeRulePackageRejectsUnsafePocFileName(t *testing.T) {
	root := t.TempDir()
	dbPath := filepath.Join(root, "arsenal.db")
	createMaterializeTestDB(t, dbPath, "../escape.yaml")

	err := MaterializeRulePackage(MaterializeOptions{
		DBPath:      dbPath,
		ConfigDir:   filepath.Join(root, "config"),
		BackupRoot:  filepath.Join(root, "data", "arsenal", "backups"),
		Hash:        "hash-unsafe",
		RuleVersion: "v1",
		BackupLimit: 3,
	})
	if err == nil {
		t.Fatalf("expected unsafe poc filename to fail materialization")
	}
	if _, statErr := os.Stat(filepath.Join(root, "escape.yaml")); !os.IsNotExist(statErr) {
		t.Fatalf("unsafe poc escaped materialization root, stat err=%v", statErr)
	}
}

func TestMaterializeRulePackageRejectsUnsafePocAssetPath(t *testing.T) {
	root := t.TempDir()
	dbPath := filepath.Join(root, "arsenal.db")
	createMaterializeTestDB(t, dbPath, "demo-poc.yaml")
	if err := DB.Create(&PocAsset{
		RelativePath: "../escape.txt",
		Content:      "owned\n",
		Enabled:      true,
	}).Error; err != nil {
		t.Fatalf("create unsafe poc asset: %v", err)
	}

	err := MaterializeRulePackage(MaterializeOptions{
		DBPath:      dbPath,
		ConfigDir:   filepath.Join(root, "config"),
		BackupRoot:  filepath.Join(root, "data", "arsenal", "backups"),
		Hash:        "hash-unsafe-asset",
		RuleVersion: "v1",
		BackupLimit: 3,
	})
	if err == nil {
		t.Fatalf("expected unsafe poc asset path to fail materialization")
	}
	if _, statErr := os.Stat(filepath.Join(root, "escape.txt")); !os.IsNotExist(statErr) {
		t.Fatalf("unsafe poc asset escaped materialization root, stat err=%v", statErr)
	}
}

func TestMaterializeRulePackageRejectsUnsafeConfigAssetPath(t *testing.T) {
	root := t.TempDir()
	dbPath := filepath.Join(root, "arsenal.db")
	createMaterializeTestDB(t, dbPath, "demo-poc.yaml")
	if err := DB.Create(&ConfigAsset{
		RelativePath: "../api-config.yaml",
		Content:      "owned\n",
		Enabled:      true,
	}).Error; err != nil {
		t.Fatalf("create unsafe config asset: %v", err)
	}

	err := MaterializeRulePackage(MaterializeOptions{
		DBPath:      dbPath,
		ConfigDir:   filepath.Join(root, "config"),
		BackupRoot:  filepath.Join(root, "data", "arsenal", "backups"),
		Hash:        "hash-unsafe-config-asset",
		RuleVersion: "v1",
		BackupLimit: 3,
	})
	if err == nil {
		t.Fatalf("expected unsafe config asset path to fail materialization")
	}
	if _, statErr := os.Stat(filepath.Join(root, "api-config.yaml")); !os.IsNotExist(statErr) {
		t.Fatalf("unsafe config asset escaped materialization root, stat err=%v", statErr)
	}
}

func createMaterializeTestDB(t *testing.T, dbPath, pocFile string) {
	t.Helper()
	if err := OpenDB(dbPath); err != nil {
		t.Fatalf("open test arsenal db: %v", err)
	}
	t.Cleanup(func() { DB = nil })
	if err := DB.Create(&Fingerprint{ProductName: "DemoProduct", RuleExpr: `body="demo-product"`, Enabled: true}).Error; err != nil {
		t.Fatalf("create fingerprint: %v", err)
	}
	if err := DB.Create(&Workflow{ProductName: "DemoProduct", PocName: pocFile, MatchType: "root", Enabled: true}).Error; err != nil {
		t.Fatalf("create workflow: %v", err)
	}
	if err := DB.Create(&DirProbe{ProductName: "DemoProduct", Path: "/demo", Enabled: true}).Error; err != nil {
		t.Fatalf("create dir probe: %v", err)
	}
	if err := DB.Create(&Poc{
		Name:     "demo-poc",
		FileName: pocFile,
		Content:  "id: demo-poc\ninfo:\n  name: demo\n  author: test\n  severity: info\nrequests: []\n",
		Enabled:  true,
	}).Error; err != nil {
		t.Fatalf("create poc: %v", err)
	}
	if err := DB.Create(&PocAsset{
		RelativePath: "helpers/payloads/demo.txt",
		Content:      "payload\n",
		Enabled:      true,
	}).Error; err != nil {
		t.Fatalf("create poc asset: %v", err)
	}
	if err := DB.Create(&ConfigAsset{
		RelativePath: "dict/mysql.txt",
		Content:      "synced:mysql\n",
		Enabled:      true,
	}).Error; err != nil {
		t.Fatalf("create dict config asset: %v", err)
	}
	if err := DB.Create(&ConfigAsset{
		RelativePath: "subdomains.txt",
		Content:      "www\napi\n",
		Enabled:      true,
	}).Error; err != nil {
		t.Fatalf("create subdomains config asset: %v", err)
	}
}

func mustWriteFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func assertYAMLFile(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read yaml %s: %v", path, err)
	}
	var out any
	if err := yaml.Unmarshal(data, &out); err != nil {
		t.Fatalf("parse yaml %s: %v", path, err)
	}
}

func assertFileContent(t *testing.T, path, expected string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(data) != expected {
		t.Fatalf("content %s = %q, want %q", path, string(data), expected)
	}
}

func slicesContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
