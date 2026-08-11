package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/glebarez/sqlite"
	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
)

func TestExportSeedDBToConfigDirExportsApprovedRules(t *testing.T) {
	root := t.TempDir()
	seedPath := filepath.Join(root, "arsenal_seed.db")
	stagingDir := filepath.Join(root, "staging")
	createSeedDB(t, seedPath, []arsenalRow{
		row("finger", "finger.yaml", "Approved", "Demo:\n  - 'body=\"demo\"'\n"),
		row("workflow", "workflow.yaml", "Approved", "Demo:\n  type:\n    - root\n  pocs:\n    - demo-poc\n"),
		row("dir", "dir.yaml", "Approved", "Demo:\n  - /demo/\n"),
		row("poc", "demo-poc.yaml", "Approved", "id: demo-poc\ninfo:\n  name: demo\n  severity: info\n"),
		row("poc", "draft-poc.yaml", "Draft", "id: draft-poc\n"),
		row("poc_asset", "helpers/payloads.txt", "Approved", "payload\n"),
		row("config_asset", "dict/mysql.txt", "Approved", "root:root\n"),
		row("config_asset", "subdomains.txt", "Approved", "www\napi\n"),
		row("apiconfig", "api-config.yaml", "Approved", "fofa: secret\n"),
	})

	summary, err := ExportSeedDBToConfigDir(seedPath, stagingDir)
	if err != nil {
		t.Fatalf("export seed db: %v", err)
	}

	assertFileContent(t, filepath.Join(stagingDir, "finger.yaml"), "Demo:\n  - 'body=\"demo\"'\n")
	assertFileContent(t, filepath.Join(stagingDir, "workflow.yaml"), "Demo:\n  type:\n    - root\n  pocs:\n    - demo-poc\n")
	assertFileContent(t, filepath.Join(stagingDir, "dir.yaml"), "Demo:\n  - /demo/\n")
	assertFileContent(t, filepath.Join(stagingDir, "pocs", "demo-poc.yaml"), "id: demo-poc\ninfo:\n  name: demo\n  severity: info\n")
	assertFileContent(t, filepath.Join(stagingDir, "pocs", "helpers", "payloads.txt"), "payload\n")
	assertFileContent(t, filepath.Join(stagingDir, "dict", "mysql.txt"), "root:root\n")
	assertFileContent(t, filepath.Join(stagingDir, "subdomains.txt"), "www\napi\n")
	assertNotExists(t, filepath.Join(stagingDir, "pocs", "draft-poc.yaml"))
	assertNotExists(t, filepath.Join(stagingDir, "socket.yaml"))
	assertNotExists(t, filepath.Join(stagingDir, "api-config.yaml"))

	if summary.ApprovedRows != 7 {
		t.Fatalf("expected 7 approved managed rows, got %d", summary.ApprovedRows)
	}
	if !slices.Contains(summary.ManagedFiles, "dict/") || !slices.Contains(summary.ManagedFiles, "subdomains.txt") {
		t.Fatalf("expected managed config assets in summary, got %#v", summary.ManagedFiles)
	}

	assertYAMLFile(t, filepath.Join(stagingDir, "finger.yaml"))
	assertYAMLFile(t, filepath.Join(stagingDir, "workflow.yaml"))
	assertYAMLFile(t, filepath.Join(stagingDir, "dir.yaml"))
}

func TestApplySeedDBToConfigDirBacksUpAndPreservesUnmanagedFiles(t *testing.T) {
	root := t.TempDir()
	seedPath := filepath.Join(root, "arsenal_seed.db")
	configDir := filepath.Join(root, "config")
	backupRoot := filepath.Join(root, "backups")
	mustWriteFile(t, filepath.Join(configDir, "finger.yaml"), []byte("Old:\n  - old\n"))
	mustWriteFile(t, filepath.Join(configDir, "workflow.yaml"), []byte("Old:\n  type: [root]\n  pocs: [old]\n"))
	mustWriteFile(t, filepath.Join(configDir, "dir.yaml"), []byte("Old:\n  - /old/\n"))
	mustWriteFile(t, filepath.Join(configDir, "pocs", "old.yaml"), []byte("id: old\n"))
	mustWriteFile(t, filepath.Join(configDir, "dict", "local.txt"), []byte("keep-local\n"))
	mustWriteFile(t, filepath.Join(configDir, "subdomains.txt"), []byte("keep.example\n"))
	mustWriteFile(t, filepath.Join(configDir, "api-config.yaml"), []byte("fofa: keep\n"))
	mustWriteFile(t, filepath.Join(configDir, "socket.yaml"), []byte("socket: keep\n"))

	createSeedDB(t, seedPath, []arsenalRow{
		row("finger", "finger.yaml", "Approved", "New:\n  - new\n"),
		row("workflow", "workflow.yaml", "Approved", "New:\n  type: [root]\n  pocs: [new]\n"),
		row("dir", "dir.yaml", "Approved", "New:\n  - /new/\n"),
		row("poc", "new.yaml", "Approved", "id: new\n"),
	})

	summary, err := ApplySeedDBToConfigDir(ApplyOptions{
		SeedDBPath: seedPath,
		ConfigDir:  configDir,
		BackupRoot: backupRoot,
		Confirm:    true,
	})
	if err != nil {
		t.Fatalf("apply seed db: %v", err)
	}

	assertFileContent(t, filepath.Join(configDir, "finger.yaml"), "New:\n  - new\n")
	assertFileContent(t, filepath.Join(configDir, "pocs", "new.yaml"), "id: new\n")
	assertNotExists(t, filepath.Join(configDir, "pocs", "old.yaml"))
	assertFileContent(t, filepath.Join(configDir, "dict", "local.txt"), "keep-local\n")
	assertFileContent(t, filepath.Join(configDir, "subdomains.txt"), "keep.example\n")
	assertFileContent(t, filepath.Join(configDir, "api-config.yaml"), "fofa: keep\n")
	assertFileContent(t, filepath.Join(configDir, "socket.yaml"), "socket: keep\n")

	if summary.BackupDir == "" {
		t.Fatal("expected backup dir")
	}
	assertFileContent(t, filepath.Join(summary.BackupDir, "config", "pocs", "old.yaml"), "id: old\n")
}

func TestApplySeedDBToConfigDirRequiresConfirmation(t *testing.T) {
	root := t.TempDir()
	seedPath := filepath.Join(root, "arsenal_seed.db")
	configDir := filepath.Join(root, "config")
	createSeedDB(t, seedPath, []arsenalRow{
		row("finger", "finger.yaml", "Approved", "New:\n  - new\n"),
		row("workflow", "workflow.yaml", "Approved", "New:\n  type: [root]\n  pocs: [new]\n"),
		row("dir", "dir.yaml", "Approved", "New:\n  - /new/\n"),
	})

	_, err := ApplySeedDBToConfigDir(ApplyOptions{
		SeedDBPath: seedPath,
		ConfigDir:  configDir,
		Confirm:    false,
	})
	if err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("expected confirmation error, got %v", err)
	}
}

func TestApplySeedDBToConfigDirRejectsBackupRootInsideConfig(t *testing.T) {
	root := t.TempDir()
	seedPath := filepath.Join(root, "arsenal_seed.db")
	configDir := filepath.Join(root, "config")
	createSeedDB(t, seedPath, []arsenalRow{
		row("finger", "finger.yaml", "Approved", "New:\n  - new\n"),
		row("workflow", "workflow.yaml", "Approved", "New:\n  type: [root]\n  pocs: [new]\n"),
		row("dir", "dir.yaml", "Approved", "New:\n  - /new/\n"),
	})
	mustWriteFile(t, filepath.Join(configDir, "finger.yaml"), []byte("Old:\n  - old\n"))

	_, err := ApplySeedDBToConfigDir(ApplyOptions{
		SeedDBPath: seedPath,
		ConfigDir:  configDir,
		BackupRoot: filepath.Join(configDir, ".backups"),
		Confirm:    true,
	})
	if err == nil || !strings.Contains(err.Error(), "backup root") {
		t.Fatalf("expected backup root containment error, got %v", err)
	}
	assertNotExists(t, filepath.Join(configDir, ".backups"))
}

func TestApplySeedDBToConfigDirSkipsBackupWhenNoDiff(t *testing.T) {
	root := t.TempDir()
	seedPath := filepath.Join(root, "arsenal_seed.db")
	configDir := filepath.Join(root, "config")
	backupRoot := filepath.Join(root, "backups")
	createSeedDB(t, seedPath, []arsenalRow{
		row("finger", "finger.yaml", "Approved", "Same:\n  - same\n"),
		row("workflow", "workflow.yaml", "Approved", "Same:\n  type: [root]\n  pocs: [same]\n"),
		row("dir", "dir.yaml", "Approved", "Same:\n  - /same/\n"),
	})
	mustWriteFile(t, filepath.Join(configDir, "finger.yaml"), []byte("Same:\n  - same\n"))
	mustWriteFile(t, filepath.Join(configDir, "workflow.yaml"), []byte("Same:\n  type: [root]\n  pocs: [same]\n"))
	mustWriteFile(t, filepath.Join(configDir, "dir.yaml"), []byte("Same:\n  - /same/\n"))
	if err := os.MkdirAll(filepath.Join(configDir, "pocs"), 0o755); err != nil {
		t.Fatalf("mkdir pocs: %v", err)
	}

	summary, err := ApplySeedDBToConfigDir(ApplyOptions{
		SeedDBPath: seedPath,
		ConfigDir:  configDir,
		BackupRoot: backupRoot,
		Confirm:    true,
	})
	if err != nil {
		t.Fatalf("apply seed db: %v", err)
	}
	if summary.BackupDir != "" {
		t.Fatalf("expected no backup on empty diff, got %s", summary.BackupDir)
	}
	assertNotExists(t, backupRoot)
}

func TestDiffSeedDBWithConfigDirRejectsSymlinks(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, configDir string)
	}{
		{
			name: "managed scalar symlink",
			setup: func(t *testing.T, configDir string) {
				mustWriteFile(t, filepath.Join(configDir, "real-finger.yaml"), []byte("Demo:\n  - ok\n"))
				mustSymlink(t, filepath.Join(configDir, "real-finger.yaml"), filepath.Join(configDir, "finger.yaml"))
			},
		},
		{
			name: "managed pocs dir symlink",
			setup: func(t *testing.T, configDir string) {
				realPocs := filepath.Join(configDir, "real-pocs")
				if err := os.MkdirAll(realPocs, 0o755); err != nil {
					t.Fatalf("mkdir real pocs: %v", err)
				}
				mustSymlink(t, realPocs, filepath.Join(configDir, "pocs"))
			},
		},
		{
			name: "nested pocs symlink",
			setup: func(t *testing.T, configDir string) {
				mustWriteFile(t, filepath.Join(configDir, "pocs", "real.txt"), []byte("payload\n"))
				mustSymlink(t, filepath.Join(configDir, "pocs", "real.txt"), filepath.Join(configDir, "pocs", "link.txt"))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			seedPath := filepath.Join(root, "arsenal_seed.db")
			configDir := filepath.Join(root, "config")
			createSeedDB(t, seedPath, []arsenalRow{
				row("finger", "finger.yaml", "Approved", "Demo:\n  - ok\n"),
				row("workflow", "workflow.yaml", "Approved", "Demo:\n  type: [root]\n  pocs: [ok]\n"),
				row("dir", "dir.yaml", "Approved", "Demo:\n  - /\n"),
			})
			mustWriteFile(t, filepath.Join(configDir, "workflow.yaml"), []byte("Demo:\n  type: [root]\n  pocs: [ok]\n"))
			mustWriteFile(t, filepath.Join(configDir, "dir.yaml"), []byte("Demo:\n  - /\n"))
			if tc.name != "managed scalar symlink" {
				mustWriteFile(t, filepath.Join(configDir, "finger.yaml"), []byte("Demo:\n  - ok\n"))
			}
			if tc.name != "managed pocs dir symlink" {
				if err := os.MkdirAll(filepath.Join(configDir, "pocs"), 0o755); err != nil {
					t.Fatalf("mkdir pocs: %v", err)
				}
			}
			tc.setup(t, configDir)

			_, err := DiffSeedDBWithConfigDir(seedPath, configDir)
			if err == nil || !strings.Contains(err.Error(), "symlink") {
				t.Fatalf("expected symlink error, got %v", err)
			}
		})
	}
}

func TestExportSeedDBToConfigDirRejectsUnsafePaths(t *testing.T) {
	tests := []struct {
		name string
		row  arsenalRow
	}{
		{name: "poc absolute path", row: row("poc", "/tmp/poc.yaml", "Approved", "id: bad\n")},
		{name: "poc asset traversal", row: row("poc_asset", "../escape.txt", "Approved", "bad\n")},
		{name: "config asset traversal", row: row("config_asset", "dict/../x.txt", "Approved", "bad\n")},
		{name: "unsupported config asset", row: row("config_asset", "socket.yaml", "Approved", "bad\n")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			seedPath := filepath.Join(root, "arsenal_seed.db")
			createSeedDB(t, seedPath, []arsenalRow{
				row("finger", "finger.yaml", "Approved", "Demo:\n  - ok\n"),
				row("workflow", "workflow.yaml", "Approved", "Demo:\n  type: [root]\n  pocs: [ok]\n"),
				row("dir", "dir.yaml", "Approved", "Demo:\n  - /\n"),
				tc.row,
			})

			_, err := ExportSeedDBToConfigDir(seedPath, filepath.Join(root, "staging"))
			if err == nil {
				t.Fatal("expected unsafe path error")
			}
			assertNotExists(t, filepath.Join(root, "escape.txt"))
		})
	}
}

func TestDiffSeedDBWithConfigDirReportsAddedModifiedDeleted(t *testing.T) {
	root := t.TempDir()
	seedPath := filepath.Join(root, "arsenal_seed.db")
	configDir := filepath.Join(root, "config")
	mustWriteFile(t, filepath.Join(configDir, "finger.yaml"), []byte("Old:\n  - old\n"))
	mustWriteFile(t, filepath.Join(configDir, "workflow.yaml"), []byte("Demo:\n  type: [root]\n  pocs: [demo]\n"))
	mustWriteFile(t, filepath.Join(configDir, "dir.yaml"), []byte("Demo:\n  - /\n"))
	mustWriteFile(t, filepath.Join(configDir, "pocs", "old.yaml"), []byte("id: old\n"))
	createSeedDB(t, seedPath, []arsenalRow{
		row("finger", "finger.yaml", "Approved", "New:\n  - new\n"),
		row("workflow", "workflow.yaml", "Approved", "Demo:\n  type: [root]\n  pocs: [demo]\n"),
		row("dir", "dir.yaml", "Approved", "Demo:\n  - /\n"),
		row("poc", "new.yaml", "Approved", "id: new\n"),
	})

	diff, err := DiffSeedDBWithConfigDir(seedPath, configDir)
	if err != nil {
		t.Fatalf("diff seed db: %v", err)
	}

	if !slices.Contains(diff.Added, "pocs/new.yaml") {
		t.Fatalf("expected pocs/new.yaml added, got %#v", diff.Added)
	}
	if !slices.Contains(diff.Modified, "finger.yaml") {
		t.Fatalf("expected finger.yaml modified, got %#v", diff.Modified)
	}
	if !slices.Contains(diff.Deleted, "pocs/old.yaml") {
		t.Fatalf("expected pocs/old.yaml deleted, got %#v", diff.Deleted)
	}
}

func createSeedDB(t *testing.T, path string, rows []arsenalRow) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	if err != nil {
		t.Fatalf("open seed db: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get seed db handle: %v", err)
	}
	t.Cleanup(func() {
		if err := sqlDB.Close(); err != nil {
			t.Errorf("close seed db: %v", err)
		}
	})
	if err := db.AutoMigrate(&arsenalRow{}); err != nil {
		t.Fatalf("migrate seed db: %v", err)
	}
	for i := range rows {
		if rows[i].ID == "" {
			rows[i].ID = rows[i].Type + "_" + rows[i].FileName
		}
		if rows[i].TenantID == "" {
			rows[i].TenantID = "default"
		}
		if rows[i].Version == 0 {
			rows[i].Version = 1
		}
	}
	if err := db.Create(&rows).Error; err != nil {
		t.Fatalf("seed rows: %v", err)
	}
}

func mustSymlink(t *testing.T, oldname, newname string) {
	t.Helper()
	if err := os.Symlink(oldname, newname); err != nil {
		const windowsErrorPrivilegeNotHeld syscall.Errno = 1314
		if runtime.GOOS == "windows" && errors.Is(err, windowsErrorPrivilegeNotHeld) {
			t.Skipf("symlink creation requires Windows privilege: %v", err)
		}
		t.Fatalf("symlink %s: %v", newname, err)
	}
}

func row(typ, fileName, state, content string) arsenalRow {
	return arsenalRow{
		Type:     typ,
		FileName: fileName,
		State:    state,
		Content:  content,
		Hash:     fileName + "-hash",
	}
}

func mustWriteFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func assertFileContent(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(data) != want {
		t.Fatalf("unexpected content for %s\nwant:\n%s\ngot:\n%s", path, want, string(data))
	}
}

func assertNotExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected %s to not exist, stat err=%v", path, err)
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
