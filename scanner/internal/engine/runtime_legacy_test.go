package engine

import (
	"dddd/scanner/ddout"
	"dddd/scanner/internal/arsenal"
	"os"
	"path/filepath"
	"testing"
)

func TestToEngineOutputMessageKeepsGoPocShowMsg(t *testing.T) {
	src := ddout.OutputMessage{
		Type: "GoPoc",
		GoPoc: ddout.GoPocsResultType{
			PocName:  "Shiro Weak Key",
			ShowMsg:  "http://127.0.0.1:8081 key=kPH+bIxk5D2deZiIxcaaaA==",
			Security: "CRITICAL",
		},
	}

	got := toEngineOutputMessage(src)
	if got.GoPoc.ShowMsg != src.GoPoc.ShowMsg {
		t.Fatalf("show message lost during conversion: got %q want %q", got.GoPoc.ShowMsg, src.GoPoc.ShowMsg)
	}
}

func TestNewScanContextRuleFilesOnlyIgnoresArsenalDB(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "config")
	if err := os.MkdirAll(filepath.Join(configDir, "pocs"), 0o755); err != nil {
		t.Fatalf("mkdir pocs: %v", err)
	}
	writeEngineTestFile(t, filepath.Join(configDir, "finger.yaml"), []byte("FileProduct:\n  - 'body=\"file-product\"'\n"))
	writeEngineTestFile(t, filepath.Join(configDir, "workflow.yaml"), []byte("FileProduct:\n  type:\n    - root\n  pocs:\n    - file-poc.yaml\n"))
	writeEngineTestFile(t, filepath.Join(configDir, "dir.yaml"), []byte("FileProduct:\n  - /file\n"))

	dbPath := filepath.Join(root, "data", "arsenal.db")
	if err := arsenal.OpenDB(dbPath); err != nil {
		t.Fatalf("open test arsenal db: %v", err)
	}
	t.Cleanup(func() { _ = arsenal.CloseDB() })
	if err := arsenal.DB.Create(&arsenal.Fingerprint{ProductName: "DBProduct", RuleExpr: `body="db-product"`, Enabled: true}).Error; err != nil {
		t.Fatalf("create db fingerprint: %v", err)
	}

	ctx, err := NewScanContext(Config{
		RuleFilesOnly:        true,
		FingerConfigFilePath: filepath.Join(configDir, "finger.yaml"),
		WorkflowYamlPath:     filepath.Join(configDir, "workflow.yaml"),
		DirSearchYaml:        filepath.Join(configDir, "dir.yaml"),
		NucleiTemplate:       filepath.Join(configDir, "pocs"),
	})
	if err != nil {
		t.Fatalf("new scan context: %v", err)
	}
	defer ctx.Close()

	var sawFileProduct, sawDBProduct bool
	for _, fp := range ctx.FingerprintDB {
		switch fp.ProductName {
		case "FileProduct":
			sawFileProduct = true
		case "DBProduct":
			sawDBProduct = true
		}
	}
	if !sawFileProduct {
		t.Fatalf("expected fingerprint from rule file")
	}
	if sawDBProduct {
		t.Fatalf("expected RuleFilesOnly scan context to ignore data/arsenal.db")
	}
}

func writeEngineTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
