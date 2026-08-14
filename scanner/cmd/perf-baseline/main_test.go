package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/P0lar1ght/argus/scanner/internal/arsenal"
)

func TestParseCommandArgsIsBoundedAndStrict(t *testing.T) {
	args, err := parseCommandArgs(`["-h","http://127.0.0.1:3000"]`)
	if err != nil || len(args) != 2 || args[0] != "-h" {
		t.Fatalf("valid args = %v, %v", args, err)
	}
	for name, raw := range map[string]string{
		"null":     `null`,
		"object":   `{}`,
		"trailing": `[] {}`,
		"newline":  `["bad\nvalue"]`,
		"too many": `[` + strings.Repeat(`"x",`, 32) + `"x"]`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseCommandArgs(raw); err == nil {
				t.Fatal("invalid args accepted")
			}
		})
	}
}

func TestFileSHA256AndNearestRank(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity")
	if err := os.WriteFile(path, []byte("argus"), 0o600); err != nil {
		t.Fatal(err)
	}
	hash, err := fileSHA256(path)
	if err != nil || hash != "444b759c5264422ea582403ae2083d2447fd226a2e40795968dd740e9202cb97" {
		t.Fatalf("hash = %q, %v", hash, err)
	}
	values := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	if nearest(values, 50) != 5 || nearest(values, 95) != 10 {
		t.Fatalf("unexpected nearest ranks: p50=%d p95=%d", nearest(values, 50), nearest(values, 95))
	}
}

func TestAgentContextConfigRequiresMaterializedRuleFilesAndSafeDefaults(t *testing.T) {
	dir := t.TempDir()
	if _, err := agentContextConfig(dir); err == nil {
		t.Fatal("incomplete Agent config was accepted")
	}
	for _, name := range []string{"finger.yaml", "workflow.yaml", "dir.yaml"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"pocs", "active-fingerprints"} {
		if err := os.MkdirAll(filepath.Join(dir, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeAgentContextManifest(t, dir, map[string]any{
		"schema_version": arsenal.RulePackageSchemaVersion,
		"hash":           "package-hash-v1",
		"rule_version":   "v2026.08.10.1",
		"package_sha256": strings.Repeat("a", 64),
	})
	cfg, err := agentContextConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.RuleFilesOnly || !cfg.NoPoc || cfg.GolangPoc || !cfg.DisableGeneralPoc || len(cfg.Targets) != 0 || cfg.KnowledgePackageHash != strings.Repeat("a", 64) || cfg.KnowledgeRuleVersion != "v2026.08.10.1" {
		t.Fatalf("unsafe Agent context benchmark config: %+v", cfg)
	}
}

func TestAgentContextConfigRejectsInvalidManifest(t *testing.T) {
	for name, manifest := range map[string]any{
		"missing":         nil,
		"empty":           "",
		"wrong schema":    map[string]any{"schema_version": "other/v1", "hash": "package-hash", "rule_version": "rules-v1", "package_sha256": strings.Repeat("a", 64)},
		"empty hash":      map[string]any{"schema_version": arsenal.RulePackageSchemaVersion, "hash": "", "rule_version": "rules-v1", "package_sha256": strings.Repeat("a", 64)},
		"spaced version":  map[string]any{"schema_version": arsenal.RulePackageSchemaVersion, "hash": "package-hash", "rule_version": " rules-v1", "package_sha256": strings.Repeat("a", 64)},
		"control hash":    map[string]any{"schema_version": arsenal.RulePackageSchemaVersion, "hash": "package\nhash", "rule_version": "rules-v1", "package_sha256": strings.Repeat("a", 64)},
		"missing package": map[string]any{"schema_version": arsenal.RulePackageSchemaVersion, "hash": "package-hash", "rule_version": "rules-v1"},
		"bad package":     map[string]any{"schema_version": arsenal.RulePackageSchemaVersion, "hash": "package-hash", "rule_version": "rules-v1", "package_sha256": strings.Repeat("A", 64)},
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeAgentContextRules(t)
			if manifest != nil {
				if text, ok := manifest.(string); ok {
					if err := os.WriteFile(filepath.Join(dir, ".argus-arsenal.json"), []byte(text), 0o600); err != nil {
						t.Fatal(err)
					}
				} else {
					writeAgentContextManifest(t, dir, manifest)
				}
			}
			if _, err := agentContextConfig(dir); err == nil {
				t.Fatal("invalid Agent rule manifest was accepted")
			}
		})
	}
}

func TestVerifyAgentContextArsenalRequiresManifestPackageMatch(t *testing.T) {
	dir := writeAgentContextRules(t)
	arsenalPath := filepath.Join(t.TempDir(), "arsenal.db")
	if err := os.WriteFile(arsenalPath, []byte("verified-package"), 0o600); err != nil {
		t.Fatal(err)
	}
	packageHash, err := fileSHA256(arsenalPath)
	if err != nil {
		t.Fatal(err)
	}
	writeAgentContextManifest(t, dir, map[string]any{
		"schema_version": arsenal.RulePackageSchemaVersion,
		"hash":           "package-hash-v1",
		"rule_version":   "v2026.08.10.1",
		"package_sha256": packageHash,
	})
	cfg, err := agentContextConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := verifyAgentContextArsenal(cfg, arsenalPath); err != nil || got != packageHash {
		t.Fatalf("verified Arsenal identity = %q, %v; want %q", got, err, packageHash)
	}
	if err := os.WriteFile(arsenalPath, []byte("different-package"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyAgentContextArsenal(cfg, arsenalPath); err == nil {
		t.Fatal("mismatched Arsenal bytes were accepted")
	}
	if _, err := verifyAgentContextArsenal(cfg, filepath.Join(t.TempDir(), "missing.db")); err == nil {
		t.Fatal("missing Arsenal file was accepted")
	}
}

func writeAgentContextRules(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"finger.yaml", "workflow.yaml", "dir.yaml"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"pocs", "active-fingerprints"} {
		if err := os.MkdirAll(filepath.Join(dir, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func writeAgentContextManifest(t *testing.T, dir string, manifest any) {
	t.Helper()
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".argus-arsenal.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}
