package engine

import (
	"context"
	"crypto/sha256"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/TokEat/argus/scanner/internal/vuln/nuclei"
	"github.com/TokEat/argus/scanner/structs"
	nucleiOutput "github.com/projectdiscovery/nuclei/v3/pkg/output"
)

const activeFingerprintTestYAML = `id: shiro-detect
info:
  name: Detect Apache Shiro
  severity: info
  metadata:
    argus-rule-kind: active-fingerprint
    argus-product: APACHE-Shiro
    argus-behavior-kind: cookie
    argus-auto-profile: safe
    max-request: 1
http:
  - method: GET
    path: ['{{BaseURL}}']
    headers:
      Cookie: rememberMe={{randstr}}
    matchers:
      - type: word
        part: header
        words: ['rememberMe=deleteMe']
`

func TestRunActiveFingerprintPhaseUsesSealedPlanAndEmitsFingerprint(t *testing.T) {
	originalCall := callNucleiLimited
	t.Cleanup(func() { callNucleiLimited = originalCall })
	var received map[string][]string
	callNucleiLimited = func(targets map[string][]string, _ string, callback func(nucleiOutput.ResultEvent), nameForSearch string, noInteractsh bool, _ bool, _ embed.FS, templateDir string, _ []string, _ []string, limits nuclei.ExecutionLimits, _ bool) ([]nucleiOutput.ResultEvent, error) {
		received = targets
		if nameForSearch != "" || !noInteractsh || limits.RequestBudget != 1 || templateDir == "" {
			t.Fatalf("unexpected active fingerprint execution contract: search=%q noInteractsh=%v limits=%+v dir=%q", nameForSearch, noInteractsh, limits, templateDir)
		}
		callback(nucleiOutput.ResultEvent{TemplatePath: filepath.Join(templateDir, "shiro-detect.yaml"), Matched: "http://127.0.0.1:8081"})
		return nil, nil
	}

	dir := t.TempDir()
	content := []byte(activeFingerprintTestYAML)
	if err := os.WriteFile(filepath.Join(dir, "shiro-detect.yaml"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	var output []structs.OutputMessage
	ctx := &ScanContext{Ctx: context.Background(), OutputHook: func(message structs.OutputMessage) { output = append(output, message) }}
	cfg := &Config{
		BehaviorProbe: true, ActiveFingerprintTemplate: dir,
		ActiveFingerprintHashes:    map[string]string{"shiro-detect.yaml": fmt.Sprintf("%x", sha256.Sum256(content))},
		ActiveFingerprintProducts:  map[string]string{"shiro-detect.yaml": "APACHE-Shiro"},
		BehaviorProbeRequestBudget: 1, WebThreads: 2,
	}
	if err := runActiveFingerprintPhase(ctx, cfg, []string{"http://127.0.0.1:8081", "http://127.0.0.1:8081/redirected?from=probe"}); err != nil {
		t.Fatal(err)
	}
	if want := map[string][]string{"http://127.0.0.1:8081": {"shiro-detect.yaml"}}; !reflect.DeepEqual(received, want) {
		t.Fatalf("targets = %#v, want %#v", received, want)
	}
	if len(output) != 1 || output[0].Type != "Active-Finger" || !reflect.DeepEqual(output[0].Finger, []string{"APACHE-Shiro"}) {
		t.Fatalf("unexpected output: %#v", output)
	}
}

func TestValidatedActiveFingerprintFilesRejectsRuleDrift(t *testing.T) {
	dir := t.TempDir()
	content := []byte(activeFingerprintTestYAML)
	if err := os.WriteFile(filepath.Join(dir, "shiro-detect.yaml"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		ActiveFingerprintTemplate: dir,
		ActiveFingerprintHashes:   map[string]string{"shiro-detect.yaml": fmt.Sprintf("%x", sha256.Sum256([]byte("different")))},
		ActiveFingerprintProducts: map[string]string{"shiro-detect.yaml": "APACHE-Shiro"},
	}
	if _, _, err := validatedActiveFingerprintFiles(cfg); err == nil {
		t.Fatal("expected sealed hash drift to fail before execution")
	}
}
