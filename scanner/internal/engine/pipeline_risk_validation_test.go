package engine

import (
	"context"
	"crypto/md5"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	nucleiOutput "github.com/projectdiscovery/nuclei/v3/pkg/output"
)

func TestPipelineRiskValidationRunsOnlyExactNucleiPhase(t *testing.T) {
	originalCall := callNuclei
	t.Cleanup(func() { callNuclei = originalCall })
	var received map[string][]string
	callNuclei = func(
		targets map[string][]string,
		_ string,
		_ func(nucleiOutput.ResultEvent),
		nameForSearch string,
		_ bool,
		_ bool,
		_ embed.FS,
		_ string,
		_ []string,
		_ []string,
	) []nucleiOutput.ResultEvent {
		if nameForSearch != "" {
			t.Fatalf("risk validation used fuzzy POC search: %q", nameForSearch)
		}
		received = targets
		return nil
	}

	pocDir := t.TempDir()
	pocHashes := make(map[string]string)
	for name, content := range map[string]string{"one.yaml": "id: one\n", "two.yml": "id: two\n"} {
		if err := os.WriteFile(filepath.Join(pocDir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		pocHashes[name] = fmt.Sprintf("%x", md5.Sum([]byte(content)))
	}

	var phases []PhaseEvent
	ctx := &ScanContext{
		Config: Config{
			ExecutionMode:           "risk_validation",
			RequiredRuleVersion:     "rules-v1",
			Targets:                 []string{"https://risk.example"},
			NucleiTemplate:          pocDir,
			RiskValidationPocHashes: pocHashes,
			RiskValidationTargets: map[string][]string{
				"https://risk.example": {"one.yaml", "two.yml"},
			},
			RuleFilesOnly: true,
		},
		FingerprintDB: []FingerPEntity{{ProductName: "loaded"}},
		WorkFlowDB:    map[string]WorkFlowEntity{"loaded": {}},
		DirDB:         map[string][]string{"/": {"loaded"}},
		Ctx:           context.Background(),
		OutputHook:    func(OutputMessage) {},
		PhaseHook:     func(event PhaseEvent) { phases = append(phases, event) },
	}
	if err := (&Pipeline{}).Run(ctx); err != nil {
		t.Fatalf("risk validation pipeline failed: %v", err)
	}
	want := map[string][]string{"https://risk.example": {"one.yaml", "two.yml"}}
	if !reflect.DeepEqual(received, want) {
		t.Fatalf("exact POC mapping = %#v, want %#v", received, want)
	}
	if len(phases) != 2 || phases[0].Phase != PhaseNuclei || phases[0].Status != "start" || phases[1].Phase != PhaseNuclei || phases[1].Status != "end" {
		t.Fatalf("risk validation emitted discovery phases: %+v", phases)
	}
}

func TestRunPocSearchEmitsRiskPhase(t *testing.T) {
	originalCall := callNuclei
	t.Cleanup(func() { callNuclei = originalCall })
	callNuclei = func(
		_ map[string][]string, _ string, _ func(nucleiOutput.ResultEvent), _ string,
		_ bool, _ bool, _ embed.FS, _ string, _ []string, _ []string,
	) []nucleiOutput.ResultEvent {
		return nil
	}
	var phases []PhaseEvent
	ctx := &ScanContext{PhaseObserver: func(event PhaseEvent) { phases = append(phases, event) }}
	cfg := Config{PocNameForSearch: "explicit-check"}
	if _, err := runPocSearch(ctx, &cfg, []string{"https://example.test"}, false); err != nil {
		t.Fatal(err)
	}
	if len(phases) != 2 || phases[0].Phase != PhaseNuclei || phases[0].Status != "start" || phases[1].Phase != PhaseNuclei || phases[1].Status != "end" {
		t.Fatalf("POC search phases = %#v", phases)
	}
}

func TestRiskValidationTargetsRejectScopeAndPathEscapes(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{
			name: "target outside batch",
			cfg: Config{ExecutionMode: "risk_validation", Targets: []string{"https://allowed.example"}, RiskValidationTargets: map[string][]string{
				"https://other.example": {"safe.yaml"},
			}},
		},
		{
			name: "unsafe POC path",
			cfg: Config{ExecutionMode: "risk_validation", Targets: []string{"https://allowed.example"}, RiskValidationTargets: map[string][]string{
				"https://allowed.example": {"../unsafe.yaml"},
			}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := normalizedRiskValidationTargets(&test.cfg); err == nil {
				t.Fatal("unsafe risk validation mapping was accepted")
			}
		})
	}
}

func TestRiskValidationRejectsChangedPocContent(t *testing.T) {
	pocDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(pocDir, "safe.yaml"), []byte("id: changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		ExecutionMode: "risk_validation", Targets: []string{"https://allowed.example"}, NucleiTemplate: pocDir,
		RiskValidationTargets:   map[string][]string{"https://allowed.example": {"safe.yaml"}},
		RiskValidationPocHashes: map[string]string{"safe.yaml": fmt.Sprintf("%x", md5.Sum([]byte("id: confirmed\n")))},
	}
	targets, _, err := normalizedRiskValidationTargets(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRiskValidationPocFiles(&cfg, targets); err == nil {
		t.Fatal("changed POC content was accepted")
	}
}
