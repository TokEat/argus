package engine

import (
	"context"
	"crypto/md5"
	"embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/TokEat/argus/scanner/internal/vuln/nuclei"
	nucleiOutput "github.com/projectdiscovery/nuclei/v3/pkg/output"
)

func TestNativeWorkflowMatchWithEmptyFingerprintsEmitsNoPhase(t *testing.T) {
	originalCall := callNucleiLimited
	t.Cleanup(func() { callNucleiLimited = originalCall })
	callNucleiLimited = func(
		map[string][]string, string, func(nucleiOutput.ResultEvent), string, bool, bool, embed.FS, string, []string, []string, nuclei.ExecutionLimits, bool,
	) ([]nucleiOutput.ResultEvent, error) {
		t.Fatal("empty fingerprint native match must not invoke Nuclei")
		return nil, nil
	}
	var phases []PhaseEvent
	ctx := &ScanContext{
		Config: Config{
			ExecutionMode:               "risk_validation",
			TargetFingerprints:          map[string][]string{},
			ValidationBudgetID:          "empty-budget",
			ValidationTargetConcurrency: 1,
			ValidationRateLimit:         10,
			ValidationRequestBudget:     1,
			ValidationEstimatedRequests: 1,
		},
		PhaseHook: func(event PhaseEvent) { phases = append(phases, event) },
	}
	if err := (&Pipeline{}).Run(ctx); err != nil {
		t.Fatalf("empty fingerprint risk validation failed: %v", err)
	}
	if len(phases) != 0 {
		t.Fatalf("empty fingerprint native match emitted phases: %+v", phases)
	}
}

func TestNativeWorkflowMatchIgnoresServerRequestBudget(t *testing.T) {
	originalCall := callNucleiLimited
	t.Cleanup(func() { callNucleiLimited = originalCall })
	var got nuclei.ExecutionLimits
	callNucleiLimited = func(
		_ map[string][]string, _ string, _ func(nucleiOutput.ResultEvent), _ string, _ bool, _ bool, _ embed.FS, _ string, _ []string, _ []string, limits nuclei.ExecutionLimits, _ bool,
	) ([]nucleiOutput.ResultEvent, error) {
		got = limits
		return nil, nil
	}
	ctx := &ScanContext{
		Config: Config{
			ExecutionMode:               "risk_validation",
			Targets:                     []string{"https://app.example"},
			TargetFingerprints:          map[string][]string{"https://app.example": {"nginx"}},
			ValidationBudgetID:          "tiny-budget",
			ValidationTargetConcurrency: 1,
			ValidationRateLimit:         10,
			ValidationRequestBudget:     25,
			ValidationEstimatedRequests: 25,
			AllowHighRiskAutoExecution:  true,
		},
		WorkFlowDB: map[string]WorkFlowEntity{
			"nginx": {PocsName: []string{"one.yaml", "two.yaml"}, RootType: true},
		},
		Ctx:        context.Background(),
		OutputHook: func(OutputMessage) {},
	}
	if err := (&Pipeline{}).Run(ctx); err != nil {
		t.Fatalf("native match failed: %v", err)
	}
	if got.RequestBudget != 0 {
		t.Fatalf("native match must not apply Server request budget, got %d", got.RequestBudget)
	}
	if got.RateLimit != 10 || got.TargetConcurrency != 1 {
		t.Fatalf("intensity limits should still apply: %+v", got)
	}
}

func TestPipelineRiskValidationRunsOnlyExactNucleiPhase(t *testing.T) {
	originalCall := callNucleiLimited
	t.Cleanup(func() { callNucleiLimited = originalCall })
	var received map[string][]string
	callNucleiLimited = func(
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
		limits nuclei.ExecutionLimits,
		_ bool,
	) ([]nucleiOutput.ResultEvent, error) {
		if nameForSearch != "" {
			t.Fatalf("risk validation used fuzzy POC search: %q", nameForSearch)
		}
		received = targets
		if limits.RateLimit != 10 || limits.TargetConcurrency != 1 || limits.RequestBudget != 2 {
			t.Fatalf("unexpected sealed Nuclei limits: %+v", limits)
		}
		return nil, nil
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
			RuleFilesOnly:               true,
			ValidationBudgetID:          "root-budget",
			ValidationTargetConcurrency: 1,
			ValidationRateLimit:         10,
			ValidationRequestBudget:     2,
			ValidationEstimatedRequests: 2,
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
	) ([]nucleiOutput.ResultEvent, error) {
		return nil, nil
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

func TestRunPocSearchPropagatesNucleiFailure(t *testing.T) {
	originalCall := callNuclei
	t.Cleanup(func() { callNuclei = originalCall })
	wantErr := errors.New("nuclei runner unavailable")
	callNuclei = func(
		_ map[string][]string, _ string, _ func(nucleiOutput.ResultEvent), _ string,
		_ bool, _ bool, _ embed.FS, _ string, _ []string, _ []string,
	) ([]nucleiOutput.ResultEvent, error) {
		return nil, wantErr
	}
	var phases []PhaseEvent
	ctx := &ScanContext{PhaseObserver: func(event PhaseEvent) { phases = append(phases, event) }}
	cfg := Config{PocNameForSearch: "explicit-check"}
	if _, err := runPocSearch(ctx, &cfg, []string{"https://example.test"}, false); !errors.Is(err, wantErr) {
		t.Fatalf("runPocSearch error = %v, want %v", err, wantErr)
	}
	if len(phases) != 2 || phases[0].Status != "start" || phases[1].Status != "failed" {
		t.Fatalf("failed POC search phases = %#v", phases)
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
