package engine

import (
	"strings"
	"testing"

	"github.com/P0lar1ght/argus/scanner/structs"
	"github.com/P0lar1ght/argus/shared/proto/go/scanpolicy"
	nucleiOutput "github.com/projectdiscovery/nuclei/v3/pkg/output"
)

func TestRunProtocolCheckPhaseBuildsExactGovernedTargets(t *testing.T) {
	original := dispatchProtocolCheckTargets
	t.Cleanup(func() { dispatchProtocolCheckTargets = original })
	called := false
	dispatchProtocolCheckTargets = func(targets []scanpolicy.GoPocTarget, catalog string, capability scanpolicy.GoPocCapability, threads, rate int, budget int64, emit func(structs.OutputMessage)) ([]structs.GoPocsResultType, error) {
		called = true
		if catalog != scanpolicy.GoPocCatalogSHA256() || capability != scanpolicy.GoPocProtocolCheck || len(targets) != 1 || targets[0].Plugin != "DNP3-Scan" || targets[0].Target != "192.0.2.10:20000" {
			t.Fatalf("unexpected protocol plan: catalog=%s capability=%s targets=%+v", catalog, capability, targets)
		}
		return nil, nil
	}
	cfg := Config{ProtocolCheckEnabled: true, ProtocolCheckTargetLimit: 2, ProtocolCheckRateLimit: 10, ProtocolCheckRequestBudget: 2, GoPocThreads: 1, GoPocCatalogSHA256: scanpolicy.GoPocCatalogSHA256()}
	if err := runProtocolCheckPhase(&ScanContext{}, &cfg, map[string]string{"192.0.2.10:20000": "dnp3", "192.0.2.20:80": "http"}); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("protocol dispatcher was not called")
	}
}

func TestRiskGoPocPlanRequiresCatalogAndPositiveNucleiSignal(t *testing.T) {
	item, err := scanpolicy.GoPocTargetForSignal("https://example.invalid/", "Shiro-Key-Crack", "nuclei", "shiro-detect", strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{ExecutionMode: "risk_validation", Targets: []string{item.Target}, RiskValidationGoPocTargets: []scanpolicy.GoPocTarget{item}, GoPocCatalogSHA256: scanpolicy.GoPocCatalogSHA256(), ValidationRequestBudget: 128}
	items, cost, err := normalizedRiskValidationGoPocTargets(&cfg)
	if err != nil || len(items) != 1 || cost != 128 {
		t.Fatalf("valid risk GoPoc plan rejected: items=%+v cost=%d err=%v", items, cost, err)
	}
	if got := activatedRiskGoPocTargets(items, nil); len(got) != 0 {
		t.Fatalf("Nuclei-dependent GoPoc ran without a positive result: %+v", got)
	}
	if got := activatedRiskGoPocTargets(items, []nucleiOutput.ResultEvent{{TemplateID: "shiro-detect", Matched: item.Target}}); len(got) != 1 {
		t.Fatalf("positive sealed Nuclei signal did not activate GoPoc: %+v", got)
	}
	cfg.GoPocCatalogSHA256 = strings.Repeat("0", 64)
	if _, _, err := normalizedRiskValidationGoPocTargets(&cfg); err == nil {
		t.Fatal("catalog drift was accepted")
	}
}
