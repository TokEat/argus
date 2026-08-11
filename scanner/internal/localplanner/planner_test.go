package localplanner

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"dddd/scanner/internal/engine"
	"dddd/scanner/internal/localstate"
	"dddd/scanner/internal/timing"
	"github.com/user/dddd-proto/go/scanplan"
)

func TestApplyCLISafetyDefaultsDisablesImplicitRiskExecution(t *testing.T) {
	cfg, explicit := applyCLISafetyDefaults(engine.Config{})
	if explicit || !cfg.NoPoc || cfg.GolangPoc || !cfg.DisableGeneralPoc {
		t.Fatalf("ordinary CLI config was not made discovery-only: %#v explicit=%v", cfg, explicit)
	}

	cfg, explicit = applyCLISafetyDefaults(engine.Config{PocNameForSearch: "explicit-check"})
	if !explicit || cfg.PocNameForSearch != "explicit-check" {
		t.Fatalf("explicit POC selection was changed: %#v explicit=%v", cfg, explicit)
	}
	cfg, explicit = applyCLISafetyDefaults(engine.Config{GolangPoc: true})
	if !explicit || !cfg.GolangPoc {
		t.Fatalf("explicit Go POC selection was changed: %#v explicit=%v", cfg, explicit)
	}
}

func TestPortIncludedHonorsExplicitScope(t *testing.T) {
	for _, test := range []struct {
		ports, candidate string
		want             bool
	}{
		{ports: "3000", candidate: "445", want: false},
		{ports: "22,80,443", candidate: "80", want: true},
		{ports: "8000-8100", candidate: "8080", want: true},
		{ports: "8000-8100", candidate: "443", want: false},
	} {
		if got := portIncluded(test.ports, test.candidate); got != test.want {
			t.Fatalf("portIncluded(%q, %q)=%v, want %v", test.ports, test.candidate, got, test.want)
		}
	}
}

func TestPreflightRevalidatesLivenessWithoutExpandingPortScope(t *testing.T) {
	policy := localstate.DefaultLocalPolicy().Revalidation
	previousProbe := probeTCP
	probeTCP = func(endpoint string, _ time.Duration) bool {
		return endpoint == "192.0.2.10:3000" || endpoint == "192.0.2.10:445"
	}
	t.Cleanup(func() { probeTCP = previousProbe })

	result, ok := preflightTarget("192.0.2.10", "3000", []string{"192.0.2.10:3000"}, []string{"192.0.2.10"}, policy)
	if !ok || !result.unchanged || len(result.openEndpoints) != 2 {
		t.Fatalf("out-of-scope liveness result = %#v, ok=%v", result, ok)
	}
	result, ok = preflightTarget("192.0.2.10", "3000,445", []string{"192.0.2.10:3000"}, []string{"192.0.2.10"}, policy)
	if !ok || result.unchanged {
		t.Fatalf("new in-scope service was not detected: %#v, ok=%v", result, ok)
	}
}

func TestLocalPolicyParticipatesInConfigHash(t *testing.T) {
	cfg := engine.Config{Ports: "80"}
	first := localstate.DefaultLocalPolicy()
	second := first
	second.TTL.Port = localstate.Duration(90 * time.Minute)
	if localConfigHash(cfg, first) == localConfigHash(cfg, second) {
		t.Fatal("policy change did not invalidate config hash")
	}
}

func TestBuildExecutionsResumesAtProtocolAfterStablePortCoverage(t *testing.T) {
	now := time.Date(2026, 8, 9, 1, 2, 3, 0, time.UTC)
	cfg := engine.Config{
		Targets: []string{"192.0.2.10"}, Ports: "80,443", SkipHostDiscovery: true,
		NoHostBind: true, NoDirSearch: true, NoPoc: true, DisableGeneralPoc: true,
	}
	policy := localstate.DefaultLocalPolicy()
	ruleVersion, configHash := hashValues("rules"), localConfigHash(cfg, policy)
	scopeHash := hashValues("internal-fast", cfg.Targets[0])
	key := scanplan.WorkKey{
		TenantID: scanplan.LocalTenantID, ProjectID: scanplan.LocalProjectID, NetworkZone: scanplan.LocalNetworkZone,
		NormalizedTarget: cfg.Targets[0], Stage: scanplan.StagePortScan, ScopeHash: scopeHash,
		ConfigHash: configHash, RuleVersion: ruleVersion,
	}
	workKey, err := key.Digest()
	if err != nil {
		t.Fatal(err)
	}
	snapshot := localstate.Snapshot{
		Assets: []localstate.AssetRecord{{NormalizedTarget: "192.0.2.10:80", AssetType: "ip_port", NetworkZone: scanplan.LocalNetworkZone, Status: "active"}},
		Coverages: []localstate.CoverageRecord{{
			WorkKey: workKey, NormalizedTarget: cfg.Targets[0], Stage: string(scanplan.StagePortScan),
			ScopeHash: scopeHash, ConfigHash: configHash, RuleVersion: ruleVersion, Outcome: "success",
			ObservedAt: now.Add(-time.Minute), ValidUntil: now.Add(time.Hour), LastRunID: "source-run",
		}},
	}
	previousProbe := probeTCP
	probeTCP = func(endpoint string, _ time.Duration) bool { return endpoint == "192.0.2.10:80" }
	t.Cleanup(func() { probeTCP = previousProbe })

	executions, decisions := buildExecutions(cfg, snapshot, policy, ruleVersion, configHash, now, false, false)
	if len(executions) != 1 || executions[0].plan == nil {
		t.Fatalf("executions = %#v, want one incremental plan", executions)
	}
	plan := executions[0].plan
	if plan.StartStage != scanplan.StageProtocolIdentify || len(plan.ReusedStages) != 1 || plan.ReusedStages[0] != scanplan.StagePortScan {
		t.Fatalf("resume plan starts at %q with reused %v", plan.StartStage, plan.ReusedStages)
	}
	if got := plan.Checkpoints[0].Checkpoint.OpenPorts; len(got) != 1 || got[0] != "192.0.2.10:80" {
		t.Fatalf("checkpoint ports = %v", got)
	}
	if err := engine.ValidateResumePlan(cfg, cfg.Targets, ruleVersion, executions[0].planHash, plan); err != nil {
		t.Fatalf("generated plan was rejected: %v", err)
	}
	if decision := decisions[cfg.Targets[0]]; decision.Action != "incremental" {
		t.Fatalf("decision = %#v", decision)
	}
	if len(executions[0].preflight) != 1 || executions[0].preflight[0].Stage != string(scanplan.StageTCPLiveness) || executions[0].preflight[0].Outcome != "success" {
		t.Fatalf("preflight coverage = %#v", executions[0].preflight)
	}
	if got := executions[0].preflight[0].ValidUntil.Sub(executions[0].preflight[0].ObservedAt); got != 5*time.Minute {
		t.Fatalf("liveness TTL = %s", got)
	}
	probeTCP = func(string, time.Duration) bool { panic("force scan must not probe reusable coverage") }
	forced, forceDecisions := buildExecutions(cfg, snapshot, policy, ruleVersion, configHash, now, false, true)
	if len(forced) != 1 || forced[0].plan != nil || forceDecisions[cfg.Targets[0]].Reason != "force_full_scan" {
		t.Fatalf("force execution=%#v decisions=%#v", forced, forceDecisions)
	}
}

func TestBuildExecutionsFallsBackForExpiredOrChangedCoverage(t *testing.T) {
	now := time.Now().UTC()
	cfg := engine.Config{Targets: []string{"192.0.2.10"}, Ports: "22,80,443,445,3389", SkipHostDiscovery: true, NoPoc: true, DisableGeneralPoc: true}
	policy := localstate.DefaultLocalPolicy()
	ruleVersion, configHash := hashValues("rules"), localConfigHash(cfg, policy)
	scopeHash := hashValues("internal-fast", cfg.Targets[0])
	key := scanplan.WorkKey{
		TenantID: scanplan.LocalTenantID, ProjectID: scanplan.LocalProjectID, NetworkZone: scanplan.LocalNetworkZone,
		NormalizedTarget: cfg.Targets[0], Stage: scanplan.StagePortScan, ScopeHash: scopeHash, ConfigHash: configHash, RuleVersion: ruleVersion,
	}
	workKey, _ := key.Digest()
	snapshot := localstate.Snapshot{Coverages: []localstate.CoverageRecord{{
		WorkKey: workKey, Outcome: "negative", ValidUntil: now.Add(-time.Second), LastRunID: "old",
	}}}
	executions, _ := buildExecutions(cfg, snapshot, policy, ruleVersion, configHash, now, false, false)
	if len(executions) != 1 || executions[0].plan != nil {
		t.Fatalf("expired coverage should produce a full execution: %#v", executions)
	}

	snapshot.Coverages[0].ValidUntil = now.Add(time.Hour)
	previousProbe := probeTCP
	probeTCP = func(endpoint string, _ time.Duration) bool { return endpoint == "192.0.2.10:22" }
	t.Cleanup(func() { probeTCP = previousProbe })
	executions, _ = buildExecutions(cfg, snapshot, policy, ruleVersion, configHash, now, false, false)
	if len(executions) != 1 || executions[0].plan != nil {
		t.Fatalf("new common service should produce a full execution: %#v", executions)
	}
}

func TestStageReporterPersistsSuccessfulPortCoverage(t *testing.T) {
	home := localstate.Home{Root: filepath.Join(t.TempDir(), "argus-data")}
	run, err := localstate.StartRun(home, []string{"192.0.2.20"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := engine.Config{Targets: []string{"192.0.2.20"}, SkipHostDiscovery: true, NoHostBind: true, NoDirSearch: true, NoPoc: true, DisableGeneralPoc: true}
	policy := localstate.DefaultLocalPolicy()
	reporter := newStageReporter(run, cfg.Targets, cfg, policy, hashValues("rules"), localConfigHash(cfg, policy), nil)
	reporter.observePhase(engine.PhaseEvent{Phase: engine.PhasePortScan, Status: "start"})
	reporter.observeOutput(engine.OutputMessage{Type: "PortScan", IP: "192.0.2.20", Port: "80"})
	reporter.observePhase(engine.PhaseEvent{Phase: engine.PhasePortScan, Status: "end"})
	if err := run.Finish(nil); err != nil {
		t.Fatal(err)
	}
	snapshot, err := localstate.LoadSnapshot(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Coverages) != 1 || snapshot.Coverages[0].Stage != string(scanplan.StagePortScan) || snapshot.Coverages[0].Outcome != "success" {
		t.Fatalf("coverage = %#v", snapshot.Coverages)
	}
	if got := snapshot.Coverages[0].ValidUntil.Sub(snapshot.Coverages[0].ObservedAt); got != time.Hour {
		t.Fatalf("port TTL = %s", got)
	}
}

func TestStageReporterUsesRiskValidationTTL(t *testing.T) {
	home := localstate.Home{Root: filepath.Join(t.TempDir(), "argus-data")}
	run, err := localstate.StartRun(home, []string{"https://example.test"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := engine.Config{Targets: []string{"https://example.test"}, PocNameForSearch: "explicit-check"}
	policy := localstate.DefaultLocalPolicy()
	policy.TTL.RiskValidation = localstate.Duration(90 * time.Minute)
	reporter := newStageReporter(run, cfg.Targets, cfg, policy, hashValues("rules"), localConfigHash(cfg, policy), nil)
	reporter.observePhase(engine.PhaseEvent{Phase: engine.PhaseNuclei, Status: "start"})
	reporter.observeOutput(engine.OutputMessage{Type: "Nuclei", URI: "https://example.test"})
	reporter.observePhase(engine.PhaseEvent{Phase: engine.PhaseNuclei, Status: "end"})
	reporter.observePhase(engine.PhaseEvent{Phase: engine.PhaseGoPoc, Status: "start"})
	reporter.observeOutput(engine.OutputMessage{Type: "GoPoc", IP: "192.0.2.10", Port: "22"})
	reporter.observePhase(engine.PhaseEvent{Phase: engine.PhaseGoPoc, Status: "end"})
	reporter.finalize(nil)
	if err := run.Finish(nil); err != nil {
		t.Fatal(err)
	}
	snapshot, err := localstate.LoadSnapshot(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Coverages) != 1 || snapshot.Coverages[0].Stage != string(scanplan.StageRiskValidation) || snapshot.Coverages[0].Outcome != "success" {
		t.Fatalf("risk coverage = %#v", snapshot.Coverages)
	}
	if got := snapshot.Coverages[0].ValidUntil.Sub(snapshot.Coverages[0].ObservedAt); got != 90*time.Minute {
		t.Fatalf("risk validation TTL = %s", got)
	}
}

func TestStageReporterTimesStartedFailureButNotUnstartedSkip(t *testing.T) {
	home := localstate.Home{Root: filepath.Join(t.TempDir(), "argus-data")}
	run, err := localstate.StartRun(home, []string{"https://example.test"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := engine.Config{Targets: []string{"https://example.test"}, NoPoc: true, DisableGeneralPoc: true}
	policy := localstate.DefaultLocalPolicy()
	recorder := timing.NewRecorder(nil)
	reporter := newStageReporter(run, cfg.Targets, cfg, policy, hashValues("rules"), localConfigHash(cfg, policy), nil).withTiming(recorder)
	reporter.observePhase(engine.PhaseEvent{Phase: engine.PhaseHTTPProbe, Status: "start"})
	reporter.observePhase(engine.PhaseEvent{Phase: engine.PhaseHTTPProbe, Status: "failed"})
	reporter.observePhase(engine.PhaseEvent{Phase: engine.PhaseFingerprint, Status: "skipped"})
	if err := recorder.Bind(run.ID, "cli-local"); err != nil {
		t.Fatal(err)
	}
	events, err := recorder.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Kind != scanplan.TimingStage || events[0].Stage != scanplan.StageHTTPProbe || events[0].Outcome != scanplan.ObservationFailed {
		t.Fatalf("unexpected failed/skipped timing evidence: %+v", events)
	}
	if err := run.Finish(errors.New("expected scan failure")); err != nil {
		t.Fatal(err)
	}
	snapshot, err := localstate.LoadSnapshot(home)
	if err != nil {
		t.Fatal(err)
	}
	for _, coverage := range snapshot.Coverages {
		if coverage.Stage == string(scanplan.StageHTTPProbe) {
			t.Fatalf("failed HTTP budget must not become reusable coverage: %+v", coverage)
		}
	}
}
