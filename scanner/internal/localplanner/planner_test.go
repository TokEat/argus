package localplanner

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TokEat/argus/scanner/internal/engine"
	"github.com/TokEat/argus/scanner/internal/localstate"
	"github.com/TokEat/argus/scanner/internal/timing"
	"github.com/TokEat/argus/shared/proto/go/scanplan"
)

func TestApplyCLISafetyDefaultsEnablesNucleiAndGoPoc(t *testing.T) {
	cfg := applyCLISafetyDefaults(engine.Config{})
	if cfg.NoPoc || !cfg.GolangPoc || cfg.NoGoPoc {
		t.Fatalf("ordinary CLI config was not risk-on: %#v", cfg)
	}

	cfg = applyCLISafetyDefaults(engine.Config{NoPoc: true})
	if !cfg.NoPoc || !cfg.GolangPoc {
		t.Fatalf("-nopoc should leave GoPoc enabled: %#v", cfg)
	}

	cfg = applyCLISafetyDefaults(engine.Config{NoPoc: true, NoGoPoc: true})
	if !cfg.NoPoc || cfg.GolangPoc || !cfg.NoGoPoc {
		t.Fatalf("-nopoc -nogpoc should be discovery-only: %#v", cfg)
	}
}

func TestBuildExecutionsSkipsTargetsFoundInDatasHistory(t *testing.T) {
	history := dataResultHistory{targetSources: map[string]string{}, ipSources: map[string]string{}}
	history.addTarget("192.0.2.10", "run-a")
	history.addTarget("https://app.example.test/login", "run-b")
	cfg := engine.Config{Targets: []string{"192.0.2.10", "192.0.2.11", "https://APP.example.test/login"}, SkipSeenHistory: true}
	executions, decisions, summary := buildExecutions(cfg, history, "rules", "config", false)

	if len(executions) != 1 || len(executions[0].targets) != 1 || executions[0].targets[0] != "192.0.2.11" {
		t.Fatalf("executions = %#v, want only the unseen target", executions)
	}
	if got := decisions["192.0.2.10"]; got.Action != "skipped" || !strings.Contains(got.Reason, "history_asset_match:run-a") {
		t.Fatalf("skipped decision = %#v", got)
	}
	if got := decisions["https://APP.example.test/login"]; got.Action != "skipped" {
		t.Fatalf("URL decision = %#v", got)
	}
	if got := decisions["192.0.2.11"]; got.Action != "full" || got.Reason != "history_asset_missing" {
		t.Fatalf("full decision = %#v", got)
	}
	if summary.inputsFull != 1 || summary.inputsSkipped != 2 || summary.assetsPlanned != 1 || summary.assetsSkipped != 2 {
		t.Fatalf("summary = %#v", summary)
	}
}

func TestBuildExecutionsSubtractsKnownIPsFromCIDR(t *testing.T) {
	history := dataResultHistory{targetSources: map[string]string{}, ipSources: map[string]string{}}
	history.addTarget("192.0.2.1:80", "run-a")
	history.addTarget("http://192.0.2.2/admin", "run-b")
	cfg := engine.Config{Targets: []string{"192.0.2.0/30"}, SkipSeenHistory: true}
	executions, decisions, summary := buildExecutions(cfg, history, "rules", "config", false)
	if len(executions) != 1 || strings.Join(executions[0].targets, ",") != "192.0.2.0,192.0.2.3" {
		t.Fatalf("executions = %#v", executions)
	}
	if got := decisions["192.0.2.0/30"]; got.Action != "partial" || got.Reason != "history_asset_difference" {
		t.Fatalf("decision = %#v", got)
	}
	if summary.inputsPartial != 1 || summary.assetsPlanned != 2 || summary.assetsSkipped != 2 {
		t.Fatalf("summary = %#v", summary)
	}
	if len(summary.skippedAddresses) != 2 || summary.skippedAddresses[0].ip != "192.0.2.1" || summary.skippedAddresses[1].ip != "192.0.2.2" {
		t.Fatalf("skipped = %#v", summary.skippedAddresses)
	}
	messages := strings.Join(historySkipMessages(summary), "\n")
	for _, want := range []string{"跳过 datas 历史 IP", "192.0.2.1 (run-a)", "192.0.2.2 (run-b)", "跳过=2", "待扫描=2"} {
		if !strings.Contains(messages, want) {
			t.Fatalf("history messages %q do not contain %q", messages, want)
		}
	}
}

func TestBuildExecutionsKeepsCIDRWhenHistoryDoesNotOverlap(t *testing.T) {
	history := dataResultHistory{targetSources: map[string]string{}, ipSources: map[string]string{}}
	history.addTarget("198.51.100.10", "run-a")
	executions, _, summary := buildExecutions(engine.Config{Targets: []string{"192.0.2.0/30"}, SkipSeenHistory: true}, history, "rules", "config", false)
	if len(executions) != 1 || len(executions[0].targets) != 1 || executions[0].targets[0] != "192.0.2.0/30" {
		t.Fatalf("executions = %#v, want the original non-overlapping CIDR", executions)
	}
	if summary.inputsFull != 1 || summary.assetsPlanned != 4 || summary.assetsSkipped != 0 {
		t.Fatalf("summary = %#v", summary)
	}
}

func TestBuildExecutionsSkipsOnlyWhenSkipSeenEnabled(t *testing.T) {
	history := dataResultHistory{targetSources: map[string]string{}, ipSources: map[string]string{}}
	history.addTarget("192.0.2.10", "run-a")
	cfg := engine.Config{Targets: []string{"192.0.2.10"}}
	executions, _, _ := buildExecutions(cfg, history, "rules", "config", false)
	if len(executions) != 1 || executions[0].targets[0] != "192.0.2.10" {
		t.Fatalf("default must not skip history: %#v", executions)
	}

	cfg.SkipSeenHistory = true
	executions, decisions, _ := buildExecutions(cfg, history, "rules", "config", false)
	if len(executions) != 0 || decisions["192.0.2.10"].Action != "skipped" {
		t.Fatalf("skip-seen must drop known IP: executions=%#v decisions=%#v", executions, decisions)
	}

	executions, decisions, _ = buildExecutions(cfg, history, "rules", "config", true)
	if len(executions) != 1 || decisions["192.0.2.10"].Reason != "force_full_scan" {
		t.Fatalf("force must override skip-seen: %#v %#v", executions, decisions)
	}
}

func TestLoadDataResultHistoryReadsOnlyCompletedResultFiles(t *testing.T) {
	root := t.TempDir()
	legacy := filepath.Join(root, "legacy")
	if err := os.Mkdir(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "result.txt"), []byte("[Port] 192.0.2.20:443\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	completed := filepath.Join(root, "completed")
	if err := os.Mkdir(completed, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(completed, "summary.txt"), []byte("schema_version=argus-run-summary/v1\nrun_id=completed\nstatus=completed\nterminal_status=completed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	targets := "# argus-tsv/v1\trun_targets\n" +
		"target_index\traw_target\tnormalized_target\ttarget_type\taction\treason\n" +
		"1\t192.0.2.30\t192.0.2.30\tip\tfull\thistory_asset_missing\n"
	if err := os.WriteFile(filepath.Join(completed, "targets.tsv"), []byte(targets), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(completed, "result.txt"), []byte("[Alive] 192.0.2.31\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	current := filepath.Join(root, "current")
	if err := os.Mkdir(current, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(current, "result.txt"), []byte("[Port] 192.0.2.40:443\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	history, warnings := loadDataResultHistory(root, filepath.Join(current, "result.txt"))
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v", warnings)
	}
	for _, target := range []string{"192.0.2.20:443", "192.0.2.31"} {
		if _, ok := history.MatchTarget(target); !ok {
			t.Fatalf("history did not match %s; keys=%v", target, sortedHistoryTargets(history))
		}
	}
	if _, ok := history.MatchTarget("192.0.2.30"); ok {
		t.Fatal("targets.tsv was used as scan memory")
	}
	if _, ok := history.MatchTarget("192.0.2.40:443"); ok {
		t.Fatal("current run result was treated as previous history")
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

func TestRunInDatasDirectoryDoesNotMergeArgusDataState(t *testing.T) {
	run, err := localstate.StartRunInDirectory(filepath.Join(t.TempDir(), "datas", "target_20260812_120000"), []string{"192.0.2.50"})
	if err != nil {
		t.Fatal(err)
	}
	if err := run.SetTargetDecisions(map[string]localstate.TargetDecision{"192.0.2.50": {Action: "skipped", Reason: "history_asset_match:old"}}); err != nil {
		t.Fatal(err)
	}
	if err := run.Finish(nil); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(run.SummaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contents), "merge_status=not_applicable") {
		t.Fatalf("datas run claimed a state merge:\n%s", contents)
	}
	if _, err := os.Stat(filepath.Join(run.Dir, "summary.txt")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"targets.tsv", "findings.tsv", "coverage.tsv", "timing.tsv", "delta.tsv"} {
		if _, err := os.Stat(filepath.Join(run.Dir, name)); !os.IsNotExist(err) {
			t.Fatalf("ordinary datas run created %s: %v", name, err)
		}
	}
}

func TestExecuteWithTimingSkipsDatasHistoryWithoutRunningPipeline(t *testing.T) {
	root := t.TempDir()
	oldDir := filepath.Join(root, "datas", "old")
	if err := os.MkdirAll(oldDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(oldDir, "result.txt"), []byte("[Port] 192.0.2.60:443\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	currentDir := filepath.Join(root, "datas", "current")
	run, err := localstate.StartRunInDirectory(currentDir, []string{"192.0.2.60:443"})
	if err != nil {
		t.Fatal(err)
	}
	previousRunTask := runTask
	runTask = func(*engine.ScanContext) error {
		t.Fatal("history-skipped targets must not execute the scanner pipeline")
		return nil
	}
	t.Cleanup(func() { runTask = previousRunTask })
	ctx := &engine.ScanContext{Config: engine.Config{
		Targets: []string{"192.0.2.60:443"}, OutputFile: filepath.Join(currentDir, "result.txt"),
		NoPoc: true, NoGoPoc: true, DisableGeneralPoc: true, SkipSeenHistory: true,
	}}
	if err := ExecuteWithTiming(ctx, run, nil); err != nil {
		t.Fatal(err)
	}
	if err := run.Finish(nil); err != nil {
		t.Fatal(err)
	}
	plan := run.PlanSummary()
	if plan.InputsSkipped != 1 || plan.AssetsSkipped != 1 || plan.AssetsPlanned != 0 {
		t.Fatalf("plan summary = %#v", plan)
	}
	contents, err := os.ReadFile(run.SummaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contents), "skipped_input_count=1") || !strings.Contains(string(contents), "history_skipped_asset_count=1") {
		t.Fatalf("summary did not record history skip:\n%s", contents)
	}
}

func TestExecuteWithTimingForceRunsEvenWhenHistoryMatches(t *testing.T) {
	root := t.TempDir()
	oldDir := filepath.Join(root, "datas", "old")
	if err := os.MkdirAll(oldDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(oldDir, "result.txt"), []byte("[Web] http://127.0.0.1:8080 200\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	currentDir := filepath.Join(root, "datas", "current")
	run, err := localstate.StartRunInDirectory(currentDir, []string{"http://127.0.0.1:8080"})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	previousRunTask := runTask
	runTask = func(ctx *engine.ScanContext) error {
		called = true
		if len(ctx.Config.Targets) != 1 || ctx.Config.Targets[0] != "http://127.0.0.1:8080" {
			t.Fatalf("targets = %#v", ctx.Config.Targets)
		}
		return nil
	}
	t.Cleanup(func() { runTask = previousRunTask })
	ctx := &engine.ScanContext{LocalForceFullScan: true, Config: engine.Config{
		Targets: []string{"http://127.0.0.1:8080"}, OutputFile: filepath.Join(currentDir, "result.txt"),
		NoPoc: true, DisableGeneralPoc: true,
	}}
	if err := ExecuteWithTiming(ctx, run, nil); err != nil {
		t.Fatal(err)
	}
	if err := run.Finish(nil); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("force scan did not execute the scanner pipeline")
	}
}
