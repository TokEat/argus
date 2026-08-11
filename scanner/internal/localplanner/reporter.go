package localplanner

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"dddd/scanner/internal/engine"
	"dddd/scanner/internal/localstate"
	"dddd/scanner/internal/timing"
	"github.com/user/dddd-proto/go/scanplan"
)

type reporterState struct {
	started  bool
	active   bool
	terminal bool
	items    []string
}

type stageReporter struct {
	mu             sync.Mutex
	run            *localstate.Run
	targets        []string
	planned        map[scanplan.Stage]struct{}
	targetStages   map[string]map[scanplan.Stage]struct{}
	states         map[scanplan.Stage]*reporterState
	scopeHashes    map[string]string
	configHash     string
	ruleVersion    string
	policy         localstate.LocalPolicy
	riskPOCSetHash string
	recorder       *timing.Recorder
	spans          map[scanplan.Stage]*timing.Span
}

func (reporter *stageReporter) withTiming(recorder *timing.Recorder) *stageReporter {
	reporter.recorder = recorder
	reporter.spans = make(map[scanplan.Stage]*timing.Span)
	return reporter
}

func newStageReporter(run *localstate.Run, targets []string, cfg engine.Config, policy localstate.LocalPolicy, ruleVersion, configHash string, resume *scanplan.ResumePlan) *stageReporter {
	planned := make(map[scanplan.Stage]struct{})
	targetStages := make(map[string]map[scanplan.Stage]struct{}, len(targets))
	for _, target := range targets {
		stages, ok := engine.RequiredResumeStages(target, cfg)
		if !ok {
			continue
		}
		stateTarget := localstate.NormalizeTargetForState(target)
		targetStages[stateTarget] = make(map[scanplan.Stage]struct{}, len(stages))
		for _, stage := range stages {
			planned[stage] = struct{}{}
			targetStages[stateTarget][stage] = struct{}{}
		}
	}
	if resume != nil {
		planned = make(map[scanplan.Stage]struct{}, len(resume.ExecutionStages))
		for _, stage := range resume.ExecutionStages {
			planned[stage] = struct{}{}
		}
		stateTarget := localstate.NormalizeTargetForState(resume.Target)
		targetStages[stateTarget] = make(map[scanplan.Stage]struct{}, len(resume.ExecutionStages))
		for _, stage := range resume.ExecutionStages {
			targetStages[stateTarget][stage] = struct{}{}
		}
	}
	riskPOCSetHash := ""
	if !cfg.NoPoc || cfg.GolangPoc || strings.TrimSpace(cfg.PocNameForSearch) != "" || strings.EqualFold(strings.TrimSpace(cfg.ExecutionMode), "risk_validation") {
		riskPOCSetHash = localRiskPOCSetHash(cfg)
		planned[scanplan.StageRiskValidation] = struct{}{}
		for _, rawTarget := range targets {
			target := localstate.NormalizeTargetForState(rawTarget)
			if targetStages[target] == nil {
				targetStages[target] = make(map[scanplan.Stage]struct{})
			}
			targetStages[target][scanplan.StageRiskValidation] = struct{}{}
		}
	}
	scopeHashes := make(map[string]string, len(targets))
	for _, target := range targets {
		target = localstate.NormalizeTargetForState(target)
		scopeHashes[target] = hashValues("internal-fast", target)
	}
	return &stageReporter{
		run: run, targets: append([]string(nil), targets...), planned: planned, targetStages: targetStages, states: make(map[scanplan.Stage]*reporterState),
		scopeHashes: scopeHashes, configHash: configHash, ruleVersion: ruleVersion, policy: policy, riskPOCSetHash: riskPOCSetHash,
	}
}

func (reporter *stageReporter) observeOutput(message engine.OutputMessage) {
	encoded, _ := json.Marshal(struct {
		Type, IP, Port, Protocol, URI, Domain string
		Finger                                []string
		Status, Title                         string
	}{message.Type, message.IP, message.Port, message.Protocol, localstate.NormalizeTargetForState(message.URI), message.Domain, message.Finger, message.Web.Status, message.Web.Title})
	digest := sha256Hex(encoded)
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	for _, state := range reporter.states {
		if state.active && !state.terminal {
			state.items = append(state.items, digest)
		}
	}
}

func (reporter *stageReporter) observePhase(event engine.PhaseEvent) {
	stage, ok := engine.CanonicalStageForPhase(event.Phase)
	if !ok {
		return
	}
	if _, ok := reporter.planned[stage]; !ok {
		return
	}
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	state := reporter.states[stage]
	if state == nil {
		state = &reporterState{}
		reporter.states[stage] = state
	}
	if state.terminal {
		return
	}
	switch strings.ToLower(strings.TrimSpace(event.Status)) {
	case "start":
		state.started = true
		state.active = true
		if reporter.recorder != nil && reporter.spans[stage] == nil {
			span, err := reporter.recorder.Begin(scanplan.TimingStage, stage)
			if err == nil {
				reporter.spans[stage] = span
			}
		}
	case "end", "success", "negative":
		if stage == scanplan.StageRiskValidation {
			// Nuclei and GoPoc share one canonical risk stage. Keep collecting
			// across their separate legacy phase pairs and finish at pipeline end.
			state.active = false
			return
		}
		reporter.finishLocked(stage, state, time.Now().UTC())
	case "failed":
		state.active = false
		state.terminal = true
		if span := reporter.spans[stage]; span != nil {
			_ = span.Finish(scanplan.ObservationFailed)
		}
	case "skipped":
		state.active = false
		state.terminal = true
		// An unstarted skipped phase has no measurable execution interval.
		if state.started {
			if span := reporter.spans[stage]; span != nil {
				_ = span.Finish(scanplan.ObservationSkipped)
			}
		}
	}
}

func (reporter *stageReporter) finalize(runErr error) {
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	if runErr == nil {
		if state := reporter.states[scanplan.StageRiskValidation]; state != nil && state.started && !state.terminal {
			reporter.finishLocked(scanplan.StageRiskValidation, state, time.Now().UTC())
		}
		return
	}
	// Started but incomplete stages deliberately produce no reusable coverage.
	for _, state := range reporter.states {
		if state.active {
			state.active = false
			state.terminal = true
		}
	}
	for stage, span := range reporter.spans {
		if state := reporter.states[stage]; state != nil && state.started && state.terminal {
			_ = span.Finish(scanplan.ObservationFailed)
		}
	}
}

func (reporter *stageReporter) finishLocked(stage scanplan.Stage, state *reporterState, observedAt time.Time) {
	state.active = false
	state.terminal = true
	sort.Strings(state.items)
	items := state.items[:0]
	for _, item := range state.items {
		if len(items) == 0 || items[len(items)-1] != item {
			items = append(items, item)
		}
	}
	outcome := "success"
	if len(items) == 0 {
		outcome = "negative"
	}
	if span := reporter.spans[stage]; span != nil {
		timingOutcome := scanplan.ObservationSuccess
		if outcome == "negative" {
			timingOutcome = scanplan.ObservationNegative
		}
		_ = span.Finish(timingOutcome)
	}
	contentHash := hashValues(items...)
	for _, rawTarget := range reporter.targets {
		target := localstate.NormalizeTargetForState(rawTarget)
		if _, applies := reporter.targetStages[target][stage]; !applies {
			continue
		}
		work := scanplan.WorkKey{
			TenantID: scanplan.LocalTenantID, ProjectID: scanplan.LocalProjectID, NetworkZone: scanplan.LocalNetworkZone,
			NormalizedTarget: target, Stage: stage, ScopeHash: reporter.scopeHashes[target], ConfigHash: reporter.configHash, RuleVersion: reporter.ruleVersion,
		}
		if stage == scanplan.StageRiskValidation {
			work.POCSetHash = reporter.riskPOCSetHash
			work.EndpointContentHash = contentHash
		}
		workKey, err := work.Digest()
		if err != nil {
			continue
		}
		reporter.run.ObserveCoverage("executed", "stage_completed", localstate.CoverageRecord{
			WorkKey: workKey, NormalizedTarget: target, Stage: string(stage), ScopeHash: reporter.scopeHashes[target],
			ConfigHash: reporter.configHash, RuleVersion: reporter.ruleVersion, Outcome: outcome, ContentHash: contentHash,
			ObservedAt: observedAt, ValidUntil: observedAt.Add(stageTTL(reporter.policy, stage)), LastRunID: reporter.run.ID,
		})
	}
}

func stageTTL(policy localstate.LocalPolicy, stage scanplan.Stage) time.Duration {
	switch stage {
	case scanplan.StageICMPDiscovery, scanplan.StageTCPLiveness:
		return policy.TTL.Liveness.Value()
	case scanplan.StagePortScan:
		return policy.TTL.Port.Value()
	case scanplan.StageHTTPProbe, scanplan.StageHostBinding, scanplan.StageDirectoryProbe:
		return policy.TTL.Web.Value()
	case scanplan.StageFingerprint:
		return policy.TTL.Fingerprint.Value()
	case scanplan.StageRiskValidation:
		return policy.TTL.RiskValidation.Value()
	default:
		return policy.TTL.Protocol.Value()
	}
}

func localRiskPOCSetHash(cfg engine.Config) string {
	items := []string{strings.TrimSpace(cfg.PocNameForSearch), strconv.FormatBool(cfg.GolangPoc)}
	for target, pocs := range cfg.RiskValidationTargets {
		for _, poc := range pocs {
			items = append(items, target+"\x00"+poc+"\x00"+cfg.RiskValidationPocHashes[poc])
		}
	}
	sort.Strings(items)
	return hashValues(items...)
}
