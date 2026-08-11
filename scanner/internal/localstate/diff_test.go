package localstate

import (
	"testing"
	"time"
)

func diffAsset(target, component, run string, observedAt time.Time) AssetRecord {
	return AssetRecord{
		AssetKey: digestStrings(localNetworkZone, target), NormalizedTarget: target,
		AssetType: targetTypeNameForTest(target), NetworkZone: localNetworkZone,
		FirstSeen: observedAt, LastSeen: observedAt, LastRunID: run, Status: "active",
		ContentHash: digestStrings(component),
	}
}

func targetTypeNameForTest(target string) string {
	if len(target) >= 4 && target[:4] == "http" {
		return "url"
	}
	return "ip_port"
}

func diffCoverage(target, stage, run, outcome string, observedAt time.Time) CoverageRecord {
	return CoverageRecord{
		WorkKey: digestStrings(target, stage, "scope", "config", "rules"), NormalizedTarget: target,
		Stage: stage, ScopeHash: "scope", ConfigHash: "config", RuleVersion: "rules", LastRunID: run,
		Outcome: outcome, ObservedAt: observedAt, ValidUntil: observedAt.Add(time.Hour),
	}
}

func TestBuildDifferenceAssetsAndStages(t *testing.T) {
	old := diffAsset("https://old.test/", "old", "run-1", time.Unix(10, 0))
	changed := diffAsset("https://changed.test/", "before", "run-1", time.Unix(10, 0))
	previousChanged := diffCoverage(changed.NormalizedTarget, "http_probe", "run-1", "success", time.Unix(11, 0))
	previousFingerprint := diffCoverage(changed.NormalizedTarget, "fingerprint", "run-1", "success", time.Unix(12, 0))
	deltas, summary := BuildDifference(DifferenceInput{
		Completed:           true,
		CurrentRunID:        "run-2",
		TrustedPreviousRuns: map[string]bool{"run-1": true},
		PreviousAssets:      []AssetRecord{old, changed},
		PreviousCoverage:    []CoverageRecord{previousChanged, previousFingerprint},
		Targets: []RunTargetRecord{
			{NormalizedTarget: changed.NormalizedTarget, Action: "full"},
			{NormalizedTarget: old.NormalizedTarget, Action: "incremental"},
		},
		Findings: []RunFindingRecord{
			{Target: changed.NormalizedTarget, Component: "after", ObservedAt: time.Unix(20, 0)},
			{Target: "https://new.test/", Component: "new", ObservedAt: time.Unix(20, 0)},
		},
		Coverage: []RunCoverageRecord{
			{Action: "executed", Reason: "stage_completed", CoverageRecord: diffCoverage(changed.NormalizedTarget, "http_probe", "run-2", "success", time.Unix(21, 0))},
			{Action: "executed", Reason: "stage_completed", CoverageRecord: diffCoverage(changed.NormalizedTarget, "fingerprint", "run-2", "success", time.Unix(22, 0))},
			{Action: "reused", Reason: "valid_local_coverage", CoverageRecord: diffCoverage(old.NormalizedTarget, "http_probe", "run-1", "success", time.Unix(21, 0))},
			{Action: "executed", Reason: "duplicate", CoverageRecord: diffCoverage(changed.NormalizedTarget, "http_probe", "run-2", "success", time.Unix(21, 0))},
		},
	})
	if summary.AssetNew != 1 || summary.ServiceChanged != 1 || summary.AssetNotAssessed != 1 || summary.StageExecuted != 2 || summary.StageReused != 1 || summary.FullTargets != 1 || summary.IncrementalTargets != 1 {
		t.Fatalf("summary = %#v, deltas = %#v", summary, deltas)
	}
	for i := 1; i < len(deltas); i++ {
		if deltaSortKey(deltas[i-1]) > deltaSortKey(deltas[i]) {
			t.Fatalf("deltas not sorted: %#v", deltas)
		}
	}
}

func TestBuildDifferenceConfirmsDisappearanceOnlyWithComparableSuccessfulFullCoverage(t *testing.T) {
	asset := diffAsset("https://gone.test/", "old", "run-1", time.Unix(10, 0))
	previous := diffCoverage(asset.NormalizedTarget, "http_probe", "run-1", "success", time.Unix(11, 0))
	base := DifferenceInput{
		Completed: true, CurrentRunID: "run-2", TrustedPreviousRuns: map[string]bool{"run-1": true},
		PreviousAssets: []AssetRecord{asset}, PreviousCoverage: []CoverageRecord{previous},
		Targets:  []RunTargetRecord{{NormalizedTarget: asset.NormalizedTarget, Action: "full"}},
		Coverage: []RunCoverageRecord{{Action: "executed", CoverageRecord: diffCoverage(asset.NormalizedTarget, "http_probe", "run-2", "negative", time.Unix(20, 0))}},
	}
	deltas, _ := BuildDifference(base)
	if len(deltas) != 2 || deltas[0].Kind != DeltaAssetDisappeared {
		t.Fatalf("deltas = %#v", deltas)
	}
	for name, change := range map[string]func(*DifferenceInput){
		"failed run":        func(in *DifferenceInput) { in.Completed = false },
		"incremental":       func(in *DifferenceInput) { in.Targets[0].Action = "incremental" },
		"reused stage":      func(in *DifferenceInput) { in.Coverage[0].Action = "reused" },
		"failed stage":      func(in *DifferenceInput) { in.Coverage[0].Outcome = "failed" },
		"config drift":      func(in *DifferenceInput) { in.Coverage[0].ConfigHash = "drift" },
		"rule drift":        func(in *DifferenceInput) { in.Coverage[0].RuleVersion = "drift" },
		"scope drift":       func(in *DifferenceInput) { in.Coverage[0].ScopeHash = "drift" },
		"stale observation": func(in *DifferenceInput) { in.Coverage[0].ObservedAt = time.Unix(9, 0) },
		"foreign run evidence": func(in *DifferenceInput) {
			in.Coverage[0].LastRunID = "run-other"
		},
		"untrusted baseline": func(in *DifferenceInput) { in.TrustedPreviousRuns["run-1"] = false },
	} {
		in := base
		in.Targets = append([]RunTargetRecord(nil), base.Targets...)
		in.Coverage = append([]RunCoverageRecord(nil), base.Coverage...)
		in.TrustedPreviousRuns = map[string]bool{"run-1": true}
		change(&in)
		deltas, _ = BuildDifference(in)
		if len(deltas) == 0 || deltas[0].Kind != DeltaAssetNotAssessed {
			t.Fatalf("%s produced unsafe disappearance: %#v", name, deltas)
		}
	}

	outOfScope := base
	outOfScope.Targets = []RunTargetRecord{{NormalizedTarget: "https://other.test/", Action: "full"}}
	deltas, _ = BuildDifference(outOfScope)
	if len(deltas) != 1 || deltas[0].Kind != DeltaStageExecuted {
		t.Fatalf("out-of-scope asset should be omitted: %#v", deltas)
	}
}

func TestBuildDifferenceMapsIPScopeToPortDisappearance(t *testing.T) {
	asset := diffAsset("192.0.2.10:443", "port", "run-1", time.Unix(10, 0))
	previous := diffCoverage("192.0.2.10", "port_scan", "run-1", "success", time.Unix(11, 0))
	deltas, _ := BuildDifference(DifferenceInput{
		Completed: true, CurrentRunID: "run-2", TrustedPreviousRuns: map[string]bool{"run-1": true},
		PreviousAssets: []AssetRecord{asset}, PreviousCoverage: []CoverageRecord{previous},
		Targets:  []RunTargetRecord{{NormalizedTarget: "192.0.2.10", Action: "full"}},
		Coverage: []RunCoverageRecord{{Action: "executed", CoverageRecord: diffCoverage("192.0.2.10", "port_scan", "run-2", "negative", time.Unix(20, 0))}},
	})
	if len(deltas) != 2 || deltas[0].Kind != DeltaAssetDisappeared || deltas[0].ScopeTarget != "192.0.2.10" {
		t.Fatalf("IP scoped disappearance = %#v", deltas)
	}
}

func TestBuildDifferenceUnchangedAndReappearedAssets(t *testing.T) {
	component := "same"
	asset := diffAsset("https://same.test/", component, "run-1", time.Unix(10, 0))
	deltas, summary := BuildDifference(DifferenceInput{
		PreviousAssets: []AssetRecord{asset},
		Findings:       []RunFindingRecord{{Target: asset.NormalizedTarget, Component: component, ObservedAt: time.Unix(20, 0)}},
	})
	if len(deltas) != 0 || summary != (DifferenceSummary{}) {
		t.Fatalf("deltas=%#v summary=%#v", deltas, summary)
	}
	asset.Status = "disappeared"
	reappearance := DifferenceInput{
		Completed: true, CurrentRunID: "run-2", TrustedPreviousRuns: map[string]bool{"run-1": true},
		PreviousAssets: []AssetRecord{asset},
		Findings:       []RunFindingRecord{{Target: asset.NormalizedTarget, Component: component, ObservedAt: time.Unix(20, 0)}},
	}
	deltas, summary = BuildDifference(reappearance)
	if len(deltas) != 1 || deltas[0].Kind != DeltaServiceChanged || deltas[0].Reason != "asset_reappeared" || summary.ServiceChanged != 1 {
		t.Fatalf("reappeared delta=%#v summary=%#v", deltas, summary)
	}
	for name, change := range map[string]func(*DifferenceInput){
		"failed":      func(in *DifferenceInput) { in.Completed = false },
		"untrusted":   func(in *DifferenceInput) { in.TrustedPreviousRuns["run-1"] = false },
		"stale":       func(in *DifferenceInput) { in.Findings[0].ObservedAt = time.Unix(9, 0) },
		"missing run": func(in *DifferenceInput) { in.CurrentRunID = "" },
	} {
		input := reappearance
		input.Findings = append([]RunFindingRecord(nil), reappearance.Findings...)
		input.TrustedPreviousRuns = map[string]bool{"run-1": true}
		change(&input)
		deltas, summary = BuildDifference(input)
		if len(deltas) != 1 || deltas[0].Kind != DeltaAssetNotAssessed || summary.AssetNotAssessed != 1 {
			t.Fatalf("%s reappearance was not fail-closed: %#v / %#v", name, deltas, summary)
		}
	}
}
