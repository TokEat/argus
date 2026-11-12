package localstate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/TokEat/argus/scanner/utils"
)

// DeltaKind describes a local, immutable observation made while comparing a
// run with the snapshot taken immediately before its state merge.
type DeltaKind string

const (
	DeltaAssetNew         DeltaKind = "asset_new"
	DeltaServiceChanged   DeltaKind = "service_changed"
	DeltaAssetDisappeared DeltaKind = "asset_disappeared"
	DeltaAssetNotAssessed DeltaKind = "asset_not_assessed"
	DeltaStageExecuted    DeltaKind = "stage_executed"
	DeltaStageReused      DeltaKind = "stage_reused"
)

var deltaSchema = tableSchema{Name: "run_delta", Columns: []string{
	"sequence", "kind", "normalized_target", "scope_target", "asset_key", "asset_type",
	"previous_status", "current_status", "previous_hash", "current_hash",
	"previous_seen_at", "current_seen_at", "previous_run_id", "current_run_id",
	"stage", "action", "outcome", "reason",
}}

// DeltaRecord deliberately contains identities, timestamps, and hashes only.
// It never copies raw findings, request data, or query strings.
type DeltaRecord struct {
	Kind             DeltaKind
	AssetKey         string
	NormalizedTarget string
	ScopeTarget      string
	AssetType        string
	Stage            string
	Action           string
	Outcome          string
	Reason           string
	PreviousStatus   string
	CurrentStatus    string
	PreviousHash     string
	CurrentHash      string
	PreviousSeenAt   time.Time
	CurrentSeenAt    time.Time
	PreviousRunID    string
	CurrentRunID     string
}

// DifferenceSummary is a compact, deterministic summary of DeltaRecords.
type DifferenceSummary struct {
	AssetNew           int
	ServiceChanged     int
	AssetDisappeared   int
	AssetNotAssessed   int
	StageExecuted      int
	StageReused        int
	FullTargets        int
	IncrementalTargets int
}

// RunTargetRecord is the non-sensitive portion of targets.tsv used by the
// diff engine. Action must be full before a missing asset can be confirmed.
type RunTargetRecord struct {
	NormalizedTarget string
	Action           string
	Reason           string
}

// RunFindingRecord is the minimal finding projection needed to derive the
// same asset identity/content hash as mergeRunAssets.
type RunFindingRecord struct {
	Target     string
	ObservedAt time.Time
	Component  string
}

// RunCoverageRecord preserves the action/reason columns that are intentionally
// not part of durable CoverageRecord state.
type RunCoverageRecord struct {
	Action string
	Reason string
	CoverageRecord
}

// DifferenceInput contains only pre-merge state and records written by this
// run. It has no filesystem or lock dependency and is safe to call under the
// merge lock immediately before state is changed.
type DifferenceInput struct {
	Completed           bool
	CurrentRunID        string
	TrustedPreviousRuns map[string]bool
	PreviousAssets      []AssetRecord
	PreviousCoverage    []CoverageRecord
	Targets             []RunTargetRecord
	Findings            []RunFindingRecord
	Coverage            []RunCoverageRecord
}

// BuildDifference compares a run to its pre-merge snapshot. It is deliberately
// fail-closed: absence alone never proves disappearance.
func BuildDifference(input DifferenceInput) ([]DeltaRecord, DifferenceSummary) {
	previousAssets := make(map[string]AssetRecord, len(input.PreviousAssets))
	for _, asset := range input.PreviousAssets {
		if strings.TrimSpace(asset.AssetKey) != "" {
			previousAssets[asset.AssetKey] = asset
		}
	}
	currentAssets := deriveRunAssets(input.Findings)
	deltas := make([]DeltaRecord, 0)
	for key, current := range currentAssets {
		previous, found := previousAssets[key]
		if !found {
			deltas = append(deltas, DeltaRecord{
				Kind: DeltaAssetNew, AssetKey: key, NormalizedTarget: current.NormalizedTarget, AssetType: current.AssetType,
				CurrentStatus: "active", CurrentHash: current.ContentHash, Reason: "first_observation",
			})
			continue
		}
		if strings.EqualFold(strings.TrimSpace(previous.Status), "disappeared") {
			record := DeltaRecord{
				Kind: DeltaAssetNotAssessed, AssetKey: key, NormalizedTarget: current.NormalizedTarget, AssetType: current.AssetType,
				PreviousStatus: "disappeared", CurrentStatus: "disappeared", PreviousHash: previous.ContentHash,
				CurrentHash: current.ContentHash, PreviousSeenAt: previous.LastSeen, CurrentSeenAt: current.LastSeen,
				PreviousRunID: previous.LastRunID, CurrentRunID: input.CurrentRunID, Reason: "reappearance_not_comparable",
			}
			if !current.LastSeen.After(previous.LastSeen) {
				record.Reason = "stale_observation"
			} else if input.Completed && input.TrustedPreviousRuns[previous.LastRunID] && strings.TrimSpace(input.CurrentRunID) != "" {
				record.Kind = DeltaServiceChanged
				record.CurrentStatus = "active"
				record.Reason = "asset_reappeared"
			}
			deltas = append(deltas, record)
			continue
		}
		if previous.ContentHash != current.ContentHash {
			scope, _ := firstAssetScope(previous, input.Targets)
			record := DeltaRecord{
				Kind: DeltaAssetNotAssessed, AssetKey: key, NormalizedTarget: current.NormalizedTarget, AssetType: current.AssetType,
				PreviousStatus: previous.Status, CurrentStatus: "active", PreviousHash: previous.ContentHash,
				CurrentHash: current.ContentHash, PreviousSeenAt: previous.LastSeen, CurrentSeenAt: current.LastSeen,
				PreviousRunID: previous.LastRunID, CurrentRunID: input.CurrentRunID,
				ScopeTarget: scope.target, Stage: scope.stage, Reason: "content_hash_not_comparable",
			}
			if !current.LastSeen.After(previous.LastSeen) {
				record.Reason = "stale_observation"
			} else if evidence, ok := contentComparableEvidence(previous, input); ok {
				record.Kind = DeltaServiceChanged
				record.ScopeTarget = evidence.target
				record.Stage = evidence.stage
				record.Reason = "content_hash_changed"
			}
			deltas = append(deltas, record)
		}
	}
	for key, previous := range previousAssets {
		if _, present := currentAssets[key]; present {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(previous.Status), "disappeared") {
			continue
		}
		if !assetInRunScope(previous, input.Targets) {
			continue
		}
		kind := DeltaAssetNotAssessed
		reason := "coverage_not_comparable"
		evidence, _ := firstAssetScope(previous, input.Targets)
		comparable, confirmed := comparableEvidence(previous, input)
		if confirmed {
			evidence = comparable
			kind = DeltaAssetDisappeared
			reason = "complete_comparable_observation"
		}
		currentStatus := "unknown"
		if confirmed {
			currentStatus = "disappeared"
		}
		deltas = append(deltas, DeltaRecord{
			Kind: kind, AssetKey: key, NormalizedTarget: safeTarget(previous.NormalizedTarget), ScopeTarget: evidence.target,
			AssetType: previous.AssetType, Stage: evidence.stage, PreviousStatus: previous.Status,
			CurrentStatus: currentStatus,
			PreviousHash:  previous.ContentHash, PreviousSeenAt: previous.LastSeen, CurrentSeenAt: evidence.observedAt,
			PreviousRunID: previous.LastRunID, CurrentRunID: evidence.runID, Reason: reason,
		})
	}
	stages := make(map[string]DeltaRecord)
	for _, coverage := range input.Coverage {
		action := strings.ToLower(strings.TrimSpace(coverage.Action))
		var kind DeltaKind
		switch action {
		case "executed":
			kind = DeltaStageExecuted
		case "reused":
			kind = DeltaStageReused
		default:
			continue
		}
		target := safeTarget(coverage.NormalizedTarget)
		record := DeltaRecord{
			Kind: kind, NormalizedTarget: target, ScopeTarget: target, Stage: strings.TrimSpace(coverage.Stage),
			Action: action, Outcome: strings.ToLower(strings.TrimSpace(coverage.Outcome)), Reason: strings.TrimSpace(coverage.Reason),
		}
		key := strings.Join([]string{string(kind), target, record.Stage}, "\x00")
		if previous, ok := stages[key]; ok && deltaSortKey(previous) <= deltaSortKey(record) {
			continue
		}
		stages[key] = record
	}
	for _, record := range stages {
		deltas = append(deltas, record)
	}
	sortDeltas(deltas)
	summary := summarizeDeltas(deltas)
	for _, target := range input.Targets {
		switch strings.ToLower(strings.TrimSpace(target.Action)) {
		case "full":
			summary.FullTargets++
		case "incremental":
			summary.IncrementalTargets++
		}
	}
	return deltas, summary
}

func prepareRunDifference(layout Layout, runDir string, completed bool) ([]DeltaRecord, DifferenceSummary, []string, error) {
	deltaPath := filepath.Join(runDir, "delta.tsv")
	if _, err := os.Stat(deltaPath); err == nil {
		records, readErr := readDelta(deltaPath)
		if readErr != nil {
			return nil, DifferenceSummary{}, nil, readErr
		}
		targets, warnings, targetErr := readRunTargets(filepath.Join(runDir, "targets.tsv"))
		if targetErr != nil {
			return nil, DifferenceSummary{}, warnings, targetErr
		}
		summary := summarizeDeltas(records)
		countTargetActions(targets, &summary)
		return records, summary, warnings, nil
	} else if !os.IsNotExist(err) {
		return nil, DifferenceSummary{}, nil, fmt.Errorf("inspect run delta: %w", err)
	}

	snapshot, err := loadSnapshotLocked(layout)
	if err != nil {
		return nil, DifferenceSummary{}, snapshot.Warnings, err
	}
	targets, targetWarnings, err := readRunTargets(filepath.Join(runDir, "targets.tsv"))
	warnings := append(append([]string(nil), snapshot.Warnings...), targetWarnings...)
	if err != nil {
		return nil, DifferenceSummary{}, warnings, err
	}
	findings, findingWarnings, err := readRunFindingRecords(filepath.Join(runDir, "findings.tsv"))
	warnings = append(warnings, findingWarnings...)
	if err != nil {
		return nil, DifferenceSummary{}, warnings, err
	}
	currentRunID := filepath.Base(runDir)
	coverage, coverageWarnings, err := readRunCoverageRecords(filepath.Join(runDir, "coverage.tsv"), currentRunID)
	warnings = append(warnings, coverageWarnings...)
	if err != nil {
		return nil, DifferenceSummary{}, warnings, err
	}
	evidenceComplete := completed && len(warnings) == 0
	trustedRuns, trustWarnings := loadTrustedPreviousRuns(layout, snapshot.Assets)
	warnings = append(warnings, trustWarnings...)
	records, summary := BuildDifference(DifferenceInput{
		Completed: evidenceComplete, CurrentRunID: currentRunID, TrustedPreviousRuns: trustedRuns,
		PreviousAssets: snapshot.Assets, PreviousCoverage: snapshot.Coverages,
		Targets: targets, Findings: findings, Coverage: coverage,
	})
	if err := writeDelta(deltaPath, records); err != nil {
		return nil, DifferenceSummary{}, warnings, err
	}
	return records, summary, warnings, nil
}

func loadTrustedPreviousRuns(layout Layout, assets []AssetRecord) (map[string]bool, []string) {
	trusted := make(map[string]bool)
	warnings := []string{}
	for _, asset := range assets {
		runID := strings.TrimSpace(asset.LastRunID)
		if runID == "" {
			continue
		}
		if _, checked := trusted[runID]; checked {
			continue
		}
		trusted[runID] = false
		summary, err := readRunSummary(filepath.Join(layout.RunsDir, runID, "summary.txt"))
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("asset baseline run %s is not trusted: %v", runID, err))
			continue
		}
		trusted[runID] = summary.RunID == runID && summary.Status == "completed" && summary.TerminalStatus == "completed" && summary.MergeStatus == "merged"
		if !trusted[runID] {
			warnings = append(warnings, fmt.Sprintf("asset baseline run %s is not a completed merged run", runID))
		}
	}
	return trusted, warnings
}

func readRunTargets(path string) ([]RunTargetRecord, []string, error) {
	rows, warnings, err := readTable(path, targetsSchema)
	if err != nil {
		return nil, warnings, err
	}
	records := make([]RunTargetRecord, 0, len(rows))
	for index, row := range rows {
		target := safeTarget(row[2])
		if target == "" || target != strings.TrimSpace(row[2]) {
			warnings = append(warnings, fmt.Sprintf("%s data row %d skipped: normalized_target is unsafe", filepath.Base(path), index+1))
			continue
		}
		action := strings.ToLower(strings.TrimSpace(row[4]))
		if action != "full" && action != "incremental" && action != "skipped" && action != "requested" {
			warnings = append(warnings, fmt.Sprintf("%s data row %d skipped: action is unsupported", filepath.Base(path), index+1))
			continue
		}
		records = append(records, RunTargetRecord{NormalizedTarget: target, Action: action, Reason: strings.TrimSpace(row[5])})
	}
	return records, warnings, nil
}

func readRunFindingRecords(path string) ([]RunFindingRecord, []string, error) {
	rows, warnings, err := readTable(path, findingsSchema)
	if err != nil {
		return nil, warnings, err
	}
	records := make([]RunFindingRecord, 0, len(rows))
	for index, row := range rows {
		target := safeTarget(row[3])
		if target == "" || target != strings.TrimSpace(row[3]) {
			warnings = append(warnings, fmt.Sprintf("%s data row %d skipped: target is empty or unsafe", filepath.Base(path), index+1))
			continue
		}
		observedAt, parseErr := time.Parse(time.RFC3339Nano, row[1])
		if parseErr != nil {
			warnings = append(warnings, fmt.Sprintf("%s data row %d skipped: invalid observed_at", filepath.Base(path), index+1))
			continue
		}
		component, marshalErr := json.Marshal(row[2:])
		if marshalErr != nil {
			return nil, warnings, fmt.Errorf("encode finding component: %w", marshalErr)
		}
		records = append(records, RunFindingRecord{Target: target, ObservedAt: observedAt.UTC(), Component: string(component)})
	}
	return records, warnings, nil
}

func readRunCoverageRecords(path, currentRunID string) ([]RunCoverageRecord, []string, error) {
	rows, warnings, err := readTable(path, runCoverageSchema)
	if err != nil {
		return nil, warnings, err
	}
	records := make([]RunCoverageRecord, 0, len(rows))
	for index, row := range rows {
		action := strings.ToLower(strings.TrimSpace(row[0]))
		if action != "executed" && action != "reused" {
			warnings = append(warnings, fmt.Sprintf("%s data row %d skipped: action is unsupported", filepath.Base(path), index+1))
			continue
		}
		if err := validateCoverageRow(row[2:]); err != nil {
			warnings = append(warnings, fmt.Sprintf("%s data row %d skipped: %v", filepath.Base(path), index+1, err))
			continue
		}
		if action == "executed" && row[12] != currentRunID {
			warnings = append(warnings, fmt.Sprintf("%s data row %d skipped: executed stage run_id does not match current run", filepath.Base(path), index+1))
			continue
		}
		observedAt, _ := time.Parse(time.RFC3339Nano, row[10])
		validUntil, _ := parseSummaryTime(row[11], false)
		records = append(records, RunCoverageRecord{Action: action, Reason: strings.TrimSpace(row[1]), CoverageRecord: CoverageRecord{
			WorkKey: row[2], NormalizedTarget: row[3], Stage: row[4], ScopeHash: row[5], ConfigHash: row[6],
			RuleVersion: row[7], Outcome: strings.ToLower(row[8]), ContentHash: row[9], ObservedAt: observedAt.UTC(),
			ValidUntil: validUntil.UTC(), LastRunID: row[12],
		}})
	}
	return records, warnings, nil
}

func writeDelta(path string, records []DeltaRecord) error {
	rows := make([][]string, 0, len(records))
	for index, record := range records {
		if err := validateDeltaRecord(record); err != nil {
			return fmt.Errorf("write run delta row %d: %w", index+1, err)
		}
		if index > 0 && deltaSortKey(records[index-1]) > deltaSortKey(record) {
			return fmt.Errorf("write run delta row %d: records are not in canonical order", index+1)
		}
		rows = append(rows, deltaRow(index+1, record))
	}
	if err := writeTableAtomic(path, deltaSchema, rows); err != nil {
		return fmt.Errorf("write run delta: %w", err)
	}
	return nil
}

func readDelta(path string) ([]DeltaRecord, error) {
	rows, warnings, err := readTable(path, deltaSchema)
	if err != nil {
		return nil, err
	}
	if len(warnings) != 0 {
		return nil, fmt.Errorf("run delta is damaged: %s", strings.Join(warnings, "; "))
	}
	records := make([]DeltaRecord, 0, len(rows))
	for index, row := range rows {
		sequence, parseErr := strconv.Atoi(row[0])
		if parseErr != nil || sequence != index+1 {
			return nil, fmt.Errorf("run delta row %d has invalid sequence", index+1)
		}
		previousSeenAt, previousSeenErr := parseSummaryTime(row[10], false)
		currentSeenAt, currentSeenErr := parseSummaryTime(row[11], false)
		if previousSeenErr != nil || currentSeenErr != nil {
			return nil, fmt.Errorf("run delta row %d has invalid observation time", index+1)
		}
		record := DeltaRecord{
			Kind: DeltaKind(row[1]), NormalizedTarget: row[2], ScopeTarget: row[3], AssetKey: row[4], AssetType: row[5],
			PreviousStatus: row[6], CurrentStatus: row[7], PreviousHash: row[8], CurrentHash: row[9],
			PreviousSeenAt: previousSeenAt, CurrentSeenAt: currentSeenAt, PreviousRunID: row[12], CurrentRunID: row[13],
			Stage: row[14], Action: row[15], Outcome: row[16], Reason: row[17],
		}
		if err := validateDeltaRecord(record); err != nil {
			return nil, fmt.Errorf("run delta row %d: %w", index+1, err)
		}
		records = append(records, record)
	}
	if !sort.SliceIsSorted(records, func(i, j int) bool { return deltaSortKey(records[i]) < deltaSortKey(records[j]) }) {
		return nil, fmt.Errorf("run delta rows are not in canonical order")
	}
	return records, nil
}

func deltaRow(sequence int, record DeltaRecord) []string {
	return []string{
		strconv.Itoa(sequence), string(record.Kind), record.NormalizedTarget, record.ScopeTarget, record.AssetKey, record.AssetType,
		record.PreviousStatus, record.CurrentStatus, record.PreviousHash, record.CurrentHash,
		formatOptionalTime(record.PreviousSeenAt), formatOptionalTime(record.CurrentSeenAt), record.PreviousRunID, record.CurrentRunID,
		record.Stage, record.Action, record.Outcome, record.Reason,
	}
}

func validateDeltaRecord(record DeltaRecord) error {
	for _, runID := range []string{record.PreviousRunID, record.CurrentRunID} {
		if runID != "" && !validLocalRunID(runID) {
			return fmt.Errorf("run identity is invalid")
		}
	}
	switch record.Kind {
	case DeltaAssetNew, DeltaServiceChanged, DeltaAssetDisappeared, DeltaAssetNotAssessed:
		target := safeTarget(record.NormalizedTarget)
		if target == "" || target != strings.TrimSpace(record.NormalizedTarget) || record.AssetKey != digestStrings(localNetworkZone, target) || record.AssetType != targetTypeName(utils.GetInputType(target)) {
			return fmt.Errorf("asset identity is invalid")
		}
		if strings.TrimSpace(record.Reason) == "" || !validOptionalDigest(record.PreviousHash) || !validOptionalDigest(record.CurrentHash) {
			return fmt.Errorf("asset evidence is invalid")
		}
		switch record.Kind {
		case DeltaAssetNew:
			if record.PreviousStatus != "" || record.CurrentStatus != "active" || record.PreviousHash != "" || record.CurrentHash == "" {
				return fmt.Errorf("new asset transition is invalid")
			}
		case DeltaServiceChanged:
			if (record.PreviousStatus != "active" && record.PreviousStatus != "disappeared") || record.CurrentStatus != "active" || record.PreviousHash == "" || record.CurrentHash == "" {
				return fmt.Errorf("changed service transition is invalid")
			}
			if record.PreviousStatus == "disappeared" && (!record.CurrentSeenAt.After(record.PreviousSeenAt) || strings.TrimSpace(record.PreviousRunID) == "" || strings.TrimSpace(record.CurrentRunID) == "") {
				return fmt.Errorf("reappeared asset evidence is invalid")
			}
		case DeltaAssetDisappeared:
			if record.PreviousStatus != "active" || record.CurrentStatus != "disappeared" || record.PreviousHash == "" || record.CurrentHash != "" || strings.TrimSpace(record.ScopeTarget) == "" || strings.TrimSpace(record.Stage) == "" || !record.CurrentSeenAt.After(record.PreviousSeenAt) || strings.TrimSpace(record.PreviousRunID) == "" || strings.TrimSpace(record.CurrentRunID) == "" {
				return fmt.Errorf("disappeared asset transition is invalid")
			}
		case DeltaAssetNotAssessed:
			validStatus := record.PreviousStatus == "active" && (record.CurrentStatus == "active" || record.CurrentStatus == "unknown")
			validStatus = validStatus || (record.PreviousStatus == "disappeared" && record.CurrentStatus == "disappeared")
			if !validStatus || record.PreviousHash == "" {
				return fmt.Errorf("unassessed asset transition is invalid")
			}
		}
	case DeltaStageExecuted, DeltaStageReused:
		target := safeTarget(record.NormalizedTarget)
		if target == "" || target != strings.TrimSpace(record.NormalizedTarget) || strings.TrimSpace(record.Stage) == "" {
			return fmt.Errorf("stage identity is invalid")
		}
		wantAction := "executed"
		if record.Kind == DeltaStageReused {
			wantAction = "reused"
		}
		if record.Action != wantAction {
			return fmt.Errorf("stage action is invalid")
		}
		if !successfulOutcome(record.Outcome) && record.Outcome != "failed" && record.Outcome != "skipped" {
			return fmt.Errorf("stage outcome is invalid")
		}
	default:
		return fmt.Errorf("kind %q is unsupported", record.Kind)
	}
	if scope := strings.TrimSpace(record.ScopeTarget); scope != "" && safeTarget(scope) != scope {
		return fmt.Errorf("scope target is unsafe")
	}
	return nil
}

func validOptionalDigest(value string) bool {
	if value == "" {
		return true
	}
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func countTargetActions(targets []RunTargetRecord, summary *DifferenceSummary) {
	for _, target := range targets {
		switch strings.ToLower(strings.TrimSpace(target.Action)) {
		case "full":
			summary.FullTargets++
		case "incremental":
			summary.IncrementalTargets++
		}
	}
}

func deriveRunAssets(findings []RunFindingRecord) map[string]AssetRecord {
	type aggregate struct {
		target     string
		firstSeen  time.Time
		lastSeen   time.Time
		components map[string]struct{}
	}
	aggregates := map[string]*aggregate{}
	for _, finding := range findings {
		target := safeTarget(finding.Target)
		if target == "" {
			continue
		}
		key := digestStrings(localNetworkZone, target)
		item := aggregates[key]
		if item == nil {
			item = &aggregate{target: target, firstSeen: finding.ObservedAt.UTC(), lastSeen: finding.ObservedAt.UTC(), components: map[string]struct{}{}}
			aggregates[key] = item
		}
		if !finding.ObservedAt.IsZero() && (item.firstSeen.IsZero() || finding.ObservedAt.Before(item.firstSeen)) {
			item.firstSeen = finding.ObservedAt.UTC()
		}
		if finding.ObservedAt.After(item.lastSeen) {
			item.lastSeen = finding.ObservedAt.UTC()
		}
		item.components[finding.Component] = struct{}{}
	}
	assets := make(map[string]AssetRecord, len(aggregates))
	for key, item := range aggregates {
		components := make([]string, 0, len(item.components))
		for component := range item.components {
			components = append(components, component)
		}
		sort.Strings(components)
		assets[key] = AssetRecord{
			AssetKey: key, NormalizedTarget: item.target, AssetType: targetTypeName(utils.GetInputType(item.target)),
			NetworkZone: localNetworkZone, FirstSeen: item.firstSeen, LastSeen: item.lastSeen, Status: "active",
			ContentHash: digestStrings(components...),
		}
	}
	return assets
}

func safeTarget(value string) string { return strings.TrimSpace(sanitizeTargetForHistory(value)) }

func sortDeltas(records []DeltaRecord) {
	sort.Slice(records, func(i, j int) bool {
		return deltaSortKey(records[i]) < deltaSortKey(records[j])
	})
}

func deltaSortKey(record DeltaRecord) string {
	return strings.Join([]string{
		string(record.Kind), record.NormalizedTarget, record.ScopeTarget, record.AssetKey, record.AssetType,
		record.Stage, record.Action, record.Outcome, record.Reason, record.PreviousStatus, record.CurrentStatus,
		record.PreviousHash, record.CurrentHash, formatOptionalTime(record.PreviousSeenAt), formatOptionalTime(record.CurrentSeenAt),
		record.PreviousRunID, record.CurrentRunID,
	}, "\x00")
}

func summarizeDeltas(records []DeltaRecord) (summary DifferenceSummary) {
	for _, record := range records {
		switch record.Kind {
		case DeltaAssetNew:
			summary.AssetNew++
		case DeltaServiceChanged:
			summary.ServiceChanged++
		case DeltaAssetDisappeared:
			summary.AssetDisappeared++
		case DeltaAssetNotAssessed:
			summary.AssetNotAssessed++
		case DeltaStageExecuted:
			summary.StageExecuted++
		case DeltaStageReused:
			summary.StageReused++
		}
	}
	return summary
}
