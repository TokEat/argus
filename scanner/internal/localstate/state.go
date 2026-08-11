package localstate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/scanner/utils"
)

const localNetworkZone = "_local"

type CoverageRecord struct {
	WorkKey          string
	NormalizedTarget string
	Stage            string
	ScopeHash        string
	ConfigHash       string
	RuleVersion      string
	Outcome          string
	ContentHash      string
	ObservedAt       time.Time
	ValidUntil       time.Time
	LastRunID        string
}

func (record CoverageRecord) validate() error {
	for name, value := range map[string]string{
		"work_key": record.WorkKey, "normalized_target": record.NormalizedTarget,
		"stage": record.Stage, "scope_hash": record.ScopeHash, "config_hash": record.ConfigHash,
		"rule_version": record.RuleVersion, "outcome": record.Outcome, "last_run_id": record.LastRunID,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("coverage %s is empty", name)
		}
	}
	switch strings.ToLower(strings.TrimSpace(record.Outcome)) {
	case "success", "negative", "failed", "skipped":
	default:
		return fmt.Errorf("coverage outcome %q is unsupported", record.Outcome)
	}
	if record.ObservedAt.IsZero() {
		return fmt.Errorf("coverage observed_at is empty")
	}
	if !record.ValidUntil.IsZero() && record.ValidUntil.Before(record.ObservedAt) {
		return fmt.Errorf("coverage valid_until precedes observed_at")
	}
	if !validLocalRunID(record.LastRunID) {
		return fmt.Errorf("coverage last_run_id is invalid")
	}
	return nil
}

func (record CoverageRecord) row() []string {
	return []string{
		record.WorkKey, record.NormalizedTarget, record.Stage, record.ScopeHash, record.ConfigHash,
		record.RuleVersion, strings.ToLower(record.Outcome), record.ContentHash,
		formatOptionalTime(record.ObservedAt), formatOptionalTime(record.ValidUntil), record.LastRunID,
	}
}

func mergeRunState(layout Layout, runDir string, completed bool) ([]string, DifferenceSummary, error) {
	lockPath := filepath.Join(layout.StateDir, ".merge.lock")
	lock, locked, err := acquireFileLock(lockPath, false)
	if err != nil {
		return nil, DifferenceSummary{}, err
	}
	if !locked {
		return nil, DifferenceSummary{}, fmt.Errorf("state merge lock was not acquired")
	}
	defer releaseFileLock(lock)
	return mergeRunStateLocked(layout, runDir, completed)
}

func mergeRunStateLocked(layout Layout, runDir string, completed bool) ([]string, DifferenceSummary, error) {
	warnings := []string{}
	deltas, summary, differenceWarnings, err := prepareRunDifference(layout, runDir, completed)
	warnings = append(warnings, differenceWarnings...)
	if err != nil {
		return warnings, DifferenceSummary{}, err
	}
	assetWarnings, err := mergeRunAssets(layout.AssetsPath, filepath.Join(runDir, "findings.tsv"), deltas, completed)
	warnings = append(warnings, assetWarnings...)
	if err != nil {
		return warnings, summary, err
	}
	coverageWarnings, err := mergeRunCoverage(layout.CoveragePath, filepath.Join(runDir, "coverage.tsv"))
	warnings = append(warnings, coverageWarnings...)
	if err != nil {
		return warnings, summary, err
	}
	return warnings, summary, nil
}

func mergeRunAssets(statePath, findingsPath string, deltas []DeltaRecord, completed bool) ([]string, error) {
	stateRows, warnings, err := readTable(statePath, assetsSchema)
	if err != nil {
		return warnings, err
	}
	assets := make(map[string][]string, len(stateRows))
	for index, row := range stateRows {
		if err := validateAssetRow(row); err != nil {
			warnings = append(warnings, fmt.Sprintf("%s data row %d skipped: %v", filepath.Base(statePath), index+1, err))
			continue
		}
		if previous, exists := assets[row[0]]; exists {
			warnings = append(warnings, fmt.Sprintf("%s duplicate asset_key %q collapsed", filepath.Base(statePath), row[0]))
			if compareOptionalTimes(row[5], previous[5]) <= 0 {
				continue
			}
		}
		assets[row[0]] = row
	}
	for _, delta := range deltas {
		if delta.Kind != DeltaAssetDisappeared {
			continue
		}
		existing, ok := assets[delta.AssetKey]
		if !ok || strings.EqualFold(existing[7], "disappeared") {
			continue
		}
		existingLastSeen, parseErr := time.Parse(time.RFC3339Nano, existing[5])
		if parseErr != nil || existing[7] != delta.PreviousStatus || existing[8] != delta.PreviousHash ||
			existing[6] != delta.PreviousRunID || !existingLastSeen.Equal(delta.PreviousSeenAt) {
			warnings = append(warnings, fmt.Sprintf("%s stale disappearance for asset_key %q was not applied", filepath.Base(statePath), delta.AssetKey))
			continue
		}
		existing[5] = formatOptionalTime(delta.CurrentSeenAt)
		existing[6] = delta.CurrentRunID
		existing[7] = "disappeared"
		assets[delta.AssetKey] = existing
	}
	findings, findingWarnings, err := readRunFindingRecords(findingsPath)
	warnings = append(warnings, findingWarnings...)
	if err != nil {
		return warnings, err
	}
	aggregates := deriveRunAssets(findings)
	for assetKey, item := range aggregates {
		firstSeen := item.FirstSeen
		lastRunID := runIDFromDir(findingsPath)
		if existing, ok := assets[assetKey]; ok {
			existingFirst, _ := time.Parse(time.RFC3339Nano, existing[4])
			existingLast, _ := time.Parse(time.RFC3339Nano, existing[5])
			if existingFirst.Before(firstSeen) {
				firstSeen = existingFirst.UTC()
			}
			if !item.LastSeen.After(existingLast) {
				existing[4] = formatOptionalTime(firstSeen)
				assets[assetKey] = existing
				continue
			}
			if !canAdvanceAssetBaseline(item, deltas, completed) {
				existing[4] = formatOptionalTime(firstSeen)
				if existing[7] != "disappeared" {
					existing[5] = formatOptionalTime(item.LastSeen)
				}
				assets[assetKey] = existing
				continue
			}
		}
		assets[assetKey] = []string{
			assetKey, item.NormalizedTarget, targetTypeName(utils.GetInputType(item.NormalizedTarget)), localNetworkZone,
			formatOptionalTime(firstSeen), formatOptionalTime(item.LastSeen), lastRunID, "active", item.ContentHash,
		}
	}
	keys := make([]string, 0, len(assets))
	for key := range assets {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	merged := make([][]string, 0, len(keys))
	for _, key := range keys {
		merged = append(merged, assets[key])
	}
	if err := writeTableAtomic(statePath, assetsSchema, merged); err != nil {
		return warnings, err
	}
	return warnings, nil
}

func canAdvanceAssetBaseline(asset AssetRecord, deltas []DeltaRecord, completed bool) bool {
	if !completed {
		return false
	}
	for _, delta := range deltas {
		if delta.AssetKey == asset.AssetKey && delta.Kind == DeltaServiceChanged && delta.Reason == "asset_reappeared" {
			return true
		}
	}
	for _, delta := range deltas {
		if delta.Kind != DeltaStageExecuted || !successfulOutcome(delta.Outcome) {
			continue
		}
		stage, owns := authoritativeStage(delta.NormalizedTarget, asset.NormalizedTarget)
		if owns && stage == delta.Stage {
			return true
		}
	}
	return false
}

func mergeRunCoverage(statePath, runPath string) ([]string, error) {
	stateRows, warnings, err := readTable(statePath, coverageSchema)
	if err != nil {
		return warnings, err
	}
	coverages := make(map[string][]string, len(stateRows))
	for index, row := range stateRows {
		if err := validateCoverageRow(row); err != nil {
			warnings = append(warnings, fmt.Sprintf("%s data row %d skipped: %v", filepath.Base(statePath), index+1, err))
			continue
		}
		if previous, exists := coverages[row[0]]; exists {
			warnings = append(warnings, fmt.Sprintf("%s duplicate work_key %q collapsed", filepath.Base(statePath), row[0]))
			if compareOptionalTimes(row[8], previous[8]) <= 0 {
				continue
			}
		}
		coverages[row[0]] = row
	}
	runRows, runWarnings, err := readTable(runPath, runCoverageSchema)
	warnings = append(warnings, runWarnings...)
	if err != nil {
		return warnings, err
	}
	for index, runRow := range runRows {
		row := append([]string(nil), runRow[2:]...)
		if err := validateCoverageRow(row); err != nil {
			warnings = append(warnings, fmt.Sprintf("%s data row %d skipped: %v", filepath.Base(runPath), index+1, err))
			continue
		}
		if previous, exists := coverages[row[0]]; exists && compareOptionalTimes(row[8], previous[8]) <= 0 {
			continue
		}
		coverages[row[0]] = row
	}
	keys := make([]string, 0, len(coverages))
	for key := range coverages {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	merged := make([][]string, 0, len(keys))
	for _, key := range keys {
		merged = append(merged, coverages[key])
	}
	if err := writeTableAtomic(statePath, coverageSchema, merged); err != nil {
		return warnings, err
	}
	return warnings, nil
}

func validateAssetRow(row []string) error {
	if len(row) != len(assetsSchema.Columns) {
		return fmt.Errorf("invalid column count")
	}
	for _, index := range []int{0, 1, 2, 3, 4, 5, 6, 7, 8} {
		if strings.TrimSpace(row[index]) == "" {
			return fmt.Errorf("%s is empty", assetsSchema.Columns[index])
		}
	}
	if _, err := time.Parse(time.RFC3339Nano, row[4]); err != nil {
		return fmt.Errorf("first_seen is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, row[5]); err != nil {
		return fmt.Errorf("last_seen is invalid")
	}
	if row[3] != localNetworkZone {
		return fmt.Errorf("network_zone %q is unsupported", row[3])
	}
	if !validLocalRunID(row[6]) {
		return fmt.Errorf("last_run_id is invalid")
	}
	if row[7] != "active" && row[7] != "disappeared" {
		return fmt.Errorf("status %q is unsupported", row[7])
	}
	if row[0] != digestStrings(row[3], row[1]) {
		return fmt.Errorf("asset_key does not match target and network_zone")
	}
	return nil
}

func validLocalRunID(value string) bool {
	trimmed := strings.TrimSpace(value)
	return value == trimmed && trimmed != "" && trimmed != "." && trimmed != ".." && len(trimmed) <= 255 && !strings.ContainsAny(trimmed, `/\:`)
}

func validateCoverageRow(row []string) error {
	if len(row) != len(coverageSchema.Columns) {
		return fmt.Errorf("invalid column count")
	}
	record := CoverageRecord{
		WorkKey: row[0], NormalizedTarget: row[1], Stage: row[2], ScopeHash: row[3], ConfigHash: row[4],
		RuleVersion: row[5], Outcome: row[6], ContentHash: row[7], LastRunID: row[10],
	}
	for _, index := range []int{0, 1, 2, 3, 4, 5, 6, 8, 10} {
		if strings.TrimSpace(row[index]) == "" {
			return fmt.Errorf("%s is empty", coverageSchema.Columns[index])
		}
	}
	var err error
	if record.ObservedAt, err = parseSummaryTime(row[8], true); err != nil {
		return fmt.Errorf("observed_at is invalid")
	}
	if record.ValidUntil, err = parseSummaryTime(row[9], false); err != nil {
		return fmt.Errorf("valid_until is invalid")
	}
	return record.validate()
}

func compareOptionalTimes(left, right string) int {
	leftTime, leftErr := time.Parse(time.RFC3339Nano, left)
	rightTime, rightErr := time.Parse(time.RFC3339Nano, right)
	if leftErr != nil && rightErr != nil {
		return strings.Compare(left, right)
	}
	if leftErr != nil {
		return -1
	}
	if rightErr != nil {
		return 1
	}
	if leftTime.Before(rightTime) {
		return -1
	}
	if leftTime.After(rightTime) {
		return 1
	}
	return 0
}

func digestStrings(values ...string) string {
	digest := sha256.New()
	for _, value := range values {
		_, _ = digest.Write([]byte(fmt.Sprintf("%d:", len(value))))
		_, _ = digest.Write([]byte(value))
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func runIDFromDir(path string) string {
	return filepath.Base(filepath.Dir(path))
}
