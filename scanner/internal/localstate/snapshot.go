package localstate

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// AssetRecord is the durable, current CLI view of a locally observed asset.
// For active assets, LastRunID identifies the Run that supplied ContentHash.
// For tombstones, it identifies the Run that last confirmed disappearance.
// LastSeen may be newer than an active asset's content baseline when an
// incremental Run lacked comparable authoritative coverage.
type AssetRecord struct {
	AssetKey         string
	NormalizedTarget string
	AssetType        string
	NetworkZone      string
	FirstSeen        time.Time
	LastSeen         time.Time
	LastRunID        string
	Status           string
	ContentHash      string
}

// Snapshot is a consistent read of the two durable CLI state tables.
type Snapshot struct {
	Assets    []AssetRecord
	Coverages []CoverageRecord
	Warnings  []string
}

// LoadSnapshot reads assets and coverage while holding the same process-wide
// lock used by finalization, so a planner never observes a half-merged run.
func LoadSnapshot(home Home) (Snapshot, error) {
	layout, err := EnsureLayout(home)
	if err != nil {
		return Snapshot{}, err
	}
	lock, locked, err := acquireFileLock(filepath.Join(layout.StateDir, ".merge.lock"), false)
	if err != nil {
		return Snapshot{}, err
	}
	if !locked {
		return Snapshot{}, fmt.Errorf("state snapshot lock was not acquired")
	}
	defer releaseFileLock(lock)
	return loadSnapshotLocked(layout)
}

// loadSnapshotLocked reads both durable tables while the caller holds the
// state merge lock. Keeping this parser shared prevents diff finalization and
// the incremental planner from interpreting the same state differently.
func loadSnapshotLocked(layout Layout) (Snapshot, error) {
	assetRows, warnings, err := readTable(layout.AssetsPath, assetsSchema)
	if err != nil {
		return Snapshot{Warnings: warnings}, err
	}
	snapshot := Snapshot{Warnings: append([]string(nil), warnings...)}
	assetsByKey := make(map[string]AssetRecord, len(assetRows))
	for index, row := range assetRows {
		if err := validateAssetRow(row); err != nil {
			snapshot.Warnings = append(snapshot.Warnings, fmt.Sprintf("%s data row %d skipped: %v", filepath.Base(layout.AssetsPath), index+1, err))
			continue
		}
		firstSeen, _ := time.Parse(time.RFC3339Nano, row[4])
		lastSeen, _ := time.Parse(time.RFC3339Nano, row[5])
		record := AssetRecord{
			AssetKey: row[0], NormalizedTarget: row[1], AssetType: row[2], NetworkZone: row[3],
			FirstSeen: firstSeen.UTC(), LastSeen: lastSeen.UTC(), LastRunID: row[6], Status: row[7], ContentHash: row[8],
		}
		if previous, duplicate := assetsByKey[record.AssetKey]; duplicate {
			snapshot.Warnings = append(snapshot.Warnings, fmt.Sprintf("%s duplicate asset_key %q collapsed", filepath.Base(layout.AssetsPath), record.AssetKey))
			if !record.LastSeen.After(previous.LastSeen) {
				continue
			}
		}
		assetsByKey[record.AssetKey] = record
	}
	assetKeys := make([]string, 0, len(assetsByKey))
	for key := range assetsByKey {
		assetKeys = append(assetKeys, key)
	}
	sort.Strings(assetKeys)
	for _, key := range assetKeys {
		snapshot.Assets = append(snapshot.Assets, assetsByKey[key])
	}

	coverageRows, coverageWarnings, err := readTable(layout.CoveragePath, coverageSchema)
	snapshot.Warnings = append(snapshot.Warnings, coverageWarnings...)
	if err != nil {
		return snapshot, err
	}
	coverageByKey := make(map[string]CoverageRecord, len(coverageRows))
	for index, row := range coverageRows {
		if err := validateCoverageRow(row); err != nil {
			snapshot.Warnings = append(snapshot.Warnings, fmt.Sprintf("%s data row %d skipped: %v", filepath.Base(layout.CoveragePath), index+1, err))
			continue
		}
		observedAt, _ := time.Parse(time.RFC3339Nano, row[8])
		validUntil, _ := parseSummaryTime(row[9], false)
		record := CoverageRecord{
			WorkKey: row[0], NormalizedTarget: row[1], Stage: row[2], ScopeHash: row[3], ConfigHash: row[4],
			RuleVersion: row[5], Outcome: strings.ToLower(row[6]), ContentHash: row[7],
			ObservedAt: observedAt.UTC(), ValidUntil: validUntil.UTC(), LastRunID: row[10],
		}
		if previous, duplicate := coverageByKey[record.WorkKey]; duplicate {
			snapshot.Warnings = append(snapshot.Warnings, fmt.Sprintf("%s duplicate work_key %q collapsed", filepath.Base(layout.CoveragePath), record.WorkKey))
			if !record.ObservedAt.After(previous.ObservedAt) {
				continue
			}
		}
		coverageByKey[record.WorkKey] = record
	}
	coverageKeys := make([]string, 0, len(coverageByKey))
	for key := range coverageByKey {
		coverageKeys = append(coverageKeys, key)
	}
	sort.Strings(coverageKeys)
	for _, key := range coverageKeys {
		snapshot.Coverages = append(snapshot.Coverages, coverageByKey[key])
	}
	return snapshot, nil
}
