package localstate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const recoveryMarkerVersion = "argus-recovery/v1\n"

func recoverRuns(layout Layout, now time.Time) ([]string, error) {
	stateLock, locked, err := acquireFileLock(filepath.Join(layout.StateDir, ".merge.lock"), false)
	if err != nil {
		return nil, err
	}
	if !locked {
		return nil, fmt.Errorf("state recovery lock was not acquired")
	}
	defer releaseFileLock(stateLock)
	markerPath := filepath.Join(layout.StateDir, ".recovery-v1")
	markerContents, markerErr := os.ReadFile(markerPath)
	legacyScan := markerErr != nil || string(markerContents) != recoveryMarkerVersion
	entries, err := os.ReadDir(layout.RunsDir)
	if err != nil {
		return nil, fmt.Errorf("list CLI runs: %w", err)
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].Name() < entries[right].Name() })
	warnings := []string{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		runDir := filepath.Join(layout.RunsDir, entry.Name())
		lockPath := filepath.Join(runDir, ".active.lock")
		if !legacyScan {
			if _, statErr := os.Stat(lockPath); errors.Is(statErr, os.ErrNotExist) {
				continue
			} else if statErr != nil {
				warnings = append(warnings, fmt.Sprintf("run %s recovery marker check failed: %v", entry.Name(), statErr))
				continue
			}
		}
		runLock, acquired, lockErr := acquireFileLock(lockPath, true)
		if lockErr != nil {
			warnings = append(warnings, fmt.Sprintf("run %s recovery skipped: %v", entry.Name(), lockErr))
			continue
		}
		if !acquired {
			continue
		}
		runWarnings, retainMarker := recoverUnlockedRun(layout, runDir, entry.Name(), now.UTC())
		warnings = append(warnings, runWarnings...)
		if releaseErr := releaseFileLock(runLock); releaseErr != nil {
			warnings = append(warnings, fmt.Sprintf("run %s lock release failed: %v", entry.Name(), releaseErr))
		}
		if !retainMarker {
			if removeErr := os.Remove(lockPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				warnings = append(warnings, fmt.Sprintf("run %s stale lock cleanup failed: %v", entry.Name(), removeErr))
			}
		}
	}
	if legacyScan {
		if err := writeFileAtomic(markerPath, []byte(recoveryMarkerVersion), 0o600); err != nil {
			return warnings, fmt.Errorf("write CLI recovery marker: %w", err)
		}
	}
	return warnings, nil
}

func recoverUnlockedRun(layout Layout, runDir, directoryRunID string, now time.Time) ([]string, bool) {
	summaryPath := filepath.Join(runDir, "summary.txt")
	summary, err := readRunSummary(summaryPath)
	if err != nil {
		return []string{fmt.Sprintf("run %s recovery skipped: %v", directoryRunID, err)}, true
	}
	if summary.RunID != directoryRunID {
		return []string{fmt.Sprintf("run %s recovery skipped: summary run_id is %q", directoryRunID, summary.RunID)}, true
	}
	switch summary.Status {
	case "running":
		summary.Status = "interrupted"
		summary.TerminalStatus = "interrupted"
		summary.MergeStatus = "not_merged"
		summary.FinishedAt = now
		if strings.TrimSpace(summary.Error) == "" {
			summary.Error = "previous CLI process ended before run finalization"
		}
		if err := writeRunSummary(summaryPath, summary); err != nil {
			return []string{fmt.Sprintf("run %s interruption recovery failed: %v", directoryRunID, err)}, true
		}
		return []string{fmt.Sprintf("run %s marked interrupted; state was not merged", directoryRunID)}, false
	case "interrupted":
		return nil, false
	case "finalizing", "completed", "failed":
		if summary.MergeStatus == "merged" || summary.MergeStatus == "not_merged" {
			return nil, false
		}
	default:
		return []string{fmt.Sprintf("run %s recovery skipped: unsupported status %q", directoryRunID, summary.Status)}, true
	}
	terminalStatus := summary.TerminalStatus
	if terminalStatus != "completed" && terminalStatus != "failed" {
		terminalStatus = "completed"
		if strings.TrimSpace(summary.Error) != "" {
			terminalStatus = "failed"
		}
	}
	warnings, difference, mergeErr := mergeRunStateLocked(layout, runDir, terminalStatus == "completed")
	for index := range warnings {
		warnings[index] = fmt.Sprintf("run %s: %s", directoryRunID, warnings[index])
	}
	if mergeErr != nil {
		warnings = append(warnings, fmt.Sprintf("run %s state merge recovery failed: %v", directoryRunID, mergeErr))
		return warnings, true
	}
	summary.Difference = difference
	summary.Status = terminalStatus
	summary.TerminalStatus = terminalStatus
	summary.MergeStatus = "merged"
	summary.MergedAt = now
	if summary.FinishedAt.IsZero() {
		summary.FinishedAt = now
	}
	if err := writeRunSummary(summaryPath, summary); err != nil {
		warnings = append(warnings, fmt.Sprintf("run %s recovered state but summary update failed: %v", directoryRunID, err))
		return warnings, true
	}
	warnings = append(warnings, fmt.Sprintf("run %s pending state merge recovered", directoryRunID))
	return warnings, false
}
