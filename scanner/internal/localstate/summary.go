package localstate

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const RunSummarySchemaVersion = "argus-run-summary/v1"

type runSummary struct {
	RunID          string
	Status         string
	TerminalStatus string
	MergeStatus    string
	StartedAt      time.Time
	FinishedAt     time.Time
	MergedAt       time.Time
	TargetCount    int
	FindingCount   int
	CoverageCount  int
	Difference     DifferenceSummary
	Error          string
}

func writeRunSummary(path string, summary runSummary) error {
	values := []struct{ key, value string }{
		{"schema_version", RunSummarySchemaVersion},
		{"run_id", summary.RunID},
		{"status", summary.Status},
		{"terminal_status", summary.TerminalStatus},
		{"merge_status", summary.MergeStatus},
		{"started_at", formatOptionalTime(summary.StartedAt)},
		{"finished_at", formatOptionalTime(summary.FinishedAt)},
		{"merged_at", formatOptionalTime(summary.MergedAt)},
		{"target_count", strconv.Itoa(summary.TargetCount)},
		{"finding_count", strconv.Itoa(summary.FindingCount)},
		{"coverage_count", strconv.Itoa(summary.CoverageCount)},
		{"new_asset_count", strconv.Itoa(summary.Difference.AssetNew)},
		{"changed_service_count", strconv.Itoa(summary.Difference.ServiceChanged)},
		{"disappeared_asset_count", strconv.Itoa(summary.Difference.AssetDisappeared)},
		{"not_assessed_asset_count", strconv.Itoa(summary.Difference.AssetNotAssessed)},
		{"executed_stage_count", strconv.Itoa(summary.Difference.StageExecuted)},
		{"reused_stage_count", strconv.Itoa(summary.Difference.StageReused)},
		{"full_target_count", strconv.Itoa(summary.Difference.FullTargets)},
		{"incremental_target_count", strconv.Itoa(summary.Difference.IncrementalTargets)},
		{"error", escapeSummaryValue(summary.Error)},
	}
	var builder strings.Builder
	for _, value := range values {
		builder.WriteString(value.key)
		builder.WriteByte('=')
		builder.WriteString(value.value)
		builder.WriteByte('\n')
	}
	if err := writeFileAtomic(path, []byte(builder.String()), 0o600); err != nil {
		return fmt.Errorf("write run summary: %w", err)
	}
	return nil
}

func readRunSummary(path string) (runSummary, error) {
	file, err := os.Open(path)
	if err != nil {
		return runSummary{}, fmt.Errorf("open run summary: %w", err)
	}
	defer file.Close()
	values := make(map[string]string)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
			return runSummary{}, fmt.Errorf("summary line %d is damaged", lineNumber)
		}
		if _, duplicate := values[parts[0]]; duplicate {
			return runSummary{}, fmt.Errorf("summary line %d repeats key %q", lineNumber, parts[0])
		}
		values[parts[0]] = parts[1]
	}
	if err := scanner.Err(); err != nil {
		return runSummary{}, fmt.Errorf("read run summary: %w", err)
	}
	if values["schema_version"] != RunSummarySchemaVersion {
		return runSummary{}, fmt.Errorf("unsupported run summary schema %q", values["schema_version"])
	}
	summary := runSummary{
		RunID:          strings.TrimSpace(values["run_id"]),
		Status:         strings.TrimSpace(values["status"]),
		TerminalStatus: strings.TrimSpace(values["terminal_status"]),
		MergeStatus:    strings.TrimSpace(values["merge_status"]),
	}
	if summary.RunID == "" || summary.Status == "" {
		return runSummary{}, fmt.Errorf("run summary is missing run_id or status")
	}
	if summary.StartedAt, err = parseSummaryTime(values["started_at"], true); err != nil {
		return runSummary{}, fmt.Errorf("parse started_at: %w", err)
	}
	if summary.FinishedAt, err = parseSummaryTime(values["finished_at"], false); err != nil {
		return runSummary{}, fmt.Errorf("parse finished_at: %w", err)
	}
	if summary.MergedAt, err = parseSummaryTime(values["merged_at"], false); err != nil {
		return runSummary{}, fmt.Errorf("parse merged_at: %w", err)
	}
	if summary.TargetCount, err = parseSummaryCount(values["target_count"], "target_count"); err != nil {
		return runSummary{}, err
	}
	if summary.FindingCount, err = parseSummaryCount(values["finding_count"], "finding_count"); err != nil {
		return runSummary{}, err
	}
	if summary.CoverageCount, err = parseSummaryCount(values["coverage_count"], "coverage_count"); err != nil {
		return runSummary{}, err
	}
	counts := []struct {
		key string
		to  *int
	}{
		{"new_asset_count", &summary.Difference.AssetNew},
		{"changed_service_count", &summary.Difference.ServiceChanged},
		{"disappeared_asset_count", &summary.Difference.AssetDisappeared},
		{"not_assessed_asset_count", &summary.Difference.AssetNotAssessed},
		{"executed_stage_count", &summary.Difference.StageExecuted},
		{"reused_stage_count", &summary.Difference.StageReused},
		{"full_target_count", &summary.Difference.FullTargets},
		{"incremental_target_count", &summary.Difference.IncrementalTargets},
	}
	for _, count := range counts {
		if *count.to, err = parseSummaryCount(values[count.key], count.key); err != nil {
			return runSummary{}, err
		}
	}
	if summary.Error, err = decodeSummaryValue(values["error"]); err != nil {
		return runSummary{}, fmt.Errorf("decode summary error: %w", err)
	}
	return summary, nil
}

func parseSummaryTime(value string, required bool) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		if required {
			return time.Time{}, fmt.Errorf("value is empty")
		}
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, err
	}
	return parsed.UTC(), nil
}

func parseSummaryCount(value, key string) (int, error) {
	if strings.TrimSpace(value) == "" {
		return 0, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return 0, fmt.Errorf("summary %s is invalid", key)
	}
	return parsed, nil
}

func decodeSummaryValue(value string) (string, error) {
	fields, err := decodeTSVRow(value)
	if err != nil {
		return "", err
	}
	if len(fields) != 1 {
		return "", fmt.Errorf("summary value contains an unescaped separator")
	}
	return fields[0], nil
}

func escapeSummaryValue(value string) string {
	return escapeTSVField(value)
}

func formatOptionalTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}
