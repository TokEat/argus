package localstate

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/P0lar1ght/argus/scanner/internal/engine"
	"github.com/P0lar1ght/argus/scanner/structs"
	"github.com/P0lar1ght/argus/scanner/utils"
	"github.com/P0lar1ght/argus/shared/proto/go/scanplan"
)

type Layout struct {
	Root         string
	StateDir     string
	RunsDir      string
	AssetsPath   string
	CoveragePath string
}

type Run struct {
	ID           string
	Dir          string
	SummaryPath  string
	TargetsPath  string
	FindingsPath string
	CoveragePath string
	DeltaPath    string
	TimingPath   string

	mu            sync.Mutex
	startedAt     time.Time
	targetCount   int
	findingCount  int
	coverageCount int
	findingsFile  *os.File
	coverageFile  *os.File
	timingFile    *os.File
	activeLock    *os.File
	layout        Layout
	warnings      []string
	writeErr      error
	finished      bool
	mergeState    bool
}

type TargetDecision struct {
	Action string
	Reason string
}

func EnsureLayout(home Home) (Layout, error) {
	root := strings.TrimSpace(home.Root)
	if root == "" {
		return Layout{}, errors.New("Argus data root is empty")
	}
	absolute, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return Layout{}, fmt.Errorf("normalize Argus data root: %w", err)
	}
	layout := Layout{
		Root:     absolute,
		StateDir: filepath.Join(absolute, "state"),
		RunsDir:  filepath.Join(absolute, "runs"),
	}
	layout.AssetsPath = filepath.Join(layout.StateDir, "assets.tsv")
	layout.CoveragePath = filepath.Join(layout.StateDir, "coverage.tsv")
	for _, directory := range []string{layout.Root, layout.StateDir, layout.RunsDir} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return Layout{}, fmt.Errorf("create Argus data directory %q: %w", directory, err)
		}
		info, err := os.Stat(directory)
		if err != nil || !info.IsDir() {
			return Layout{}, fmt.Errorf("Argus data path %q is not a directory", directory)
		}
	}
	if err := ensureTable(layout.AssetsPath, assetsSchema); err != nil {
		return Layout{}, err
	}
	if err := ensureTable(layout.CoveragePath, coverageSchema); err != nil {
		return Layout{}, err
	}
	return layout, nil
}

func StartRun(home Home, targets []string) (*Run, error) {
	layout, err := EnsureLayout(home)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	warnings, err := recoverRuns(layout, now)
	if err != nil {
		return nil, err
	}
	run, err := startRun(layout, targets, now, rand.Reader)
	if err != nil {
		return nil, err
	}
	run.warnings = append(run.warnings, warnings...)
	return run, nil
}

func startRun(layout Layout, targets []string, startedAt time.Time, random io.Reader) (*Run, error) {
	runID, err := newRunID(startedAt, random)
	if err != nil {
		return nil, err
	}
	runDir := filepath.Join(layout.RunsDir, runID)
	if err := os.Mkdir(runDir, 0o700); err != nil {
		return nil, fmt.Errorf("create run directory %q: %w", runDir, err)
	}
	activeLock, locked, err := acquireFileLock(filepath.Join(runDir, ".active.lock"), false)
	if err != nil {
		return nil, err
	}
	if !locked {
		return nil, fmt.Errorf("acquire active lock for run %q", runID)
	}
	run := &Run{
		ID: runID, Dir: runDir, startedAt: startedAt.UTC(), targetCount: len(targets),
		SummaryPath:  filepath.Join(runDir, "summary.txt"),
		TargetsPath:  filepath.Join(runDir, "targets.tsv"),
		FindingsPath: filepath.Join(runDir, "findings.tsv"),
		CoveragePath: filepath.Join(runDir, "coverage.tsv"),
		DeltaPath:    filepath.Join(runDir, "delta.tsv"),
		TimingPath:   filepath.Join(runDir, "timing.tsv"),
		activeLock:   activeLock,
		layout:       layout,
		mergeState:   true,
	}
	if err := run.writeInitialFiles(targets); err != nil {
		run.releaseActiveLock(false)
		return nil, err
	}
	return run, nil
}

// StartRunInDirectory records the current CLI run beside result.txt and the
// HTML report under datas/<run>. It deliberately skips the old argus-data
// state merge; datas is the only user-visible history source for CLI scans.
func StartRunInDirectory(runDir string, targets []string) (*Run, error) {
	runDir = strings.TrimSpace(runDir)
	if runDir == "" {
		return nil, errors.New("run directory is empty")
	}
	absolute, err := filepath.Abs(filepath.Clean(runDir))
	if err != nil {
		return nil, fmt.Errorf("normalize run directory: %w", err)
	}
	if err := os.MkdirAll(absolute, 0o700); err != nil {
		return nil, fmt.Errorf("create run directory %q: %w", absolute, err)
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return nil, fmt.Errorf("inspect run directory %q: %w", absolute, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("run path %q is not a directory", absolute)
	}
	runID := sanitizeRunDirectoryID(filepath.Base(absolute))
	if runID == "" {
		return nil, fmt.Errorf("run directory %q does not produce a valid run id", absolute)
	}
	activeLock, locked, err := acquireFileLock(filepath.Join(absolute, ".active.lock"), false)
	if err != nil {
		return nil, err
	}
	if !locked {
		return nil, fmt.Errorf("acquire active lock for run %q", runID)
	}
	run := &Run{
		ID: runID, Dir: absolute, startedAt: time.Now().UTC(), targetCount: len(targets),
		SummaryPath:  filepath.Join(absolute, "summary.txt"),
		TargetsPath:  filepath.Join(absolute, "targets.tsv"),
		FindingsPath: filepath.Join(absolute, "findings.tsv"),
		CoveragePath: filepath.Join(absolute, "coverage.tsv"),
		DeltaPath:    filepath.Join(absolute, "delta.tsv"),
		TimingPath:   filepath.Join(absolute, "timing.tsv"),
		activeLock:   activeLock,
		mergeState:   false,
	}
	if err := run.writeInitialFiles(targets); err != nil {
		run.releaseActiveLock(false)
		return nil, err
	}
	return run, nil
}

func sanitizeRunDirectoryID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || value == "." || value == ".." {
		return ""
	}
	var builder strings.Builder
	for _, char := range value {
		switch {
		case char >= 'a' && char <= 'z', char >= 'A' && char <= 'Z', char >= '0' && char <= '9':
			builder.WriteRune(char)
		case char == '-', char == '_', char == '.':
			builder.WriteRune(char)
		default:
			builder.WriteByte('_')
		}
		if builder.Len() >= 255 {
			break
		}
	}
	return strings.Trim(builder.String(), ".")
}

func newRunID(startedAt time.Time, random io.Reader) (string, error) {
	bytes := make([]byte, 6)
	if _, err := io.ReadFull(random, bytes); err != nil {
		return "", fmt.Errorf("generate run id: %w", err)
	}
	return startedAt.UTC().Format("20060102T150405.000000000Z") + "-" + hex.EncodeToString(bytes), nil
}

func (run *Run) writeInitialFiles(targets []string) error {
	if err := writeRunSummary(run.SummaryPath, runSummary{
		RunID: run.ID, Status: "running", MergeStatus: "pending", StartedAt: run.startedAt, TargetCount: len(targets),
	}); err != nil {
		return err
	}
	targetFile, err := createRunTable(run.TargetsPath, targetsSchema)
	if err != nil {
		return err
	}
	for index, target := range targets {
		raw := sanitizeTargetForHistory(target)
		normalized := strings.TrimSpace(raw)
		if _, err := io.WriteString(targetFile, encodeTSVRow(
			strconv.Itoa(index+1), raw, normalized, targetTypeName(utils.GetInputType(normalized)), "requested", "initial_input",
		)); err != nil {
			_ = targetFile.Close()
			return fmt.Errorf("write run targets: %w", err)
		}
	}
	if err := targetFile.Close(); err != nil {
		return fmt.Errorf("close run targets: %w", err)
	}
	run.findingsFile, err = createRunTable(run.FindingsPath, findingsSchema)
	if err != nil {
		return err
	}
	run.coverageFile, err = createRunTable(run.CoveragePath, runCoverageSchema)
	if err != nil {
		_ = run.findingsFile.Close()
		return err
	}
	run.timingFile, err = createRunTable(run.TimingPath, timingSchema)
	if err != nil {
		_ = run.findingsFile.Close()
		_ = run.coverageFile.Close()
		return err
	}
	return nil
}

// ObserveTiming appends only validated, bounded shared timing events. The TSV
// deliberately excludes targets, messages, configuration and credentials.
func (run *Run) ObserveTiming(event scanplan.TimingEvent) {
	run.mu.Lock()
	defer run.mu.Unlock()
	if run.finished || run.writeErr != nil || run.timingFile == nil {
		return
	}
	if event.AttemptID != run.ID {
		run.writeErr = fmt.Errorf("timing attempt_id does not match run")
		return
	}
	if err := event.Validate(); err != nil {
		run.writeErr = fmt.Errorf("validate timing event: %w", err)
		return
	}
	if _, err := io.WriteString(run.timingFile, encodeTSVRow(event.EventID, event.AttemptID, event.AgentID, string(event.Kind), string(event.Stage), string(event.Outcome), event.StartedAt.UTC().Format(time.RFC3339Nano), event.FinishedAt.UTC().Format(time.RFC3339Nano), strconv.FormatInt(event.DurationNS, 10))); err != nil {
		run.writeErr = fmt.Errorf("write run timing: %w", err)
	}
}

func (run *Run) ObserveOutput(message engine.OutputMessage) {
	run.mu.Lock()
	defer run.mu.Unlock()
	if run.finished || run.writeErr != nil || run.findingsFile == nil {
		return
	}
	fingerprints, err := json.Marshal(message.Finger)
	if err != nil {
		run.writeErr = fmt.Errorf("encode finding fingerprints: %w", err)
		return
	}
	run.findingCount++
	fields := []string{
		strconv.Itoa(run.findingCount), time.Now().UTC().Format(time.RFC3339Nano), message.Type,
		findingTarget(message), message.IP, message.Port, message.Protocol, sanitizeTargetForHistory(message.URI), message.Domain,
		string(fingerprints), message.Web.Status, message.Web.Title,
		message.GoPoc.PocName, message.GoPoc.Security, message.GoPoc.Description,
		sanitizeNucleiJSON(message.Nuclei), message.AdditionalMsg, findingDisplay(message),
	}
	if _, err := io.WriteString(run.findingsFile, encodeTSVRow(fields...)); err != nil {
		run.writeErr = fmt.Errorf("write run finding: %w", err)
	}
}

func (run *Run) ObserveCoverage(action, reason string, record CoverageRecord) {
	run.mu.Lock()
	defer run.mu.Unlock()
	if run.finished || run.writeErr != nil || run.coverageFile == nil {
		return
	}
	action = strings.ToLower(strings.TrimSpace(action))
	if action != "executed" && action != "reused" {
		run.writeErr = fmt.Errorf("coverage action %q is unsupported", action)
		return
	}
	if strings.TrimSpace(record.LastRunID) == "" {
		record.LastRunID = run.ID
	}
	normalizedTarget := strings.TrimSpace(record.NormalizedTarget)
	if safeTarget := sanitizeTargetForHistory(normalizedTarget); safeTarget != normalizedTarget {
		run.writeErr = fmt.Errorf("coverage normalized_target contains URL credentials, query, or fragment")
		return
	}
	record.NormalizedTarget = normalizedTarget
	if err := record.validate(); err != nil {
		run.writeErr = err
		return
	}
	row := append([]string{action, strings.TrimSpace(reason)}, record.row()...)
	if _, err := io.WriteString(run.coverageFile, encodeTSVRow(row...)); err != nil {
		run.writeErr = fmt.Errorf("write run coverage: %w", err)
		return
	}
	run.coverageCount++
}

// SetTargetDecisions replaces only planner-owned action/reason columns. Raw
// inputs remain sanitized and otherwise unchanged.
func (run *Run) SetTargetDecisions(decisions map[string]TargetDecision) error {
	run.mu.Lock()
	defer run.mu.Unlock()
	if run.finished {
		return errors.New("run is already finished")
	}
	rows, warnings, err := readTable(run.TargetsPath, targetsSchema)
	run.warnings = append(run.warnings, warnings...)
	if err != nil {
		return err
	}
	for index := range rows {
		decision, ok := decisions[strings.TrimSpace(rows[index][2])]
		if !ok {
			continue
		}
		action := strings.ToLower(strings.TrimSpace(decision.Action))
		if action != "full" && action != "incremental" && action != "skipped" {
			return fmt.Errorf("target decision action %q is unsupported", action)
		}
		rows[index][4] = action
		rows[index][5] = strings.TrimSpace(decision.Reason)
	}
	return writeTableAtomic(run.TargetsPath, targetsSchema, rows)
}

func (run *Run) AddWarnings(warnings ...string) {
	run.mu.Lock()
	defer run.mu.Unlock()
	for _, warning := range warnings {
		if warning = strings.TrimSpace(warning); warning != "" {
			run.warnings = append(run.warnings, warning)
		}
	}
}

func (run *Run) Finish(scanErr error) error {
	run.mu.Lock()
	defer run.mu.Unlock()
	if run.finished {
		return run.writeErr
	}
	run.finished = true
	if run.findingsFile != nil {
		if err := run.findingsFile.Close(); err != nil && run.writeErr == nil {
			run.writeErr = fmt.Errorf("close run findings: %w", err)
		}
	}
	if run.coverageFile != nil {
		if err := run.coverageFile.Close(); err != nil && run.writeErr == nil {
			run.writeErr = fmt.Errorf("close run coverage: %w", err)
		}
	}
	if run.timingFile != nil {
		if err := run.timingFile.Sync(); err != nil && run.writeErr == nil {
			run.writeErr = fmt.Errorf("sync run timing: %w", err)
		}
		if err := run.timingFile.Close(); err != nil && run.writeErr == nil {
			run.writeErr = fmt.Errorf("close run timing: %w", err)
		}
	}
	terminalStatus := "completed"
	errorText := ""
	if scanErr != nil {
		terminalStatus = "failed"
		errorText = scanErr.Error()
	}
	if run.writeErr != nil {
		terminalStatus = "failed"
		if errorText == "" {
			errorText = run.writeErr.Error()
		} else {
			errorText += "; history: " + run.writeErr.Error()
		}
	}
	finishedAt := time.Now().UTC()
	baseSummary := runSummary{
		RunID: run.ID, TerminalStatus: terminalStatus, StartedAt: run.startedAt, FinishedAt: finishedAt,
		TargetCount: run.targetCount, FindingCount: run.findingCount, CoverageCount: run.coverageCount, Error: errorText,
	}
	if run.writeErr != nil {
		baseSummary.Status = "failed"
		baseSummary.MergeStatus = "not_merged"
		removeMarker := true
		if err := writeRunSummary(run.SummaryPath, baseSummary); err != nil {
			run.writeErr = errors.Join(run.writeErr, err)
			removeMarker = false
		}
		run.releaseActiveLock(removeMarker)
		return run.writeErr
	}
	if !run.mergeState {
		baseSummary.Status = terminalStatus
		baseSummary.MergeStatus = "merged"
		baseSummary.MergedAt = time.Now().UTC()
		if err := writeRunSummary(run.SummaryPath, baseSummary); err != nil {
			run.writeErr = err
		}
		run.releaseActiveLock(run.writeErr == nil)
		return run.writeErr
	}
	baseSummary.Status = "finalizing"
	baseSummary.MergeStatus = "pending"
	if err := writeRunSummary(run.SummaryPath, baseSummary); err != nil {
		run.writeErr = err
		run.releaseActiveLock(false)
		return run.writeErr
	}
	warnings, difference, err := mergeRunState(run.layout, run.Dir, terminalStatus == "completed")
	run.warnings = append(run.warnings, warnings...)
	baseSummary.Difference = difference
	if err != nil {
		run.writeErr = fmt.Errorf("merge CLI state: %w", err)
		baseSummary.MergeStatus = "failed"
		if summaryErr := writeRunSummary(run.SummaryPath, baseSummary); summaryErr != nil {
			run.writeErr = errors.Join(run.writeErr, summaryErr)
		}
		run.releaseActiveLock(false)
		return run.writeErr
	}
	baseSummary.Status = terminalStatus
	baseSummary.MergeStatus = "merged"
	baseSummary.MergedAt = time.Now().UTC()
	if err := writeRunSummary(run.SummaryPath, baseSummary); err != nil {
		run.writeErr = err
	}
	run.releaseActiveLock(run.writeErr == nil)
	return run.writeErr
}

// DifferenceSummary returns the immutable delta counts persisted by a
// successfully merged Run. It does not recompute against mutable state.
func (run *Run) DifferenceSummary() (DifferenceSummary, error) {
	run.mu.Lock()
	defer run.mu.Unlock()
	if !run.finished {
		return DifferenceSummary{}, errors.New("run is not finished")
	}
	summary, err := readRunSummary(run.SummaryPath)
	if err != nil {
		return DifferenceSummary{}, err
	}
	if summary.MergeStatus != "merged" {
		return DifferenceSummary{}, fmt.Errorf("run state is not merged: %s", summary.MergeStatus)
	}
	return summary.Difference, nil
}

func (run *Run) Warnings() []string {
	run.mu.Lock()
	defer run.mu.Unlock()
	return append([]string(nil), run.warnings...)
}

// Counts returns the bounded in-memory counters for the current Run. It is
// safe after Finish even when the durable summary could not be finalized.
func (run *Run) Counts() (targets, findings, coverage int) {
	run.mu.Lock()
	defer run.mu.Unlock()
	return run.targetCount, run.findingCount, run.coverageCount
}

func (run *Run) releaseActiveLock(removeMarker bool) {
	if run.activeLock == nil {
		return
	}
	lockPath := run.activeLock.Name()
	if err := releaseFileLock(run.activeLock); err != nil {
		run.warnings = append(run.warnings, fmt.Sprintf("release run lock: %v", err))
	}
	run.activeLock = nil
	if removeMarker {
		if err := os.Remove(lockPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			run.warnings = append(run.warnings, fmt.Sprintf("remove completed run lock: %v", err))
		}
	}
}

func targetTypeName(targetType int) string {
	switch targetType {
	case structs.TypeDomain:
		return "domain"
	case structs.TypeDomainPort:
		return "domain_port"
	case structs.TypeIPRange:
		return "ip_range"
	case structs.TypeCIDR:
		return "cidr"
	case structs.TypeIP:
		return "ip"
	case structs.TypeIPPort:
		return "ip_port"
	case structs.TypeURL:
		return "url"
	default:
		return "unknown"
	}
}

func findingTarget(message engine.OutputMessage) string {
	if value := strings.TrimSpace(message.URI); value != "" {
		return sanitizeTargetForHistory(value)
	}
	if value := strings.TrimSpace(message.GoPoc.Target); value != "" {
		return sanitizeTargetForHistory(value)
	}
	if value := strings.TrimSpace(message.Domain); value != "" {
		return value
	}
	if value := strings.TrimSpace(message.IP); value != "" {
		if port := strings.TrimSpace(message.Port); port != "" {
			return value + ":" + port
		}
		return value
	}
	return ""
}

func sanitizeTargetForHistory(value string) string {
	value = strings.TrimSpace(value)
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return value
	}
	if parsed.User != nil {
		parsed.User = url.User("redacted")
	}
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	return parsed.String()
}

// NormalizeTargetForState returns the credential-free target identity used by
// CLI TSV state. It is intentionally not a general scanner input normalizer.
func NormalizeTargetForState(value string) string {
	return sanitizeTargetForHistory(value)
}

func sanitizeNucleiJSON(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	var source map[string]any
	if err := json.Unmarshal([]byte(value), &source); err != nil {
		return ""
	}
	safe := make(map[string]any)
	for _, key := range []string{
		"template-id", "matcher-name", "extractor-name", "type", "port", "scheme",
		"ip", "timestamp", "matcher-status", "error",
	} {
		if item, ok := source[key]; ok {
			safe[key] = item
		}
	}
	for _, key := range []string{"host", "url", "matched-at"} {
		if item, ok := source[key].(string); ok {
			safe[key] = sanitizeTargetForHistory(item)
		}
	}
	if info, ok := source["info"].(map[string]any); ok {
		safeInfo := make(map[string]any)
		for _, key := range []string{"name", "severity", "tags", "description", "reference", "classification"} {
			if item, exists := info[key]; exists {
				safeInfo[key] = item
			}
		}
		if len(safeInfo) > 0 {
			safe["info"] = safeInfo
		}
	}
	encoded, err := json.Marshal(safe)
	if err != nil {
		return ""
	}
	return string(encoded)
}

func findingDisplay(message engine.OutputMessage) string {
	if strings.EqualFold(strings.TrimSpace(message.Type), "Nuclei") ||
		strings.EqualFold(strings.TrimSpace(message.Type), "GoPoc") {
		return ""
	}
	return message.Show
}
