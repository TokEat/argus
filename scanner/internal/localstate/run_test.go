package localstate

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/P0lar1ght/argus/scanner/internal/engine"
)

func TestRunWritesLayeredHistory(t *testing.T) {
	layout, err := EnsureLayout(Home{Root: filepath.Join(t.TempDir(), "argus-data")})
	if err != nil {
		t.Fatalf("ensure layout: %v", err)
	}
	startedAt := time.Date(2026, 8, 9, 12, 34, 56, 123, time.UTC)
	run, err := startRun(layout, []string{" 10.0.0.1 ", "https://user:secret@example.test/a?token=secret#fragment"}, startedAt, bytes.NewReader([]byte{1, 2, 3, 4, 5, 6}))
	if err != nil {
		t.Fatalf("start run: %v", err)
	}
	if want := "20260809T123456.000000123Z-010203040506"; run.ID != want {
		t.Fatalf("run id = %q, want %q", run.ID, want)
	}

	const findings = 32
	var wait sync.WaitGroup
	for index := 0; index < findings; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			run.ObserveOutput(engine.OutputMessage{
				Type: "Web", URI: "https://user:secret@example.test/" + strconv.Itoa(index),
				Finger: []string{"nginx", "line\nbreak"}, Show: "title\tvalue",
			})
		}(index)
	}
	wait.Wait()
	if err := run.Finish(nil); err != nil {
		t.Fatalf("finish run: %v", err)
	}
	if err := run.Finish(nil); err != nil {
		t.Fatalf("idempotent finish: %v", err)
	}

	assertSummaryValue(t, run.SummaryPath, "status", "completed")
	assertSummaryValue(t, run.SummaryPath, "target_count", "2")
	assertSummaryValue(t, run.SummaryPath, "finding_count", strconv.Itoa(findings))
	targetRows := assertTableRows(t, run.TargetsPath, targetsSchema, 2)
	if got := targetRows[1][1]; got != "https://redacted@example.test/a" {
		t.Fatalf("persisted input target = %q", got)
	}
	rows := assertTableRows(t, run.FindingsPath, findingsSchema, findings)
	for _, row := range rows {
		if strings.Contains(row[3], "secret") || !strings.Contains(row[3], "redacted@example.test") {
			t.Fatalf("persisted finding target was not redacted: %q", row[3])
		}
	}
	assertTableRows(t, run.CoveragePath, runCoverageSchema, 0)
}

func TestSetTargetDecisionsPreservesSanitizedInputs(t *testing.T) {
	layout, err := EnsureLayout(Home{Root: filepath.Join(t.TempDir(), "argus-data")})
	if err != nil {
		t.Fatal(err)
	}
	run, err := startRun(layout, []string{"https://user:secret@example.test/a?token=secret"}, time.Unix(1, 0), bytes.NewReader(make([]byte, 6)))
	if err != nil {
		t.Fatal(err)
	}
	if err := run.SetTargetDecisions(map[string]TargetDecision{
		"https://redacted@example.test/a": {Action: "incremental", Reason: "known_services_revalidated"},
	}); err != nil {
		t.Fatal(err)
	}
	rows := assertTableRows(t, run.TargetsPath, targetsSchema, 1)
	if rows[0][1] != "https://redacted@example.test/a" || rows[0][4] != "incremental" || rows[0][5] != "known_services_revalidated" {
		t.Fatalf("target row = %#v", rows[0])
	}
	if err := run.Finish(nil); err != nil {
		t.Fatal(err)
	}
}

func TestObserveOutputStoresOnlyNucleiEvidenceSummary(t *testing.T) {
	layout, err := EnsureLayout(Home{Root: filepath.Join(t.TempDir(), "argus-data")})
	if err != nil {
		t.Fatalf("ensure layout: %v", err)
	}
	run, err := startRun(layout, []string{"https://example.test"}, time.Unix(1, 0), bytes.NewReader(make([]byte, 6)))
	if err != nil {
		t.Fatalf("start run: %v", err)
	}
	run.ObserveOutput(engine.OutputMessage{
		Type:   "Nuclei",
		Nuclei: `{"template-id":"safe-check","type":"http","host":"https://user:password@example.test/a?token=secret","matched-at":"https://example.test/a?token=secret","request":"Authorization: Bearer secret","response":"secret body","packet":{"1":{"request":"secret","response":"secret"}},"curl-command":"curl -H secret","extracted-results":["secret"],"info":{"name":"Safe check","severity":"low","metadata":{"secret":"value"}}}`,
		Show:   "[safe-check] [low] https://example.test/a?token=secret",
	})
	if err := run.Finish(nil); err != nil {
		t.Fatalf("finish run: %v", err)
	}
	rows := assertTableRows(t, run.FindingsPath, findingsSchema, 1)
	nuclei := rows[0][15]
	for _, secret := range []string{"password", "token=secret", "Authorization", "secret body", "curl -H", "extracted-results", "metadata"} {
		if strings.Contains(nuclei, secret) {
			t.Fatalf("nuclei summary contains %q: %s", secret, nuclei)
		}
	}
	if !strings.Contains(nuclei, `"template-id":"safe-check"`) || rows[0][17] != "" {
		t.Fatalf("nuclei summary/display = %q / %q", nuclei, rows[0][17])
	}
}

func TestObserveOutputDoesNotPersistGoPocCredentialDetail(t *testing.T) {
	layout, err := EnsureLayout(Home{Root: filepath.Join(t.TempDir(), "argus-data")})
	if err != nil {
		t.Fatalf("ensure layout: %v", err)
	}
	run, err := startRun(layout, []string{"192.0.2.1"}, time.Unix(1, 0), bytes.NewReader(make([]byte, 6)))
	if err != nil {
		t.Fatalf("start run: %v", err)
	}
	run.ObserveOutput(engine.OutputMessage{
		Type: "GoPoc",
		GoPoc: engine.GoPocsResultType{
			PocName: "SSH-Login", Security: "CRITICAL", Description: "weak credential",
			Target: "192.0.2.1:22", InfoLeft: "Password: secret", InfoRight: "shell output", ShowMsg: "ssh://user:secret@192.0.2.1",
		},
		Show: "ssh://user:secret@192.0.2.1",
	})
	if err := run.Finish(nil); err != nil {
		t.Fatalf("finish run: %v", err)
	}
	contents, err := os.ReadFile(run.FindingsPath)
	if err != nil {
		t.Fatalf("read findings: %v", err)
	}
	for _, secret := range []string{"Password: secret", "shell output", "user:secret"} {
		if strings.Contains(string(contents), secret) {
			t.Fatalf("GoPoc history contains credential detail %q", secret)
		}
	}
	rows := assertTableRows(t, run.FindingsPath, findingsSchema, 1)
	if rows[0][12] != "SSH-Login" || rows[0][13] != "CRITICAL" || rows[0][17] != "" {
		t.Fatalf("GoPoc summary = %#v", rows[0])
	}
}

func TestRunRecordsFailureWithoutPhysicalNewlines(t *testing.T) {
	layout, err := EnsureLayout(Home{Root: filepath.Join(t.TempDir(), "argus-data")})
	if err != nil {
		t.Fatalf("ensure layout: %v", err)
	}
	run, err := startRun(layout, []string{"example.test"}, time.Unix(1, 0), bytes.NewReader(make([]byte, 6)))
	if err != nil {
		t.Fatalf("start run: %v", err)
	}
	if err := run.Finish(errors.New("scan\tfailed\nlocally")); err != nil {
		t.Fatalf("finish failed run: %v", err)
	}
	assertSummaryValue(t, run.SummaryPath, "status", "failed")
	assertSummaryValue(t, run.SummaryPath, "error", `scan\tfailed\nlocally`)
	contents, err := os.ReadFile(run.SummaryPath)
	if err != nil {
		t.Fatalf("read summary: %v", err)
	}
	if lines := strings.Split(strings.TrimSuffix(string(contents), "\n"), "\n"); len(lines) != 20 {
		t.Fatalf("summary has %d physical lines, want 20: %q", len(lines), contents)
	}
}

func assertSummaryValue(t *testing.T, path, key, want string) {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read summary: %v", err)
	}
	for _, line := range strings.Split(string(contents), "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 && parts[0] == key {
			if parts[1] != want {
				t.Fatalf("summary %s = %q, want %q", key, parts[1], want)
			}
			return
		}
	}
	t.Fatalf("summary key %q not found", key)
}

func assertTableRows(t *testing.T, path string, schema tableSchema, wantRows int) [][]string {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read table %s: %v", path, err)
	}
	lines := strings.Split(strings.TrimSuffix(string(contents), "\n"), "\n")
	if len(lines) != wantRows+2 {
		t.Fatalf("%s has %d data rows, want %d", path, len(lines)-2, wantRows)
	}
	if got := strings.Join(lines[:2], "\n") + "\n"; got != tableHeader(schema) {
		t.Fatalf("%s has unexpected header %q", path, got)
	}
	rows := make([][]string, 0, wantRows)
	for _, line := range lines[2:] {
		row, err := decodeTSVRow(line)
		if err != nil {
			t.Fatalf("decode row in %s: %v", path, err)
		}
		if len(row) != len(schema.Columns) {
			t.Fatalf("row in %s has %d columns, want %d", path, len(row), len(schema.Columns))
		}
		rows = append(rows, row)
	}
	return rows
}
