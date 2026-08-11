package ddout

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestJSONOutputIsVersionedNDJSONAndSummarizedOnce(t *testing.T) {
	resetForTest()
	t.Cleanup(resetForTest)
	var out bytes.Buffer
	writeMu.Lock()
	stdout = &out
	OutputType = "json"
	writeMu.Unlock()

	if err := BeginRun("run-1"); err != nil {
		t.Fatal(err)
	}
	if err := FormatOutputE(OutputMessage{Type: "Web", URI: "http://127.0.0.1:3000"}); err != nil {
		t.Fatal(err)
	}
	if err := EndRun(RunSummary{Status: "completed", ExitCode: 0, Counts: RunCounts{StagesReused: 2}}); err != nil {
		t.Fatal(err)
	}
	if err := EndRun(RunSummary{Status: "completed", ExitCode: 0}); err == nil {
		t.Fatal("expected duplicate EndRun to fail")
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d records, want 2: %q", len(lines), out.String())
	}
	var finding, summary JSONRecord
	if err := json.Unmarshal([]byte(lines[0]), &finding); err != nil {
		t.Fatalf("finding is not JSON: %v", err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &summary); err != nil {
		t.Fatalf("summary is not JSON: %v", err)
	}
	if finding.SchemaVersion != JSONSchemaVersion || finding.RecordType != "finding" || finding.Sequence != 1 || finding.RunID != "run-1" || finding.Finding == nil || finding.Finding.URI != "http://127.0.0.1:3000" {
		t.Fatalf("unexpected finding record: %#v", finding)
	}
	if finding.Finding.Web != nil || finding.Finding.GoPoc != nil {
		t.Fatalf("empty nested values leaked into finding: %#v", finding.Finding)
	}
	if summary.RecordType != "run_summary" || summary.Sequence != 2 || summary.Summary == nil || summary.Summary.Counts.Findings != 1 || summary.Summary.Counts.StagesReused != 2 {
		t.Fatalf("unexpected summary record: %#v", summary)
	}
}

func TestDecodeFindingLineSupportsVersionedAndLegacyFingerRecords(t *testing.T) {
	versioned, err := json.Marshal(JSONRecord{
		SchemaVersion: JSONSchemaVersion, RecordType: "finding", Sequence: 1,
		Finding: &JSONFinding{Type: "Finger", URI: "https://127.0.0.1", Finger: []string{"nginx"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	legacy := `{"type":"Finger","finger":["apache"],"uri":"http://127.0.0.1"}`
	for _, test := range []struct {
		line, uri, finger string
	}{{string(versioned), "https://127.0.0.1", "nginx"}, {legacy, "http://127.0.0.1", "apache"}} {
		message, ok, err := DecodeFindingLine(test.line)
		if err != nil || !ok || message.URI != test.uri || len(message.Finger) != 1 || message.Finger[0] != test.finger {
			t.Fatalf("DecodeFindingLine(%s) = %#v, %v, %v", test.line, message, ok, err)
		}
	}
	summary, err := json.Marshal(JSONRecord{SchemaVersion: JSONSchemaVersion, RecordType: "run_summary", Summary: &RunSummary{Status: "completed"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := DecodeFindingLine(string(summary)); err != nil || ok {
		t.Fatalf("summary decoded as finding: ok=%v err=%v", ok, err)
	}
}

func TestJSONOutputRequiresRunAndRejectsPostSummaryFinding(t *testing.T) {
	resetForTest()
	t.Cleanup(resetForTest)
	writeMu.Lock()
	OutputType = "json"
	stdout = &bytes.Buffer{}
	writeMu.Unlock()
	if err := FormatOutputE(OutputMessage{Type: "IPAlive"}); err == nil {
		t.Fatal("expected missing run error")
	}
	if err := BeginRun("failed-run"); err != nil {
		t.Fatal(err)
	}
	if err := EndRun(RunSummary{Status: "failed", ExitCode: 1}); err != nil {
		t.Fatal(err)
	}
	if err := FormatOutputE(OutputMessage{Type: "IPAlive"}); err == nil {
		t.Fatal("expected post-summary error")
	}
}

func TestJSONRunRejectsInvalidIdentityAndTerminalPair(t *testing.T) {
	resetForTest()
	t.Cleanup(resetForTest)
	OutputType = "json"
	stdout = &bytes.Buffer{}
	if err := BeginRun(""); err == nil {
		t.Fatal("empty run id was accepted")
	}
	if err := BeginRun("run-1"); err != nil {
		t.Fatal(err)
	}
	if err := EndRun(RunSummary{Status: "completed", ExitCode: 1}); err == nil {
		t.Fatal("mismatched terminal status and exit code were accepted")
	}
	if err := EndRun(RunSummary{Status: "completed", ExitCode: 0}); err != nil {
		t.Fatal(err)
	}
}

func TestJSONOutputWritesIdenticalRecordsToResultFile(t *testing.T) {
	resetForTest()
	t.Cleanup(resetForTest)
	var out bytes.Buffer
	path := t.TempDir() + "/results.ndjson"
	writeMu.Lock()
	stdout, OutputType, OutputFileName = &out, "json", path
	writeMu.Unlock()
	if err := BeginRun("file-run"); err != nil {
		t.Fatal(err)
	}
	if err := FormatOutputE(OutputMessage{Type: "IPAlive", IP: "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	if err := EndRun(RunSummary{Status: "completed", ExitCode: 0}); err != nil {
		t.Fatal(err)
	}
	file, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(file) != out.String() {
		t.Fatalf("stdout and result file differ:\nstdout=%q\nfile=%q", out.String(), string(file))
	}
}

func TestJSONTerminalRecordReportsResultFileFailure(t *testing.T) {
	resetForTest()
	t.Cleanup(resetForTest)
	var out bytes.Buffer
	OutputType, OutputFileName, stdout = "json", t.TempDir()+"/missing/results.ndjson", &out
	if err := BeginRun("file-failure"); err != nil {
		t.Fatal(err)
	}
	if err := EndRun(RunSummary{Status: "completed", ExitCode: 0}); err == nil {
		t.Fatal("expected result file failure")
	}
	var record JSONRecord
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &record); err != nil {
		t.Fatalf("terminal stdout is invalid: %v: %q", err, out.String())
	}
	if record.Summary == nil || record.Summary.Status != "failed" || record.Summary.ExitCode != 1 {
		t.Fatalf("terminal record did not reflect persistence failure: %#v", record)
	}
}

func TestJSONTerminalStdoutFailureRewritesFileSummaryAsFailed(t *testing.T) {
	resetForTest()
	t.Cleanup(resetForTest)
	path := t.TempDir() + "/result.ndjson"
	stdout, OutputType, OutputFileName = failingWriter{}, "json", path
	if err := BeginRun("stdout-failure"); err != nil {
		t.Fatal(err)
	}
	if err := EndRun(RunSummary{Status: "completed", ExitCode: 0}); err == nil {
		t.Fatal("expected terminal stdout failure")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(contents)), "\n")
	if len(lines) != 1 {
		t.Fatalf("terminal records=%d, want exactly one: %q", len(lines), contents)
	}
	var record JSONRecord
	if err := json.Unmarshal([]byte(lines[0]), &record); err != nil {
		t.Fatal(err)
	}
	if record.Summary == nil || record.Summary.Status != "failed" || record.Summary.ExitCode != 1 {
		t.Fatalf("persisted terminal summary contradicts output failure: %#v", record)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("stdout unavailable")
}

func TestRenderActiveFingerIncludesFallbackTag(t *testing.T) {
	got := Render(OutputMessage{
		Type:          "Active-Finger",
		URI:           "http://127.0.0.1:8081/aaa",
		Finger:        []string{"Shiro"},
		AdditionalMsg: "[dir-fallback]",
	})
	want := "[Active-Finger] http://127.0.0.1:8081/aaa [Shiro] [dir-fallback]"
	if got != want {
		t.Fatalf("unexpected render output: got %q want %q", got, want)
	}
}

func TestRenderGoPocUsesShowMsgAndSecurity(t *testing.T) {
	got := Render(OutputMessage{
		Type: "GoPoc",
		GoPoc: GoPocsResultType{
			Security: "CRITICAL",
			ShowMsg:  "http://127.0.0.1:8081 key=kPH+bIxk5D2deZiIxcaaaA==",
		},
	})
	want := "[CRITICAL] http://127.0.0.1:8081 key=kPH+bIxk5D2deZiIxcaaaA=="
	if got != want {
		t.Fatalf("unexpected render output: got %q want %q", got, want)
	}
}
