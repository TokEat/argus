package engine

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/TokEat/argus/yaksha/internal/protocol"
)

func TestNativeYaklangCapabilitiesRemainAvailable(t *testing.T) {
	tests := []struct {
		name   string
		script string
		want   any
	}{
		{name: "eval", script: `value = 1; eval("value = 2"); yaksha.result(value)`, want: 2},
		{name: "formatter", script: `formatted = yakfmt("value=1"); yaksha.result(formatted != "")`, want: true},
		{name: "dynamic scope", script: `value = "scope"; yaksha.result(getFromScope("value"))`, want: "scope"},
		{name: "scope inspection", script: `values, err = getScopeInspects(); yaksha.result(err == nil)`, want: true},
		{name: "async go", script: `go func() { yaksha.evidence("async", true) }(); waitAllAsyncCallFinish(); yaksha.result("done")`, want: "done"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := execScript(t, tc.script, 5_000)
			if resp.Status != protocol.StatusSucceeded || resp.Result != tc.want {
				t.Fatalf("response=%+v, want result=%v", resp, tc.want)
			}
			if tc.name == "async go" && resp.Evidence["async"] != true {
				t.Fatalf("response=%+v, want async evidence", resp)
			}
		})
	}
}

func TestIncludeRemainsAvailable(t *testing.T) {
	includePath := filepath.Join(t.TempDir(), "shared.yak")
	if err := os.WriteFile(includePath, []byte(`includedValue = "from-include"`), 0o600); err != nil {
		t.Fatal(err)
	}
	resp := execScript(t, `include `+strconv.Quote(includePath)+`; yaksha.result(includedValue)`, 5_000)
	if resp.Status != protocol.StatusSucceeded || resp.Result != "from-include" {
		t.Fatalf("response=%+v", resp)
	}
}

func TestUninjectedLibraryIsUnavailable(t *testing.T) {
	resp := execScript(t, `os.exec("id")`, 5_000)
	if resp.Status != protocol.StatusFailed {
		t.Fatalf("response=%+v", resp)
	}
}

func TestExecutionStateIsIsolatedPerRequest(t *testing.T) {
	first := execScript(t, `yaksha.result("first")`, 5_000)
	second := execScript(t, `yaksha.log("second")`, 5_000)
	if first.Result != "first" || second.Result != nil {
		t.Fatalf("first=%+v second=%+v", first, second)
	}
}

func TestExecuteWaitsForFireAndForgetYaklangTasks(t *testing.T) {
	response := execScript(t, `go func() { for i = 0; i < 10000; i++ {}; yaksha.evidence("async", true) }(); yaksha.result("done")`, 1_000)
	if response.Status != protocol.StatusSucceeded || response.Result != "done" || response.Evidence["async"] != true {
		t.Fatalf("response=%+v", response)
	}
}

func TestExecuteTimesOutUnfinishedYaklangTasks(t *testing.T) {
	response := execScript(t, `go func() { for i = 0; i < 100000000; i++ {} }(); yaksha.result("must-not-succeed")`, 20)
	if response.Status != protocol.StatusTimeout {
		t.Fatalf("status=%s error=%q", response.Status, response.Error)
	}
}

func TestLogsAndEvidenceAreBounded(t *testing.T) {
	resp := execScript(t, `
for i = 0; i < 400; i++ {
    yaksha.log("entry-" + yaksha.toString(i))
    yaksha.evidence("key-" + yaksha.toString(i), i)
}
yaksha.log("`+strings.Repeat("x", maxLogEntryBytes+100)+`")
yaksha.result("done")`, 5_000)
	if resp.Status != protocol.StatusSucceeded {
		t.Fatalf("response=%+v", resp)
	}
	if len(resp.Logs) != maxLogEntries {
		t.Fatalf("logs=%d, want %d", len(resp.Logs), maxLogEntries)
	}
	if len(resp.Evidence) != maxEvidenceEntries {
		t.Fatalf("evidence=%d, want %d", len(resp.Evidence), maxEvidenceEntries)
	}
}

func TestDirectRequestValidation(t *testing.T) {
	resp := Execute(protocol.Request{ID: "oversized", Script: strings.Repeat("x", protocol.MaxScriptBytes+1)})
	if resp.Status != protocol.StatusFailed || !strings.Contains(resp.Error, "request rejected") {
		t.Fatalf("response=%+v", resp)
	}
}
