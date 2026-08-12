package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

var yakshaBin string

type wireResponse struct {
	ID      string `json:"id"`
	Action  string `json:"action"`
	Status  string `json:"status"`
	Context *struct {
		ExpID        string `json:"exp_id"`
		Revision     int    `json:"revision"`
		SourceSHA256 string `json:"source_sha256"`
	} `json:"context"`
	Result     any `json:"result"`
	Inspection *struct {
		Valid      bool `json:"valid"`
		Parameters []struct {
			Name     string `json:"name"`
			Required bool   `json:"required"`
		} `json:"parameters"`
		Diagnostics []struct {
			Code string `json:"code"`
		} `json:"diagnostics"`
	} `json:"inspection"`
	Validation *struct {
		Valid       bool `json:"valid"`
		Diagnostics []struct {
			Code  string `json:"code"`
			Field string `json:"field"`
		} `json:"diagnostics"`
	} `json:"validation"`
	Debug *struct {
		Events []struct {
			Kind string `json:"kind"`
		} `json:"events"`
	} `json:"debug"`
	Test *struct {
		Passed int `json:"passed"`
		Failed int `json:"failed"`
		Cases  []struct {
			ID     string `json:"id"`
			Passed bool   `json:"passed"`
		} `json:"cases"`
	} `json:"test"`
	Error string `json:"error"`
}

func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "yaksha-test-")
	if err != nil {
		panic(err)
	}
	yakshaBin = filepath.Join(tmp, "yaksha")
	build := exec.Command("go", "build", "-o", yakshaBin, "./cmd/yaksha")
	build.Dir = filepath.Clean("../..")
	build.Env = append(os.Environ(), "GOWORK=off")
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build Yaksha: %v\n%s", err, out)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(tmp)
	os.Exit(code)
}

func TestYakshaProtocolRoundtrip(t *testing.T) {
	cmd := exec.Command(yakshaBin)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	reader := bufio.NewReader(stdout)

	contractScript := `target = cli.String("target", cli.setRequired(true)); cli.check(); yaksha.result(target)`
	contractHash := fmt.Sprintf("%x", sha256.Sum256([]byte(contractScript)))

	// 1. the publishable source runs with bound official CLI parameters.
	runRequest, err := json.Marshal(map[string]any{
		"id":            "it1",
		"script":        contractScript,
		"params":        map[string]any{"target": "authorized.invalid"},
		"timeout_ms":    5000,
		"exp_id":        "exp-roundtrip",
		"revision":      3,
		"source_sha256": contractHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stdin.Write(append(runRequest, '\n')); err != nil {
		t.Fatal(err)
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	var resp wireResponse
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.ID != "it1" || resp.Action != "run" || resp.Status != "Succeeded" || resp.Result != "authorized.invalid" || resp.Validation == nil || !resp.Validation.Valid || resp.Context == nil || resp.Context.ExpID != "exp-roundtrip" || resp.Context.Revision != 3 || resp.Context.SourceSHA256 != contractHash {
		t.Fatalf("unexpected response: %s", line)
	}

	// 2. inspect extracts the UI contract without executing the source.
	inspectScript := `target = cli.String("target", cli.setRequired(true)); cli.check(); panic("must not execute")`
	request, err := json.Marshal(map[string]any{"id": "inspect-1", "action": "inspect", "script": inspectScript})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stdin.Write(append(request, '\n')); err != nil {
		t.Fatal(err)
	}
	line, err = reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	resp = wireResponse{}
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.ID != "inspect-1" || resp.Action != "inspect" || resp.Status != "Succeeded" || resp.Inspection == nil || !resp.Inspection.Valid {
		t.Fatalf("unexpected inspect response: %s", line)
	}
	if len(resp.Inspection.Parameters) != 1 || resp.Inspection.Parameters[0].Name != "target" || !resp.Inspection.Parameters[0].Required {
		t.Fatalf("unexpected inspect parameters: %s", line)
	}

	// 3. validate checks the same source and parameters without executing it.
	validateRequest, err := json.Marshal(map[string]any{
		"id":     "validate-1",
		"action": "validate",
		"script": contractScript,
		"params": map[string]any{"target": "authorized.invalid"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stdin.Write(append(validateRequest, '\n')); err != nil {
		t.Fatal(err)
	}
	line, err = reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	resp = wireResponse{}
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.ID != "validate-1" || resp.Action != "validate" || resp.Status != "Succeeded" || resp.Validation == nil || !resp.Validation.Valid {
		t.Fatalf("unexpected validate response: %s", line)
	}

	// 4. invalid parameters are diagnostics, and validate still does not execute.
	if _, err := stdin.Write([]byte(`{"id":"validate-2","action":"validate","script":"target = cli.String(\"target\", cli.setRequired(true)); cli.check(); panic(\"must not execute\")"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	line, err = reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	resp = wireResponse{}
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Status != "Succeeded" || resp.Validation == nil || resp.Validation.Valid || len(resp.Validation.Diagnostics) == 0 || resp.Validation.Diagnostics[0].Field != "target" {
		t.Fatalf("unexpected invalid validate response: %s", line)
	}

	// 5. debug executes the EXP with diagnostic output on the same connection.
	debugScript := "target = cli.String(\"target\", cli.setRequired(true))\ncli.check()\nvalue = target + \"-debug\"\nyaksha.result(value)"
	debugRequest, err := json.Marshal(map[string]any{
		"id":     "debug-1",
		"action": "debug",
		"script": debugScript,
		"params": map[string]any{"target": "authorized.invalid"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stdin.Write(append(debugRequest, '\n')); err != nil {
		t.Fatal(err)
	}
	line, err = reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	resp = wireResponse{}
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.ID != "debug-1" || resp.Action != "debug" || resp.Status != "Succeeded" || resp.Debug == nil || resp.Result != "authorized.invalid-debug" {
		t.Fatalf("unexpected debug response: %s", line)
	}

	// 6. test executes repeatable cases and reports assertion outcomes.
	testScript := `input = cli.Int("input", cli.setRequired(true)); cli.check(); yaksha.result(input * 2)`
	testRequest, err := json.Marshal(map[string]any{
		"id":     "test-1",
		"action": "test",
		"script": testScript,
		"test_cases": []any{
			map[string]any{"id": "pass", "params": map[string]any{"input": 2}, "expect": map[string]any{"result": 4}},
			map[string]any{"id": "fail", "params": map[string]any{"input": 3}, "expect": map[string]any{"result": 7}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stdin.Write(append(testRequest, '\n')); err != nil {
		t.Fatal(err)
	}
	line, err = reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	resp = wireResponse{}
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.ID != "test-1" || resp.Action != "test" || resp.Status != "Succeeded" || resp.Test == nil || resp.Test.Passed != 1 || resp.Test.Failed != 1 {
		t.Fatalf("unexpected test response: %s", line)
	}

	// 7. an invalid source is a successful inspection with diagnostics.
	if _, err := stdin.Write([]byte(`{"id":"inspect-2","action":"inspect","script":"cli.String(\"target\")"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	line, err = reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	resp = wireResponse{}
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Status != "Succeeded" || resp.Inspection == nil || resp.Inspection.Valid || len(resp.Inspection.Diagnostics) == 0 {
		t.Fatalf("unexpected invalid inspect response: %s", line)
	}

	// 8. malformed request line
	if _, err := stdin.Write([]byte("not-json\n")); err != nil {
		t.Fatal(err)
	}
	line, err = reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	var bad struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal([]byte(line), &bad); err != nil {
		t.Fatal(err)
	}
	if bad.Status != "InternalError" {
		t.Fatalf("want InternalError, got %s", bad.Status)
	}

	// 9. malformed input does not poison the next request.
	if _, err := stdin.Write([]byte(`{"id":"it2","script":"cli.check(); yaksha.result(\"after-error\")"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	line, err = reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	var after struct {
		ID     string `json:"id"`
		Status string `json:"status"`
		Result any    `json:"result"`
	}
	if err := json.Unmarshal([]byte(line), &after); err != nil {
		t.Fatal(err)
	}
	if after.ID != "it2" || after.Status != "Succeeded" || after.Result != "after-error" {
		t.Fatalf("unexpected response after malformed input: %s", line)
	}

	// 10. an oversized VM result degrades to a bounded error response.
	largeResultScript := `cli.check(); value = "x"; for i = 0; i < 22; i++ { value += value }; yaksha.result(value)`
	request, err = json.Marshal(map[string]any{"id": "it3", "script": largeResultScript, "timeout_ms": 5000})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stdin.Write(append(request, '\n')); err != nil {
		t.Fatal(err)
	}
	line, err = reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	var oversized struct {
		ID     string `json:"id"`
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal([]byte(line), &oversized); err != nil {
		t.Fatal(err)
	}
	if oversized.ID != "it3" || oversized.Status != "InternalError" || oversized.Error == "" {
		t.Fatalf("unexpected oversized response fallback: %s", line)
	}

	// 11. parser errors are returned through the process interface.
	if _, err := stdin.Write([]byte(`{"id":"it4","script":"if true {"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	line, err = reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	resp = wireResponse{}
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.ID != "it4" || resp.Status != "Failed" || resp.Error == "" {
		t.Fatalf("unexpected parser error response: %s", line)
	}

	// 12. runaway scripts time out without terminating the process.
	if _, err := stdin.Write([]byte(`{"id":"it5","script":"cli.check(); for 1 == 1 {}","timeout_ms":100}` + "\n")); err != nil {
		t.Fatal(err)
	}
	line, err = reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	resp = wireResponse{}
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.ID != "it5" || resp.Status != "Timeout" {
		t.Fatalf("unexpected timeout response: %s", line)
	}

	// 13. the process remains usable after a timed-out VM execution.
	if _, err := stdin.Write([]byte(`{"id":"it6","script":"cli.check(); yaksha.result(\"after-timeout\")"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	line, err = reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	resp = wireResponse{}
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.ID != "it6" || resp.Status != "Succeeded" || resp.Result != "after-timeout" {
		t.Fatalf("unexpected response after timeout: %s", line)
	}

	// 14. graceful exit on stdin EOF
	stdin.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("Yaksha exit: %v", err)
	}
}
