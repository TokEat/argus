package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/P0lar1ght/argus/scanner/ddout"
)

const cliMachineHelperMode = "ARGUS_CLI_MACHINE_HELPER"

func TestCLIProcessMachineAndNonTTYOutputContracts(t *testing.T) {
	home := filepath.Join(t.TempDir(), "argus-data")
	jsonRun := runMachineHelper(t, "json", "", home)
	if jsonRun.exitCode != exitSuccess || jsonRun.stderr != "" {
		t.Fatalf("json exit=%d stderr=%q", jsonRun.exitCode, jsonRun.stderr)
	}
	if strings.Contains(jsonRun.stdout, "Argus CLI v") || strings.ContainsRune(jsonRun.stdout, '\x1b') {
		t.Fatalf("json stdout contains presentation noise: %q", jsonRun.stdout)
	}
	lines := nonEmptyLines(jsonRun.stdout)
	if len(lines) != 2 {
		t.Fatalf("json records=%d, want finding+summary: %q", len(lines), jsonRun.stdout)
	}
	var finding, summary ddout.JSONRecord
	if err := json.Unmarshal([]byte(lines[0]), &finding); err != nil {
		t.Fatalf("decode finding: %v", err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &summary); err != nil {
		t.Fatalf("decode summary: %v", err)
	}
	if finding.RecordType != "finding" || finding.Finding == nil || !strings.HasPrefix(finding.Finding.URI, "http://127.0.0.1:") {
		t.Fatalf("unexpected finding: %#v", finding)
	}
	if summary.RecordType != "run_summary" || summary.Summary == nil || summary.Summary.Status != "completed" || summary.Summary.ExitCode != 0 || summary.Summary.Counts.Findings != 1 {
		t.Fatalf("unexpected summary: %#v", summary)
	}
	assertResultFileMatchesStdout(t, jsonRun.workDir, jsonRun.stdout)
	assertUnifiedHTMLReport(t, jsonRun.workDir, finding.Finding.URI)

	textRun := runMachineHelper(t, "text", "", home)
	if textRun.exitCode != exitSuccess || textRun.stderr != "" {
		t.Fatalf("text exit=%d stderr=%q", textRun.exitCode, textRun.stderr)
	}
	textTarget := firstWebOutputURI(textRun.stdout)
	if strings.Contains(textRun.stdout, "Argus CLI v") || strings.ContainsRune(textRun.stdout, '\x1b') || !strings.HasPrefix(textTarget, "http://127.0.0.1:") {
		t.Fatalf("redirected text output is noisy or missing finding: %q", textRun.stdout)
	}
	assertUnifiedHTMLReport(t, textRun.workDir, textTarget)
}

func TestCLIProcessUsageErrorsKeepStructuredStdoutEmpty(t *testing.T) {
	for _, mode := range []string{"invalid-output", "unknown-flag", "no-target"} {
		t.Run(mode, func(t *testing.T) {
			home := filepath.Join(t.TempDir(), "argus-data")
			result := runMachineHelper(t, mode, "", home)
			if result.exitCode != exitUsage {
				t.Fatalf("exit=%d stdout=%q stderr=%q", result.exitCode, result.stdout, result.stderr)
			}
			if result.stdout != "" || strings.ContainsRune(result.stderr, '\x1b') {
				t.Fatalf("usage channels are not clean: stdout=%q stderr=%q", result.stdout, result.stderr)
			}
			if mode == "invalid-output" {
				if _, err := os.Stat(home); !os.IsNotExist(err) {
					t.Fatalf("invalid output type created ARGUS_HOME: %v", err)
				}
			}
		})
	}
}

func TestTerminalOutcomeUsesStableCodes(t *testing.T) {
	for _, test := range []struct {
		scanErr, otherErr error
		code              int
		status            string
	}{
		{code: exitSuccess, status: "completed"},
		{scanErr: context.Canceled, code: exitCanceled, status: "canceled"},
		{scanErr: context.Canceled, otherErr: os.ErrPermission, code: exitFailure, status: "failed"},
		{scanErr: errors.Join(context.Canceled, os.ErrPermission), code: exitFailure, status: "failed"},
		{scanErr: context.DeadlineExceeded, code: exitFailure, status: "failed"},
		{otherErr: os.ErrPermission, code: exitFailure, status: "failed"},
	} {
		code, status := terminalOutcome(test.scanErr, test.otherErr)
		if code != test.code || status != test.status {
			t.Fatalf("terminalOutcome(%v,%v)=(%d,%q), want (%d,%q)", test.scanErr, test.otherErr, code, status, test.code, test.status)
		}
	}
}

type machineHelperResult struct {
	exitCode       int
	stdout, stderr string
	workDir        string
}

func runMachineHelper(t *testing.T, mode, target, home string) machineHelperResult {
	t.Helper()
	workDir := t.TempDir()
	command := exec.Command(os.Args[0], "-test.run=^TestCLIMachineProcessHelper$")
	command.Dir = workDir
	command.Env = append(os.Environ(), cliMachineHelperMode+"="+mode, "ARGUS_CLI_MACHINE_TARGET="+target, "ARGUS_HOME="+home)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	exitCode := 0
	if err != nil {
		exitError, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("run helper: %v", err)
		}
		exitCode = exitError.ExitCode()
	}
	return machineHelperResult{exitCode: exitCode, stdout: stdout.String(), stderr: stderr.String(), workDir: workDir}
}

func TestCLIMachineProcessHelper(t *testing.T) {
	mode := os.Getenv(cliMachineHelperMode)
	if mode == "" {
		return
	}
	target := os.Getenv("ARGUS_CLI_MACHINE_TARGET")
	if (mode == "json" || mode == "text") && strings.TrimSpace(target) == "" {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("<html><title>Argus fixture</title></html>"))
		}))
		defer server.Close()
		target = server.URL
	}
	base := []string{"argus", "-t", target, "-Pn", "-nd", "-npoc", "-force", "-wto", "5", "-wt", "1"}
	switch mode {
	case "json":
		os.Args = append(base, "-ot", "json")
	case "text":
		os.Args = base
	case "invalid-output":
		os.Args = []string{"argus", "-t", "http://127.0.0.1", "-ot", "yaml"}
	case "unknown-flag":
		os.Args = []string{"argus", "-t", "http://127.0.0.1", "-ot", "json", "--does-not-exist"}
	case "no-target":
		os.Args = []string{"argus"}
	default:
		t.Fatalf("unknown helper mode %q", mode)
	}
	main()
	os.Exit(0)
}

func nonEmptyLines(value string) []string {
	var lines []string
	for _, line := range strings.Split(value, "\n") {
		if strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func firstWebOutputURI(stdout string) string {
	for _, line := range nonEmptyLines(stdout) {
		if !strings.HasPrefix(line, "[Web] ") {
			continue
		}
		return firstOutputField(strings.TrimPrefix(line, "[Web] "))
	}
	return ""
}

func firstOutputField(value string) string {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func assertResultFileMatchesStdout(t *testing.T, workDir, stdout string) {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(workDir, "datas", "*", "result.txt"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("result files=%v err=%v", paths, err)
	}
	contents, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != stdout {
		t.Fatalf("result file differs from stdout:\nfile=%q\nstdout=%q", contents, stdout)
	}
}

func assertUnifiedHTMLReport(t *testing.T, workDir, target string) {
	t.Helper()
	reports, err := filepath.Glob(filepath.Join(workDir, "datas", "*", "*.html"))
	if err != nil || len(reports) != 1 {
		t.Fatalf("HTML reports=%v err=%v", reports, err)
	}
	rootReports, err := filepath.Glob(filepath.Join(workDir, "*.html"))
	if err != nil || len(rootReports) != 0 {
		t.Fatalf("unexpected split HTML reports=%v err=%v", rootReports, err)
	}
	contents, err := os.ReadFile(reports[0])
	if err != nil {
		t.Fatal(err)
	}
	html := string(contents)
	if !strings.Contains(html, "Argus") || !strings.Contains(html, target) || strings.Contains(strings.ToLower(html), "_assets.html") {
		t.Fatalf("unified report missing Argus/target or references a split report: %s", reports[0])
	}
}
