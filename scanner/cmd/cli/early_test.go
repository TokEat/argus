package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const cliProcessHelperMode = "ARGUS_CLI_PROCESS_HELPER"

func TestDispatchEarlyCLIVersionIsFastAndStandalone(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	handled, exitCode := dispatchEarlyCLI([]string{"--version"}, &stdout, &stderr)
	if !handled || exitCode != 0 {
		t.Fatalf("version handled=%v exit=%d", handled, exitCode)
	}
	if got := stdout.String(); got != "Argus CLI v2.0.1\n" {
		t.Fatalf("version output = %q", got)
	}
	if stderr.Len() != 0 {
		t.Fatalf("version stderr = %q", stderr.String())
	}
}

func TestDispatchEarlyCLIRejectsEveryServerOnlyProviderFlag(t *testing.T) {
	flags := []string{
		"-hunter", "--hunter=true",
		"-hps", "--hunter-page-size=50",
		"-hmpc", "--hunter-max-page-count=2",
		"-lpm", "--low-perception-mode",
		"-oip",
		"-fofa", "--fofa=true", "-fmc", "--fofa-max-count=20",
		"-quake", "--quake=true", "-qmc", "--quake-max-count=20",
		"-acf", "--api-config-file=config/api-config.yaml",
	}
	for _, flag := range flags {
		t.Run(strings.TrimLeft(flag, "-"), func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			handled, exitCode := dispatchEarlyCLI([]string{"-t", "query", flag}, &stdout, &stderr)
			if !handled || exitCode != providerMigrationExitCode {
				t.Fatalf("%s handled=%v exit=%d", flag, handled, exitCode)
			}
			if stdout.Len() != 0 {
				t.Fatalf("%s stdout = %q", flag, stdout.String())
			}
			message := stderr.String()
			for _, want := range []string{"Argus CLI", "Argus Server", "资产测绘", "不再读取 Provider 凭据"} {
				if !strings.Contains(message, want) {
					t.Fatalf("%s migration message %q does not contain %q", flag, message, want)
				}
			}
		})
	}
}

func TestDispatchEarlyCLIPreservesGeneralScanningAndArgumentTerminator(t *testing.T) {
	for _, args := range [][]string{
		{"-t", "https://example.com", "-Pn", "-nd", "-npoc"},
		{"help"},
		{"finger", "--help"},
		{"--", "-hunter"},
		{"version"},
		{"-version"},
	} {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		handled, exitCode := dispatchEarlyCLI(args, &stdout, &stderr)
		if handled || exitCode != 0 || stdout.Len() != 0 || stderr.Len() != 0 {
			t.Fatalf("args=%v handled=%v exit=%d stdout=%q stderr=%q", args, handled, exitCode, stdout.String(), stderr.String())
		}
	}
}

func TestCLIProcessEntrypointHandlesMetadataBeforeLocalInitialization(t *testing.T) {
	tests := []struct {
		name     string
		mode     string
		exitCode int
		contains []string
	}{
		{name: "version", mode: "version", exitCode: 0, contains: []string{"Argus CLI v2.0.1"}},
		{name: "provider migration", mode: "provider", exitCode: providerMigrationExitCode, contains: []string{"Argus Server", "资产测绘"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			argusHome := filepath.Join(t.TempDir(), "argus-data")
			command := exec.Command(os.Args[0], "-test.run=^TestCLIProcessHelper$")
			command.Env = append(os.Environ(), cliProcessHelperMode+"="+tt.mode, "ARGUS_HOME="+argusHome)
			output, err := command.CombinedOutput()
			if tt.exitCode == 0 {
				if err != nil {
					t.Fatalf("run helper: %v: %s", err, output)
				}
			} else {
				exitError, ok := err.(*exec.ExitError)
				if !ok || exitError.ExitCode() != tt.exitCode {
					t.Fatalf("helper error=%v, want exit %d: %s", err, tt.exitCode, output)
				}
			}
			for _, want := range tt.contains {
				if !bytes.Contains(output, []byte(want)) {
					t.Fatalf("helper output %q does not contain %q", output, want)
				}
			}
			if _, err := os.Stat(argusHome); !os.IsNotExist(err) {
				t.Fatalf("early command created ARGUS_HOME %q: %v", argusHome, err)
			}
		})
	}
}

func TestCLIProcessHelper(t *testing.T) {
	switch os.Getenv(cliProcessHelperMode) {
	case "":
		return
	case "version":
		os.Args = []string{"argus", "--version"}
	case "provider":
		os.Args = []string{"argus", "-t", "harmless", "--fofa=true"}
	default:
		t.Fatalf("unknown helper mode")
	}
	main()
	os.Exit(0)
}
