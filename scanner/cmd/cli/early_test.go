package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
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

func TestDispatchEarlyCLILeavesScanArgumentsAlone(t *testing.T) {
	for _, args := range [][]string{
		{"-a", "https://example.com", "-Pn", "-nd", "-nopoc", "-nogpoc"},
		{"-a", "10.0.0.1", "-t", "800"},
		{"-tr", "192.0.2.9"},
		{"-h"},
		{"version"},
	} {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		handled, exitCode := dispatchEarlyCLI(args, &stdout, &stderr)
		if handled || exitCode != 0 || stdout.Len() != 0 || stderr.Len() != 0 {
			t.Fatalf("args=%v handled=%v exit=%d stdout=%q stderr=%q", args, handled, exitCode, stdout.String(), stderr.String())
		}
	}
}

func TestCLIProcessEntrypointHandlesVersionBeforeLocalInitialization(t *testing.T) {
	argusHome := filepath.Join(t.TempDir(), "argus-data")
	command := exec.Command(os.Args[0], "-test.run=^TestCLIProcessHelper$")
	command.Env = append(os.Environ(), cliProcessHelperMode+"=version", "ARGUS_HOME="+argusHome)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("run helper: %v: %s", err, output)
	}
	if !bytes.Contains(output, []byte("Argus CLI v2.0.1")) {
		t.Fatalf("helper output %q", output)
	}
	if _, err := os.Stat(argusHome); !os.IsNotExist(err) {
		t.Fatalf("version command created ARGUS_HOME %q: %v", argusHome, err)
	}
}

func TestCLIProcessHelper(t *testing.T) {
	switch os.Getenv(cliProcessHelperMode) {
	case "":
		return
	case "version":
		os.Args = []string{"argus", "--version"}
	default:
		t.Fatalf("unknown helper mode")
	}
	main()
	os.Exit(0)
}
