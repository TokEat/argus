package portscan

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestScanSYNUsesRequestedPorts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake masscan helper uses a POSIX shell")
	}
	dir := t.TempDir()
	argsPath := filepath.Join(dir, "args")
	helper := filepath.Join(dir, "masscan")
	script := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$@\" > %q\nprintf '<nmaprun></nmaprun>'\n", argsPath)
	if err := os.WriteFile(helper, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	ScanSYN([]string{"192.0.2.1"}, "80,443", helper, 10, false, 0, nil)
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(args)), "\n")
	found := false
	for i := 0; i+1 < len(lines); i++ {
		if lines[i] == "-p" && lines[i+1] == "80,443" {
			found = true
		}
		if lines[i] == "-p" && lines[i+1] == "1-65535" {
			t.Fatal("SYN scan silently expanded configured ports to all ports")
		}
	}
	if !found {
		t.Fatalf("masscan args do not contain requested ports: %q", lines)
	}
}
