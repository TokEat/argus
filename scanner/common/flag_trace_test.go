package common

import (
	"testing"

	"github.com/TokEat/argus/scanner/structs"
)

func TestCLITraceRequested(t *testing.T) {
	for _, args := range [][]string{
		{"-tr", "192.0.2.9"},
		{"--trace", "res.txt"},
		{"-tr=10.0.0.1"},
		{"--trace=hosts.txt"},
		{"-ot", "json", "-tr", "192.0.2.9"},
	} {
		if !CLITraceRequested(args) {
			t.Fatalf("expected trace command: %v", args)
		}
	}
	for _, args := range [][]string{
		{"-a", "10.0.0.1"},
		{"-h"},
		{"--version"},
		{"-a", "10.0.0.0/16", "-Pn"},
	} {
		if CLITraceRequested(args) {
			t.Fatalf("scan args treated as trace: %v", args)
		}
	}
}

func TestApplyTraceFlagTakesStandaloneTarget(t *testing.T) {
	t.Cleanup(func() {
		TraceTarget = ""
		TargetString = ""
		structs.GlobalConfig.TraceOnly = false
		structs.GlobalConfig.TraceRoute = false
		structs.GlobalConfig.Targets = nil
	})
	TraceTarget = "192.0.2.9"
	TargetString = "should-be-replaced"
	applyTraceFlag()
	if !structs.GlobalConfig.TraceOnly || !structs.GlobalConfig.TraceRoute {
		t.Fatalf("trace mode not armed: %+v", structs.GlobalConfig)
	}
	if TargetString != "192.0.2.9" {
		t.Fatalf("target = %q", TargetString)
	}
}

func TestHasIPv4TraceTargetFromResultLines(t *testing.T) {
	ingested := ingestScanInputLines([]string{
		"[Alive] 10.0.2.20",
		"[Port] [tcp] 10.0.2.21:445 smb",
		"[WEB] http://10.0.2.22/",
		"[Path] 10.0.2.20 hops=2 10.0.0.1 -> 10.0.2.20",
	})
	if !hasIPv4TraceTarget(ingested.Targets) {
		t.Fatalf("expected IPv4 targets, got %v", ingested.Targets)
	}
	if hasIPv4TraceTarget([]string{"example.test", "http://example.test/"}) {
		t.Fatal("hostname-only input should not count as IPv4")
	}
}
