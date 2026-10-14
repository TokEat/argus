package engine

import (
	"testing"

	"github.com/P0lar1ght/argus/scanner/structs"
)

func newLineageTestContext() *ScanContext {
	return &ScanContext{
		Config:         Config{Targets: []string{"example.com"}},
		IPDomainMap:    map[string][]string{"1.2.3.4": {"www.example.com"}},
		LineageParents: map[string]string{},
	}
}

func TestRecordAndLookupWebLineage(t *testing.T) {
	ctx := newLineageTestContext()
	msg := structs.OutputMessage{Type: "Web", URI: "http://1.2.3.4:8080/login"}
	RecordLineageParent(ctx, msg)
	if got := ctx.LineageParents["http://1.2.3.4:8080"]; got != "1.2.3.4:8080" {
		t.Fatalf("web lineage parent=%q want ip:port bare", got)
	}
	if got := LineageSourceFor(ctx, msg); got != "1.2.3.4:8080" {
		t.Fatalf("LineageSourceFor=%q want 1.2.3.4:8080", got)
	}
}

func TestPortScanLineageParentIsIP(t *testing.T) {
	ctx := newLineageTestContext()
	msg := structs.OutputMessage{Type: "PortScan", IP: "1.2.3.4", Port: "80"}
	if got := LineageSourceFor(ctx, msg); got != "1.2.3.4" {
		t.Fatalf("portscan parent=%q want 1.2.3.4", got)
	}
}

func TestIPAliveLineageParentFromIPDomainMap(t *testing.T) {
	ctx := newLineageTestContext()
	msg := structs.OutputMessage{Type: "IPAlive", IP: "1.2.3.4"}
	if got := LineageSourceFor(ctx, msg); got != "www.example.com" {
		t.Fatalf("ipalive parent=%q want www.example.com", got)
	}
}

func TestSubdomainLineageParentIsRootDomain(t *testing.T) {
	ctx := newLineageTestContext()
	msg := structs.OutputMessage{Type: "DNS-SubFinder", Domain: "www.example.com"}
	if got := LineageSourceFor(ctx, msg); got != "example.com" {
		t.Fatalf("subdomain parent=%q want example.com", got)
	}
}

func TestLineageNilAndUnknownSafe(t *testing.T) {
	if got := LineageSourceFor(nil, structs.OutputMessage{Type: "Web", URI: "http://x"}); got != "" {
		t.Fatalf("nil ctx should yield empty source, got %q", got)
	}
	ctx := newLineageTestContext()
	if got := LineageSourceFor(ctx, structs.OutputMessage{Type: "Web", URI: "unknown"}); got != "" {
		t.Fatalf("unknown target should yield empty source, got %q", got)
	}
	if got := LineageSourceFor(ctx, structs.OutputMessage{Type: "Nuclei"}); got != "" {
		t.Fatalf("unmapped type should yield empty source, got %q", got)
	}
}
