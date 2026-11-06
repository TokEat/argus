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

// 网段扫描：存活 IP 必须回溯到输入网段本身作为链路起点，而不是停在派生 IP。
func TestIPAliveLineageParentIsInputSegment(t *testing.T) {
	ctx := &ScanContext{
		Config:         Config{Targets: []string{"10.3.130.0/24"}},
		IPDomainMap:    map[string][]string{},
		LineageParents: map[string]string{},
	}
	msg := structs.OutputMessage{Type: "IPAlive", IP: "10.3.130.95"}
	if got := LineageSourceFor(ctx, msg); got != "10.3.130.0/24" {
		t.Fatalf("cidr ipalive parent=%q want 10.3.130.0/24", got)
	}
	RecordLineageParent(ctx, msg)
	if got := ctx.LineageParents["10.3.130.95"]; got != "10.3.130.0/24" {
		t.Fatalf("cidr recorded parent=%q want 10.3.130.0/24", got)
	}
}

// IP 段（a-b）输入同理：起点是段输入，不是段内某个 IP。
func TestIPAliveLineageParentIsInputRange(t *testing.T) {
	ctx := &ScanContext{
		Config:         Config{Targets: []string{"10.3.130.1-10.3.130.100"}},
		IPDomainMap:    map[string][]string{},
		LineageParents: map[string]string{},
	}
	msg := structs.OutputMessage{Type: "IPAlive", IP: "10.3.130.50"}
	if got := LineageSourceFor(ctx, msg); got != "10.3.130.1-10.3.130.100" {
		t.Fatalf("range ipalive parent=%q want 10.3.130.1-10.3.130.100", got)
	}
}

// 多个输入并存时命中包含该 IP 的那段；不在任何段内时回退到域名链。
func TestIPAliveLineageSegmentSelectionAndDomainFallback(t *testing.T) {
	ctx := &ScanContext{
		Config:         Config{Targets: []string{"example.com", "10.3.130.0/24"}},
		IPDomainMap:    map[string][]string{"1.2.3.4": {"www.example.com"}},
		LineageParents: map[string]string{},
	}
	// 1.2.3.4 不在 10.3.130.0/24 内 → 回退到解析它的域名。
	outside := structs.OutputMessage{Type: "IPAlive", IP: "1.2.3.4"}
	if got := LineageSourceFor(ctx, outside); got != "www.example.com" {
		t.Fatalf("outside-segment ipalive parent=%q want www.example.com", got)
	}
	// 10.3.130.7 在段内（即使域名表无关）→ 命中段输入。
	inside := structs.OutputMessage{Type: "IPAlive", IP: "10.3.130.7"}
	if got := LineageSourceFor(ctx, inside); got != "10.3.130.0/24" {
		t.Fatalf("inside-segment ipalive parent=%q want 10.3.130.0/24", got)
	}
}

// 裸 IP 输入：IP 自身即根，不能变成自父引用。
func TestIPAliveBareIPInputIsOwnRoot(t *testing.T) {
	ctx := &ScanContext{
		Config:         Config{Targets: []string{"10.3.130.95"}},
		IPDomainMap:    map[string][]string{},
		LineageParents: map[string]string{},
	}
	msg := structs.OutputMessage{Type: "IPAlive", IP: "10.3.130.95"}
	if got := LineageSourceFor(ctx, msg); got != "" {
		t.Fatalf("bare-ip input should be its own root, got parent=%q", got)
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
