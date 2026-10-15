package common

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIngestScanInputLinesReusesAliveAndPorts(t *testing.T) {
	got := ingestScanInputLines([]string{
		"[Alive] 10.0.0.2",
		"[Alive] 10.0.0.3 extra",
		"[Port] 10.0.0.3:22",
		"[Protocol] 10.0.0.3:80 http",
		"[Port] [tcp] 10.0.0.3:445 smb",
		"192.0.2.9",
	})
	joined := strings.Join(got.Targets, ",")
	if !strings.Contains(joined, "10.0.0.2") || !strings.Contains(joined, "10.0.0.3:22") || !strings.Contains(joined, "10.0.0.3:80") || !strings.Contains(joined, "10.0.0.3:445") || !strings.Contains(joined, "192.0.2.9") {
		t.Fatalf("targets = %q", joined)
	}
	if strings.Contains(joined, "10.0.0.3,") || strings.HasSuffix(joined, "10.0.0.3") {
		t.Fatalf("alive host with ports should not be queued for host scan: %q", joined)
	}
	if !got.SkipDiscover || got.ReusedAlive != 2 || got.ReusedPorts != 3 {
		t.Fatalf("reuse counters = %#v", got)
	}
}

func TestIngestScanInputLinesDoesNotReuseUDPAsTCPPort(t *testing.T) {
	got := ingestScanInputLines([]string{
		"[Port] [udp] 10.0.0.8:53",
		"[Protocol] [udp] 10.0.0.8:161 snmp",
		"[Port] 10.0.0.9:53/udp",
		"[Port] [tcp] 10.0.0.7:22",
	})
	joined := strings.Join(got.Targets, ",")
	if strings.Contains(joined, "10.0.0.8:53") || strings.Contains(joined, "10.0.0.8:161") || strings.Contains(joined, "10.0.0.9:53") {
		t.Fatalf("udp results reused as tcp ports: %q", joined)
	}
	if !strings.Contains(joined, "10.0.0.8") || !strings.Contains(joined, "10.0.0.9") || !strings.Contains(joined, "10.0.0.7:22") {
		t.Fatalf("udp hosts / tcp port missing: %q", joined)
	}
	if got.ReusedPorts != 1 || got.ReusedAlive != 3 {
		t.Fatalf("reuse counters = %#v targets=%q", got, joined)
	}
}

func TestIngestScanInputLinesIgnoresPathAndTopo(t *testing.T) {
	got := ingestScanInputLines([]string{
		"[Alive] 10.0.2.20",
		"[Path] 10.0.2.20 hops=2 10.0.0.1 -> 10.0.2.1 -> 10.0.2.20",
		"[Topo] 10.0.0.1 -> 10.0.2.0/24",
	})
	joined := strings.Join(got.Targets, ",")
	if joined != "10.0.2.20" {
		t.Fatalf("path/topo ingested as targets: %q", joined)
	}
	if got.ReusedAlive != 1 {
		t.Fatalf("reuse = %#v", got)
	}
}

func TestIngestScanInputLinesReadsWEBHeaderAndIgnoresChildren(t *testing.T) {
	got := ingestScanInputLines([]string{
		"[WEB] http://10.0.0.8/",
		"     [Finger] Nginx,GitLab",
		"     [Code] 302",
		"     [Size] 2862",
		"     [Redirect] https://10.0.0.8/login",
		"[Web] http://10.0.0.8:8080 200 old",
	})
	joined := strings.Join(got.Targets, ",")
	if !strings.Contains(joined, "http://10.0.0.8/") || !strings.Contains(joined, "http://10.0.0.8:8080") {
		t.Fatalf("targets = %q", joined)
	}
	if strings.Contains(joined, "302") || strings.Contains(joined, "login") {
		t.Fatalf("child fields ingested as targets: %q", joined)
	}
	fingers := got.Fingers["http://10.0.0.8/"]
	if len(fingers) != 2 || fingers[0] != "Nginx" || fingers[1] != "GitLab" {
		t.Fatalf("web child fingers = %q", fingers)
	}
}

func TestResolveScanInputFileUsesResultTxtInDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "result.txt")
	if err := os.WriteFile(path, []byte("[Alive] 10.1.1.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := resolveScanInputFile(dir); got != path {
		t.Fatalf("resolve = %q, want %q", got, path)
	}
}

func TestIngestScanInputLinesParsesServiceFingerNewAndLegacyFormats(t *testing.T) {
	got := ingestScanInputLines([]string{
		"[Finger] ssh://172.20.0.180:22 OpenSSH,SSH",
		"[Finger] http://10.0.0.8/app [Nginx,GitLab]",
	})
	ssh := got.Fingers["ssh://172.20.0.180:22"]
	if len(ssh) != 2 || ssh[0] != "OpenSSH" || ssh[1] != "SSH" {
		t.Fatalf("service finger parsed = %q, want [OpenSSH SSH]", ssh)
	}
	http := got.Fingers["http://10.0.0.8/app"]
	if len(http) != 2 || http[0] != "Nginx" || http[1] != "GitLab" {
		t.Fatalf("legacy finger parsed = %q, want [Nginx GitLab]", http)
	}
}

func TestIsFileLikeInputDistinguishesPathsFromTypedTargets(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"result.txt", true},
		{"targets.txt", true},
		{"logs/result.log", true},
		{"dir/result.txt", true},
		{"scan-results.json", true},
		{"example.com", false},
		{"192.168.1.0/24", false},
		{"10.0.0.1", false},
		{"10.0.0.1:80", false},
		{"http://example.com", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := isFileLikeInput(tc.in); got != tc.want {
			t.Fatalf("isFileLikeInput(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
