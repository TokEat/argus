package gonmap

import (
	"testing"
	"time"
)

func TestScanClearsProbeUsedFromEarlierTargets(t *testing.T) {
	scanner := New()
	scanner.SetTimeout(20 * time.Millisecond)
	scanner.probeUsed = append(ProbeList(nil), scanner.allProbeMap...)
	scanner.probeUsed = append(scanner.probeUsed, scanner.sslProbeMap...)
	if !scanner.probeUsed.exist("TCP_GetRequest") {
		t.Fatal("precondition: leftover probeUsed must include TCP_GetRequest")
	}

	status, _ := scanner.Scan("127.0.0.1", 1)
	if status == 0 {
		t.Fatal("Scan returned the zero status, leftover probeUsed was probably not reset")
	}
	if scanner.probeUsed.exist("TCP_GetRequest") && len(scanner.probeUsed) == len(scanner.allProbeMap)+len(scanner.sslProbeMap) {
		t.Fatal("Scan kept the leftover used-probe set instead of recording this target")
	}
}

func TestFixProtocolCanonicalAliases(t *testing.T) {
	cases := map[string]string{
		"ms-wbt-server":   "rdp",
		"microsoft-ds":    "smb",
		"ms-sql-s":        "mssql",
		"sqlserver":       "mssql",
		"java-rmi":        "rmi",
		"rmiregistry":     "rmi",
		"java-debug":      "jdwp",
		"jmxmp":           "jmx",
		"java-serialized": "java-serialization",
		"postgres":        "postgresql",
		"kerberos-sec":    "kerberos",
		"dns-sd":          "mdns",
		"ssl/http":        "https",
		"netbios-ssn":     "netbios",
	}
	for raw, want := range cases {
		if got := FixProtocol(raw); got != want {
			t.Fatalf("FixProtocol(%q) = %q, want %q", raw, got, want)
		}
	}
}
