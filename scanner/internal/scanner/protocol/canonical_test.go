package protocol

import "testing"

func TestCanonicalProtocol(t *testing.T) {
	cases := map[string]string{
		"  MS-WBT-SERVER ": "rdp",
		"microsoft-ds":     "smb",
		"java-rmi":         "rmi",
		"rmiregistry":      "rmi",
		"sqlserver":        "mssql",
		"postgres":         "postgresql",
		"ssl/http":         "https",
		"ssh":              "ssh",
	}
	for raw, want := range cases {
		if got := CanonicalProtocol(raw); got != want {
			t.Fatalf("CanonicalProtocol(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestUnidentified(t *testing.T) {
	for _, name := range []string{"", "tcp", "udp", "unknown", "ssl", "portscan"} {
		if !Unidentified(name) {
			t.Fatalf("Unidentified(%q) = false", name)
		}
	}
	if Unidentified("ssh") || Unidentified("microsoft-ds") {
		t.Fatal("identified services must not be treated as unknown")
	}
}
