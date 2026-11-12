package main

import (
	"strings"
	"testing"
)

func TestAllowedLegacyEvidenceIsNarrow(t *testing.T) {
	legacy := strings.Repeat("d", 4)
	tests := []struct {
		name string
		path string
		line string
		want bool
	}{
		{"upstream attribution", "README.md", "[source](https://github.com/SleepingBag945/" + legacy + ")", true},
		{"README branding", "README.md", "run " + legacy + " --help", false},
		{"upgrade migration", "deploy/upgrade-server.sh", "grep /bin/" + legacy + "-server", true},
		{"new install legacy binary", "deploy/setup-server.sh", "install /bin/" + legacy + "-server", false},
		{"historical payload", "scanner/common/config/pocs/jinghang-upload.yaml", "GET /upload/" + legacy + ".jsp", true},
		{"POC branding", "scanner/common/config/pocs/jinghang-upload.yaml", "product: " + legacy, false},
		{"G31 historical case", "docs/performance-baselines/g31-2026-08-10.json", `"case": "` + legacy + `-help-before",`, true},
		{"G31 historical field", "docs/performance-baselines/g31-2026-08-10.json", `"` + legacy + `_help_p95_le_300ms": false,`, true},
		{"G31 arbitrary case", "docs/performance-baselines/g31-2026-08-10.json", `"case": "` + legacy + `-new",`, false},
		{"G31 malicious field", "docs/performance-baselines/g31-2026-08-10.json", `"description": "new ` + legacy + ` branding",`, false},
		{"G31 appended text", "docs/performance-baselines/g31-2026-08-10.json", `"case": "` + legacy + `-help-before", "name": "evil"`, false},
		{"G32 historical case", "docs/performance-baselines/g32-2026-08-10.json", `"case": "g32-` + legacy + `-help-after",`, true},
		{"G32 historical field", "docs/performance-baselines/g32-2026-08-10.json", `"` + legacy + `_help_p95_le_300ms": true,`, true},
		{"G32 wrong historical value", "docs/performance-baselines/g32-2026-08-10.json", `"` + legacy + `_help_p95_le_300ms": false,`, false},
		{"performance doc branding", "docs/performance-baseline.md", "run " + legacy + " -h", false},
		{"machine key hex data", "scanner/common/config/dict/machineKeys.txt", "A1B2" + strings.ToUpper(legacy) + "C3,0123ABCD", true},
		{"machine key arbitrary text", "scanner/common/config/dict/machineKeys.txt", "product=" + legacy, false},
		{"machine key comment", "scanner/common/config/dict/machineKeys.txt", "# " + legacy, false},
		{"machine key missing field", "scanner/common/config/dict/machineKeys.txt", strings.ToUpper(legacy) + ",", false},
		{"machine key extra field", "scanner/common/config/dict/machineKeys.txt", "AA," + strings.ToUpper(legacy) + ",BB", false},
		{"machine key surrounding whitespace", "scanner/common/config/dict/machineKeys.txt", " AA" + strings.ToUpper(legacy) + ",BB ", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := allowedLegacyEvidence(test.path, test.line); got != test.want {
				t.Fatalf("allowedLegacyEvidence(%q, %q) = %t, want %t", test.path, test.line, got, test.want)
			}
		})
	}
}

func TestLegacyOnlyInHexOrUUID(t *testing.T) {
	legacy := strings.Repeat("d", 4)
	tests := []struct {
		name string
		line string
		want bool
	}{
		{"digest hex comment", "# digest: 4b0a00483046022100f389769f114f5af6928dc61169dbedbf9f91fe0ca6f7ef" + legacy + "75964cb38986400221009c1e5f78c80d3a8277e0553855eab8d5afd6069520d4c4f30d1e564e91e8012f:922c64590222798bb761d5b6d8e72950", true},
		{"wpscan uuid with embedded token", "- https://wpscan.com/vulnerability/cb232354-f74d-48bb-b437-7b" + legacy + "1df42a", true},
		{"wpscan uuid segment equals token", "- https://wpscan.com/vulnerability/63270b61-" + legacy + "-4cc0-a091-a04cb4f682ec/", true},
		{"standalone product brand", "product: " + legacy, false},
		{"command brand", "run " + legacy + " --help", false},
		{"historical jsp payload", "GET /upload/" + legacy + ".jsp", false},
		{"brand beside hex still fails", "product: " + legacy + " hash=abcdef0123456789", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := legacyOnlyInHexOrUUID(test.line); got != test.want {
				t.Fatalf("legacyOnlyInHexOrUUID(%q) = %t, want %t", test.line, got, test.want)
			}
		})
	}
}
