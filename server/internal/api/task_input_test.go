package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDefaultTaskScanConfigIncludesDatabaseGoPocPorts(t *testing.T) {
	ports := "," + defaultTaskScanConfig().Ports + ","
	for _, port := range []string{"2379", "5236", "54321"} {
		if !strings.Contains(ports, ","+port+",") {
			t.Fatalf("expected default task ports to include %s, got %q", port, defaultTaskScanConfig().Ports)
		}
	}
}

func TestDefaultTaskScanConfigEnablesWAFSkipOnManyFingerprints(t *testing.T) {
	if !defaultTaskScanConfig().WAFSkipOnManyFingerprints {
		t.Fatal("expected WAFSkipOnManyFingerprints to default to true")
	}
}

func TestDefaultTaskScanConfigUsesSafeExternalMapProfile(t *testing.T) {
	cfg := defaultTaskScanConfig()
	if !cfg.Subdomain || !cfg.NoSubdomainBruteForce || cfg.NoSubFinder || !cfg.NoHostBind {
		t.Fatalf("unexpected discovery defaults: Subdomain=%v NoSubdomainBruteForce=%v NoSubFinder=%v NoHostBind=%v",
			cfg.Subdomain, cfg.NoSubdomainBruteForce, cfg.NoSubFinder, cfg.NoHostBind)
	}
	if !cfg.NoPoc || cfg.GolangPoc || !cfg.DisableGeneralPoc || !cfg.NoDirSearch {
		t.Fatalf("expected POC, password-adjacent directory probing, and general POC to stay disabled: NoPoc=%v GolangPoc=%v DisableGeneralPoc=%v NoDirSearch=%v",
			cfg.NoPoc, cfg.GolangPoc, cfg.DisableGeneralPoc, cfg.NoDirSearch)
	}
}

func TestDirectTargetsAllowUnderscoreHostInFullURL(t *testing.T) {
	targets, summary, err := parseAndValidateTargetsForMode(
		json.RawMessage(`["http://mzt_sc_gov_cn_ipv6.dynky.cn"]`),
		taskTargetModeDirect,
	)
	if err != nil {
		t.Fatalf("expected full URL with underscore host to be accepted, got error: %v", err)
	}
	if len(targets) != 1 || summary.URLs != 1 || summary.Domains != 0 {
		t.Fatalf("unexpected target summary for underscore URL: targets=%v summary=%+v", targets, summary)
	}
}

func TestDirectTargetsKeepUnderscoreBareDomainUnsupported(t *testing.T) {
	_, _, err := parseAndValidateTargetsForMode(
		json.RawMessage(`["mzt_sc_gov_cn_ipv6.dynky.cn"]`),
		taskTargetModeDirect,
	)
	if err == nil || !strings.Contains(err.Error(), "unsupported target") {
		t.Fatalf("expected bare domain with underscore to stay unsupported, got %v", err)
	}
}

func TestDirectTargetsNormalizeBeforeDeduplication(t *testing.T) {
	targets, summary, err := parseAndValidateTargetsForMode(json.RawMessage(`[
		"EXAMPLE.COM",
		"example.com",
		"HTTPS://Example.COM/",
		"https://example.com#ignored",
		"192.168.1.12/24",
		"192.168.1.0/24",
		"192.168.1.10 - 192.168.1.20",
		"192.168.1.10-192.168.1.20"
	]`), taskTargetModeDirect)
	if err != nil {
		t.Fatalf("normalize targets: %v", err)
	}
	want := []string{
		"example.com",
		"https://example.com",
		"192.168.1.0/24",
		"192.168.1.10-192.168.1.20",
	}
	if len(targets) != len(want) {
		t.Fatalf("normalized targets = %v, want %v", targets, want)
	}
	for index := range want {
		if targets[index] != want[index] {
			t.Fatalf("normalized target %d = %q, want %q", index, targets[index], want[index])
		}
	}
	if summary.Total != len(want) || summary.Domains != 1 || summary.URLs != 1 || summary.CIDRs != 1 || summary.IPRanges != 1 {
		t.Fatalf("unexpected normalized summary: %+v", summary)
	}
}

func TestDirectTargetsRejectMalformedURLs(t *testing.T) {
	tests := []struct {
		name   string
		target string
	}{
		{name: "empty_host", target: "http:///path"},
		{name: "invalid_port", target: "http://example.com:65536"},
		{name: "userinfo", target: "http://user@example.com"},
		{name: "control_character", target: "http://example.com/\nadmin"},
		{name: "invalid_scheme", target: "http+unix://example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := json.Marshal([]string{tt.target})
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = parseAndValidateTargetsForMode(raw, taskTargetModeDirect)
			if err == nil || !strings.Contains(err.Error(), "unsupported target") {
				t.Fatalf("expected malformed URL %q to be unsupported, got %v", tt.target, err)
			}
		})
	}
}

func TestClassifyTargetsKeepsValidTargetsAndReportsInvalidTargets(t *testing.T) {
	valid, invalid, summary := classifyTargets([]string{
		"http://127.0.0.1:18080",
		"invalid target",
		"192.168.1.0/24",
	}, taskTargetModeDirect)

	if len(valid) != 2 || valid[0] != "http://127.0.0.1:18080" || valid[1] != "192.168.1.0/24" {
		t.Fatalf("unexpected valid targets: %v", valid)
	}
	if len(invalid) != 1 || invalid[0].Target != "invalid target" || invalid[0].Reason == "" {
		t.Fatalf("unexpected invalid targets: %+v", invalid)
	}
	if summary.Total != 3 || summary.URLs != 1 || summary.CIDRs != 1 {
		t.Fatalf("unexpected target summary: %+v", summary)
	}
}

func TestNormalizeTaskConfigRejectsLegacyProviderSettings(t *testing.T) {
	for _, payload := range []string{
		`{"Hunter":true}`, `{"Fofa":true}`, `{"Quake":true}`,
		`{"LowPerceptionMode":true}`, `{"OnlyIPPort":true}`,
		`{"APIConfigFilePath":"config/api-config.yaml"}`,
	} {
		if _, _, err := normalizeTaskConfigPayload(json.RawMessage(payload)); err == nil || !strings.Contains(err.Error(), "Server-only") {
			t.Fatalf("legacy Provider payload %s err = %v, want Server-only rejection", payload, err)
		}
	}
}

func TestNormalizeTaskConfigRejectsUnmanagedSubdomainInputs(t *testing.T) {
	for _, test := range []struct {
		payload string
		want    string
	}{
		{`{"SubdomainBruteforceDepth":5}`, "between 1 and 4"},
		{`{"SubdomainWordListFile":"/tmp/custom.txt"}`, "Agent-managed"},
		{`{"SubdomainDictionaryWords":["dev"]}`, "Server-only"},
		{`{"SubdomainDictionaryRefs":[{"id":"dict","revision":1}]}`, "Server-only"},
	} {
		if _, _, err := normalizeTaskConfigPayload(json.RawMessage(test.payload)); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Fatalf("payload %s err = %v, want %q rejection", test.payload, err, test.want)
		}
	}
}

func TestNormalizeTaskConfigRejectsCallerControlledGoPocProtocolChecks(t *testing.T) {
	for _, payload := range []string{
		`{"ProtocolCheckEnabled":true}`,
		`{"ProtocolCheckTargetLimit":1}`,
		`{"ProtocolCheckRateLimit":1}`,
		`{"ProtocolCheckRequestBudget":1}`,
		`{"GoPocCatalogSHA256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`,
	} {
		if _, _, err := normalizeTaskConfigPayload(json.RawMessage(payload)); err == nil || !strings.Contains(err.Error(), "Server-only") {
			t.Fatalf("caller-controlled GoPoc payload %s err = %v, want Server-only rejection", payload, err)
		}
	}
}
