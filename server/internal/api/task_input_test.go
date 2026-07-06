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

func TestDefaultTaskScanConfigDisablesNoisyDiscoveryByDefault(t *testing.T) {
	cfg := defaultTaskScanConfig()
	if !cfg.NoSubdomainBruteForce || !cfg.NoSubFinder || !cfg.NoHostBind {
		t.Fatalf("expected noisy discovery defaults to be disabled, got NoSubdomainBruteForce=%v NoSubFinder=%v NoHostBind=%v",
			cfg.NoSubdomainBruteForce, cfg.NoSubFinder, cfg.NoHostBind)
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
