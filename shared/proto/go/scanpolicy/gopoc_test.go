package scanpolicy

import (
	"strings"
	"testing"
)

func TestGoPocCatalogIsUniqueAndGoverned(t *testing.T) {
	descriptors := GoPocDescriptors()
	seen := make(map[string]struct{}, len(descriptors))
	for _, item := range descriptors {
		if item.Plugin == "" || item.Revision < 1 || item.RequestCost < 1 || !item.Reviewed {
			t.Fatalf("ungoverned GoPoc descriptor: %+v", item)
		}
		if _, duplicate := seen[item.Plugin]; duplicate {
			t.Fatalf("duplicate GoPoc descriptor %q", item.Plugin)
		}
		seen[item.Plugin] = struct{}{}
	}
	if hash := GoPocCatalogSHA256(); len(hash) != 64 || hash != strings.ToLower(hash) {
		t.Fatalf("invalid catalog hash %q", hash)
	}
	descriptors[0].Plugin = "mutated"
	descriptors[0].Services[0] = "mutated"
	if current := GoPocDescriptors()[0]; current.Plugin == "mutated" || current.Services[0] == "mutated" {
		t.Fatal("callers can mutate the shared GoPoc descriptor authority")
	}
}

func TestGoPocEndpointResolutionSeparatesCapabilities(t *testing.T) {
	observation := strings.Repeat("a", 64)
	protocol := GoPocTargetsForEndpoint("192.0.2.10:445", "smb", 445, observation, GoPocProtocolCheck)
	vulnerabilities := GoPocTargetsForEndpoint("192.0.2.10:445", "smb", 445, observation, GoPocVulnerabilityCheck)
	if len(protocol) != 1 || protocol[0].Plugin != "NetBios-GetHostInfo" {
		t.Fatalf("unexpected protocol plan: %+v", protocol)
	}
	if len(vulnerabilities) != 1 || vulnerabilities[0].Plugin != "SMB-MS17-010" {
		t.Fatalf("unexpected vulnerability plan: %+v", vulnerabilities)
	}
	if got := GoPocTargetsForEndpoint("192.0.2.20:445", "smtp", 445, observation, GoPocVulnerabilityCheck); len(got) != 0 {
		t.Fatalf("conflicting observed service used port fallback: %+v", got)
	}
	if got := GoPocTargetsForEndpoint("192.0.2.30:3306", "mysql", 3306, observation, GoPocVulnerabilityCheck); len(got) != 0 {
		t.Fatalf("TiDB service-only match widened its required port: %+v", got)
	}
	if got := GoPocTargetsForEndpoint("192.0.2.30:4000", "mysql", 4000, observation, GoPocVulnerabilityCheck); len(got) != 1 || got[0].Plugin != "TiDB-Scan" || got[0].Trigger != "protocol_and_port" {
		t.Fatalf("TiDB service+port trigger was not preserved: %+v", got)
	}
}

func TestGoPocSignalTargetRequiresDeclaredTrigger(t *testing.T) {
	observation := strings.Repeat("b", 64)
	item, err := GoPocTargetForSignal("https://example.invalid/", "Shiro-Key-Crack", "nuclei", "shiro-detect", observation)
	if err != nil || item.Trigger != "nuclei:shiro-detect" {
		t.Fatalf("valid signal target rejected: item=%+v err=%v", item, err)
	}
	if _, err := GoPocTargetForSignal("https://example.invalid/", "Shiro-Key-Crack", "nuclei", "unreviewed", observation); err == nil {
		t.Fatal("undeclared signal was accepted")
	}
}

func TestDisabledGoPocCannotEnterScopedPlan(t *testing.T) {
	item := GoPocTarget{Target: "192.0.2.10:23", Service: "telnet", Plugin: "Telnet-Bypass", Capability: GoPocVulnerabilityCheck, Trigger: "protocol", ObservationSHA256: strings.Repeat("c", 64), PluginRevision: 1, RequestCost: 1}
	if err := ValidateGoPocTarget(item, GoPocVulnerabilityCheck); err == nil {
		t.Fatal("disabled GoPoc was accepted")
	}
}
