package structs

import (
	"strings"
	"testing"

	"github.com/P0lar1ght/argus/shared/proto/go/scanpolicy"
)

func TestDefaultConfigIncludesDatabaseGoPocPorts(t *testing.T) {
	ports := "," + DefaultConfig().Ports + ","
	for _, port := range []string{"2379", "5236", "54321", "20880", "5672", "4369", "10911", "11740", "61616"} {
		if !strings.Contains(ports, ","+port+",") {
			t.Fatalf("expected default ports to include %s, got %q", port, DefaultConfig().Ports)
		}
	}
}

func TestDefaultConfigUsesCommonProtocolPorts(t *testing.T) {
	ports := strings.Split(DefaultConfig().Ports, ",")
	seen := make(map[string]struct{}, len(ports))
	for _, port := range ports {
		if _, duplicate := seen[port]; duplicate {
			t.Fatalf("duplicate default port %s", port)
		}
		seen[port] = struct{}{}
	}
	if len(seen) != scanpolicy.PortCount(scanpolicy.Common100Ports) {
		t.Fatalf("default port count = %d, want %d", len(seen), scanpolicy.PortCount(scanpolicy.Common100Ports))
	}
	for _, port := range []string{"789", "2404", "5006", "5007", "9600", "10001", "20000"} {
		if _, ok := seen[port]; !ok {
			t.Fatalf("default protocol ports missing %s", port)
		}
	}
}

func TestDefaultConfigEnablesWAFSkipOnManyFingerprints(t *testing.T) {
	if !DefaultConfig().WAFSkipOnManyFingerprints {
		t.Fatal("expected WAFSkipOnManyFingerprints to default to true")
	}
}

func TestDefaultConfigDisablesNoisyDiscoveryByDefault(t *testing.T) {
	cfg := DefaultConfig()
	if !cfg.NoSubdomainBruteForce || !cfg.NoSubFinder || !cfg.NoHostBind {
		t.Fatalf("expected noisy discovery defaults to be disabled, got NoSubdomainBruteForce=%v NoSubFinder=%v NoHostBind=%v",
			cfg.NoSubdomainBruteForce, cfg.NoSubFinder, cfg.NoHostBind)
	}
}

func TestDefaultConfigEnablesDomainFormProbe(t *testing.T) {
	if DefaultConfig().NoDomainProbe {
		t.Fatal("expected NoDomainProbe to default to false so domain-bound ports are probed as domain:port")
	}
}

func TestDefaultConfigDisablesImplicitPocAndCredentialChecks(t *testing.T) {
	cfg := DefaultConfig()
	if !cfg.NoPoc || cfg.GolangPoc || !cfg.DisableGeneralPoc || cfg.PocNameForSearch != "" {
		t.Fatalf("expected shared defaults to require explicit risk execution, got NoPoc=%v GolangPoc=%v DisableGeneralPoc=%v PocNameForSearch=%q",
			cfg.NoPoc, cfg.GolangPoc, cfg.DisableGeneralPoc, cfg.PocNameForSearch)
	}
}
