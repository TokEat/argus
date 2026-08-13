package structs

import (
	"strings"
	"testing"
)

func TestDefaultConfigIncludesDatabaseGoPocPorts(t *testing.T) {
	ports := "," + DefaultConfig().Ports + ","
	for _, port := range []string{"2379", "5236", "54321"} {
		if !strings.Contains(ports, ","+port+",") {
			t.Fatalf("expected default ports to include %s, got %q", port, DefaultConfig().Ports)
		}
	}
}

func TestDefaultConfigHasExactlyCommon100Ports(t *testing.T) {
	ports := strings.Split(DefaultConfig().Ports, ",")
	seen := make(map[string]struct{}, len(ports))
	for _, port := range ports {
		if _, duplicate := seen[port]; duplicate {
			t.Fatalf("duplicate default port %s", port)
		}
		seen[port] = struct{}{}
	}
	if len(seen) != 100 {
		t.Fatalf("default port count = %d, want 100", len(seen))
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

func TestDefaultConfigDisablesImplicitPocAndCredentialChecks(t *testing.T) {
	cfg := DefaultConfig()
	if !cfg.NoPoc || cfg.GolangPoc || !cfg.DisableGeneralPoc || cfg.PocNameForSearch != "" {
		t.Fatalf("expected shared defaults to require explicit risk execution, got NoPoc=%v GolangPoc=%v DisableGeneralPoc=%v PocNameForSearch=%q",
			cfg.NoPoc, cfg.GolangPoc, cfg.DisableGeneralPoc, cfg.PocNameForSearch)
	}
}
