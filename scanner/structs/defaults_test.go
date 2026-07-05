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

func TestDefaultConfigEnablesWAFSkipOnManyFingerprints(t *testing.T) {
	if !DefaultConfig().WAFSkipOnManyFingerprints {
		t.Fatal("expected WAFSkipOnManyFingerprints to default to true")
	}
}
