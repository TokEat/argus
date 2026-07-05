package api

import (
	"strings"
	"testing"
)

func TestDefaultTaskScanConfigIncludesDatabaseGoPocPorts(t *testing.T) {
	ports := "," + defaultTaskScanConfig().Ports + ","
	for _, port := range []string{"5236", "54321"} {
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
