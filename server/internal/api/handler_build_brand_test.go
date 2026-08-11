package api

import (
	"strings"
	"testing"
)

func TestSupportedBuildArtifactNameOnlyAcceptsCurrentArgusArtifacts(t *testing.T) {
	accepted := []string{
		"argus-linux-amd64",
		"argus-agent-darwin-arm64",
		"argus-server-windows-amd64.exe",
		"argus-windows-arm64.tar.gz",
		"server-ui-dist.tar.gz",
	}
	for _, name := range accepted {
		if !isSupportedBuildArtifactName(name) {
			t.Fatalf("expected supported artifact %q", name)
		}
	}

	legacyPrefix := strings.Repeat("d", 4)
	rejected := []string{
		legacyPrefix + "-agent-linux-amd64",
		"argus-agent-linux-amd64.tar.gz",
		"argus-server-linux-amd64.exe",
		"argus-plan.txt",
		"unrelated-linux-amd64",
	}
	for _, name := range rejected {
		if isSupportedBuildArtifactName(name) {
			t.Fatalf("expected unsupported artifact %q", name)
		}
	}
}
