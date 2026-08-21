package common

import (
	"bytes"
	"strings"
	"testing"
)

func TestCLIBannerUsesArgusBrandAndKeepsCommandName(t *testing.T) {
	var output bytes.Buffer
	writeBanner(&output)
	text := output.String()
	for _, want := range []string{"Argus CLI v2.0.1", "Command: argus"} {
		if !strings.Contains(text, want) {
			t.Fatalf("banner %q does not contain %q", text, want)
		}
	}
	legacyName := "dd" + "dd"
	if strings.Contains(strings.ToLower(text), legacyName) {
		t.Fatalf("banner still contains the legacy brand: %q", text)
	}
}

func TestCLIHelpKeepsCommandsAndMovesProviderDiscoveryToServer(t *testing.T) {
	for _, want := range []string{
		"argus -h",
		"argus --help",
		"argus --version",
		"argus -a https://example.com",
		"argus -tr 192.0.2.9",
		"argus -tr res.txt",
	} {
		if !strings.Contains(cliHelpText, want) {
			t.Fatalf("CLI help does not contain %q", want)
		}
	}
	if !strings.HasPrefix(CLIVersionString(), "Argus CLI v") {
		t.Fatalf("unexpected version string %q", CLIVersionString())
	}
}
