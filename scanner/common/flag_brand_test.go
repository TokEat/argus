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
		"argus help finger",
		"argus finger --help",
		"argus poc list --severity high",
		"argus workflow list --product ruoyi",
		"argus --version",
		"Argus Server",
		"资产测绘",
	} {
		if !strings.Contains(cliHelpText, want) {
			t.Fatalf("CLI help does not contain %q", want)
		}
	}
	for _, removedFlag := range []string{"-hunter", "-fofa", "-quake", "-lpm", "-oip"} {
		if strings.Contains(cliHelpText, removedFlag) {
			t.Fatalf("CLI help still advertises Server-only flag %q", removedFlag)
		}
	}
	if !strings.HasPrefix(CLIVersionString(), "Argus CLI v") {
		t.Fatalf("unexpected version string %q", CLIVersionString())
	}
}
