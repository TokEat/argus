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
	for _, want := range []string{"Argus CLI v2.0.1", "Command: dddd"} {
		if !strings.Contains(text, want) {
			t.Fatalf("banner %q does not contain %q", text, want)
		}
	}
	for _, legacy := range []string{"dddd.version", "dddd是一款"} {
		if strings.Contains(text, legacy) {
			t.Fatalf("banner still contains legacy brand %q: %q", legacy, text)
		}
	}
}

func TestCLIHelpKeepsCommandsAndMovesProviderDiscoveryToServer(t *testing.T) {
	for _, want := range []string{
		"dddd help finger",
		"dddd finger --help",
		"dddd poc list --severity high",
		"dddd workflow list --product ruoyi",
		"dddd --version",
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
