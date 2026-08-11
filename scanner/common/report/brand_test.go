package report

import (
	"strings"
	"testing"
)

func TestReportsUseArgusBrand(t *testing.T) {
	legacyName := "dd" + "dd"
	for name, content := range map[string]string{
		"default report": defaultHeader(),
		"asset report":   generateAssetHTML([]*AssetEntry{{EntryType: "Web", URL: "https://example.com"}}, "result.txt"),
	} {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(content, "Argus") {
				t.Fatalf("%s is missing the Argus brand", name)
			}
			if strings.Contains(strings.ToLower(content), legacyName) {
				t.Fatalf("%s still contains the legacy brand", name)
			}
		})
	}
}
