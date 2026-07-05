package callnuclei

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

func TestReadConfigWAFBypassHeaders(t *testing.T) {
	targets := map[string][]string{"http://127.0.0.1": []string{}}

	enabled := &types.Options{}
	readConfig(enabled, targets, "", "", true, true, "config/pocs", nil)
	if len(enabled.CustomHeaders) == 0 {
		t.Fatal("expected WAF bypass headers when enabled")
	}
	if enabled.CustomHeaders[0] != "X-Forwarded-For: 127.0.0.1" {
		t.Fatalf("unexpected first WAF header: %q", enabled.CustomHeaders[0])
	}

	disabled := &types.Options{}
	readConfig(disabled, targets, "", "", true, false, "config/pocs", nil)
	if len(disabled.CustomHeaders) != 0 {
		t.Fatalf("expected no WAF bypass headers when disabled, got %v", disabled.CustomHeaders)
	}
}
