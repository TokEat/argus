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

func TestApplyPresentationUsesArgusAsInteractiveFindingSink(t *testing.T) {
	options := &types.Options{NoColor: false, EnableProgressBar: true}
	applyPresentation(options, nil)
	if options.NoColor || !options.EnableProgressBar || !options.DisableStdout {
		t.Fatalf("interactive presentation changed options: %+v", options)
	}
}

func TestApplyPresentationConfiguresMachineOutput(t *testing.T) {
	options := &types.Options{NoColor: false, EnableProgressBar: true}
	applyPresentation(options, []Presentation{{MachineOutput: true}})
	if !options.NoColor || options.EnableProgressBar || !options.DisableStdout {
		t.Fatalf("machine presentation did not set no-color/progress options: %+v", options)
	}
}

func TestApplyPresentationAppliesSealedExecutionLimits(t *testing.T) {
	options := &types.Options{RateLimit: 150, BulkSize: 64, TemplateThreads: 64, HeadlessBulkSize: 10, HeadlessTemplateThreads: 10, Retries: 2}
	applyPresentation(options, []Presentation{{RateLimit: 12, BulkSize: 3, TemplateThreads: 2, RequestLimit: 25}})
	if options.RateLimit != 12 || options.BulkSize != 3 || options.HeadlessBulkSize != 3 || options.TemplateThreads != 2 || options.HeadlessTemplateThreads != 2 || options.RequestLimit != 25 || options.Retries != 0 {
		t.Fatalf("sealed execution limits were not applied: %+v", options)
	}
}
