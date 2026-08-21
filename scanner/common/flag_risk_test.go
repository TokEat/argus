package common

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/P0lar1ght/argus/scanner/structs"
)

func TestValidateCLIRiskFlagsRejectsExplicitPOCWithNoPoc(t *testing.T) {
	tests := []struct {
		name   string
		config structs.Config
	}{
		{
			name:   "named nuclei POC",
			config: structs.Config{NoPoc: true, PocNameForSearch: "shiro"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateCLIRiskFlags(test.config)
			var usageErr *CLIUsageError
			if !errors.As(err, &usageErr) {
				t.Fatalf("expected CLIUsageError, got %v", err)
			}
		})
	}
}

func TestSanitizeResultDirectoryNameAcceptsURLQueriesOnWindows(t *testing.T) {
	name := sanitizeResultDirectoryName(`https://scan.example.test/path?q=one&next=two|three`)
	if name == "" || strings.ContainsAny(name, `<>:"/\\|?*`) {
		t.Fatalf("unsafe result directory name %q", name)
	}
}

func TestHTMLReportExtensionIsCaseInsensitive(t *testing.T) {
	for _, name := range []string{"report.html", "report.HTM", "report.HTML"} {
		if !hasHTMLReportExtension(name) {
			t.Fatalf("expected HTML report extension to be accepted: %q", name)
		}
	}
	if hasHTMLReportExtension("report.txt") {
		t.Fatal("non-HTML report extension was accepted")
	}
}

func TestValidateCLIArtifactNamesRejectsPortableCollisions(t *testing.T) {
	for _, test := range []struct {
		output, report, audit string
	}{
		{output: "evidence.html", report: "EVIDENCE.HTML"},
		{output: "result.txt", report: "report.html", audit: "REPORT.HTML"},
		{output: "result.txt", report: "report.html", audit: "result.txt."},
		{output: "result.txt ", report: "report.html", audit: "RESULT.TXT"},
	} {
		if err := validateCLIArtifactNames(test.output, test.report, test.audit); err == nil {
			t.Fatalf("expected artifact collision for %#v", test)
		}
	}
	if err := validateCLIArtifactNames("result.txt", "report.html", "audit.log"); err != nil {
		t.Fatalf("unexpected distinct artifact error: %v", err)
	}
}

func TestCreateUniqueResultDirectoryDoesNotReuseExistingRun(t *testing.T) {
	root := t.TempDir()
	first, err := createUniqueResultDirectory(root, "target_20260811_120000")
	if err != nil {
		t.Fatalf("create first result directory: %v", err)
	}
	marker := filepath.Join(first, "result.txt")
	if err := os.WriteFile(marker, []byte("first run"), 0o600); err != nil {
		t.Fatalf("write first result: %v", err)
	}
	second, err := createUniqueResultDirectory(root, "target_20260811_120000")
	if err != nil {
		t.Fatalf("create second result directory: %v", err)
	}
	if first == second {
		t.Fatalf("result directory was reused: %q", first)
	}
	if contents, err := os.ReadFile(marker); err != nil || string(contents) != "first run" {
		t.Fatalf("first run was changed: contents=%q err=%v", contents, err)
	}
}

func TestValidateCLIRiskFlagsAllowsInformationOnlyOrExplicitRisk(t *testing.T) {
	for _, config := range []structs.Config{
		{NoPoc: true},
		{PocNameForSearch: "shiro"},
		{GolangPoc: true},
	} {
		if err := validateCLIRiskFlags(config); err != nil {
			t.Fatalf("unexpected validation error for %#v: %v", config, err)
		}
	}
}
