package arsenal

import (
	"io"
	"os"
	"strings"
	"sync"
	"testing"
)

var usageOutputMu sync.Mutex

func TestRuleCommandUsageUsesArgusExecutable(t *testing.T) {
	tests := []struct {
		name  string
		usage func()
		want  string
	}{
		{name: "finger", usage: fingerUsage, want: "argus finger"},
		{name: "poc", usage: pocUsage, want: "argus poc"},
		{name: "workflow", usage: workflowUsage, want: "argus workflow"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := captureUsageOutput(t, tt.usage)
			if !strings.Contains(output, "Argus CLI") {
				t.Fatalf("usage is missing Argus CLI branding: %q", output)
			}
			if !strings.Contains(output, tt.want) {
				t.Fatalf("usage is missing Argus command syntax %q: %q", tt.want, output)
			}
			if strings.Contains(strings.ToLower(output), "dd"+"dd") {
				t.Fatalf("usage still contains the legacy executable name: %q", output)
			}
		})
	}
}

func captureUsageOutput(t *testing.T, usage func()) string {
	t.Helper()
	usageOutputMu.Lock()
	defer usageOutputMu.Unlock()

	original := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}
	os.Stdout = writer
	defer func() {
		os.Stdout = original
		_ = writer.Close()
		_ = reader.Close()
	}()

	usage()
	if err := writer.Close(); err != nil {
		t.Fatalf("close stdout writer: %v", err)
	}
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	return string(output)
}
