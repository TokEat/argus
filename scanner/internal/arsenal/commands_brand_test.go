package arsenal

import (
	"io"
	"os"
	"strings"
	"sync"
	"testing"
)

var usageOutputMu sync.Mutex

func TestRuleCommandUsageKeepsArgusBrandAndDDDDSyntax(t *testing.T) {
	tests := []struct {
		name  string
		usage func()
		want  string
	}{
		{name: "finger", usage: fingerUsage, want: "dddd finger"},
		{name: "poc", usage: pocUsage, want: "dddd poc"},
		{name: "workflow", usage: workflowUsage, want: "dddd workflow"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := captureUsageOutput(t, tt.usage)
			if !strings.Contains(output, "Argus CLI") {
				t.Fatalf("usage is missing Argus CLI branding: %q", output)
			}
			if !strings.Contains(output, tt.want) {
				t.Fatalf("usage is missing compatible command syntax %q: %q", tt.want, output)
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
