package runner

import (
	"errors"
	"os"
	"testing"

	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

func TestInitializeTemplatesHTTPInputClosesHybridMapWhenHTTPXCreationFails(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("TMP", tempDir)
	t.Setenv("TEMP", tempDir)
	t.Setenv("TMPDIR", tempDir)

	runner := &Runner{options: &types.Options{}}
	_, err := runner.initializeTemplatesHTTPInputWithHTTPXFactory(func(*httpx.Options) (*httpx.HTTPX, error) {
		return nil, errors.New("httpx initialization failed")
	})
	if err == nil {
		t.Fatal("expected httpx initialization failure")
	}

	entries, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatalf("read temporary directory: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected no HybridMap temporary files after failure, found %d", len(entries))
	}
}
