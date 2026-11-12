//go:build !windows

package ddout

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOutputFileUsesPrivateMode(t *testing.T) {
	resetForTest()
	path := filepath.Join(t.TempDir(), "result.txt")
	if err := appendToFile(path, "sensitive evidence"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("output mode = %o, want 600", got)
	}
}
