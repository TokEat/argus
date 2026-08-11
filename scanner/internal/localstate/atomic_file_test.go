package localstate

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAtomicWriteReplacementFailurePreservesCurrentFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "state.tsv")
	if err := os.WriteFile(path, []byte("current\n"), 0o600); err != nil {
		t.Fatalf("write current state: %v", err)
	}
	wantErr := errors.New("injected replacement failure")
	err := writeFileAtomicWith(path, []byte("new\n"), 0o600, func(source, destination string) error {
		if source == path || destination != path {
			t.Fatalf("replace paths = %q -> %q", source, destination)
		}
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("atomic write error = %v", err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read current state: %v", err)
	}
	if string(contents) != "current\n" {
		t.Fatalf("current state changed after failed replacement: %q", contents)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("list temporary files: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".state.tsv.tmp-") {
			t.Fatalf("temporary file was not cleaned: %s", entry.Name())
		}
	}
}
