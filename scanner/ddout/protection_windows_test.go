//go:build windows

package ddout

import (
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestOutputFileUsesCurrentUserOnlyDACL(t *testing.T) {
	resetForTest()
	path := filepath.Join(t.TempDir(), "result.txt")
	if err := appendToFile(path, "sensitive evidence"); err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("read output DACL: %v", err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatalf("read output DACL entries: %v", err)
	}
	if dacl.AceCount != 1 {
		t.Fatalf("output DACL ACE count = %d, want 1", dacl.AceCount)
	}
}
