//go:build windows

package report

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestProtectReportFileUsesCurrentUserOnlyDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.part")
	if err := os.WriteFile(path, []byte("sensitive evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := protectReportFile(path); err != nil {
		t.Fatalf("protect report file: %v", err)
	}
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatalf("read report DACL: %v", err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatalf("read report DACL entries: %v", err)
	}
	if dacl.AceCount != 1 {
		t.Fatalf("report DACL ACE count = %d, want 1", dacl.AceCount)
	}
}
