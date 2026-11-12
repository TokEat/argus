//go:build !windows

package report

import "os"

func protectReportFile(path string) error {
	return os.Chmod(path, 0o600)
}
