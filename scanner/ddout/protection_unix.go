//go:build !windows

package ddout

import "os"

func protectOutputFile(path string) error {
	return os.Chmod(path, 0o600)
}
