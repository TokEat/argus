package localstate

import (
	"fmt"
	"os"
)

// ExclusiveFileLock is a small cross-platform process lock used by CLI-local
// state components. It never crosses the standalone CLI boundary.
type ExclusiveFileLock struct {
	file *os.File
}

// AcquireExclusiveFileLock waits for an exclusive lock on path.
func AcquireExclusiveFileLock(path string) (*ExclusiveFileLock, error) {
	file, locked, err := acquireFileLock(path, false)
	if err != nil {
		return nil, err
	}
	if !locked {
		return nil, fmt.Errorf("exclusive lock %q was not acquired", path)
	}
	return &ExclusiveFileLock{file: file}, nil
}

// Close releases the process lock.
func (lock *ExclusiveFileLock) Close() error {
	if lock == nil {
		return nil
	}
	file := lock.file
	lock.file = nil
	return releaseFileLock(file)
}

func acquireFileLock(path string, nonblocking bool) (*os.File, bool, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, false, fmt.Errorf("open lock %q: %w", path, err)
	}
	locked, err := lockFile(file, nonblocking)
	if err != nil {
		_ = file.Close()
		return nil, false, fmt.Errorf("lock %q: %w", path, err)
	}
	if !locked {
		_ = file.Close()
		return nil, false, nil
	}
	return file, true, nil
}

func releaseFileLock(file *os.File) error {
	if file == nil {
		return nil
	}
	unlockErr := unlockFile(file)
	closeErr := file.Close()
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
