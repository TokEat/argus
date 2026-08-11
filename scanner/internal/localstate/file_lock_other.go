//go:build !windows

package localstate

import (
	"errors"
	"os"
	"syscall"
)

func lockFile(file *os.File, nonblocking bool) (bool, error) {
	operation := syscall.LOCK_EX
	if nonblocking {
		operation |= syscall.LOCK_NB
	}
	err := syscall.Flock(int(file.Fd()), operation)
	if nonblocking && (errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN)) {
		return false, nil
	}
	return err == nil, err
}

func unlockFile(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
}
