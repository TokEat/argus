package localstate

import (
	"fmt"
	"os"
	"path/filepath"
)

func writeFileAtomic(path string, contents []byte, mode os.FileMode) error {
	return writeFileAtomicWith(path, contents, mode, replaceFileAtomic)
}

func writeFileAtomicWith(path string, contents []byte, mode os.FileMode, replace func(string, string) error) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary file for %s: %w", filepath.Base(path), err)
	}
	temporaryPath := temporary.Name()
	keepTemporary := true
	defer func() {
		_ = temporary.Close()
		if keepTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(mode); err != nil {
		return fmt.Errorf("set temporary file mode for %s: %w", filepath.Base(path), err)
	}
	if _, err := temporary.Write(contents); err != nil {
		return fmt.Errorf("write temporary file for %s: %w", filepath.Base(path), err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary file for %s: %w", filepath.Base(path), err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary file for %s: %w", filepath.Base(path), err)
	}
	if err := replace(temporaryPath, path); err != nil {
		return fmt.Errorf("replace %s: %w", filepath.Base(path), err)
	}
	keepTemporary = false
	if err := syncDirectory(directory); err != nil {
		return fmt.Errorf("sync directory for %s: %w", filepath.Base(path), err)
	}
	return nil
}
