package report

import (
	"path/filepath"
	"runtime"
	"strings"
)

func pathsEqual(left, right string) bool {
	if strings.TrimSpace(left) == "" || strings.TrimSpace(right) == "" {
		return false
	}
	leftAbsolute, leftErr := filepath.Abs(left)
	rightAbsolute, rightErr := filepath.Abs(right)
	if leftErr != nil || rightErr != nil {
		return false
	}
	leftAbsolute = filepath.Clean(leftAbsolute)
	rightAbsolute = filepath.Clean(rightAbsolute)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(leftAbsolute, rightAbsolute)
	}
	return leftAbsolute == rightAbsolute
}
