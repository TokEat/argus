// Package localstate owns CLI-only local run metadata and the compatibility
// root used by explicit offline arsenal commands. It does not upload state and
// is not used by Server-managed Agents.
package localstate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	HomeEnvironment = "ARGUS_HOME"
	DefaultHomeName = "argus-data"
)

// Home describes the stable compatibility root reserved for explicit offline
// arsenal management and legacy local-state helpers. Ordinary scan runs write
// their evidence under datas/<run> instead of this root.
type Home struct {
	Root string
}

// Resolve returns the CLI history root without changing the filesystem.
func Resolve() (Home, error) {
	executablePath, err := os.Executable()
	if err != nil {
		return Home{}, fmt.Errorf("resolve Argus executable: %w", err)
	}
	workingDir, _ := os.Getwd()
	root, err := resolveHome(executablePath, os.Getenv(HomeEnvironment), workingDir)
	if err != nil {
		return Home{}, err
	}
	return Home{Root: root}, nil
}

// Ensure resolves and creates the private CLI history root. Existing roots are
// preserved; this function never removes or rewrites user data.
func Ensure() (Home, error) {
	home, err := Resolve()
	if err != nil {
		return Home{}, err
	}
	if err := os.MkdirAll(home.Root, 0o700); err != nil {
		return Home{}, fmt.Errorf("create Argus data directory %q: %w", home.Root, err)
	}
	info, err := os.Stat(home.Root)
	if err != nil {
		return Home{}, fmt.Errorf("inspect Argus data directory %q: %w", home.Root, err)
	}
	if !info.IsDir() {
		return Home{}, fmt.Errorf("Argus data path %q is not a directory", home.Root)
	}
	return home, nil
}

func resolveHome(executablePath, override, workingDir string) (string, error) {
	normalizedWorkingDir := func() (string, error) {
		workingDir = strings.TrimSpace(workingDir)
		if workingDir == "" {
			return "", fmt.Errorf("current directory is unavailable for a relative Argus data path")
		}
		absolute, err := filepath.Abs(workingDir)
		if err != nil {
			return "", fmt.Errorf("normalize current directory: %w", err)
		}
		return absolute, nil
	}

	if override = strings.TrimSpace(override); override != "" {
		if !filepath.IsAbs(override) {
			base, err := normalizedWorkingDir()
			if err != nil {
				return "", err
			}
			override = filepath.Join(base, override)
		}
		root, err := filepath.Abs(filepath.Clean(override))
		if err != nil {
			return "", fmt.Errorf("normalize %s: %w", HomeEnvironment, err)
		}
		return root, nil
	}

	executablePath = strings.TrimSpace(executablePath)
	if executablePath == "" {
		return "", fmt.Errorf("Argus executable path is empty")
	}
	if !filepath.IsAbs(executablePath) {
		base, err := normalizedWorkingDir()
		if err != nil {
			return "", err
		}
		executablePath = filepath.Join(base, executablePath)
	}
	executablePath, err := filepath.Abs(filepath.Clean(executablePath))
	if err != nil {
		return "", fmt.Errorf("normalize Argus executable path: %w", err)
	}
	// Prefer the real binary location for symlink-based installations, but do
	// not fail startup if the executable was atomically replaced after launch.
	if resolved, evalErr := filepath.EvalSymlinks(executablePath); evalErr == nil {
		executablePath = resolved
	}
	return filepath.Join(filepath.Dir(executablePath), DefaultHomeName), nil
}
