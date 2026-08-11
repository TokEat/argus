// Package localarsenal activates the standalone CLI's offline rule package.
// It never downloads rules and is not used by Server-managed Agents.
package localarsenal

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/P0lar1ght/argus/scanner/internal/arsenal"
	"github.com/P0lar1ght/argus/scanner/internal/localstate"
)

const BackupLimit = 3

type Activation struct {
	Active       bool
	DBPath       string
	ConfigDir    string
	FileHash     string
	RuleVersion  string
	ImportedFrom string
}

type Layout struct {
	Root         string
	DBPath       string
	ConfigDir    string
	BackupRoot   string
	PackageStore string
	LockPath     string
}

type packageCandidate struct {
	path          string
	failIfInvalid bool
}

func ResolveLayout(homeRoot string) Layout {
	root := filepath.Join(filepath.Clean(homeRoot), "arsenal")
	return Layout{
		Root: root, DBPath: filepath.Join(root, "arsenal.db"), ConfigDir: filepath.Join(root, "config"),
		BackupRoot: filepath.Join(root, "backups"), PackageStore: filepath.Join(root, "packages"),
		LockPath: filepath.Join(root, ".package.lock"),
	}
}

// Prepare validates and activates the fixed offline package. When ARGUS_HOME
// points elsewhere, the release package beside the executable is imported once.
// A legacy ./data/arsenal.db is accepted only when the fixed path is empty and
// the full runtime-package validation succeeds.
func Prepare(homeRoot string) (Activation, error) {
	layout := ResolveLayout(homeRoot)
	if err := os.MkdirAll(layout.Root, 0o700); err != nil {
		return Activation{}, fmt.Errorf("create local arsenal directory: %w", err)
	}
	lock, err := localstate.AcquireExclusiveFileLock(layout.LockPath)
	if err != nil {
		return Activation{}, err
	}
	defer lock.Close()

	candidates := make([]packageCandidate, 0, 2)
	if executable, execErr := os.Executable(); execErr == nil {
		shipped := filepath.Join(filepath.Dir(executable), localstate.DefaultHomeName, "arsenal", "arsenal.db")
		if !samePath(shipped, layout.DBPath) {
			candidates = append(candidates, packageCandidate{path: shipped, failIfInvalid: true})
		}
	}
	if workingDir, cwdErr := os.Getwd(); cwdErr == nil {
		legacy := filepath.Join(workingDir, "data", "arsenal.db")
		if !samePath(legacy, layout.DBPath) {
			candidates = append(candidates, packageCandidate{path: legacy})
		}
	}
	return prepareLocked(layout, candidates)
}

func prepareLocked(layout Layout, candidates []packageCandidate) (Activation, error) {
	activation := Activation{DBPath: layout.DBPath, ConfigDir: layout.ConfigDir}
	if _, err := os.Lstat(layout.DBPath); os.IsNotExist(err) {
		for _, candidate := range candidates {
			if _, candidateErr := os.Lstat(candidate.path); candidateErr != nil {
				continue
			}
			if _, candidateErr := arsenal.InspectRulePackage(candidate.path); candidateErr != nil {
				if candidate.failIfInvalid {
					return activation, fmt.Errorf("validate shipped offline arsenal package: %w", candidateErr)
				}
				continue
			}
			if copyErr := copyFileAtomic(candidate.path, layout.DBPath); copyErr != nil {
				return activation, fmt.Errorf("import offline arsenal package: %w", copyErr)
			}
			activation.ImportedFrom = candidate.path
			break
		}
	} else if err != nil {
		return activation, fmt.Errorf("inspect local arsenal package: %w", err)
	}
	if _, err := os.Lstat(layout.DBPath); os.IsNotExist(err) {
		return activation, nil
	} else if err != nil {
		return activation, fmt.Errorf("inspect local arsenal package: %w", err)
	}

	fileHash, err := arsenal.HashRulePackageFile(layout.DBPath)
	if err != nil {
		return activation, err
	}
	if arsenal.IsRulePackageMaterialized(layout.ConfigDir, fileHash) {
		manifest, manifestErr := arsenal.ReadRulePackageManifest(layout.ConfigDir)
		if manifestErr != nil {
			return activation, fmt.Errorf("read local arsenal manifest: %w", manifestErr)
		}
		activation.Active = true
		activation.FileHash = fileHash
		activation.RuleVersion = manifest.RuleVersion
		if err := snapshotPackage(layout, fileHash); err != nil {
			return activation, fmt.Errorf("snapshot local arsenal package: %w", err)
		}
		if err := prunePackageSnapshots(layout.PackageStore, BackupLimit); err != nil {
			return activation, err
		}
		return activation, nil
	}

	inspection, err := arsenal.InspectRulePackage(layout.DBPath)
	if err != nil {
		return activation, fmt.Errorf("validate local arsenal package: %w", err)
	}
	if err := arsenal.MaterializeRulePackage(arsenal.MaterializeOptions{
		DBPath: layout.DBPath, ConfigDir: layout.ConfigDir, BackupRoot: layout.BackupRoot,
		Hash: inspection.FileHash, RuleVersion: inspection.RuleVersion, BackupLimit: BackupLimit,
	}); err != nil {
		return activation, fmt.Errorf("materialize local arsenal package: %w", err)
	}
	if err := snapshotPackage(layout, inspection.FileHash); err != nil {
		return activation, fmt.Errorf("snapshot local arsenal package: %w", err)
	}
	if err := prunePackageSnapshots(layout.PackageStore, BackupLimit); err != nil {
		return activation, err
	}
	activation.Active = true
	activation.FileHash = inspection.FileHash
	activation.RuleVersion = inspection.RuleVersion
	return activation, nil
}

func snapshotPackage(layout Layout, hash string) error {
	destination := filepath.Join(layout.PackageStore, hash, "arsenal.db")
	if info, err := os.Lstat(destination); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("arsenal package snapshot must be a regular non-symlink file")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	return copyFileAtomic(layout.DBPath, destination)
}

func prunePackageSnapshots(root string, keep int) error {
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read arsenal package snapshots: %w", err)
	}
	type snapshot struct {
		name string
		time int64
	}
	items := make([]snapshot, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			return infoErr
		}
		items = append(items, snapshot{name: entry.Name(), time: info.ModTime().UnixNano()})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].time < items[j].time })
	for len(items) > keep {
		if err := os.RemoveAll(filepath.Join(root, items[0].name)); err != nil {
			return fmt.Errorf("remove old arsenal package snapshot: %w", err)
		}
		items = items[1:]
	}
	return nil
}

func copyFileAtomic(source, destination string) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("source package must be a regular non-symlink file")
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(destination), ".arsenal.db.tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := io.Copy(tmp, in); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if _, err := os.Stat(destination); err == nil {
		return fmt.Errorf("destination package already exists")
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(tmpPath, destination); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func samePath(left, right string) bool {
	leftAbs, leftErr := filepath.Abs(filepath.Clean(left))
	rightAbs, rightErr := filepath.Abs(filepath.Clean(right))
	if leftErr != nil || rightErr != nil {
		return false
	}
	return strings.EqualFold(leftAbs, rightAbs)
}
