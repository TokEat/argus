package main

import (
	"crypto/md5"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/glebarez/sqlite"
	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var baseManagedFiles = []string{
	"finger.yaml",
	"workflow.yaml",
	"dir.yaml",
	"pocs/",
}

type arsenalRow struct {
	ID       string `gorm:"primaryKey"`
	TenantID string `gorm:"default:'default';index"`
	Type     string `gorm:"index"`
	FileName string `gorm:"index"`
	Content  string `gorm:"type:text"`
	Hash     string
	State    string `gorm:"default:'Draft';index"`
	Version  int    `gorm:"default:1"`
}

func (arsenalRow) TableName() string { return "arsenals" }

type ExportSummary struct {
	ApprovedRows int
	ManagedFiles []string
	Warnings     []string
}

type DiffSummary struct {
	Added    []string
	Modified []string
	Deleted  []string
	Warnings []string
}

func (d DiffSummary) IsEmpty() bool {
	return len(d.Added)+len(d.Modified)+len(d.Deleted) == 0
}

type ApplyOptions struct {
	SeedDBPath string
	ConfigDir  string
	BackupRoot string
	Confirm    bool
}

type ApplySummary struct {
	ExportSummary
	Diff      DiffSummary
	BackupDir string
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		printUsage(stderr)
		return errors.New("missing command")
	}
	switch args[0] {
	case "diff":
		fs := flag.NewFlagSet("diff", flag.ContinueOnError)
		fs.SetOutput(stderr)
		seedDB := fs.String("seed-db", "", "path to arsenal_seed.db")
		configDir := fs.String("config", filepath.Join("scanner", "common", "config"), "path to scanner config dir")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if strings.TrimSpace(*seedDB) == "" {
			return errors.New("--seed-db is required")
		}
		diff, err := DiffSeedDBWithConfigDir(*seedDB, *configDir)
		if err != nil {
			return err
		}
		printDiff(stdout, diff)
		return nil
	case "export":
		fs := flag.NewFlagSet("export", flag.ContinueOnError)
		fs.SetOutput(stderr)
		seedDB := fs.String("seed-db", "", "path to arsenal_seed.db")
		outDir := fs.String("out", "", "output staging config dir")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if strings.TrimSpace(*seedDB) == "" || strings.TrimSpace(*outDir) == "" {
			return errors.New("--seed-db and --out are required")
		}
		summary, err := ExportSeedDBToConfigDir(*seedDB, *outDir)
		if err != nil {
			return err
		}
		printExportSummary(stdout, *outDir, summary)
		return nil
	case "apply":
		fs := flag.NewFlagSet("apply", flag.ContinueOnError)
		fs.SetOutput(stderr)
		seedDB := fs.String("seed-db", "", "path to arsenal_seed.db")
		configDir := fs.String("config", filepath.Join("scanner", "common", "config"), "path to scanner config dir")
		backupRoot := fs.String("backup-root", filepath.Join("data", "arsenal", "config-backups"), "backup root")
		yes := fs.Bool("yes", false, "confirm replacing managed config files")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if strings.TrimSpace(*seedDB) == "" {
			return errors.New("--seed-db is required")
		}
		summary, err := ApplySeedDBToConfigDir(ApplyOptions{
			SeedDBPath: *seedDB,
			ConfigDir:  *configDir,
			BackupRoot: *backupRoot,
			Confirm:    *yes,
		})
		if err != nil {
			return err
		}
		printApplySummary(stdout, summary)
		return nil
	default:
		printUsage(stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "usage:")
	fmt.Fprintln(w, "  go run ./tools/arsenal-sync diff --seed-db <path> --config scanner/common/config")
	fmt.Fprintln(w, "  go run ./tools/arsenal-sync export --seed-db <path> --out <staging-dir>")
	fmt.Fprintln(w, "  go run ./tools/arsenal-sync apply --seed-db <path> --config scanner/common/config --yes")
}

func printExportSummary(w io.Writer, outDir string, summary *ExportSummary) {
	fmt.Fprintf(w, "exported to %s\n", outDir)
	fmt.Fprintf(w, "approved managed rows: %d\n", summary.ApprovedRows)
	fmt.Fprintf(w, "managed files: %s\n", strings.Join(summary.ManagedFiles, ", "))
	for _, warning := range summary.Warnings {
		fmt.Fprintf(w, "warning: %s\n", warning)
	}
}

func printDiff(w io.Writer, diff DiffSummary) {
	for _, warning := range diff.Warnings {
		fmt.Fprintf(w, "warning: %s\n", warning)
	}
	if len(diff.Added)+len(diff.Modified)+len(diff.Deleted) == 0 {
		fmt.Fprintln(w, "no differences")
		return
	}
	for _, name := range diff.Added {
		fmt.Fprintf(w, "A %s\n", name)
	}
	for _, name := range diff.Modified {
		fmt.Fprintf(w, "M %s\n", name)
	}
	for _, name := range diff.Deleted {
		fmt.Fprintf(w, "D %s\n", name)
	}
}

func printApplySummary(w io.Writer, summary *ApplySummary) {
	fmt.Fprintf(w, "applied approved managed rows: %d\n", summary.ApprovedRows)
	if summary.BackupDir != "" {
		fmt.Fprintf(w, "backup: %s\n", summary.BackupDir)
	}
	printDiff(w, summary.Diff)
}

func ExportSeedDBToConfigDir(seedDBPath, outDir string) (*ExportSummary, error) {
	if strings.TrimSpace(seedDBPath) == "" {
		return nil, errors.New("seed db path is required")
	}
	if strings.TrimSpace(outDir) == "" {
		return nil, errors.New("output dir is required")
	}
	if err := ensureWritableOutputDir(outDir); err != nil {
		return nil, err
	}

	rows, err := loadApprovedArsenals(seedDBPath)
	if err != nil {
		return nil, err
	}

	summary, err := writeRowsToConfigDir(rows, outDir)
	if err != nil {
		_ = os.RemoveAll(outDir)
		return nil, err
	}
	return summary, nil
}

func DiffSeedDBWithConfigDir(seedDBPath, configDir string) (DiffSummary, error) {
	if strings.TrimSpace(configDir) == "" {
		configDir = filepath.Join("scanner", "common", "config")
	}
	stagingRoot, err := os.MkdirTemp("", "arsenal-sync-diff-*")
	if err != nil {
		return DiffSummary{}, fmt.Errorf("create diff staging dir: %w", err)
	}
	defer os.RemoveAll(stagingRoot)

	stagingDir := filepath.Join(stagingRoot, "config")
	summary, err := ExportSeedDBToConfigDir(seedDBPath, stagingDir)
	if err != nil {
		return DiffSummary{}, err
	}
	diff, err := compareConfigDirs(stagingDir, configDir, summary.ManagedFiles)
	if err != nil {
		return DiffSummary{}, err
	}
	diff.Warnings = append(diff.Warnings, summary.Warnings...)
	return diff, nil
}

func ApplySeedDBToConfigDir(opts ApplyOptions) (*ApplySummary, error) {
	if !opts.Confirm {
		return nil, errors.New("refusing to apply without --yes")
	}
	if strings.TrimSpace(opts.ConfigDir) == "" {
		opts.ConfigDir = filepath.Join("scanner", "common", "config")
	}
	if strings.TrimSpace(opts.BackupRoot) == "" {
		opts.BackupRoot = filepath.Join("data", "arsenal", "config-backups")
	}
	if err := validateBackupRoot(opts.ConfigDir, opts.BackupRoot); err != nil {
		return nil, err
	}

	stagingRoot, err := os.MkdirTemp("", "arsenal-sync-apply-*")
	if err != nil {
		return nil, fmt.Errorf("create apply staging dir: %w", err)
	}
	defer os.RemoveAll(stagingRoot)

	stagingDir := filepath.Join(stagingRoot, "config")
	exportSummary, err := ExportSeedDBToConfigDir(opts.SeedDBPath, stagingDir)
	if err != nil {
		return nil, err
	}
	diff, err := compareConfigDirs(stagingDir, opts.ConfigDir, exportSummary.ManagedFiles)
	if err != nil {
		return nil, err
	}
	if diff.IsEmpty() {
		return &ApplySummary{
			ExportSummary: *exportSummary,
			Diff:          diff,
		}, nil
	}
	backupDir, err := backupConfigDir(opts.ConfigDir, opts.BackupRoot)
	if err != nil {
		return nil, err
	}
	if err := activateConfigDir(stagingDir, opts.ConfigDir, exportSummary.ManagedFiles); err != nil {
		return nil, err
	}
	return &ApplySummary{
		ExportSummary: *exportSummary,
		Diff:          diff,
		BackupDir:     backupDir,
	}, nil
}

func loadApprovedArsenals(seedDBPath string) ([]arsenalRow, error) {
	info, err := os.Stat(seedDBPath)
	if err != nil {
		return nil, fmt.Errorf("stat seed db: %w", err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("seed db path is a directory: %s", seedDBPath)
	}
	database, err := gorm.Open(sqlite.Open(seedDBPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("open seed db: %w", err)
	}
	sqlDB, err := database.DB()
	if err != nil {
		return nil, fmt.Errorf("get seed db handle: %w", err)
	}
	defer sqlDB.Close()

	var rows []arsenalRow
	if err := database.
		Where("state = ?", "Approved").
		Order("type, file_name, version, id").
		Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("query approved arsenals: %w", err)
	}
	return rows, nil
}

func writeRowsToConfigDir(rows []arsenalRow, outDir string) (*ExportSummary, error) {
	if err := os.MkdirAll(filepath.Join(outDir, "pocs"), 0o755); err != nil {
		return nil, fmt.Errorf("create pocs dir: %w", err)
	}

	scalarRows := map[string]arsenalRow{}
	approvedRows := 0
	wroteDict := false
	wroteSubdomains := false
	warnings := []string{}
	for _, row := range rows {
		typ := canonicalArsenalType(row.Type)
		switch typ {
		case "finger", "workflow", "dir":
			target, ok := scalarTargetName(typ, row.FileName)
			if !ok {
				warnings = append(warnings, fmt.Sprintf("ignored unsupported %s file %q", typ, row.FileName))
				continue
			}
			scalarRows[target] = row
		case "poc":
			name, err := safePocFileName(row.FileName)
			if err != nil {
				return nil, err
			}
			if err := writeValidatedFile(filepath.Join(outDir, "pocs", name), []byte(row.Content)); err != nil {
				return nil, err
			}
			approvedRows++
		case "poc_asset":
			rel, err := safePocAssetPath(row.FileName)
			if err != nil {
				return nil, err
			}
			if err := writeFile(filepath.Join(outDir, "pocs", filepath.FromSlash(rel)), []byte(row.Content)); err != nil {
				return nil, err
			}
			approvedRows++
		case "config_asset":
			rel, root, err := safeConfigAssetPath(row.FileName)
			if err != nil {
				return nil, err
			}
			if err := writeFile(filepath.Join(outDir, filepath.FromSlash(rel)), []byte(row.Content)); err != nil {
				return nil, err
			}
			approvedRows++
			if root == "dict/" {
				wroteDict = true
			}
			if root == "subdomains.txt" {
				wroteSubdomains = true
			}
		default:
			continue
		}
	}

	for typ, target := range map[string]string{"finger": "finger.yaml", "workflow": "workflow.yaml", "dir": "dir.yaml"} {
		row, ok := scalarRows[target]
		if !ok {
			return nil, fmt.Errorf("approved %s rule %s not found in seed db", typ, target)
		}
		if err := writeValidatedFile(filepath.Join(outDir, target), []byte(row.Content)); err != nil {
			return nil, err
		}
		approvedRows++
	}

	managedFiles := append([]string(nil), baseManagedFiles...)
	if wroteDict {
		managedFiles = append(managedFiles, "dict/")
	} else {
		warnings = append(warnings, "seed db has no dict/*.txt config assets; existing dict/ will be preserved on apply")
	}
	if wroteSubdomains {
		managedFiles = append(managedFiles, "subdomains.txt")
	} else {
		warnings = append(warnings, "seed db has no subdomains.txt config asset; existing subdomains.txt will be preserved on apply")
	}

	sort.Strings(managedFiles)
	return &ExportSummary{
		ApprovedRows: approvedRows,
		ManagedFiles: managedFiles,
		Warnings:     warnings,
	}, nil
}

func scalarTargetName(typ, fileName string) (string, bool) {
	expected := typ + ".yaml"
	if typ == "finger" {
		expected = "finger.yaml"
	}
	clean := strings.TrimSpace(fileName)
	return expected, clean == expected
}

func ensureWritableOutputDir(outDir string) error {
	if _, err := os.Stat(outDir); err == nil {
		return fmt.Errorf("output dir must not already exist: %s", outDir)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat output dir: %w", err)
	}
	return os.MkdirAll(outDir, 0o755)
}

func compareConfigDirs(expectedDir, currentDir string, managedFiles []string) (DiffSummary, error) {
	expected, err := collectManagedFiles(expectedDir, managedFiles)
	if err != nil {
		return DiffSummary{}, fmt.Errorf("collect expected files: %w", err)
	}
	current, err := collectManagedFiles(currentDir, managedFiles)
	if err != nil {
		return DiffSummary{}, fmt.Errorf("collect current files: %w", err)
	}

	diff := DiffSummary{}
	for name, expectedHash := range expected {
		currentHash, ok := current[name]
		if !ok {
			diff.Added = append(diff.Added, name)
			continue
		}
		if currentHash != expectedHash {
			diff.Modified = append(diff.Modified, name)
		}
	}
	for name := range current {
		if _, ok := expected[name]; !ok {
			diff.Deleted = append(diff.Deleted, name)
		}
	}
	sort.Strings(diff.Added)
	sort.Strings(diff.Modified)
	sort.Strings(diff.Deleted)
	return diff, nil
}

func collectManagedFiles(root string, managedFiles []string) (map[string]string, error) {
	files := map[string]string{}
	if _, err := os.Stat(root); os.IsNotExist(err) {
		return files, nil
	} else if err != nil {
		return nil, err
	}
	for _, managed := range managedFiles {
		switch managed {
		case "finger.yaml", "workflow.yaml", "dir.yaml", "subdomains.txt":
			if err := collectFileHash(root, managed, files); err != nil {
				return nil, err
			}
		case "pocs/", "dict/":
			if err := collectDirHashes(root, strings.TrimSuffix(managed, "/"), files); err != nil {
				return nil, err
			}
		}
	}
	return files, nil
}

func collectFileHash(root, rel string, files map[string]string) error {
	fullPath := filepath.Join(root, filepath.FromSlash(rel))
	info, err := os.Lstat(fullPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to read symlink %s", fullPath)
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory", fullPath)
	}
	data, err := os.ReadFile(fullPath)
	if err != nil {
		return err
	}
	files[rel] = fmt.Sprintf("%x", md5.Sum(data))
	return nil
}

func collectDirHashes(root, relDir string, files map[string]string) error {
	fullDir := filepath.Join(root, filepath.FromSlash(relDir))
	info, err := os.Lstat(fullDir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to read symlink %s", fullDir)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", fullDir)
	}
	return filepath.WalkDir(fullDir, func(filePath string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if filePath == fullDir {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to read symlink %s", filePath)
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, filePath)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(filePath)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(rel)] = fmt.Sprintf("%x", md5.Sum(data))
		return nil
	})
}

func backupConfigDir(configDir, backupRoot string) (string, error) {
	info, err := os.Stat(configDir)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("stat config dir: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s exists but is not a directory", configDir)
	}
	backupDir := filepath.Join(backupRoot, time.Now().UTC().Format("20060102T150405.000000000"))
	if err := copyDir(configDir, filepath.Join(backupDir, "config")); err != nil {
		return "", fmt.Errorf("backup config dir: %w", err)
	}
	return backupDir, nil
}

func validateBackupRoot(configDir, backupRoot string) error {
	configAbs, err := filepath.Abs(configDir)
	if err != nil {
		return fmt.Errorf("resolve config dir: %w", err)
	}
	backupAbs, err := filepath.Abs(backupRoot)
	if err != nil {
		return fmt.Errorf("resolve backup root: %w", err)
	}
	configAbs = filepath.Clean(configAbs)
	backupAbs = filepath.Clean(backupAbs)
	if isSameOrSubpath(backupAbs, configAbs) {
		return fmt.Errorf("backup root must not be inside config dir: %s", backupRoot)
	}
	if realConfig, err := resolveExistingPath(configAbs); err == nil {
		if realBackup, err := resolveExistingPathForWrite(backupAbs); err == nil && isSameOrSubpath(realBackup, realConfig) {
			return fmt.Errorf("backup root must not resolve inside config dir: %s", backupRoot)
		}
	}
	return nil
}

func resolveExistingPath(pathValue string) (string, error) {
	real, err := filepath.EvalSymlinks(pathValue)
	if err != nil {
		return "", err
	}
	return filepath.Clean(real), nil
}

func resolveExistingPathForWrite(pathValue string) (string, error) {
	clean := filepath.Clean(pathValue)
	if real, err := filepath.EvalSymlinks(clean); err == nil {
		return filepath.Clean(real), nil
	}
	parts := []string{}
	current := clean
	for {
		if current == "." || current == string(filepath.Separator) || current == filepath.Dir(current) {
			break
		}
		if _, err := os.Lstat(current); err == nil {
			real, err := filepath.EvalSymlinks(current)
			if err != nil {
				return "", err
			}
			for i := len(parts) - 1; i >= 0; i-- {
				real = filepath.Join(real, parts[i])
			}
			return filepath.Clean(real), nil
		}
		parts = append(parts, filepath.Base(current))
		current = filepath.Dir(current)
	}
	return clean, nil
}

func isSameOrSubpath(candidate, root string) bool {
	rel, err := filepath.Rel(root, candidate)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel))
}

func activateConfigDir(stagingDir, configDir string, managedFiles []string) error {
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	for _, name := range []string{"finger.yaml", "workflow.yaml", "dir.yaml"} {
		if err := replaceFile(filepath.Join(stagingDir, name), filepath.Join(configDir, name)); err != nil {
			return err
		}
	}
	if err := replaceDir(filepath.Join(stagingDir, "pocs"), filepath.Join(configDir, "pocs")); err != nil {
		return err
	}
	if containsManaged(managedFiles, "dict/") {
		if err := replaceDir(filepath.Join(stagingDir, "dict"), filepath.Join(configDir, "dict")); err != nil {
			return err
		}
	}
	if containsManaged(managedFiles, "subdomains.txt") {
		if err := replaceFile(filepath.Join(stagingDir, "subdomains.txt"), filepath.Join(configDir, "subdomains.txt")); err != nil {
			return err
		}
	}
	return nil
}

func containsManaged(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func replaceFile(src, dst string) error {
	if err := rejectSymlink(dst); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fmt.Errorf("create parent dir for %s: %w", dst, err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), "."+filepath.Base(dst)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file for %s: %w", dst, err)
	}
	tmpPath := tmp.Name()
	if err := copyFileToWriter(src, tmp); err != nil {
		tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close temp file for %s: %w", dst, err)
	}
	_ = os.Remove(dst)
	if err := os.Rename(tmpPath, dst); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("replace %s: %w", dst, err)
	}
	return nil
}

func replaceDir(src, dst string) error {
	if err := rejectSymlink(dst); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fmt.Errorf("create parent dir for %s: %w", dst, err)
	}
	tmp, err := os.MkdirTemp(filepath.Dir(dst), "."+filepath.Base(dst)+".new-*")
	if err != nil {
		return fmt.Errorf("create temp dir for %s: %w", dst, err)
	}
	_ = os.RemoveAll(tmp)
	if err := copyDir(src, tmp); err != nil {
		_ = os.RemoveAll(tmp)
		return fmt.Errorf("copy replacement dir %s: %w", dst, err)
	}
	old := ""
	if _, err := os.Stat(dst); err == nil {
		old = filepath.Join(filepath.Dir(dst), "."+filepath.Base(dst)+".old-"+time.Now().UTC().Format("20060102T150405.000000000"))
		if err := os.Rename(dst, old); err != nil {
			_ = os.RemoveAll(tmp)
			return fmt.Errorf("move old dir %s: %w", dst, err)
		}
	} else if err != nil && !os.IsNotExist(err) {
		_ = os.RemoveAll(tmp)
		return fmt.Errorf("stat old dir %s: %w", dst, err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		if old != "" {
			_ = os.Rename(old, dst)
		}
		_ = os.RemoveAll(tmp)
		return fmt.Errorf("replace dir %s: %w", dst, err)
	}
	if old != "" {
		_ = os.RemoveAll(old)
	}
	return nil
}

func rejectSymlink(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to replace symlink %s", path)
	}
	return nil
}

func copyDir(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to copy symlink %s", src)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", src)
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to copy symlink %s", srcPath)
		}
		if entry.IsDir() {
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
			continue
		}
		if err := copyFile(srcPath, dstPath); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if err := copyFileToWriter(src, out); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func copyFileToWriter(src string, dst io.Writer) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer in.Close()
	if _, err := io.Copy(dst, in); err != nil {
		return fmt.Errorf("copy %s: %w", src, err)
	}
	return nil
}

func writeValidatedFile(path string, data []byte) error {
	if strings.HasSuffix(strings.ToLower(filepath.Base(path)), ".yaml") || strings.HasSuffix(strings.ToLower(filepath.Base(path)), ".yml") {
		var parsed any
		if err := yaml.Unmarshal(data, &parsed); err != nil {
			return fmt.Errorf("parse yaml %s: %w", path, err)
		}
	}
	return writeFile(path, data)
}

func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create parent dir for %s: %w", path, err)
	}
	return os.WriteFile(path, data, 0o644)
}

func safePocFileName(fileName string) (string, error) {
	raw := strings.TrimSpace(fileName)
	normalized := strings.ReplaceAll(raw, "\\", "/")
	if normalized == "" || path.IsAbs(normalized) {
		return "", fmt.Errorf("unsafe poc filename %q", fileName)
	}
	clean := path.Clean(normalized)
	if clean != normalized || clean == "." || clean == ".." || strings.Contains(clean, "/") {
		return "", fmt.Errorf("unsafe poc filename %q", fileName)
	}
	if !strings.HasSuffix(strings.ToLower(clean), ".yaml") && !strings.HasSuffix(strings.ToLower(clean), ".yml") {
		return "", fmt.Errorf("poc filename must be yaml %q", fileName)
	}
	return clean, nil
}

func safePocAssetPath(fileName string) (string, error) {
	raw := strings.TrimSpace(fileName)
	normalized := strings.ReplaceAll(raw, "\\", "/")
	if normalized == "" || path.IsAbs(normalized) {
		return "", fmt.Errorf("unsafe poc asset path %q", fileName)
	}
	clean := path.Clean(normalized)
	if clean != normalized || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../") {
		return "", fmt.Errorf("unsafe poc asset path %q", fileName)
	}
	if strings.HasSuffix(strings.ToLower(clean), ".yaml") || strings.HasSuffix(strings.ToLower(clean), ".yml") {
		return "", fmt.Errorf("poc asset path must not be a yaml template %q", fileName)
	}
	return clean, nil
}

func safeConfigAssetPath(fileName string) (relPath string, root string, err error) {
	raw := strings.TrimSpace(fileName)
	normalized := strings.ReplaceAll(raw, "\\", "/")
	if normalized == "" || path.IsAbs(normalized) {
		return "", "", fmt.Errorf("unsafe config asset path %q", fileName)
	}
	clean := path.Clean(normalized)
	if clean != normalized || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../") {
		return "", "", fmt.Errorf("unsafe config asset path %q", fileName)
	}
	if clean == "subdomains.txt" {
		return clean, "subdomains.txt", nil
	}
	if strings.HasPrefix(clean, "dict/") {
		name := strings.TrimPrefix(clean, "dict/")
		if name == "" || strings.Contains(name, "/") || path.Base(name) != name || !strings.HasSuffix(strings.ToLower(name), ".txt") {
			return "", "", fmt.Errorf("unsupported config asset path %q", fileName)
		}
		return clean, "dict/", nil
	}
	return "", "", fmt.Errorf("unsupported config asset path %q", fileName)
}

func canonicalArsenalType(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "finger", "fingerprint":
		return "finger"
	case "workflow":
		return "workflow"
	case "dir", "dirprobe":
		return "dir"
	case "poc":
		return "poc"
	case "poc_asset", "pocasset":
		return "poc_asset"
	case "config_asset", "configasset", "dict_asset", "dictasset":
		return "config_asset"
	default:
		return strings.ToLower(strings.TrimSpace(raw))
	}
}
