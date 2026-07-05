package arsenal

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var managedRuleFiles = []string{
	"finger.yaml",
	"workflow.yaml",
	"dir.yaml",
	"pocs/",
}

type MaterializeOptions struct {
	DBPath      string
	ConfigDir   string
	BackupRoot  string
	Hash        string
	RuleVersion string
	BackupLimit int
}

type RulePackageCounts struct {
	Fingerprints int `json:"fingerprints"`
	Workflows    int `json:"workflows"`
	DirProbes    int `json:"dir_probes"`
	Pocs         int `json:"pocs"`
	PocAssets    int `json:"poc_assets"`
	ConfigAssets int `json:"config_assets"`
}

type RulePackageManifest struct {
	Hash           string            `json:"hash"`
	RuleVersion    string            `json:"rule_version"`
	MaterializedAt string            `json:"materialized_at"`
	ManagedFiles   []string          `json:"managed_files"`
	Counts         RulePackageCounts `json:"counts"`
}

type PreparedRulePackage struct {
	StagingConfigDir string
	ConfigDir        string
	BackupRoot       string
	BackupLimit      int
	Manifest         RulePackageManifest
}

func MaterializeRulePackage(opts MaterializeOptions) error {
	prepared, err := PrepareRulePackage(opts)
	if err != nil {
		return err
	}
	return ActivatePreparedRulePackage(prepared)
}

func PrepareRulePackage(opts MaterializeOptions) (*PreparedRulePackage, error) {
	opts = withMaterializeDefaults(opts)
	if strings.TrimSpace(opts.Hash) == "" {
		return nil, fmt.Errorf("rule package hash is required")
	}
	if err := OpenDB(opts.DBPath); err != nil {
		return nil, fmt.Errorf("open arsenal db: %w", err)
	}
	if !IsDBReady() {
		return nil, fmt.Errorf("arsenal db is empty or not ready")
	}

	packageRoot := filepath.Join(filepath.Dir(opts.BackupRoot), "staging", safePathPart(opts.Hash)+"-"+time.Now().UTC().Format("20060102T150405.000000000"))
	stagingConfigDir := filepath.Join(packageRoot, "config")
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(packageRoot)
		}
	}()

	if err := os.MkdirAll(filepath.Join(stagingConfigDir, "pocs"), 0o755); err != nil {
		return nil, fmt.Errorf("create staging config: %w", err)
	}

	fingerYAML, err := ExportFingerYAML()
	if err != nil {
		return nil, err
	}
	workflowYAML, err := ExportWorkflowYAML()
	if err != nil {
		return nil, err
	}
	dirYAML, err := ExportDirYAML()
	if err != nil {
		return nil, err
	}

	if err := os.WriteFile(filepath.Join(stagingConfigDir, "finger.yaml"), fingerYAML, 0o644); err != nil {
		return nil, fmt.Errorf("write staging finger.yaml: %w", err)
	}
	if err := os.WriteFile(filepath.Join(stagingConfigDir, "workflow.yaml"), workflowYAML, 0o644); err != nil {
		return nil, fmt.Errorf("write staging workflow.yaml: %w", err)
	}
	if err := os.WriteFile(filepath.Join(stagingConfigDir, "dir.yaml"), dirYAML, 0o644); err != nil {
		return nil, fmt.Errorf("write staging dir.yaml: %w", err)
	}

	pocs, err := GetAllEnabledPocs()
	if err != nil {
		return nil, fmt.Errorf("query pocs: %w", err)
	}
	writtenPocs := 0
	for _, poc := range pocs {
		if strings.TrimSpace(poc.FileName) == "" || poc.Content == "" {
			continue
		}
		fileName, err := safePocFileName(poc.FileName)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(stagingConfigDir, "pocs", fileName), []byte(poc.Content), 0o644); err != nil {
			return nil, fmt.Errorf("write staging poc %s: %w", fileName, err)
		}
		writtenPocs++
	}

	assets, err := GetAllEnabledPocAssets()
	if err != nil {
		return nil, fmt.Errorf("query poc assets: %w", err)
	}
	writtenAssets := 0
	for _, asset := range assets {
		if strings.TrimSpace(asset.RelativePath) == "" || asset.Content == "" {
			continue
		}
		relPath, err := safePocAssetPath(asset.RelativePath)
		if err != nil {
			return nil, err
		}
		dst := filepath.Join(stagingConfigDir, "pocs", filepath.FromSlash(relPath))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return nil, fmt.Errorf("create staging poc asset dir %s: %w", relPath, err)
		}
		if err := os.WriteFile(dst, []byte(asset.Content), 0o644); err != nil {
			return nil, fmt.Errorf("write staging poc asset %s: %w", relPath, err)
		}
		writtenAssets++
	}

	configAssets, err := GetAllEnabledConfigAssets()
	if err != nil {
		return nil, fmt.Errorf("query config assets: %w", err)
	}
	writtenConfigAssets := 0
	wroteDictAssets := false
	wroteSubdomains := false
	for _, asset := range configAssets {
		if strings.TrimSpace(asset.RelativePath) == "" || asset.Content == "" {
			continue
		}
		relPath, root, err := safeConfigAssetPath(asset.RelativePath)
		if err != nil {
			return nil, err
		}
		dst := filepath.Join(stagingConfigDir, filepath.FromSlash(relPath))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return nil, fmt.Errorf("create staging config asset dir %s: %w", relPath, err)
		}
		if err := os.WriteFile(dst, []byte(asset.Content), 0o644); err != nil {
			return nil, fmt.Errorf("write staging config asset %s: %w", relPath, err)
		}
		writtenConfigAssets++
		switch root {
		case "dict/":
			wroteDictAssets = true
		case "subdomains.txt":
			wroteSubdomains = true
		}
	}

	fingers, err := GetAllEnabledFingerprints()
	if err != nil {
		return nil, fmt.Errorf("query fingerprints: %w", err)
	}
	workflows, err := GetAllEnabledWorkflows()
	if err != nil {
		return nil, fmt.Errorf("query workflows: %w", err)
	}
	probes, err := GetAllEnabledDirProbes()
	if err != nil {
		return nil, fmt.Errorf("query dir probes: %w", err)
	}

	managedFiles := append([]string(nil), managedRuleFiles...)
	if wroteDictAssets {
		managedFiles = append(managedFiles, "dict/")
	}
	if wroteSubdomains {
		managedFiles = append(managedFiles, "subdomains.txt")
	}

	cleanup = false
	return &PreparedRulePackage{
		StagingConfigDir: stagingConfigDir,
		ConfigDir:        opts.ConfigDir,
		BackupRoot:       opts.BackupRoot,
		BackupLimit:      opts.BackupLimit,
		Manifest: RulePackageManifest{
			Hash:           opts.Hash,
			RuleVersion:    opts.RuleVersion,
			MaterializedAt: time.Now().UTC().Format(time.RFC3339Nano),
			ManagedFiles:   managedFiles,
			Counts: RulePackageCounts{
				Fingerprints: len(fingers),
				Workflows:    len(workflows),
				DirProbes:    len(probes),
				Pocs:         writtenPocs,
				PocAssets:    writtenAssets,
				ConfigAssets: writtenConfigAssets,
			},
		},
	}, nil
}

func ActivatePreparedRulePackage(prepared *PreparedRulePackage) error {
	if prepared == nil {
		return fmt.Errorf("prepared rule package is nil")
	}
	packageRoot := filepath.Dir(prepared.StagingConfigDir)
	defer os.RemoveAll(packageRoot)

	if err := backupConfigDir(prepared.ConfigDir, prepared.BackupRoot); err != nil {
		return err
	}
	if err := os.MkdirAll(prepared.ConfigDir, 0o755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	for _, name := range []string{"finger.yaml", "workflow.yaml", "dir.yaml"} {
		if err := replaceFile(filepath.Join(prepared.StagingConfigDir, name), filepath.Join(prepared.ConfigDir, name)); err != nil {
			return err
		}
	}
	if err := replaceDir(filepath.Join(prepared.StagingConfigDir, "pocs"), filepath.Join(prepared.ConfigDir, "pocs")); err != nil {
		return err
	}
	if info, err := os.Stat(filepath.Join(prepared.StagingConfigDir, "dict")); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("staging dict is not a directory")
		}
		if err := replaceDir(filepath.Join(prepared.StagingConfigDir, "dict"), filepath.Join(prepared.ConfigDir, "dict")); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat staging dict: %w", err)
	}
	if info, err := os.Stat(filepath.Join(prepared.StagingConfigDir, "subdomains.txt")); err == nil {
		if info.IsDir() {
			return fmt.Errorf("staging subdomains.txt is a directory")
		}
		if err := replaceFile(filepath.Join(prepared.StagingConfigDir, "subdomains.txt"), filepath.Join(prepared.ConfigDir, "subdomains.txt")); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat staging subdomains.txt: %w", err)
	}
	if err := writeManifest(prepared.ConfigDir, prepared.Manifest); err != nil {
		return err
	}
	if err := pruneBackups(prepared.BackupRoot, prepared.BackupLimit); err != nil {
		return err
	}
	return nil
}

func IsRulePackageMaterialized(configDir, hash string) bool {
	if strings.TrimSpace(configDir) == "" {
		configDir = "config"
	}
	if !HasUsableRuleFiles(configDir) {
		return false
	}
	data, err := os.ReadFile(filepath.Join(configDir, ".argus-arsenal.json"))
	if err != nil {
		return false
	}
	var manifest RulePackageManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return false
	}
	return manifest.Hash == hash
}

func HasUsableRuleFiles(configDir string) bool {
	if strings.TrimSpace(configDir) == "" {
		configDir = "config"
	}
	for _, name := range []string{"finger.yaml", "workflow.yaml", "dir.yaml"} {
		info, err := os.Stat(filepath.Join(configDir, name))
		if err != nil || info.IsDir() || info.Size() == 0 {
			return false
		}
	}
	info, err := os.Stat(filepath.Join(configDir, "pocs"))
	return err == nil && info.IsDir()
}

func withMaterializeDefaults(opts MaterializeOptions) MaterializeOptions {
	if opts.DBPath == "" {
		opts.DBPath = DefaultDBPath
	}
	if opts.ConfigDir == "" {
		opts.ConfigDir = "config"
	}
	if opts.BackupRoot == "" {
		opts.BackupRoot = filepath.Join("data", "arsenal", "backups")
	}
	if opts.BackupLimit <= 0 {
		opts.BackupLimit = 3
	}
	return opts
}

func backupConfigDir(configDir, backupRoot string) error {
	info, err := os.Stat(configDir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat config dir: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s exists but is not a directory", configDir)
	}
	backupDir := filepath.Join(backupRoot, time.Now().UTC().Format("20060102T150405.000000000"), "config")
	if err := copyDir(configDir, backupDir); err != nil {
		return fmt.Errorf("backup config dir: %w", err)
	}
	return nil
}

func replaceFile(src, dst string) error {
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
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("close temp file for %s: %w", dst, err)
	}
	_ = os.Remove(dst)
	if err := os.Rename(tmpPath, dst); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("replace %s: %w", dst, err)
	}
	return nil
}

func replaceDir(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fmt.Errorf("create parent dir for %s: %w", dst, err)
	}
	tmp, err := os.MkdirTemp(filepath.Dir(dst), "."+filepath.Base(dst)+".new-*")
	if err != nil {
		return fmt.Errorf("create temp dir for %s: %w", dst, err)
	}
	if err := os.Remove(tmp); err != nil {
		return fmt.Errorf("remove temp placeholder %s: %w", tmp, err)
	}
	if err := copyDir(src, tmp); err != nil {
		os.RemoveAll(tmp)
		return fmt.Errorf("copy replacement dir %s: %w", dst, err)
	}

	old := ""
	if _, err := os.Stat(dst); err == nil {
		old = filepath.Join(filepath.Dir(dst), "."+filepath.Base(dst)+".old-"+time.Now().UTC().Format("20060102T150405.000000000"))
		if err := os.Rename(dst, old); err != nil {
			os.RemoveAll(tmp)
			return fmt.Errorf("move old dir %s: %w", dst, err)
		}
	}
	if err := os.Rename(tmp, dst); err != nil {
		if old != "" {
			_ = os.Rename(old, dst)
		}
		os.RemoveAll(tmp)
		return fmt.Errorf("replace dir %s: %w", dst, err)
	}
	if old != "" {
		_ = os.RemoveAll(old)
	}
	return nil
}

func writeManifest(configDir string, manifest RulePackageManifest) error {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal rule package manifest: %w", err)
	}
	data = append(data, '\n')
	return writeFileAtomic(filepath.Join(configDir, ".argus-arsenal.json"), data, 0o644)
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create parent dir for %s: %w", path, err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file for %s: %w", path, err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("write temp file for %s: %w", path, err)
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("chmod temp file for %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("close temp file for %s: %w", path, err)
	}
	_ = os.Remove(path)
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}

func copyDir(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
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
		if entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())
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
		out.Close()
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

func pruneBackups(backupRoot string, keep int) error {
	if keep <= 0 {
		keep = 3
	}
	entries, err := os.ReadDir(backupRoot)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read backup root: %w", err)
	}
	var dirs []string
	for _, entry := range entries {
		if entry.IsDir() {
			dirs = append(dirs, entry.Name())
		}
	}
	sort.Strings(dirs)
	if len(dirs) <= keep {
		return nil
	}
	for _, name := range dirs[:len(dirs)-keep] {
		if err := os.RemoveAll(filepath.Join(backupRoot, name)); err != nil {
			return fmt.Errorf("remove old backup %s: %w", name, err)
		}
	}
	return nil
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

func safePathPart(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	var b strings.Builder
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}
