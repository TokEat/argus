package arsenal

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
)

const (
	RulePackageSchemaVersion = "argus-arsenal-package/v1"
	MaxRulePackageSize       = int64(4 << 30)
)

type RulePackageInspection struct {
	SchemaVersion string
	RuleVersion   string
	FileHash      string
	Counts        RulePackageCounts
}

// HashRulePackageFile validates the outer file boundary and returns its SHA-256
// identity. This cheap identity is used to skip repeat SQLite materialization;
// RuleVersion below remains a semantic content identity.
func HashRulePackageFile(dbPath string) (string, error) {
	info, err := os.Lstat(dbPath)
	if err != nil {
		return "", fmt.Errorf("inspect arsenal package: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", fmt.Errorf("arsenal package must be a regular non-symlink file")
	}
	if info.Size() <= 16 || info.Size() > MaxRulePackageSize {
		return "", fmt.Errorf("arsenal package size %d is outside the supported range", info.Size())
	}
	file, err := os.Open(dbPath)
	if err != nil {
		return "", fmt.Errorf("open arsenal package: %w", err)
	}
	defer file.Close()
	header := make([]byte, 16)
	if _, err := io.ReadFull(file, header); err != nil {
		return "", fmt.Errorf("read arsenal package header: %w", err)
	}
	if string(header) != "SQLite format 3\x00" {
		return "", fmt.Errorf("arsenal package is not a SQLite 3 database")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", fmt.Errorf("rewind arsenal package: %w", err)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("hash arsenal package: %w", err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// InspectRulePackage validates the runtime schema and produces a stable rule
// version from scan-relevant content. IDs, timestamps, row order and source
// labels are deliberately excluded so Server, Agent and CLI packages built
// from the same rules share the same semantic identity.
func InspectRulePackage(dbPath string) (inspection RulePackageInspection, err error) {
	inspection.SchemaVersion = RulePackageSchemaVersion
	inspection.FileHash, err = HashRulePackageFile(dbPath)
	if err != nil {
		return inspection, err
	}
	if err := OpenExistingDB(dbPath); err != nil {
		return inspection, err
	}
	defer func() {
		if closeErr := CloseDB(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()

	required := []any{&Fingerprint{}, &Poc{}, &PocAsset{}, &ConfigAsset{}, &Workflow{}, &DirProbe{}}
	for _, model := range required {
		if !DB.Migrator().HasTable(model) {
			return inspection, fmt.Errorf("arsenal package is missing required table for %T", model)
		}
	}

	var fingers []Fingerprint
	var pocs []Poc
	var pocAssets []PocAsset
	var configAssets []ConfigAsset
	var workflows []Workflow
	var probes []DirProbe
	queries := []struct {
		label string
		out   any
		order string
	}{
		{"fingerprints", &fingers, "product_name, rule_expr"},
		{"pocs", &pocs, "name, file_name"},
		{"poc assets", &pocAssets, "relative_path"},
		{"config assets", &configAssets, "relative_path"},
		{"workflows", &workflows, "product_name, poc_name, match_type"},
		{"dir probes", &probes, "path, product_name"},
	}
	for _, query := range queries {
		if queryErr := DB.Where("enabled = ?", true).Order(query.order).Find(query.out).Error; queryErr != nil {
			return inspection, fmt.Errorf("query %s: %w", query.label, queryErr)
		}
	}
	if len(fingers) == 0 || len(workflows) == 0 || len(probes) == 0 {
		return inspection, fmt.Errorf("arsenal package is incomplete: fingerprints=%d workflows=%d dir_probes=%d", len(fingers), len(workflows), len(probes))
	}

	inspection.Counts = RulePackageCounts{
		Fingerprints: len(fingers), Workflows: len(workflows), DirProbes: len(probes),
		Pocs: len(pocs), PocAssets: len(pocAssets), ConfigAssets: len(configAssets),
	}
	digest := sha256.New()
	writeSemantic := func(parts ...string) {
		for _, part := range parts {
			_, _ = fmt.Fprintf(digest, "%d:%s", len(part), part)
		}
	}
	for _, item := range fingers {
		writeSemantic("finger", item.ProductName, item.RuleExpr, item.Category, item.Tags)
	}
	for _, item := range pocs {
		class := strings.ToLower(strings.TrimSpace(item.ExecutionClass))
		risk := strings.ToLower(strings.TrimSpace(item.RiskLevel))
		if class == "" {
			class = "detection"
		}
		if risk == "" {
			risk = "unknown"
		}
		if class != "detection" && class != "verification" {
			return inspection, fmt.Errorf("POC %q has forbidden execution class %q", item.Name, item.ExecutionClass)
		}
		switch risk {
		case "unknown", "low", "medium", "high":
		default:
			return inspection, fmt.Errorf("POC %q has unsupported risk level %q", item.Name, item.RiskLevel)
		}
		if _, pathErr := safePocFileName(item.FileName); pathErr != nil {
			return inspection, pathErr
		}
		writeSemantic("poc", item.Name, item.FileName, item.Content, item.ContentHash, item.Severity, class, risk, item.Tags, item.Author, item.Description)
	}
	for _, item := range pocAssets {
		if _, pathErr := safePocAssetPath(item.RelativePath); pathErr != nil {
			return inspection, pathErr
		}
		writeSemantic("poc_asset", item.RelativePath, item.Content, item.ContentHash)
	}
	for _, item := range configAssets {
		if _, _, pathErr := safeConfigAssetPath(item.RelativePath); pathErr != nil {
			return inspection, pathErr
		}
		writeSemantic("config_asset", item.RelativePath, item.Content, item.ContentHash)
	}
	for _, item := range workflows {
		writeSemantic("workflow", item.ProductName, item.PocName, strings.ToLower(item.MatchType))
	}
	for _, item := range probes {
		writeSemantic("dir", item.Path, item.ProductName)
	}
	inspection.RuleVersion = "sha256:" + hex.EncodeToString(digest.Sum(nil))
	return inspection, nil
}

// BuildRulePackageFromConfig creates the release-time runtime arsenal.db from
// the same reviewed scanner/common/config baseline used to seed Server rules.
// It is a build helper only; CLI startup never recompiles the embedded rules.
func BuildRulePackageFromConfig(configDir, outputPath string) (RulePackageInspection, error) {
	configDir = filepath.Clean(configDir)
	if info, err := os.Stat(configDir); err != nil || !info.IsDir() {
		return RulePackageInspection{}, fmt.Errorf("rule config directory is unavailable: %s", configDir)
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return RulePackageInspection{}, fmt.Errorf("create package output directory: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(outputPath), ".arsenal.db.tmp-*")
	if err != nil {
		return RulePackageInspection{}, fmt.Errorf("create package staging file: %w", err)
	}
	tmpPath := tmp.Name()
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return RulePackageInspection{}, err
	}
	_ = os.Remove(tmpPath)
	cleanup := true
	defer func() {
		_ = CloseDB()
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := OpenDB(tmpPath); err != nil {
		return RulePackageInspection{}, err
	}
	packageTime := time.Unix(1, 0).UTC()

	read := func(name string) ([]byte, error) {
		data, readErr := os.ReadFile(filepath.Join(configDir, name))
		if readErr != nil {
			return nil, fmt.Errorf("read %s: %w", name, readErr)
		}
		return data, nil
	}
	finger, err := read("finger.yaml")
	if err != nil {
		return RulePackageInspection{}, err
	}
	workflow, err := read("workflow.yaml")
	if err != nil {
		return RulePackageInspection{}, err
	}
	dirRules, err := read("dir.yaml")
	if err != nil {
		return RulePackageInspection{}, err
	}

	var rawFingers map[string][]string
	if err := yaml.Unmarshal(finger, &rawFingers); err != nil {
		return RulePackageInspection{}, fmt.Errorf("parse finger.yaml: %w", err)
	}
	fingerRows := make([]Fingerprint, 0)
	for product, rules := range rawFingers {
		seen := make(map[string]struct{}, len(rules))
		for _, rule := range rules {
			rule = strings.TrimSpace(rule)
			if rule == "" {
				continue
			}
			if _, exists := seen[rule]; exists {
				continue
			}
			seen[rule] = struct{}{}
			fingerRows = append(fingerRows, Fingerprint{ProductName: product, RuleExpr: rule, Category: "web", Enabled: true, Source: "builtin", CreatedAt: packageTime, UpdatedAt: packageTime})
		}
	}
	sort.Slice(fingerRows, func(i, j int) bool {
		if fingerRows[i].ProductName == fingerRows[j].ProductName {
			return fingerRows[i].RuleExpr < fingerRows[j].RuleExpr
		}
		return fingerRows[i].ProductName < fingerRows[j].ProductName
	})

	type workflowYAML struct {
		Type []string `yaml:"type"`
		Pocs []string `yaml:"pocs"`
	}
	var rawWorkflows map[string]workflowYAML
	if err := yaml.Unmarshal(workflow, &rawWorkflows); err != nil {
		return RulePackageInspection{}, fmt.Errorf("parse workflow.yaml: %w", err)
	}
	workflowRows := make([]Workflow, 0)
	workflowSeen := make(map[string]struct{})
	for product, rule := range rawWorkflows {
		for _, pocName := range rule.Pocs {
			for _, matchType := range rule.Type {
				pocName = strings.TrimSpace(pocName)
				matchType = strings.ToLower(strings.TrimSpace(matchType))
				key := product + "\x00" + pocName + "\x00" + matchType
				if pocName == "" || matchType == "" {
					continue
				}
				if _, exists := workflowSeen[key]; exists {
					continue
				}
				workflowSeen[key] = struct{}{}
				workflowRows = append(workflowRows, Workflow{ProductName: product, PocName: pocName, MatchType: matchType, Enabled: true, CreatedAt: packageTime, UpdatedAt: packageTime})
			}
		}
	}
	sort.Slice(workflowRows, func(i, j int) bool {
		left := workflowRows[i].ProductName + "\x00" + workflowRows[i].PocName + "\x00" + workflowRows[i].MatchType
		right := workflowRows[j].ProductName + "\x00" + workflowRows[j].PocName + "\x00" + workflowRows[j].MatchType
		return left < right
	})

	var rawDirs map[string][]string
	if err := yaml.Unmarshal(dirRules, &rawDirs); err != nil {
		return RulePackageInspection{}, fmt.Errorf("parse dir.yaml: %w", err)
	}
	dirRows := make([]DirProbe, 0)
	dirSeen := make(map[string]struct{})
	for product, paths := range rawDirs {
		for _, probePath := range paths {
			probePath = strings.TrimSpace(probePath)
			key := product + "\x00" + probePath
			if probePath == "" {
				continue
			}
			if _, exists := dirSeen[key]; exists {
				continue
			}
			dirSeen[key] = struct{}{}
			dirRows = append(dirRows, DirProbe{ProductName: product, Path: probePath, Enabled: true, CreatedAt: packageTime, UpdatedAt: packageTime})
		}
	}
	sort.Slice(dirRows, func(i, j int) bool {
		left := dirRows[i].Path + "\x00" + dirRows[i].ProductName
		right := dirRows[j].Path + "\x00" + dirRows[j].ProductName
		return left < right
	})

	pocRoot := filepath.Join(configDir, "pocs")
	pocRows := make(map[string]Poc)
	pocAssetRows := make([]PocAsset, 0)
	if err := filepath.Walk(pocRoot, func(filePath string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() || strings.HasPrefix(info.Name(), ".") {
			return nil
		}
		data, readErr := os.ReadFile(filePath)
		if readErr != nil {
			return readErr
		}
		if len(data) == 0 {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(info.Name()), ".yaml") || strings.HasSuffix(strings.ToLower(info.Name()), ".yml") {
			meta := parsePocMeta(data)
			if governanceErr := validatePocGovernanceMeta(meta); governanceErr != nil {
				return fmt.Errorf("%s: %w", filePath, governanceErr)
			}
			name := meta.id
			if name == "" {
				name = strings.TrimSuffix(info.Name(), filepath.Ext(info.Name()))
			}
			content := packageText(data)
			pocRows[name] = Poc{
				Name: name, FileName: info.Name(), Content: content,
				ContentHash: fmt.Sprintf("%x", md5.Sum([]byte(content))), Severity: meta.severity,
				ExecutionClass: meta.executionClass, RiskLevel: meta.riskLevel, Tags: meta.tags,
				Author: meta.author, Description: meta.description, Enabled: true, Source: "builtin", CreatedAt: packageTime, UpdatedAt: packageTime,
			}
			return nil
		}
		rel, relErr := filepath.Rel(pocRoot, filePath)
		if relErr != nil {
			return relErr
		}
		content := packageText(data)
		pocAssetRows = append(pocAssetRows, PocAsset{
			RelativePath: filepath.ToSlash(rel), Content: content,
			ContentHash: fmt.Sprintf("%x", md5.Sum([]byte(content))), Enabled: true, Source: "builtin", CreatedAt: packageTime, UpdatedAt: packageTime,
		})
		return nil
	}); err != nil {
		return RulePackageInspection{}, fmt.Errorf("import POC rules: %w", err)
	}

	dictRoot := filepath.Join(configDir, "dict")
	configAssetRows := make([]ConfigAsset, 0)
	if err := filepath.Walk(dictRoot, func(filePath string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() || strings.HasPrefix(info.Name(), ".") || !strings.HasSuffix(strings.ToLower(info.Name()), ".txt") {
			return nil
		}
		data, readErr := os.ReadFile(filePath)
		if readErr != nil {
			return readErr
		}
		if len(data) == 0 {
			return nil
		}
		content := packageText(data)
		configAssetRows = append(configAssetRows, ConfigAsset{
			RelativePath: filepath.ToSlash(filepath.Join("dict", info.Name())), Content: content,
			ContentHash: fmt.Sprintf("%x", md5.Sum([]byte(content))), Enabled: true, Source: "builtin", CreatedAt: packageTime, UpdatedAt: packageTime,
		})
		return nil
	}); err != nil {
		return RulePackageInspection{}, fmt.Errorf("import runtime dictionaries: %w", err)
	}
	if data, readErr := os.ReadFile(filepath.Join(configDir, "subdomains.txt")); readErr == nil {
		content := packageText(data)
		configAssetRows = append(configAssetRows, ConfigAsset{
			RelativePath: "subdomains.txt", Content: content,
			ContentHash: fmt.Sprintf("%x", md5.Sum([]byte(content))), Enabled: true, Source: "builtin", CreatedAt: packageTime, UpdatedAt: packageTime,
		})
	}
	sort.Slice(pocAssetRows, func(i, j int) bool { return pocAssetRows[i].RelativePath < pocAssetRows[j].RelativePath })
	sort.Slice(configAssetRows, func(i, j int) bool { return configAssetRows[i].RelativePath < configAssetRows[j].RelativePath })

	pocNames := make([]string, 0, len(pocRows))
	for name := range pocRows {
		pocNames = append(pocNames, name)
	}
	sort.Strings(pocNames)
	pocs := make([]Poc, 0, len(pocNames))
	for _, name := range pocNames {
		pocs = append(pocs, pocRows[name])
	}
	if err := DB.Transaction(func(tx *gorm.DB) error {
		batches := []struct {
			rows any
			len  int
		}{
			{fingerRows, len(fingerRows)}, {workflowRows, len(workflowRows)}, {dirRows, len(dirRows)},
			{pocs, len(pocs)}, {pocAssetRows, len(pocAssetRows)}, {configAssetRows, len(configAssetRows)},
		}
		for _, batch := range batches {
			if batch.len > 0 {
				if err := tx.CreateInBatches(batch.rows, 500).Error; err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		return RulePackageInspection{}, fmt.Errorf("write runtime arsenal package: %w", err)
	}
	if err := CloseDB(); err != nil {
		return RulePackageInspection{}, fmt.Errorf("close built arsenal package: %w", err)
	}
	inspection, err := InspectRulePackage(tmpPath)
	if err != nil {
		return RulePackageInspection{}, fmt.Errorf("validate built arsenal package: %w", err)
	}
	_ = os.Remove(outputPath)
	if err := os.Rename(tmpPath, outputPath); err != nil {
		return RulePackageInspection{}, fmt.Errorf("activate built arsenal package: %w", err)
	}
	cleanup = false
	return inspection, nil
}

func packageText(data []byte) string {
	text := string(data)
	if !utf8.Valid(data) {
		text = strings.ToValidUTF8(text, "")
	}
	return strings.ReplaceAll(text, "\x00", "")
}
