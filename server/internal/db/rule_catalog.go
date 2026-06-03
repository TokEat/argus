package db

import (
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/user/dddd-proto/pyexp"
	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	RuleCatalogBootstrapKey    = "rule_catalog_v1"
	RuleCatalogSchemaVersion   = 2
	RuleCatalogStatusReady     = "ready"
	RuleCatalogStatusPartial   = "partial"
	RuleCatalogStatusEmpty     = "empty"
	maxRuleCatalogErrorMessage = 4000
	maxPocDescriptionRunes     = 500
)

// RuleCatalogBootstrap tracks whether the structured rule catalog has been
// materialized from the raw arsenals table for the current schema version.
type RuleCatalogBootstrap struct {
	Key              string `gorm:"primaryKey"`
	SchemaVersion    int
	Source           string
	Status           string `gorm:"index"`
	AggregateHash    string `gorm:"index"`
	ArsenalCount     int
	FingerprintCount int
	WorkflowCount    int
	DirProbeCount    int
	PocCount         int
	ExploitCount     int
	LastError        string `gorm:"type:text"`
	LastSeededAt     *time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// FingerprintRule stores one fingerprint expression per row for search,
// analytics, initialization checks, and future management workflows.
type FingerprintRule struct {
	ID          uint   `gorm:"primaryKey;autoIncrement"`
	TenantID    string `gorm:"default:'default';index;uniqueIndex:idx_fp_rule_unique"`
	ArtifactID  string `gorm:"index"`
	SourceFile  string `gorm:"index"`
	ProductName string `gorm:"index;not null;uniqueIndex:idx_fp_rule_unique"`
	RuleExpr    string `gorm:"type:text;not null;uniqueIndex:idx_fp_rule_unique"`
	Category    string `gorm:"default:'web';index"`
	ContentHash string `gorm:"index"`
	Version     int    `gorm:"default:1"`
	State       string `gorm:"index"`
	Enabled     bool   `gorm:"default:true;index"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// PocRule stores normalized metadata for one POC template while keeping the
// raw template text in arsenals for distribution to agents.
type PocRule struct {
	ID                  uint   `gorm:"primaryKey;autoIncrement"`
	TenantID            string `gorm:"default:'default';index;uniqueIndex:idx_poc_rule_unique"`
	ArtifactID          string `gorm:"index"`
	SourceFile          string `gorm:"index;uniqueIndex:idx_poc_rule_unique"`
	Name                string `gorm:"index;not null"`
	TargetProduct       string `gorm:"index"`
	CVE                 string `gorm:"index"`
	CompatibilityStatus string `gorm:"index;default:'unknown'"`
	SourceVersion       string
	ContentHash         string `gorm:"index"`
	Severity            string `gorm:"index;default:'info'"`
	Tags                string `gorm:"type:text"`
	Author              string
	Description         string `gorm:"type:text"`
	Version             int    `gorm:"default:1"`
	State               string `gorm:"index"`
	Enabled             bool   `gorm:"default:true;index"`
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// WorkflowRule stores one product -> poc -> match_type mapping per row.
type WorkflowRule struct {
	ID          uint   `gorm:"primaryKey;autoIncrement"`
	TenantID    string `gorm:"default:'default';index;uniqueIndex:idx_workflow_rule_unique"`
	ArtifactID  string `gorm:"index"`
	SourceFile  string `gorm:"index"`
	ProductName string `gorm:"index;not null;uniqueIndex:idx_workflow_rule_unique"`
	PocName     string `gorm:"index;not null;uniqueIndex:idx_workflow_rule_unique"`
	MatchType   string `gorm:"index;not null;uniqueIndex:idx_workflow_rule_unique"`
	ContentHash string `gorm:"index"`
	Version     int    `gorm:"default:1"`
	State       string `gorm:"index"`
	Enabled     bool   `gorm:"default:true;index"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// DirRule stores one active directory probe path per product.
type DirRule struct {
	ID          uint   `gorm:"primaryKey;autoIncrement"`
	TenantID    string `gorm:"default:'default';index;uniqueIndex:idx_dir_rule_unique"`
	ArtifactID  string `gorm:"index"`
	SourceFile  string `gorm:"index"`
	Path        string `gorm:"index;not null;uniqueIndex:idx_dir_rule_unique"`
	ProductName string `gorm:"index;not null;uniqueIndex:idx_dir_rule_unique"`
	ContentHash string `gorm:"index"`
	Version     int    `gorm:"default:1"`
	State       string `gorm:"index"`
	Enabled     bool   `gorm:"default:true;index"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// ExploitRule stores searchable metadata for one Python EXP package. The raw
// script content stays in arsenals so migration and rollback use one truth source.
type ExploitRule struct {
	ID               uint   `gorm:"primaryKey;autoIncrement"`
	TenantID         string `gorm:"default:'default';index;uniqueIndex:idx_exploit_rule_unique"`
	ArtifactID       string `gorm:"index"`
	SourceFile       string `gorm:"index"`
	RuleID           string `gorm:"index;not null;uniqueIndex:idx_exploit_rule_unique"`
	Name             string `gorm:"index;not null"`
	Description      string `gorm:"type:text"`
	TargetProduct    string `gorm:"index"`
	CVE              string `gorm:"index"`
	RiskLevel        string `gorm:"index;default:'medium'"`
	RequiresAuth     bool   `gorm:"default:false;index"`
	SideEffects      string `gorm:"type:text"`
	CleanupSupported bool   `gorm:"default:false;index"`
	CleanupRequired  bool   `gorm:"default:false;index"`
	DryRunSupported  bool   `gorm:"default:false;index"`
	Capabilities     string `gorm:"type:jsonb"`
	LinkedPocs       string `gorm:"type:jsonb"`
	ParamsSchema     string `gorm:"type:jsonb"`
	Requirements     string `gorm:"type:jsonb"`
	RequirementsHash string `gorm:"index"`
	SandboxProfile   string `gorm:"index;default:'local-python'"`
	TimeoutSec       int
	RuntimeEngine    string `gorm:"index"`
	ContentHash      string `gorm:"index"`
	Version          int    `gorm:"default:1"`
	State            string `gorm:"index"`
	Enabled          bool   `gorm:"default:true;index"`
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

func CanonicalArsenalType(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "finger", "fingerprint":
		return "finger"
	case "workflow":
		return "workflow"
	case "dir", "dirprobe":
		return "dir"
	case "poc":
		return "poc"
	case "exp", "exploit":
		return "exp"
	case "apiconfig":
		return "apiconfig"
	default:
		return strings.ToLower(strings.TrimSpace(raw))
	}
}

func ArsenalTypeAliases(raw string) []string {
	switch CanonicalArsenalType(raw) {
	case "finger":
		return []string{"finger", "fingerprint"}
	case "dir":
		return []string{"dir", "dirprobe"}
	case "workflow":
		return []string{"workflow"}
	case "poc":
		return []string{"poc"}
	case "exp":
		return []string{"exp", "exploit"}
	case "apiconfig":
		return []string{"apiconfig"}
	default:
		normalized := strings.ToLower(strings.TrimSpace(raw))
		if normalized == "" {
			return nil
		}
		return []string{normalized}
	}
}

func BuildTenantArsenalID(tenantID, typ, fileName string) string {
	tenantID = strings.TrimSpace(tenantID)
	baseID := CanonicalArsenalType(typ) + "_" + fileName
	if tenantID == "" || tenantID == "default" {
		return baseID
	}
	return tenantID + "_" + baseID
}

func BuildArsenalID(typ, fileName string) string {
	return BuildTenantArsenalID("default", typ, fileName)
}

func FindTenantArsenalByTypeAndFile(tenantID, typ, fileName string) (*Arsenal, error) {
	var arsenal Arsenal
	err := DB.Where("tenant_id = ? AND type IN ? AND file_name = ?", strings.TrimSpace(tenantID), ArsenalTypeAliases(typ), fileName).
		Order("updated_at DESC").
		First(&arsenal).Error
	if err != nil {
		return nil, err
	}
	return &arsenal, nil
}

func FindArsenalByTypeAndFile(typ, fileName string) (*Arsenal, error) {
	return FindTenantArsenalByTypeAndFile("default", typ, fileName)
}

func SyncRuleCatalogFromArsenal() error {
	var arsenals []Arsenal
	if err := DB.Order("tenant_id, type, file_name").Find(&arsenals).Error; err != nil {
		return err
	}

	aggregateHash := buildArsenalAggregateHash(arsenals)

	var bootstrap RuleCatalogBootstrap
	if err := DB.Where("key = ?", RuleCatalogBootstrapKey).First(&bootstrap).Error; err == nil {
		if bootstrap.SchemaVersion == RuleCatalogSchemaVersion &&
			bootstrap.AggregateHash == aggregateHash &&
			(bootstrap.Status == RuleCatalogStatusReady || bootstrap.Status == RuleCatalogStatusEmpty) {
			return nil
		}
		if bootstrap.Status == RuleCatalogStatusPartial && bootstrap.AggregateHash == aggregateHash {
			log.Printf("[RuleCatalog] previous materialization was partial (errors: %s), retrying...", bootstrap.LastError)
		}
	}

	materialized := materializeRuleCatalog(arsenals)
	now := time.Now()
	status := RuleCatalogStatusReady
	if len(arsenals) == 0 {
		status = RuleCatalogStatusEmpty
	} else if len(materialized.errors) > 0 {
		status = RuleCatalogStatusPartial
	}

	state := RuleCatalogBootstrap{
		Key:              RuleCatalogBootstrapKey,
		SchemaVersion:    RuleCatalogSchemaVersion,
		Source:           "arsenals",
		Status:           status,
		AggregateHash:    aggregateHash,
		ArsenalCount:     len(arsenals),
		FingerprintCount: len(materialized.fingerprints),
		WorkflowCount:    len(materialized.workflows),
		DirProbeCount:    len(materialized.dirs),
		PocCount:         len(materialized.pocs),
		ExploitCount:     len(materialized.exploits),
		LastError:        summarizeRuleCatalogErrors(materialized.errors),
		LastSeededAt:     &now,
	}

	err := DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&FingerprintRule{}).Error; err != nil {
			return err
		}
		if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&WorkflowRule{}).Error; err != nil {
			return err
		}
		if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&DirRule{}).Error; err != nil {
			return err
		}
		if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&PocRule{}).Error; err != nil {
			return err
		}
		if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&ExploitRule{}).Error; err != nil {
			return err
		}

		if err := createInBatches(tx, materialized.fingerprints); err != nil {
			return err
		}
		if err := createInBatches(tx, materialized.workflows); err != nil {
			return err
		}
		if err := createInBatches(tx, materialized.dirs); err != nil {
			return err
		}
		if err := createInBatches(tx, materialized.pocs); err != nil {
			return err
		}
		if err := createInBatches(tx, materialized.exploits); err != nil {
			return err
		}

		return tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "key"}},
			UpdateAll: true,
		}).Create(&state).Error
	})
	if err != nil {
		return err
	}

	log.Printf(
		"[RuleCatalog] bootstrap=%s arsenals=%d pocs=%d exploits=%d fingerprints=%d workflows=%d dirs=%d errors=%d",
		status,
		len(arsenals),
		len(materialized.pocs),
		len(materialized.exploits),
		len(materialized.fingerprints),
		len(materialized.workflows),
		len(materialized.dirs),
		len(materialized.errors),
	)
	if len(materialized.errors) > 0 {
		return fmt.Errorf("rule catalog materialized with %d errors: %s", len(materialized.errors), summarizeRuleCatalogErrors(materialized.errors))
	}
	return nil
}

func normalizeLegacyArsenalTypes() error {
	legacyMappings := map[string]string{
		"fingerprint": "finger",
		"dirprobe":    "dir",
		"exploit":     "exp",
	}

	return DB.Transaction(func(tx *gorm.DB) error {
		for oldType, newType := range legacyMappings {
			var rows []Arsenal
			if err := tx.Where("type = ?", oldType).Find(&rows).Error; err != nil {
				return err
			}
			for _, row := range rows {
				newID := BuildTenantArsenalID(row.TenantID, newType, row.FileName)
				if row.ID == newID && row.Type == newType {
					continue
				}

				var existing Arsenal
				err := tx.Where("id = ? AND tenant_id = ?", newID, row.TenantID).First(&existing).Error
				if err == nil {
					if row.UpdatedAt.After(existing.UpdatedAt) {
						row.ID = newID
						row.Type = newType
						if saveErr := tx.Save(&row).Error; saveErr != nil {
							return saveErr
						}
					}
					if delErr := tx.Delete(&Arsenal{}, "id = ? AND tenant_id = ?", BuildTenantArsenalID(row.TenantID, oldType, row.FileName), row.TenantID).Error; delErr != nil {
						return delErr
					}
					continue
				}
				if !errorsIsNotFound(err) {
					return err
				}

				if execErr := tx.Exec(
					"UPDATE arsenals SET id = ?, type = ? WHERE id = ? AND tenant_id = ?",
					newID,
					newType,
					BuildTenantArsenalID(row.TenantID, oldType, row.FileName),
					row.TenantID,
				).Error; execErr != nil {
					return execErr
				}
			}
		}
		return nil
	})
}

func errorsIsNotFound(err error) bool {
	return errors.Is(err, gorm.ErrRecordNotFound)
}

type materializedRuleCatalog struct {
	fingerprints []FingerprintRule
	workflows    []WorkflowRule
	dirs         []DirRule
	pocs         []PocRule
	exploits     []ExploitRule
	errors       []string
}

func materializeRuleCatalog(arsenals []Arsenal) materializedRuleCatalog {
	var out materializedRuleCatalog

	for _, arsenal := range arsenals {
		sanitizeArsenalTextFields(&arsenal)
		switch CanonicalArsenalType(arsenal.Type) {
		case "finger":
			rows, err := materializeFingerprintRules(arsenal)
			if err != nil {
				out.errors = append(out.errors, err.Error())
				continue
			}
			out.fingerprints = append(out.fingerprints, rows...)
		case "workflow":
			rows, err := materializeWorkflowRules(arsenal)
			if err != nil {
				out.errors = append(out.errors, err.Error())
				continue
			}
			out.workflows = append(out.workflows, rows...)
		case "dir":
			rows, err := materializeDirRules(arsenal)
			if err != nil {
				out.errors = append(out.errors, err.Error())
				continue
			}
			out.dirs = append(out.dirs, rows...)
		case "poc":
			out.pocs = append(out.pocs, materializePocRule(arsenal))
		case "exp":
			rule, err := materializeExploitRule(arsenal)
			if err != nil {
				out.errors = append(out.errors, err.Error())
				continue
			}
			out.exploits = append(out.exploits, rule)
		}
	}

	return out
}

func materializeFingerprintRules(arsenal Arsenal) ([]FingerprintRule, error) {
	var raw map[string][]string
	if err := yaml.Unmarshal([]byte(sanitizePostgresText(arsenal.Content)), &raw); err != nil {
		return nil, fmt.Errorf("finger yaml parse failed for %s: %w", arsenal.FileName, err)
	}

	rows := make([]FingerprintRule, 0)
	for productName, rules := range raw {
		for _, ruleExpr := range rules {
			ruleExpr = strings.TrimSpace(ruleExpr)
			if ruleExpr == "" {
				continue
			}
			rows = append(rows, FingerprintRule{
				TenantID:    arsenal.TenantID,
				ArtifactID:  arsenal.ID,
				SourceFile:  arsenal.FileName,
				ProductName: strings.TrimSpace(productName),
				RuleExpr:    ruleExpr,
				Category:    "web",
				ContentHash: arsenal.Hash,
				Version:     arsenal.Version,
				State:       arsenal.State,
				Enabled:     arsenal.State == "Approved",
			})
		}
	}
	return rows, nil
}

func materializeWorkflowRules(arsenal Arsenal) ([]WorkflowRule, error) {
	type workflowEntry struct {
		Type []string `yaml:"type"`
		Pocs []string `yaml:"pocs"`
	}

	var raw map[string]workflowEntry
	if err := yaml.Unmarshal([]byte(sanitizePostgresText(arsenal.Content)), &raw); err != nil {
		return nil, fmt.Errorf("workflow yaml parse failed for %s: %w", arsenal.FileName, err)
	}

	rows := make([]WorkflowRule, 0)
	for productName, entry := range raw {
		for _, pocName := range entry.Pocs {
			pocName = strings.TrimSpace(pocName)
			if pocName == "" {
				continue
			}
			for _, matchType := range entry.Type {
				matchType = strings.ToLower(strings.TrimSpace(matchType))
				if matchType == "" {
					continue
				}
				rows = append(rows, WorkflowRule{
					TenantID:    arsenal.TenantID,
					ArtifactID:  arsenal.ID,
					SourceFile:  arsenal.FileName,
					ProductName: strings.TrimSpace(productName),
					PocName:     pocName,
					MatchType:   matchType,
					ContentHash: arsenal.Hash,
					Version:     arsenal.Version,
					State:       arsenal.State,
					Enabled:     arsenal.State == "Approved",
				})
			}
		}
	}
	return rows, nil
}

func materializeDirRules(arsenal Arsenal) ([]DirRule, error) {
	var raw map[string][]string
	if err := yaml.Unmarshal([]byte(sanitizePostgresText(arsenal.Content)), &raw); err != nil {
		return nil, fmt.Errorf("dir yaml parse failed for %s: %w", arsenal.FileName, err)
	}

	rows := make([]DirRule, 0)
	for productName, paths := range raw {
		for _, probePath := range paths {
			probePath = strings.TrimSpace(probePath)
			if probePath == "" {
				continue
			}
			rows = append(rows, DirRule{
				TenantID:    arsenal.TenantID,
				ArtifactID:  arsenal.ID,
				SourceFile:  arsenal.FileName,
				Path:        probePath,
				ProductName: strings.TrimSpace(productName),
				ContentHash: arsenal.Hash,
				Version:     arsenal.Version,
				State:       arsenal.State,
				Enabled:     arsenal.State == "Approved",
			})
		}
	}
	return rows, nil
}

func materializePocRule(arsenal Arsenal) PocRule {
	meta := parsePocMeta([]byte(arsenal.Content))
	name := meta.id
	if name == "" {
		ext := filepath.Ext(arsenal.FileName)
		name = strings.TrimSuffix(arsenal.FileName, ext)
	}

	return PocRule{
		TenantID:            arsenal.TenantID,
		ArtifactID:          arsenal.ID,
		SourceFile:          arsenal.FileName,
		Name:                name,
		TargetProduct:       meta.targetProduct,
		CVE:                 meta.cve,
		CompatibilityStatus: meta.compatibilityStatus,
		SourceVersion:       meta.sourceVersion,
		ContentHash:         arsenal.Hash,
		Severity:            meta.severity,
		Tags:                meta.tags,
		Author:              meta.author,
		Description:         meta.description,
		Version:             arsenal.Version,
		State:               arsenal.State,
		Enabled:             arsenal.State == "Approved",
	}
}

func materializeExploitRule(arsenal Arsenal) (ExploitRule, error) {
	meta, err := parseExploitMeta([]byte(arsenal.Content))
	if err != nil {
		return ExploitRule{}, fmt.Errorf("exp python parse failed for %s: %w", arsenal.FileName, err)
	}
	if meta.RuleID == "" {
		ext := filepath.Ext(arsenal.FileName)
		meta.RuleID = strings.TrimSuffix(arsenal.FileName, ext)
	}
	if meta.Name == "" {
		meta.Name = meta.RuleID
	}
	if meta.RiskLevel == "" {
		meta.RiskLevel = "medium"
	}
	if meta.TimeoutSec <= 0 {
		meta.TimeoutSec = 60
	}

	return ExploitRule{
		TenantID:         arsenal.TenantID,
		ArtifactID:       arsenal.ID,
		SourceFile:       arsenal.FileName,
		RuleID:           meta.RuleID,
		Name:             meta.Name,
		Description:      meta.Description,
		TargetProduct:    meta.TargetProduct,
		CVE:              meta.CVE,
		RiskLevel:        meta.RiskLevel,
		RequiresAuth:     meta.RequiresAuth,
		SideEffects:      strings.Join(meta.SideEffects, "\n"),
		CleanupSupported: meta.CleanupSupported,
		CleanupRequired:  meta.CleanupRequired,
		DryRunSupported:  meta.DryRunSupported,
		Capabilities:     marshalJSONText(meta.Capabilities),
		LinkedPocs:       marshalJSONText(meta.LinkedPocs),
		ParamsSchema:     marshalJSONText(meta.ParamsSchema),
		Requirements:     marshalJSONText(meta.Requirements),
		RequirementsHash: meta.RequirementsHash,
		SandboxProfile:   meta.SandboxProfile,
		TimeoutSec:       meta.TimeoutSec,
		RuntimeEngine:    meta.RuntimeEngine,
		ContentHash:      arsenal.Hash,
		Version:          arsenal.Version,
		State:            arsenal.State,
		Enabled:          arsenal.State == "Approved",
	}, nil
}

type pocMeta struct {
	id                  string
	severity            string
	tags                string
	author              string
	description         string
	targetProduct       string
	cve                 string
	compatibilityStatus string
	sourceVersion       string
}

type exploitMeta struct {
	RuleID           string
	Name             string
	Description      string
	TargetProduct    string
	CVE              string
	RiskLevel        string
	RequiresAuth     bool
	SideEffects      []string
	CleanupSupported bool
	CleanupRequired  bool
	DryRunSupported  bool
	Capabilities     []string
	LinkedPocs       []string
	ParamsSchema     map[string]interface{}
	Requirements     []string
	RequirementsHash string
	SandboxProfile   string
	TimeoutSec       int
	RuntimeEngine    string
}

func parseExploitMeta(content []byte) (exploitMeta, error) {
	content = sanitizePostgresTextBytes(content)
	raw, err := pyexp.ParseTemplate(content)
	if err != nil {
		return exploitMeta{}, err
	}
	return exploitMeta{
		RuleID:           strings.TrimSpace(raw.ID),
		Name:             strings.TrimSpace(raw.Name),
		Description:      strings.TrimSpace(raw.Description),
		TargetProduct:    strings.TrimSpace(raw.TargetProduct),
		CVE:              strings.TrimSpace(raw.CVE),
		RiskLevel:        raw.RiskLevel,
		RequiresAuth:     raw.Policy.RequiresAuth,
		SideEffects:      normalizeStringSlice(raw.Policy.SideEffects),
		CleanupSupported: raw.Policy.CleanupSupported,
		CleanupRequired:  raw.Policy.CleanupRequired,
		DryRunSupported:  raw.Policy.DryRunSupported,
		Capabilities:     normalizeStringSlice(raw.Policy.Capabilities),
		LinkedPocs:       normalizeStringSlice(raw.LinkedPocs),
		ParamsSchema:     pyexp.ParamSchema(raw.Params),
		Requirements:     normalizeStringSlice(raw.Requirements),
		RequirementsHash: raw.RequirementsHash,
		SandboxProfile:   "local-python",
		TimeoutSec:       raw.Policy.TimeoutSec,
		RuntimeEngine:    pyexp.RuntimeEngine,
	}, nil
}

func parsePocMeta(content []byte) pocMeta {
	text := sanitizePostgresText(string(content))
	content = []byte(text)
	meta := pocMeta{severity: "info", compatibilityStatus: "unknown"}
	type nucleiYAML struct {
		ID   string `yaml:"id"`
		Info struct {
			Name           string      `yaml:"name"`
			Severity       string      `yaml:"severity"`
			Author         interface{} `yaml:"author"`
			Tags           interface{} `yaml:"tags"`
			Description    string      `yaml:"description"`
			Classification struct {
				CVEID interface{} `yaml:"cve-id"`
			} `yaml:"classification"`
			Metadata map[string]interface{} `yaml:"metadata"`
		} `yaml:"info"`
	}
	var parsed nucleiYAML
	if err := yaml.Unmarshal(content, &parsed); err == nil {
		meta.id = strings.TrimSpace(parsed.ID)
		meta.severity = strings.ToLower(strings.TrimSpace(parsed.Info.Severity))
		meta.tags = stringifyPocMetaValue(parsed.Info.Tags)
		meta.author = stringifyPocMetaValue(parsed.Info.Author)
		meta.description = truncatePocDescription(parsed.Info.Description)
		meta.cve = normalizePocCVE(stringifyPocMetaValue(parsed.Info.Classification.CVEID))
		meta.targetProduct = strings.TrimSpace(firstPocMetadataValue(parsed.Info.Metadata, "product", "vendor", "fofa-query", "shodan-query"))
		meta.sourceVersion = strings.TrimSpace(firstPocMetadataValue(parsed.Info.Metadata, "version", "source_version", "template-version"))
		if meta.id != "" || strings.TrimSpace(parsed.Info.Name) != "" {
			meta.compatibilityStatus = "indexed"
		}
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "id:"):
			if meta.id == "" {
				meta.id = strings.TrimSpace(strings.TrimPrefix(line, "id:"))
			}
		case strings.HasPrefix(line, "severity:"):
			if meta.severity == "" || meta.severity == "info" {
				meta.severity = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(line, "severity:")))
			}
		case strings.HasPrefix(line, "tags:"):
			if meta.tags == "" {
				meta.tags = strings.TrimSpace(strings.TrimPrefix(line, "tags:"))
			}
		case strings.HasPrefix(line, "author:"):
			if meta.author == "" {
				meta.author = strings.TrimSpace(strings.TrimPrefix(line, "author:"))
			}
		case strings.HasPrefix(line, "description:"):
			if meta.description == "" {
				meta.description = truncatePocDescription(strings.TrimSpace(strings.TrimPrefix(line, "description:")))
			}
		case strings.HasPrefix(line, "cve-id:"):
			if meta.cve == "" {
				meta.cve = normalizePocCVE(strings.TrimSpace(strings.TrimPrefix(line, "cve-id:")))
			}
		}
	}
	if meta.severity == "" {
		meta.severity = "info"
	}
	return meta
}

func stringifyPocMetaValue(value interface{}) string {
	if value == nil {
		return ""
	}
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(sanitizePostgresText(v))
	case []interface{}:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			if s := stringifyPocMetaValue(item); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ",")
	case []string:
		return sanitizePostgresText(strings.Join(v, ","))
	default:
		return strings.TrimSpace(sanitizePostgresText(fmt.Sprint(v)))
	}
}

func firstPocMetadataValue(metadata map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if metadata == nil {
			return ""
		}
		for actualKey, value := range metadata {
			if strings.EqualFold(actualKey, key) {
				return stringifyPocMetaValue(value)
			}
		}
	}
	return ""
}

func normalizePocCVE(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "nil") || strings.EqualFold(value, "<nil>") {
		return ""
	}
	return strings.ToUpper(value)
}

func truncatePocDescription(desc string) string {
	return truncateUTF8Runes(strings.TrimSpace(desc), maxPocDescriptionRunes)
}

func normalizeStringSlice(items []string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(sanitizePostgresText(item))
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func marshalJSONText(v interface{}) string {
	if v == nil {
		return "[]"
	}
	data, err := json.Marshal(v)
	if err != nil {
		return "null"
	}
	return string(data)
}

func buildArsenalAggregateHash(arsenals []Arsenal) string {
	if len(arsenals) == 0 {
		return ""
	}

	parts := make([]string, 0, len(arsenals))
	for _, arsenal := range arsenals {
		parts = append(parts,
			arsenal.TenantID+"|"+
				CanonicalArsenalType(arsenal.Type)+"|"+
				arsenal.FileName+"|"+
				arsenal.Hash+"|"+
				arsenal.State+"|"+
				strconv.Itoa(arsenal.Version),
		)
	}
	sort.Strings(parts)
	return fmt.Sprintf("%x", md5.Sum([]byte(strings.Join(parts, "\n"))))
}

func summarizeRuleCatalogErrors(items []string) string {
	if len(items) == 0 {
		return ""
	}
	message := strings.Join(items, " | ")
	return truncateUTF8Runes(message, maxRuleCatalogErrorMessage)
}

func createInBatches[T any](tx *gorm.DB, items []T) error {
	if len(items) == 0 {
		return nil
	}
	sanitizedCount := 0
	for i := range items {
		if sanitizeStringFieldsForPostgres(&items[i]) {
			sanitizedCount++
		}
	}
	if sanitizedCount > 0 {
		log.Printf("[RuleCatalog] Sanitized PostgreSQL text fields in %d materialized rows before insert.", sanitizedCount)
	}
	return tx.CreateInBatches(items, 500).Error
}

func sanitizePostgresTextBytes(content []byte) []byte {
	if utf8.Valid(content) {
		text := string(content)
		if !strings.ContainsRune(text, '\x00') {
			return content
		}
	}
	return []byte(sanitizePostgresText(string(content)))
}

func sanitizePostgresText(value string) string {
	if utf8.ValidString(value) && !strings.ContainsRune(value, '\x00') {
		return value
	}
	value = strings.ToValidUTF8(value, "")
	return strings.ReplaceAll(value, "\x00", "")
}

func truncateUTF8Runes(value string, maxRunes int) string {
	if maxRunes <= 0 {
		return ""
	}
	value = sanitizePostgresText(value)
	if utf8.RuneCountInString(value) <= maxRunes {
		return value
	}
	runes := []rune(value)
	return string(runes[:maxRunes])
}

func hashString(value string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(value)))
}

func sanitizeArsenalTextFields(arsenal *Arsenal) bool {
	if arsenal == nil {
		return false
	}

	changed := false
	sanitizeField := func(field *string) {
		cleaned := sanitizePostgresText(*field)
		if cleaned != *field {
			*field = cleaned
			changed = true
		}
	}

	originalContent := arsenal.Content
	originalPreviousContent := arsenal.PreviousContent

	sanitizeField(&arsenal.ID)
	sanitizeField(&arsenal.TenantID)
	sanitizeField(&arsenal.Type)
	sanitizeField(&arsenal.FileName)
	sanitizeField(&arsenal.Content)
	sanitizeField(&arsenal.Hash)
	sanitizeField(&arsenal.PreviousHash)
	sanitizeField(&arsenal.PreviousContent)
	sanitizeField(&arsenal.State)

	if arsenal.Content != originalContent {
		arsenal.Hash = hashString(arsenal.Content)
	}
	if arsenal.PreviousContent != originalPreviousContent && arsenal.PreviousContent != "" {
		arsenal.PreviousHash = hashString(arsenal.PreviousContent)
	}

	return changed
}

func sanitizeStringFieldsForPostgres(item any) bool {
	value := reflect.ValueOf(item)
	if value.Kind() != reflect.Pointer || value.IsNil() {
		return false
	}
	return sanitizeReflectValueForPostgres(value.Elem())
}

func sanitizeReflectValueForPostgres(value reflect.Value) bool {
	if !value.IsValid() {
		return false
	}

	changed := false
	switch value.Kind() {
	case reflect.Pointer:
		if !value.IsNil() {
			changed = sanitizeReflectValueForPostgres(value.Elem()) || changed
		}
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			field := value.Field(i)
			if field.CanSet() {
				changed = sanitizeReflectValueForPostgres(field) || changed
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < value.Len(); i++ {
			changed = sanitizeReflectValueForPostgres(value.Index(i)) || changed
		}
	case reflect.String:
		if !value.CanSet() {
			return changed
		}
		cleaned := sanitizePostgresText(value.String())
		if cleaned != value.String() {
			value.SetString(cleaned)
			changed = true
		}
	}
	return changed
}
