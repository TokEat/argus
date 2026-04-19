package db

import (
	"crypto/md5"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	RuleCatalogBootstrapKey    = "rule_catalog_v1"
	RuleCatalogSchemaVersion   = 1
	RuleCatalogStatusReady     = "ready"
	RuleCatalogStatusPartial   = "partial"
	RuleCatalogStatusEmpty     = "empty"
	maxRuleCatalogErrorMessage = 4000
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
	ID          uint   `gorm:"primaryKey;autoIncrement"`
	TenantID    string `gorm:"default:'default';index;uniqueIndex:idx_poc_rule_unique"`
	ArtifactID  string `gorm:"index"`
	SourceFile  string `gorm:"index;uniqueIndex:idx_poc_rule_unique"`
	Name        string `gorm:"index;not null"`
	ContentHash string `gorm:"index"`
	Severity    string `gorm:"index;default:'info'"`
	Tags        string `gorm:"type:text"`
	Author      string
	Description string `gorm:"type:text"`
	Version     int    `gorm:"default:1"`
	State       string `gorm:"index"`
	Enabled     bool   `gorm:"default:true;index"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
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
	default:
		normalized := strings.ToLower(strings.TrimSpace(raw))
		if normalized == "" {
			return nil
		}
		return []string{normalized}
	}
}

func BuildArsenalID(typ, fileName string) string {
	return CanonicalArsenalType(typ) + "_" + fileName
}

func FindArsenalByTypeAndFile(typ, fileName string) (*Arsenal, error) {
	var arsenal Arsenal
	err := DB.Where("type IN ? AND file_name = ?", ArsenalTypeAliases(typ), fileName).
		Order("updated_at DESC").
		First(&arsenal).Error
	if err != nil {
		return nil, err
	}
	return &arsenal, nil
}

func BootstrapRuleCatalog(configBaseDir string) error {
	if err := normalizeLegacyArsenalTypes(); err != nil {
		return fmt.Errorf("normalize legacy arsenal types: %w", err)
	}

	SeedArsenalFromDisk(configBaseDir)

	if err := SyncRuleCatalogFromArsenal(); err != nil {
		return fmt.Errorf("sync structured rule catalog: %w", err)
	}

	return nil
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
			(bootstrap.Status == RuleCatalogStatusReady || bootstrap.Status == RuleCatalogStatusPartial || bootstrap.Status == RuleCatalogStatusEmpty) {
			return nil
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

		return tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "key"}},
			UpdateAll: true,
		}).Create(&state).Error
	})
	if err != nil {
		return err
	}

	log.Printf(
		"[RuleCatalog] bootstrap=%s arsenals=%d pocs=%d fingerprints=%d workflows=%d dirs=%d errors=%d",
		status,
		len(arsenals),
		len(materialized.pocs),
		len(materialized.fingerprints),
		len(materialized.workflows),
		len(materialized.dirs),
		len(materialized.errors),
	)
	return nil
}

func normalizeLegacyArsenalTypes() error {
	legacyMappings := map[string]string{
		"fingerprint": "finger",
		"dirprobe":    "dir",
	}

	return DB.Transaction(func(tx *gorm.DB) error {
		for oldType, newType := range legacyMappings {
			var rows []Arsenal
			if err := tx.Where("type = ?", oldType).Find(&rows).Error; err != nil {
				return err
			}
			for _, row := range rows {
				newID := BuildArsenalID(newType, row.FileName)
				if row.ID == newID && row.Type == newType {
					continue
				}

				var existing Arsenal
				err := tx.Where("id = ?", newID).First(&existing).Error
				if err == nil {
					if row.UpdatedAt.After(existing.UpdatedAt) {
						row.ID = newID
						row.Type = newType
						if saveErr := tx.Save(&row).Error; saveErr != nil {
							return saveErr
						}
					}
					if delErr := tx.Delete(&Arsenal{}, "id = ?", BuildArsenalID(oldType, row.FileName)).Error; delErr != nil {
						return delErr
					}
					continue
				}
				if !errorsIsNotFound(err) {
					return err
				}

				if execErr := tx.Exec(
					"UPDATE arsenals SET id = ?, type = ? WHERE id = ?",
					newID,
					newType,
					BuildArsenalID(oldType, row.FileName),
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
	errors       []string
}

func materializeRuleCatalog(arsenals []Arsenal) materializedRuleCatalog {
	var out materializedRuleCatalog

	for _, arsenal := range arsenals {
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
		}
	}

	return out
}

func materializeFingerprintRules(arsenal Arsenal) ([]FingerprintRule, error) {
	var raw map[string][]string
	if err := yaml.Unmarshal([]byte(arsenal.Content), &raw); err != nil {
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
	if err := yaml.Unmarshal([]byte(arsenal.Content), &raw); err != nil {
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
	if err := yaml.Unmarshal([]byte(arsenal.Content), &raw); err != nil {
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
		TenantID:    arsenal.TenantID,
		ArtifactID:  arsenal.ID,
		SourceFile:  arsenal.FileName,
		Name:        name,
		ContentHash: arsenal.Hash,
		Severity:    meta.severity,
		Tags:        meta.tags,
		Author:      meta.author,
		Description: meta.description,
		Version:     arsenal.Version,
		State:       arsenal.State,
		Enabled:     arsenal.State == "Approved",
	}
}

type pocMeta struct {
	id          string
	severity    string
	tags        string
	author      string
	description string
}

func parsePocMeta(content []byte) pocMeta {
	meta := pocMeta{severity: "info"}
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "id:"):
			meta.id = strings.TrimSpace(strings.TrimPrefix(line, "id:"))
		case strings.HasPrefix(line, "severity:"):
			meta.severity = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(line, "severity:")))
		case strings.HasPrefix(line, "tags:"):
			meta.tags = strings.TrimSpace(strings.TrimPrefix(line, "tags:"))
		case strings.HasPrefix(line, "author:"):
			meta.author = strings.TrimSpace(strings.TrimPrefix(line, "author:"))
		case strings.HasPrefix(line, "description:"):
			desc := strings.TrimSpace(strings.TrimPrefix(line, "description:"))
			if len(desc) > 500 {
				desc = desc[:500]
			}
			meta.description = desc
		}
	}
	return meta
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
	if len(message) > maxRuleCatalogErrorMessage {
		return message[:maxRuleCatalogErrorMessage]
	}
	return message
}

func createInBatches[T any](tx *gorm.DB, items []T) error {
	if len(items) == 0 {
		return nil
	}
	return tx.CreateInBatches(items, 500).Error
}
