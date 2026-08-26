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
	"sync"
	"time"
	"unicode/utf8"

	"github.com/P0lar1ght/argus/shared/proto/go/activefingerprint"
	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	RuleCatalogBootstrapKey    = "rule_catalog_v1"
	RuleCatalogSchemaVersion   = 8
	RuleCatalogStatusReady     = "ready"
	RuleCatalogStatusPartial   = "partial"
	RuleCatalogStatusEmpty     = "empty"
	maxRuleCatalogErrorMessage = 4000
	maxPocDescriptionRunes     = 500
)

const (
	PocExecutionClassDetection    = "detection"
	PocExecutionClassVerification = "verification"
	PocRiskLevelUnknown           = "unknown"
	PocRiskLevelInfo              = "info"
	PocRiskLevelLow               = "low"
	PocRiskLevelMedium            = "medium"
	PocRiskLevelHigh              = "high"
)

var (
	ruleCatalogSyncMu            sync.Mutex
	ruleCatalogSyncAfterLoadHook func()
)

// RuleCatalogBootstrap tracks whether the structured rule catalog has been
// materialized from the raw arsenals table for the current schema version.
type RuleCatalogBootstrap struct {
	Key               string `gorm:"primaryKey"`
	SchemaVersion     int
	Source            string
	Status            string `gorm:"index"`
	AggregateHash     string `gorm:"index"`
	ArsenalCount      int
	FingerprintCount  int
	WorkflowCount     int
	DirProbeCount     int
	ActiveFingerCount int
	PocCount          int
	LastError         string `gorm:"type:text"`
	LastSeededAt      *time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
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
	ExecutionClass      string `gorm:"index;default:'detection'"`
	RiskLevel           string `gorm:"index;default:'unknown'"`
	Tags                string `gorm:"type:text"`
	Author              string
	Description         string `gorm:"type:text"`
	Version             int    `gorm:"default:1"`
	State               string `gorm:"index"`
	Enabled             bool   `gorm:"default:true;index"`
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// ActiveFingerprintRule is the derived, queryable index for one independently
// versioned Nuclei behavior probe. Raw YAML remains authoritative in arsenals.
type ActiveFingerprintRule struct {
	ID                   uint   `gorm:"primaryKey;autoIncrement"`
	TenantID             string `gorm:"default:'default';index;uniqueIndex:idx_active_finger_rule_unique"`
	ArtifactID           string `gorm:"index"`
	SourceFile           string `gorm:"index;not null;uniqueIndex:idx_active_finger_rule_unique"`
	Name                 string `gorm:"index;not null"`
	ProductName          string `gorm:"index;not null"`
	ContentHash          string `gorm:"index;not null"`
	Version              int    `gorm:"default:1"`
	State                string `gorm:"index"`
	Enabled              bool   `gorm:"default:true;index"`
	DeclaredAutoProfile  string `gorm:"index"`
	ComputedAutoProfile  string `gorm:"index;not null"`
	AutoEligible         bool   `gorm:"index"`
	MaxRequests          int
	ClassificationReason string `gorm:"type:text"`
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

func NormalizePocExecutionClass(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", PocExecutionClassDetection:
		return PocExecutionClassDetection, nil
	case PocExecutionClassVerification:
		return PocExecutionClassVerification, nil
	case "exploit", "exp":
		return "", fmt.Errorf("POC execution_class %q is not allowed; use a separate EXP package", raw)
	default:
		return "", fmt.Errorf("POC execution_class must be detection or verification")
	}
}

// PocRiskLevelFromNucleiSeverity maps Nuclei info.severity onto the stored
// execution-risk field. critical is stored as high; missing or invalid
// severity stays unknown so it still requires second confirmation.
func PocRiskLevelFromNucleiSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case PocRiskLevelInfo:
		return PocRiskLevelInfo
	case PocRiskLevelLow:
		return PocRiskLevelLow
	case PocRiskLevelMedium:
		return PocRiskLevelMedium
	case PocRiskLevelHigh, "critical":
		return PocRiskLevelHigh
	default:
		return PocRiskLevelUnknown
	}
}

func NormalizePocRiskLevel(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", PocRiskLevelUnknown:
		return PocRiskLevelUnknown, nil
	case PocRiskLevelInfo:
		return PocRiskLevelInfo, nil
	case PocRiskLevelLow:
		return PocRiskLevelLow, nil
	case PocRiskLevelMedium:
		return PocRiskLevelMedium, nil
	case "critical":
		return PocRiskLevelHigh, nil
	case PocRiskLevelHigh:
		return PocRiskLevelHigh, nil
	default:
		return "", fmt.Errorf("POC risk_level must be unknown, info, low, medium, or high")
	}
}

func PocRequiresSecondConfirmation(riskLevel string) bool {
	normalized, err := NormalizePocRiskLevel(riskLevel)
	if err != nil {
		return true
	}
	switch normalized {
	case PocRiskLevelInfo, PocRiskLevelLow, PocRiskLevelMedium:
		return false
	default:
		return true
	}
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

// WorkflowProductSummary stores one product-level relationship summary for the
// arsenal governance UI. It is derived from workflow_rules, fingerprint_rules,
// and poc_rules and can be rebuilt from arsenals at any time.
type WorkflowProductSummary struct {
	TenantID             string `gorm:"primaryKey;default:'default';index"`
	ProductName          string `gorm:"primaryKey;index"`
	IsGeneralPoc         bool   `gorm:"default:false;index"`
	MatchTypes           string `gorm:"type:jsonb"`
	PocNames             string `gorm:"type:jsonb"`
	PocCount             int
	MissingPocNames      string `gorm:"type:jsonb"`
	MissingPocCount      int    `gorm:"index"`
	FingerprintBound     bool   `gorm:"default:false;index"`
	FingerprintRuleCount int
	State                string `gorm:"index"`
	Enabled              bool   `gorm:"default:false;index"`
	ContentHash          string `gorm:"index"`
	Version              int    `gorm:"default:1"`
	UpdatedAt            time.Time
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
	case "active_fingerprint", "active-fingerprint", "behavior_probe", "behavior-probe":
		return "active_fingerprint"
	case "poc_asset", "pocasset":
		return "poc_asset"
	case "config_asset", "configasset", "dict_asset", "dictasset":
		return "config_asset"
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
	case "active_fingerprint":
		return []string{"active_fingerprint", "active-fingerprint", "behavior_probe", "behavior-probe"}
	case "poc_asset":
		return []string{"poc_asset", "pocasset"}
	case "config_asset":
		return []string{"config_asset", "configasset", "dict_asset", "dictasset"}
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
	ruleCatalogSyncMu.Lock()
	defer ruleCatalogSyncMu.Unlock()
	return syncRuleCatalogFromArsenalLocked()
}

func syncRuleCatalogFromArsenalLocked() error {
	var arsenals []Arsenal
	if err := DB.Order("tenant_id, type, file_name").Find(&arsenals).Error; err != nil {
		return err
	}
	if ruleCatalogSyncAfterLoadHook != nil {
		ruleCatalogSyncAfterLoadHook()
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
		Key:               RuleCatalogBootstrapKey,
		SchemaVersion:     RuleCatalogSchemaVersion,
		Source:            "arsenals",
		Status:            status,
		AggregateHash:     aggregateHash,
		ArsenalCount:      len(arsenals),
		FingerprintCount:  len(materialized.fingerprints),
		WorkflowCount:     len(materialized.workflows),
		DirProbeCount:     len(materialized.dirs),
		ActiveFingerCount: len(materialized.activeFingers),
		PocCount:          len(materialized.pocs),
		LastError:         summarizeRuleCatalogErrors(materialized.errors),
		LastSeededAt:      &now,
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
		if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&ActiveFingerprintRule{}).Error; err != nil {
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
		if err := createInBatches(tx, materialized.activeFingers); err != nil {
			return err
		}
		if err := validateAutomaticActiveFingerprintLimit(materialized.activeFingers); err != nil {
			return err
		}
		if err := disableNonApprovedCatalogRows(tx); err != nil {
			return err
		}
		if err := refreshWorkflowProductSummaries(tx, materialized.fingerprints, materialized.workflows, materialized.pocs); err != nil {
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
		"[RuleCatalog] bootstrap=%s arsenals=%d pocs=%d fingerprints=%d workflows=%d dirs=%d active_fingers=%d errors=%d",
		status,
		len(arsenals),
		len(materialized.pocs),
		len(materialized.fingerprints),
		len(materialized.workflows),
		len(materialized.dirs),
		len(materialized.activeFingers),
		len(materialized.errors),
	)
	if len(materialized.errors) > 0 {
		return fmt.Errorf("rule catalog materialized with %d errors: %s", len(materialized.errors), summarizeRuleCatalogErrors(materialized.errors))
	}
	return nil
}

func activeFingerprintTenantSet(rules []ActiveFingerprintRule) map[string]struct{} {
	out := make(map[string]struct{})
	for _, rule := range rules {
		out[rule.TenantID] = struct{}{}
	}
	return out
}

func validateAutomaticActiveFingerprintLimit(rules []ActiveFingerprintRule) error {
	for tenantID := range activeFingerprintTenantSet(rules) {
		enabled := 0
		ids := make(map[string]string)
		for _, rule := range rules {
			if rule.TenantID == tenantID && rule.Enabled && rule.AutoEligible {
				enabled++
				id := strings.ToLower(strings.TrimSpace(rule.Name))
				if other, duplicate := ids[id]; duplicate {
					return fmt.Errorf("tenant %s active fingerprints %s and %s use duplicate template id %q", tenantID, other, rule.SourceFile, rule.Name)
				}
				ids[id] = rule.SourceFile
			}
		}
		if enabled > activefingerprint.MaxAutoSafePerTenant {
			return fmt.Errorf("tenant %s enables %d automatic active fingerprints; maximum is %d", tenantID, enabled, activefingerprint.MaxAutoSafePerTenant)
		}
	}
	return nil
}

// ValidateRuleCatalogCandidate verifies that replacing or adding one arsenal
// row would still allow the derived rule catalog to materialize. It does not
// write to the database.
func ValidateRuleCatalogCandidate(candidate Arsenal) error {
	ruleCatalogSyncMu.Lock()
	defer ruleCatalogSyncMu.Unlock()
	return validateRuleCatalogCandidateLocked(candidate)
}

func validateRuleCatalogCandidateLocked(candidate Arsenal) error {
	var arsenals []Arsenal
	if err := DB.Order("tenant_id, type, file_name").Find(&arsenals).Error; err != nil {
		return err
	}
	replaced := false
	for i := range arsenals {
		if arsenals[i].ID == candidate.ID && arsenals[i].TenantID == candidate.TenantID {
			arsenals[i] = candidate
			replaced = true
			break
		}
	}
	if !replaced {
		arsenals = append(arsenals, candidate)
	}
	materialized := materializeRuleCatalog(arsenals)
	if len(materialized.errors) > 0 {
		return fmt.Errorf("rule catalog materialized with %d errors: %s", len(materialized.errors), summarizeRuleCatalogErrors(materialized.errors))
	}
	return validateAutomaticActiveFingerprintLimit(materialized.activeFingers)
}

// ApplyRuleCatalogCandidate serializes a validated governance mutation with
// catalog materialization. This prevents concurrent publication of two safe
// probes from both passing the per-tenant budget against stale state.
func ApplyRuleCatalogCandidate(candidate Arsenal, mutate func(*gorm.DB) error) error {
	ruleCatalogSyncMu.Lock()
	defer ruleCatalogSyncMu.Unlock()
	if err := validateRuleCatalogCandidateLocked(candidate); err != nil {
		return err
	}
	if err := DB.Transaction(mutate); err != nil {
		return err
	}
	return syncRuleCatalogFromArsenalLocked()
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
	fingerprints  []FingerprintRule
	workflows     []WorkflowRule
	dirs          []DirRule
	activeFingers []ActiveFingerprintRule
	pocs          []PocRule
	errors        []string
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
			rule, err := materializePocRule(arsenal)
			if err != nil {
				out.errors = append(out.errors, err.Error())
				continue
			}
			out.pocs = append(out.pocs, rule)
		case "active_fingerprint":
			rule, err := materializeActiveFingerprintRule(arsenal)
			if err != nil {
				out.errors = append(out.errors, err.Error())
				continue
			}
			out.activeFingers = append(out.activeFingers, rule)
		}
	}

	return out
}

func materializeActiveFingerprintRule(arsenal Arsenal) (ActiveFingerprintRule, error) {
	classification, err := activefingerprint.Inspect(arsenal.FileName, []byte(sanitizePostgresText(arsenal.Content)))
	if err != nil {
		return ActiveFingerprintRule{}, fmt.Errorf("active fingerprint %s is invalid: %w", arsenal.FileName, err)
	}
	reasons, _ := json.Marshal(classification.Reasons)
	return ActiveFingerprintRule{
		TenantID: arsenal.TenantID, ArtifactID: arsenal.ID, SourceFile: arsenal.FileName,
		Name: classification.ID, ProductName: classification.Product, ContentHash: arsenal.Hash,
		Version: arsenal.Version, State: arsenal.State, Enabled: arsenal.State == "Approved",
		DeclaredAutoProfile: classification.DeclaredProfile, ComputedAutoProfile: classification.ComputedProfile,
		AutoEligible: classification.AutoEligible, MaxRequests: classification.MaxRequests,
		ClassificationReason: string(reasons),
	}, nil
}

func materializeFingerprintRules(arsenal Arsenal) ([]FingerprintRule, error) {
	content := sanitizePostgresText(arsenal.Content)

	var single struct {
		Category string      `json:"category"`
		Product  string      `json:"product"`
		Rule     string      `json:"rule"`
		Tags     interface{} `json:"tags"`
	}
	if err := json.Unmarshal([]byte(content), &single); err == nil && strings.TrimSpace(single.Product) != "" && strings.TrimSpace(single.Rule) != "" {
		category := strings.TrimSpace(single.Category)
		if category == "" {
			category = "web"
		}
		return []FingerprintRule{{
			TenantID:    arsenal.TenantID,
			ArtifactID:  arsenal.ID,
			SourceFile:  arsenal.FileName,
			ProductName: strings.TrimSpace(single.Product),
			RuleExpr:    strings.TrimSpace(single.Rule),
			Category:    category,
			ContentHash: arsenal.Hash,
			Version:     arsenal.Version,
			State:       arsenal.State,
			Enabled:     arsenal.State == "Approved",
		}}, nil
	}

	var raw map[string]interface{}
	if err := yaml.Unmarshal([]byte(content), &raw); err != nil {
		return nil, fmt.Errorf("finger yaml parse failed for %s: %w", arsenal.FileName, err)
	}

	rows := make([]FingerprintRule, 0)
	for productName, value := range raw {
		rules := toStringSlice(value)
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
	content := sanitizePostgresText(arsenal.Content)

	var single struct {
		MatchType string `json:"match_type"`
		Poc       string `json:"poc"`
		Product   string `json:"product"`
	}
	if err := json.Unmarshal([]byte(content), &single); err == nil && strings.TrimSpace(single.Product) != "" && strings.TrimSpace(single.Poc) != "" {
		matchType := strings.ToLower(strings.TrimSpace(single.MatchType))
		if matchType == "" {
			matchType = "root"
		}
		return []WorkflowRule{{
			TenantID:    arsenal.TenantID,
			ArtifactID:  arsenal.ID,
			SourceFile:  arsenal.FileName,
			ProductName: strings.TrimSpace(single.Product),
			PocName:     strings.TrimSpace(single.Poc),
			MatchType:   matchType,
			ContentHash: arsenal.Hash,
			Version:     arsenal.Version,
			State:       arsenal.State,
			Enabled:     arsenal.State == "Approved",
		}}, nil
	}

	type workflowEntry struct {
		Type []string `yaml:"type"`
		Pocs []string `yaml:"pocs"`
	}

	var raw map[string]workflowEntry
	if err := yaml.Unmarshal([]byte(content), &raw); err != nil {
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
	content := sanitizePostgresText(arsenal.Content)

	var single struct {
		Path    string `json:"path"`
		Product string `json:"product"`
	}
	if err := json.Unmarshal([]byte(content), &single); err == nil && strings.TrimSpace(single.Product) != "" && strings.TrimSpace(single.Path) != "" {
		return []DirRule{{
			TenantID:    arsenal.TenantID,
			ArtifactID:  arsenal.ID,
			SourceFile:  arsenal.FileName,
			Path:        strings.TrimSpace(single.Path),
			ProductName: strings.TrimSpace(single.Product),
			ContentHash: arsenal.Hash,
			Version:     arsenal.Version,
			State:       arsenal.State,
			Enabled:     arsenal.State == "Approved",
		}}, nil
	}

	var raw map[string]interface{}
	if err := yaml.Unmarshal([]byte(content), &raw); err != nil {
		return nil, fmt.Errorf("dir yaml parse failed for %s: %w", arsenal.FileName, err)
	}

	rows := make([]DirRule, 0)
	for productName, value := range raw {
		paths := toStringSlice(value)
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

func materializePocRule(arsenal Arsenal) (PocRule, error) {
	meta := parsePocMeta([]byte(arsenal.Content))
	executionClass, err := NormalizePocExecutionClass(meta.executionClass)
	if err != nil {
		return PocRule{}, fmt.Errorf("poc governance metadata invalid for %s: %w", arsenal.FileName, err)
	}
	riskLevel, err := NormalizePocRiskLevel(meta.riskLevel)
	if err != nil {
		return PocRule{}, fmt.Errorf("poc governance metadata invalid for %s: %w", arsenal.FileName, err)
	}
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
		ExecutionClass:      executionClass,
		RiskLevel:           riskLevel,
		Tags:                meta.tags,
		Author:              meta.author,
		Description:         meta.description,
		Version:             arsenal.Version,
		State:               arsenal.State,
		Enabled:             arsenal.State == "Approved",
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
	executionClass      string
	riskLevel           string
}

func parsePocMeta(content []byte) pocMeta {
	text := sanitizePostgresText(string(content))
	content = []byte(text)
	meta := pocMeta{
		compatibilityStatus: "unknown",
		executionClass:      PocExecutionClassDetection,
		riskLevel:           PocRiskLevelUnknown,
	}
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
		meta.executionClass = strings.TrimSpace(firstPocMetadataValue(parsed.Info.Metadata, "argus-execution-class", "argus_execution_class", "execution-class", "execution_class"))
		if meta.executionClass == "" {
			meta.executionClass = PocExecutionClassDetection
		}
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
	meta.riskLevel = PocRiskLevelFromNucleiSeverity(meta.severity)
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

func toStringSlice(value interface{}) []string {
	switch v := value.(type) {
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return v
	case string:
		if strings.TrimSpace(v) == "" {
			return nil
		}
		return []string{v}
	default:
		return nil
	}
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
	return tx.Clauses(clause.OnConflict{DoNothing: true}).CreateInBatches(items, 500).Error
}

func disableNonApprovedCatalogRows(tx *gorm.DB) error {
	for _, model := range []interface{}{&FingerprintRule{}, &WorkflowRule{}, &DirRule{}, &PocRule{}, &ActiveFingerprintRule{}} {
		if err := tx.Model(model).Where("state <> ?", "Approved").Update("enabled", false).Error; err != nil {
			return err
		}
	}
	return nil
}

func refreshWorkflowProductSummaries(tx *gorm.DB, fingerprints []FingerprintRule, workflows []WorkflowRule, pocs []PocRule) error {
	if !tx.Migrator().HasTable(&WorkflowProductSummary{}) {
		if err := tx.AutoMigrate(&WorkflowProductSummary{}); err != nil {
			return err
		}
	}

	tenantSet := make(map[string]struct{})
	for _, row := range workflows {
		tenantSet[row.TenantID] = struct{}{}
	}
	for _, row := range fingerprints {
		tenantSet[row.TenantID] = struct{}{}
	}
	for _, row := range pocs {
		tenantSet[row.TenantID] = struct{}{}
	}
	if len(tenantSet) == 0 {
		return tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&WorkflowProductSummary{}).Error
	}

	fingerprintCounts := make(map[string]map[string]int)
	for _, row := range fingerprints {
		if !row.Enabled {
			continue
		}
		if _, ok := fingerprintCounts[row.TenantID]; !ok {
			fingerprintCounts[row.TenantID] = make(map[string]int)
		}
		fingerprintCounts[row.TenantID][row.ProductName]++
	}

	pocNames := make(map[string]map[string]struct{})
	for _, row := range pocs {
		if !row.Enabled {
			continue
		}
		if _, ok := pocNames[row.TenantID]; !ok {
			pocNames[row.TenantID] = make(map[string]struct{})
		}
		pocNames[row.TenantID][row.SourceFile] = struct{}{}
		pocNames[row.TenantID][strings.TrimSuffix(row.SourceFile, filepath.Ext(row.SourceFile))] = struct{}{}
		if row.Name != "" {
			pocNames[row.TenantID][row.Name] = struct{}{}
		}
	}

	type summaryBuilder struct {
		tenantID    string
		productName string
		matchTypes  map[string]struct{}
		pocs        map[string]struct{}
		missingPocs map[string]struct{}
		enabled     bool
		state       string
		contentHash string
		version     int
		updatedAt   time.Time
	}
	builders := make(map[string]*summaryBuilder)
	for _, row := range workflows {
		key := row.TenantID + "\x00" + row.ProductName
		b := builders[key]
		if b == nil {
			b = &summaryBuilder{
				tenantID:    row.TenantID,
				productName: row.ProductName,
				matchTypes:  make(map[string]struct{}),
				pocs:        make(map[string]struct{}),
				missingPocs: make(map[string]struct{}),
				state:       row.State,
				contentHash: row.ContentHash,
				version:     row.Version,
				updatedAt:   row.UpdatedAt,
			}
			builders[key] = b
		}
		if row.Enabled {
			b.enabled = true
		}
		if row.State == "Approved" {
			b.state = row.State
		}
		if row.Version > b.version {
			b.version = row.Version
		}
		if row.UpdatedAt.After(b.updatedAt) {
			b.updatedAt = row.UpdatedAt
		}
		if row.MatchType != "" {
			b.matchTypes[row.MatchType] = struct{}{}
		}
		if row.PocName != "" {
			b.pocs[row.PocName] = struct{}{}
			if _, ok := pocNames[row.TenantID][row.PocName]; !ok {
				b.missingPocs[row.PocName] = struct{}{}
			}
		}
	}

	summaries := make([]WorkflowProductSummary, 0, len(builders))
	for _, b := range builders {
		matchTypes := sortedKeys(b.matchTypes)
		pocsForProduct := sortedKeys(b.pocs)
		missing := sortedKeys(b.missingPocs)
		fpCount := fingerprintCounts[b.tenantID][b.productName]
		if b.updatedAt.IsZero() {
			b.updatedAt = time.Now()
		}
		summaries = append(summaries, WorkflowProductSummary{
			TenantID:             b.tenantID,
			ProductName:          b.productName,
			IsGeneralPoc:         strings.HasPrefix(b.productName, "General-Poc-"),
			MatchTypes:           marshalJSONText(matchTypes),
			PocNames:             marshalJSONText(pocsForProduct),
			PocCount:             len(pocsForProduct),
			MissingPocNames:      marshalJSONText(missing),
			MissingPocCount:      len(missing),
			FingerprintBound:     fpCount > 0,
			FingerprintRuleCount: fpCount,
			State:                b.state,
			Enabled:              b.enabled,
			ContentHash:          b.contentHash,
			Version:              b.version,
			UpdatedAt:            b.updatedAt,
		})
	}

	for tenantID := range tenantSet {
		if err := tx.Where("tenant_id = ?", tenantID).Delete(&WorkflowProductSummary{}).Error; err != nil {
			return err
		}
	}
	return createInBatches(tx, summaries)
}

func sortedKeys(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
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
