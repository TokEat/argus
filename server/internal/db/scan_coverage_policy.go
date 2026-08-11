package db

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/shared/proto/go/scanplan"
	"gorm.io/gorm"
)

const (
	serverLivenessCoverageTTL  = 5 * time.Minute
	serverPortCoverageTTL      = time.Hour
	serverDiscoveryCoverageTTL = 6 * time.Hour
	serverRiskCoverageTTL      = 24 * time.Hour
)

// serverCoverageTTL keeps Server-side reuse bounded even when an Agent does
// not provide an expiry. CLI policy remains independently configurable in
// argus-data and is introduced by the CLI goals.
func serverCoverageTTL(stage scanplan.Stage) time.Duration {
	switch stage {
	case scanplan.StageICMPDiscovery, scanplan.StageTCPLiveness:
		return serverLivenessCoverageTTL
	case scanplan.StagePortScan:
		return serverPortCoverageTTL
	case scanplan.StageSearchEngine, scanplan.StageSubdomainDiscovery, scanplan.StageCDNClassification,
		scanplan.StageProtocolIdentify, scanplan.StageHTTPProbe, scanplan.StageHostBinding,
		scanplan.StageDirectoryProbe, scanplan.StageFingerprint:
		return serverDiscoveryCoverageTTL
	case scanplan.StageRiskValidation:
		return serverRiskCoverageTTL
	default:
		return 0
	}
}

func coverageValidUntil(status scanplan.CoverageStatus, stage scanplan.Stage, finishedAt time.Time) *time.Time {
	if status != scanplan.CoverageComplete || finishedAt.IsZero() {
		return nil
	}
	ttl := serverCoverageTTL(stage)
	if ttl <= 0 {
		return nil
	}
	validUntil := finishedAt.Add(ttl)
	return &validUntil
}

// dependentCoverageStages returns only stages whose evidence consumes the
// changed stage output. Upstream and unrelated evidence remains valid.
func dependentCoverageStages(stage scanplan.Stage) []scanplan.Stage {
	switch stage {
	case scanplan.StageSearchEngine:
		return []scanplan.Stage{scanplan.StageSubdomainDiscovery, scanplan.StageCDNClassification, scanplan.StagePortScan, scanplan.StageProtocolIdentify, scanplan.StageHTTPProbe, scanplan.StageHostBinding, scanplan.StageDirectoryProbe, scanplan.StageFingerprint, scanplan.StageRiskValidation}
	case scanplan.StageSubdomainDiscovery:
		return []scanplan.Stage{scanplan.StageCDNClassification, scanplan.StagePortScan, scanplan.StageProtocolIdentify, scanplan.StageHTTPProbe, scanplan.StageHostBinding, scanplan.StageDirectoryProbe, scanplan.StageFingerprint, scanplan.StageRiskValidation}
	case scanplan.StageCDNClassification, scanplan.StageICMPDiscovery, scanplan.StageTCPLiveness:
		return []scanplan.Stage{scanplan.StagePortScan, scanplan.StageProtocolIdentify, scanplan.StageHTTPProbe, scanplan.StageHostBinding, scanplan.StageDirectoryProbe, scanplan.StageFingerprint, scanplan.StageRiskValidation}
	case scanplan.StagePortScan:
		return []scanplan.Stage{scanplan.StageProtocolIdentify, scanplan.StageHTTPProbe, scanplan.StageHostBinding, scanplan.StageDirectoryProbe, scanplan.StageFingerprint, scanplan.StageRiskValidation}
	case scanplan.StageProtocolIdentify:
		return []scanplan.Stage{scanplan.StageHTTPProbe, scanplan.StageHostBinding, scanplan.StageDirectoryProbe, scanplan.StageFingerprint, scanplan.StageRiskValidation}
	case scanplan.StageHTTPProbe:
		return []scanplan.Stage{scanplan.StageHostBinding, scanplan.StageDirectoryProbe, scanplan.StageFingerprint, scanplan.StageRiskValidation}
	case scanplan.StageHostBinding, scanplan.StageDirectoryProbe:
		return []scanplan.Stage{scanplan.StageFingerprint, scanplan.StageRiskValidation}
	case scanplan.StageFingerprint:
		return []scanplan.Stage{scanplan.StageRiskValidation}
	default:
		return nil
	}
}

func currentCoverageContentHash(tx *gorm.DB, tenantID, projectID, workKeyHash string) (string, bool, error) {
	var coverage ScanCoverage
	err := tx.Select("source_observation_id").Where(
		"tenant_id = ? AND project_id = ? AND work_key_hash = ?", tenantID, projectID, workKeyHash,
	).First(&coverage).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("load previous scan coverage: %w", err)
	}
	if coverage.SourceObservationID == 0 {
		return "", false, nil
	}
	var observation ScanObservation
	if err := tx.Select("content_hash").Where(
		"id = ? AND tenant_id = ? AND project_id = ?", coverage.SourceObservationID, tenantID, projectID,
	).First(&observation).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("load previous scan observation content: %w", err)
	}
	return strings.TrimSpace(observation.ContentHash), true, nil
}

// invalidateChangedContentDependents invalidates only older downstream
// evidence in the same WorkKey dimensions. Risk validation is additionally
// invalidated across its confirmed config because endpoint content is an
// explicit risk WorkKey dimension.
func invalidateChangedContentDependents(tx *gorm.DB, observation ScanObservation, stage scanplan.Stage) (int64, error) {
	dependents := dependentCoverageStages(stage)
	if len(dependents) == 0 {
		return 0, nil
	}
	reason := "upstream_content_changed:" + string(stage)
	commonStages := make([]string, 0, len(dependents))
	includeRisk := false
	for _, dependent := range dependents {
		if dependent == scanplan.StageRiskValidation {
			includeRisk = true
			continue
		}
		commonStages = append(commonStages, string(dependent))
	}
	updates := map[string]interface{}{
		"status":         string(scanplan.CoverageInvalidated),
		"valid_until":    nil,
		"invalid_reason": reason,
		"revision":       gorm.Expr("revision + 1"),
	}
	var invalidated int64
	if len(commonStages) > 0 {
		result := tx.Model(&ScanCoverage{}).Where(
			"tenant_id = ? AND project_id = ? AND network_zone = ? AND target_hash = ? AND scope_hash = ? AND config_hash = ? AND rule_version = ? AND stage IN ? AND status = ? AND finished_at <= ?",
			observation.TenantID, observation.ProjectID, observation.NetworkZone, observation.TargetHash,
			observation.ScopeHash, observation.ConfigHash, observation.RuleVersion, commonStages,
			string(scanplan.CoverageComplete), observation.ObservedAt,
		).Updates(updates)
		if result.Error != nil {
			return 0, fmt.Errorf("invalidate dependent scan coverage: %w", result.Error)
		}
		invalidated += result.RowsAffected
	}
	if includeRisk {
		result := tx.Model(&ScanCoverage{}).Where(
			"tenant_id = ? AND project_id = ? AND network_zone = ? AND target_hash = ? AND stage = ? AND status = ? AND finished_at <= ?",
			observation.TenantID, observation.ProjectID, observation.NetworkZone, observation.TargetHash,
			string(scanplan.StageRiskValidation), string(scanplan.CoverageComplete), observation.ObservedAt,
		).Updates(updates)
		if result.Error != nil {
			return 0, fmt.Errorf("invalidate endpoint-dependent risk coverage: %w", result.Error)
		}
		invalidated += result.RowsAffected
	}
	return invalidated, nil
}
