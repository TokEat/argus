package db

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/P0lar1ght/argus/shared/proto/go/scanplan"
	"gorm.io/gorm"
)

func riskValidationPOCSetHash(config, target string) (string, bool) {
	var internal struct {
		ExecutionMode              string
		RiskValidationTargets      map[string][]string
		RiskValidationPocHashes    map[string]string
		TargetFingerprints         map[string][]string
		GoPocCatalogSHA256         string
		RiskValidationGoPocTargets []struct {
			Target, Plugin, Capability, Trigger, ObservationSHA256 string
			PluginRevision, RequestCost                            int
		}
	}
	if json.Unmarshal([]byte(config), &internal) != nil || !strings.EqualFold(strings.TrimSpace(internal.ExecutionMode), "risk_validation") {
		return "", false
	}
	pocs := append([]string(nil), internal.RiskValidationTargets[target]...)
	sort.Strings(pocs)
	parts := make([]string, 0, len(pocs)+len(internal.RiskValidationGoPocTargets)+len(internal.TargetFingerprints[target]))
	for _, poc := range pocs {
		poc = strings.TrimSpace(poc)
		hash := strings.ToLower(strings.TrimSpace(internal.RiskValidationPocHashes[poc]))
		if poc == "" || hash == "" {
			return "", false
		}
		parts = append(parts, strings.Join([]string{"nuclei", poc, hash}, "\x00"))
	}
	for _, item := range internal.RiskValidationGoPocTargets {
		if strings.TrimSpace(item.Target) != target {
			continue
		}
		if strings.TrimSpace(internal.GoPocCatalogSHA256) == "" || item.Plugin == "" || item.PluginRevision < 1 || item.RequestCost < 1 || item.ObservationSHA256 == "" {
			return "", false
		}
		parts = append(parts, strings.Join([]string{"gopoc", internal.GoPocCatalogSHA256, item.Plugin, item.Capability, item.Trigger, item.ObservationSHA256, fmt.Sprint(item.PluginRevision), fmt.Sprint(item.RequestCost)}, "\x00"))
	}
	if len(parts) == 0 {
		prints := append([]string(nil), internal.TargetFingerprints[target]...)
		for i := range prints {
			prints[i] = strings.TrimSpace(prints[i])
		}
		sort.Strings(prints)
		for _, product := range prints {
			if product == "" {
				return "", false
			}
			parts = append(parts, strings.Join([]string{"fingerprint", product}, "\x00"))
		}
	}
	if len(parts) == 0 {
		return "", false
	}
	sort.Strings(parts)
	return sha256Hex([]byte(strings.Join(parts, "\x00"))), true
}

func riskValidationEndpointContentHash(tx *gorm.DB, attempt SubTask, networkZone, target, targetHash string) (string, bool) {
	if hash, ok := latestEndpointContentHash(tx, attempt.TenantID, attempt.ProjectID, networkZone, targetHash); ok {
		return hash, true
	}
	if httpCoverageRecorded(tx, attempt.TenantID, attempt.ProjectID, networkZone, targetHash) {
		return "", false
	}
	if hash, ok := endpointContentHashFromFingerprintSource(tx, attempt, networkZone, target); ok {
		return hash, true
	}
	return uniqueParentBatchEndpointContentHash(tx, attempt, networkZone)
}

func latestEndpointContentHash(tx *gorm.DB, tenantID, projectID, networkZone, targetHash string) (string, bool) {
	var coverage ScanCoverage
	if err := tx.Where(
		"tenant_id = ? AND project_id = ? AND network_zone = ? AND target_hash = ? AND stage = ? AND status = ?",
		tenantID, projectID, networkZone, targetHash, string(scanplan.StageHTTPProbe), string(scanplan.CoverageComplete),
	).Order("finished_at DESC").First(&coverage).Error; err != nil {
		return "", false
	}
	return observationContentHashByID(tx, tenantID, projectID, coverage.SourceObservationID)
}

func httpCoverageRecorded(tx *gorm.DB, tenantID, projectID, networkZone, targetHash string) bool {
	var count int64
	if err := tx.Model(&ScanCoverage{}).Where(
		"tenant_id = ? AND project_id = ? AND network_zone = ? AND target_hash = ? AND stage = ?",
		tenantID, projectID, networkZone, targetHash, string(scanplan.StageHTTPProbe),
	).Count(&count).Error; err != nil {
		return false
	}
	return count > 0
}

func observationContentHashByID(tx *gorm.DB, tenantID, projectID string, observationID uint64) (string, bool) {
	if observationID == 0 {
		return "", false
	}
	var observation ScanObservation
	if err := tx.Select("content_hash").Where("id = ? AND tenant_id = ? AND project_id = ?", observationID, tenantID, projectID).First(&observation).Error; err != nil {
		return "", false
	}
	contentHash := strings.TrimSpace(observation.ContentHash)
	return contentHash, contentHash != ""
}

func endpointContentHashFromFingerprintSource(tx *gorm.DB, attempt SubTask, networkZone, target string) (string, bool) {
	var hits []FingerprintHit
	if err := tx.Select("task_id").Where(
		"tenant_id = ? AND project_id = ? AND root_task_id = ? AND target = ?",
		attempt.TenantID, attempt.ProjectID, attempt.RootTaskID, target,
	).Limit(16).Find(&hits).Error; err != nil || len(hits) == 0 {
		return "", false
	}
	attemptIDs := make([]string, 0, len(hits))
	seen := make(map[string]struct{}, len(hits))
	for _, hit := range hits {
		id := strings.TrimSpace(hit.TaskID)
		if id == "" {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		attemptIDs = append(attemptIDs, id)
	}
	if len(attemptIDs) == 0 {
		return "", false
	}
	var sources []SubTask
	if err := tx.Select("id", "tenant_id", "project_id", "root_task_id", "chunk_targets").
		Where("tenant_id = ? AND project_id = ? AND root_task_id = ? AND id IN ?", attempt.TenantID, attempt.ProjectID, attempt.RootTaskID, attemptIDs).
		Find(&sources).Error; err != nil || len(sources) == 0 {
		return "", false
	}
	hashes := make(map[string]struct{}, len(sources))
	for _, source := range sources {
		var chunk []string
		if json.Unmarshal([]byte(source.ChunkTargets), &chunk) != nil {
			continue
		}
		for _, parentTarget := range chunk {
			parentTarget = strings.TrimSpace(parentTarget)
			if parentTarget == "" {
				continue
			}
			hash, ok := latestEndpointContentHash(tx, attempt.TenantID, attempt.ProjectID, networkZone, sha256Hex([]byte(parentTarget)))
			if !ok {
				continue
			}
			hashes[hash] = struct{}{}
		}
	}
	if len(hashes) != 1 {
		return "", false
	}
	for hash := range hashes {
		return hash, true
	}
	return "", false
}

func uniqueParentBatchEndpointContentHash(tx *gorm.DB, attempt SubTask, networkZone string) (string, bool) {
	parentBatchID, ok := parentAssetBatchID(attempt.BatchID)
	if !ok {
		return "", false
	}
	var rows []ScanCoverage
	if err := tx.Select("source_observation_id").Where(
		"tenant_id = ? AND project_id = ? AND network_zone = ? AND source_task_id = ? AND source_batch_id = ? AND stage = ? AND status = ?",
		attempt.TenantID, attempt.ProjectID, networkZone, attempt.RootTaskID, parentBatchID,
		string(scanplan.StageHTTPProbe), string(scanplan.CoverageComplete),
	).Find(&rows).Error; err != nil || len(rows) == 0 {
		return "", false
	}
	hashes := make(map[string]struct{}, len(rows))
	for _, row := range rows {
		hash, found := observationContentHashByID(tx, attempt.TenantID, attempt.ProjectID, row.SourceObservationID)
		if !found {
			return "", false
		}
		hashes[hash] = struct{}{}
	}
	if len(hashes) != 1 {
		return "", false
	}
	for hash := range hashes {
		return hash, true
	}
	return "", false
}

func parentAssetBatchID(batchID string) (string, bool) {
	const suffix = "-risk"
	batchID = strings.TrimSpace(batchID)
	if !strings.HasSuffix(batchID, suffix) {
		return "", false
	}
	parent := strings.TrimSuffix(batchID, suffix)
	if parent == "" {
		return "", false
	}
	return parent, true
}
