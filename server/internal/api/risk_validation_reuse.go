package api

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/TokEat/argus/server/internal/db"
)

type riskValidationReuseSource struct {
	SourceTaskID    string
	SourceAttemptID string
	Target          string
}

func taskFingerprintReuseSources(ctx context.Context, tenantID string, task db.RootTask) ([]riskValidationReuseSource, error) {
	var sources []riskValidationReuseSource
	err := db.DB.WithContext(ctx).Table("task_coverage_links AS l").Distinct().
		Select("l.source_task_id, l.source_attempt_id, c.normalized_target AS target").
		Joins("JOIN scan_coverages c ON c.id = l.coverage_id AND c.tenant_id = l.tenant_id AND c.project_id = l.project_id").
		Where("l.tenant_id = ? AND l.project_id = ? AND l.root_task_id = ? AND l.link_type = ? AND l.status = ?", tenantID, task.ProjectID, task.ID, "reused", "active").
		Where("c.stage = ? AND c.status = ? AND c.source_task_id = l.source_task_id AND c.source_attempt_id = l.source_attempt_id", "fingerprint", "complete").
		Where("c.valid_until IS NULL OR c.valid_until > ?", time.Now().UTC()).
		Order("l.source_task_id asc, l.source_attempt_id asc, c.normalized_target asc").
		Scan(&sources).Error
	if err != nil {
		return nil, fmt.Errorf("load reused fingerprint sources: %w", err)
	}
	return sources, nil
}

func loadReusedFingerprintHits(ctx context.Context, tenantID, projectID string, sources []riskValidationReuseSource) ([]db.FingerprintHit, error) {
	if len(sources) == 0 {
		return nil, nil
	}
	taskIDs, attemptIDs := make([]string, 0, len(sources)), make([]string, 0, len(sources))
	allowed := make(map[string]struct{}, len(sources)*2)
	for _, source := range sources {
		taskIDs = append(taskIDs, source.SourceTaskID)
		attemptIDs = append(attemptIDs, source.SourceAttemptID)
		allowed[source.SourceTaskID+"\x00"+source.Target] = struct{}{}
		allowed[source.SourceAttemptID+"\x00"+source.Target] = struct{}{}
	}
	var candidates []db.FingerprintHit
	if err := db.DB.WithContext(ctx).Where("tenant_id = ? AND project_id = ? AND (root_task_id IN ? OR task_id IN ?)", tenantID, projectID, taskIDs, attemptIDs).
		Order("target asc, product_name asc").Find(&candidates).Error; err != nil {
		return nil, fmt.Errorf("load reused fingerprint hits: %w", err)
	}
	hits := make([]db.FingerprintHit, 0, len(candidates))
	for _, hit := range candidates {
		_, taskAllowed := allowed[hit.RootTaskID+"\x00"+hit.Target]
		_, attemptAllowed := allowed[hit.TaskID+"\x00"+hit.Target]
		if taskAllowed || attemptAllowed {
			hits = append(hits, hit)
		}
	}
	return hits, nil
}

func loadRiskValidationAssets(ctx context.Context, tenantID string, task db.RootTask, subTaskIDs []string, reuseSources []riskValidationReuseSource) ([]riskValidationAssetPreview, map[string]riskValidationAssetPreview, error) {
	byTarget := make(map[string]riskValidationAssetPreview)
	var assets []db.Asset
	query := db.DB.WithContext(ctx).Where("tenant_id = ? AND project_id = ?", tenantID, task.ProjectID)
	if len(subTaskIDs) > 0 {
		query = query.Where("(root_task_id = ? OR task_id IN ?)", task.ID, subTaskIDs)
	} else {
		query = query.Where("root_task_id = ?", task.ID)
	}
	if err := query.Order("target asc, updated_at desc").Find(&assets).Error; err != nil {
		return nil, nil, fmt.Errorf("load task assets: %w", err)
	}
	if len(reuseSources) > 0 {
		taskIDs, attemptIDs := make([]string, 0, len(reuseSources)), make([]string, 0, len(reuseSources))
		allowed := make(map[string]struct{}, len(reuseSources)*2)
		for _, source := range reuseSources {
			taskIDs = append(taskIDs, source.SourceTaskID)
			attemptIDs = append(attemptIDs, source.SourceAttemptID)
			allowed[source.SourceTaskID+"\x00"+source.Target] = struct{}{}
			allowed[source.SourceAttemptID+"\x00"+source.Target] = struct{}{}
		}
		var reused []db.Asset
		if err := db.DB.WithContext(ctx).Where("tenant_id = ? AND project_id = ? AND (root_task_id IN ? OR task_id IN ?)", tenantID, task.ProjectID, taskIDs, attemptIDs).
			Order("target asc, updated_at desc").Find(&reused).Error; err != nil {
			return nil, nil, fmt.Errorf("load reused task assets: %w", err)
		}
		for _, asset := range reused {
			_, taskAllowed := allowed[asset.RootTaskID+"\x00"+asset.Target]
			_, attemptAllowed := allowed[asset.TaskID+"\x00"+asset.Target]
			if taskAllowed || attemptAllowed {
				assets = append(assets, asset)
			}
		}
	}
	out := make([]riskValidationAssetPreview, 0, len(assets))
	seenEndpoint := make(map[string]struct{}, len(assets))
	for _, asset := range assets {
		candidate := riskValidationAssetPreview{
			Target: asset.Target, URL: asset.URL, Protocol: asset.Protocol,
			Port: asset.Port, Title: asset.Title, Service: asset.Service,
		}
		current, exists := byTarget[asset.Target]
		if !exists || (current.URL == "" && candidate.URL != "") {
			byTarget[asset.Target] = candidate
		}
		endpoint := strings.TrimSpace(candidate.URL)
		if endpoint == "" {
			endpoint = strings.TrimSpace(candidate.Target)
		}
		key := strings.ToLower(endpoint) + "\x00" + strings.ToLower(strings.TrimSpace(candidate.Target))
		if endpoint == "" {
			continue
		}
		if _, duplicate := seenEndpoint[key]; duplicate {
			continue
		}
		seenEndpoint[key] = struct{}{}
		out = append(out, candidate)
	}
	return out, byTarget, nil
}
