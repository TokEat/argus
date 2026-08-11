package api

import (
	"fmt"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/P0lar1ght/argus/shared/proto/go/scanplan"
	"gorm.io/gorm"
)

const taskCoverageExplanationLimit = 100

type taskCoverageExplanationSummary struct {
	ExecutedWorkItems int64 `json:"executed_work_items"`
	ReusedStages      int64 `json:"reused_stages"`
	InFlightWorkItems int64 `json:"in_flight_work_items"`
	InvalidatedStages int64 `json:"invalidated_stages"`
	ExpiredStages     int64 `json:"expired_stages"`
	SavedStages       int64 `json:"saved_stages"`
	SavedTargets      int   `json:"saved_targets"`
}

type taskCoverageExplanationSource struct {
	TaskID    string `json:"task_id"`
	TaskName  string `json:"task_name"`
	BatchID   string `json:"batch_id"`
	AttemptID string `json:"attempt_id"`
}

type taskCoverageExplanationItem struct {
	LinkType         string                        `json:"link_type"`
	Status           string                        `json:"status"`
	NormalizedTarget string                        `json:"normalized_target"`
	Stage            string                        `json:"stage"`
	NetworkZone      string                        `json:"network_zone"`
	Source           taskCoverageExplanationSource `json:"source"`
	Reason           string                        `json:"reason"`
	CreatedAt        time.Time                     `json:"created_at"`
}

type taskCoverageInvalidationItem struct {
	NormalizedTarget string                        `json:"normalized_target"`
	Stage            string                        `json:"stage"`
	Status           string                        `json:"status"`
	Reason           string                        `json:"reason"`
	Source           taskCoverageExplanationSource `json:"source"`
	InvalidatedAt    time.Time                     `json:"invalidated_at"`
	ValidUntil       *time.Time                    `json:"valid_until"`
}

type taskCoverageExplanation struct {
	SchemaVersion          string                         `json:"schema_version"`
	Summary                taskCoverageExplanationSummary `json:"summary"`
	Items                  []taskCoverageExplanationItem  `json:"items"`
	Invalidations          []taskCoverageInvalidationItem `json:"invalidations"`
	ItemsTruncated         bool                           `json:"items_truncated"`
	InvalidationsTruncated bool                           `json:"invalidations_truncated"`
}

type taskCoverageLinkCount struct {
	LinkType string
	Status   string
	Count    int64
}

func buildTaskCoverageExplanation(store *gorm.DB, root db.RootTask) (taskCoverageExplanation, error) {
	result := taskCoverageExplanation{
		SchemaVersion: "argus.task-coverage-explanation/v1",
		Items:         []taskCoverageExplanationItem{},
		Invalidations: []taskCoverageInvalidationItem{},
	}
	if store == nil {
		return result, fmt.Errorf("task coverage store is unavailable")
	}

	linkBase := func() *gorm.DB {
		return store.Model(&db.TaskCoverageLink{}).Where(
			"tenant_id = ? AND project_id = ? AND root_task_id = ?", root.TenantID, root.ProjectID, root.ID,
		)
	}
	var counts []taskCoverageLinkCount
	if err := linkBase().Select("link_type, status, count(*) AS count").Group("link_type, status").Scan(&counts).Error; err != nil {
		return result, fmt.Errorf("count task coverage links: %w", err)
	}
	for _, count := range counts {
		switch count.LinkType {
		case "executed":
			result.Summary.ExecutedWorkItems = count.Count
		case "reused":
			result.Summary.ReusedStages = count.Count
			result.Summary.SavedStages = count.Count
		case "in_flight":
			if count.Status != "waiting" {
				continue
			}
			result.Summary.InFlightWorkItems = count.Count
		}
	}

	reusedTargets, err := linkedCoverageTargets(store, root, []string{"reused"})
	if err != nil {
		return result, err
	}
	executedTargets, err := linkedClaimTargets(store, root, []string{"executed", "in_flight"})
	if err != nil {
		return result, err
	}
	for target := range reusedTargets {
		if _, executed := executedTargets[target]; !executed {
			result.Summary.SavedTargets++
		}
	}

	var links []db.TaskCoverageLink
	if err := linkBase().Order("created_at desc, id desc").Limit(taskCoverageExplanationLimit + 1).Find(&links).Error; err != nil {
		return result, fmt.Errorf("load task coverage links: %w", err)
	}
	if len(links) > taskCoverageExplanationLimit {
		result.ItemsTruncated = true
		links = links[:taskCoverageExplanationLimit]
	}
	coverages, claims, err := loadTaskCoverageLinkEvidence(store, root, links)
	if err != nil {
		return result, err
	}

	invalidations, invalidatedCount, expiredCount, truncated, err := loadTaskCoverageInvalidations(store, root)
	if err != nil {
		return result, err
	}
	result.Summary.InvalidatedStages = invalidatedCount
	result.Summary.ExpiredStages = expiredCount
	result.Invalidations = invalidations
	result.InvalidationsTruncated = truncated

	sourceTaskIDs := make(map[string]struct{})
	for _, link := range links {
		if link.SourceTaskID != "" {
			sourceTaskIDs[link.SourceTaskID] = struct{}{}
		}
	}
	for _, item := range invalidations {
		if item.Source.TaskID != "" {
			sourceTaskIDs[item.Source.TaskID] = struct{}{}
		}
	}
	sourceTaskNames, err := loadTaskCoverageSourceNames(store, root, sourceTaskIDs)
	if err != nil {
		return result, err
	}

	for _, link := range links {
		item := taskCoverageExplanationItem{
			LinkType:  link.LinkType,
			Status:    link.Status,
			Reason:    publicTaskCoverageReason(link.Reason),
			CreatedAt: link.CreatedAt,
		}
		if link.LinkType == "reused" {
			if coverage, ok := coverages[link.CoverageID]; ok && coverage.WorkKeyHash == link.WorkKeyHash {
				item.NormalizedTarget = coverage.NormalizedTarget
				item.Stage = coverage.Stage
				item.NetworkZone = coverage.NetworkZone
			}
		} else if claim, ok := claims[link.ClaimID]; ok && claim.WorkKeyHash == link.WorkKeyHash {
			item.NormalizedTarget = claim.NormalizedTarget
			item.Stage = claim.Stage
			item.NetworkZone = claim.NetworkZone
		}
		if name, allowed := sourceTaskNames[link.SourceTaskID]; allowed {
			item.Source = taskCoverageExplanationSource{
				TaskID: link.SourceTaskID, TaskName: name, BatchID: link.SourceBatchID, AttemptID: link.SourceAttemptID,
			}
		}
		result.Items = append(result.Items, item)
	}
	for index := range result.Invalidations {
		if name, allowed := sourceTaskNames[result.Invalidations[index].Source.TaskID]; allowed {
			result.Invalidations[index].Source.TaskName = name
		} else {
			result.Invalidations[index].Source = taskCoverageExplanationSource{}
		}
	}
	return result, nil
}

func linkedCoverageTargets(store *gorm.DB, root db.RootTask, linkTypes []string) (map[string]struct{}, error) {
	var targets []string
	err := store.Table("task_coverage_links AS links").
		Distinct("coverage.normalized_target").
		Joins("JOIN scan_coverages AS coverage ON coverage.id = links.coverage_id AND coverage.tenant_id = links.tenant_id AND coverage.project_id = links.project_id").
		Where("links.tenant_id = ? AND links.project_id = ? AND links.root_task_id = ? AND links.link_type IN ?", root.TenantID, root.ProjectID, root.ID, linkTypes).
		Where("coverage.normalized_target <> ''").
		Pluck("coverage.normalized_target", &targets).Error
	if err != nil {
		return nil, fmt.Errorf("load reused task coverage targets: %w", err)
	}
	return stringSet(targets), nil
}

func linkedClaimTargets(store *gorm.DB, root db.RootTask, linkTypes []string) (map[string]struct{}, error) {
	var targets []string
	err := store.Table("task_coverage_links AS links").
		Distinct("claim.normalized_target").
		Joins("JOIN scan_work_claims AS claim ON claim.id = links.claim_id AND claim.tenant_id = links.tenant_id AND claim.project_id = links.project_id").
		Where("links.tenant_id = ? AND links.project_id = ? AND links.root_task_id = ? AND links.link_type IN ?", root.TenantID, root.ProjectID, root.ID, linkTypes).
		Where("claim.normalized_target <> ''").
		Pluck("claim.normalized_target", &targets).Error
	if err != nil {
		return nil, fmt.Errorf("load executed task coverage targets: %w", err)
	}
	return stringSet(targets), nil
}

func stringSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			result[value] = struct{}{}
		}
	}
	return result
}

func loadTaskCoverageLinkEvidence(store *gorm.DB, root db.RootTask, links []db.TaskCoverageLink) (map[uint64]db.ScanCoverage, map[uint64]db.ScanWorkClaim, error) {
	coverageIDs := make([]uint64, 0, len(links))
	claimIDs := make([]uint64, 0, len(links))
	for _, link := range links {
		if link.CoverageID != 0 {
			coverageIDs = append(coverageIDs, link.CoverageID)
		}
		if link.ClaimID != 0 {
			claimIDs = append(claimIDs, link.ClaimID)
		}
	}
	coverages := make(map[uint64]db.ScanCoverage, len(coverageIDs))
	if len(coverageIDs) > 0 {
		var rows []db.ScanCoverage
		if err := store.Where("tenant_id = ? AND project_id = ? AND id IN ?", root.TenantID, root.ProjectID, coverageIDs).Find(&rows).Error; err != nil {
			return nil, nil, fmt.Errorf("load task coverage evidence: %w", err)
		}
		for _, row := range rows {
			coverages[row.ID] = row
		}
	}
	claims := make(map[uint64]db.ScanWorkClaim, len(claimIDs))
	if len(claimIDs) > 0 {
		var rows []db.ScanWorkClaim
		if err := store.Where("tenant_id = ? AND project_id = ? AND id IN ?", root.TenantID, root.ProjectID, claimIDs).Find(&rows).Error; err != nil {
			return nil, nil, fmt.Errorf("load task execution claims: %w", err)
		}
		for _, row := range rows {
			claims[row.ID] = row
		}
	}
	return coverages, claims, nil
}

func loadTaskCoverageInvalidations(store *gorm.DB, root db.RootTask) ([]taskCoverageInvalidationItem, int64, int64, bool, error) {
	now := time.Now().UTC()
	linkedCoverageIDs := func() *gorm.DB {
		return store.Model(&db.TaskCoverageLink{}).
			Select("coverage_id").
			Where("tenant_id = ? AND project_id = ? AND root_task_id = ? AND coverage_id <> 0", root.TenantID, root.ProjectID, root.ID)
	}
	coverageBase := func() *gorm.DB {
		return store.Model(&db.ScanCoverage{}).
			Where("tenant_id = ? AND project_id = ?", root.TenantID, root.ProjectID).
			Where("source_task_id = ? OR id IN (?)", root.ID, linkedCoverageIDs())
	}
	var invalidatedCount int64
	if err := coverageBase().Where("status <> ? OR invalid_reason <> ''", string(scanplan.CoverageComplete)).Count(&invalidatedCount).Error; err != nil {
		return nil, 0, 0, false, fmt.Errorf("count invalidated task coverage: %w", err)
	}
	var expiredCount int64
	if err := coverageBase().Where("status = ? AND valid_until IS NOT NULL AND valid_until <= ?", string(scanplan.CoverageComplete), now).Count(&expiredCount).Error; err != nil {
		return nil, 0, 0, false, fmt.Errorf("count expired task coverage: %w", err)
	}
	var rows []db.ScanCoverage
	if err := coverageBase().Where("status <> ? OR invalid_reason <> '' OR (valid_until IS NOT NULL AND valid_until <= ?)", string(scanplan.CoverageComplete), now).
		Order("updated_at desc, id desc").Limit(taskCoverageExplanationLimit + 1).Find(&rows).Error; err != nil {
		return nil, 0, 0, false, fmt.Errorf("load task coverage invalidations: %w", err)
	}
	truncated := len(rows) > taskCoverageExplanationLimit
	if truncated {
		rows = rows[:taskCoverageExplanationLimit]
	}
	items := make([]taskCoverageInvalidationItem, 0, len(rows))
	for _, row := range rows {
		status := row.Status
		reason := strings.TrimSpace(row.InvalidReason)
		if row.Status == string(scanplan.CoverageComplete) && row.ValidUntil != nil && !row.ValidUntil.After(now) {
			status = "expired"
			if reason == "" {
				reason = "ttl_expired"
			}
		}
		items = append(items, taskCoverageInvalidationItem{
			NormalizedTarget: row.NormalizedTarget,
			Stage:            row.Stage,
			Status:           status,
			Reason:           reason,
			Source:           taskCoverageExplanationSource{TaskID: row.SourceTaskID, BatchID: row.SourceBatchID, AttemptID: row.SourceAttemptID},
			InvalidatedAt:    row.UpdatedAt,
			ValidUntil:       row.ValidUntil,
		})
	}
	return items, invalidatedCount, expiredCount, truncated, nil
}

func loadTaskCoverageSourceNames(store *gorm.DB, root db.RootTask, sourceIDs map[string]struct{}) (map[string]string, error) {
	ids := make([]string, 0, len(sourceIDs)+1)
	for id := range sourceIDs {
		ids = append(ids, id)
	}
	if _, exists := sourceIDs[root.ID]; !exists {
		ids = append(ids, root.ID)
	}
	if len(ids) == 0 {
		return map[string]string{}, nil
	}
	var rows []db.RootTask
	if err := store.Select("id", "name").Where("tenant_id = ? AND project_id = ? AND id IN ?", root.TenantID, root.ProjectID, ids).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("load task coverage sources: %w", err)
	}
	result := make(map[string]string, len(rows))
	for _, row := range rows {
		result[row.ID] = row.Name
	}
	return result, nil
}

func publicTaskCoverageReason(reason string) string {
	reason = strings.TrimSpace(reason)
	if strings.HasPrefix(reason, "resume_plan:") {
		return "checkpoint_resume"
	}
	return reason
}
