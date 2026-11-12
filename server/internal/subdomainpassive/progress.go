package subdomainpassive

import (
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/TokEat/argus/server/internal/db"
	"gorm.io/gorm"
)

// TaskCollectionProgress is the frontend projection of one RootTask's
// Server-side passive collection: overall state plus which held domain
// batches are waiting for it.
type TaskCollectionProgress struct {
	Active       bool                  `json:"active"`
	State        string                `json:"state"`
	DomainsTotal int                   `json:"domains_total"`
	DomainsDone  int                   `json:"domains_done"`
	UpdatedAt    time.Time             `json:"updated_at"`
	HeldBatches  []HeldBatchSum        `json:"held_batches"`
	Results      []DomainCollectionRow `json:"results"`
}

// HeldBatchSum describes one held domain batch (the subtask scheduled from
// the user's domain targets that dispatch waits for collection).
type HeldBatchSum struct {
	BatchID     string    `json:"batch_id"`
	AttemptID   string    `json:"attempt_id"`
	State       string    `json:"state"`
	Domains     []string  `json:"domains"`
	DomainsDone int       `json:"domains_done"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// DomainCollectionRow is one main domain and every subdomain collected for
// it in this task (sealed into the dispatched attempt configs).
type DomainCollectionRow struct {
	Domain     string   `json:"domain"`
	Count      int      `json:"count"`
	Subdomains []string `json:"subdomains"`
}

// CollectionProgressForTask aggregates all collection jobs of a RootTask and
// projects the sealed per-domain results from the task's attempt configs.
// It never leaks cross-tenant rows: jobs and attempts are filtered by tenant.
func CollectionProgressForTask(store *gorm.DB, tenantID, rootTaskID string) TaskCollectionProgress {
	progress := TaskCollectionProgress{State: JobStateReleased, HeldBatches: []HeldBatchSum{}, Results: []DomainCollectionRow{}}
	if store == nil || strings.TrimSpace(rootTaskID) == "" {
		return progress
	}
	var jobs []db.SubdomainPassiveJob
	if err := store.Where("tenant_id = ? AND root_task_id = ?", tenantID, rootTaskID).
		Order("created_at ASC").Find(&jobs).Error; err != nil {
		return progress
	}
	// 结果投影独立于 job 行：认领时密封的任务没有收集 job，也必须能看到结果。
	progress.Results = sealedResultsForTask(store, tenantID, rootTaskID)
	if len(jobs) == 0 {
		return progress
	}
	rank := map[string]int{JobStatePending: 0, JobStateRunning: 1, JobStateReleased: 2, JobStateFailed: 3}
	progress.Active = false
	progress.State = JobStateReleased
	currentRank := 5
	for _, job := range jobs {
		var domains []string
		_ = json.Unmarshal([]byte(job.Domains), &domains)
		progress.DomainsTotal += len(domains)
		progress.DomainsDone += job.DomainsDone
		if job.UpdatedAt.After(progress.UpdatedAt) {
			progress.UpdatedAt = job.UpdatedAt
		}
		if job.State == JobStatePending || job.State == JobStateRunning {
			progress.Active = true
		}
		if r, ok := rank[job.State]; ok && r < currentRank {
			currentRank = r
			progress.State = job.State
		}
		progress.HeldBatches = append(progress.HeldBatches, HeldBatchSum{
			BatchID:     job.BatchID,
			AttemptID:   job.AttemptID,
			State:       job.State,
			Domains:     domains,
			DomainsDone: job.DomainsDone,
			UpdatedAt:   job.UpdatedAt,
		})
	}
	return progress
}

// sealedResultsForTask reads SubdomainPassiveResults from every attempt
// config of the task and unions them per main domain, one row per domain.
// Sealed configs are exactly what was dispatched to Agents for this task,
// which keeps the projection task-scoped (not the shared global cache).
func sealedResultsForTask(store *gorm.DB, tenantID, rootTaskID string) []DomainCollectionRow {
	var attempts []db.SubTask
	if err := store.Select("config").
		Where("tenant_id = ? AND root_task_id = ?", tenantID, rootTaskID).
		Find(&attempts).Error; err != nil {
		return []DomainCollectionRow{}
	}
	merged := make(map[string]map[string]struct{})
	for _, attempt := range attempts {
		if strings.TrimSpace(attempt.Config) == "" {
			continue
		}
		var payload struct {
			SubdomainPassiveResults map[string][]string
		}
		if err := json.Unmarshal([]byte(attempt.Config), &payload); err != nil {
			continue
		}
		for domain, subdomains := range payload.SubdomainPassiveResults {
			key := strings.ToLower(strings.TrimSpace(domain))
			if key == "" {
				continue
			}
			if merged[key] == nil {
				merged[key] = make(map[string]struct{})
			}
			for _, subdomain := range subdomains {
				if value := strings.ToLower(strings.TrimSpace(subdomain)); value != "" {
					merged[key][value] = struct{}{}
				}
			}
		}
	}
	rows := make([]DomainCollectionRow, 0, len(merged))
	for domain, subdomains := range merged {
		list := make([]string, 0, len(subdomains))
		for subdomain := range subdomains {
			list = append(list, subdomain)
		}
		sortStrings(list)
		rows = append(rows, DomainCollectionRow{Domain: domain, Count: len(list), Subdomains: list})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Domain < rows[j].Domain })
	return rows
}
