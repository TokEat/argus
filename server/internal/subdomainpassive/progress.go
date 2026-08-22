package subdomainpassive

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"gorm.io/gorm"
)

// TaskCollectionProgress is the frontend projection of one RootTask's
// Server-side passive collection: overall state plus which held domain
// batches are waiting for it.
type TaskCollectionProgress struct {
	Active       bool           `json:"active"`
	State        string         `json:"state"`
	DomainsTotal int            `json:"domains_total"`
	DomainsDone  int            `json:"domains_done"`
	UpdatedAt    time.Time      `json:"updated_at"`
	HeldBatches  []HeldBatchSum `json:"held_batches"`
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

// CollectionProgressForTask aggregates all collection jobs of a RootTask.
// It never leaks cross-tenant rows: jobs are filtered by tenant.
func CollectionProgressForTask(store *gorm.DB, tenantID, rootTaskID string) TaskCollectionProgress {
	progress := TaskCollectionProgress{State: JobStateReleased, HeldBatches: []HeldBatchSum{}}
	if store == nil || strings.TrimSpace(rootTaskID) == "" {
		return progress
	}
	var jobs []db.SubdomainPassiveJob
	if err := store.Where("tenant_id = ? AND root_task_id = ?", tenantID, rootTaskID).
		Order("created_at ASC").Find(&jobs).Error; err != nil || len(jobs) == 0 {
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
