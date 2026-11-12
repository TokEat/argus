package api

import (
	"context"
	"net/http"

	"github.com/TokEat/argus/server/internal/db"
	"github.com/gin-gonic/gin"
)

func getQueueDepth(c *gin.Context) {
	if routerRuntime().TaskQueue == nil {
		c.JSON(http.StatusOK, gin.H{"error": "queue not initialized"})
		return
	}

	tenantID := currentTenantID(c)
	ctx := context.Background()
	depth := routerRuntime().TaskQueue.QueueDepth(ctx)
	pending := routerRuntime().TaskQueue.PendingCount(ctx)

	readyBatches := int64(0)
	pendingBatches := int64(0)
	for _, v := range depth {
		readyBatches += v
	}
	for _, v := range pending {
		pendingBatches += v
	}

	var readyTargets, pendingTargets int64
	type targetCountResult struct {
		Status string
		Cnt    int64
	}
	var results []targetCountResult
	db.DB.Raw(`
			SELECT status, SUM(jsonb_array_length(chunk_targets::jsonb)) as cnt
			FROM sub_tasks
			WHERE tenant_id = ? AND status IN ('Pending', 'Dispatching', 'Running', 'Recovered')
			GROUP BY status
		`, tenantID).Scan(&results)
	for _, r := range results {
		switch db.NormalizeSubTaskStatus(r.Status) {
		case "PENDING", "DISPATCHING", "RECOVERED":
			readyTargets += r.Cnt
		case "RUNNING":
			pendingTargets += r.Cnt
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"depth":           depth,
		"pending":         pending,
		"mode":            routerRuntime().TaskQueue.Mode(),
		"ready_batches":   readyBatches,
		"pending_batches": pendingBatches,
		"ready_targets":   readyTargets,
		"pending_targets": pendingTargets,
	})
}
