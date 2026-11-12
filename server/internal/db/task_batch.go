package db

import (
	"strings"

	"gorm.io/gorm"
)

// SyncTaskBatchStatuses mirrors the latest Attempt status into its stable
// TaskBatch row. SubTask remains the execution source during the rolling
// migration so old Agents can continue without protocol changes.
func SyncTaskBatchStatuses(tx *gorm.DB, tenantID, rootTaskID string) error {
	if tx == nil || strings.TrimSpace(tenantID) == "" || strings.TrimSpace(rootTaskID) == "" {
		return nil
	}
	return tx.Exec(`
		UPDATE task_batches
		SET status = (
			SELECT st.status
			FROM sub_tasks st
			WHERE st.id = task_batches.latest_attempt_id
			  AND st.tenant_id = task_batches.tenant_id
		), updated_at = CURRENT_TIMESTAMP
		WHERE tenant_id = ? AND root_task_id = ? AND archived_at IS NULL
		  AND EXISTS (
			SELECT 1
			FROM sub_tasks st
			WHERE st.id = task_batches.latest_attempt_id
			  AND st.tenant_id = task_batches.tenant_id
		  )
	`, tenantID, rootTaskID).Error
}

// SettleStoppedTaskBatch advances the orthogonal control state after the
// latest Attempt has acknowledged or timed out a stop request.
func SettleStoppedTaskBatch(tx *gorm.DB, tenantID, batchID, attemptID string) error {
	if tx == nil || strings.TrimSpace(batchID) == "" || strings.TrimSpace(attemptID) == "" {
		return nil
	}
	return tx.Model(&TaskBatch{}).
		Where("id = ? AND tenant_id = ? AND latest_attempt_id = ? AND control_state = ?", batchID, tenantID, attemptID, BatchControlStopping).
		Updates(map[string]interface{}{
			"status":        "Cancelled",
			"control_state": BatchControlStopped,
		}).Error
}
