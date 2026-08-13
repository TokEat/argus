package api

import "github.com/P0lar1ght/argus/server/internal/db"

type taskResultStats struct {
	AssetCount         int64
	FingerprintCount   int64
	VulnerabilityCount int64
	Severity           map[string]int64
}

func loadTaskResultStats(rootTaskID, tenantID string, attempts []db.SubTask) taskResultStats {
	var stats taskResultStats
	db.DB.Model(&db.Asset{}).Where("root_task_id = ? AND tenant_id = ?", rootTaskID, tenantID).Count(&stats.AssetCount)
	db.DB.Model(&db.FingerprintHit{}).Where("root_task_id = ? AND tenant_id = ?", rootTaskID, tenantID).Count(&stats.FingerprintCount)
	db.DB.Model(&db.Vulnerability{}).Where("root_task_id = ? AND tenant_id = ?", rootTaskID, tenantID).Count(&stats.VulnerabilityCount)

	// Historical rows may predate root_task_id and remain addressable by attempt ID.
	if stats.AssetCount == 0 && stats.FingerprintCount == 0 && stats.VulnerabilityCount == 0 && len(attempts) > 0 {
		attemptIDs := make([]string, len(attempts))
		for index, attempt := range attempts {
			attemptIDs[index] = attempt.ID
		}
		db.DB.Model(&db.Asset{}).Where("task_id IN ? AND tenant_id = ?", attemptIDs, tenantID).Count(&stats.AssetCount)
		db.DB.Model(&db.FingerprintHit{}).Where("task_id IN ? AND tenant_id = ?", attemptIDs, tenantID).Count(&stats.FingerprintCount)
		db.DB.Model(&db.Vulnerability{}).Where("task_id IN ? AND tenant_id = ?", attemptIDs, tenantID).Count(&stats.VulnerabilityCount)
	}

	type severityCount struct {
		Severity string
		Count    int64 `gorm:"column:count"`
	}
	var rows []severityCount
	db.DB.Model(&db.Vulnerability{}).
		Select("severity, count(*) as count").
		Where("root_task_id = ? AND tenant_id = ?", rootTaskID, tenantID).
		Group("severity").Scan(&rows)
	stats.Severity = make(map[string]int64, len(rows))
	for _, row := range rows {
		stats.Severity[row.Severity] = row.Count
	}
	return stats
}
