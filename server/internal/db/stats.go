package db

import (
	"time"
)

// TrendPoint 趋势数据点
type TrendPoint struct {
	Date  string `json:"date"`
	Count int64  `json:"count"`
}

// SeverityCount 严重度分布
type SeverityCount struct {
	Severity string `json:"severity"`
	Count    int64  `json:"count"`
}

// TaskStats 任务维度统计
type TaskStats struct {
	TaskID     string `json:"task_id"`
	TaskName   string `json:"task_name"`
	AssetCount int64  `json:"asset_count"`
	FPCount    int64  `json:"fp_count"`
	VulnCount  int64  `json:"vuln_count"`
}

// GetVulnTrends 获取最近 N 天的漏洞趋势数据（含租户隔离 + 项目隔离）
func GetVulnTrends(tenantID string, projectID string, days int) []TrendPoint {
	if days <= 0 {
		days = 30
	}
	startDate := time.Now().AddDate(0, 0, -days)

	var results []TrendPoint
	if projectID != "" {
		DB.Raw(`
			SELECT TO_CHAR(created_at, 'YYYY-MM-DD') as date, COUNT(*) as count
			FROM vulnerabilities
			WHERE tenant_id = ? AND project_id = ? AND created_at >= ?
			GROUP BY TO_CHAR(created_at, 'YYYY-MM-DD')
			ORDER BY date
		`, tenantID, projectID, startDate).Scan(&results)
	} else {
		DB.Raw(`
			SELECT TO_CHAR(created_at, 'YYYY-MM-DD') as date, COUNT(*) as count
			FROM vulnerabilities
			WHERE tenant_id = ? AND created_at >= ?
			GROUP BY TO_CHAR(created_at, 'YYYY-MM-DD')
			ORDER BY date
		`, tenantID, startDate).Scan(&results)
	}

	return results
}

// GetSeverityDistribution 获取漏洞严重度分布（含租户隔离 + 项目隔离）
func GetSeverityDistribution(tenantID string, projectID string) []SeverityCount {
	var results []SeverityCount
	if projectID != "" {
		DB.Raw(`
			SELECT severity, COUNT(*) as count
			FROM vulnerabilities
			WHERE tenant_id = ? AND project_id = ?
			GROUP BY severity
			ORDER BY count DESC
		`, tenantID, projectID).Scan(&results)
	} else {
		DB.Raw(`
			SELECT severity, COUNT(*) as count
			FROM vulnerabilities
			WHERE tenant_id = ?
			GROUP BY severity
			ORDER BY count DESC
		`, tenantID).Scan(&results)
	}
	return results
}

// GetTaskResultStats 获取任务维度的结果统计（含租户隔离 + 项目隔离 + 修复 JOIN 关系）
//
// 修复说明：assets/fingerprint_hits/vulnerabilities 中的 task_id 存储的是 SubTask.ID，
// 而非 RootTask.ID，因此需要通过 sub_tasks 表关联才能正确聚合到 RootTask 维度。
func GetTaskResultStats(tenantID string, projectID string, limit int) []TaskStats {
	if limit <= 0 {
		limit = 20
	}
	var results []TaskStats
	if projectID != "" {
		DB.Raw(`
			SELECT rt.id as task_id, rt.name as task_name,
				COALESCE(a.cnt, 0) as asset_count,
				COALESCE(f.cnt, 0) as fp_count,
				COALESCE(v.cnt, 0) as vuln_count
			FROM root_tasks rt
			LEFT JOIN (
				SELECT st.root_task_id, COUNT(*) as cnt
				FROM assets a2 JOIN sub_tasks st ON a2.task_id = st.id
				WHERE a2.tenant_id = ? AND a2.project_id = ?
				GROUP BY st.root_task_id
			) a ON a.root_task_id = rt.id
			LEFT JOIN (
				SELECT st.root_task_id, COUNT(*) as cnt
				FROM fingerprint_hits f2 JOIN sub_tasks st ON f2.task_id = st.id
				WHERE f2.tenant_id = ? AND f2.project_id = ?
				GROUP BY st.root_task_id
			) f ON f.root_task_id = rt.id
			LEFT JOIN (
				SELECT st.root_task_id, COUNT(*) as cnt
				FROM vulnerabilities v2 JOIN sub_tasks st ON v2.task_id = st.id
				WHERE v2.tenant_id = ? AND v2.project_id = ?
				GROUP BY st.root_task_id
			) v ON v.root_task_id = rt.id
			WHERE rt.tenant_id = ? AND rt.project_id = ?
			ORDER BY rt.created_at DESC
			LIMIT ?
		`, tenantID, projectID, tenantID, projectID, tenantID, projectID, tenantID, projectID, limit).Scan(&results)
	} else {
		DB.Raw(`
			SELECT rt.id as task_id, rt.name as task_name,
				COALESCE(a.cnt, 0) as asset_count,
				COALESCE(f.cnt, 0) as fp_count,
				COALESCE(v.cnt, 0) as vuln_count
			FROM root_tasks rt
			LEFT JOIN (
				SELECT st.root_task_id, COUNT(*) as cnt
				FROM assets a2 JOIN sub_tasks st ON a2.task_id = st.id
				WHERE a2.tenant_id = ?
				GROUP BY st.root_task_id
			) a ON a.root_task_id = rt.id
			LEFT JOIN (
				SELECT st.root_task_id, COUNT(*) as cnt
				FROM fingerprint_hits f2 JOIN sub_tasks st ON f2.task_id = st.id
				WHERE f2.tenant_id = ?
				GROUP BY st.root_task_id
			) f ON f.root_task_id = rt.id
			LEFT JOIN (
				SELECT st.root_task_id, COUNT(*) as cnt
				FROM vulnerabilities v2 JOIN sub_tasks st ON v2.task_id = st.id
				WHERE v2.tenant_id = ?
				GROUP BY st.root_task_id
			) v ON v.root_task_id = rt.id
			WHERE rt.tenant_id = ?
			ORDER BY rt.created_at DESC
			LIMIT ?
		`, tenantID, tenantID, tenantID, tenantID, limit).Scan(&results)
	}
	return results
}

// GetRecentHighVulns 获取最近高危漏洞（含租户隔离 + 项目隔离）
func GetRecentHighVulns(tenantID string, projectID string, limit int) []Vulnerability {
	if limit <= 0 {
		limit = 10
	}
	var vulns []Vulnerability
	query := DB.Where("tenant_id = ? AND severity IN ?", tenantID, []string{"critical", "high", "Critical", "High"})
	if projectID != "" {
		query = query.Where("project_id = ?", projectID)
	}
	query.Order("created_at DESC").Limit(limit).Find(&vulns)
	return vulns
}
