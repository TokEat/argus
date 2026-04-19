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

// GetVulnTrends 获取最近 N 天的漏洞趋势数据
func GetVulnTrends(days int) []TrendPoint {
	if days <= 0 {
		days = 30
	}
	startDate := time.Now().AddDate(0, 0, -days)

	var results []TrendPoint
	DB.Raw(`
		SELECT TO_CHAR(created_at, 'YYYY-MM-DD') as date, COUNT(*) as count
		FROM vulnerabilities
		WHERE created_at >= ?
		GROUP BY TO_CHAR(created_at, 'YYYY-MM-DD')
		ORDER BY date
	`, startDate).Scan(&results)

	return results
}

// GetSeverityDistribution 获取漏洞严重度分布
func GetSeverityDistribution() []SeverityCount {
	var results []SeverityCount
	DB.Raw(`
		SELECT severity, COUNT(*) as count
		FROM vulnerabilities
		GROUP BY severity
		ORDER BY count DESC
	`).Scan(&results)
	return results
}

// GetTaskResultStats 获取任务维度的结果统计
func GetTaskResultStats(limit int) []TaskStats {
	if limit <= 0 {
		limit = 20
	}
	var results []TaskStats
	DB.Raw(`
		SELECT rt.id as task_id, rt.name as task_name,
			COALESCE(a.cnt, 0) as asset_count,
			COALESCE(f.cnt, 0) as fp_count,
			COALESCE(v.cnt, 0) as vuln_count
		FROM root_tasks rt
		LEFT JOIN (SELECT task_id, COUNT(*) as cnt FROM assets GROUP BY task_id) a ON a.task_id = rt.id
		LEFT JOIN (SELECT task_id, COUNT(*) as cnt FROM fingerprint_hits GROUP BY task_id) f ON f.task_id = rt.id
		LEFT JOIN (SELECT task_id, COUNT(*) as cnt FROM vulnerabilities GROUP BY task_id) v ON v.task_id = rt.id
		ORDER BY rt.created_at DESC
		LIMIT ?
	`, limit).Scan(&results)
	return results
}

// GetRecentHighVulns 获取最近高危漏洞
func GetRecentHighVulns(limit int) []Vulnerability {
	if limit <= 0 {
		limit = 10
	}
	var vulns []Vulnerability
	DB.Where("severity IN ?", []string{"critical", "high", "Critical", "High"}).
		Order("created_at DESC").Limit(limit).Find(&vulns)
	return vulns
}
