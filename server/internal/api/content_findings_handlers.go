package api

import (
	"net/http"
	"strings"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// 主动爬取关联资产候选 + 敏感信息候选的结果查询接口，供任务结果页"内容分析"页签使用。

// scopeContentFindings 应用租户 / 项目 / 任务（含子任务展开）访问范围。
func scopeContentFindings(c *gin.Context, query *gorm.DB) *gorm.DB {
	query = query.Where("tenant_id = ?", currentTenantID(c))
	query, _ = applyProjectScope(c, query, "project_id")
	if taskID := strings.TrimSpace(c.Query("task_id")); taskID != "" {
		scoped := resolveAccessibleTaskIDs(c, taskID)
		if len(scoped) == 0 {
			return query.Where("1 = 0")
		}
		query = query.Where("task_id IN ? OR root_task_id = ?", scoped, taskID)
	}
	return query
}

func listCrawlSiteCandidates(c *gin.Context) {
	var items []db.CrawlSiteCandidate
	query := db.DB.Model(&db.CrawlSiteCandidate{})
	query = scopeContentFindings(c, query)
	if status := strings.TrimSpace(c.Query("ai_status")); status != "" {
		query = query.Where("ai_status = ?", status)
	}
	if siteType := strings.TrimSpace(c.Query("site_type")); siteType != "" {
		query = query.Where("site_type = ?", siteType)
	}
	if search := strings.TrimSpace(c.Query("search")); search != "" {
		like := "%" + search + "%"
		query = query.Where("url LIKE ? OR host LIKE ?", like, like)
	}
	query = query.Order("created_at desc")
	page, pageSize, total, ok := paginateResultQuery(c, query, &db.CrawlSiteCandidate{}, &items)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, pagedResponse(items, total, page, pageSize, ""))
}

func listSensitiveFindings(c *gin.Context) {
	var items []db.SensitiveFinding
	query := db.DB.Model(&db.SensitiveFinding{})
	query = scopeContentFindings(c, query)
	if kind := strings.TrimSpace(c.Query("kind")); kind != "" {
		query = query.Where("kind = ?", kind)
	}
	if status := strings.TrimSpace(c.Query("ai_status")); status != "" {
		query = query.Where("ai_status = ?", status)
	}
	if search := strings.TrimSpace(c.Query("search")); search != "" {
		like := "%" + search + "%"
		query = query.Where("value LIKE ? OR host LIKE ?", like, like)
	}
	query = query.Order("created_at desc")
	page, pageSize, total, ok := paginateResultQuery(c, query, &db.SensitiveFinding{}, &items)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, pagedResponse(items, total, page, pageSize, ""))
}
