package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/P0lar1ght/argus/server/internal/storage"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type agentLogLevelCount struct {
	Level string `json:"level"`
	Count int64  `json:"count"`
}

func getAgentLogRetentionDays() int {
	var cfg db.SystemConfig
	if err := db.DB.Where("key = ?", agentLogRetentionKey).First(&cfg).Error; err == nil {
		if days, parseErr := strconv.Atoi(strings.TrimSpace(cfg.Value)); parseErr == nil && days > 0 {
			if days > 365 {
				return 365
			}
			return days
		}
	}
	return defaultAgentLogRetention
}

func saveAgentLogRetentionDays(days int) error {
	if days <= 0 || days > 365 {
		return fmt.Errorf("retention_days must be between 1 and 365")
	}
	cfg := db.SystemConfig{
		Key:       agentLogRetentionKey,
		Value:     strconv.Itoa(days),
		UpdatedAt: time.Now(),
	}
	return db.DB.Save(&cfg).Error
}

func cleanupAgentLogsOnce(days int) (int64, error) {
	if days <= 0 {
		days = getAgentLogRetentionDays()
	}
	cutoff := time.Now().AddDate(0, 0, -days)
	cutoffMs := cutoff.UnixMilli()
	res := db.DB.Where("created_at < ? OR (timestamp > 0 AND timestamp < ?)", cutoff, cutoffMs).Delete(&db.AgentLog{})
	return res.RowsAffected, res.Error
}

type AgentLogRetentionService struct {
	interval time.Duration
}

func NewAgentLogRetentionService() *AgentLogRetentionService {
	return &AgentLogRetentionService{interval: time.Hour}
}

func (s *AgentLogRetentionService) Run(ctx context.Context) {
	if deleted, err := cleanupAgentLogsOnce(0); err != nil {
		log.Printf("[AgentLogRetention] cleanup failed: %v", err)
	} else if deleted > 0 {
		log.Printf("[AgentLogRetention] cleaned %d expired logs", deleted)
	}

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if deleted, err := cleanupAgentLogsOnce(0); err != nil {
				log.Printf("[AgentLogRetention] cleanup failed: %v", err)
			} else if deleted > 0 {
				log.Printf("[AgentLogRetention] cleaned %d expired logs", deleted)
			}
		}
	}
}

// StartAgentLogRetentionDaemon 保留旧内部入口，委托给显式 service。
func StartAgentLogRetentionDaemon(ctx context.Context) {
	NewAgentLogRetentionService().Run(ctx)
}

func tenantAgentIDs(tenantID string) []string {
	tenantID = normalizeTenantID(tenantID)
	seen := make(map[string]struct{})
	agentIDs := make([]string, 0)
	add := func(id string) {
		id = strings.TrimSpace(id)
		if id == "" {
			return
		}
		if _, ok := seen[id]; ok {
			return
		}
		seen[id] = struct{}{}
		agentIDs = append(agentIDs, id)
	}

	var nodeIDs []string
	scopedNodeQuery(tenantID).Model(&db.Node{}).Pluck("agent_id", &nodeIDs)
	for _, id := range nodeIDs {
		add(id)
	}

	var logIDs []string
	scopedAgentLogQuery(tenantID).Distinct("agent_id").Pluck("agent_id", &logIDs)
	for _, id := range logIDs {
		var crossTenantNodes int64
		db.DB.Model(&db.Node{}).
			Where("agent_id = ? AND tenant_id <> ?", id, tenantID).
			Count(&crossTenantNodes)
		if crossTenantNodes > 0 {
			continue
		}
		add(id)
	}
	sort.Strings(agentIDs)
	return agentIDs
}

func scopedAgentLogQuery(tenantID string) *gorm.DB {
	tenantID = normalizeTenantID(tenantID)
	return db.DB.Model(&db.AgentLog{}).Where("tenant_id = ?", tenantID)
}

func getAgentLogSummary(c *gin.Context) {
	tenantID := currentTenantID(c)
	agentIDs := tenantAgentIDs(tenantID)
	if len(agentIDs) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"agents":         []string{},
			"level_counts":   []agentLogLevelCount{},
			"recent_errors":  []db.AgentLog{},
			"retention_days": getAgentLogRetentionDays(),
		})
		return
	}

	query := scopedAgentLogQuery(tenantID).Where("agent_id IN ?", agentIDs)
	if agentID := strings.TrimSpace(c.Query("agent_id")); agentID != "" {
		query = query.Where("agent_id = ?", agentID)
	}
	var since, until int64
	if raw := strings.TrimSpace(c.Query("since")); raw != "" {
		if v, err := strconv.ParseInt(raw, 10, 64); err == nil && v > 0 {
			since = v
		}
	}
	if raw := strings.TrimSpace(c.Query("until")); raw != "" {
		if v, err := strconv.ParseInt(raw, 10, 64); err == nil && v > 0 {
			until = v
		}
	}
	if since > 0 {
		query = query.Where("timestamp >= ?", since)
	}
	if until > 0 {
		query = query.Where("timestamp <= ?", until)
	}

	counts := make([]agentLogLevelCount, 0)
	query.Select("level, count(*) as count").Group("level").Order("count DESC").Scan(&counts)

	limit := 20
	if raw := strings.TrimSpace(c.Query("limit")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			limit = v
		}
	}
	if limit > 100 {
		limit = 100
	}
	recentErrors := make([]db.AgentLog, 0)
	errQuery := scopedAgentLogQuery(tenantID).Where("agent_id IN ? AND level IN ?", agentIDs, []string{"ERROR", "WARN"})
	if agentID := strings.TrimSpace(c.Query("agent_id")); agentID != "" {
		errQuery = errQuery.Where("agent_id = ?", agentID)
	}
	if since > 0 {
		errQuery = errQuery.Where("timestamp >= ?", since)
	}
	if until > 0 {
		errQuery = errQuery.Where("timestamp <= ?", until)
	}
	errQuery.Order("timestamp DESC").Limit(limit).Find(&recentErrors)

	c.JSON(http.StatusOK, gin.H{
		"agents":         agentIDs,
		"level_counts":   counts,
		"recent_errors":  recentErrors,
		"retention_days": getAgentLogRetentionDays(),
	})
}

func getAgentLogRetention(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"retention_days": getAgentLogRetentionDays()})
}

func updateAgentLogRetention(c *gin.Context) {
	var req struct {
		RetentionDays int `json:"retention_days"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := saveAgentLogRetentionDays(req.RetentionDays); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	deleted, err := cleanupAgentLogsOnce(req.RetentionDays)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"retention_days": req.RetentionDays, "deleted": deleted})
}

func getAgentLogs(c *gin.Context) {
	agentID := c.Param("id")
	tenantID := currentTenantID(c)
	limit := 100
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 {
			limit = v
		}
	}
	if limit > 1000 {
		limit = 1000
	}
	level := strings.TrimSpace(c.Query("level")) // 可选过滤: INFO, WARN, ERROR
	keyword := strings.TrimSpace(c.Query("q"))
	var since, until int64
	if raw := strings.TrimSpace(c.Query("since")); raw != "" {
		if v, err := strconv.ParseInt(raw, 10, 64); err == nil && v > 0 {
			since = v
		}
	}
	if raw := strings.TrimSpace(c.Query("until")); raw != "" {
		if v, err := strconv.ParseInt(raw, 10, 64); err == nil && v > 0 {
			until = v
		}
	}

	var node db.Node
	if err := scopedNodeQuery(tenantID).Where("agent_id = ?", agentID).First(&node).Error; err != nil {
		var crossTenantNodes int64
		db.DB.Model(&db.Node{}).
			Where("agent_id = ? AND tenant_id <> ?", agentID, normalizeTenantID(tenantID)).
			Count(&crossTenantNodes)
		if crossTenantNodes > 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "Agent not found"})
			return
		}
		var historicalLogs int64
		scopedAgentLogQuery(tenantID).Where("agent_id = ?", agentID).Count(&historicalLogs)
		if historicalLogs == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "Agent not found"})
			return
		}
	}

	logs := make([]db.AgentLog, 0)
	query := scopedAgentLogQuery(tenantID).Where("agent_id = ?", agentID)
	if level != "" {
		query = query.Where("level = ?", level)
	}
	if keyword != "" {
		query = query.Where("LOWER(message) LIKE LOWER(?)", "%"+keyword+"%")
	}
	if since > 0 {
		query = query.Where("timestamp >= ?", since)
	}
	if until > 0 {
		query = query.Where("timestamp <= ?", until)
	}
	query.Order("timestamp DESC").Limit(limit).Find(&logs)
	c.JSON(http.StatusOK, logs)
}

func listAgentLogAlertRules(c *gin.Context) {
	rules := make([]db.AgentLogAlertRule, 0)
	db.DB.Where("tenant_id = ?", currentTenantID(c)).Order("created_at DESC").Find(&rules)
	c.JSON(http.StatusOK, rules)
}

func createAgentLogAlertRule(c *gin.Context) {
	var req struct {
		Name    string `json:"name"`
		AgentID string `json:"agent_id"`
		Level   string `json:"level"`
		Keyword string `json:"keyword"`
		Enabled *bool  `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	rule := db.AgentLogAlertRule{
		TenantID:  currentTenantID(c),
		Name:      name,
		AgentID:   strings.TrimSpace(req.AgentID),
		Level:     strings.ToUpper(strings.TrimSpace(req.Level)),
		Keyword:   strings.TrimSpace(req.Keyword),
		Enabled:   enabled,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if rule.Level == "" && rule.Keyword == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "level or keyword is required"})
		return
	}
	if err := db.DB.Create(&rule).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, rule)
}

func deleteAgentLogAlertRule(c *gin.Context) {
	res := db.DB.Where("tenant_id = ? AND id = ?", currentTenantID(c), c.Param("id")).Delete(&db.AgentLogAlertRule{})
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": res.Error.Error()})
		return
	}
	if res.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "alert rule not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

func listAgentLogAlertEvents(c *gin.Context) {
	limit := 100
	if raw := strings.TrimSpace(c.Query("limit")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			limit = v
		}
	}
	if limit > 500 {
		limit = 500
	}
	events := make([]db.AgentLogAlertEvent, 0)
	query := db.DB.Where("tenant_id = ?", currentTenantID(c))
	if agentID := strings.TrimSpace(c.Query("agent_id")); agentID != "" {
		query = query.Where("agent_id = ?", agentID)
	}
	query.Order("created_at DESC").Limit(limit).Find(&events)
	c.JSON(http.StatusOK, events)
}

func archiveAgentLogs(c *gin.Context) {
	day := strings.TrimSpace(c.Query("day"))
	if day == "" {
		day = time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	}
	start, err := time.Parse("2006-01-02", day)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "day must use YYYY-MM-DD"})
		return
	}
	end := start.AddDate(0, 0, 1)
	agentIDs := tenantAgentIDs(currentTenantID(c))
	if len(agentIDs) == 0 {
		c.JSON(http.StatusOK, gin.H{"day": day, "log_count": 0, "status": "empty"})
		return
	}
	var logs []db.AgentLog
	if err := scopedAgentLogQuery(currentTenantID(c)).Where("agent_id IN ? AND created_at >= ? AND created_at < ?", agentIDs, start, end).
		Order("timestamp ASC").Find(&logs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, item := range logs {
		_ = enc.Encode(item)
	}
	key := fmt.Sprintf("agent-logs/%s/%s.ndjson", currentTenantID(c), day)
	store, err := storage.NewLocalStore(routerRuntime().ObjectStorageRoot)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	obj, err := store.Put(c.Request.Context(), key, &buf)
	archive := db.AgentLogArchive{
		TenantID:   currentTenantID(c),
		Day:        day,
		StorageKey: key,
		LogCount:   len(logs),
		Status:     "success",
		CreatedAt:  time.Now(),
	}
	if err != nil {
		archive.Status = "failed"
		archive.Error = err.Error()
		_ = db.DB.Create(&archive).Error
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	archive.StorageKey = obj.Key
	_ = db.DB.Create(&archive).Error
	c.JSON(http.StatusOK, archive)
}
