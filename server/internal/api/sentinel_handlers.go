package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/TokEat/argus/server/internal/db"
	"github.com/TokEat/argus/server/internal/sentinel"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// sentinelTaskPusher is wired once in main with the RabbitMQ-backed queue; nil
// leaves rescan attempts Pending for the dispatch reconciler (tests run nil).
var sentinelTaskPusher sentinel.TaskPusher

// SetSentinelTaskPusher connects the executor to the real agent queues.
func SetSentinelTaskPusher(p sentinel.TaskPusher) {
	sentinelTaskPusher = p
}

func listSentinelEvents(c *gin.Context) {
	tenant := currentTenantID(c)
	q := db.DB.Model(&db.EgressBanEvent{}).Where("tenant_id = ?", tenant)
	if v := c.Query("status"); v != "" {
		q = q.Where("status = ?", v)
	}
	if v := c.Query("classification"); v != "" {
		q = q.Where("classification = ?", v)
	}
	if v := c.Query("signal_type"); v != "" {
		q = q.Where("signal_type = ?", v)
	}
	if v := c.Query("root_task_id"); v != "" {
		q = q.Where("root_task_id = ?", v)
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 200 {
		pageSize = 20
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	var items []db.EgressBanEvent
	if err := q.Order("id DESC").
		Offset((page - 1) * pageSize).
		Limit(pageSize).
		Find(&items).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"items":     items,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

func executeSentinelEvent(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid event id"})
		return
	}
	var req struct {
		Action string `json:"action"`
	}
	_ = c.ShouldBindJSON(&req) // body is optional
	ex := &sentinel.Executor{DB: db.DB, Pusher: sentinelTaskPusher}
	ev, err := ex.ExecuteByID(c.Request.Context(), uint(id), taskOperatorID(c), req.Action)
	if err != nil {
		status := http.StatusInternalServerError
		if err == gorm.ErrRecordNotFound {
			status = http.StatusNotFound
		} else if err == sentinel.ErrEventNotActionable {
			status = http.StatusConflict
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, ev)
}

func dismissSentinelEvent(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid event id"})
		return
	}
	res := db.DB.Model(&db.EgressBanEvent{}).
		Where("id = ? AND tenant_id = ? AND status = ?", uint(id), currentTenantID(c), sentinel.EventOpen).
		Updates(map[string]interface{}{
			"status":      sentinel.EventDismissed,
			"executed_by": taskOperatorID(c),
			"executed_at": time.Now(),
		})
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": res.Error.Error()})
		return
	}
	if res.RowsAffected == 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "event is not open"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id, "status": sentinel.EventDismissed})
}

func getSentinelConfig(c *gin.Context) {
	c.JSON(http.StatusOK, readSentinelConfig())
}

func saveSentinelConfig(c *gin.Context) {
	var req struct {
		Enabled         *bool `json:"enabled"`
		AutoExecute     *bool `json:"auto_execute"`
		CooldownMinutes *int  `json:"cooldown_minutes"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.CooldownMinutes != nil && *req.CooldownMinutes < 1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cooldown_minutes must be >= 1"})
		return
	}
	now := time.Now()
	write := func(key, value string) {
		db.DB.Save(&db.SystemConfig{Key: key, Value: value, UpdatedAt: now})
	}
	if req.Enabled != nil {
		write(sentinel.ConfigKeyEnabled, strconv.FormatBool(*req.Enabled))
	}
	if req.AutoExecute != nil {
		write(sentinel.ConfigKeyAutoExecute, strconv.FormatBool(*req.AutoExecute))
	}
	if req.CooldownMinutes != nil {
		write(sentinel.ConfigKeyCooldownMinutes, strconv.Itoa(*req.CooldownMinutes))
	}
	c.JSON(http.StatusOK, readSentinelConfig())
}

func readSentinelConfig() gin.H {
	return gin.H{
		"enabled":          sentinel.LoadEnabled(db.DB),
		"auto_execute":     sentinel.LoadAutoExecute(db.DB),
		"cooldown_minutes": loadTriageSystemInt(sentinel.ConfigKeyCooldownMinutes, 10),
	}
}

func loadTriageSystemInt(key string, def int) int {
	var row db.SystemConfig
	if err := db.DB.Where("key = ?", key).First(&row).Error; err != nil {
		return def
	}
	n, err := strconv.Atoi(row.Value)
	if err != nil {
		return def
	}
	return n
}
