package api

import (
	"net/http"
	"strconv"
	"time"

	aipkg "github.com/P0lar1ght/argus/server/internal/ai"
	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/gin-gonic/gin"
)

// 主动爬取关联资产 + 敏感信息的全局 AI 内容分析开关（system_configs 持久化，默认开）。

func getContentAnalysisConfig(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"enabled": aipkg.LoadContentAnalysisEnabled(db.DB),
	})
}

func saveContentAnalysisConfig(c *gin.Context) {
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Enabled != nil {
		db.DB.Save(&db.SystemConfig{
			Key:       aipkg.ContentAnalysisConfigKeyEnabled,
			Value:     strconv.FormatBool(*req.Enabled),
			UpdatedAt: time.Now(),
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"enabled": aipkg.LoadContentAnalysisEnabled(db.DB),
	})
}
