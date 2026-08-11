package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/gin-gonic/gin"
)

func listMcpKeys(c *gin.Context) {
	var configs []db.SystemConfig
	db.DB.Where("key LIKE ?", "mcp_%").Find(&configs)

	type McpKey struct {
		ID       string `json:"id"`
		Provider string `json:"provider"`
		Key      string `json:"key"`
		Status   string `json:"status"`
	}

	keys := make([]McpKey, 0, len(configs))
	for _, cfg := range configs {
		provider := strings.TrimPrefix(cfg.Key, "mcp_")
		masked := cfg.Value
		if len(masked) > 8 {
			masked = masked[:4] + "****" + masked[len(masked)-4:]
		}
		keys = append(keys, McpKey{
			ID:       cfg.Key,
			Provider: provider,
			Key:      masked,
			Status:   "active",
		})
	}

	c.JSON(http.StatusOK, keys)
}

func saveMcpKey(c *gin.Context) {
	var req struct {
		Provider string `json:"provider" binding:"required"` // fofa, hunter, quake, openai, deepseek
		Key      string `json:"key" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	configKey := "mcp_" + strings.ToLower(req.Provider)
	cfg := db.SystemConfig{
		Key:       configKey,
		Value:     req.Key,
		UpdatedAt: time.Now(),
	}
	db.DB.Save(&cfg)

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func deleteMcpKey(c *gin.Context) {
	id := c.Param("id")
	db.DB.Delete(&db.SystemConfig{}, "key = ?", id)
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
