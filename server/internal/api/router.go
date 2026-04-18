package api

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/user/dddd-server/internal/db"
	"github.com/user/dddd-server/internal/scheduler"
)

var taskQueue *scheduler.TaskQueue

func SetTaskQueue(queue *scheduler.TaskQueue) {
	taskQueue = queue
}

// InitRouter 初始化 Gin 路由
func InitRouter(port string) {
	r := gin.Default()

	// 跨域处理
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE, UPDATE")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	// 启动 WebSocket 广播中心
	go Hub.Start()

	api := r.Group("/api/v1")
	{
		// WebSocket 入口
		api.GET("/ws", HandleWS)

		// Dashboard 统计数据
		api.GET("/stats", getStats)

		// 任务 CRUD
		api.GET("/tasks", getTasks)
		api.POST("/tasks", createTask)
		api.DELETE("/tasks/:id", deleteTask)

		// 漏洞资产
		api.GET("/vulns", getVulns)

		// Agent 节点
		api.GET("/nodes", getNodes)

		// Arsenal 弹药库热发车网关
		api.GET("/arsenals/:type", getArsenals)
		api.POST("/arsenals/:type/:filename", saveArsenal)
		api.DELETE("/arsenals/:type/:filename", deleteArsenal)
	}

	// SPA 控制塔前台映射兜底
	r.Static("/assets", "./dddd-ui/dist/assets")
	r.StaticFile("/favicon.ico", "./dddd-ui/dist/favicon.ico")
	r.NoRoute(func(c *gin.Context) {
		if !strings.HasPrefix(c.Request.URL.Path, "/api/") {
			c.File("./dddd-ui/dist/index.html")
		} else {
			c.JSON(http.StatusNotFound, gin.H{"error": "API route not found"})
		}
	})

	log.Printf("Starting API Server on %s", port)
	if err := r.Run(port); err != nil {
		log.Fatalf("API server failed: %v", err)
	}
}

// -------------------- Handlers --------------------

func getStats(c *gin.Context) {
	var taskCount, nodeCount, vulnCount int64
	db.DB.Model(&db.Task{}).Count(&taskCount)
	db.DB.Model(&db.Node{}).Count(&nodeCount)
	db.DB.Model(&db.Vuln{}).Count(&vulnCount)

	c.JSON(http.StatusOK, gin.H{
		"tasks": taskCount,
		"nodes": nodeCount,
		"vulns": vulnCount,
	})
}

func getTasks(c *gin.Context) {
	var tasks []db.Task
	db.DB.Order("created_at desc").Limit(50).Find(&tasks)
	c.JSON(http.StatusOK, tasks)
}

func createTask(c *gin.Context) {
	var req struct {
		Name    string          `json:"name"`
		Targets json.RawMessage `json:"targets"`
		Config  json.RawMessage `json:"config"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	targets, err := parseTargets(req.Targets)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(targets) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "targets is empty"})
		return
	}

	configJSON, err := normalizeConfigPayload(req.Config)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	targetsJSON, err := json.Marshal(targets)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	taskID := fmt.Sprintf("task-%d", time.Now().UnixNano())
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = targets[0]
	}

	task := db.Task{
		ID:      taskID,
		Name:    name,
		Status:  "Pending",
		Targets: string(targetsJSON),
		Config:  configJSON,
	}
	if err := db.DB.Create(&task).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if taskQueue != nil {
		pbTask, err := db.TaskToProto(&task)
		if err != nil {
			_ = db.DB.Delete(&db.Task{}, "id = ?", task.ID).Error
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if err := taskQueue.PushTask(context.Background(), pbTask); err != nil {
			_ = db.DB.Delete(&db.Task{}, "id = ?", task.ID).Error
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"status": "task_created", "task_id": task.ID})
}

func getArsenals(c *gin.Context) {
	var arsenals []db.Arsenal
	typ := c.Param("type")
	db.DB.Where("type = ?", typ).Find(&arsenals)
	c.JSON(http.StatusOK, arsenals)
}

func saveArsenal(c *gin.Context) {
	typ := c.Param("type")
	fn := c.Param("filename")

	var req struct {
		Content string `json:"content"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hash := fmt.Sprintf("%x", md5.Sum([]byte(req.Content)))

	arsenal := db.Arsenal{
		ID:       typ + "_" + fn,
		Type:     typ,
		FileName: fn,
		Content:  req.Content,
		Hash:     hash,
	}
	db.DB.Save(&arsenal)
	c.JSON(http.StatusOK, gin.H{"status": "saved", "hash": hash})
}

func deleteArsenal(c *gin.Context) {
	typ := c.Param("type")
	fn := c.Param("filename")
	db.DB.Delete(&db.Arsenal{}, "id = ?", typ+"_"+fn)
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

func deleteTask(c *gin.Context) {
	id := c.Param("id")
	db.DB.Delete(&db.Task{}, "id = ?", id)
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

func getVulns(c *gin.Context) {
	var vulns []db.Vuln
	db.DB.Order("created_at desc").Limit(100).Find(&vulns)
	c.JSON(http.StatusOK, vulns)
}

func getNodes(c *gin.Context) {
	var nodes []db.Node
	db.DB.Find(&nodes)
	c.JSON(http.StatusOK, nodes)
}

func parseTargets(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}

	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}

	var targets []string
	switch trimmed[0] {
	case '"':
		var input string
		if err := json.Unmarshal(raw, &input); err != nil {
			return nil, err
		}
		targets = splitTargets(input)
	case '[':
		if err := json.Unmarshal(raw, &targets); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("targets must be a string or string array")
	}

	return dedupeStrings(targets), nil
}

func normalizeConfigPayload(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "{}", nil
	}

	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return "{}", nil
	}

	switch trimmed[0] {
	case '"':
		var input string
		if err := json.Unmarshal(raw, &input); err != nil {
			return "", err
		}
		input = strings.TrimSpace(input)
		if input == "" {
			return "{}", nil
		}
		if !json.Valid([]byte(input)) {
			return "", fmt.Errorf("config must be valid json")
		}
		return input, nil
	case '{':
		if !json.Valid(raw) {
			return "", fmt.Errorf("config must be valid json")
		}
		return string(raw), nil
	default:
		return "", fmt.Errorf("config must be a json object or json string")
	}
}

func splitTargets(input string) []string {
	input = strings.ReplaceAll(input, "\r\n", "\n")
	input = strings.ReplaceAll(input, ",", "\n")
	parts := strings.Split(input, "\n")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func dedupeStrings(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}
