package api

import (
	"context"
	"crypto/md5"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/user/dddd-server/internal/db"
	"github.com/user/dddd-server/internal/scheduler"
	"gorm.io/gorm"
)

var taskQueue *scheduler.TaskQueue

func SetTaskQueue(queue *scheduler.TaskQueue) {
	taskQueue = queue
}

var jwtSecret = []byte("P8-MUST-HAVE-SECRET-KEY") // TODO: 生产环境应从配置文件读取

// TenantMiddleware 强制 JWT 校验并拦截身份
func TenantMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 跳过 Auth 登录自己
		if c.Request.URL.Path == "/api/v1/auth/login" {
			c.Next()
			return
		}

		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing or malformed JWT token"})
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			c.Set("tenant", claims["tenant_id"])
		} else {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid claims map"})
			return
		}

		c.Next()
	}
}

// Global variable acting as hot-reload trigger
var GlobalArsenalReloadCounter int64 = 0

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
	api.Use(TenantMiddleware())
	{
		// JWT 签发
		api.POST("/auth/login", authLogin)

		// WebSocket 入口
		api.GET("/ws", HandleWS)

		// Dashboard 统计数据
		api.GET("/stats", getStats)

		// 任务 CRUD
		api.GET("/tasks", getTasks)
		api.POST("/tasks", createTask)
		api.DELETE("/tasks/:id", deleteTask)
		api.POST("/tasks/:id/cancel", cancelTask)

		// 漏洞资产与关联画像
		api.GET("/vulns", getVulns)
		api.GET("/assets", getAssets)
		api.GET("/fingerprints", getFingerprints)
		api.GET("/profiles", getProfiles)
		
		// 战报输出引擎
		api.GET("/reports/export/vulns", exportVulns)

		// Agent 节点
		api.GET("/nodes", getNodes)
		api.GET("/agents/:id/commands", getAgentCommands)

		// Arsenal 弹药库热发车网关与审核墙
		api.GET("/arsenals/:type", getArsenals)
		api.POST("/arsenals/:type/:filename", saveArsenal)
		api.POST("/arsenals/:type/:filename/approve", approveArsenal)
		api.POST("/arsenals/ai/analyze", aiAnalyzeArsenal)
		api.DELETE("/arsenals/:type/:filename", deleteArsenal)

		// Dictionary Parsing Gateway (for workflow etc)
		api.GET("/dictionaries/workflow", getWorkflowDict)
		api.POST("/dictionaries/workflow", addWorkflowDict)
		api.PUT("/dictionaries/workflow/:product", updateWorkflowDict)
		api.DELETE("/dictionaries/workflow/:product", deleteWorkflowDict)

		api.GET("/dictionaries/fingerprint", getFingerprintDict)
		api.POST("/dictionaries/fingerprint", addFingerprintDict)
		api.PUT("/dictionaries/fingerprint/:product", updateFingerprintDict)
		api.DELETE("/dictionaries/fingerprint/:product", deleteFingerprintDict)
	}

	// SPA 控制塔前台映射兜底
	r.Static("/assets", "./server-ui/dist/assets")
	r.StaticFile("/favicon.ico", "./server-ui/dist/favicon.ico")
	r.NoRoute(func(c *gin.Context) {
		if !strings.HasPrefix(c.Request.URL.Path, "/api/") {
			c.File("./server-ui/dist/index.html")
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
	var taskCount, nodeCount, assetCount, fpCount, vulnCount int64
	db.DB.Model(&db.RootTask{}).Count(&taskCount)
	db.DB.Model(&db.Node{}).Count(&nodeCount)
	db.DB.Model(&db.Asset{}).Count(&assetCount)
	db.DB.Model(&db.FingerprintHit{}).Count(&fpCount)
	db.DB.Model(&db.Vulnerability{}).Count(&vulnCount)

	c.JSON(http.StatusOK, gin.H{
		"tasks":        taskCount,
		"nodes":        nodeCount,
		"assets":       assetCount,
		"fingerprints": fpCount,
		"vulns":        vulnCount,
	})
}

func getTasks(c *gin.Context) {
	var tasks []db.RootTask
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

	rootTaskID := fmt.Sprintf("task-%d", time.Now().UnixNano())
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = targets[0]
	}

	// 多租户隔离下钻
	tenantID := c.GetString("tenant")

	// 1. Task Splitter Logic
	chunkSize := 256
	var subTasks []db.SubTask
	for i := 0; i < len(targets); i += chunkSize {
		end := i + chunkSize
		if end > len(targets) {
			end = len(targets)
		}
		chunkTargets := targets[i:end]
		chunkJSON, _ := json.Marshal(chunkTargets)

		subTasks = append(subTasks, db.SubTask{
			ID:           fmt.Sprintf("%s-sub-%d", rootTaskID, i/chunkSize),
			TenantID:     tenantID,
			RootTaskID:   rootTaskID,
			ChunkTargets: string(chunkJSON),
			Status:       "Pending",
			Config:       configJSON,
		})
	}

	rootTask := db.RootTask{
		ID:              rootTaskID,
		TenantID:        tenantID,
		Name:            name,
		Status:          "Pending",
		OriginalTargets: string(targetsJSON),
		Config:          configJSON,
		TotalChunks:     len(subTasks),
		CompletedChunks: 0,
	}

	// 2. Transaction for Root and SubTasks
	err = db.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&rootTask).Error; err != nil {
			return err
		}
		if len(subTasks) > 0 {
			if err := tx.CreateInBatches(subTasks, 100).Error; err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 3. Dispatch to Queue
	if taskQueue != nil {
		for _, st := range subTasks {
			pbSub, _ := db.SubTaskToProto(&st)
			if err := taskQueue.PushTask(context.Background(), pbSub); err != nil {
				log.Printf("Failed to push subtask %s: %v", st.ID, err)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{"status": "task_created", "task_id": rootTask.ID})
}

// ---------------- Arsenal --------------------

func getArsenals(c *gin.Context) {
	var arsenals []db.Arsenal
	typ := c.Param("type")
	query := db.DB.Where("type = ?", typ)

	// 如果没有 ?all=1 参数，默认只下发已审核武器给 Agent
	if c.Query("all") != "1" {
		query = query.Where("state = ?", "Approved")
	}

	// 如果指定了 lite=1 ，则省略动辄几千上万行的巨大 Content 正文内容，只提取主要元数据
	if c.Query("lite") == "1" {
		query = query.Omit("Content")
	}

	query.Find(&arsenals)
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
		TenantID: c.GetString("tenant"),
		Type:     typ,
		FileName: fn,
		Content:  req.Content,
		Hash:     hash,
		State:    "Draft", // 初始提交强制为草稿状态
	}
	db.DB.Save(&arsenal)
	c.JSON(http.StatusOK, gin.H{"status": "saved", "hash": hash, "state": "Draft"})
}

func approveArsenal(c *gin.Context) {
	typ := c.Param("type")
	fn := c.Param("filename")
	tenantID := c.GetString("tenant")
	id := typ + "_" + fn
	db.DB.Model(&db.Arsenal{}).Where("id = ? AND tenant_id = ?", id, tenantID).Update("state", "Approved")
	
	// 触发全网 Agent 重新拉取
	GlobalArsenalReloadCounter++
	log.Printf("[Arsenal Hub] Rules updated by Tenant %s. Global Rule Reload Triggered!", tenantID)
	
	c.JSON(http.StatusOK, gin.H{"status": "approved"})
}

func deleteArsenal(c *gin.Context) {
	typ := c.Param("type")
	fn := c.Param("filename")
	db.DB.Delete(&db.Arsenal{}, "id = ?", typ+"_"+fn)
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

// ---------------- 融合画像数据源 --------------------

type Profile struct {
	Target       string              `json:"target"`
	Assets       []db.Asset          `json:"assets"`
	Fingerprints []db.FingerprintHit `json:"fingerprints"`
	Vulns        []db.Vulnerability  `json:"vulns"`
}

func getProfiles(c *gin.Context) {
	// TODO: 后期随着数据量增加，可以在此处开启分页、租户隔离、或者走 Elasticsearch
	var assets []db.Asset
	db.DB.Find(&assets)
	var fps []db.FingerprintHit
	db.DB.Find(&fps)
	var vulns []db.Vulnerability
	db.DB.Find(&vulns)

	pm := make(map[string]*Profile)
	
	for _, a := range assets {
		if _, ok := pm[a.Target]; !ok { pm[a.Target] = &Profile{Target: a.Target} }
		pm[a.Target].Assets = append(pm[a.Target].Assets, a)
	}
	for _, f := range fps {
		if _, ok := pm[f.Target]; !ok { pm[f.Target] = &Profile{Target: f.Target} }
		pm[f.Target].Fingerprints = append(pm[f.Target].Fingerprints, f)
	}
	for _, v := range vulns {
		if _, ok := pm[v.Target]; !ok { pm[v.Target] = &Profile{Target: v.Target} }
		pm[v.Target].Vulns = append(pm[v.Target].Vulns, v)
	}

	var results []Profile
	for _, p := range pm {
		results = append(results, *p)
	}
	c.JSON(http.StatusOK, results)
}

func deleteTask(c *gin.Context) {
	id := c.Param("id")
	db.DB.Delete(&db.RootTask{}, "id = ?", id)
	db.DB.Delete(&db.SubTask{}, "root_task_id = ?", id)
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

// ---------------- 战报引擎 --------------------

func exportVulns(c *gin.Context) {
	c.Writer.Header().Set("Content-Type", "text/csv")
	c.Writer.Header().Set("Content-Disposition", "attachment;filename=vulnerabilities.csv")
	
	writer := csv.NewWriter(c.Writer)
	defer writer.Flush()
	
	writer.Write([]string{"TenantID", "TaskID", "Target", "Plugin", "Severity", "DetectedAt"})
	
	var vulns []db.Vulnerability
	tenantID := c.GetString("tenant")
	query := db.DB.Model(&db.Vulnerability{})
	if tenantID != "default" {
		query = query.Where("tenant_id = ?", tenantID)
	}
	query.Find(&vulns)
	
	for _, v := range vulns {
		writer.Write([]string{v.TenantID, v.TaskID, v.Target, v.Plugin, v.Severity, v.CreatedAt.Format(time.RFC3339)})
	}
}

func aiAnalyzeArsenal(c *gin.Context) {
	var req struct {
		Content string `json:"content"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	// Mock AI Heuristic rules
	lowerContent := strings.ToLower(req.Content)
	if strings.Contains(lowerContent, "cve-2023") || strings.Contains(lowerContent, "log4j") {
		c.JSON(http.StatusOK, gin.H{
			"suggestion": "Reject",
			"reason": "Highly overlaps with known existing high-profile vulnerabilities in our Arsenal. Please check your entries to avoid payload duplicates.",
			"confidence": 0.88,
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"suggestion": "Approve",
		"reason": "Rule signature is unique, syntactically correct, and does not overlap with existing cluster profiles.",
		"confidence": 0.96,
	})
}


func cancelTask(c *gin.Context) {
	id := c.Param("id")
	// 将该 RootTask 下的所有排队中、运行中的 SubTask 标记为 CancelPending，供 Agent 拦截
	db.DB.Model(&db.SubTask{}).Where("root_task_id = ? AND status IN ('Pending', 'Running')", id).Update("status", "CancelPending")
	c.JSON(http.StatusOK, gin.H{"status": "cancellation dispatched"})
}

// 提供给 Agent 轮询其需强制退出的指令以及规则重载指令
func getAgentCommands(c *gin.Context) {
	id := c.Param("id")
	var subTasks []db.SubTask
	// 对于该节点正在运行但被强制退出的任务
	db.DB.Where("agent_id = ? AND status = 'CancelPending'", id).Find(&subTasks)

	var cancels []string
	for _, st := range subTasks {
		cancels = append(cancels, st.ID)
		// 一旦下发，直接标记为 Cancelled 避免重复下发
		db.DB.Model(&st).Update("status", "Cancelled")
		// Ack the task if it's running so it doesn't stay in queue forever
		if taskQueue != nil && st.StreamMsgID != "" {
			_ = taskQueue.AckTask(context.Background(), st.StreamMsgID)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"cancel_tasks": cancels,
		"reload_rules": GlobalArsenalReloadCounter > 0,
	})
}

func getVulns(c *gin.Context) {
	var vulns []db.Vulnerability
	query := db.DB.Order("created_at desc")
	if taskID := c.Query("task_id"); taskID != "" {
		query = query.Where("task_id = ?", taskID)
	}
	query.Limit(500).Find(&vulns)
	c.JSON(http.StatusOK, vulns)
}

func getAssets(c *gin.Context) {
	var assets []db.Asset
	query := db.DB.Order("created_at desc")
	if taskID := c.Query("task_id"); taskID != "" {
		query = query.Where("task_id = ?", taskID)
	}
	query.Limit(500).Find(&assets)
	c.JSON(http.StatusOK, assets)
}

func getFingerprints(c *gin.Context) {
	var fps []db.FingerprintHit
	query := db.DB.Order("created_at desc")
	if taskID := c.Query("task_id"); taskID != "" {
		query = query.Where("task_id = ?", taskID)
	}
	query.Limit(500).Find(&fps)
	c.JSON(http.StatusOK, fps)
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

// ---------------- 鉴权引擎 --------------------
func authLogin(c *gin.Context) {
	var req struct {
		TenantID string `json:"tenant_id"`
		Password string `json:"password"` // 占位，生产该走密码库比对
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// 虚拟校验
	if req.Password != "8888" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Wrong password"})
		return
	}
	
	// 颁发 Token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"tenant_id": req.TenantID,
		"exp":       time.Now().Add(time.Hour * 72).Unix(),
	})
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to sign"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}
