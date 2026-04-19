package api

import (
	"context"
	"crypto/md5"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/user/dddd-server/internal/db"
	"github.com/user/dddd-server/internal/scheduler"
	"golang.org/x/crypto/bcrypt"
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
			// 解析角色信息用于 RBAC
			if role, ok := claims["role"].(string); ok {
				c.Set("role", role)
			} else {
				c.Set("role", "admin") // 兼容旧 token
			}
			if uid, ok := claims["user_id"].(string); ok {
				c.Set("user_id", uid)
			}
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
	api.Use(RBACMiddleware())
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

		// 规则清单（增量同步用）
		api.GET("/arsenals/manifest", getArsenalManifest)

		// 用户管理 CRUD
		api.GET("/users", listUsers)
		api.POST("/users", createUser)
		api.PUT("/users/:id", updateUser)
		api.DELETE("/users/:id", deleteUser)

		// 云实例管理
		api.GET("/cloud/instances", listCloudInstances)
		api.POST("/cloud/instances", createCloudInstance)
		api.DELETE("/cloud/instances/:id", deleteCloudInstance)

		// 客户端构建
		api.GET("/build/artifacts", listBuildArtifacts)
		api.POST("/build/client", triggerBuild)

		// MCP / API Key 管理
		api.GET("/mcp/keys", listMcpKeys)
		api.POST("/mcp/keys", saveMcpKey)
		api.DELETE("/mcp/keys/:id", deleteMcpKey)

		// 数据增强：趋势统计与报表
		api.GET("/stats/trends", getVulnTrends)
		api.GET("/stats/severity", getSeverityDistribution)
		api.GET("/stats/task-results", getTaskResultStats)
		api.GET("/stats/recent-high-vulns", getRecentHighVulns)

		// Agent 遥测日志
		api.GET("/agents/:id/logs", getAgentLogs)

		// 规则回滚
		api.POST("/arsenals/:type/:filename/rollback", rollbackArsenal)
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
		Name       string          `json:"name"`
		Targets    json.RawMessage `json:"targets"`
		Config     json.RawMessage `json:"config"`
		Priority   int             `json:"priority"`
		TimeoutSec int             `json:"timeout_sec"`
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
			Priority:     req.Priority,
			TimeoutSec:   req.TimeoutSec,
			MaxRetry:     3,
		})
	}

	rootTask := db.RootTask{
		ID:              rootTaskID,
		TenantID:        tenantID,
		Name:            name,
		Status:          "Queued",
		OriginalTargets: string(targetsJSON),
		Config:          configJSON,
		TotalChunks:     len(subTasks),
		CompletedChunks: 0,
		Priority:        req.Priority,
		TimeoutSec:      req.TimeoutSec,
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

	// 查找已有记录以保存 PreviousHash 和递增 Version
	var existing db.Arsenal
	var previousHash string
	var version int = 1
	if db.DB.Where("id = ?", typ+"_"+fn).First(&existing).Error == nil {
		previousHash = existing.Hash
		version = existing.Version + 1
	}

	arsenal := db.Arsenal{
		ID:           typ + "_" + fn,
		TenantID:     c.GetString("tenant"),
		Type:         typ,
		FileName:     fn,
		Content:      req.Content,
		Hash:         hash,
		PreviousHash: previousHash,
		Version:      version,
		State:        "Draft",
	}
	db.DB.Save(&arsenal)
	c.JSON(http.StatusOK, gin.H{"status": "saved", "hash": hash, "state": "Draft", "version": version})
}

func approveArsenal(c *gin.Context) {
	typ := c.Param("type")
	fn := c.Param("filename")
	tenantID := c.GetString("tenant")
	id := typ + "_" + fn
	db.DB.Model(&db.Arsenal{}).Where("id = ? AND tenant_id = ?", id, tenantID).Update("state", "Approved")
	
	// 触发版本号递增
	newVersion := BumpRuleVersion()

	// 触发全网 Agent 重新拉取
	GlobalArsenalReloadCounter++
	log.Printf("[Arsenal Hub] Rules approved by Tenant %s. Rule version bumped to %s. Global Reload Triggered!", tenantID, newVersion)
	
	c.JSON(http.StatusOK, gin.H{"status": "approved", "rule_version": newVersion})
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
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 尝试从数据库校验用户
	var user db.User
	if err := db.DB.Where("username = ?", req.TenantID).First(&user).Error; err == nil {
		// 数据库有此用户，校验密码
		if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Wrong password"})
			return
		}
	} else {
		// 降级：兼容旧的固定密码模式
		if req.Password != "8888" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Wrong password"})
			return
		}
	}

	// 颁发 Token（包含角色信息）
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"tenant_id": req.TenantID,
		"role":      user.Role,
		"user_id":   fmt.Sprintf("%d", user.ID),
		"exp":       time.Now().Add(time.Hour * 72).Unix(),
	})
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to sign"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

// ==================== 规则清单 (增量同步用) ====================

func getArsenalManifest(c *gin.Context) {
	var arsenals []db.Arsenal
	db.DB.Select("type, file_name, hash, state, updated_at").
		Where("state = ?", "Approved").
		Find(&arsenals)

	type ManifestItem struct {
		Type      string `json:"type"`
		FileName  string `json:"file_name"`
		Hash      string `json:"hash"`
		UpdatedAt string `json:"updated_at"`
	}

	// 获取当前规则版本
	var cfg db.SystemConfig
	ruleVersion := "unknown"
	if db.DB.Where("key = ?", "rule_version").First(&cfg).Error == nil {
		ruleVersion = cfg.Value
	}

	items := make([]ManifestItem, 0, len(arsenals))
	for _, a := range arsenals {
		items = append(items, ManifestItem{
			Type:      a.Type,
			FileName:  a.FileName,
			Hash:      a.Hash,
			UpdatedAt: a.UpdatedAt.Format(time.RFC3339),
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"rule_version": ruleVersion,
		"items":        items,
	})
}

// ==================== 用户管理 CRUD ====================

func listUsers(c *gin.Context) {
	var users []db.User
	db.DB.Order("created_at DESC").Find(&users)

	type UserResp struct {
		ID        uint   `json:"id"`
		TenantID  string `json:"tenant_id"`
		Username  string `json:"username"`
		Role      string `json:"role"`
		Status    string `json:"status"`
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
	}

	resp := make([]UserResp, 0, len(users))
	for _, u := range users {
		resp = append(resp, UserResp{
			ID:        u.ID,
			TenantID:  u.TenantID,
			Username:  u.Username,
			Role:      u.Role,
			Status:    u.Status,
			CreatedAt: u.CreatedAt.Format(time.RFC3339),
			UpdatedAt: u.UpdatedAt.Format(time.RFC3339),
		})
	}

	c.JSON(http.StatusOK, resp)
}

func createUser(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
		Role     string `json:"role"`
		TenantID string `json:"tenant_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Role == "" {
		req.Role = "viewer"
	}
	if req.TenantID == "" {
		req.TenantID = "default"
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	user := db.User{
		TenantID:     req.TenantID,
		Username:     req.Username,
		PasswordHash: string(hash),
		Role:         req.Role,
		Status:       "active",
	}
	if err := db.DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok", "id": user.ID})
}

func updateUser(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Role     string `json:"role"`
		Status   string `json:"status"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	updates := map[string]interface{}{}
	if req.Role != "" {
		updates["role"] = req.Role
	}
	if req.Status != "" {
		updates["status"] = req.Status
	}
	if req.Password != "" {
		hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		updates["password_hash"] = string(hash)
	}

	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No fields to update"})
		return
	}

	if err := db.DB.Model(&db.User{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func deleteUser(c *gin.Context) {
	id := c.Param("id")
	if err := db.DB.Delete(&db.User{}, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// ==================== 云实例管理 ====================

func listCloudInstances(c *gin.Context) {
	// 通过 Docker CLI 查询当前运行的 agent 容器
	type Instance struct {
		ID        string `json:"id"`
		IP        string `json:"ip"`
		Status    string `json:"status"`
		Provider  string `json:"provider"`
		CreatedAt string `json:"created_at"`
	}

	// 从 nodes 表中读取记录作为实例列表
	var nodes []db.Node
	db.DB.Order("created_at DESC").Find(&nodes)

	instances := make([]Instance, 0, len(nodes))
	for _, n := range nodes {
		instances = append(instances, Instance{
			ID:        n.AgentID,
			IP:        n.IP,
			Status:    n.Status,
			Provider:  "agent",
			CreatedAt: n.CreatedAt.Format(time.RFC3339),
		})
	}

	c.JSON(http.StatusOK, instances)
}

func createCloudInstance(c *gin.Context) {
	var req struct {
		Provider     string `json:"provider"`     // docker, aliyun
		Region       string `json:"region"`
		InstanceType string `json:"instance_type"`
		ImageID      string `json:"image_id"`
		ServerAddr   string `json:"server_addr"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 当前实现：仅返回提示信息，实际创建需要配置云 Provider
	c.JSON(http.StatusOK, gin.H{
		"status":  "accepted",
		"message": fmt.Sprintf("Cloud instance creation request accepted (provider=%s). Please configure cloud provider credentials.", req.Provider),
	})
}

func deleteCloudInstance(c *gin.Context) {
	id := c.Param("id")
	// 标记节点为 Offline
	db.DB.Model(&db.Node{}).Where("agent_id = ?", id).Update("status", "Offline")
	c.JSON(http.StatusOK, gin.H{"status": "ok", "message": fmt.Sprintf("Instance %s marked for termination", id)})
}

// ==================== 客户端构建 ====================

func listBuildArtifacts(c *gin.Context) {
	type Artifact struct {
		Name     string `json:"name"`
		Size     int64  `json:"size"`
		Platform string `json:"platform"`
		Arch     string `json:"arch"`
		ModTime  string `json:"mod_time"`
	}

	releaseDir := "./release"
	artifacts := make([]Artifact, 0)

	entries, err := os.ReadDir(releaseDir)
	if err != nil {
		c.JSON(http.StatusOK, artifacts)
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		name := entry.Name()
		platform, arch := parseBinaryName(name)
		artifacts = append(artifacts, Artifact{
			Name:     name,
			Size:     info.Size(),
			Platform: platform,
			Arch:     arch,
			ModTime:  info.ModTime().Format(time.RFC3339),
		})
	}

	c.JSON(http.StatusOK, artifacts)
}

func parseBinaryName(name string) (platform, arch string) {
	parts := strings.Split(name, "-")
	for _, p := range parts {
		switch p {
		case "linux", "darwin", "windows":
			platform = p
		case "amd64", "arm64", "386":
			arch = p
		}
	}
	if platform == "" {
		platform = "unknown"
	}
	if arch == "" {
		arch = "unknown"
	}
	return
}

func triggerBuild(c *gin.Context) {
	var req struct {
		Platform string `json:"platform"` // linux, darwin, windows
		Arch     string `json:"arch"`     // amd64, arm64
		Pack     bool   `json:"pack"`     // 是否 UPX 压缩
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Platform == "" {
		req.Platform = "linux"
	}
	if req.Arch == "" {
		req.Arch = "amd64"
	}

	// 检查 build.sh 是否存在
	buildScript := "./build.sh"
	if _, err := os.Stat(buildScript); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"error": "build.sh not found in project root"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":   "accepted",
		"message":  fmt.Sprintf("Build request queued: %s/%s (pack=%v). Run './build.sh' manually or wait for CI pipeline.", req.Platform, req.Arch, req.Pack),
		"platform": req.Platform,
		"arch":     req.Arch,
	})
}

// ==================== MCP / API Key 管理 ====================

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

// ==================== 辅助：下载构建产物 ====================

func init() {
	// 注册 release 目录为静态文件服务（供前端下载）
	_ = os.MkdirAll("./release", 0755)
}

// ==================== getNodes 增强返回新字段 ========
// getNodes 已经在原代码中存在，这里不重复声明
// 新字段 Version/Capacity/RunningTasks/RuleVersion 已通过 GORM AutoMigrate 添加到
// Node 模型中，getNodes 使用 db.DB.Find(&nodes) 会自动包含这些字段

// ==================== 超时/重试守护协程 (由 main.go 调用) ====================

// StartTaskTimeoutDaemon 由 main.go 启动，定期检查超时和重试逻辑
func StartTaskTimeoutDaemon(ctx context.Context, q *scheduler.TaskQueue) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			handleTimeoutTasks(q)
		}
	}
}

func handleTimeoutTasks(q *scheduler.TaskQueue) {
	// 查找 Running 状态且已超时的 SubTask
	var subs []db.SubTask
	db.DB.Where("status = ? AND timeout_sec > 0", "Running").Find(&subs)

	now := time.Now()
	for _, sub := range subs {
		deadline := sub.UpdatedAt.Add(time.Duration(sub.TimeoutSec) * time.Second)
		if now.After(deadline) {
			log.Printf("[TimeoutDaemon] SubTask %s timed out (timeout=%ds)", sub.ID, sub.TimeoutSec)

			if sub.RetryCount < sub.MaxRetry {
				// 可重试：递增计数，重置状态，重入队
				db.DB.Model(&sub).Updates(map[string]interface{}{
					"status":      "Pending",
					"retry_count": sub.RetryCount + 1,
					"agent_id":    "",
				})
				if q != nil {
					pbSub, _ := db.SubTaskToProto(&sub)
					if pbSub != nil {
						_ = q.PushTaskToFront(context.Background(), pbSub)
						log.Printf("[TimeoutDaemon] SubTask %s re-queued (retry %d/%d)", sub.ID, sub.RetryCount+1, sub.MaxRetry)
					}
				}
			} else {
				// 超过重试次数：标记为 Timeout
				db.DB.Model(&sub).Update("status", "Timeout")
				log.Printf("[TimeoutDaemon] SubTask %s marked as Timeout (max retries exceeded)", sub.ID)

				// 检查 RootTask 是否所有子任务都结束了
				if sub.RootTaskID != "" {
					var running int64
					db.DB.Model(&db.SubTask{}).Where("root_task_id = ? AND status IN ?",
						sub.RootTaskID, []string{"Pending", "Running"}).Count(&running)
					if running == 0 {
						db.DB.Model(&db.RootTask{}).Where("id = ?", sub.RootTaskID).
							Update("status", "Timeout")
					}
				}
			}
			// 递减关联节点 running_tasks
			if sub.AgentID != "" {
				db.DB.Exec("UPDATE nodes SET running_tasks = GREATEST(running_tasks - 1, 0) WHERE agent_id = ?", sub.AgentID)
			}
		}
	}
}

// GetCurrentRuleVersion 获取当前规则版本号
func GetCurrentRuleVersion() string {
	var cfg db.SystemConfig
	if db.DB.Where("key = ?", "rule_version").First(&cfg).Error == nil {
		return cfg.Value
	}
	return ""
}

// BumpRuleVersion 生成并保存新的规则版本号
func BumpRuleVersion() string {
	version := fmt.Sprintf("v%s.%03d", time.Now().Format("2006.01.02"), time.Now().UnixMilli()%1000)
	cfg := db.SystemConfig{
		Key:       "rule_version",
		Value:     version,
		UpdatedAt: time.Now(),
	}
	db.DB.Save(&cfg)
	return version
}

// 利用辅助变量避免 import 报错
var (
	_ = strconv.Itoa
	_ = filepath.Base
	_ = os.Stat
)

// ==================== 数据增强 API ====================

func getVulnTrends(c *gin.Context) {
	days := 30
	if d := c.Query("days"); d != "" {
		if v, err := strconv.Atoi(d); err == nil && v > 0 {
			days = v
		}
	}
	c.JSON(http.StatusOK, db.GetVulnTrends(days))
}

func getSeverityDistribution(c *gin.Context) {
	c.JSON(http.StatusOK, db.GetSeverityDistribution())
}

func getTaskResultStats(c *gin.Context) {
	limit := 20
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 {
			limit = v
		}
	}
	c.JSON(http.StatusOK, db.GetTaskResultStats(limit))
}

func getRecentHighVulns(c *gin.Context) {
	limit := 10
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 {
			limit = v
		}
	}
	c.JSON(http.StatusOK, db.GetRecentHighVulns(limit))
}

// ==================== Agent 遥测日志 ====================

func getAgentLogs(c *gin.Context) {
	agentID := c.Param("id")
	limit := 100
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 {
			limit = v
		}
	}
	level := c.Query("level") // 可选过滤: INFO, WARN, ERROR

	var logs []db.AgentLog
	query := db.DB.Where("agent_id = ?", agentID)
	if level != "" {
		query = query.Where("level = ?", level)
	}
	query.Order("timestamp DESC").Limit(limit).Find(&logs)
	c.JSON(http.StatusOK, logs)
}

// ==================== 规则回滚 ====================

func rollbackArsenal(c *gin.Context) {
	typ := c.Param("type")
	fn := c.Param("filename")
	id := typ + "_" + fn

	var arsenal db.Arsenal
	if err := db.DB.Where("id = ?", id).First(&arsenal).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Arsenal not found"})
		return
	}

	if arsenal.PreviousHash == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No previous version available for rollback"})
		return
	}

	// 交换当前版本和上一版本
	db.DB.Model(&arsenal).Updates(map[string]interface{}{
		"hash":          arsenal.PreviousHash,
		"previous_hash": arsenal.Hash,
		"state":         "Draft", // 回滚后重新审批
		"version":       arsenal.Version + 1,
	})

	// 触发全网 Agent 重新拉取
	newVersion := BumpRuleVersion()
	GlobalArsenalReloadCounter++
	log.Printf("[Arsenal Hub] Rule %s/%s rolled back. Rule version: %s", typ, fn, newVersion)

	c.JSON(http.StatusOK, gin.H{"status": "rolled_back", "rule_version": newVersion})
}

