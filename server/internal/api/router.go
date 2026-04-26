package api

import (
	"context"
	"crypto/md5"
	"crypto/subtle"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/user/dddd-server/internal/db"
	grpcpkg "github.com/user/dddd-server/internal/grpc"
	"github.com/user/dddd-server/internal/scheduler"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var taskQueue *scheduler.TaskQueue
var notifyHub *grpcpkg.NotifyHub
var agentPSK string
var developmentMode bool

const (
	subTaskStatusDispatching = "Dispatching"
	cancelPendingSettleGrace = 45 * time.Second
)

func SetTaskQueue(queue *scheduler.TaskQueue) {
	taskQueue = queue
}

// SetAgentPSK 注入 Agent 预共享密钥，用于 Agent 内部 API 鉴权。
func SetAgentPSK(psk string) {
	agentPSK = strings.TrimSpace(psk)
}

func SetDevelopmentMode(enabled bool) {
	developmentMode = enabled
}

func isAgentInternalEndpoint(c *gin.Context) bool {
	if c.Request.Method != http.MethodGet {
		return false
	}
	path := c.Request.URL.Path
	if strings.HasPrefix(path, "/api/v1/agents/") && strings.HasSuffix(path, "/commands") {
		return true
	}
	if path == "/api/v1/arsenals/manifest" {
		return true
	}
	// Agent 整体 DB 同步端点
	if path == "/api/v1/arsenals/db" || path == "/api/v1/arsenals/db/hash" || path == "/api/v1/arsenals/db/stats" {
		return true
	}
	if strings.HasPrefix(path, "/api/v1/arsenals/") {
		rest := strings.TrimPrefix(path, "/api/v1/arsenals/")
		return rest != "" && !strings.Contains(rest, "/")
	}
	return false
}

func validateAgentPSK(c *gin.Context) bool {
	// 与 gRPC 保持一致：未配置 PSK 时允许开发模式开放访问。
	if agentPSK == "" {
		return true
	}
	token := strings.TrimSpace(c.GetHeader("x-agent-psk"))
	if token == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(agentPSK)) == 1
}

// SetNotifyHub 注入 gRPC NotifyHub 引用，用于 createTask 后广播通知 Agent
func SetNotifyHub(hub *grpcpkg.NotifyHub) {
	notifyHub = hub
	db.DebugEventHook = handleAgentDebugEvent
}

func currentTenantID(c *gin.Context) string {
	tenantID := strings.TrimSpace(c.GetString("tenant"))
	if tenantID == "" {
		return "default"
	}
	return tenantID
}

func currentRuleVersionValue() string {
	if version := strings.TrimSpace(GetCurrentRuleVersion()); version != "" {
		return version
	}
	return "unknown"
}

func shouldAgentReloadRules(agentRuleVersion, ruleVersion string) bool {
	ruleVersion = strings.TrimSpace(ruleVersion)
	if ruleVersion == "" || ruleVersion == "unknown" {
		return false
	}
	return strings.TrimSpace(agentRuleVersion) != ruleVersion
}

func resolveScopedTaskIDs(tenantID, taskID string) []string {
	taskID = strings.TrimSpace(taskID)
	if taskID == "" {
		return nil
	}

	var rootTask db.RootTask
	if err := db.DB.Select("id").Where("id = ? AND tenant_id = ?", taskID, tenantID).First(&rootTask).Error; err == nil {
		var subTaskIDs []string
		db.DB.Model(&db.SubTask{}).
			Where("root_task_id = ? AND tenant_id = ?", taskID, tenantID).
			Pluck("id", &subTaskIDs)
		if len(subTaskIDs) > 0 {
			return subTaskIDs
		}
	}

	return []string{taskID}
}

func scopedNodeQuery(tenantID string) *gorm.DB {
	if tenantID == "default" {
		return db.DB.Where("tenant_id = ? OR tenant_id = ''", tenantID)
	}
	return db.DB.Where("tenant_id = ?", tenantID)
}

var jwtSecretWarningOnce sync.Once

// currentJWTSecret 从环境变量 ARGUS_JWT_SECRET 读取，未设置则使用默认值（仅限开发环境）
func currentJWTSecret() []byte {
	if secret := os.Getenv("ARGUS_JWT_SECRET"); secret != "" {
		return []byte(secret)
	}
	jwtSecretWarningOnce.Do(func() {
		log.Println("[Auth] WARNING: ARGUS_JWT_SECRET not set, using insecure default (dev only)")
	})
	return []byte("P8-MUST-HAVE-SECRET-KEY")
}

// TenantMiddleware 强制 JWT 校验并拦截身份
func TenantMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 跳过 Auth 登录自己
		if c.Request.URL.Path == "/api/v1/auth/login" {
			c.Next()
			return
		}

		// Agent 内部 API：使用 PSK 鉴权（无需 JWT）。
		if isAgentInternalEndpoint(c) {
			if !validateAgentPSK(c) {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or missing agent pre-shared key"})
				return
			}
			// 注入默认身份，兼容 RBAC 逻辑。
			c.Set("tenant", "default")
			c.Set("role", "admin")
			c.Next()
			return
		}

		authHeader := c.GetHeader("Authorization")
		// WebSocket 握手无法携带 Authorization Header，
		// 前端通过 ?token=xxx query 参数传递 JWT，需要回退提取。
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			if qToken := c.Query("token"); qToken != "" {
				authHeader = "Bearer " + qToken
			}
		}
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing or malformed JWT token"})
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return currentJWTSecret(), nil
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

	// 连接底层的实时推流 Hook
	db.WSBroadcastHook = Hub.BroadcastToTenant

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

		// 项目 CRUD
		api.GET("/projects", getProjects)
		api.POST("/projects", createProject)

		// 任务 CRUD
		api.GET("/tasks", getTasks)
		api.GET("/tasks/:id", getTaskDetail)
		api.POST("/tasks", createTask)
		api.DELETE("/tasks/:id", deleteTask)
		api.POST("/tasks/:id/cancel", cancelTask)
		api.POST("/tasks/:id/append", appendTargets) // 动态追加目标

		// 队列监控
		api.GET("/queue/depth", getQueueDepth)

		// 漏洞资产与关联画像
		api.GET("/vulns", getVulns)
		api.GET("/assets", getAssets)
		api.GET("/fingerprints", getFingerprints)
		api.GET("/profiles", getProfiles)

		// 战报输出引擎
		api.GET("/reports/export/vulns", exportVulns)

		// Agent 节点
		api.GET("/nodes", getNodes)
		api.DELETE("/nodes/:id", deleteNode)
		api.POST("/nodes/clean", cleanOfflineNodes)
		api.GET("/agents/:id/commands", getAgentCommands)

		// Server-side AI analysis and configuration
		api.GET("/ai/config", getAIConfig)
		api.PUT("/ai/config", saveAIConfig)
		api.GET("/ai/models", listAIModels)
		api.POST("/ai/test", testAIConnection)
		api.POST("/ai/arsenal/analyze", analyzeArsenalWithAI)
		api.POST("/ai/arsenal/analyze/stream", analyzeArsenalStream)
		api.POST("/ai/chat", globalAIChat)

		// Arsenal 弹药库热发车网关与审核墙
		api.POST("/arsenals/ai/analyze", aiAnalyzeArsenal)
		api.POST("/arsenals/:type", debugPocGateway)
		api.GET("/arsenals/:type", getArsenals)
		api.POST("/arsenals/:type/:filename", saveArsenal)
		api.POST("/arsenals/:type/:filename/cancel", cancelDebugSessionGateway)
		api.POST("/arsenals/:type/:filename/approve", approveArsenal)
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

		api.GET("/dictionaries/dir", getDirDict)
		api.POST("/dictionaries/dir", addDirDict)
		api.PUT("/dictionaries/dir/:product", updateDirDict)
		api.DELETE("/dictionaries/dir/:product", deleteDirDict)

		// 规则清单（增量同步用）
		api.GET("/arsenals/manifest", getArsenalManifest)

		// Arsenal DB 整体同步（Agent 用）
		api.GET("/arsenals/db", getArsenalDB)
		api.GET("/arsenals/db/hash", getArsenalDBHash)
		api.GET("/arsenals/db/stats", getArsenalDBStats)

		// API 密钥集中管理
		api.GET("/config/api-keys", getApiKeysConfig)
		api.PUT("/config/api-keys", saveApiKeysConfig)

		// 用户管理 CRUD
		api.GET("/users", listUsers)
		api.POST("/users", createUser)
		api.PUT("/users/:id", updateUser)
		api.DELETE("/users/:id", deleteUser)

		// ====== 云资源编排 ======
		// 云账号凭证管理
		api.GET("/cloud/accounts", listCloudAccounts)
		api.POST("/cloud/accounts", createCloudAccount)
		api.PUT("/cloud/accounts/:id", updateCloudAccount)
		api.DELETE("/cloud/accounts/:id", deleteCloudAccount)
		api.POST("/cloud/accounts/:id/test", testCloudAccount)
		// 伸缩策略管理
		api.GET("/cloud/policies", listCloudPolicies)
		api.POST("/cloud/policies", createCloudPolicy)
		api.PUT("/cloud/policies/:id", updateCloudPolicy)
		api.DELETE("/cloud/policies/:id", deleteCloudPolicy)
		api.POST("/cloud/policies/:id/toggle", toggleCloudPolicy)
		// 云实例管理
		api.GET("/cloud/instances", listCloudInstancesReal)
		api.POST("/cloud/instances", createCloudInstanceManual)
		api.DELETE("/cloud/instances/:id", deleteCloudInstanceReal)
		// 云仪表盘
		api.GET("/cloud/dashboard", cloudDashboard)

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
	tenantID := currentTenantID(c)
	var taskCount, nodeCount, assetCount, fpCount, vulnCount int64
	db.DB.Model(&db.RootTask{}).Where("tenant_id = ?", tenantID).Count(&taskCount)
	scopedNodeQuery(tenantID).Model(&db.Node{}).Count(&nodeCount)
	db.DB.Model(&db.Asset{}).Where("tenant_id = ?", tenantID).Count(&assetCount)
	db.DB.Model(&db.FingerprintHit{}).Where("tenant_id = ?", tenantID).Count(&fpCount)
	db.DB.Model(&db.Vulnerability{}).Where("tenant_id = ?", tenantID).Count(&vulnCount)

	c.JSON(http.StatusOK, gin.H{
		"tasks":        taskCount,
		"nodes":        nodeCount,
		"assets":       assetCount,
		"fingerprints": fpCount,
		"vulns":        vulnCount,
	})
}

func getProjects(c *gin.Context) {
	var projects []db.Project
	tenantID := c.GetString("tenant")
	db.DB.Where("tenant_id = ?", tenantID).Order("created_at desc").Find(&projects)
	c.JSON(http.StatusOK, projects)
}

func createProject(c *gin.Context) {
	var req struct {
		Name        string `json:"name" binding:"required"`
		Description string `json:"description"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tenantID := c.GetString("tenant")
	project := db.Project{
		ID:            fmt.Sprintf("proj-%d", time.Now().UnixNano()),
		TenantID:      tenantID,
		Name:          req.Name,
		Description:   req.Description,
		Tags:          "[]",
		SeedTargets:   "[]",
		Scope:         "[]",
		DefaultConfig: "{}",
		NodeAffinity:  "{}",
		Status:        "active",
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	if err := db.DB.Create(&project).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, project)
}

func getTasks(c *gin.Context) {
	var tasks []db.RootTask
	tenantID := c.GetString("tenant")
	query := db.DB.Where("tenant_id = ?", tenantID)
	if projectID := c.Query("project_id"); projectID != "" {
		query = query.Where("project_id = ?", projectID)
	}
	query.Order("created_at desc").Limit(50).Find(&tasks)

	// 增强返回：包含目标维度进度
	type TaskResponse struct {
		db.RootTask
	}
	resp := make([]TaskResponse, 0, len(tasks))
	for _, t := range tasks {
		resp = append(resp, TaskResponse{RootTask: t})
	}
	c.JSON(http.StatusOK, resp)
}

// getTaskDetail 返回单个任务的详细信息，包括子任务列表和结果统计
func getTaskDetail(c *gin.Context) {
	taskID := c.Param("id")
	tenantID := currentTenantID(c)

	// 查询 RootTask
	var rootTask db.RootTask
	if err := db.DB.Where("id = ? AND tenant_id = ?", taskID, tenantID).First(&rootTask).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
		return
	}

	// 查询关联的所有 SubTask
	var subTasks []db.SubTask
	db.DB.Where("root_task_id = ? AND tenant_id = ?", taskID, tenantID).
		Order("created_at asc").Find(&subTasks)

	// 子任务状态分布统计
	statusDistribution := make(map[string]int)
	for _, st := range subTasks {
		statusDistribution[st.Status]++
	}

	// 构建子任务摘要（不暴露完整 Config 和 ChunkTargets 原文）
	type SubTaskSummary struct {
		ID          string    `json:"id"`
		Status      string    `json:"status"`
		AgentID     string    `json:"agent_id"`
		TargetCount int       `json:"target_count"`
		RetryCount  int       `json:"retry_count"`
		MaxRetry    int       `json:"max_retry"`
		Priority    int       `json:"priority"`
		TimeoutSec  int       `json:"timeout_sec"`
		CreatedAt   time.Time `json:"created_at"`
		UpdatedAt   time.Time `json:"updated_at"`
	}
	subSummaries := make([]SubTaskSummary, 0, len(subTasks))
	for _, st := range subTasks {
		var targets []string
		targetCount := 0
		if json.Unmarshal([]byte(st.ChunkTargets), &targets) == nil {
			targetCount = len(targets)
		}
		subSummaries = append(subSummaries, SubTaskSummary{
			ID:          st.ID,
			Status:      st.Status,
			AgentID:     st.AgentID,
			TargetCount: targetCount,
			RetryCount:  st.RetryCount,
			MaxRetry:    st.MaxRetry,
			Priority:    st.Priority,
			TimeoutSec:  st.TimeoutSec,
			CreatedAt:   st.CreatedAt,
			UpdatedAt:   st.UpdatedAt,
		})
	}

	// 结果统计（通过 root_task_id 直接关联到 RootTask，不受 upsert 改写 task_id 影响）
	var assetCount, fpCount, vulnCount int64
	db.DB.Model(&db.Asset{}).Where("root_task_id = ? AND tenant_id = ?", taskID, tenantID).Count(&assetCount)
	db.DB.Model(&db.FingerprintHit{}).Where("root_task_id = ? AND tenant_id = ?", taskID, tenantID).Count(&fpCount)
	db.DB.Model(&db.Vulnerability{}).Where("root_task_id = ? AND tenant_id = ?", taskID, tenantID).Count(&vulnCount)

	// Fallback: 如果 root_task_id 为空（旧数据），用 task_id IN subTaskIDs 兜底
	if assetCount == 0 && fpCount == 0 && vulnCount == 0 && len(subTasks) > 0 {
		subTaskIDs := make([]string, len(subTasks))
		for i, st := range subTasks {
			subTaskIDs[i] = st.ID
		}
		db.DB.Model(&db.Asset{}).Where("task_id IN ? AND tenant_id = ?", subTaskIDs, tenantID).Count(&assetCount)
		db.DB.Model(&db.FingerprintHit{}).Where("task_id IN ? AND tenant_id = ?", subTaskIDs, tenantID).Count(&fpCount)
		db.DB.Model(&db.Vulnerability{}).Where("task_id IN ? AND tenant_id = ?", subTaskIDs, tenantID).Count(&vulnCount)
	}

	// 漏洞严重度分布
	type sevCount struct {
		Severity string
		Cnt      int64
	}
	var sevDist []sevCount
	db.DB.Model(&db.Vulnerability{}).
		Select("severity, count(*) as cnt").
		Where("root_task_id = ? AND tenant_id = ?", taskID, tenantID).
		Group("severity").Scan(&sevDist)
	severityMap := make(map[string]int64)
	for _, s := range sevDist {
		severityMap[s.Severity] = s.Cnt
	}

	// 解析原始配置为 JSON 对象返回
	var configObj interface{}
	if json.Unmarshal([]byte(rootTask.Config), &configObj) != nil {
		configObj = rootTask.Config
	}

	c.JSON(http.StatusOK, gin.H{
		"task": gin.H{
			"id":                rootTask.ID,
			"name":              rootTask.Name,
			"status":            rootTask.Status,
			"priority":          rootTask.Priority,
			"total_chunks":      rootTask.TotalChunks,
			"completed_chunks":  rootTask.CompletedChunks,
			"total_targets":     rootTask.TotalTargets,
			"completed_targets": rootTask.CompletedTargets,
			"timeout_sec":       rootTask.TimeoutSec,
			"original_targets":  rootTask.OriginalTargets,
			"config":            configObj,
			"rule_version":      rootTask.RuleVersion,
			"created_at":        rootTask.CreatedAt,
			"updated_at":        rootTask.UpdatedAt,
		},
		"sub_tasks":           subSummaries,
		"status_distribution": statusDistribution,
		"result_stats": gin.H{
			"assets":       assetCount,
			"fingerprints": fpCount,
			"vulns":        vulnCount,
			"severity":     severityMap,
		},
	})
}

func dispatchSubTasks(ctx context.Context, q *scheduler.TaskQueue, subTasks []db.SubTask) (map[int]int, int) {
	pushedByPriority := make(map[int]int)
	if len(subTasks) == 0 {
		return pushedByPriority, 0
	}
	if q == nil {
		return pushedByPriority, len(subTasks)
	}

	dispatchPending := 0
	for _, st := range subTasks {
		pbSub, err := db.SubTaskToProto(&st)
		if err != nil || pbSub == nil {
			log.Printf("[Dispatch] Failed to encode subtask %s: %v", st.ID, err)
			dispatchPending++
			continue
		}

		if err := q.PushTask(ctx, pbSub); err != nil {
			log.Printf("[Dispatch] Failed to push subtask %s: %v", st.ID, err)
			dispatchPending++
			continue
		}

		// 入队成功后再将状态推进为 Pending，避免“先改状态后崩溃”导致任务既不在队列也不可恢复。
		updateRes := db.DB.Model(&db.SubTask{}).
			Where("id = ? AND status = ?", st.ID, subTaskStatusDispatching).
			Update("status", "Pending")
		if updateRes.Error != nil {
			log.Printf("[Dispatch] Subtask %s queued but status transition to Pending failed: %v", st.ID, updateRes.Error)
		}

		pushedByPriority[st.Priority]++
	}

	return pushedByPriority, dispatchPending
}

func totalDispatchedTasks(pushedByPriority map[int]int) int {
	total := 0
	for _, n := range pushedByPriority {
		total += n
	}
	return total
}

func broadcastDispatchedTasks(pushedByPriority map[int]int) {
	if notifyHub == nil {
		return
	}
	for priority, count := range pushedByPriority {
		if count <= 0 {
			continue
		}
		notifyHub.BroadcastNewTask(int32(count), int32(priority))
	}
}

func createTask(c *gin.Context) {
	var req struct {
		ProjectID  string          `json:"project_id"`
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

	if req.ProjectID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "project_id is required"})
		return
	}

	if req.Priority < 0 || req.Priority > 2 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "priority must be 0 (urgent), 1 (normal), or 2 (low)"})
		return
	}
	if req.TimeoutSec < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "timeout_sec must be greater than or equal to 0"})
		return
	}

	configJSON, targetMode, err := normalizeTaskConfigPayload(req.Config)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	targets, targetSummary, err := parseAndValidateTargetsForMode(req.Targets, targetMode)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(targets) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "targets is empty"})
		return
	}

	targetsJSON, err := json.Marshal(targets)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if taskQueue == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "task queue not initialized"})
		return
	}

	rootTaskID := fmt.Sprintf("task-%d", time.Now().UnixNano())
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = targets[0]
	}

	// 多租户隔离下钻
	tenantID := c.GetString("tenant")

	// ================================================================
	// 批次聚合入队（激进档）
	//
	// 替代原有"每目标一个SubTask"的原子拆分：
	//   1. 按 target_type 分组
	//   2. 每组按激进档批大小切片生成聚合 SubTask
	//   3. 聚合后 TotalChunks = 批次数（不再等于目标数）
	//   4. TotalTargets 记录原始目标总数用于进度展示
	// ================================================================

	batches := groupAndBatchTargets(targets, targetMode)

	var subTasks []db.SubTask
	profile := batchProfile{
		TotalTargets:  len(targets),
		TotalBatches:  len(batches),
		BatchesByType: make(map[string]int),
		BatchSize:     make(map[string]int),
	}

	for idx, batch := range batches {
		chunkJSON, _ := json.Marshal(batch.Targets)

		subTasks = append(subTasks, db.SubTask{
			ID:            fmt.Sprintf("%s-batch-%d-%s", rootTaskID, idx, batch.TargetType),
			TenantID:      tenantID,
			ProjectID:     req.ProjectID,
			RootTaskID:    rootTaskID,
			ChunkTargets:  string(chunkJSON),
			Status:        subTaskStatusDispatching,
			Config:        configJSON,
			Priority:      req.Priority,
			TimeoutSec:    req.TimeoutSec,
			MaxRetry:      3,
			AgentSelector: batch.SelectorJSON,
		})

		profile.BatchesByType[batch.TargetType]++
		if _, ok := profile.BatchSize[batch.TargetType]; !ok {
			profile.BatchSize[batch.TargetType] = batchSizeForTargetType(batch.TargetType)
		}
	}

	rootTask := db.RootTask{
		ID:               rootTaskID,
		TenantID:         tenantID,
		ProjectID:        req.ProjectID,
		Name:             name,
		Status:           "Queued",
		OriginalTargets:  string(targetsJSON),
		Config:           configJSON,
		TotalChunks:      len(subTasks),
		CompletedChunks:  0,
		TotalTargets:     len(targets),
		CompletedTargets: 0,
		Priority:         req.Priority,
		TimeoutSec:       req.TimeoutSec,
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

	// 3. Dispatch to Queue（闭环保证：失败任务保留 Dispatching，守护协程会继续补投）
	pushedByPriority, dispatchPending := dispatchSubTasks(context.Background(), taskQueue, subTasks)
	pushedCount := totalDispatchedTasks(pushedByPriority)
	broadcastDispatchedTasks(pushedByPriority)
	if dispatchPending > 0 {
		log.Printf("[CreateTask] RootTask %s has %d batches pending dispatch recovery", rootTask.ID, dispatchPending)
	}

	log.Printf("[CreateTask] RootTask %s: %d targets → %d batches (profile: %v)",
		rootTask.ID, len(targets), len(subTasks), profile.BatchesByType)

	c.JSON(http.StatusOK, gin.H{
		"status":           "task_created",
		"task_id":          rootTask.ID,
		"target_summary":   targetSummary,
		"dispatched":       pushedCount,
		"dispatch_pending": dispatchPending,
		"batch_profile":    profile,
		"batch_summary": gin.H{
			"total_targets": len(targets),
			"total_batches": len(subTasks),
		},
	})
}

// ---------------- Arsenal --------------------

func getArsenals(c *gin.Context) {
	var arsenals []db.Arsenal
	typ := db.CanonicalArsenalType(c.Param("type"))
	query := db.DB.Where("tenant_id = ? AND type IN ?", currentTenantID(c), db.ArsenalTypeAliases(typ))

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
	typ := db.CanonicalArsenalType(c.Param("type"))
	fn := c.Param("filename")
	tenantID := currentTenantID(c)

	var req struct {
		Content string `json:"content"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hash := fmt.Sprintf("%x", md5.Sum([]byte(req.Content)))

	// 查找已有记录以保存 PreviousHash/PreviousContent 和递增 Version
	var existing db.Arsenal
	var previousHash string
	var previousContent string
	var version int = 1
	approvedChanged := false
	if err := db.DB.Where("tenant_id = ? AND type = ? AND file_name = ?", tenantID, typ, fn).First(&existing).Error; err == nil {
		previousHash = existing.Hash
		previousContent = existing.Content // 保存当前内容用于回滚
		version = existing.Version + 1
		approvedChanged = strings.EqualFold(existing.State, "Approved")
	}

	arsenal := db.Arsenal{
		ID:              db.BuildTenantArsenalID(tenantID, typ, fn),
		TenantID:        tenantID,
		Type:            typ,
		FileName:        fn,
		Content:         req.Content,
		Hash:            hash,
		PreviousHash:    previousHash,
		PreviousContent: previousContent,
		Version:         version,
		State:           "Draft",
	}
	if err := db.DB.Save(&arsenal).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := db.SyncRuleCatalogFromArsenal(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	resp := gin.H{"status": "saved", "hash": hash, "state": "Draft", "version": version}
	if approvedChanged {
		resp["rule_version"] = BumpRuleVersion()
	}
	c.JSON(http.StatusOK, resp)
}

func approveArsenal(c *gin.Context) {
	typ := db.CanonicalArsenalType(c.Param("type"))
	fn := c.Param("filename")
	tenantID := currentTenantID(c)
	if err := db.DB.Model(&db.Arsenal{}).Where("tenant_id = ? AND type = ? AND file_name = ?", tenantID, typ, fn).Update("state", "Approved").Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := db.SyncRuleCatalogFromArsenal(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 触发版本号递增
	newVersion := BumpRuleVersion()
	log.Printf("[Arsenal Hub] Rules approved by Tenant %s. Rule version bumped to %s. Global Reload Triggered!", tenantID, newVersion)

	c.JSON(http.StatusOK, gin.H{"status": "approved", "rule_version": newVersion})
}

func deleteArsenal(c *gin.Context) {
	typ := db.CanonicalArsenalType(c.Param("type"))
	fn := c.Param("filename")
	tenantID := currentTenantID(c)
	var arsenal db.Arsenal
	if err := db.DB.Where("tenant_id = ? AND type = ? AND file_name = ?", tenantID, typ, fn).First(&arsenal).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Arsenal not found"})
		return
	}
	if err := db.DB.Delete(&db.Arsenal{}, "tenant_id = ? AND type = ? AND file_name = ?", tenantID, typ, fn).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := db.SyncRuleCatalogFromArsenal(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	resp := gin.H{"status": "deleted"}
	if strings.EqualFold(arsenal.State, "Approved") {
		resp["rule_version"] = BumpRuleVersion()
	}
	c.JSON(http.StatusOK, resp)
}

// ---------------- 融合画像数据源 --------------------

type Profile struct {
	Target       string              `json:"target"`
	Assets       []db.Asset          `json:"assets"`
	Fingerprints []db.FingerprintHit `json:"fingerprints"`
	Vulns        []db.Vulnerability  `json:"vulns"`
}

func getProfiles(c *gin.Context) {
	tenantID := c.GetString("tenant")
	page := 1
	pageSize := 50
	if p := c.Query("page"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 {
			page = v
		}
	}
	if ps := c.Query("page_size"); ps != "" {
		if v, err := strconv.Atoi(ps); err == nil && v > 0 && v <= 200 {
			pageSize = v
		}
	}

	// 先分页获取去重的 target 列表
	var targets []string
	query := db.DB.Model(&db.Asset{}).Select("DISTINCT target")
	if tenantID != "" {
		query = query.Where("tenant_id = ?", tenantID)
	}
	if search := c.Query("search"); search != "" {
		query = query.Where("target LIKE ?", "%"+search+"%")
	}
	query.Order("target").Offset((page-1)*pageSize).Limit(pageSize).Pluck("target", &targets)

	if len(targets) == 0 {
		c.JSON(http.StatusOK, gin.H{"data": []Profile{}, "page": page, "page_size": pageSize, "total": 0})
		return
	}

	// 批量查询这些 target 的关联数据（含租户隔离）
	var assets []db.Asset
	assocQ := db.DB.Where("target IN ?", targets)
	if tenantID != "" {
		assocQ = assocQ.Where("tenant_id = ?", tenantID)
	}
	assocQ.Find(&assets)

	var fps []db.FingerprintHit
	fpQ := db.DB.Where("target IN ?", targets)
	if tenantID != "" {
		fpQ = fpQ.Where("tenant_id = ?", tenantID)
	}
	fpQ.Find(&fps)

	var vulns []db.Vulnerability
	vulnQ := db.DB.Where("target IN ?", targets)
	if tenantID != "" {
		vulnQ = vulnQ.Where("tenant_id = ?", tenantID)
	}
	vulnQ.Find(&vulns)

	pm := make(map[string]*Profile, len(targets))
	for _, t := range targets {
		pm[t] = &Profile{Target: t}
	}
	for _, a := range assets {
		if p, ok := pm[a.Target]; ok {
			p.Assets = append(p.Assets, a)
		}
	}
	for _, f := range fps {
		if p, ok := pm[f.Target]; ok {
			p.Fingerprints = append(p.Fingerprints, f)
		}
	}
	for _, v := range vulns {
		if p, ok := pm[v.Target]; ok {
			p.Vulns = append(p.Vulns, v)
		}
	}

	results := make([]Profile, 0, len(targets))
	for _, t := range targets {
		results = append(results, *pm[t])
	}

	// 统计总数（同步 search 过滤条件）
	var total int64
	countQ := db.DB.Model(&db.Asset{}).Select("COUNT(DISTINCT target)")
	if tenantID != "" {
		countQ = countQ.Where("tenant_id = ?", tenantID)
	}
	if search := c.Query("search"); search != "" {
		countQ = countQ.Where("target LIKE ?", "%"+search+"%")
	}
	countQ.Count(&total)

	c.JSON(http.StatusOK, gin.H{"data": results, "page": page, "page_size": pageSize, "total": total})
}

func deleteTask(c *gin.Context) {
	id := c.Param("id")
	tenantID := currentTenantID(c)
	db.DB.Delete(&db.RootTask{}, "id = ? AND tenant_id = ?", id, tenantID)
	db.DB.Delete(&db.SubTask{}, "root_task_id = ? AND tenant_id = ?", id, tenantID)

	// 删除任务关联的扫描结果
	db.DB.Where("root_task_id = ? AND tenant_id = ?", id, tenantID).Delete(&db.Asset{})
	db.DB.Where("root_task_id = ? AND tenant_id = ?", id, tenantID).Delete(&db.FingerprintHit{})
	db.DB.Where("root_task_id = ? AND tenant_id = ?", id, tenantID).Delete(&db.Vulnerability{})

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
	tenantID := currentTenantID(c)
	query := db.DB.Model(&db.Vulnerability{}).Where("tenant_id = ?", tenantID)
	query.Find(&vulns)

	for _, v := range vulns {
		writer.Write([]string{v.TenantID, v.TaskID, v.Target, v.Plugin, v.Severity, v.CreatedAt.Format(time.RFC3339)})
	}
}

func cancelTask(c *gin.Context) {
	id := c.Param("id")
	tenantID := currentTenantID(c)
	cancelledWithoutClaim := int64(0)
	cancelPendingRunning := int64(0)

	if err := db.DB.Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&db.SubTask{}).
			Where("root_task_id = ? AND tenant_id = ? AND status IN ?", id, tenantID, []string{"Pending", "Recovered", subTaskStatusDispatching}).
			Updates(map[string]interface{}{
				"status":        "Cancelled",
				"agent_id":      "",
				"stream_msg_id": "",
			})
		if res.Error != nil {
			return res.Error
		}
		cancelledWithoutClaim = res.RowsAffected

		res = tx.Model(&db.SubTask{}).
			Where("root_task_id = ? AND tenant_id = ? AND status IN ?", id, tenantID, []string{"Running", "CancelPending"}).
			Update("status", "CancelPending")
		if res.Error != nil {
			return res.Error
		}
		cancelPendingRunning = res.RowsAffected
		return nil
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	db.RefreshRootTaskStatus(id)

	c.JSON(http.StatusOK, gin.H{
		"status":                   "cancellation dispatched",
		"cancelled_without_claim":  cancelledWithoutClaim,
		"cancel_pending_on_agents": cancelPendingRunning,
	})
}

// 提供给 Agent 轮询其需强制退出的指令以及规则重载指令
func getAgentCommands(c *gin.Context) {
	id := c.Param("id")
	tenantID := currentTenantID(c)
	var subTasks []db.SubTask
	// 对于该节点正在运行但被强制退出的任务
	db.DB.Where("agent_id = ? AND tenant_id = ? AND status = 'CancelPending'", id, tenantID).Find(&subTasks)

	var cancels []string
	for _, st := range subTasks {
		cancels = append(cancels, st.ID)
	}

	ruleVersion := currentRuleVersionValue()
	reloadRules := false
	var nodes []db.Node
	if err := scopedNodeQuery(tenantID).Select("rule_version").Where("agent_id = ?", id).Limit(1).Find(&nodes).Error; err == nil && len(nodes) > 0 {
		reloadRules = shouldAgentReloadRules(nodes[0].RuleVersion, ruleVersion)
	}

	c.JSON(http.StatusOK, gin.H{
		"cancel_tasks": cancels,
		"reload_rules": reloadRules,
		"rule_version": ruleVersion,
	})
}

func getVulns(c *gin.Context) {
	var vulns []db.Vulnerability
	tenantID := currentTenantID(c)
	query := db.DB.Where("tenant_id = ?", tenantID).Order("created_at desc")
	if taskID := c.Query("task_id"); taskID != "" {
		if scopedTaskIDs := resolveScopedTaskIDs(tenantID, taskID); len(scopedTaskIDs) > 1 {
			query = query.Where("task_id IN ?", scopedTaskIDs)
		} else if len(scopedTaskIDs) == 1 {
			query = query.Where("task_id = ?", scopedTaskIDs[0])
		}
	}
	query.Limit(500).Find(&vulns)
	c.JSON(http.StatusOK, vulns)
}

func getAssets(c *gin.Context) {
	var assets []db.Asset
	tenantID := currentTenantID(c)
	query := db.DB.Where("tenant_id = ?", tenantID).Order("created_at desc")
	if taskID := c.Query("task_id"); taskID != "" {
		if scopedTaskIDs := resolveScopedTaskIDs(tenantID, taskID); len(scopedTaskIDs) > 1 {
			query = query.Where("task_id IN ?", scopedTaskIDs)
		} else if len(scopedTaskIDs) == 1 {
			query = query.Where("task_id = ?", scopedTaskIDs[0])
		}
	}
	query.Limit(500).Find(&assets)
	c.JSON(http.StatusOK, assets)
}

func getFingerprints(c *gin.Context) {
	var fps []db.FingerprintHit
	tenantID := currentTenantID(c)
	query := db.DB.Where("tenant_id = ?", tenantID).Order("created_at desc")
	if taskID := c.Query("task_id"); taskID != "" {
		if scopedTaskIDs := resolveScopedTaskIDs(tenantID, taskID); len(scopedTaskIDs) > 1 {
			query = query.Where("task_id IN ?", scopedTaskIDs)
		} else if len(scopedTaskIDs) == 1 {
			query = query.Where("task_id = ?", scopedTaskIDs[0])
		}
	}
	query.Limit(500).Find(&fps)
	c.JSON(http.StatusOK, fps)
}

type NodeResponse struct {
	db.Node
	RunningTaskDetails []map[string]interface{} `json:"RunningTaskDetails"`
}

func getNodes(c *gin.Context) {
	tenantID := currentTenantID(c)
	var nodes []db.Node
	scopedNodeQuery(tenantID).Find(&nodes)

	var resp []NodeResponse
	for _, n := range nodes {
		nr := NodeResponse{
			Node:               n,
			RunningTaskDetails: make([]map[string]interface{}, 0),
		}
		if n.RunningTaskIDs != "" && n.RunningTaskIDs != "[]" {
			var ids []string
			if err := json.Unmarshal([]byte(n.RunningTaskIDs), &ids); err == nil && len(ids) > 0 {
				var subTasks []db.SubTask
				db.DB.Where("tenant_id = ? AND id IN ?", tenantID, ids).Find(&subTasks)
				for _, sub := range subTasks {
					var targets []string
					_ = json.Unmarshal([]byte(sub.ChunkTargets), &targets)
					// 生成目标预览（前5个）
					previewLimit := 5
					preview := targets
					if len(preview) > previewLimit {
						preview = preview[:previewLimit]
					}
					nr.RunningTaskDetails = append(nr.RunningTaskDetails, map[string]interface{}{
						"task_id":        sub.ID,
						"targets":        targets,
						"target_count":   len(targets),
						"target_preview": preview,
					})
				}
			}
		}
		resp = append(resp, nr)
	}

	c.JSON(http.StatusOK, resp)
}

func deleteNode(c *gin.Context) {
	agentID := c.Param("id")
	tenantID := currentTenantID(c)

	res := scopedNodeQuery(tenantID).Where("agent_id = ?", agentID).Delete(&db.Node{})
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": res.Error.Error()})
		return
	}
	if res.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Node not found or already deleted"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

func cleanOfflineNodes(c *gin.Context) {
	tenantID := currentTenantID(c)

	res := scopedNodeQuery(tenantID).Where("status = ?", "Offline").Delete(&db.Node{})
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": res.Error.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "cleaned", "count": res.RowsAffected})
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
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	req.TenantID = strings.TrimSpace(req.TenantID)
	req.Username = strings.TrimSpace(req.Username)

	// Backward compatibility: if username is empty but tenant_id is provided, use tenant_id as username
	// This supports the legacy login flow where tenant_id was used as the username
	loginUsername := req.Username
	if loginUsername == "" {
		if req.TenantID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "username or tenant_id is required"})
			return
		}
		loginUsername = req.TenantID
	}

	// 尝试从数据库校验用户
	var user db.User
	tenantClaim := req.TenantID
	if tenantClaim == "" {
		tenantClaim = "default" // default fallback if neither provided
	}
	roleClaim := "admin"
	userIDClaim := "dev:" + loginUsername
	if err := db.DB.Where("username = ?", loginUsername).First(&user).Error; err == nil {
		// 数据库有此用户，校验密码
		if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Wrong password"})
			return
		}
		tenantClaim = user.TenantID
		roleClaim = user.Role
		if roleClaim == "" {
			roleClaim = "viewer"
		}
		userIDClaim = fmt.Sprintf("%d", user.ID)
	} else if errors.Is(err, gorm.ErrRecordNotFound) {
		if !developmentMode || req.Password != "8888" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Wrong password"})
			return
		}
		// 开发模式降级：强制使用 default 租户，与 Agent 注册的默认 tenant_id 保持一致
		tenantClaim = "default"
	} else {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query user"})
		return
	}

	// 颁发 Token（包含角色信息）
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"tenant_id": tenantClaim,
		"role":      roleClaim,
		"user_id":   userIDClaim,
		"exp":       time.Now().Add(time.Hour * 72).Unix(),
	})
	tokenString, err := token.SignedString(currentJWTSecret())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to sign"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

// ==================== 规则清单 (增量同步用) ====================

func getArsenalManifest(c *gin.Context) {
	var arsenals []db.Arsenal
	tenantID := currentTenantID(c)
	db.DB.Select("type, file_name, hash, state, updated_at").
		Where("tenant_id = ? AND state = ?", tenantID, "Approved").
		Find(&arsenals)

	type ManifestItem struct {
		Type      string `json:"type"`
		FileName  string `json:"file_name"`
		Hash      string `json:"hash"`
		UpdatedAt string `json:"updated_at"`
	}

	ruleVersion := currentRuleVersionValue()

	items := make([]ManifestItem, 0, len(arsenals))
	for _, a := range arsenals {
		items = append(items, ManifestItem{
			Type:      db.CanonicalArsenalType(a.Type),
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
// (已迁移到 handler_cloud.go)

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
// 新字段 Version/Capacity/RunningTasks/RuleVersion 已通过数据库 migration runner 收敛到
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
			recoverDispatchingTasks(q)
			handleTimeoutTasks(q)
		}
	}
}

func recoverDispatchingTasks(q *scheduler.TaskQueue) {
	if q == nil {
		return
	}

	var subs []db.SubTask
	db.DB.Where("status = ?", subTaskStatusDispatching).
		Order("updated_at asc").
		Limit(200).
		Find(&subs)
	if len(subs) == 0 {
		return
	}

	pushedByPriority, dispatchPending := dispatchSubTasks(context.Background(), q, subs)
	pushedCount := totalDispatchedTasks(pushedByPriority)
	if pushedCount > 0 {
		broadcastDispatchedTasks(pushedByPriority)
	}
	if pushedCount > 0 || dispatchPending > 0 {
		log.Printf("[DispatchRecover] scanned=%d dispatched=%d pending=%d", len(subs), pushedCount, dispatchPending)
	}
}

func handleTimeoutTasks(q *scheduler.TaskQueue) {
	// 查找超时运行任务 + 长时间未收敛的取消任务
	var subs []db.SubTask
	db.DB.Where("(status = ? AND timeout_sec > 0) OR status = ?", "Running", "CancelPending").Find(&subs)

	now := time.Now()
	for _, sub := range subs {
		if db.NormalizeSubTaskStatus(sub.Status) == "CANCELPENDING" {
			cancelDeadline := sub.UpdatedAt.Add(cancelPendingSettleGrace)
			if now.Before(cancelDeadline) {
				continue
			}

			if q != nil && sub.StreamMsgID != "" {
				_ = q.AckTask(context.Background(), sub.StreamMsgID)
			}

			updateRes := db.DB.Model(&db.SubTask{}).
				Where("id = ? AND status = ?", sub.ID, "CancelPending").
				Updates(map[string]interface{}{
					"status":        "Cancelled",
					"agent_id":      "",
					"stream_msg_id": "",
				})
			if updateRes.Error != nil {
				log.Printf("[TimeoutDaemon] Failed to settle CancelPending subtask %s: %v", sub.ID, updateRes.Error)
				continue
			}
			if updateRes.RowsAffected == 0 {
				continue
			}

			log.Printf("[TimeoutDaemon] SubTask %s force-settled to Cancelled after %s grace", sub.ID, cancelPendingSettleGrace)
			if sub.AgentID != "" {
				db.DB.Exec("UPDATE nodes SET running_tasks = GREATEST(running_tasks - 1, 0) WHERE agent_id = ?", sub.AgentID)
			}
			if sub.RootTaskID != "" {
				db.RefreshRootTaskStatus(sub.RootTaskID)
			}
			continue
		}

		deadline := sub.UpdatedAt.Add(time.Duration(sub.TimeoutSec) * time.Second)
		if now.Before(deadline) {
			continue
		}

		log.Printf("[TimeoutDaemon] SubTask %s timed out (timeout=%ds)", sub.ID, sub.TimeoutSec)
		if sub.RetryCount < sub.MaxRetry {
			recoveredByNack := false
			if q != nil && sub.StreamMsgID != "" {
				if err := q.NackTask(context.Background(), sub.StreamMsgID); err != nil {
					log.Printf("[TimeoutDaemon] Nack failed for subtask %s: %v", sub.ID, err)
				} else {
					recoveredByNack = true
				}
			}

			nextStatus := subTaskStatusDispatching
			if recoveredByNack {
				nextStatus = "Pending"
			}

			updateRes := db.DB.Model(&sub).Where("status = ?", "Running").Updates(map[string]interface{}{
				"status":        nextStatus,
				"retry_count":   sub.RetryCount + 1,
				"agent_id":      "",
				"stream_msg_id": "",
			})
			if updateRes.Error != nil {
				log.Printf("[TimeoutDaemon] Failed to recover timed-out subtask %s: %v", sub.ID, updateRes.Error)
				continue
			}
			if updateRes.RowsAffected == 0 {
				continue
			}

			// 对无法通过 Nack 回收的任务立即尝试补投，失败则交由 dispatch 守护继续处理。
			if !recoveredByNack && q != nil {
				_, dispatchPending := dispatchSubTasks(context.Background(), q, []db.SubTask{sub})
				if dispatchPending == 0 {
					broadcastDispatchedTasks(map[int]int{sub.Priority: 1})
				}
			}

			log.Printf("[TimeoutDaemon] SubTask %s recovered (retry %d/%d)", sub.ID, sub.RetryCount+1, sub.MaxRetry)
		} else {
			// 超过重试次数：先尝试拆批（多目标批次的最后机会）
			if q != nil && sub.StreamMsgID != "" {
				_ = q.AckTask(context.Background(), sub.StreamMsgID)
			}

			// 尝试二分拆分重试（绕过 retry_count 上限检查，直接看目标数）
			var targets []string
			_ = json.Unmarshal([]byte(sub.ChunkTargets), &targets)
			if len(targets) > 1 {
				// 重置重试次数以允许拆分（拆分后的子批次用新的预算）
				sub.RetryCount = 0
				splitSubs, didSplit := db.SplitFailedSubTask(&sub)
				if didSplit && q != nil {
					_, dispatchPending := dispatchSubTasks(context.Background(), q, splitSubs)
					if dispatchPending == 0 {
						broadcastDispatchedTasks(map[int]int{sub.Priority: 1})
					}
					log.Printf("[TimeoutDaemon] SubTask %s split into %d sub-batches (last-resort)", sub.ID, len(splitSubs))
					if sub.AgentID != "" {
						db.DB.Exec("UPDATE nodes SET running_tasks = GREATEST(running_tasks - 1, 0) WHERE agent_id = ?", sub.AgentID)
					}
					continue
				}
			}

			updateRes := db.DB.Model(&sub).Where("status = ?", "Running").Updates(map[string]interface{}{
				"status":        "Timeout",
				"agent_id":      "",
				"stream_msg_id": "",
			})
			if updateRes.Error != nil {
				log.Printf("[TimeoutDaemon] Failed to mark subtask %s as Timeout: %v", sub.ID, updateRes.Error)
				continue
			}
			if updateRes.RowsAffected == 0 {
				continue
			}

			log.Printf("[TimeoutDaemon] SubTask %s marked as Timeout (max retries exceeded)", sub.ID)
			if sub.RootTaskID != "" {
				db.RefreshRootTaskStatus(sub.RootTaskID)
			}
		}

		// 递减关联节点 running_tasks
		if sub.AgentID != "" {
			db.DB.Exec("UPDATE nodes SET running_tasks = GREATEST(running_tasks - 1, 0) WHERE agent_id = ?", sub.AgentID)
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

// ==================== 数据增强 API ====================

func getVulnTrends(c *gin.Context) {
	tenantID := currentTenantID(c)
	days := 30
	if d := c.Query("days"); d != "" {
		if v, err := strconv.Atoi(d); err == nil && v > 0 {
			days = v
		}
	}
	c.JSON(http.StatusOK, db.GetVulnTrends(tenantID, days))
}

func getSeverityDistribution(c *gin.Context) {
	c.JSON(http.StatusOK, db.GetSeverityDistribution(currentTenantID(c)))
}

func getTaskResultStats(c *gin.Context) {
	tenantID := currentTenantID(c)
	limit := 20
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 {
			limit = v
		}
	}
	c.JSON(http.StatusOK, db.GetTaskResultStats(tenantID, limit))
}

func getRecentHighVulns(c *gin.Context) {
	tenantID := currentTenantID(c)
	limit := 10
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 {
			limit = v
		}
	}
	c.JSON(http.StatusOK, db.GetRecentHighVulns(tenantID, limit))
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
	typ := db.CanonicalArsenalType(c.Param("type"))
	fn := c.Param("filename")
	tenantID := currentTenantID(c)

	var arsenal db.Arsenal
	if err := db.DB.Where("tenant_id = ? AND type = ? AND file_name = ?", tenantID, typ, fn).First(&arsenal).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Arsenal not found"})
		return
	}

	if arsenal.PreviousHash == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No previous version available for rollback"})
		return
	}

	// 交换当前版本和上一版本（含 Content 内容回滚）
	if err := db.DB.Model(&arsenal).Updates(map[string]interface{}{
		"content":          arsenal.PreviousContent,
		"previous_content": arsenal.Content,
		"hash":             arsenal.PreviousHash,
		"previous_hash":    arsenal.Hash,
		"state":            "Draft", // 回滚后重新审批
		"version":          arsenal.Version + 1,
	}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := db.SyncRuleCatalogFromArsenal(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 触发全网 Agent 重新拉取
	newVersion := BumpRuleVersion()
	log.Printf("[Arsenal Hub] Rule %s/%s rolled back. Rule version: %s", typ, fn, newVersion)

	c.JSON(http.StatusOK, gin.H{"status": "rolled_back", "rule_version": newVersion})
}

// ==================== 动态追加目标 ====================

// appendTargets 向运行中的任务动态追加目标
// POST /tasks/:id/append  body: { "targets": "1.1.1.1\n2.2.2.2" }
func appendTargets(c *gin.Context) {
	rootTaskID := c.Param("id")

	var req struct {
		Targets json.RawMessage `json:"targets"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 校验 RootTask 存在（含租户隔离）
	var rootTask db.RootTask
	if err := db.DB.Where("id = ? AND tenant_id = ?", rootTaskID, currentTenantID(c)).First(&rootTask).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
		return
	}

	// 解析新目标
	targetMode := detectTargetModeFromStoredConfig(rootTask.Config)
	newTargets, targetSummary, err := parseAndValidateTargetsForMode(req.Targets, targetMode)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(newTargets) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No targets to append"})
		return
	}
	if taskQueue == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "task queue not initialized"})
		return
	}

	tenantID := c.GetString("tenant")

	// 获取当前已有子任务数量作为新批次的起始编号
	var existingCount int64
	db.DB.Model(&db.SubTask{}).Where("root_task_id = ?", rootTaskID).Count(&existingCount)
	baseIndex := int(existingCount)

	// 聚合切批生成 SubTasks
	batches := groupAndBatchTargets(newTargets, targetMode)
	configJSON := rootTask.Config

	var newSubTasks []db.SubTask
	profile := batchProfile{
		TotalTargets:  len(newTargets),
		TotalBatches:  len(batches),
		BatchesByType: make(map[string]int),
		BatchSize:     make(map[string]int),
	}

	for idx, batch := range batches {
		chunkJSON, _ := json.Marshal(batch.Targets)
		newSubTasks = append(newSubTasks, db.SubTask{
			ID:            fmt.Sprintf("%s-batch-%d-%s", rootTaskID, baseIndex+idx, batch.TargetType),
			TenantID:      tenantID,
			ProjectID:     rootTask.ProjectID,
			RootTaskID:    rootTaskID,
			ChunkTargets:  string(chunkJSON),
			Status:        subTaskStatusDispatching,
			Config:        configJSON,
			Priority:      rootTask.Priority,
			TimeoutSec:    rootTask.TimeoutSec,
			MaxRetry:      3,
			AgentSelector: batch.SelectorJSON,
		})
		profile.BatchesByType[batch.TargetType]++
		if _, ok := profile.BatchSize[batch.TargetType]; !ok {
			profile.BatchSize[batch.TargetType] = batchSizeForTargetType(batch.TargetType)
		}
	}

	// 事务写入新 SubTasks
	err = db.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.CreateInBatches(newSubTasks, 100).Error; err != nil {
			return err
		}
		// 更新 RootTask 的 TotalChunks/TotalTargets 和状态
		return tx.Model(&rootTask).Updates(map[string]interface{}{
			"total_chunks":  gorm.Expr("total_chunks + ?", len(newSubTasks)),
			"total_targets": gorm.Expr("total_targets + ?", len(newTargets)),
			"status":        "Running", // 如果之前是 FINISHED/PartialDone，重新激活
		}).Error
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 推入调度队列（失败保留 Dispatching，守护协程继续补投）
	pushedByPriority, dispatchPending := dispatchSubTasks(context.Background(), taskQueue, newSubTasks)
	pushedCount := totalDispatchedTasks(pushedByPriority)
	broadcastDispatchedTasks(pushedByPriority)
	if dispatchPending > 0 {
		log.Printf("[AppendTargets] RootTask %s has %d batches pending dispatch recovery", rootTaskID, dispatchPending)
	}

	log.Printf("[AppendTargets] RootTask %s: appended %d targets → %d batches", rootTaskID, len(newTargets), len(newSubTasks))

	c.JSON(http.StatusOK, gin.H{
		"status":           "appended",
		"new_subtasks":     len(newSubTasks),
		"new_targets":      len(newTargets),
		"total_chunks":     rootTask.TotalChunks + len(newSubTasks),
		"target_summary":   targetSummary,
		"dispatched":       pushedCount,
		"dispatch_pending": dispatchPending,
		"batch_profile":    profile,
		"batch_summary": gin.H{
			"total_targets": len(newTargets),
			"total_batches": len(newSubTasks),
		},
	})
}

// ==================== 队列深度监控 ====================

func getQueueDepth(c *gin.Context) {
	if taskQueue == nil {
		c.JSON(http.StatusOK, gin.H{"error": "queue not initialized"})
		return
	}

	ctx := context.Background()
	depth := taskQueue.QueueDepth(ctx)
	pending := taskQueue.PendingCount(ctx)

	// 计算批次维度总量
	readyBatches := int64(0)
	pendingBatches := int64(0)
	for _, v := range depth {
		readyBatches += v
	}
	for _, v := range pending {
		pendingBatches += v
	}

	// 从 DB 统计目标维度（按 SubTask 状态聚合 ChunkTargets 中的目标数量）
	var readyTargets, pendingTargets int64
	type targetCountResult struct {
		Status string
		Cnt    int64
	}
	var results []targetCountResult
	db.DB.Raw(`
		SELECT status, SUM(jsonb_array_length(chunk_targets::jsonb)) as cnt
		FROM sub_tasks
		WHERE status IN ('Pending', 'Dispatching', 'Running', 'Recovered')
		GROUP BY status
	`).Scan(&results)
	for _, r := range results {
		switch db.NormalizeSubTaskStatus(r.Status) {
		case "PENDING", "DISPATCHING", "RECOVERED":
			readyTargets += r.Cnt
		case "RUNNING":
			pendingTargets += r.Cnt
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"depth":           depth,
		"pending":         pending,
		"mode":            taskQueue.Mode(),
		"ready_batches":   readyBatches,
		"pending_batches": pendingBatches,
		"ready_targets":   readyTargets,
		"pending_targets": pendingTargets,
	})
}
