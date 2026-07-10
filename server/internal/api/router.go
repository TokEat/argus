package api

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/subtle"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/user/dddd-server/internal/db"
	grpcpkg "github.com/user/dddd-server/internal/grpc"
	"github.com/user/dddd-server/internal/scheduler"
	"github.com/user/dddd-server/internal/storage"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var taskQueue *scheduler.TaskQueue
var notifyHub *grpcpkg.NotifyHub
var agentPSK string
var buildMu sync.Mutex
var buildCancelMu sync.Mutex
var buildCancels = map[uint]context.CancelFunc{}
var buildJobRunner = runBuildJob
var errBuildAlreadyQueued = errors.New("another build job is already queued or running")
var objectStorageRoot = "./data/objects"

const (
	subTaskStatusDispatching = "Dispatching"
	subTaskQueuedMarker      = "queued"
	strandedPendingGrace     = 60 * time.Second
	cancelPendingSettleGrace = 45 * time.Second
	agentLogRetentionKey     = "agent_logs_retention_days"
	defaultAgentLogRetention = 14
	agentSessionTTL          = 7 * 24 * time.Hour
)

func SetTaskQueue(queue *scheduler.TaskQueue) {
	taskQueue = queue
}

// SetAgentPSK 注入 Agent 预共享密钥，用于 Agent 内部 API 鉴权。
func SetAgentPSK(psk string) {
	agentPSK = strings.TrimSpace(psk)
}

func isAgentInternalEndpoint(c *gin.Context) bool {
	if c.Request.Method != http.MethodGet {
		return false
	}
	path := c.Request.URL.Path
	if strings.HasPrefix(path, "/api/v1/agents/") && strings.HasSuffix(path, "/commands") {
		return true
	}
	if path == "/api/v1/agents/config/api-keys" {
		return true
	}
	if path == "/api/v1/arsenals/manifest" {
		return true
	}
	// Agent 整体 DB 同步端点
	if path == "/api/v1/arsenals/db" || path == "/api/v1/arsenals/db/hash" || path == "/api/v1/arsenals/db/stats" {
		return true
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

func hasBearerAuth(c *gin.Context) bool {
	authHeader := c.GetHeader("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return true
	}
	return strings.TrimSpace(c.Query("token")) != ""
}

func validateAgentSession(c *gin.Context) bool {
	agentID := strings.TrimSpace(c.GetHeader("x-agent-id"))
	token := strings.TrimSpace(c.GetHeader("x-agent-token"))
	if agentID == "" || token == "" {
		return false
	}
	if strings.HasPrefix(c.Request.URL.Path, "/api/v1/agents/") && strings.HasSuffix(c.Request.URL.Path, "/commands") {
		pathAgentID := strings.TrimPrefix(c.Request.URL.Path, "/api/v1/agents/")
		pathAgentID = strings.TrimSuffix(pathAgentID, "/commands")
		if pathAgentID != agentID {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "agent id mismatch"})
			return false
		}
	}

	var node db.Node
	if err := db.DB.Select("agent_id", "tenant_id", "token", "status", "token_expires_at", "token_revoked_at").Where("agent_id = ?", agentID).First(&node).Error; err != nil {
		return false
	}
	if node.Status != "Alive" {
		return false
	}
	if node.TokenRevokedAt != nil || (node.TokenExpiresAt != nil && time.Now().After(*node.TokenExpiresAt)) {
		return false
	}
	if strings.TrimSpace(node.Token) == "" || subtle.ConstantTimeCompare([]byte(token), []byte(node.Token)) != 1 {
		return false
	}
	tenantID := strings.TrimSpace(node.TenantID)
	if tenantID == "" {
		tenantID = "default"
	}
	c.Set("tenant", tenantID)
	c.Set("role", "admin")
	c.Set("agent_id", agentID)
	c.Set("agent_internal", true)
	return true
}

// SetNotifyHub 注入 gRPC NotifyHub 引用，用于 createTask 后广播通知 Agent
func SetNotifyHub(hub *grpcpkg.NotifyHub) {
	notifyHub = hub
	db.DebugEventHook = handleAgentDebugEvent
	db.ExploitCleanupDispatchHook = func(run db.ExploitRun) error {
		return dispatchExploitCleanup(run, run.TenantID)
	}
}

func currentTenantID(c *gin.Context) string {
	return normalizeTenantID(c.GetString("tenant"))
}

func normalizeTenantID(tenantID string) string {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return "default"
	}
	return tenantID
}

func normalizeUserRole(role string) (string, bool) {
	role = strings.TrimSpace(role)
	if role == "" {
		return "viewer", true
	}
	if _, ok := roleHierarchy[role]; !ok {
		return "", false
	}
	return role, true
}

func normalizeUserRoleForTenant(tenantID, role string) (string, bool) {
	role = strings.TrimSpace(role)
	if role == "" {
		return "viewer", true
	}
	if _, ok := roleHierarchy[role]; ok {
		return role, true
	}
	if db.DB == nil {
		return "", false
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		tenantID = "default"
	}
	var count int64
	db.DB.Model(&db.CustomRole{}).Where("tenant_id = ? AND name = ?", tenantID, role).Count(&count)
	return role, count > 0
}

func normalizeUserStatus(status string) (string, bool) {
	status = strings.TrimSpace(status)
	if status == "" {
		return "", true
	}
	switch status {
	case "active", "disabled":
		return status, true
	default:
		return "", false
	}
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

func currentAPIConfigHashValue(tenantID string) string {
	arsenal, err := db.FindTenantArsenalByTypeAndFile(normalizeTenantID(tenantID), "apiconfig", "api-config.yaml")
	if err != nil || strings.TrimSpace(arsenal.Content) == "" {
		return ""
	}
	if hash := strings.TrimSpace(arsenal.Hash); hash != "" {
		return hash
	}
	return fmt.Sprintf("%x", md5.Sum([]byte(arsenal.Content)))
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

		// Agent 内部 API：Agent 使用 Register 返回的 session token；普通用户仍可用 JWT 访问。
		if isAgentInternalEndpoint(c) && !hasBearerAuth(c) {
			if !validateAgentSession(c) {
				if c.IsAborted() {
					return
				}
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or missing agent session token"})
				return
			}
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
			if expAuthorized, ok := claims["exp_authorized"].(bool); ok {
				c.Set("exp_authorized", expAuthorized)
			} else {
				c.Set("exp_authorized", false)
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

func validateUTF8TextBodyMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !shouldValidateUTF8Body(c.Request.Method, c.GetHeader("Content-Type")) || c.Request.Body == nil {
			c.Next()
			return
		}
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "failed to read request body"})
			return
		}
		if !utf8.Valid(body) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "request body contains invalid UTF-8, please use UTF-8 encoding",
			})
			return
		}
		c.Request.Body = io.NopCloser(bytes.NewReader(body))
		c.Next()
	}
}

func shouldValidateUTF8Body(method string, contentType string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
	default:
		return false
	}
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	return mediaType == "application/json" ||
		strings.HasSuffix(mediaType, "+json") ||
		strings.HasPrefix(mediaType, "text/") ||
		mediaType == "application/x-www-form-urlencoded"
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
	r.Use(validateUTF8TextBodyMiddleware())
	r.Use(gzipMiddleware())

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
		api.PUT("/projects/:id", updateProject)
		api.DELETE("/projects/:id", deleteProject)
		api.GET("/projects/:id/stats", getProjectStats)
		api.GET("/projects/:id/members", getProjectMembers)
		api.PUT("/projects/:id/members", updateProjectMembers)

		// 任务 CRUD
		api.GET("/tasks", getTasks)
		api.GET("/tasks/:id", getTaskDetail)
		api.POST("/tasks/preview-selector", previewTaskSelector)
		api.POST("/tasks", createTask)
		api.DELETE("/tasks/:id", deleteTask)
		api.POST("/tasks/:id/cancel", cancelTask)
		api.POST("/tasks/:id/pause", pauseTask)
		api.POST("/tasks/:id/resume", resumeTask)
		api.POST("/tasks/:id/append", appendTargets) // 动态追加目标

		// 队列监控
		api.GET("/queue/depth", getQueueDepth)

		// 漏洞资产与关联画像
		api.GET("/vulns", getVulns)
		api.GET("/assets", getAssets)
		api.GET("/fingerprints", getFingerprints)
		api.GET("/profiles", getProfiles)
		api.GET("/poc-rules", listPocRules)
		api.GET("/exploits", listExploitRules)
		api.GET("/exploits/audits", listExploitAudits)
		api.POST("/exploits/source/validate", validateSourceExploit)
		api.POST("/exploits/source/dry-run", dryRunSourceExploit)
		api.POST("/exploits/source/debug", debugSourceExploit)
		api.POST("/exploits/batch/approve", batchApproveExploitRules)
		api.POST("/exploits/batch/deprecate", batchDeprecateExploitRules)
		api.GET("/exploits/:id/risk-waiver", getExploitRiskWaiver)
		api.POST("/exploits/:id/risk-waiver", upsertExploitRiskWaiver)
		api.PUT("/exploits/:id/risk-waiver", upsertExploitRiskWaiver)
		api.DELETE("/exploits/:id/risk-waiver", deleteExploitRiskWaiver)
		api.POST("/exploits/:id/approve", approveExploitRule)
		api.POST("/exploits/:id/deprecate", deprecateExploitRule)
		api.POST("/exploits/:id/dry-run", dryRunExploit)
		api.POST("/exploits/:id/debug", debugExploit)
		api.DELETE("/exploits/:id", deleteExploitRule)
		api.GET("/vulns/:id/exploit-candidates", getExploitCandidatesForVuln)
		api.GET("/assets/:id/exploit-candidates", getExploitCandidatesForAsset)

		// EXP 执行管理
		api.POST("/exploit-runs", createExploitRun)
		api.GET("/exploit-runs", listExploitRuns)
		api.GET("/exploit-runs/:id", getExploitRun)
		api.POST("/exploit-runs/:id/cancel", cancelExploitRun)
		api.POST("/exploit-runs/:id/cleanup", cleanupExploitRun)
		api.GET("/exploit-artifacts/:id", getExploitArtifact)

		// 战报输出引擎
		api.GET("/reports/export/vulns", exportVulns)
		api.GET("/reports/export/assets", exportAssets)
		api.GET("/reports/export/fingerprints", exportFingerprints)

		// Agent 节点
		api.GET("/nodes", getNodes)
		api.DELETE("/nodes/:id", deleteNode)
		api.POST("/nodes/:id/revoke-token", revokeNodeToken)
		api.POST("/nodes/clean", cleanOfflineNodes)
		api.GET("/agents/:id/commands", getAgentCommands)
		api.GET("/agents/:id/pyenv", getAgentPyenv)
		api.POST("/agents/:id/pyenv/install", installAgentPyenvRequirements)
		api.GET("/agents/:id/pyenv/jobs/:job_id", getAgentPyenvJob)

		// MCP support APIs for Codex/agent rule authoring loops.
		api.GET("/mcp/resources/argus-mcp/quickstart", mcpArgusMCPQuickstart)
		api.GET("/mcp/resources/argus-mcp/tool-guide", mcpArgusMCPToolGuide)
		api.GET("/mcp/resources/fingerprint/spec", mcpFingerprintSpec)
		api.GET("/mcp/resources/fingerprint/template", mcpFingerprintTemplate)
		api.GET("/mcp/resources/poc/spec", mcpPOCSpec)
		api.GET("/mcp/resources/pyexp/spec", mcpPyexpSpec)
		api.GET("/mcp/resources/pyexp/template", mcpPyexpTemplate)
		api.GET("/mcp/resources/poc/template", mcpPOCTemplate)
		api.GET("/mcp/resources/workflow/spec", mcpWorkflowSpec)
		api.GET("/mcp/resources/workflow/template", mcpWorkflowTemplate)
		api.GET("/mcp/resources/examples/fingerprint-poc-workflow", mcpFullChainExample)
		api.POST("/mcp/tools/poc/debug", mcpPOCDebug)
		api.POST("/mcp/tools/poc/save-draft", mcpPOCSaveDraft)
		api.POST("/mcp/tools/agent/python-run", mcpAgentPythonRun)
		api.POST("/mcp/tools/rule/context", mcpRuleContext)
		api.POST("/mcp/tools/rule/debug", mcpRuleDebug)
		api.POST("/mcp/tools/rule/save", mcpRuleSave)
		api.POST("/mcp/tools/rule/apply", mcpRuleApply)

		// Server-side AI analysis and configuration
		api.GET("/ai/config", getAIConfig)
		api.PUT("/ai/config", saveAIConfig)
		api.GET("/ai/models", listAIModels)
		api.POST("/ai/test", testAIConnection)
		api.POST("/ai/arsenal/analyze", analyzeArsenalWithAI)
		api.POST("/ai/arsenal/analyze/stream", analyzeArsenalStream)
		api.POST("/ai/chat", globalAIChat)
		api.POST("/ai/actions/confirm", confirmCopilotAction)
		api.GET("/ai/copilot/prompts", getCopilotPromptProfiles)
		api.GET("/ai/tool-invocations", listAIToolInvocations)

		// Arsenal 弹药库热发车网关与审核墙
		api.POST("/arsenals/ai/analyze", aiAnalyzeArsenal)
		api.POST("/arsenals/:type", debugPocGateway)
		api.GET("/arsenals/:type", getArsenals)
		api.GET("/arsenals/:type/:filename", getArsenal)
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

		// Arsenal 安装/迁移 DB 导出（admin 用）
		api.GET("/arsenals/seed-db", exportArsenalSeedDB)

		// Arsenal DB 整体同步（Agent 用）
		api.GET("/arsenals/db", getArsenalDB)
		api.GET("/arsenals/db/hash", getArsenalDBHash)
		api.GET("/arsenals/db/stats", getArsenalDBStats)

		// API 密钥集中管理
		api.GET("/config/api-keys", getApiKeysConfig)
		api.PUT("/config/api-keys", saveApiKeysConfig)
		api.GET("/agents/config/api-keys", getAgentAPIConfig)

		// 用户管理 CRUD
		api.GET("/users", listUsers)
		api.POST("/users", createUser)
		api.PUT("/users/:id", updateUser)
		api.DELETE("/users/:id", deleteUser)

		// 角色与权限矩阵
		api.GET("/roles", listRoles)
		api.POST("/roles", createRole)
		api.PUT("/roles/:name", updateRole)
		api.DELETE("/roles/:name", deleteRole)
		api.GET("/tenants/:id/quotas", getTenantQuota)
		api.PUT("/tenants/:id/quotas", updateTenantQuota)

		// ====== 云资源编排 ======
		// 云账号凭证管理
		api.GET("/cloud/accounts", listCloudAccounts)
		api.POST("/cloud/accounts", createCloudAccount)
		api.PUT("/cloud/accounts/:id", updateCloudAccount)
		api.DELETE("/cloud/accounts/:id", deleteCloudAccount)
		api.POST("/cloud/accounts/:id/test", testCloudAccount)
		api.GET("/cloud/accounts/:id/bindings", getCloudAccountBindings)
		api.PUT("/cloud/accounts/:id/bindings", updateCloudAccountBindings)
		api.POST("/cloud/accounts/:id/oss/upload", uploadAgentToOSS)
		api.POST("/cloud/accounts/:id/oss/upload-local", uploadLocalAgentToOSS)
		api.POST("/cloud/accounts/:id/oss/test", testOSSConnection)
		api.GET("/cloud/accounts/:id/oss/files", listOSSFiles)
		api.POST("/cloud/accounts/:id/oss/delete", deleteOSSFile)
		api.GET("/cloud/accounts/:id/release-files", listReleaseFiles)
		api.GET("/cloud/accounts/:id/regions", listCloudRegions)
		api.GET("/cloud/accounts/:id/discover", discoverCloudResources)
		api.POST("/cloud/accounts/:id/auto-configure", autoConfigureCloudAccount)
		api.POST("/cloud/accounts/:id/one-click-setup", oneClickSetup)
		api.GET("/cloud/accounts/:id/permissions", checkCloudPermissions)
		api.GET("/cloud/accounts/:id/price", queryCloudPrice)
		api.GET("/cloud/accounts/:id/instance-types", listAvailableInstanceTypes)
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
		api.POST("/cloud/instances/:id/reboot", rebootCloudInstance)
		api.POST("/cloud/instances/cleanup", cleanupCloudInstances)
		// 云仪表盘
		api.GET("/cloud/dashboard", cloudDashboard)

		// 客户端构建
		api.GET("/build/artifacts", listBuildArtifacts)
		api.GET("/build/jobs", listBuildJobs)
		api.GET("/build/jobs/:id", getBuildJob)
		api.GET("/build/jobs/:id/logs", getBuildJobLogs)
		api.POST("/build/jobs/:id/cancel", cancelBuildJob)
		api.POST("/build/jobs/:id/retry", retryBuildJob)
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
		api.GET("/agent-logs/summary", getAgentLogSummary)
		api.GET("/agent-logs/retention", getAgentLogRetention)
		api.PUT("/agent-logs/retention", updateAgentLogRetention)
		api.GET("/agent-logs/alerts", listAgentLogAlertEvents)
		api.GET("/agent-logs/alert-rules", listAgentLogAlertRules)
		api.POST("/agent-logs/alert-rules", createAgentLogAlertRule)
		api.DELETE("/agent-logs/alert-rules/:id", deleteAgentLogAlertRule)
		api.POST("/agent-logs/archive", archiveAgentLogs)
		api.GET("/agents/:id/logs", getAgentLogs)

		// 规则回滚
		api.POST("/arsenals/:type/:filename/rollback", rollbackArsenal)
	}

	// SPA 控制塔前台映射兜底
	r.Static("/assets", "./server-ui/dist/assets")
	r.Static("/release", "./release") // Agent 二进制分发（OSS fallback）
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

	taskQ := db.DB.Model(&db.RootTask{}).Where("tenant_id = ?", tenantID)
	taskQ, _ = applyProjectScope(c, taskQ, "project_id")
	taskQ.Count(&taskCount)

	scopedNodeQuery(tenantID).Model(&db.Node{}).Count(&nodeCount)

	assetQ := db.DB.Model(&db.Asset{}).Where("tenant_id = ?", tenantID)
	assetQ, _ = applyProjectScope(c, assetQ, "project_id")
	assetQ.Count(&assetCount)

	fpQ := db.DB.Model(&db.FingerprintHit{}).Where("tenant_id = ?", tenantID)
	fpQ, _ = applyProjectScope(c, fpQ, "project_id")
	fpQ.Count(&fpCount)

	vulnQ := db.DB.Model(&db.Vulnerability{}).Where("tenant_id = ?", tenantID)
	vulnQ, _ = applyProjectScope(c, vulnQ, "project_id")
	vulnQ.Count(&vulnCount)

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
	scopedProjectsQuery(c).Order("created_at desc").Find(&projects)
	c.JSON(http.StatusOK, buildProjectResponses(c, projects))
}

func createProject(c *gin.Context) {
	var req struct {
		Name          string   `json:"name" binding:"required"`
		Description   string   `json:"description"`
		MemberUserIDs []string `json:"member_user_ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tenantID := c.GetString("tenant")
	ownerUserID := currentUserID(c)
	project := db.Project{
		ID:            fmt.Sprintf("proj-%d", time.Now().UnixNano()),
		TenantID:      tenantID,
		OwnerUserID:   ownerUserID,
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

	memberUserIDs := []string{}
	if currentUserIsAdmin(c) && len(req.MemberUserIDs) > 0 {
		var err error
		memberUserIDs, err = validateAssignableProjectUsers(tenantID, req.MemberUserIDs)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "member_user_ids must be active users in current tenant"})
			return
		}
	}

	if err := db.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&project).Error; err != nil {
			return err
		}
		if err := upsertProjectMember(tx, tenantID, project.ID, ownerUserID, "owner"); err != nil {
			return err
		}
		for _, userID := range memberUserIDs {
			if err := upsertProjectMember(tx, tenantID, project.ID, userID, "operator"); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, buildProjectResponses(c, []db.Project{project})[0])
}

func updateProject(c *gin.Context) {
	projectID := c.Param("id")

	var req struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
		Status      *string `json:"status"` // active, archived
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	project, ok := requireProjectManage(c, projectID)
	if !ok {
		return
	}

	updates := map[string]interface{}{}
	if req.Name != nil {
		updates["name"] = *req.Name
	}
	if req.Description != nil {
		updates["description"] = *req.Description
	}
	if req.Status != nil {
		allowed := map[string]bool{"active": true, "archived": true}
		if !allowed[*req.Status] {
			c.JSON(http.StatusBadRequest, gin.H{"error": "status must be 'active' or 'archived'"})
			return
		}
		updates["status"] = *req.Status
	}

	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no fields to update"})
		return
	}

	db.DB.Model(&project).Updates(updates)
	scopedProjectsQuery(c).Where("id = ?", projectID).First(&project)
	c.JSON(http.StatusOK, buildProjectResponses(c, []db.Project{project})[0])
}

func deleteProject(c *gin.Context) {
	projectID := c.Param("id")

	project, ok := requireProjectManage(c, projectID)
	if !ok {
		return
	}

	// 软删除（GORM DeletedAt）
	db.DB.Delete(&project)

	c.JSON(http.StatusOK, gin.H{"status": "deleted", "message": "项目已软删除，可通过数据库恢复"})
}

func getProjectStats(c *gin.Context) {
	projectID := c.Param("id")
	tenantID := c.GetString("tenant")

	project, ok := requireProjectAccess(c, projectID)
	if !ok {
		return
	}

	var taskCount, assetCount, fpCount, vulnCount int64
	db.DB.Model(&db.RootTask{}).Where("project_id = ? AND tenant_id = ?", projectID, tenantID).Count(&taskCount)
	db.DB.Model(&db.Asset{}).Where("project_id = ?", projectID).Count(&assetCount)
	db.DB.Model(&db.FingerprintHit{}).Where("project_id = ?", projectID).Count(&fpCount)
	db.DB.Model(&db.Vulnerability{}).Where("project_id = ?", projectID).Count(&vulnCount)

	c.JSON(http.StatusOK, gin.H{
		"project_id":   projectID,
		"project_name": project.Name,
		"tasks":        taskCount,
		"assets":       assetCount,
		"fingerprints": fpCount,
		"vulns":        vulnCount,
	})
}

type projectResponse struct {
	db.Project
	OwnerUsername string                 `json:"owner_username"`
	AccessLevel   string                 `json:"access_level"`
	MemberUserIDs []string               `json:"member_user_ids,omitempty"`
	Members       []projectMemberPayload `json:"members,omitempty"`
}

type projectMemberPayload struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

func buildProjectResponses(c *gin.Context, projects []db.Project) []projectResponse {
	resp := make([]projectResponse, 0, len(projects))
	if len(projects) == 0 {
		return resp
	}

	ownerIDs := make([]string, 0, len(projects))
	ownerSeen := map[string]struct{}{}
	projectIDs := make([]string, 0, len(projects))
	for _, p := range projects {
		projectIDs = append(projectIDs, p.ID)
		if p.OwnerUserID != "" {
			if _, ok := ownerSeen[p.OwnerUserID]; !ok {
				ownerSeen[p.OwnerUserID] = struct{}{}
				ownerIDs = append(ownerIDs, p.OwnerUserID)
			}
		}
	}

	ownerNames := map[string]string{}
	if len(ownerIDs) > 0 {
		var users []db.User
		db.DB.Select("id", "username").Where("tenant_id = ? AND id IN ?", currentTenantID(c), ownerIDs).Find(&users)
		for _, u := range users {
			ownerNames[strconv.FormatUint(uint64(u.ID), 10)] = u.Username
		}
	}

	memberMap := map[string][]string{}
	memberDetailMap := map[string][]projectMemberPayload{}
	if currentUserIsAdmin(c) {
		var members []db.ProjectMember
		db.DB.Where("tenant_id = ? AND project_id IN ?", currentTenantID(c), projectIDs).Find(&members)
		for _, m := range members {
			if m.Role != "owner" {
				memberMap[m.ProjectID] = append(memberMap[m.ProjectID], m.UserID)
			}
			memberDetailMap[m.ProjectID] = append(memberDetailMap[m.ProjectID], projectMemberPayload{UserID: m.UserID, Role: fallbackProjectMemberRole(m.Role)})
		}
	}

	userID := currentUserID(c)
	for _, p := range projects {
		accessLevel := "member"
		if currentUserIsAdmin(c) {
			accessLevel = "admin"
		} else if p.OwnerUserID == userID {
			accessLevel = "owner"
		} else if role := projectMemberRole(c, p.ID); role != "" {
			accessLevel = role
		}
		resp = append(resp, projectResponse{
			Project:       p,
			OwnerUsername: ownerNames[p.OwnerUserID],
			AccessLevel:   accessLevel,
			MemberUserIDs: memberMap[p.ID],
			Members:       memberDetailMap[p.ID],
		})
	}
	return resp
}

func fallbackProjectMemberRole(role string) string {
	switch strings.TrimSpace(role) {
	case "viewer", "operator", "owner":
		return strings.TrimSpace(role)
	default:
		return "operator"
	}
}

func getProjectMembers(c *gin.Context) {
	projectID := c.Param("id")
	if _, ok := requireProjectAccess(c, projectID); !ok {
		return
	}
	var members []db.ProjectMember
	db.DB.Where("tenant_id = ? AND project_id = ?", currentTenantID(c), projectID).Find(&members)
	userIDs := make([]string, 0, len(members))
	memberPayloads := make([]projectMemberPayload, 0, len(members))
	for _, m := range members {
		if m.Role != "owner" {
			userIDs = append(userIDs, m.UserID)
		}
		memberPayloads = append(memberPayloads, projectMemberPayload{UserID: m.UserID, Role: fallbackProjectMemberRole(m.Role)})
	}
	c.JSON(http.StatusOK, gin.H{"project_id": projectID, "user_ids": userIDs, "members": memberPayloads})
}

func updateProjectMembers(c *gin.Context) {
	projectID := c.Param("id")
	project, ok := requireProjectManage(c, projectID)
	if !ok {
		return
	}
	var req struct {
		UserIDs []string               `json:"user_ids"`
		Members []projectMemberPayload `json:"members"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(req.Members) == 0 {
		for _, userID := range req.UserIDs {
			req.Members = append(req.Members, projectMemberPayload{UserID: userID, Role: "operator"})
		}
	}
	userIDs := make([]string, 0, len(req.Members))
	for _, member := range req.Members {
		userIDs = append(userIDs, member.UserID)
	}
	userIDs, err := validateAssignableProjectUsers(currentTenantID(c), userIDs)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "members must reference active users in current tenant"})
		return
	}
	allowedUsers := map[string]struct{}{}
	for _, userID := range userIDs {
		allowedUsers[userID] = struct{}{}
	}
	validMembers := make([]projectMemberPayload, 0, len(req.Members))
	for _, member := range req.Members {
		if _, ok := allowedUsers[member.UserID]; !ok || member.UserID == project.OwnerUserID {
			continue
		}
		role := fallbackProjectMemberRole(member.Role)
		validMembers = append(validMembers, projectMemberPayload{UserID: member.UserID, Role: role})
	}
	if err := db.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("tenant_id = ? AND project_id = ?", currentTenantID(c), projectID).Delete(&db.ProjectMember{}).Error; err != nil {
			return err
		}
		if err := upsertProjectMember(tx, currentTenantID(c), projectID, project.OwnerUserID, "owner"); err != nil {
			return err
		}
		for _, member := range validMembers {
			if err := upsertProjectMember(tx, currentTenantID(c), projectID, member.UserID, member.Role); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"project_id": projectID, "user_ids": userIDs, "members": validMembers})
}

func getTasks(c *gin.Context) {
	var tasks []db.RootTask
	tenantID := c.GetString("tenant")
	page, pageSize := parsePagination(c, 20, 100)
	query := db.DB.Where("tenant_id = ?", tenantID)
	query, _ = applyProjectScope(c, query, "project_id")

	var total int64
	if err := query.Model(&db.RootTask{}).Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := query.Order("created_at desc").Offset((page - 1) * pageSize).Limit(pageSize).Find(&tasks).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 增强返回：包含目标维度进度
	type TaskResponse struct {
		db.RootTask
	}
	resp := make([]TaskResponse, 0, len(tasks))
	for _, t := range tasks {
		resp = append(resp, TaskResponse{RootTask: t})
	}
	c.JSON(http.StatusOK, pagedResponse(resp, total, page, pageSize, ""))
}

type taskReasonStat struct {
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	Count       int    `json:"count"`
	TargetCount int    `json:"target_count"`
}

func subTaskTargetCount(st db.SubTask) int {
	var targets []string
	if json.Unmarshal([]byte(st.ChunkTargets), &targets) == nil {
		return len(targets)
	}
	return 0
}

func buildTaskReasonStats(subTasks []db.SubTask) []taskReasonStat {
	type acc struct {
		status      string
		reason      string
		count       int
		targetCount int
	}
	statsByKey := make(map[string]*acc)
	order := make([]string, 0)
	add := func(status, reason string, targetCount int) {
		if reason == "" {
			return
		}
		key := status + "\x00" + reason
		if _, ok := statsByKey[key]; !ok {
			statsByKey[key] = &acc{status: status, reason: reason}
			order = append(order, key)
		}
		statsByKey[key].count++
		statsByKey[key].targetCount += targetCount
	}

	for _, st := range subTasks {
		targetCount := subTaskTargetCount(st)
		switch db.NormalizeSubTaskStatus(st.Status) {
		case "FAILED":
			add(st.Status, "批次失败或重试耗尽", targetCount)
		case "TIMEOUT":
			if st.TimeoutSec > 0 {
				add(st.Status, fmt.Sprintf("超过 %d 秒未完成或重试耗尽", st.TimeoutSec), targetCount)
			} else {
				add(st.Status, "批次超时或重试耗尽", targetCount)
			}
		case "CANCELLED":
			add(st.Status, "用户取消后已终止", targetCount)
		case "CANCELPENDING":
			add(st.Status, "取消请求已下发，等待 Agent 确认", targetCount)
		case "PENDING", "DISPATCHING", "RECOVERED":
			if strings.TrimSpace(st.AgentID) == "" {
				add(st.Status, "等待可匹配节点认领", targetCount)
			}
		}
	}

	stats := make([]taskReasonStat, 0, len(order))
	for _, key := range order {
		item := statsByKey[key]
		stats = append(stats, taskReasonStat{
			Status:      item.status,
			Reason:      item.reason,
			Count:       item.count,
			TargetCount: item.targetCount,
		})
	}
	return stats
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
	if !canAccessProject(c, rootTask.ProjectID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "project not accessible"})
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
		targetCount := subTaskTargetCount(st)
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
		"reason_stats":        buildTaskReasonStats(subTasks),
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
			Updates(map[string]interface{}{
				"status":        "Pending",
				"stream_msg_id": queuedMarkerForQueue(q),
			})
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

func parseAgentSelector(raw json.RawMessage) (map[string]string, error) {
	if len(raw) == 0 || strings.TrimSpace(string(raw)) == "" || strings.TrimSpace(string(raw)) == "null" {
		return nil, nil
	}
	var values map[string]interface{}
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil, fmt.Errorf("agent_selector must be a flat object of string values")
	}
	selector := make(map[string]string, len(values))
	for key, val := range values {
		k := strings.TrimSpace(key)
		if k == "" {
			return nil, fmt.Errorf("agent_selector contains empty key")
		}
		s, ok := val.(string)
		if !ok {
			return nil, fmt.Errorf("agent_selector.%s must be a string", k)
		}
		s = strings.TrimSpace(s)
		if s == "" {
			return nil, fmt.Errorf("agent_selector.%s must not be empty", k)
		}
		selector[k] = s
	}
	return selector, nil
}

func parseAgentSelectorRules(raw json.RawMessage) (db.AgentSelectorRules, error) {
	return db.ParseSelectorRulesBytes(raw)
}

func mergeAgentSelector(baseJSON string, extra map[string]string) string {
	merged := make(map[string]string)
	if strings.TrimSpace(baseJSON) != "" {
		_ = json.Unmarshal([]byte(baseJSON), &merged)
	}
	for key, val := range extra {
		merged[key] = val
	}
	if len(merged) == 0 {
		return "{}"
	}
	data, err := json.Marshal(merged)
	if err != nil {
		return "{}"
	}
	return string(data)
}

func parseSelectorJSONString(raw string) map[string]string {
	selector := make(map[string]string)
	if strings.TrimSpace(raw) == "" || strings.TrimSpace(raw) == "{}" {
		return selector
	}
	_ = json.Unmarshal([]byte(raw), &selector)
	return selector
}

func effectiveSelectorRules(baseJSON string, userSelector map[string]string, userRules db.AgentSelectorRules) (map[string]string, db.AgentSelectorRules, string) {
	selectorJSON := mergeAgentSelector(baseJSON, userSelector)
	legacy := parseSelectorJSONString(selectorJSON)
	rules := db.MergeSelectorRules(legacy, userRules)
	return legacy, rules, db.SelectorRulesToJSON(rules)
}

func nodeMatchesSelector(selector map[string]string, nodeTags string) (bool, string) {
	return db.NodeMatchesSelectorRules(selector, db.AgentSelectorRules{}, nodeTags)
}

type selectorPreviewNode struct {
	AgentID        string `json:"agent_id"`
	Status         string `json:"status"`
	Capacity       int    `json:"capacity"`
	RunningTasks   int    `json:"running_tasks"`
	AvailableSlots int    `json:"available_slots"`
	Matched        bool   `json:"matched"`
	Reason         string `json:"reason,omitempty"`
}

type selectorPreviewGroup struct {
	TargetType       string                `json:"target_type"`
	TargetCount      int                   `json:"target_count"`
	BatchCount       int                   `json:"batch_count"`
	Selector         map[string]string     `json:"selector"`
	SelectorRules    db.AgentSelectorRules `json:"selector_rules"`
	MatchedNodes     int                   `json:"matched_nodes"`
	AvailableSlots   int                   `json:"available_slots"`
	ImmediateBatches int                   `json:"immediate_batches"`
	WaitingBatches   int                   `json:"waiting_batches"`
	Reasons          []string              `json:"reasons"`
	Nodes            []selectorPreviewNode `json:"nodes"`
}

func buildSelectorPreviewGroups(batches []targetBatchGroup, userSelector map[string]string, userRules db.AgentSelectorRules, nodes []db.Node) ([]selectorPreviewGroup, []map[string]string, int, int, []string) {
	type groupAccumulator struct {
		targetType string
		selector   map[string]string
		rules      db.AgentSelectorRules
		targets    int
		batches    int
	}
	groupsByKey := make(map[string]*groupAccumulator)
	groupOrder := make([]string, 0)
	effectiveSelectors := make([]map[string]string, 0)
	seenSelectors := make(map[string]struct{})

	for _, batch := range batches {
		selector, rules, rulesJSON := effectiveSelectorRules(batch.SelectorJSON, userSelector, userRules)
		key := batch.TargetType + "\x00" + rulesJSON
		if _, ok := groupsByKey[key]; !ok {
			groupsByKey[key] = &groupAccumulator{targetType: batch.TargetType, selector: selector, rules: rules}
			groupOrder = append(groupOrder, key)
		}
		groupsByKey[key].targets += len(batch.Targets)
		groupsByKey[key].batches++

		if _, ok := seenSelectors[rulesJSON]; !ok {
			seenSelectors[rulesJSON] = struct{}{}
			effectiveSelectors = append(effectiveSelectors, selector)
		}
	}
	if len(groupOrder) == 0 {
		selector := make(map[string]string)
		for key, val := range userSelector {
			selector[key] = val
		}
		rules := db.MergeSelectorRules(selector, userRules)
		groupsByKey["unknown\x00{}"] = &groupAccumulator{targetType: "unknown", selector: selector, rules: rules}
		groupOrder = append(groupOrder, "unknown\x00{}")
		effectiveSelectors = append(effectiveSelectors, selector)
	}

	overallMatched := make(map[string]int)
	overallReasons := make(map[string]struct{})
	addOverallReason := func(reason string) {
		if strings.TrimSpace(reason) != "" {
			overallReasons[reason] = struct{}{}
		}
	}

	groups := make([]selectorPreviewGroup, 0, len(groupOrder))
	for _, key := range groupOrder {
		acc := groupsByKey[key]
		reasonSet := make(map[string]struct{})
		addReason := func(reason string) {
			if strings.TrimSpace(reason) != "" {
				reasonSet[reason] = struct{}{}
			}
		}
		group := selectorPreviewGroup{
			TargetType:    acc.targetType,
			TargetCount:   acc.targets,
			BatchCount:    acc.batches,
			Selector:      acc.selector,
			SelectorRules: acc.rules,
			Nodes:         make([]selectorPreviewNode, 0, len(nodes)),
		}

		offlineNodes := 0
		mismatchedNodes := 0
		capacityExhausted := 0
		for _, node := range nodes {
			availableSlots := node.Capacity - node.RunningTasks
			if availableSlots < 0 {
				availableSlots = 0
			}
			nodePreview := selectorPreviewNode{
				AgentID:        node.AgentID,
				Status:         node.Status,
				Capacity:       node.Capacity,
				RunningTasks:   node.RunningTasks,
				AvailableSlots: availableSlots,
			}
			if node.Status != "Alive" {
				offlineNodes++
				nodePreview.Reason = "节点离线"
				group.Nodes = append(group.Nodes, nodePreview)
				continue
			}
			matched, reason := db.NodeMatchesSelectorRules(acc.selector, acc.rules, node.Tags)
			if !matched {
				mismatchedNodes++
				if reason == "" {
					reason = "不满足 selector"
				}
				nodePreview.Reason = reason
				group.Nodes = append(group.Nodes, nodePreview)
				continue
			}
			nodePreview.Matched = true
			if availableSlots == 0 {
				capacityExhausted++
				nodePreview.Reason = "容量已满"
			}
			group.MatchedNodes++
			group.AvailableSlots += availableSlots
			overallMatched[node.AgentID] = availableSlots
			group.Nodes = append(group.Nodes, nodePreview)
		}
		if group.AvailableSlots >= group.BatchCount {
			group.ImmediateBatches = group.BatchCount
		} else {
			group.ImmediateBatches = group.AvailableSlots
		}
		if group.BatchCount > group.ImmediateBatches {
			group.WaitingBatches = group.BatchCount - group.ImmediateBatches
			if group.ImmediateBatches > 0 {
				addReason(fmt.Sprintf("%d 个批次需要等待容量释放", group.WaitingBatches))
			}
		}

		if offlineNodes > 0 {
			addReason(fmt.Sprintf("%d 个节点离线", offlineNodes))
		}
		if mismatchedNodes > 0 {
			addReason(fmt.Sprintf("%d 个在线节点不满足 selector", mismatchedNodes))
		}
		if group.MatchedNodes > 0 && group.AvailableSlots == 0 && capacityExhausted > 0 {
			addReason("匹配节点当前没有空闲槽位")
		}
		if group.MatchedNodes == 0 {
			addReason("没有在线节点满足 selector")
		}
		group.Reasons = sortedReasonSet(reasonSet)
		for _, reason := range group.Reasons {
			addOverallReason(fmt.Sprintf("%s: %s", group.TargetType, reason))
		}
		groups = append(groups, group)
	}

	overallMatchedNodes := len(overallMatched)
	overallAvailableSlots := 0
	for _, slots := range overallMatched {
		overallAvailableSlots += slots
	}
	reasons := sortedReasonSet(overallReasons)
	if overallMatchedNodes == 0 {
		reasons = append(reasons, "没有在线节点满足最终 selector")
	}
	return groups, effectiveSelectors, overallMatchedNodes, overallAvailableSlots, reasons
}

func sortedReasonSet(reasonSet map[string]struct{}) []string {
	reasons := make([]string, 0, len(reasonSet))
	for reason := range reasonSet {
		reasons = append(reasons, reason)
	}
	sort.Strings(reasons)
	return reasons
}

func previewTaskSelector(c *gin.Context) {
	var req struct {
		ProjectID          string          `json:"project_id"`
		Targets            json.RawMessage `json:"targets"`
		Config             json.RawMessage `json:"config"`
		AgentSelector      json.RawMessage `json:"agent_selector"`
		AgentSelectorRules json.RawMessage `json:"agent_selector_rules"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.ProjectID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "project_id is required"})
		return
	}
	if _, ok := requireProjectAccess(c, req.ProjectID); !ok {
		return
	}
	userSelector, err := parseAgentSelector(req.AgentSelector)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	userRules, err := parseAgentSelectorRules(req.AgentSelectorRules)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, targetMode, err := normalizeTaskConfigPayload(req.Config)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	targets, targetSummary, err := parseAndValidateTargetsForMode(req.Targets, targetMode)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	batches := groupAndBatchTargets(targets, targetMode)

	tenantID := currentTenantID(c)
	var nodes []db.Node
	scopedNodeQuery(tenantID).Find(&nodes)
	groups, effectiveSelectors, matchedNodes, availableSlots, reasons := buildSelectorPreviewGroups(batches, userSelector, userRules, nodes)

	c.JSON(http.StatusOK, gin.H{
		"matched_nodes":       matchedNodes,
		"available_slots":     availableSlots,
		"reasons":             reasons,
		"effective_selectors": effectiveSelectors,
		"groups":              groups,
		"target_summary":      targetSummary,
	})
}

func createTask(c *gin.Context) {
	var req struct {
		ProjectID          string          `json:"project_id"`
		Name               string          `json:"name"`
		Targets            json.RawMessage `json:"targets"`
		Config             json.RawMessage `json:"config"`
		Priority           int             `json:"priority"`
		TimeoutSec         int             `json:"timeout_sec"`
		AgentSelector      json.RawMessage `json:"agent_selector"`
		AgentSelectorRules json.RawMessage `json:"agent_selector_rules"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.ProjectID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "project_id is required"})
		return
	}
	project, ok := requireProjectAccess(c, req.ProjectID)
	if !ok {
		return
	}
	if project.Status != "active" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "project is not active"})
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
	userSelector, err := parseAgentSelector(req.AgentSelector)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	userRules, err := parseAgentSelectorRules(req.AgentSelectorRules)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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

		_, _, rulesJSON := effectiveSelectorRules(batch.SelectorJSON, userSelector, userRules)
		subTasks = append(subTasks, db.SubTask{
			ID:                 fmt.Sprintf("%s-batch-%d-%s", rootTaskID, idx, batch.TargetType),
			TenantID:           tenantID,
			ProjectID:          req.ProjectID,
			RootTaskID:         rootTaskID,
			ChunkTargets:       string(chunkJSON),
			Status:             subTaskStatusDispatching,
			Config:             configJSON,
			Priority:           req.Priority,
			TimeoutSec:         req.TimeoutSec,
			MaxRetry:           3,
			AgentSelector:      mergeAgentSelector(batch.SelectorJSON, userSelector),
			AgentSelectorRules: rulesJSON,
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
		UserID:           currentUserID(c),
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
		if err := db.CheckTenantTaskCreationQuota(tx, tenantID, time.Now()); err != nil {
			return err
		}
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
		if writeTenantQuotaError(c, err) {
			return
		}
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

	isLite := c.Query("lite") == "1"
	// 如果指定了 lite=1 ，则省略动辄几千上万行的巨大 Content 正文内容，只提取主要元数据
	if isLite {
		query = query.Omit("Content", "PreviousContent")
	}

	if q := strings.TrimSpace(c.Query("q")); q != "" {
		like := "%" + strings.ToLower(q) + "%"
		query = query.Where("LOWER(file_name) LIKE ? OR LOWER(state) LIKE ? OR LOWER(hash) LIKE ?", like, like, like)
	}

	if c.Query("page") != "" || c.Query("page_size") != "" || strings.TrimSpace(c.Query("q")) != "" {
		page, pageSize := parsePagination(c, 50, 200)
		var total int64
		if err := query.Model(&db.Arsenal{}).Count(&total).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if err := query.Order("updated_at DESC, file_name ASC, id ASC").Limit(pageSize).Offset((page - 1) * pageSize).Find(&arsenals).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if isLite {
			clearArsenalLargeFields(arsenals)
		}
		c.JSON(http.StatusOK, pagedResponse(arsenals, total, page, pageSize, currentRuleVersion()))
		return
	}

	if err := query.Find(&arsenals).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if isLite {
		clearArsenalLargeFields(arsenals)
	}
	c.JSON(http.StatusOK, arsenals)
}

func getArsenal(c *gin.Context) {
	typ := db.CanonicalArsenalType(c.Param("type"))
	fn := c.Param("filename")
	tenantID := currentTenantID(c)
	arsenal, err := db.FindTenantArsenalByTypeAndFile(tenantID, typ, fn)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Arsenal not found"})
		return
	}
	c.JSON(http.StatusOK, arsenal)
}

func clearArsenalLargeFields(arsenals []db.Arsenal) {
	for i := range arsenals {
		arsenals[i].Content = ""
		arsenals[i].PreviousContent = ""
	}
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

	// EXP 包基础校验
	if typ == "exp" {
		if !strings.HasSuffix(strings.ToLower(fn), ".py") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "EXP filename must end with .py"})
			return
		}
		if err := validateExpPackage(req.Content, false); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("EXP validation failed: %v", err)})
			return
		}
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
	if approvedChanged && typ != "exp" {
		resp["rule_version"] = BumpRuleVersion()
	}
	c.JSON(http.StatusOK, resp)
}

func approveArsenal(c *gin.Context) {
	typ := db.CanonicalArsenalType(c.Param("type"))
	fn := c.Param("filename")
	tenantID := currentTenantID(c)

	// EXP 包严格校验
	if typ == "exp" {
		var existing db.Arsenal
		if err := db.DB.Where("tenant_id = ? AND type = ? AND file_name = ?", tenantID, typ, fn).First(&existing).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Arsenal not found"})
			return
		}
		if err := validateExpPackage(existing.Content, true); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("EXP validation failed: %v", err)})
			return
		}
	}

	if err := db.DB.Model(&db.Arsenal{}).Where("tenant_id = ? AND type = ? AND file_name = ?", tenantID, typ, fn).Update("state", "Approved").Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := db.SyncRuleCatalogFromArsenal(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if typ == "exp" {
		c.JSON(http.StatusOK, gin.H{"status": "approved"})
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
	if typ == "poc" {
		if refs := workflowReferencesForPOC(tenantID, fn); len(refs) > 0 {
			c.JSON(http.StatusConflict, gin.H{
				"error":      "POC is referenced by workflow rules",
				"references": refs,
			})
			return
		}
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
	if strings.EqualFold(arsenal.State, "Approved") && typ != "exp" {
		resp["rule_version"] = BumpRuleVersion()
	}
	c.JSON(http.StatusOK, resp)
}

func workflowReferencesForPOC(tenantID, fileName string) []gin.H {
	names := map[string]bool{}
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value != "" {
			names[value] = true
		}
	}
	add(fileName)
	add(strings.TrimSuffix(fileName, filepath.Ext(fileName)))
	var poc db.PocRule
	if err := db.DB.Where("tenant_id = ? AND source_file = ?", tenantID, fileName).First(&poc).Error; err == nil {
		add(poc.Name)
		add(poc.SourceFile)
	}
	list := make([]string, 0, len(names))
	for name := range names {
		list = append(list, name)
	}
	sort.Strings(list)
	var workflows []db.WorkflowRule
	if err := db.DB.Where("tenant_id = ? AND poc_name IN ?", tenantID, list).Order("product_name, poc_name, match_type").Find(&workflows).Error; err != nil {
		return nil
	}
	refs := make([]gin.H, 0, len(workflows))
	for _, wf := range workflows {
		refs = append(refs, gin.H{
			"product_name": wf.ProductName,
			"poc_name":     wf.PocName,
			"match_type":   wf.MatchType,
			"source_file":  wf.SourceFile,
			"state":        wf.State,
			"enabled":      wf.Enabled,
		})
	}
	return refs
}

// ---------------- 融合画像数据源 --------------------

// HostProfile 以主机(IP/域名)为单位聚合的画像
type HostProfile struct {
	Host         string              `json:"host"`
	Ports        []PortInfo          `json:"ports"`
	Assets       []db.Asset          `json:"assets"`
	Fingerprints []db.FingerprintHit `json:"fingerprints"`
	Vulns        []db.Vulnerability  `json:"vulns"`
}

type PortInfo struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Service  string `json:"service"`
	Title    string `json:"title"`
	URL      string `json:"url"`
}

// extractHost 从 target 字符串中提取主机部分 (IP 或域名)
// 支持格式: "1.2.3.4:80", "http://example.com:8080", "example.com"
func extractHost(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return target
	}
	// URL 格式
	if strings.Contains(target, "://") {
		if u, err := url.Parse(target); err == nil && u.Host != "" {
			return u.Hostname()
		}
	}
	// IP:Port 或 IP:Port:Extra 格式
	if host, _, err := net.SplitHostPort(target); err == nil {
		return host
	}
	// 可能是 IP:Port:Proto 三段式
	parts := strings.Split(target, ":")
	if len(parts) >= 2 {
		if ip := net.ParseIP(parts[0]); ip != nil {
			return parts[0]
		}
	}
	return target
}

func getProfiles(c *gin.Context) {
	tenantID := c.GetString("tenant")
	page := 1
	pageSize := 20
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

	// 步骤 1: 获取所有去重 target 值用于提取 host
	var allTargets []string
	tq := db.DB.Model(&db.Asset{}).Select("DISTINCT target")
	if tenantID != "" {
		tq = tq.Where("tenant_id = ?", tenantID)
	}
	tq, _ = applyProjectScope(c, tq, "project_id")
	if search := c.Query("search"); search != "" {
		tq = tq.Where("target LIKE ?", "%"+search+"%")
	}
	tq.Pluck("target", &allTargets)

	// 步骤 2: 在 Go 层按 host 聚合, 建立 host → targets 映射
	hostTargetsMap := make(map[string][]string)
	for _, t := range allTargets {
		h := extractHost(t)
		hostTargetsMap[h] = append(hostTargetsMap[h], t)
	}

	// 收集所有 host 并排序
	allHosts := make([]string, 0, len(hostTargetsMap))
	for h := range hostTargetsMap {
		allHosts = append(allHosts, h)
	}
	sort.Strings(allHosts)

	totalHosts := len(allHosts)

	// 分页
	start := (page - 1) * pageSize
	if start >= totalHosts {
		c.JSON(http.StatusOK, gin.H{"data": []HostProfile{}, "page": page, "page_size": pageSize, "total": totalHosts})
		return
	}
	end := start + pageSize
	if end > totalHosts {
		end = totalHosts
	}
	pagedHosts := allHosts[start:end]

	// 收集当前页所有 host 对应的 targets
	var pagedTargets []string
	for _, h := range pagedHosts {
		pagedTargets = append(pagedTargets, hostTargetsMap[h]...)
	}
	if len(pagedTargets) == 0 {
		c.JSON(http.StatusOK, gin.H{"data": []HostProfile{}, "page": page, "page_size": pageSize, "total": totalHosts})
		return
	}

	// 步骤 3: 批量查询关联数据（含租户隔离 + 项目隔离）
	var assets []db.Asset
	assocQ := db.DB.Where("target IN ?", pagedTargets)
	if tenantID != "" {
		assocQ = assocQ.Where("tenant_id = ?", tenantID)
	}
	assocQ, _ = applyProjectScope(c, assocQ, "project_id")
	assocQ.Find(&assets)

	var fps []db.FingerprintHit
	fpQ := db.DB.Where("target IN ?", pagedTargets)
	if tenantID != "" {
		fpQ = fpQ.Where("tenant_id = ?", tenantID)
	}
	fpQ, _ = applyProjectScope(c, fpQ, "project_id")
	fpQ.Find(&fps)

	var vulns []db.Vulnerability
	vulnQ := db.DB.Where("target IN ?", pagedTargets)
	if tenantID != "" {
		vulnQ = vulnQ.Where("tenant_id = ?", tenantID)
	}
	vulnQ, _ = applyProjectScope(c, vulnQ, "project_id")
	vulnQ.Find(&vulns)

	// 步骤 4: 按 host 聚合
	profiles := make([]HostProfile, 0, len(pagedHosts))
	for _, host := range pagedHosts {
		hp := HostProfile{Host: host}
		targets := hostTargetsMap[host]
		targetSet := make(map[string]bool, len(targets))
		for _, t := range targets {
			targetSet[t] = true
		}

		// 聚合端口信息 (去重)
		portSeen := make(map[string]bool)
		for _, a := range assets {
			if !targetSet[a.Target] {
				continue
			}
			hp.Assets = append(hp.Assets, a)

			// 从 Asset.Port 或 Target 字符串中提取端口号
			resolvedPort := a.Port
			if resolvedPort == 0 && a.Target != "" {
				if u, err := url.Parse(a.Target); err == nil && u.Port() != "" {
					if pv, e := strconv.Atoi(u.Port()); e == nil {
						resolvedPort = pv
					}
				} else if _, portStr, err := net.SplitHostPort(a.Target); err == nil {
					if pv, e := strconv.Atoi(portStr); e == nil {
						resolvedPort = pv
					}
				}
			}

			portKey := fmt.Sprintf("%d:%s", resolvedPort, a.Protocol)
			if !portSeen[portKey] {
				portSeen[portKey] = true
				hp.Ports = append(hp.Ports, PortInfo{
					Port:     resolvedPort,
					Protocol: a.Protocol,
					Service:  a.Service,
					Title:    a.Title,
					URL:      a.URL,
				})
			}
		}

		for _, f := range fps {
			if targetSet[f.Target] {
				hp.Fingerprints = append(hp.Fingerprints, f)
			}
		}
		for _, v := range vulns {
			if targetSet[v.Target] {
				hp.Vulns = append(hp.Vulns, v)
			}
		}

		// 端口排序
		sort.Slice(hp.Ports, func(i, j int) bool { return hp.Ports[i].Port < hp.Ports[j].Port })
		profiles = append(profiles, hp)
	}

	c.JSON(http.StatusOK, gin.H{"data": profiles, "page": page, "page_size": pageSize, "total": totalHosts})
}

func deleteTask(c *gin.Context) {
	id := c.Param("id")
	tenantID := currentTenantID(c)
	var rootTask db.RootTask
	if err := db.DB.Select("id", "project_id").Where("id = ? AND tenant_id = ?", id, tenantID).First(&rootTask).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
		return
	}
	if !canAccessProject(c, rootTask.ProjectID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "project not accessible"})
		return
	}
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
	var vulns []db.Vulnerability
	tenantID := currentTenantID(c)
	query := db.DB.Model(&db.Vulnerability{}).Where("tenant_id = ?", tenantID)
	query = applyReportResultScope(c, query)
	query.Find(&vulns)

	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)
	_ = writer.Write([]string{"TenantID", "ProjectID", "TaskID", "Target", "Plugin", "Severity", "DetectedAt"})
	for _, v := range vulns {
		_ = writer.Write([]string{v.TenantID, v.ProjectID, v.TaskID, v.Target, v.Plugin, v.Severity, v.CreatedAt.Format(time.RFC3339)})
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	recordReportExport(c, tenantID, "vulnerabilities", "vulnerabilities.csv", buf.Bytes())

	c.Writer.Header().Set("Content-Type", "text/csv")
	c.Writer.Header().Set("Content-Disposition", "attachment;filename=vulnerabilities.csv")
	c.Data(http.StatusOK, "text/csv", buf.Bytes())
}

func exportAssets(c *gin.Context) {
	var assets []db.Asset
	tenantID := currentTenantID(c)
	query := db.DB.Model(&db.Asset{}).Where("tenant_id = ?", tenantID)
	query = applyReportResultScope(c, query)
	query.Find(&assets)

	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)
	_ = writer.Write([]string{"TenantID", "ProjectID", "TaskID", "Target", "Protocol", "Port", "URL", "Title", "Service", "DetectedAt"})
	for _, a := range assets {
		_ = writer.Write([]string{a.TenantID, a.ProjectID, a.TaskID, a.Target, a.Protocol, strconv.Itoa(a.Port), a.URL, a.Title, a.Service, a.CreatedAt.Format(time.RFC3339)})
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	recordReportExport(c, tenantID, "assets", "assets.csv", buf.Bytes())

	c.Writer.Header().Set("Content-Type", "text/csv")
	c.Writer.Header().Set("Content-Disposition", "attachment;filename=assets.csv")
	c.Data(http.StatusOK, "text/csv", buf.Bytes())
}

func exportFingerprints(c *gin.Context) {
	var fps []db.FingerprintHit
	tenantID := currentTenantID(c)
	query := db.DB.Model(&db.FingerprintHit{}).Where("tenant_id = ?", tenantID)
	query = applyReportResultScope(c, query)
	query.Find(&fps)

	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)
	_ = writer.Write([]string{"TenantID", "ProjectID", "TaskID", "Target", "ProductName", "RuleName", "DetectedAt"})
	for _, f := range fps {
		_ = writer.Write([]string{f.TenantID, f.ProjectID, f.TaskID, f.Target, f.ProductName, f.RuleName, f.CreatedAt.Format(time.RFC3339)})
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	recordReportExport(c, tenantID, "fingerprints", "fingerprints.csv", buf.Bytes())

	c.Writer.Header().Set("Content-Type", "text/csv")
	c.Writer.Header().Set("Content-Disposition", "attachment;filename=fingerprints.csv")
	c.Data(http.StatusOK, "text/csv", buf.Bytes())
}

func applyReportResultScope(c *gin.Context, query *gorm.DB) *gorm.DB {
	query, _ = applyProjectScope(c, query, "project_id")
	if taskID := strings.TrimSpace(c.Query("task_id")); taskID != "" {
		if scopedTaskIDs := resolveAccessibleTaskIDs(c, taskID); len(scopedTaskIDs) > 1 {
			query = query.Where("task_id IN ?", scopedTaskIDs)
		} else if len(scopedTaskIDs) == 1 {
			query = query.Where("task_id = ?", scopedTaskIDs[0])
		} else {
			query = query.Where("1 = 0")
		}
	}
	return query
}

func recordReportExport(c *gin.Context, tenantID, reportType, fileName string, content []byte) {
	store, err := storage.NewLocalStore(objectStorageRoot)
	if err != nil {
		log.Printf("[Report] storage unavailable: %v", err)
		return
	}
	now := time.Now().UTC()
	key := fmt.Sprintf("reports/%s/%s-%s.csv", tenantID, reportType, now.Format("20060102T150405Z"))
	obj, err := store.Put(c.Request.Context(), key, bytes.NewReader(content))
	if err != nil {
		log.Printf("[Report] failed to persist export %s: %v", key, err)
		return
	}
	report := db.Report{
		ID:        fmt.Sprintf("%s:%d", tenantID, now.UnixNano()),
		ProjectID: strings.TrimSpace(c.Query("project_id")),
		Name:      fileName,
		Type:      reportType,
		Format:    "csv",
		FileURL:   "local://" + obj.Key,
		Status:    "ready",
		CreatedBy: currentUserID(c),
		CreatedAt: now,
	}
	if err := db.DB.Create(&report).Error; err != nil {
		log.Printf("[Report] failed to record export metadata %s: %v", report.ID, err)
	}
}

func cancelTask(c *gin.Context) {
	id := c.Param("id")
	tenantID := currentTenantID(c)
	var rootTask db.RootTask
	if err := db.DB.Select("id", "project_id").Where("id = ? AND tenant_id = ?", id, tenantID).First(&rootTask).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
		return
	}
	if !canAccessProject(c, rootTask.ProjectID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "project not accessible"})
		return
	}
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

func pauseTask(c *gin.Context) {
	id := c.Param("id")
	tenantID := currentTenantID(c)
	var rootTask db.RootTask
	if err := db.DB.Select("id", "project_id", "status").Where("id = ? AND tenant_id = ?", id, tenantID).First(&rootTask).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
		return
	}
	if !canAccessProject(c, rootTask.ProjectID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "project not accessible"})
		return
	}
	switch db.NormalizeSubTaskStatus(rootTask.Status) {
	case "QUEUED", "RUNNING", "PARTIALDONE":
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "task is not in a pausable state"})
		return
	}

	var pausedWithoutClaim int64
	if err := db.DB.Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&db.SubTask{}).
			Where("root_task_id = ? AND tenant_id = ? AND status IN ?", id, tenantID, []string{"Pending", "Recovered", subTaskStatusDispatching}).
			Updates(map[string]interface{}{
				"status":        "Paused",
				"agent_id":      "",
				"stream_msg_id": "",
			})
		if res.Error != nil {
			return res.Error
		}
		pausedWithoutClaim = res.RowsAffected
		return tx.Model(&db.RootTask{}).
			Where("id = ? AND tenant_id = ?", id, tenantID).
			Update("status", "Paused").Error
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":                 "paused",
		"paused_without_claim":   pausedWithoutClaim,
		"running_tasks_continue": true,
	})
}

func resumeTask(c *gin.Context) {
	id := c.Param("id")
	tenantID := currentTenantID(c)
	var rootTask db.RootTask
	if err := db.DB.Select("id", "project_id", "status").Where("id = ? AND tenant_id = ?", id, tenantID).First(&rootTask).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
		return
	}
	if !canAccessProject(c, rootTask.ProjectID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "project not accessible"})
		return
	}
	if db.NormalizeSubTaskStatus(rootTask.Status) != "PAUSED" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "task is not paused"})
		return
	}

	var pausedSubs []db.SubTask
	if err := db.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("root_task_id = ? AND tenant_id = ? AND status = ?", id, tenantID, "Paused").
			Find(&pausedSubs).Error; err != nil {
			return err
		}
		for i := range pausedSubs {
			pausedSubs[i].Status = subTaskStatusDispatching
		}
		if len(pausedSubs) > 0 {
			ids := make([]string, 0, len(pausedSubs))
			for _, sub := range pausedSubs {
				ids = append(ids, sub.ID)
			}
			if err := tx.Model(&db.SubTask{}).
				Where("id IN ? AND root_task_id = ? AND tenant_id = ? AND status = ?", ids, id, tenantID, "Paused").
				Updates(map[string]interface{}{
					"status":        subTaskStatusDispatching,
					"agent_id":      "",
					"stream_msg_id": "",
				}).Error; err != nil {
				return err
			}
		}
		return tx.Model(&db.RootTask{}).
			Where("id = ? AND tenant_id = ?", id, tenantID).
			Update("status", "Queued").Error
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	pushedByPriority, dispatchPending := dispatchSubTasks(context.Background(), taskQueue, pausedSubs)
	if totalDispatchedTasks(pushedByPriority) > 0 {
		broadcastDispatchedTasks(pushedByPriority)
	}
	db.RefreshRootTaskStatus(id)

	c.JSON(http.StatusOK, gin.H{
		"status":           "resumed",
		"reactivated":      len(pausedSubs),
		"dispatch_pending": dispatchPending,
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
	apiConfigHash := currentAPIConfigHashValue(tenantID)
	agentAPIConfigHash := strings.TrimSpace(c.Query("api_config_hash"))
	syncAPIConfig := agentAPIConfigHash != apiConfigHash

	c.JSON(http.StatusOK, gin.H{
		"cancel_tasks":    cancels,
		"reload_rules":    reloadRules,
		"rule_version":    ruleVersion,
		"sync_api_config": syncAPIConfig,
		"api_config_hash": apiConfigHash,
	})
}

func getVulns(c *gin.Context) {
	var vulns []db.Vulnerability
	tenantID := currentTenantID(c)
	query := db.DB.Where("tenant_id = ?", tenantID).Order("created_at desc")
	query, _ = applyProjectScope(c, query, "project_id")
	if taskID := c.Query("task_id"); taskID != "" {
		if scopedTaskIDs := resolveAccessibleTaskIDs(c, taskID); len(scopedTaskIDs) > 1 {
			query = query.Where("task_id IN ?", scopedTaskIDs)
		} else if len(scopedTaskIDs) == 1 {
			query = query.Where("task_id = ?", scopedTaskIDs[0])
		} else {
			query = query.Where("1 = 0")
		}
	}
	page, pageSize, total, ok := paginateResultQuery(c, query, &db.Vulnerability{}, &vulns)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, pagedResponse(vulns, total, page, pageSize, ""))
}

func getAssets(c *gin.Context) {
	var assets []db.Asset
	tenantID := currentTenantID(c)
	query := db.DB.Where("tenant_id = ?", tenantID).Order("created_at desc")
	query, _ = applyProjectScope(c, query, "project_id")
	if taskID := c.Query("task_id"); taskID != "" {
		if scopedTaskIDs := resolveAccessibleTaskIDs(c, taskID); len(scopedTaskIDs) > 1 {
			query = query.Where("task_id IN ?", scopedTaskIDs)
		} else if len(scopedTaskIDs) == 1 {
			query = query.Where("task_id = ?", scopedTaskIDs[0])
		} else {
			query = query.Where("1 = 0")
		}
	}
	page, pageSize, total, ok := paginateResultQuery(c, query, &db.Asset{}, &assets)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, pagedResponse(assets, total, page, pageSize, ""))
}

func getFingerprints(c *gin.Context) {
	var fps []db.FingerprintHit
	baseQuery := fingerprintResultQuery(c)
	if strings.EqualFold(strings.TrimSpace(c.Query("group_by")), "product") {
		getFingerprintGroups(c, baseQuery)
		return
	}
	query := baseQuery.Order("created_at desc")
	page, pageSize, total, ok := paginateResultQuery(c, query, &db.FingerprintHit{}, &fps)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, pagedResponse(fps, total, page, pageSize, ""))
}

func fingerprintResultQuery(c *gin.Context) *gorm.DB {
	tenantID := currentTenantID(c)
	query := db.DB.Model(&db.FingerprintHit{}).Where("tenant_id = ?", tenantID)
	query, _ = applyProjectScope(c, query, "project_id")
	if taskID := c.Query("task_id"); taskID != "" {
		if scopedTaskIDs := resolveAccessibleTaskIDs(c, taskID); len(scopedTaskIDs) > 1 {
			query = query.Where("task_id IN ?", scopedTaskIDs)
		} else if len(scopedTaskIDs) == 1 {
			query = query.Where("task_id = ?", scopedTaskIDs[0])
		} else {
			query = query.Where("1 = 0")
		}
	}
	return query
}

type fingerprintGroupTarget struct {
	Target    string
	RuleName  string
	Evidence  string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type fingerprintGroup struct {
	ProductName string
	TargetCount int64
	Targets     []fingerprintGroupTarget
	FirstSeen   time.Time
	LastSeen    time.Time
}

func getFingerprintGroups(c *gin.Context, query *gorm.DB) {
	page, pageSize := parsePagination(c, 20, 200)
	totalQuery := query.Session(&gorm.Session{}).
		Select("product_name").
		Group("product_name")

	var total int64
	if err := db.DB.Table("(?) as grouped", totalQuery).Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	type groupRow struct {
		ProductName string
		TargetCount int64
	}
	rows := make([]groupRow, 0)
	if err := query.Session(&gorm.Session{}).
		Select("product_name, COUNT(*) as target_count").
		Group("product_name").
		Order("target_count DESC, product_name ASC").
		Limit(pageSize).
		Offset((page - 1) * pageSize).
		Scan(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	productNames := make([]string, 0, len(rows))
	groupIndexByProduct := make(map[string]int, len(rows))
	groups := make([]fingerprintGroup, 0, len(rows))
	for _, row := range rows {
		group := fingerprintGroup{
			ProductName: row.ProductName,
			TargetCount: row.TargetCount,
			Targets:     make([]fingerprintGroupTarget, 0, int(row.TargetCount)),
		}
		groups = append(groups, group)
		groupIndexByProduct[row.ProductName] = len(groups) - 1
		productNames = append(productNames, row.ProductName)
	}

	if len(productNames) > 0 {
		hits := make([]db.FingerprintHit, 0)
		if err := query.Session(&gorm.Session{}).
			Where("product_name IN ?", productNames).
			Order("product_name ASC, target ASC, created_at ASC").
			Find(&hits).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		for _, hit := range hits {
			groupIndex, ok := groupIndexByProduct[hit.ProductName]
			if !ok {
				continue
			}
			group := &groups[groupIndex]
			group.Targets = append(group.Targets, fingerprintGroupTarget{
				Target:    hit.Target,
				RuleName:  hit.RuleName,
				Evidence:  hit.Evidence,
				CreatedAt: hit.CreatedAt,
				UpdatedAt: hit.UpdatedAt,
			})
			if group.FirstSeen.IsZero() || hit.CreatedAt.Before(group.FirstSeen) {
				group.FirstSeen = hit.CreatedAt
			}
			if group.LastSeen.IsZero() || hit.UpdatedAt.After(group.LastSeen) {
				group.LastSeen = hit.UpdatedAt
			}
		}
	}

	c.JSON(http.StatusOK, pagedResponse(groups, total, page, pageSize, ""))
}

func paginateResultQuery(c *gin.Context, query *gorm.DB, model interface{}, dest interface{}) (int, int, int64, bool) {
	page, pageSize := parsePagination(c, 20, 200)
	var total int64
	if err := query.Session(&gorm.Session{}).Model(model).Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return page, pageSize, 0, false
	}
	if err := query.Session(&gorm.Session{}).Limit(pageSize).Offset((page - 1) * pageSize).Find(dest).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return page, pageSize, total, false
	}
	return page, pageSize, total, true
}

type NodeResponse struct {
	db.Node
	RunningTaskDetails []map[string]interface{} `json:"RunningTaskDetails"`
}

func getNodes(c *gin.Context) {
	tenantID := currentTenantID(c)
	var nodes []db.Node
	scopedNodeQuery(tenantID).Find(&nodes)

	resp := make([]NodeResponse, 0, len(nodes))
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

func revokeNodeToken(c *gin.Context) {
	agentID := c.Param("id")
	tenantID := currentTenantID(c)
	now := time.Now()
	res := scopedNodeQuery(tenantID).Where("agent_id = ?", agentID).Updates(map[string]interface{}{
		"token":            "",
		"token_revoked_at": &now,
		"status":           "Offline",
	})
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": res.Error.Error()})
		return
	}
	if res.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Node not found"})
		return
	}
	_ = db.DB.Create(&db.AgentSessionAudit{
		TenantID:   tenantID,
		AgentID:    agentID,
		Action:     "revoke",
		Reason:     "admin revoked agent session token",
		OperatorID: currentUserID(c),
		CreatedAt:  now,
	}).Error
	c.JSON(http.StatusOK, gin.H{"status": "revoked", "agent_id": agentID, "token_revoked_at": now})
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
	var tenantClaim string
	var roleClaim string
	var userIDClaim string
	var expAuthorizedClaim bool
	if err := db.DB.Where("username = ?", loginUsername).First(&user).Error; err == nil {
		// 数据库有此用户，校验密码
		if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Wrong password"})
			return
		}
		if user.Status != "active" {
			c.JSON(http.StatusForbidden, gin.H{"error": "User is disabled"})
			return
		}
		tenantClaim = user.TenantID
		roleClaim = user.Role
		if roleClaim == "" {
			roleClaim = "viewer"
		}
		userIDClaim = fmt.Sprintf("%d", user.ID)
		expAuthorizedClaim = user.ExpAuthorized
	} else if errors.Is(err, gorm.ErrRecordNotFound) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Wrong password"})
		return
	} else {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query user"})
		return
	}

	// 颁发 Token（包含角色信息）
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"tenant_id":      tenantClaim,
		"role":           roleClaim,
		"role_base":      baseRoleForToken(tenantClaim, roleClaim),
		"user_id":        userIDClaim,
		"exp_authorized": expAuthorizedClaim,
		"exp":            time.Now().Add(time.Hour * 72).Unix(),
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
		Where("tenant_id = ? AND state = ? AND type IN ?", tenantID, "Approved", agentSyncArsenalTypes()).
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
	tenantID := currentTenantID(c)
	var users []db.User
	db.DB.Where("tenant_id = ?", tenantID).Order("created_at DESC").Find(&users)

	type UserResp struct {
		ID            uint   `json:"id"`
		TenantID      string `json:"tenant_id"`
		Username      string `json:"username"`
		Role          string `json:"role"`
		Status        string `json:"status"`
		ExpAuthorized bool   `json:"exp_authorized"`
		CreatedAt     string `json:"created_at"`
		UpdatedAt     string `json:"updated_at"`
	}

	resp := make([]UserResp, 0, len(users))
	for _, u := range users {
		resp = append(resp, UserResp{
			ID:            u.ID,
			TenantID:      u.TenantID,
			Username:      u.Username,
			Role:          u.Role,
			Status:        u.Status,
			ExpAuthorized: u.ExpAuthorized,
			CreatedAt:     u.CreatedAt.Format(time.RFC3339),
			UpdatedAt:     u.UpdatedAt.Format(time.RFC3339),
		})
	}

	c.JSON(http.StatusOK, resp)
}

func createUser(c *gin.Context) {
	var req struct {
		Username      string `json:"username" binding:"required"`
		Password      string `json:"password" binding:"required"`
		Role          string `json:"role"`
		TenantID      string `json:"tenant_id"`
		ExpAuthorized bool   `json:"exp_authorized"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tenantID := currentTenantID(c)
	role, ok := normalizeUserRoleForTenant(tenantID, req.Role)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role must be a built-in role or an existing custom role"})
		return
	}
	if req.TenantID != "" && req.TenantID != tenantID {
		c.JSON(http.StatusForbidden, gin.H{"error": "cannot create user for another tenant"})
		return
	}
	req.TenantID = tenantID

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	user := db.User{
		TenantID:      req.TenantID,
		Username:      req.Username,
		PasswordHash:  string(hash),
		Role:          role,
		Status:        "active",
		ExpAuthorized: req.ExpAuthorized,
	}
	if err := db.DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok", "id": user.ID})
}

func updateUser(c *gin.Context) {
	id := c.Param("id")
	tenantID := currentTenantID(c)
	var req struct {
		Role          string `json:"role"`
		Status        string `json:"status"`
		Password      string `json:"password"`
		ExpAuthorized *bool  `json:"exp_authorized"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	updates := map[string]interface{}{}
	if req.Role != "" {
		role, ok := normalizeUserRoleForTenant(tenantID, req.Role)
		if !ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": "role must be a built-in role or an existing custom role"})
			return
		}
		updates["role"] = role
	}
	if req.Status != "" {
		status, ok := normalizeUserStatus(req.Status)
		if !ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": "status must be one of: active, disabled"})
			return
		}
		updates["status"] = status
	}
	if req.Password != "" {
		hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		updates["password_hash"] = string(hash)
	}
	if req.ExpAuthorized != nil {
		updates["exp_authorized"] = *req.ExpAuthorized
	}

	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No fields to update"})
		return
	}

	res := db.DB.Model(&db.User{}).Where("id = ? AND tenant_id = ?", id, tenantID).Updates(updates)
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": res.Error.Error()})
		return
	}
	if res.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func deleteUser(c *gin.Context) {
	id := c.Param("id")
	tenantID := currentTenantID(c)
	res := db.DB.Delete(&db.User{}, "id = ? AND tenant_id = ?", id, tenantID)
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": res.Error.Error()})
		return
	}
	if res.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
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

	artifacts := make([]Artifact, 0)
	store, err := storage.NewLocalStore("./release")
	if err != nil {
		c.JSON(http.StatusOK, artifacts)
		return
	}
	objects, err := store.List(c.Request.Context(), "")
	if err != nil {
		c.JSON(http.StatusOK, artifacts)
		return
	}
	for _, obj := range objects {
		if strings.Contains(obj.Key, "/") {
			continue
		}
		name := obj.Key
		platform, arch := parseBinaryName(name)
		artifacts = append(artifacts, Artifact{
			Name:     name,
			Size:     obj.Size,
			Platform: platform,
			Arch:     arch,
			ModTime:  obj.ModTime.Format(time.RFC3339),
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

func listBuildJobs(c *gin.Context) {
	limit := 20
	if raw := strings.TrimSpace(c.Query("limit")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			limit = v
		}
	}
	if limit > 100 {
		limit = 100
	}
	var jobs []db.BuildJob
	db.DB.Select("id", "platform", "arch", "components", "pack", "status", "artifact", "artifacts", "log_tail", "error", "started_at", "finished_at", "created_at", "updated_at").
		Order("created_at DESC").Limit(limit).Find(&jobs)
	c.JSON(http.StatusOK, buildJobResponses(jobs))
}

func getBuildJob(c *gin.Context) {
	var job db.BuildJob
	if err := db.DB.Select("id", "platform", "arch", "components", "pack", "status", "artifact", "artifacts", "log_tail", "error", "started_at", "finished_at", "created_at", "updated_at").
		First(&job, "id = ?", c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Build job not found"})
		return
	}
	c.JSON(http.StatusOK, buildJobResponse(job))
}

func buildJobResponses(jobs []db.BuildJob) []gin.H {
	out := make([]gin.H, 0, len(jobs))
	for _, job := range jobs {
		out = append(out, buildJobResponse(job))
	}
	return out
}

func buildJobResponse(job db.BuildJob) gin.H {
	return gin.H{
		"id": job.ID, "platform": job.Platform, "arch": job.Arch, "pack": job.Pack,
		"components": buildComponentsFromJSON(job.Components),
		"status":     job.Status, "artifact": job.Artifact, "artifacts": buildArtifactsFromJSON(job.Artifacts, job.Artifact),
		"log_tail": job.LogTail, "error": job.Error, "started_at": job.StartedAt, "finished_at": job.FinishedAt,
		"created_at": job.CreatedAt, "updated_at": job.UpdatedAt,
	}
}

func getBuildJobLogs(c *gin.Context) {
	var job db.BuildJob
	if err := db.DB.Select("id", "log_tail", "log_text").First(&job, "id = ?", c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Build job not found"})
		return
	}
	logText := job.LogText
	if logText == "" {
		logText = job.LogTail
	}
	c.String(http.StatusOK, logText)
}

func cancelBuildJob(c *gin.Context) {
	jobID, err := parseBuildJobID(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid build job id"})
		return
	}

	buildMu.Lock()
	defer buildMu.Unlock()

	var job db.BuildJob
	if err := db.DB.Select("id", "status").First(&job, "id = ?", jobID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Build job not found"})
		return
	}
	if job.Status != "queued" && job.Status != "running" {
		c.JSON(http.StatusConflict, gin.H{"error": "build job is already finished"})
		return
	}

	cancelRegisteredBuild(jobID)
	finishedAt := time.Now()
	result := db.DB.Model(&db.BuildJob{}).
		Where("id = ? AND status IN ?", jobID, []string{"queued", "running"}).
		Updates(map[string]interface{}{
			"status":      "canceled",
			"error":       "build canceled by user",
			"finished_at": &finishedAt,
		})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": result.Error.Error()})
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "build job is already finished"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "canceled", "job_id": jobID})
}

func retryBuildJob(c *gin.Context) {
	jobID, err := parseBuildJobID(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid build job id"})
		return
	}

	var oldJob db.BuildJob
	if err := db.DB.Select("id", "platform", "arch", "pack", "status").First(&oldJob, "id = ?", jobID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Build job not found"})
		return
	}
	if oldJob.Status == "queued" || oldJob.Status == "running" {
		c.JSON(http.StatusConflict, gin.H{"error": "build job is still active"})
		return
	}
	if !isSupportedBuildTarget(oldJob.Platform, oldJob.Arch) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported build target"})
		return
	}

	if _, err := os.Stat("./build.sh"); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"error": "build.sh not found in project root"})
		return
	}
	job, err := createBuildJobIfIdle(oldJob.Platform, oldJob.Arch, oldJob.Pack, buildComponentsFromJSON(oldJob.Components))
	if errors.Is(err, errBuildAlreadyQueued) {
		c.JSON(http.StatusConflict, gin.H{"error": "another build job is already queued or running"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	go buildJobRunner(job.ID)

	c.JSON(http.StatusAccepted, gin.H{
		"status":      "queued",
		"message":     fmt.Sprintf("Build job retried: %s/%s (pack=%v)", oldJob.Platform, oldJob.Arch, oldJob.Pack),
		"job_id":      job.ID,
		"retry_of_id": oldJob.ID,
	})
}

func triggerBuild(c *gin.Context) {
	var req struct {
		Platform   string   `json:"platform"` // linux, darwin, windows
		Arch       string   `json:"arch"`     // amd64, arm64
		Pack       bool     `json:"pack"`     // 是否 UPX 压缩
		Components []string `json:"components"`
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
	if !isSupportedBuildTarget(req.Platform, req.Arch) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported build target"})
		return
	}

	components, err := normalizeBuildComponents(req.Components)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 检查 build.sh 是否存在
	buildScript := "./build.sh"
	if _, err := os.Stat(buildScript); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"error": "build.sh not found in project root"})
		return
	}

	job, err := createBuildJobIfIdle(req.Platform, req.Arch, req.Pack, components)
	if errors.Is(err, errBuildAlreadyQueued) {
		c.JSON(http.StatusConflict, gin.H{"error": "another build job is already queued or running"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	go buildJobRunner(job.ID)

	c.JSON(http.StatusAccepted, gin.H{
		"status":     "queued",
		"message":    fmt.Sprintf("Build job queued: %s/%s (pack=%v)", req.Platform, req.Arch, req.Pack),
		"job_id":     job.ID,
		"platform":   req.Platform,
		"arch":       req.Arch,
		"components": components,
	})
}

func createBuildJobIfIdle(platform, arch string, pack bool, componentSets ...[]string) (db.BuildJob, error) {
	buildMu.Lock()
	defer buildMu.Unlock()

	var running int64
	if err := db.DB.Model(&db.BuildJob{}).Where("status IN ?", []string{"queued", "running"}).Count(&running).Error; err != nil {
		return db.BuildJob{}, err
	}
	if running > 0 {
		return db.BuildJob{}, errBuildAlreadyQueued
	}

	components := []string(nil)
	if len(componentSets) > 0 {
		components = componentSets[0]
	}
	components, err := normalizeBuildComponents(components)
	if err != nil {
		return db.BuildJob{}, err
	}
	componentJSON, _ := json.Marshal(components)
	job := db.BuildJob{
		Platform:   platform,
		Arch:       arch,
		Components: string(componentJSON),
		Pack:       pack,
		Status:     "queued",
	}
	if err := db.DB.Create(&job).Error; err != nil {
		return db.BuildJob{}, err
	}
	return job, nil
}

func parseBuildJobID(raw string) (uint, error) {
	id, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 64)
	if err != nil || id == 0 {
		return 0, errors.New("invalid build job id")
	}
	return uint(id), nil
}

func registerBuildCancel(jobID uint, cancel context.CancelFunc) {
	buildCancelMu.Lock()
	defer buildCancelMu.Unlock()
	buildCancels[jobID] = cancel
}

func unregisterBuildCancel(jobID uint) {
	buildCancelMu.Lock()
	defer buildCancelMu.Unlock()
	delete(buildCancels, jobID)
}

func cancelRegisteredBuild(jobID uint) {
	buildCancelMu.Lock()
	cancel := buildCancels[jobID]
	buildCancelMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func isSupportedBuildTarget(platform, arch string) bool {
	switch platform {
	case "linux", "darwin":
		return arch == "amd64" || arch == "arm64"
	case "windows":
		return arch == "amd64" || arch == "386"
	default:
		return false
	}
}

func normalizeBuildComponents(raw []string) ([]string, error) {
	if len(raw) == 0 {
		return []string{"dddd-agent"}, nil
	}
	allowed := map[string]bool{"dddd": true, "dddd-agent": true, "dddd-server": true, "server-ui": true}
	seen := map[string]struct{}{}
	components := make([]string, 0, len(raw))
	for _, item := range raw {
		component := strings.TrimSpace(item)
		if component == "" {
			continue
		}
		if !allowed[component] {
			return nil, fmt.Errorf("unsupported build component: %s", component)
		}
		if _, ok := seen[component]; ok {
			continue
		}
		seen[component] = struct{}{}
		components = append(components, component)
	}
	if len(components) == 0 {
		return []string{"dddd-agent"}, nil
	}
	return components, nil
}

func buildComponentsFromJSON(raw string) []string {
	var components []string
	if strings.TrimSpace(raw) != "" {
		_ = json.Unmarshal([]byte(raw), &components)
	}
	components, _ = normalizeBuildComponents(components)
	return components
}

func buildArtifactsFromJSON(raw, fallback string) []string {
	var artifacts []string
	if strings.TrimSpace(raw) != "" {
		_ = json.Unmarshal([]byte(raw), &artifacts)
	}
	if len(artifacts) == 0 && strings.TrimSpace(fallback) != "" {
		artifacts = []string{fallback}
	}
	return artifacts
}

func expectedBuildArtifacts(components []string, platform, arch string) []string {
	artifacts := make([]string, 0, len(components))
	for _, component := range components {
		if component == "server-ui" {
			artifacts = append(artifacts, "server-ui-dist.tar.gz")
			continue
		}
		name := fmt.Sprintf("%s-%s-%s", component, platform, arch)
		if platform == "windows" {
			name += ".exe"
		}
		artifacts = append(artifacts, name)
	}
	return artifacts
}

func runBuildJob(jobID uint) {
	var job db.BuildJob
	if err := db.DB.First(&job, jobID).Error; err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	registerBuildCancel(jobID, cancel)
	defer func() {
		cancel()
		unregisterBuildCancel(jobID)
	}()

	startedAt := time.Now()
	result := db.DB.Model(&db.BuildJob{}).Where("id = ? AND status = ?", jobID, "queued").Updates(map[string]interface{}{
		"status":     "running",
		"started_at": &startedAt,
		"log_tail":   "",
		"log_text":   "",
		"error":      "",
	})
	if result.Error != nil || result.RowsAffected == 0 {
		return
	}

	var output bytes.Buffer
	components := buildComponentsFromJSON(job.Components)
	nativeComponents := make([]string, 0, len(components))
	hasServerUI := false
	for _, component := range components {
		if component == "server-ui" {
			hasServerUI = true
		} else {
			nativeComponents = append(nativeComponents, component)
		}
	}
	var err error
	if len(nativeComponents) > 0 {
		args := []string{"--component", strings.Join(nativeComponents, ","), "--target", fmt.Sprintf("%s/%s", job.Platform, job.Arch)}
		if job.Pack {
			args = append([]string{"--pack"}, args...)
		}
		cmd := exec.CommandContext(ctx, "./build.sh", args...)
		cmd.Dir = "."
		cmd.Stdout = &output
		cmd.Stderr = &output
		err = cmd.Run()
	}
	if err == nil && hasServerUI {
		npm := exec.CommandContext(ctx, "npm", "--prefix", "server-ui", "run", "build")
		npm.Dir = "."
		npm.Stdout = &output
		npm.Stderr = &output
		err = npm.Run()
		if err == nil {
			_ = os.MkdirAll("./release", 0755)
			tarCmd := exec.CommandContext(ctx, "tar", "-czf", "release/server-ui-dist.tar.gz", "-C", "server-ui", "dist")
			tarCmd.Dir = "."
			tarCmd.Stdout = &output
			tarCmd.Stderr = &output
			err = tarCmd.Run()
		}
	}
	logText := output.String()
	logTail := truncateBuildLog(logText, 20000)
	finishedAt := time.Now()
	updates := map[string]interface{}{
		"finished_at": &finishedAt,
		"log_tail":    logTail,
		"log_text":    logText,
	}
	if err != nil {
		status := "failed"
		errMsg := err.Error()
		if ctx.Err() == context.DeadlineExceeded {
			errMsg = "build timed out after 30 minutes"
		} else if ctx.Err() == context.Canceled {
			status = "canceled"
			errMsg = "build canceled by user"
		}
		updates["status"] = status
		updates["error"] = errMsg
		db.DB.Model(&db.BuildJob{}).Where("id = ? AND status = ?", jobID, "running").Updates(updates)
		return
	}

	artifacts := expectedBuildArtifacts(components, job.Platform, job.Arch)
	store, storeErr := storage.NewLocalStore("./release")
	if storeErr != nil {
		updates["status"] = "failed"
		updates["error"] = fmt.Sprintf("build artifact storage is unavailable: %v", storeErr)
	} else {
		missing := make([]string, 0)
		for _, artifact := range artifacts {
			if _, ok, statErr := store.Exists(context.Background(), artifact); statErr != nil || !ok {
				missing = append(missing, artifact)
			}
		}
		if len(missing) > 0 {
			updates["status"] = "failed"
			updates["error"] = "build completed but expected artifacts were not found: " + strings.Join(missing, ", ")
			db.DB.Model(&db.BuildJob{}).Where("id = ? AND status = ?", jobID, "running").Updates(updates)
			return
		}
		artifactJSON, _ := json.Marshal(artifacts)
		updates["status"] = "success"
		updates["artifact"] = artifacts[0]
		updates["artifacts"] = string(artifactJSON)
		updates["error"] = ""
	}
	db.DB.Model(&db.BuildJob{}).Where("id = ? AND status = ?", jobID, "running").Updates(updates)
}

func expectedBuildArtifact(platform, arch string) string {
	name := fmt.Sprintf("dddd-agent-%s-%s", platform, arch)
	if platform == "windows" {
		name += ".exe"
	}
	return name
}

func truncateBuildLog(logText string, maxLen int) string {
	if len(logText) <= maxLen {
		return logText
	}
	return logText[len(logText)-maxLen:]
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

	pendingRecovery := &pendingRecoveryState{}
	_, err := recoverPendingTasksForQueueGeneration(ctx, q, pendingRecovery, time.Now())
	if err != nil {
		log.Printf("[DispatchRecover] initial pending reconciliation failed: %v", err)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			recoverQueueIfDead(q)
			recoverDispatchingTasks(q)
			recovered, err := recoverPendingTasksForQueueGeneration(ctx, q, pendingRecovery, time.Now())
			if err != nil {
				log.Printf("[DispatchRecover] pending reconciliation failed: %v", err)
			} else if recovered > 0 {
				log.Printf("[DispatchRecover] reconciled %d stranded pending subtasks", recovered)
			}
			handleTimeoutTasks(q)
			db.AutoDispatchCleanup()
		}
	}
}

func recoverQueueIfDead(q *scheduler.TaskQueue) {
	if q == nil {
		return
	}
	recovered, err := q.ForceRecover()
	if err != nil {
		log.Printf("[QueueRecover] RabbitMQ reconnect failed: %v", err)
		return
	}
	if recovered {
		log.Printf("[QueueRecover] RabbitMQ connection was dead -- rebuilt; stranded tasks will recover in next dispatch cycle")
	}
}

func recoverDispatchingTasks(q *scheduler.TaskQueue) {
	if q == nil {
		return
	}

	var subs []db.SubTask
	if err := db.DB.Where("status = ?", subTaskStatusDispatching).
		Order("updated_at asc").
		Limit(200).
		Find(&subs).Error; err != nil || len(subs) == 0 {
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

type pendingRecoveryState struct {
	token              string
	queuedRecoveryDone bool
}

func queuedMarkerForQueue(q *scheduler.TaskQueue) string {
	if q == nil {
		return subTaskQueuedMarker
	}
	token := q.RecoveryToken()
	if token == "" {
		return subTaskQueuedMarker
	}
	return subTaskQueuedMarker + ":" + token
}

func recoverPendingTasksForQueueGeneration(
	ctx context.Context,
	q *scheduler.TaskQueue,
	state *pendingRecoveryState,
	now time.Time,
) (int, error) {
	if q == nil {
		return 0, nil
	}
	token := q.RecoveryToken()
	if token == "" {
		return 0, nil
	}
	if state.token != token {
		state.token = token
		state.queuedRecoveryDone = q.Mode() != "memory"
	}

	totalPushed := 0
	dispatchClaimed := func(subs []db.SubTask) {
		if len(subs) == 0 {
			return
		}
		pushedByPriority, dispatchPending := dispatchSubTasks(ctx, q, subs)
		pushedCount := totalDispatchedTasks(pushedByPriority)
		totalPushed += pushedCount
		if pushedCount > 0 {
			broadcastDispatchedTasks(pushedByPriority)
		}
		log.Printf("[DispatchRecover] stranded-pending claimed=%d dispatched=%d pending=%d", len(subs), pushedCount, dispatchPending)
	}

	// The in-memory queue is intentionally ephemeral. For each new lifecycle,
	// drain queued markers that predate the lifecycle boundary. Keep this phase
	// retryable until a complete empty batch confirms that all rows were handled.
	for !state.queuedRecoveryDone {
		if err := ctx.Err(); err != nil {
			return totalPushed, err
		}
		subs, claimErr := claimStrandedPendingSubTasks(ctx, time.Time{}, 200, true, queuedMarkerForQueue(q))
		dispatchClaimed(subs)
		if claimErr != nil {
			return totalPushed, claimErr
		}
		if len(subs) == 0 {
			state.queuedRecoveryDone = true
		}
	}

	// Empty markers are scanned every cycle. This covers rows that become stale
	// after the queue generation was first observed without duplicating queued rows.
	for {
		if err := ctx.Err(); err != nil {
			return totalPushed, err
		}
		subs, claimErr := claimStrandedPendingSubTasks(ctx, now.Add(-strandedPendingGrace), 200, false, "")
		dispatchClaimed(subs)
		if claimErr != nil {
			return totalPushed, claimErr
		}
		if len(subs) == 0 {
			break
		}
	}
	return totalPushed, nil
}

func claimStrandedPendingSubTasks(
	ctx context.Context,
	cutoff time.Time,
	limit int,
	queuedOnly bool,
	currentQueuedMarker string,
) ([]db.SubTask, error) {
	var candidates []db.SubTask
	store := db.DB.WithContext(ctx)
	query := store.Where(
		"status = ? AND updated_at < ? AND agent_id = '' AND stream_msg_id = ''",
		"Pending", cutoff,
	)
	if queuedOnly {
		query = store.Where(
			"status = ? AND agent_id = '' AND (stream_msg_id = ? OR (stream_msg_id LIKE ? AND stream_msg_id <> ?))",
			"Pending", subTaskQueuedMarker, subTaskQueuedMarker+":%", currentQueuedMarker,
		)
	}
	query = query.Order("updated_at asc")
	if limit > 0 {
		query = query.Limit(limit)
	}
	if err := query.Find(&candidates).Error; err != nil {
		return nil, err
	}

	claimed := make([]db.SubTask, 0, len(candidates))
	for _, sub := range candidates {
		claimQuery := store.Model(&db.SubTask{}).
			Where("id = ? AND status = ? AND agent_id = '' AND stream_msg_id = ?", sub.ID, "Pending", sub.StreamMsgID)
		if !queuedOnly {
			claimQuery = claimQuery.Where("updated_at < ?", cutoff)
		}
		result := claimQuery.Update("status", subTaskStatusDispatching)
		if result.Error != nil {
			return claimed, result.Error
		}
		if result.RowsAffected == 0 {
			continue
		}
		sub.Status = subTaskStatusDispatching
		claimed = append(claimed, sub)
	}
	return claimed, nil
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
	projectID, ok := statsProjectID(c)
	if !ok {
		c.JSON(http.StatusOK, []db.TrendPoint{})
		return
	}
	days := 30
	if d := c.Query("days"); d != "" {
		if v, err := strconv.Atoi(d); err == nil && v > 0 {
			days = v
		}
	}
	c.JSON(http.StatusOK, db.GetVulnTrends(tenantID, projectID, days))
}

func getSeverityDistribution(c *gin.Context) {
	projectID, ok := statsProjectID(c)
	if !ok {
		c.JSON(http.StatusOK, []db.SeverityCount{})
		return
	}
	c.JSON(http.StatusOK, db.GetSeverityDistribution(currentTenantID(c), projectID))
}

func getTaskResultStats(c *gin.Context) {
	tenantID := currentTenantID(c)
	projectID, ok := statsProjectID(c)
	if !ok {
		c.JSON(http.StatusOK, []db.TaskStats{})
		return
	}
	limit := 20
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 {
			limit = v
		}
	}
	c.JSON(http.StatusOK, db.GetTaskResultStats(tenantID, projectID, limit))
}

func getRecentHighVulns(c *gin.Context) {
	tenantID := currentTenantID(c)
	projectID, ok := statsProjectID(c)
	if !ok {
		c.JSON(http.StatusOK, []db.Vulnerability{})
		return
	}
	limit := 10
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 {
			limit = v
		}
	}
	c.JSON(http.StatusOK, db.GetRecentHighVulns(tenantID, projectID, limit))
}

// ==================== Agent 遥测日志 ====================

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

func StartAgentLogRetentionDaemon(ctx context.Context) {
	if deleted, err := cleanupAgentLogsOnce(0); err != nil {
		log.Printf("[AgentLogRetention] cleanup failed: %v", err)
	} else if deleted > 0 {
		log.Printf("[AgentLogRetention] cleaned %d expired logs", deleted)
	}

	ticker := time.NewTicker(1 * time.Hour)
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
	store, err := storage.NewLocalStore(objectStorageRoot)
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
	if !canAccessProject(c, rootTask.ProjectID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "project not accessible"})
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
	db.DB.Model(&db.SubTask{}).Where("root_task_id = ? AND tenant_id = ?", rootTaskID, tenantID).Count(&existingCount)
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

	tenantID := currentTenantID(c)
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
			WHERE tenant_id = ? AND status IN ('Pending', 'Dispatching', 'Running', 'Recovered')
			GROUP BY status
		`, tenantID).Scan(&results)
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
