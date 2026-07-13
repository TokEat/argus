package api

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/user/dddd-server/internal/db"
	grpcpkg "github.com/user/dddd-server/internal/grpc"
	"github.com/user/dddd-server/internal/scheduler"
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

// NewRouter 构建 Gin 路由，不启动监听或后台 goroutine。
func NewRouter() *gin.Engine {
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

	api := r.Group("/api/v1")
	api.Use(TenantMiddleware())
	api.Use(RBACMiddleware())
	registerAPIV1Routes(api)

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

	return r
}

func InitRouter(port string) {
	// 启动 WebSocket 广播中心并连接底层实时推流 Hook。
	go Hub.Start()
	db.WSBroadcastHook = Hub.BroadcastToTenant

	r := NewRouter()
	log.Printf("Starting API Server on %s", port)
	if err := r.Run(port); err != nil {
		log.Fatalf("API server failed: %v", err)
	}
}

func init() {
	// 注册 release 目录为静态文件服务（供前端下载）
	_ = os.MkdirAll("./release", 0755)
}
