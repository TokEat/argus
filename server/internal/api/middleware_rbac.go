package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// 角色权限矩阵
// 格式: "domain:action" => 允许的最低角色
// 角色层级: admin > operator > viewer
var roleHierarchy = map[string]int{
	"admin":    3,
	"operator": 2,
	"viewer":   1,
}

// 权限映射：endpoint pattern => 最低角色
var permissionRules = map[string]string{
	// 读操作 — viewer 即可
	"GET:/tasks":        "viewer",
	"GET:/nodes":        "viewer",
	"GET:/vulns":        "viewer",
	"GET:/assets":       "viewer",
	"GET:/fingerprints": "viewer",
	"GET:/profiles":     "viewer",
	"GET:/stats":        "viewer",
	"GET:/ws":           "viewer",

	// 操作类 — operator 以上
	"POST:/tasks":          "operator",
	"POST:/tasks/*/cancel": "operator",
	"DELETE:/tasks/*":      "operator",
	"POST:/arsenals/*":     "operator",
	"DELETE:/arsenals/*":   "operator",
	"POST:/build/client":   "operator",

	// 管理类 — admin only
	"POST:/users":       "admin",
	"PUT:/users/*":      "admin",
	"DELETE:/users/*":   "admin",
	"POST:/mcp/keys":    "admin",
	"DELETE:/mcp/keys/*":"admin",
	"POST:/cloud/*":     "admin",
	"DELETE:/cloud/*":   "admin",
}

// RBACMiddleware 基于角色的访问控制中间件
func RBACMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 跳过登录接口
		if c.Request.URL.Path == "/api/v1/auth/login" {
			c.Next()
			return
		}

		// 从 context 获取角色（由 TenantMiddleware 注入）
		role, exists := c.Get("role")
		if !exists {
			// 兼容旧版本：未设置角色时默认 admin
			role = "admin"
		}

		roleStr, ok := role.(string)
		if !ok || roleStr == "" {
			roleStr = "viewer"
		}

		userLevel := roleHierarchy[roleStr]
		if userLevel == 0 {
			userLevel = 1 // 未知角色按 viewer 处理
		}

		// 检查权限
		requiredRole := matchPermission(c.Request.Method, c.Request.URL.Path)
		requiredLevel := roleHierarchy[requiredRole]

		if requiredLevel > 0 && userLevel < requiredLevel {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Insufficient permissions. Required role: " + requiredRole,
			})
			return
		}

		c.Next()
	}
}

// matchPermission 匹配请求路径到所需权限
func matchPermission(method string, path string) string {
	// 去掉 API 前缀
	cleanPath := strings.TrimPrefix(path, "/api/v1")

	// 精确匹配
	key := method + ":" + cleanPath
	if role, ok := permissionRules[key]; ok {
		return role
	}

	// 通配符匹配：逐级替换路径段为 *
	parts := strings.Split(cleanPath, "/")
	for i := len(parts) - 1; i >= 1; i-- {
		pattern := make([]string, len(parts))
		copy(pattern, parts)
		pattern[i] = "*"
		key = method + ":" + strings.Join(pattern, "/")
		if role, ok := permissionRules[key]; ok {
			return role
		}
	}

	// 默认：GET 请求 viewer 可访问，其他需要 operator
	if method == "GET" {
		return "viewer"
	}
	return "operator"
}
