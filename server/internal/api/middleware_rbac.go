package api

import (
	"net/http"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
)

// 角色权限矩阵
// 格式: "METHOD:/path" => 允许的最低角色
// 角色层级: admin > operator > viewer
//
// 租户隔离由 TenantMiddleware 注入 tenant_id 后在各 handler 查询中强制过滤。
// 这里仅表达同一租户内的功能权限；未声明的新接口默认按 admin 处理。
var roleHierarchy = map[string]int{
	"admin":    3,
	"operator": 2,
	"viewer":   1,
}

// 权限映射：endpoint pattern => 最低角色
var permissionRules = map[string]string{
	// 只读查询：viewer 起可用，仅返回当前 tenant_id 范围内数据。
	"GET:/projects":                "viewer",
	"GET:/tasks":                   "viewer",
	"GET:/tasks/*":                 "viewer",
	"GET:/nodes":                   "viewer",
	"GET:/vulns":                   "viewer",
	"GET:/assets":                  "viewer",
	"GET:/fingerprints":            "viewer",
	"GET:/profiles":                "viewer",
	"GET:/stats":                   "viewer",
	"GET:/stats/trends":            "viewer",
	"GET:/stats/severity":          "viewer",
	"GET:/stats/task-results":      "viewer",
	"GET:/stats/recent-high-vulns": "viewer",
	"GET:/reports/export/vulns":    "viewer",
	"GET:/arsenals/*":              "viewer",
	"GET:/dictionaries/*":          "viewer",
	"GET:/ws":                      "viewer",

	// 日常操作：operator 可创建项目、下发/调整任务、维护草稿规则与字典。
	"GET:/queue/depth":                "operator",
	"GET:/agents/*/logs":              "operator",
	"POST:/projects":                  "operator",
	"PUT:/projects/*":                 "operator",
	"DELETE:/projects/*":              "operator",
	"GET:/projects/*/stats":           "operator",
	"POST:/tasks":                     "operator",
	"POST:/tasks/*/append":            "operator",
	"POST:/tasks/*/cancel":            "operator",
	"DELETE:/tasks/*":                 "operator",
	"DELETE:/nodes/*":                 "operator",
	"POST:/nodes/clean":               "operator",
	"POST:/arsenals/*":                "operator",
	"POST:/arsenals/ai/analyze":       "operator",
	"DELETE:/arsenals/*":              "operator",
	"POST:/dictionaries/*":            "operator",
	"PUT:/dictionaries/*":             "operator",
	"DELETE:/dictionaries/*":          "operator",
	"POST:/ai/arsenal/analyze":        "operator",
	"POST:/ai/arsenal/analyze/stream": "operator",
	"POST:/ai/chat":                   "operator",
	"POST:/ai/actions/confirm":        "operator",
	"GET:/ai/copilot/prompts":         "operator",
	"GET:/ai/tool-invocations":        "operator",
	"GET:/cloud/*":                    "operator",
	"POST:/cloud/*":                   "operator",
	"PUT:/cloud/*":                    "operator",
	"DELETE:/cloud/*":                 "operator",

	// 管理动作：admin only。更具体的规则会覆盖上面的 operator 通配符。
	"POST:/arsenals/*/*/approve":  "admin",
	"POST:/arsenals/*/*/rollback": "admin",
	"GET:/arsenals/seed-db":       "admin",
	"GET:/build/artifacts":        "admin",
	"POST:/build/client":          "admin",
	"GET:/users":                  "admin",
	"POST:/users":                 "admin",
	"PUT:/users/*":                "admin",
	"DELETE:/users/*":             "admin",
	"GET:/projects/*/members":     "admin",
	"PUT:/projects/*/members":     "admin",
	"GET:/mcp/keys":               "admin",
	"POST:/mcp/keys":              "admin",
	"DELETE:/mcp/keys/*":          "admin",
	"GET:/config/api-keys":        "admin",
	"PUT:/config/api-keys":        "admin",
	"GET:/ai/config":              "admin",
	"PUT:/ai/config":              "admin",
	"GET:/ai/models":              "admin",
	"POST:/ai/test":               "admin",
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

	// 通配符匹配：支持多段匹配，按 pattern 长度降序选择最具体规则。
	type candidate struct {
		pattern string
		role    string
	}
	var candidates []candidate
	for ruleKey, role := range permissionRules {
		parts := strings.SplitN(ruleKey, ":", 2)
		if len(parts) != 2 {
			continue
		}
		if parts[0] != method {
			continue
		}
		pattern := parts[1]
		if wildcardPathMatch(pattern, cleanPath) {
			candidates = append(candidates, candidate{pattern: pattern, role: role})
		}
	}
	if len(candidates) > 0 {
		sort.Slice(candidates, func(i, j int) bool {
			return len(candidates[i].pattern) > len(candidates[j].pattern)
		})
		return candidates[0].role
	}

	// 默认最小权限：未显式声明的接口按 admin 处理，避免新增路由时误开放。
	return "admin"
}

// wildcardPathMatch 判断规则 pattern 是否匹配实际 path。
// 规则:
// 1) pattern 末尾为 "/*" 时，匹配该前缀下任意深度路径；
// 2) 其余情况按路径段匹配，"*" 表示当前段任意值。
func wildcardPathMatch(pattern string, path string) bool {
	if pattern == path {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		base := strings.TrimSuffix(pattern, "/*")
		if path == base {
			return true
		}
		return strings.HasPrefix(path, base+"/")
	}

	patternParts := strings.Split(strings.Trim(pattern, "/"), "/")
	pathParts := strings.Split(strings.Trim(path, "/"), "/")
	if len(patternParts) != len(pathParts) {
		return false
	}
	for i := range patternParts {
		if patternParts[i] == "*" {
			continue
		}
		if patternParts[i] != pathParts[i] {
			return false
		}
	}
	return true
}
