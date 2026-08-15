package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/P0lar1ght/argus/server/internal/db"
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
	"GET:/projects": "viewer",
	"GET:/tasks":    "viewer",
	"GET:/tasks/*":  "viewer",
	"GET:/projects/*/asset-discovery/queries":          "viewer",
	"GET:/projects/*/asset-discovery/queries/*":        "viewer",
	"GET:/projects/*/asset-discovery/queries/*/export": "viewer",
	"GET:/projects/*/asset-discovery/notebook-items":   "viewer",
	"GET:/asset-discovery/notebook-items":              "viewer",

	// This POST computes a read-only, version-bound preview and never schedules work.
	"POST:/tasks/*/risk-validation/preview": "viewer",
	"POST:/tasks/*/risk-validation":         "operator",

	"GET:/nodes":                          "viewer",
	"GET:/vulns":                          "viewer",
	"GET:/assets":                         "viewer",
	"GET:/fingerprints":                   "viewer",
	"GET:/profiles":                       "viewer",
	"GET:/poc-rules":                      "viewer",
	"GET:/active-fingerprint-rules":       "viewer",
	"POST:/exp-egress-routes":             "operator",
	"DELETE:/exp-egress-routes/*":         "operator",
	"GET:/exp-egress-audits":              "admin",
	"GET:/exp-egress-audits/*":            "admin",
	"GET:/exps":                           "operator",
	"GET:/exps/*":                         "operator",
	"POST:/exps":                          "operator",
	"PATCH:/exps/*":                       "operator",
	"DELETE:/exps/*":                      "admin",
	"GET:/exps/*/audits":                  "admin",
	"GET:/exps/*/risk-waiver":             "admin",
	"PUT:/exps/*/risk-waiver":             "admin",
	"DELETE:/exps/*/risk-waiver":          "admin",
	"POST:/exps/*/revisions":              "operator",
	"POST:/exps/*/draft/inspect":          "operator",
	"POST:/exps/*/draft/validate":         "operator",
	"POST:/exps/*/draft/test":             "operator",
	"POST:/exps/*/revisions/*/inspect":    "operator",
	"POST:/exps/*/revisions/*/validate":   "operator",
	"POST:/exps/*/revisions/*/runs":       "operator",
	"POST:/exps/*/revisions/*/test-cases": "operator",
	"PATCH:/exps/*/test-cases/*":          "operator",
	"DELETE:/exps/*/test-cases/*":         "operator",
	"POST:/exps/*/revisions/*/publish":    "admin",
	"POST:/exps/*/active-revision":        "admin",
	"GET:/exp-runs":                       "operator",
	"GET:/exp-runs/*":                     "operator",
	"POST:/exp-runs/*/cancel":             "operator",
	"GET:/exp-assets":                     "operator",
	"GET:/exp-assets/*":                   "operator",
	"POST:/exp-assets":                    "operator",
	"DELETE:/exp-assets/*":                "admin",
	"GET:/stats":                          "viewer",
	"GET:/stats/trends":                   "viewer",
	"GET:/stats/severity":                 "viewer",
	"GET:/stats/task-results":             "viewer",
	"GET:/stats/recent-high-vulns":        "viewer",
	"GET:/reports/export/vulns":           "viewer",
	"GET:/reports/export/assets":          "viewer",
	"GET:/reports/export/fingerprints":    "viewer",
	"GET:/arsenals/*":                     "admin",
	"GET:/dictionaries/*":                 "admin",
	"GET:/ws":                             "viewer",

	// 日常操作：operator 可创建项目、下发/调整任务和执行受控 MCP 草稿操作。
	"POST:/projects/*/asset-discovery/fofa/query":                     "operator",
	"POST:/projects/*/asset-discovery/hunter/query":                   "operator",
	"POST:/projects/*/asset-discovery/quake/query":                    "operator",
	"POST:/projects/*/asset-discovery/queries/*/notebook-items":       "operator",
	"POST:/projects/*/asset-discovery/notebook-distributions/preview": "operator",
	"POST:/projects/*/asset-discovery/notebook-distributions":         "operator",
	"PATCH:/projects/*/asset-discovery/notebook-items/*":              "operator",
	"POST:/projects/*/asset-discovery/notebook-items/*/remove":        "operator",
	"POST:/projects/*/asset-discovery/notebook-items/*/restore":       "operator",

	"GET:/queue/depth":                                     "operator",
	"GET:/agents/*/logs":                                   "operator",
	"GET:/mcp/resources/*":                                 "operator",
	"POST:/mcp/tools/poc/debug":                            "operator",
	"POST:/mcp/tools/poc/save-draft":                       "operator",
	"POST:/mcp/tools/rule/context":                         "operator",
	"POST:/mcp/tools/rule/debug":                           "operator",
	"POST:/mcp/tools/rule/save":                            "operator",
	"POST:/mcp/tools/rule/apply":                           "admin",
	"POST:/projects":                                       "operator",
	"PUT:/projects/*":                                      "operator",
	"DELETE:/projects/*":                                   "operator",
	"GET:/projects/*/stats":                                "operator",
	"POST:/tasks":                                          "operator",
	"POST:/tasks/preview-selector":                         "operator",
	"POST:/tasks/plan-preview":                             "operator",
	"GET:/projects/*/credential-dictionaries":              "viewer",
	"POST:/projects/*/credential-dictionaries":             "operator",
	"POST:/projects/*/credential-dictionaries/*/revisions": "operator",
	"DELETE:/projects/*/credential-dictionaries/*":         "operator",
	"POST:/credential-findings/*/reveal":                   "admin",
	"GET:/tasks/*/credential-findings":                     "viewer",
	"POST:/tasks/validate-targets":                         "operator",
	"POST:/tasks/*/append":                                 "operator",
	"POST:/tasks/*/cancel":                                 "operator",
	"POST:/tasks/*/stop":                                   "operator",
	"POST:/tasks/*/pause":                                  "operator",
	"POST:/tasks/*/resume":                                 "operator",
	"POST:/tasks/*/retry":                                  "operator",
	"POST:/tasks/*/batches/*/pause":                        "operator",
	"POST:/tasks/*/batches/*/resume":                       "operator",
	"POST:/tasks/*/batches/*/stop":                         "operator",
	"POST:/tasks/*/batches/*/retry":                        "operator",
	"PUT:/tasks/*/config":                                  "operator",
	"DELETE:/tasks/*":                                      "operator",
	"DELETE:/tasks/*/batches/*":                            "operator",
	"DELETE:/nodes/*":                                      "operator",
	"POST:/nodes/*/revoke-token":                           "admin",
	"POST:/nodes/clean":                                    "operator",
	"POST:/arsenals/*":                                     "admin",
	"POST:/arsenals/ai/analyze":                            "admin",
	"DELETE:/arsenals/*":                                   "admin",
	"POST:/dictionaries/*":                                 "admin",
	"PUT:/dictionaries/*":                                  "admin",
	"DELETE:/dictionaries/*":                               "admin",
	"POST:/ai/arsenal/analyze":                             "admin",
	"POST:/ai/arsenal/analyze/stream":                      "admin",
	"POST:/ai/chat":                                        "operator",
	"POST:/ai/actions/confirm":                             "operator",
	"GET:/ai/copilot/prompts":                              "operator",
	"GET:/ai/tool-invocations":                             "operator",
	"GET:/agent-logs/summary":                              "operator",
	"GET:/agent-logs/retention":                            "operator",
	"PUT:/agent-logs/retention":                            "admin",
	"GET:/agent-logs/alerts":                               "operator",
	"GET:/agent-logs/alert-rules":                          "operator",
	"POST:/agent-logs/alert-rules":                         "admin",
	"DELETE:/agent-logs/alert-rules/*":                     "admin",
	"POST:/agent-logs/archive":                             "admin",
	"GET:/cloud/*":                                         "operator",
	"POST:/cloud/*":                                        "operator",
	"PUT:/cloud/*":                                         "operator",
	"DELETE:/cloud/*":                                      "operator",
	"GET:/users":                                           "operator",

	// 管理动作：admin only。更具体的规则会覆盖上面的 operator 通配符。
	"POST:/arsenals/*/*/approve":   "admin",
	"POST:/arsenals/*/*/deprecate": "admin",
	"POST:/arsenals/*/*/rollback":  "admin",
	"GET:/arsenals/seed-db":        "admin",
	"GET:/build/artifacts":         "admin",
	"GET:/build/jobs":              "admin",
	"GET:/build/jobs/*":            "admin",
	"POST:/build/client":           "admin",
	"POST:/build/jobs/*/cancel":    "admin",
	"POST:/build/jobs/*/retry":     "admin",
	"POST:/users":                  "admin",
	"PUT:/users/*":                 "admin",
	"DELETE:/users/*":              "admin",
	"GET:/roles":                   "admin",
	"POST:/roles":                  "admin",
	"PUT:/roles/*":                 "admin",
	"DELETE:/roles/*":              "admin",
	"GET:/tenants/*/quotas":        "admin",
	"PUT:/tenants/*/quotas":        "admin",
	"GET:/projects/*/members":      "operator",
	"PUT:/projects/*/members":      "operator",
	"GET:/mcp/keys":                "admin",
	"POST:/mcp/keys":               "admin",
	"DELETE:/mcp/keys/*":           "admin",
	"GET:/config/api-keys":         "admin",
	"PUT:/config/api-keys":         "admin",
	"GET:/ai/config":               "admin",
	"PUT:/ai/config":               "admin",
	"GET:/ai/models":               "admin",
	"POST:/ai/test":                "admin",
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

		userLevel := roleLevelForTenant(currentTenantID(c), roleStr)

		// 检查权限
		requiredRole := matchPermission(c.Request.Method, c.Request.URL.Path)
		requiredLevel := roleHierarchy[requiredRole]

		if requiredLevel > 0 && userLevel < requiredLevel {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Insufficient permissions. Required role: " + requiredRole,
			})
			return
		}
		if !customRoleAllowsRequest(currentTenantID(c), roleStr, c.Request.Method, c.Request.URL.Path) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Insufficient permissions for custom role",
			})
			return
		}
		if isEXPEndpoint(c.Request.URL.Path) && !currentUserHasEXPAuthorization(c) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "EXP access requires user-level authorization",
			})
			return
		}

		c.Next()
	}
}

func customRoleAllowsRequest(tenantID, role, method, path string) bool {
	if _, builtin := roleHierarchy[strings.TrimSpace(role)]; builtin {
		return true
	}
	permissions, hasCustom := customRolePermissions(tenantID, role)
	if !hasCustom {
		return false
	}
	if len(permissions) == 0 {
		return false
	}
	cleanPath := strings.TrimPrefix(path, "/api/v1")
	for _, ruleKey := range permissions {
		parts := strings.SplitN(ruleKey, ":", 2)
		if len(parts) != 2 || parts[0] != method {
			continue
		}
		if wildcardPathMatch(parts[1], cleanPath) {
			return true
		}
	}
	return false
}

func customRolePermissions(tenantID, role string) ([]string, bool) {
	if db.DB == nil {
		return nil, false
	}
	var custom db.CustomRole
	err := db.DB.Select("permissions").
		Where("tenant_id = ? AND name = ?", fallbackTenantID(tenantID), strings.TrimSpace(role)).
		First(&custom).Error
	if err != nil {
		return nil, false
	}
	var permissions []string
	_ = json.Unmarshal([]byte(custom.Permissions), &permissions)
	return permissions, true
}

func roleLevelForTenant(tenantID, role string) int {
	role = strings.TrimSpace(role)
	if role == "" {
		role = "viewer"
	}
	if level := roleHierarchy[role]; level > 0 {
		return level
	}
	baseRole := customRoleBaseRole(tenantID, role)
	if level := roleHierarchy[baseRole]; level > 0 {
		return level
	}
	return roleHierarchy["viewer"]
}

func customRoleBaseRole(tenantID, role string) string {
	if db.DB == nil {
		return ""
	}
	tenantID = strings.TrimSpace(tenantID)
	tenantID = fallbackTenantID(tenantID)
	var custom db.CustomRole
	err := db.DB.Select("base_role").
		Where("tenant_id = ? AND name = ?", tenantID, strings.TrimSpace(role)).
		First(&custom).Error
	if err != nil {
		return ""
	}
	return strings.TrimSpace(custom.BaseRole)
}

func fallbackTenantID(tenantID string) string {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return "default"
	}
	return tenantID
}

func isEXPEndpoint(path string) bool {
	cleanPath := strings.TrimPrefix(path, "/api/v1")
	return strings.HasPrefix(cleanPath, "/exp-egress-") ||
		cleanPath == "/exps" || strings.HasPrefix(cleanPath, "/exps/") ||
		cleanPath == "/exp-runs" || strings.HasPrefix(cleanPath, "/exp-runs/") ||
		cleanPath == "/exp-assets" || strings.HasPrefix(cleanPath, "/exp-assets/")
}

func currentUserHasEXPAuthorization(c *gin.Context) bool {
	claimAuthorized := false
	if authorized, ok := c.Get("exp_authorized"); ok {
		claimAuthorized, _ = authorized.(bool)
	}
	userID := currentUserID(c)
	if userID == "" {
		return claimAuthorized
	}
	id, err := strconv.ParseUint(userID, 10, 64)
	if err != nil {
		return claimAuthorized
	}
	if db.DB == nil {
		return claimAuthorized
	}
	var user db.User
	if err := db.DB.Select("id", "exp_authorized").
		Where("id = ? AND tenant_id = ? AND status = ?", id, currentTenantID(c), "active").
		First(&user).Error; err != nil {
		return false
	}
	return user.ExpAuthorized
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
		if !strings.Contains(base, "*") {
			if path == base {
				return true
			}
			return strings.HasPrefix(path, base+"/")
		}
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
