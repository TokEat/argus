package api

import (
	"encoding/json"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/user/dddd-server/internal/db"
)

var customRoleNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,31}$`)

type roleResp struct {
	ID          uint     `json:"id,omitempty"`
	Name        string   `json:"name"`
	Label       string   `json:"label"`
	Description string   `json:"description"`
	BaseRole    string   `json:"base_role"`
	Permissions []string `json:"permissions"`
	Builtin     bool     `json:"builtin"`
	CreatedAt   string   `json:"created_at,omitempty"`
	UpdatedAt   string   `json:"updated_at,omitempty"`
}

type roleRequest struct {
	Name        string   `json:"name"`
	Label       string   `json:"label"`
	Description string   `json:"description"`
	BaseRole    string   `json:"base_role"`
	Permissions []string `json:"permissions"`
}

var builtinRoleDescriptions = map[string]roleResp{
	"admin": {
		Name:        "admin",
		Label:       "管理员",
		Description: "当前租户最高权限，可管理用户、角色、系统配置、云资源、规则审批和构建产物。",
		BaseRole:    "admin",
		Builtin:     true,
	},
	"operator": {
		Name:        "operator",
		Label:       "操作员",
		Description: "负责项目、扫描任务、节点运维、草稿规则维护、Agent 日志和 AI 辅助操作。",
		BaseRole:    "operator",
		Builtin:     true,
	},
	"viewer": {
		Name:        "viewer",
		Label:       "观察者",
		Description: "只读查看当前租户的仪表盘、项目、任务、节点、资产漏洞结果和报表。",
		BaseRole:    "viewer",
		Builtin:     true,
	},
}

func listRoles(c *gin.Context) {
	tenantID := currentTenantID(c)
	resp := []roleResp{
		builtinRoleResponse("admin"),
		builtinRoleResponse("operator"),
		builtinRoleResponse("viewer"),
	}

	var roles []db.CustomRole
	if err := db.DB.Where("tenant_id = ?", tenantID).Order("name ASC").Find(&roles).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list roles"})
		return
	}
	for _, role := range roles {
		resp = append(resp, customRoleResponse(role))
	}

	c.JSON(http.StatusOK, gin.H{
		"roles":      resp,
		"matrix":     rolePermissionMatrix(),
		"base_roles": []string{"viewer", "operator", "admin"},
	})
}

func createRole(c *gin.Context) {
	tenantID := currentTenantID(c)
	var req roleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	role, ok := buildCustomRoleFromRequest(tenantID, req, "")
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role name must match ^[a-z][a-z0-9_-]{1,31}$, must not be built-in, and base_role must be admin/operator/viewer"})
		return
	}
	if err := db.DB.Create(&role).Error; err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "role already exists"})
		return
	}
	c.JSON(http.StatusOK, customRoleResponse(role))
}

func updateRole(c *gin.Context) {
	tenantID := currentTenantID(c)
	name := strings.TrimSpace(c.Param("name"))
	if _, builtin := roleHierarchy[name]; builtin {
		c.JSON(http.StatusBadRequest, gin.H{"error": "built-in roles cannot be modified"})
		return
	}

	var existing db.CustomRole
	if err := db.DB.Where("tenant_id = ? AND name = ?", tenantID, name).First(&existing).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "role not found"})
		return
	}

	var req roleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	role, ok := buildCustomRoleFromRequest(tenantID, req, name)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "base_role must be admin/operator/viewer"})
		return
	}

	existing.Label = role.Label
	existing.Description = role.Description
	existing.BaseRole = role.BaseRole
	existing.Permissions = role.Permissions
	if err := db.DB.Save(&existing).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update role"})
		return
	}
	c.JSON(http.StatusOK, customRoleResponse(existing))
}

func deleteRole(c *gin.Context) {
	tenantID := currentTenantID(c)
	name := strings.TrimSpace(c.Param("name"))
	if _, builtin := roleHierarchy[name]; builtin {
		c.JSON(http.StatusBadRequest, gin.H{"error": "built-in roles cannot be deleted"})
		return
	}
	var role db.CustomRole
	if err := db.DB.Where("tenant_id = ? AND name = ?", tenantID, name).First(&role).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "role not found"})
		return
	}
	var users int64
	db.DB.Model(&db.User{}).Where("tenant_id = ? AND role = ?", tenantID, name).Count(&users)
	if users > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "role is assigned to users"})
		return
	}
	if err := db.DB.Delete(&role).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete role"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func buildCustomRoleFromRequest(tenantID string, req roleRequest, pathName string) (db.CustomRole, bool) {
	name := strings.TrimSpace(req.Name)
	if pathName != "" {
		name = pathName
	}
	baseRole := strings.TrimSpace(req.BaseRole)
	if baseRole == "" {
		baseRole = "viewer"
	}
	if _, ok := roleHierarchy[baseRole]; !ok {
		return db.CustomRole{}, false
	}
	if pathName == "" {
		if !customRoleNamePattern.MatchString(name) {
			return db.CustomRole{}, false
		}
		if _, builtin := roleHierarchy[name]; builtin {
			return db.CustomRole{}, false
		}
	}
	permissions := req.Permissions
	if len(permissions) == 0 {
		permissions = permissionsForBaseRole(baseRole)
	}
	permissionBytes, _ := json.Marshal(permissions)
	label := strings.TrimSpace(req.Label)
	if label == "" {
		label = name
	}
	return db.CustomRole{
		TenantID:    tenantID,
		Name:        name,
		Label:       label,
		Description: strings.TrimSpace(req.Description),
		BaseRole:    baseRole,
		Permissions: string(permissionBytes),
	}, true
}

func builtinRoleResponse(role string) roleResp {
	resp := builtinRoleDescriptions[role]
	resp.Permissions = permissionsForBaseRole(role)
	return resp
}

func customRoleResponse(role db.CustomRole) roleResp {
	permissions := []string{}
	if strings.TrimSpace(role.Permissions) != "" {
		_ = json.Unmarshal([]byte(role.Permissions), &permissions)
	}
	if len(permissions) == 0 {
		permissions = permissionsForBaseRole(role.BaseRole)
	}
	return roleResp{
		ID:          role.ID,
		Name:        role.Name,
		Label:       fallbackString(role.Label, role.Name),
		Description: role.Description,
		BaseRole:    fallbackString(role.BaseRole, "viewer"),
		Permissions: permissions,
		Builtin:     false,
		CreatedAt:   formatRoleTime(role.CreatedAt),
		UpdatedAt:   formatRoleTime(role.UpdatedAt),
	}
}

func permissionsForBaseRole(baseRole string) []string {
	baseLevel := roleHierarchy[baseRole]
	if baseLevel == 0 {
		baseLevel = roleHierarchy["viewer"]
	}
	permissions := make([]string, 0, len(permissionRules))
	for key, requiredRole := range permissionRules {
		if roleHierarchy[requiredRole] <= baseLevel {
			permissions = append(permissions, key)
		}
	}
	sort.Strings(permissions)
	return permissions
}

func rolePermissionMatrix() map[string][]string {
	return map[string][]string{
		"viewer":   permissionsForBaseRole("viewer"),
		"operator": permissionsForBaseRole("operator"),
		"admin":    permissionsForBaseRole("admin"),
	}
}

func baseRoleForToken(tenantID, role string) string {
	role = strings.TrimSpace(role)
	if _, ok := roleHierarchy[role]; ok {
		return role
	}
	baseRole := customRoleBaseRole(tenantID, role)
	if _, ok := roleHierarchy[baseRole]; ok {
		return baseRole
	}
	return "viewer"
}

func fallbackString(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func formatRoleTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}
