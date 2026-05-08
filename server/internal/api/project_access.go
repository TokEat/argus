package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/user/dddd-server/internal/db"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func scopedProjectsQuery(c *gin.Context) *gorm.DB {
	tenantID := currentTenantID(c)
	q := db.DB.Where("tenant_id = ?", tenantID)
	if currentUserIsAdmin(c) {
		return q
	}
	userID := currentUserID(c)
	if userID == "" {
		return q.Where("1 = 0")
	}
	memberSubquery := db.DB.Model(&db.ProjectMember{}).
		Select("project_id").
		Where("tenant_id = ? AND user_id = ?", tenantID, userID)
	return q.Where("owner_user_id = ? OR id IN (?)", userID, memberSubquery)
}

func accessibleProjectIDs(c *gin.Context) []string {
	var ids []string
	if err := scopedProjectsQuery(c).Model(&db.Project{}).Pluck("id", &ids).Error; err != nil {
		return []string{}
	}
	return ids
}

func applyProjectScope(c *gin.Context, q *gorm.DB, column string) (*gorm.DB, bool) {
	projectID := strings.TrimSpace(c.Query("project_id"))
	if projectID != "" {
		if !canAccessProject(c, projectID) {
			return q.Where("1 = 0"), false
		}
		return q.Where(column+" = ?", projectID), true
	}
	if currentUserIsAdmin(c) {
		return q, true
	}
	ids := accessibleProjectIDs(c)
	if len(ids) == 0 {
		return q.Where("1 = 0"), false
	}
	return q.Where(column+" IN ?", ids), true
}

func statsProjectID(c *gin.Context) (string, bool) {
	projectID := strings.TrimSpace(c.Query("project_id"))
	if projectID != "" {
		return projectID, canAccessProject(c, projectID)
	}
	if currentUserIsAdmin(c) {
		return "", true
	}
	ids := accessibleProjectIDs(c)
	if len(ids) == 1 {
		return ids[0], true
	}
	return "", false
}

func canAccessProject(c *gin.Context, projectID string) bool {
	if strings.TrimSpace(projectID) == "" {
		return false
	}
	var project db.Project
	return scopedProjectsQuery(c).Where("id = ?", projectID).First(&project).Error == nil
}

func requireProjectAccess(c *gin.Context, projectID string) (db.Project, bool) {
	var project db.Project
	if strings.TrimSpace(projectID) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "project_id is required"})
		return project, false
	}
	if err := scopedProjectsQuery(c).Where("id = ?", projectID).First(&project).Error; err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "project not accessible"})
		return project, false
	}
	return project, true
}

func requireProjectManage(c *gin.Context, projectID string) (db.Project, bool) {
	project, ok := requireProjectAccess(c, projectID)
	if !ok {
		return project, false
	}
	if currentUserIsAdmin(c) || project.OwnerUserID == currentUserID(c) || projectMemberRole(c, projectID) == "owner" {
		return project, true
	}
	c.JSON(http.StatusForbidden, gin.H{"error": "project can only be managed by admin or owner"})
	return project, false
}

func projectMemberRole(c *gin.Context, projectID string) string {
	userID := currentUserID(c)
	if userID == "" || strings.TrimSpace(projectID) == "" {
		return ""
	}
	var member db.ProjectMember
	if err := db.DB.Select("role").
		Where("tenant_id = ? AND project_id = ? AND user_id = ?", currentTenantID(c), projectID, userID).
		First(&member).Error; err != nil {
		return ""
	}
	return strings.TrimSpace(member.Role)
}

func resolveAccessibleTaskIDs(c *gin.Context, taskID string) []string {
	taskID = strings.TrimSpace(taskID)
	if taskID == "" {
		return nil
	}
	tenantID := currentTenantID(c)
	var rootTask db.RootTask
	if err := db.DB.Select("id", "project_id").
		Where("id = ? AND tenant_id = ?", taskID, tenantID).
		First(&rootTask).Error; err == nil {
		if !canAccessProject(c, rootTask.ProjectID) {
			return []string{}
		}
		var subTaskIDs []string
		db.DB.Model(&db.SubTask{}).
			Where("root_task_id = ? AND tenant_id = ?", taskID, tenantID).
			Pluck("id", &subTaskIDs)
		if len(subTaskIDs) > 0 {
			return subTaskIDs
		}
		return []string{taskID}
	}
	var subTask db.SubTask
	if err := db.DB.Select("id", "project_id").
		Where("id = ? AND tenant_id = ?", taskID, tenantID).
		First(&subTask).Error; err == nil {
		if !canAccessProject(c, subTask.ProjectID) {
			return []string{}
		}
		return []string{taskID}
	}
	return []string{}
}

func upsertProjectMember(tx *gorm.DB, tenantID, projectID, userID, role string) error {
	if strings.TrimSpace(userID) == "" {
		return nil
	}
	member := db.ProjectMember{
		TenantID:  tenantID,
		ProjectID: projectID,
		UserID:    userID,
		Role:      role,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	return tx.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "project_id"}, {Name: "user_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"tenant_id", "role", "updated_at"}),
	}).Create(&member).Error
}

func validateAssignableProjectUsers(tenantID string, userIDs []string) ([]string, error) {
	seen := map[string]struct{}{}
	ids := make([]string, 0, len(userIDs))
	for _, id := range userIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return []string{}, nil
	}
	var users []db.User
	if err := db.DB.Where("tenant_id = ? AND status = ? AND id IN ?", tenantID, "active", ids).Find(&users).Error; err != nil {
		return nil, err
	}
	if len(users) != len(ids) {
		return nil, gorm.ErrRecordNotFound
	}
	return ids, nil
}
