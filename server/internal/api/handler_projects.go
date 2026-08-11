package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

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
	db.DB.Model(&db.RootTask{}).Where("project_id = ? AND tenant_id = ? AND archived_at IS NULL", projectID, tenantID).Count(&taskCount)
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
