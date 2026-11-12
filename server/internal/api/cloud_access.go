package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/TokEat/argus/server/internal/db"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func currentUserID(c *gin.Context) string {
	return requestActor(c).UserID
}

func currentUserRole(c *gin.Context) string {
	return requestActor(c).Role
}

func currentUserIsAdmin(c *gin.Context) bool {
	return requestActor(c).IsAdmin()
}

func (h *CloudHandler) accessibleCloudAccountSubquery(actor RequestActor) *gorm.DB {
	q := h.DB.Model(&db.CloudAccount{}).Select("id").Where("tenant_id = ?", actor.TenantID)
	if actor.IsAdmin() {
		return q
	}
	boundSubquery := h.DB.Model(&db.CloudAccountBinding{}).
		Select("cloud_account_id").
		Where("tenant_id = ? AND user_id = ?", actor.TenantID, actor.UserID)
	return q.Where("owner_user_id = ? OR id IN (?)", actor.UserID, boundSubquery)
}

func (h *CloudHandler) cloudAccountQuery(actor RequestActor) *gorm.DB {
	return h.DB.Where("tenant_id = ? AND id IN (?)", actor.TenantID, h.accessibleCloudAccountSubquery(actor))
}

func (h *CloudHandler) loadCloudAccountForUse(c *gin.Context, accountID string, activeOnly bool) (db.CloudAccount, bool) {
	var account db.CloudAccount
	query := h.cloudAccountQuery(requestActor(c)).Where("id = ?", accountID)
	if activeOnly {
		query = query.Where("status = ?", "active")
	}
	if err := query.First(&account).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Cloud account not found or not accessible"})
		return account, false
	}
	return account, true
}

func (h *CloudHandler) loadCloudAccountForManage(c *gin.Context, accountID string) (db.CloudAccount, bool) {
	actor := requestActor(c)
	var account db.CloudAccount
	if err := h.cloudAccountQuery(actor).Where("id = ?", accountID).First(&account).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Cloud account not found or not accessible"})
		return account, false
	}
	if !actor.IsAdmin() && account.OwnerUserID != actor.UserID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Only the account owner or tenant admin can manage this cloud account"})
		return account, false
	}
	return account, true
}

func (h *CloudHandler) accountAccessLevel(actor RequestActor, account db.CloudAccount) string {
	if actor.IsAdmin() {
		return "admin"
	}
	if account.OwnerUserID == actor.UserID {
		return "owner"
	}
	return "bound"
}

func (h *CloudHandler) ensureCloudAccountBinding(tx *gorm.DB, tenantID, accountID, userID, accessType string) error {
	userID = strings.TrimSpace(userID)
	if strings.TrimSpace(userID) == "" {
		return nil
	}
	binding := db.CloudAccountBinding{
		TenantID:       tenantID,
		CloudAccountID: accountID,
		UserID:         userID,
		AccessType:     accessType,
	}
	return tx.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "tenant_id"}, {Name: "cloud_account_id"}, {Name: "user_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"access_type", "updated_at"}),
	}).Create(&binding).Error
}

func (h *CloudHandler) validateCloudAccountBindingUsers(tenantID string, userIDs []string) ([]string, error) {
	seen := make(map[string]struct{}, len(userIDs))
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
		return nil, nil
	}

	var users []db.User
	if err := h.DB.Where("tenant_id = ? AND status = ? AND role IN ? AND id IN ?", tenantID, "active", []string{"admin", "operator"}, ids).Find(&users).Error; err != nil {
		return nil, err
	}
	if len(users) != len(ids) {
		return nil, fmt.Errorf("bindings can only target active admin/operator users in the same tenant")
	}
	return ids, nil
}

func (h *CloudHandler) replaceCloudAccountBindings(account db.CloudAccount, userIDs []string) error {
	tenantID := account.TenantID
	validIDs, err := h.validateCloudAccountBindingUsers(tenantID, userIDs)
	if err != nil {
		return err
	}
	if account.OwnerUserID != "" {
		validIDs = append(validIDs, account.OwnerUserID)
	}
	seen := make(map[string]string, len(validIDs))
	for _, id := range validIDs {
		if strings.TrimSpace(id) == "" {
			continue
		}
		seen[id] = "bound"
	}
	if account.OwnerUserID != "" {
		seen[account.OwnerUserID] = "owner"
	}

	return h.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("tenant_id = ? AND cloud_account_id = ?", tenantID, account.ID).Delete(&db.CloudAccountBinding{}).Error; err != nil {
			return err
		}
		for userID, accessType := range seen {
			if err := h.ensureCloudAccountBinding(tx, tenantID, account.ID, userID, accessType); err != nil {
				return err
			}
		}
		return nil
	})
}
