package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/user/dddd-server/internal/cloud"
	"github.com/user/dddd-server/internal/db"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// cloudAutoScaler 由 main.go 通过 SetAutoScaler 注入
var cloudAutoScaler *cloud.AutoScaler

func currentUserID(c *gin.Context) string {
	return strings.TrimSpace(c.GetString("user_id"))
}

func currentUserRole(c *gin.Context) string {
	role := strings.TrimSpace(c.GetString("role"))
	if role == "" {
		return "viewer"
	}
	return role
}

func currentUserIsAdmin(c *gin.Context) bool {
	return currentUserRole(c) == "admin"
}

func accessibleCloudAccountSubquery(c *gin.Context) *gorm.DB {
	tenantID := currentTenantID(c)
	q := db.DB.Model(&db.CloudAccount{}).Select("id").Where("tenant_id = ?", tenantID)
	if currentUserIsAdmin(c) {
		return q
	}
	userID := currentUserID(c)
	boundSubquery := db.DB.Model(&db.CloudAccountBinding{}).
		Select("cloud_account_id").
		Where("tenant_id = ? AND user_id = ?", tenantID, userID)
	return q.Where("owner_user_id = ? OR id IN (?)", userID, boundSubquery)
}

func cloudAccountQuery(c *gin.Context) *gorm.DB {
	return db.DB.Where("tenant_id = ? AND id IN (?)", currentTenantID(c), accessibleCloudAccountSubquery(c))
}

func loadCloudAccountForUse(c *gin.Context, accountID string, activeOnly bool) (db.CloudAccount, bool) {
	var account db.CloudAccount
	query := cloudAccountQuery(c).Where("id = ?", accountID)
	if activeOnly {
		query = query.Where("status = ?", "active")
	}
	if err := query.First(&account).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Cloud account not found or not accessible"})
		return account, false
	}
	return account, true
}

func loadCloudAccountForManage(c *gin.Context, accountID string) (db.CloudAccount, bool) {
	var account db.CloudAccount
	if err := cloudAccountQuery(c).Where("id = ?", accountID).First(&account).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Cloud account not found or not accessible"})
		return account, false
	}
	if !currentUserIsAdmin(c) && account.OwnerUserID != currentUserID(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Only the account owner or tenant admin can manage this cloud account"})
		return account, false
	}
	return account, true
}

func accountAccessLevel(c *gin.Context, account db.CloudAccount) string {
	if currentUserIsAdmin(c) {
		return "admin"
	}
	if account.OwnerUserID == currentUserID(c) {
		return "owner"
	}
	return "bound"
}

func ensureCloudAccountBinding(tx *gorm.DB, tenantID, accountID, userID, accessType string) error {
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

func validateCloudAccountBindingUsers(tenantID string, userIDs []string) ([]string, error) {
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
	if err := db.DB.Where("tenant_id = ? AND status = ? AND role IN ? AND id IN ?", tenantID, "active", []string{"admin", "operator"}, ids).Find(&users).Error; err != nil {
		return nil, err
	}
	if len(users) != len(ids) {
		return nil, fmt.Errorf("bindings can only target active admin/operator users in the same tenant")
	}
	return ids, nil
}

func replaceCloudAccountBindings(account db.CloudAccount, userIDs []string) error {
	tenantID := account.TenantID
	validIDs, err := validateCloudAccountBindingUsers(tenantID, userIDs)
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

	return db.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("tenant_id = ? AND cloud_account_id = ?", tenantID, account.ID).Delete(&db.CloudAccountBinding{}).Error; err != nil {
			return err
		}
		for userID, accessType := range seen {
			if err := ensureCloudAccountBinding(tx, tenantID, account.ID, userID, accessType); err != nil {
				return err
			}
		}
		return nil
	})
}

// SetAutoScaler 注入 AutoScaler 实例
func SetAutoScaler(as *cloud.AutoScaler) {
	cloudAutoScaler = as
}
