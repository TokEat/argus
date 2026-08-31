package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	errTenantMCPDisabled      = errors.New("mcp_disabled")
	errTenantMCPClientBlocked = errors.New("mcp_client_blocked")
)

func tenantMCPEnabled(tenantID string) bool {
	tenantID = normalizeTenantID(tenantID)
	if db.DB == nil {
		return true
	}
	var row db.TenantMCPSettings
	if err := db.DB.Where("tenant_id = ?", tenantID).First(&row).Error; err != nil {
		return true
	}
	return row.Enabled
}

func tenantMCPClientBlocked(tenantID, clientID string) bool {
	tenantID = normalizeTenantID(tenantID)
	clientID = strings.TrimSpace(clientID)
	if db.DB == nil || clientID == "" {
		return false
	}
	var count int64
	db.DB.Model(&db.OAuthTenantClientBlock{}).
		Where("tenant_id = ? AND client_id = ?", tenantID, clientID).
		Count(&count)
	return count > 0
}

func denyIfTenantMCPBlocked(tenantID, clientID string) error {
	if !tenantMCPEnabled(tenantID) {
		return errTenantMCPDisabled
	}
	if tenantMCPClientBlocked(tenantID, clientID) {
		return errTenantMCPClientBlocked
	}
	return nil
}

func revokeTenantRefreshTokens(tenantID, clientID string) (int64, error) {
	if db.DB == nil {
		return 0, errors.New("database unavailable")
	}
	tenantID = normalizeTenantID(tenantID)
	query := db.DB.Model(&db.OAuthRefreshToken{}).
		Where("tenant_id = ? AND revoked_at IS NULL", tenantID)
	if strings.TrimSpace(clientID) != "" {
		query = query.Where("client_id = ?", strings.TrimSpace(clientID))
	}
	result := query.Update("revoked_at", time.Now())
	return result.RowsAffected, result.Error
}

func countActiveTenantSessions(tenantID, clientID string) int64 {
	if db.DB == nil {
		return 0
	}
	query := db.DB.Model(&db.OAuthRefreshToken{}).
		Where("tenant_id = ? AND revoked_at IS NULL AND expires_at > ?", tenantID, time.Now())
	if strings.TrimSpace(clientID) != "" {
		query = query.Where("client_id = ?", strings.TrimSpace(clientID))
	}
	var count int64
	query.Count(&count)
	return count
}

func upsertTenantMCPSettings(tenantID, actorID string, enabled bool) error {
	if db.DB == nil {
		return errors.New("database unavailable")
	}
	tenantID = normalizeTenantID(tenantID)
	updates := map[string]interface{}{
		"enabled":    enabled,
		"updated_by": strings.TrimSpace(actorID),
		"updated_at": time.Now(),
	}
	var existing db.TenantMCPSettings
	err := db.DB.Where("tenant_id = ?", tenantID).First(&existing).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return db.DB.Create(&db.TenantMCPSettings{
			TenantID:  tenantID,
			Enabled:   enabled,
			UpdatedBy: strings.TrimSpace(actorID),
			UpdatedAt: time.Now(),
		}).Error
	}
	if err != nil {
		return err
	}
	return db.DB.Model(&existing).Updates(updates).Error
}

func setTenantClientBlock(tenantID, clientID, actorID string, blocked bool) error {
	if db.DB == nil {
		return errors.New("database unavailable")
	}
	tenantID = normalizeTenantID(tenantID)
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return errors.New("client_id is required")
	}
	if !blocked {
		return db.DB.Where("tenant_id = ? AND client_id = ?", tenantID, clientID).
			Delete(&db.OAuthTenantClientBlock{}).Error
	}
	row := db.OAuthTenantClientBlock{
		TenantID: tenantID,
		ClientID: clientID,
		ActorID:  strings.TrimSpace(actorID),
	}
	return db.DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "tenant_id"}, {Name: "client_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"blocked_at", "actor_id"}),
	}).Create(&row).Error
}

func recordMCPAdminEvent(tenantID, actorID, action, clientID string, details map[string]interface{}) {
	if db.DB == nil {
		return
	}
	if details == nil {
		details = map[string]interface{}{}
	}
	payload, _ := json.Marshal(details)
	_ = db.DB.Create(&db.MCPAdminEvent{
		ID:       uuid.NewString(),
		TenantID: normalizeTenantID(tenantID),
		ActorID:  strings.TrimSpace(actorID),
		Action:   strings.TrimSpace(action),
		ClientID: strings.TrimSpace(clientID),
		Details:  string(payload),
	}).Error
}

func mcpSessionID(tokenHash string) string {
	sum := sha256.Sum256([]byte("argus-mcp-session|" + tokenHash))
	return hex.EncodeToString(sum[:])
}

func findTenantRefreshBySessionID(tenantID, sessionID string) (db.OAuthRefreshToken, bool) {
	var empty db.OAuthRefreshToken
	if db.DB == nil || strings.TrimSpace(sessionID) == "" {
		return empty, false
	}
	var rows []db.OAuthRefreshToken
	if err := db.DB.Where("tenant_id = ?", normalizeTenantID(tenantID)).Find(&rows).Error; err != nil {
		return empty, false
	}
	for _, row := range rows {
		if mcpSessionID(row.TokenHash) == sessionID {
			return row, true
		}
	}
	return empty, false
}

func clientUsedByOtherTenants(clientID, tenantID string) bool {
	if db.DB == nil {
		return true
	}
	clientID = strings.TrimSpace(clientID)
	tenantID = normalizeTenantID(tenantID)
	var refreshCount int64
	db.DB.Model(&db.OAuthRefreshToken{}).
		Where("client_id = ? AND tenant_id <> ?", clientID, tenantID).
		Count(&refreshCount)
	if refreshCount > 0 {
		return true
	}
	var codeCount int64
	db.DB.Model(&db.OAuthAuthorizationCode{}).
		Where("client_id = ? AND tenant_id <> ?", clientID, tenantID).
		Count(&codeCount)
	return codeCount > 0
}

func loadOAuthClientByID(clientID string) (db.OAuthClient, error) {
	var client db.OAuthClient
	if err := db.DB.Where("client_id = ?", strings.TrimSpace(clientID)).First(&client).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return db.OAuthClient{}, err
		}
		return db.OAuthClient{}, err
	}
	return client, nil
}
