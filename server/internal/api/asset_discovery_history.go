package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/user/dddd-server/internal/db"
	"gorm.io/gorm"
)

const (
	assetDiscoveryHistorySchema          = "argus.asset-discovery-query-history/v1"
	assetDiscoveryHistoryDefaultPageSize = 20
	assetDiscoveryHistoryMaxPageSize     = 100
	assetDiscoveryItemDefaultPageSize    = 100
	assetDiscoveryItemMaxPageSize        = 500
	assetDiscoveryHistoryQueryTimeout    = 10 * time.Second
)

type assetDiscoveryQuerySummary struct {
	ID             uint      `json:"id"`
	AuditID        uint      `json:"audit_id"`
	Provider       string    `json:"provider"`
	Expression     string    `json:"expression"`
	ConfigVersion  int       `json:"config_version"`
	RequestedLimit int       `json:"requested_limit"`
	ProviderTotal  int       `json:"provider_total"`
	ReturnedCount  int       `json:"returned_count"`
	SkippedRows    int       `json:"skipped_rows"`
	Truncated      bool      `json:"truncated"`
	CreatedBy      string    `json:"created_by"`
	CreatedAt      time.Time `json:"created_at"`
}

type assetDiscoveryQueryHistoryResponse struct {
	SchemaVersion string                       `json:"schema_version"`
	ProjectID     string                       `json:"project_id"`
	Items         []assetDiscoveryQuerySummary `json:"items"`
	Total         int64                        `json:"total"`
	Page          int                          `json:"page"`
	PageSize      int                          `json:"page_size"`
	HasMore       bool                         `json:"has_more"`
	GeneratedAt   string                       `json:"generated_at"`
}

type assetDiscoveryQueryAsset struct {
	ID         uint      `json:"id"`
	Position   int       `json:"position"`
	Target     string    `json:"target"`
	IP         string    `json:"ip,omitempty"`
	Port       int       `json:"port"`
	Domain     string    `json:"domain,omitempty"`
	Protocol   string    `json:"protocol,omitempty"`
	Title      string    `json:"title,omitempty"`
	ICP        string    `json:"icp,omitempty"`
	Country    string    `json:"country,omitempty"`
	City       string    `json:"city,omitempty"`
	Company    string    `json:"company,omitempty"`
	StatusCode int       `json:"status_code,omitempty"`
	Source     string    `json:"source"`
	ObservedAt time.Time `json:"observed_at"`
}

type assetDiscoveryQueryDetailResponse struct {
	SchemaVersion string                     `json:"schema_version"`
	ProjectID     string                     `json:"project_id"`
	Query         assetDiscoveryQuerySummary `json:"query"`
	Assets        []assetDiscoveryQueryAsset `json:"assets"`
	Total         int64                      `json:"total"`
	Page          int                        `json:"page"`
	PageSize      int                        `json:"page_size"`
	HasMore       bool                       `json:"has_more"`
	GeneratedAt   string                     `json:"generated_at"`
}

func listProjectDiscoveryQueries(c *gin.Context) {
	if db.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "asset discovery database is unavailable"})
		return
	}
	project, ok := requireProjectAccess(c, c.Param("id"))
	if !ok {
		return
	}

	provider := strings.ToLower(strings.TrimSpace(c.Query("provider")))
	if provider != "" && !validAssetDiscoveryProviderFilter(provider) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid asset discovery provider"})
		return
	}
	page, pageSize := parsePagination(c, assetDiscoveryHistoryDefaultPageSize, assetDiscoveryHistoryMaxPageSize)
	offset, ok := boundedPaginationOffset(page, pageSize)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid pagination"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), assetDiscoveryHistoryQueryTimeout)
	defer cancel()
	query := db.DB.WithContext(ctx).Model(&db.AssetDiscoverySnapshot{}).
		Where("tenant_id = ? AND project_id = ?", currentTenantID(c), project.ID)
	if provider != "" {
		query = query.Where("provider = ?", provider)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load asset discovery history"})
		return
	}
	var snapshots []db.AssetDiscoverySnapshot
	if err := query.Select(assetDiscoverySnapshotPublicColumns()).
		Order("created_at DESC, id DESC").Offset(offset).Limit(pageSize).Find(&snapshots).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load asset discovery history"})
		return
	}

	items := make([]assetDiscoveryQuerySummary, 0, len(snapshots))
	for _, snapshot := range snapshots {
		items = append(items, summarizeAssetDiscoverySnapshot(snapshot))
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, assetDiscoveryQueryHistoryResponse{
		SchemaVersion: assetDiscoveryHistorySchema,
		ProjectID:     project.ID,
		Items:         items,
		Total:         total,
		Page:          page,
		PageSize:      pageSize,
		HasMore:       assetDiscoveryHistoryHasMore(total, offset, pageSize),
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
	})
}

func getProjectDiscoveryQuery(c *gin.Context) {
	if db.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "asset discovery database is unavailable"})
		return
	}
	project, ok := requireProjectAccess(c, c.Param("id"))
	if !ok {
		return
	}

	snapshotID, err := strconv.ParseUint(strings.TrimSpace(c.Param("snapshot_id")), 10, strconv.IntSize)
	if err != nil || snapshotID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid asset discovery query id"})
		return
	}
	page, pageSize := parsePagination(c, assetDiscoveryItemDefaultPageSize, assetDiscoveryItemMaxPageSize)
	offset, ok := boundedPaginationOffset(page, pageSize)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid pagination"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), assetDiscoveryHistoryQueryTimeout)
	defer cancel()
	store := db.DB.WithContext(ctx)
	var snapshot db.AssetDiscoverySnapshot
	if err := store.Select(assetDiscoverySnapshotPublicColumns()).
		Where("id = ? AND tenant_id = ? AND project_id = ?", uint(snapshotID), currentTenantID(c), project.ID).
		First(&snapshot).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "asset discovery query not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load asset discovery query"})
		return
	}

	itemQuery := store.Model(&db.AssetDiscoverySnapshotItem{}).
		Where("tenant_id = ? AND project_id = ? AND snapshot_id = ?", currentTenantID(c), project.ID, snapshot.ID)
	var total int64
	if err := itemQuery.Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load asset discovery query"})
		return
	}
	var storedItems []db.AssetDiscoverySnapshotItem
	if err := itemQuery.Select(assetDiscoverySnapshotItemPublicColumns()).
		Order("position ASC, id ASC").Offset(offset).Limit(pageSize).Find(&storedItems).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load asset discovery query"})
		return
	}

	assets := make([]assetDiscoveryQueryAsset, 0, len(storedItems))
	for _, item := range storedItems {
		assets = append(assets, assetDiscoveryQueryAsset{
			ID:         item.ID,
			Position:   item.Position,
			Target:     item.NormalizedTarget,
			IP:         item.IP,
			Port:       item.Port,
			Domain:     item.Domain,
			Protocol:   item.Protocol,
			Title:      item.Title,
			ICP:        item.ICP,
			Country:    item.Country,
			City:       item.City,
			Company:    item.Company,
			StatusCode: item.StatusCode,
			Source:     item.Source,
			ObservedAt: item.ObservedAt,
		})
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, assetDiscoveryQueryDetailResponse{
		SchemaVersion: assetDiscoveryHistorySchema,
		ProjectID:     project.ID,
		Query:         summarizeAssetDiscoverySnapshot(snapshot),
		Assets:        assets,
		Total:         total,
		Page:          page,
		PageSize:      pageSize,
		HasMore:       assetDiscoveryHistoryHasMore(total, offset, pageSize),
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
	})
}

func assetDiscoverySnapshotPublicColumns() []string {
	return []string{
		"id", "audit_id", "provider", "expression", "config_version", "requested_limit",
		"provider_total", "returned_count", "skipped_rows", "truncated", "created_by", "created_at",
	}
}

func assetDiscoverySnapshotItemPublicColumns() []string {
	return []string{
		"id", "position", "normalized_target", "ip", "port", "domain", "protocol", "title", "icp",
		"country", "city", "company", "status_code", "source", "observed_at",
	}
}

func summarizeAssetDiscoverySnapshot(snapshot db.AssetDiscoverySnapshot) assetDiscoveryQuerySummary {
	return assetDiscoveryQuerySummary{
		ID:             snapshot.ID,
		AuditID:        snapshot.AuditID,
		Provider:       snapshot.Provider,
		Expression:     snapshot.Expression,
		ConfigVersion:  snapshot.ConfigVersion,
		RequestedLimit: snapshot.RequestedLimit,
		ProviderTotal:  snapshot.ProviderTotal,
		ReturnedCount:  snapshot.ReturnedCount,
		SkippedRows:    snapshot.SkippedRows,
		Truncated:      snapshot.Truncated,
		CreatedBy:      snapshot.CreatedBy,
		CreatedAt:      snapshot.CreatedAt,
	}
}

func validAssetDiscoveryProviderFilter(provider string) bool {
	if provider == "" || len(provider) > 32 {
		return false
	}
	for index, char := range []byte(provider) {
		if (char >= 'a' && char <= 'z') || (index > 0 && char >= '0' && char <= '9') || (index > 0 && (char == '-' || char == '_')) {
			continue
		}
		return false
	}
	return true
}

func boundedPaginationOffset(page, pageSize int) (int, bool) {
	if page < 1 || pageSize < 1 || page-1 > int(^uint(0)>>1)/pageSize {
		return 0, false
	}
	return (page - 1) * pageSize, true
}

func assetDiscoveryHistoryHasMore(total int64, offset, pageSize int) bool {
	return total > int64(offset) && int64(pageSize) < total-int64(offset)
}
