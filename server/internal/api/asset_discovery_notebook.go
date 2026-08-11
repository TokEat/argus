package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	assetDiscoveryNotebookSchema          = "argus.asset-discovery-notebook/v1"
	assetDiscoveryNotebookDefaultPageSize = 50
	assetDiscoveryNotebookMaxPageSize     = 100
	assetDiscoveryNotebookArchiveMaxItems = 100
	assetDiscoveryNotebookProjectMaxItems = 10000
	assetDiscoveryNotebookTimeout         = 10 * time.Second
)

var (
	errAssetDiscoveryNotebookProjectReadOnly = errors.New("asset discovery notebook project is read-only")
	errAssetDiscoveryNotebookSourceNotFound  = errors.New("asset discovery notebook source not found")
	errAssetDiscoveryNotebookLimitExceeded   = errors.New("asset discovery notebook limit exceeded")
)

type assetDiscoveryNotebookArchiveRequest struct {
	ItemIDs []uint `json:"item_ids"`
}

type assetDiscoveryNotebookArchiveResponse struct {
	SchemaVersion        string `json:"schema_version"`
	ProjectID            string `json:"project_id"`
	SnapshotID           uint   `json:"snapshot_id"`
	RequestedCount       int    `json:"requested_count"`
	CreatedCount         int    `json:"created_count"`
	LinkedSourceCount    int    `json:"linked_source_count"`
	AlreadyArchivedCount int    `json:"already_archived_count"`
	TotalCount           int64  `json:"total_count"`
}

type assetDiscoveryNotebookItemResponse struct {
	ID              uint      `json:"id"`
	Target          string    `json:"target"`
	SourceCount     int64     `json:"source_count"`
	FirstArchivedAt time.Time `json:"first_archived_at"`
	LastArchivedAt  time.Time `json:"last_archived_at"`
	CreatedBy       string    `json:"created_by"`
}

type assetDiscoveryNotebookListResponse struct {
	SchemaVersion string                               `json:"schema_version"`
	ProjectID     string                               `json:"project_id"`
	Items         []assetDiscoveryNotebookItemResponse `json:"items"`
	Total         int64                                `json:"total"`
	Page          int                                  `json:"page"`
	PageSize      int                                  `json:"page_size"`
	HasMore       bool                                 `json:"has_more"`
	GeneratedAt   string                               `json:"generated_at"`
}

type assetDiscoveryNotebookSourceAggregate struct {
	NotebookItemID uint
	SourceCount    int64
}

func archiveProjectDiscoveryNotebookItems(c *gin.Context) {
	startedAt := time.Now()
	if db.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "asset discovery database is unavailable"})
		return
	}
	c.Header("Cache-Control", "no-store")

	ctx, cancel := context.WithTimeout(c.Request.Context(), assetDiscoveryNotebookTimeout)
	defer cancel()
	store := db.DB.WithContext(ctx)
	project, ok := requireAssetDiscoveryNotebookProjectAccess(c, store, c.Param("id"))
	if !ok {
		return
	}
	if strings.EqualFold(strings.TrimSpace(project.Status), "archived") {
		c.JSON(http.StatusConflict, gin.H{"error": "archived projects are read-only"})
		return
	}

	snapshotID, err := parseAssetDiscoveryNotebookSnapshotID(c.Param("snapshot_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid asset discovery query id"})
		return
	}
	request, err := decodeAssetDiscoveryNotebookArchiveRequest(c)
	if err != nil {
		status := http.StatusBadRequest
		if errors.As(err, new(*http.MaxBytesError)) {
			status = http.StatusRequestEntityTooLarge
		}
		c.JSON(status, gin.H{"error": "invalid asset discovery notebook request"})
		return
	}

	response, err := persistAssetDiscoveryNotebookArchive(store, c, project, snapshotID, request.ItemIDs, startedAt)
	if err != nil {
		writeAssetDiscoveryNotebookError(c, normalizeAssetDiscoveryNotebookStoreError(store, err))
		return
	}
	c.JSON(http.StatusOK, response)
}

func listProjectDiscoveryNotebookItems(c *gin.Context) {
	if db.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "asset discovery database is unavailable"})
		return
	}
	c.Header("Cache-Control", "no-store")

	ctx, cancel := context.WithTimeout(c.Request.Context(), assetDiscoveryNotebookTimeout)
	defer cancel()
	store := db.DB.WithContext(ctx)
	project, ok := requireAssetDiscoveryNotebookProjectAccess(c, store, c.Param("id"))
	if !ok {
		return
	}
	page, pageSize := parsePagination(c, assetDiscoveryNotebookDefaultPageSize, assetDiscoveryNotebookMaxPageSize)
	offset, ok := boundedPaginationOffset(page, pageSize)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid pagination"})
		return
	}

	query := store.Model(&db.AssetDiscoveryNotebookItem{}).
		Where("tenant_id = ? AND project_id = ?", currentTenantID(c), project.ID)
	var total int64
	if err := query.Count(&total).Error; err != nil {
		writeAssetDiscoveryNotebookError(c, normalizeAssetDiscoveryNotebookStoreError(store, err))
		return
	}
	var storedItems []db.AssetDiscoveryNotebookItem
	if err := query.Select("id", "normalized_target", "created_by", "created_at", "updated_at").
		Order("updated_at DESC, id DESC").Offset(offset).Limit(pageSize).Find(&storedItems).Error; err != nil {
		writeAssetDiscoveryNotebookError(c, normalizeAssetDiscoveryNotebookStoreError(store, err))
		return
	}

	aggregates := make(map[uint]assetDiscoveryNotebookSourceAggregate, len(storedItems))
	if len(storedItems) > 0 {
		ids := make([]uint, 0, len(storedItems))
		for _, item := range storedItems {
			ids = append(ids, item.ID)
		}
		var rows []assetDiscoveryNotebookSourceAggregate
		if err := store.Model(&db.AssetDiscoveryNotebookSource{}).
			Select("notebook_item_id, COUNT(*) AS source_count").
			Where("tenant_id = ? AND project_id = ? AND notebook_item_id IN ?", currentTenantID(c), project.ID, ids).
			Group("notebook_item_id").Find(&rows).Error; err != nil {
			writeAssetDiscoveryNotebookError(c, normalizeAssetDiscoveryNotebookStoreError(store, err))
			return
		}
		for _, row := range rows {
			aggregates[row.NotebookItemID] = row
		}
	}

	items := make([]assetDiscoveryNotebookItemResponse, 0, len(storedItems))
	for _, item := range storedItems {
		aggregate := aggregates[item.ID]
		items = append(items, assetDiscoveryNotebookItemResponse{
			ID:              item.ID,
			Target:          item.NormalizedTarget,
			SourceCount:     aggregate.SourceCount,
			FirstArchivedAt: item.CreatedAt,
			LastArchivedAt:  item.UpdatedAt,
			CreatedBy:       item.CreatedBy,
		})
	}
	c.JSON(http.StatusOK, assetDiscoveryNotebookListResponse{
		SchemaVersion: assetDiscoveryNotebookSchema,
		ProjectID:     project.ID,
		Items:         items,
		Total:         total,
		Page:          page,
		PageSize:      pageSize,
		HasMore:       assetDiscoveryHistoryHasMore(total, offset, pageSize),
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
	})
}

func persistAssetDiscoveryNotebookArchive(store *gorm.DB, c *gin.Context, project db.Project, snapshotID uint, itemIDs []uint, startedAt time.Time) (assetDiscoveryNotebookArchiveResponse, error) {
	response := assetDiscoveryNotebookArchiveResponse{
		SchemaVersion:  assetDiscoveryNotebookSchema,
		ProjectID:      project.ID,
		SnapshotID:     snapshotID,
		RequestedCount: len(itemIDs),
	}
	tenantID := currentTenantID(c)
	operatorID := currentUserID(c)
	err := store.Transaction(func(tx *gorm.DB) error {
		var lockedProject db.Project
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Select("id", "tenant_id", "status").
			Where("id = ? AND tenant_id = ?", project.ID, tenantID).First(&lockedProject).Error; err != nil {
			return fmt.Errorf("lock asset discovery notebook project: %w", err)
		}
		if strings.EqualFold(strings.TrimSpace(lockedProject.Status), "archived") {
			return errAssetDiscoveryNotebookProjectReadOnly
		}

		var snapshot db.AssetDiscoverySnapshot
		if err := tx.Select("id", "tenant_id", "project_id", "provider", "query_hash", "config_version", "config_hash", "provider_total", "skipped_rows", "truncated").
			Where("id = ? AND tenant_id = ? AND project_id = ?", snapshotID, tenantID, project.ID).
			First(&snapshot).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return errAssetDiscoveryNotebookSourceNotFound
			}
			return fmt.Errorf("load asset discovery notebook snapshot: %w", err)
		}

		var sourceItems []db.AssetDiscoverySnapshotItem
		if err := tx.Select("id", "tenant_id", "project_id", "snapshot_id", "normalized_target", "target_hash").
			Where("tenant_id = ? AND project_id = ? AND snapshot_id = ? AND id IN ?", tenantID, project.ID, snapshot.ID, itemIDs).
			Order("id ASC").Find(&sourceItems).Error; err != nil {
			return fmt.Errorf("load asset discovery notebook source items: %w", err)
		}
		if len(sourceItems) != len(itemIDs) {
			return errAssetDiscoveryNotebookSourceNotFound
		}

		var total int64
		if err := tx.Model(&db.AssetDiscoveryNotebookItem{}).
			Where("tenant_id = ? AND project_id = ?", tenantID, project.ID).Count(&total).Error; err != nil {
			return fmt.Errorf("count asset discovery notebook items: %w", err)
		}
		targetHashes := make([]string, 0, len(sourceItems))
		for _, source := range sourceItems {
			targetHashes = append(targetHashes, source.TargetHash)
		}
		var existing []db.AssetDiscoveryNotebookItem
		if err := tx.Where("tenant_id = ? AND project_id = ? AND target_hash IN ?", tenantID, project.ID, targetHashes).
			Find(&existing).Error; err != nil {
			return fmt.Errorf("load existing asset discovery notebook items: %w", err)
		}
		entriesByHash := make(map[string]db.AssetDiscoveryNotebookItem, len(existing)+len(sourceItems))
		for _, item := range existing {
			entriesByHash[item.TargetHash] = item
		}
		if total+int64(len(sourceItems)-len(existing)) > assetDiscoveryNotebookProjectMaxItems {
			return errAssetDiscoveryNotebookLimitExceeded
		}

		now := time.Now().UTC()
		audit := db.AssetDiscoveryAudit{
			TenantID:       tenantID,
			ProjectID:      project.ID,
			Provider:       snapshot.Provider,
			Action:         "notebook_archive",
			OperatorID:     operatorID,
			QueryHash:      snapshot.QueryHash,
			ConfigVersion:  snapshot.ConfigVersion,
			ConfigHash:     snapshot.ConfigHash,
			RequestedLimit: len(itemIDs),
			Status:         "success",
			CreatedAt:      now,
		}
		if err := tx.Create(&audit).Error; err != nil {
			return fmt.Errorf("create asset discovery notebook audit: %w", err)
		}

		for _, sourceItem := range sourceItems {
			entry, exists := entriesByHash[sourceItem.TargetHash]
			entryCreated := false
			if !exists {
				candidate := db.AssetDiscoveryNotebookItem{
					TenantID:         tenantID,
					ProjectID:        project.ID,
					NormalizedTarget: sourceItem.NormalizedTarget,
					TargetHash:       sourceItem.TargetHash,
					CreatedBy:        operatorID,
					CreatedAt:        now,
					UpdatedAt:        now,
				}
				created := tx.Clauses(clause.OnConflict{
					Columns:   []clause.Column{{Name: "tenant_id"}, {Name: "project_id"}, {Name: "target_hash"}},
					DoNothing: true,
				}).Create(&candidate)
				if created.Error != nil {
					return fmt.Errorf("create asset discovery notebook item: %w", created.Error)
				}
				if created.RowsAffected == 1 {
					entry = candidate
					entryCreated = true
					response.CreatedCount++
				} else if err := tx.Where("tenant_id = ? AND project_id = ? AND target_hash = ?", tenantID, project.ID, sourceItem.TargetHash).
					First(&entry).Error; err != nil {
					return fmt.Errorf("reload asset discovery notebook item: %w", err)
				}
				entriesByHash[sourceItem.TargetHash] = entry
			}

			source := db.AssetDiscoveryNotebookSource{
				TenantID:       tenantID,
				ProjectID:      project.ID,
				NotebookItemID: entry.ID,
				SnapshotID:     snapshot.ID,
				SnapshotItemID: sourceItem.ID,
				AuditID:        audit.ID,
				ArchivedBy:     operatorID,
				ArchivedAt:     now,
			}
			created := tx.Clauses(clause.OnConflict{
				Columns: []clause.Column{
					{Name: "tenant_id"}, {Name: "project_id"}, {Name: "snapshot_id"}, {Name: "snapshot_item_id"},
				},
				DoNothing: true,
			}).Create(&source)
			if created.Error != nil {
				return fmt.Errorf("create asset discovery notebook source: %w", created.Error)
			}
			if created.RowsAffected == 1 {
				response.LinkedSourceCount++
				if !entryCreated {
					updated := tx.Model(&db.AssetDiscoveryNotebookItem{}).
						Where("id = ? AND tenant_id = ? AND project_id = ?", entry.ID, tenantID, project.ID).
						Update("updated_at", now)
					if updated.Error != nil {
						return fmt.Errorf("update asset discovery notebook item: %w", updated.Error)
					}
					if updated.RowsAffected != 1 {
						return errors.New("update asset discovery notebook item: unexpected row count")
					}
				}
			} else {
				response.AlreadyArchivedCount++
			}
		}

		auditUpdate := tx.Model(&db.AssetDiscoveryAudit{}).
			Where("id = ? AND tenant_id = ? AND project_id = ?", audit.ID, tenantID, project.ID).
			Updates(map[string]any{
				"provider_total": response.LinkedSourceCount,
				"returned_count": response.CreatedCount,
				"skipped_rows":   response.AlreadyArchivedCount,
				"duration_ms":    time.Since(startedAt).Milliseconds(),
			})
		if auditUpdate.Error != nil {
			return fmt.Errorf("update asset discovery notebook audit: %w", auditUpdate.Error)
		}
		if auditUpdate.RowsAffected != 1 {
			return errors.New("update asset discovery notebook audit: unexpected row count")
		}
		if err := tx.Model(&db.AssetDiscoveryNotebookItem{}).
			Where("tenant_id = ? AND project_id = ?", tenantID, project.ID).Count(&response.TotalCount).Error; err != nil {
			return fmt.Errorf("count archived asset discovery notebook items: %w", err)
		}
		return nil
	})
	return response, err
}

func decodeAssetDiscoveryNotebookArchiveRequest(c *gin.Context) (assetDiscoveryNotebookArchiveRequest, error) {
	var request assetDiscoveryNotebookArchiveRequest
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, assetDiscoveryRequestLimit)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return request, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return request, errors.New("expected one JSON object")
	}
	if len(request.ItemIDs) < 1 || len(request.ItemIDs) > assetDiscoveryNotebookArchiveMaxItems {
		return request, errors.New("invalid notebook item count")
	}
	seen := make(map[uint]struct{}, len(request.ItemIDs))
	for _, itemID := range request.ItemIDs {
		if itemID == 0 {
			return request, errors.New("invalid notebook item id")
		}
		if _, exists := seen[itemID]; exists {
			return request, errors.New("duplicate notebook item id")
		}
		seen[itemID] = struct{}{}
	}
	sort.Slice(request.ItemIDs, func(i, j int) bool { return request.ItemIDs[i] < request.ItemIDs[j] })
	return request, nil
}

func parseAssetDiscoveryNotebookSnapshotID(value string) (uint, error) {
	parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, strconv.IntSize)
	if err != nil || parsed == 0 {
		return 0, errors.New("invalid asset discovery query id")
	}
	return uint(parsed), nil
}

func requireAssetDiscoveryNotebookProjectAccess(c *gin.Context, store *gorm.DB, projectID string) (db.Project, bool) {
	var project db.Project
	if strings.TrimSpace(projectID) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "project_id is required"})
		return project, false
	}
	if err := scopedProjectsQuery(c).WithContext(store.Statement.Context).Where("id = ?", projectID).First(&project).Error; err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || store.Statement.Context.Err() != nil {
			c.JSON(http.StatusGatewayTimeout, gin.H{"error": "asset discovery notebook request timed out"})
			return project, false
		}
		c.JSON(http.StatusForbidden, gin.H{"error": "project not accessible"})
		return project, false
	}
	return project, true
}

func writeAssetDiscoveryNotebookError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		c.JSON(http.StatusGatewayTimeout, gin.H{"error": "asset discovery notebook request timed out"})
	case errors.Is(err, errAssetDiscoveryNotebookProjectReadOnly):
		c.JSON(http.StatusConflict, gin.H{"error": "archived projects are read-only"})
	case errors.Is(err, errAssetDiscoveryNotebookSourceNotFound), errors.Is(err, gorm.ErrRecordNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "asset discovery notebook source not found"})
	case errors.Is(err, errAssetDiscoveryNotebookLimitExceeded):
		c.JSON(http.StatusConflict, gin.H{"error": "asset discovery notebook limit exceeded"})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to access asset discovery notebook"})
	}
}

func normalizeAssetDiscoveryNotebookStoreError(store *gorm.DB, err error) error {
	if store != nil && store.Statement != nil && store.Statement.Context != nil {
		if contextErr := store.Statement.Context.Err(); contextErr != nil {
			return contextErr
		}
	}
	return err
}
