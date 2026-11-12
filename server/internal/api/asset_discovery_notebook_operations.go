package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/TokEat/argus/server/internal/db"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type notebookOperationRequest struct {
	Tags *[]string `json:"tags"`
	Note *string   `json:"note"`
}
type notebookOperationItem struct {
	ID              uint       `json:"id"`
	ProjectID       string     `json:"project_id"`
	ProjectName     string     `json:"project_name,omitempty"`
	Target          string     `json:"target"`
	SourceCount     int64      `json:"source_count"`
	FirstArchivedAt time.Time  `json:"first_archived_at"`
	LastArchivedAt  time.Time  `json:"last_archived_at"`
	CreatedBy       string     `json:"created_by"`
	Tags            []string   `json:"tags"`
	Note            string     `json:"note"`
	RemovedAt       *time.Time `json:"removed_at,omitempty"`
	RemovedBy       string     `json:"removed_by,omitempty"`
	UpdatedBy       string     `json:"updated_by,omitempty"`
}
type notebookOperationList struct {
	SchemaVersion string                  `json:"schema_version"`
	ProjectID     string                  `json:"project_id"`
	Items         []notebookOperationItem `json:"items"`
	Total         int64                   `json:"total"`
	Page          int                     `json:"page"`
	PageSize      int                     `json:"page_size"`
	HasMore       bool                    `json:"has_more"`
	GeneratedAt   string                  `json:"generated_at"`
}

func listTenantDiscoveryNotebookItems(c *gin.Context) { listNotebookOperations(c, "", true) }
func listProjectDiscoveryNotebookItemsOperations(c *gin.Context) {
	listNotebookOperations(c, c.Param("id"), false)
}
func listNotebookOperations(c *gin.Context, projectID string, tenantView bool) {
	if db.DB == nil {
		c.JSON(500, gin.H{"error": "asset discovery database is unavailable"})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), assetDiscoveryNotebookTimeout)
	defer cancel()
	store := db.DB.WithContext(ctx)
	c.Header("Cache-Control", "no-store")
	if !tenantView {
		p, ok := requireAssetDiscoveryNotebookProjectAccess(c, store, projectID)
		if !ok {
			return
		}
		projectID = p.ID
	}
	state := strings.TrimSpace(c.Query("state"))
	if state == "" {
		state = "active"
	}
	if state != "active" && state != "removed" && state != "all" {
		c.JSON(400, gin.H{"error": "invalid notebook state"})
		return
	}
	q := strings.TrimSpace(c.Query("q"))
	if !utf8.ValidString(q) || len(q) > 256 {
		c.JSON(400, gin.H{"error": "invalid notebook query"})
		return
	}
	tag := strings.ToLower(strings.TrimSpace(c.Query("tag")))
	if !utf8.ValidString(tag) || len(tag) > 64 {
		c.JSON(400, gin.H{"error": "invalid notebook tag"})
		return
	}
	page, size := parsePagination(c, 50, 100)
	off, ok := boundedPaginationOffset(page, size)
	if !ok {
		c.JSON(400, gin.H{"error": "invalid pagination"})
		return
	}
	query := store.Model(&db.AssetDiscoveryNotebookItem{}).Joins("JOIN projects ON projects.id = asset_discovery_notebook_items.project_id AND projects.tenant_id = asset_discovery_notebook_items.tenant_id")
	if tenantView {
		projectScope := scopedProjectsQuery(c).WithContext(ctx).Model(&db.Project{}).Select("projects.id")
		query = query.Where("asset_discovery_notebook_items.project_id IN (?)", projectScope)
		if requestedProjectID := strings.TrimSpace(c.Query("project_id")); requestedProjectID != "" {
			query = query.Where("asset_discovery_notebook_items.project_id = ?", requestedProjectID)
		}
	} else {
		query = query.Where("asset_discovery_notebook_items.project_id = ?", projectID)
	}
	query = query.Where("asset_discovery_notebook_items.tenant_id = ?", currentTenantID(c))
	if state == "active" {
		query = query.Where("asset_discovery_notebook_items.removed_at IS NULL")
	} else if state == "removed" {
		query = query.Where("asset_discovery_notebook_items.removed_at IS NOT NULL")
	}
	if q != "" {
		query = query.Where("LOWER(asset_discovery_notebook_items.normalized_target) LIKE ?", "%"+strings.ToLower(q)+"%")
	}
	if tag != "" {
		query = query.Joins("JOIN asset_discovery_notebook_item_tags nit ON nit.tenant_id=asset_discovery_notebook_items.tenant_id AND nit.project_id=asset_discovery_notebook_items.project_id AND nit.notebook_item_id=asset_discovery_notebook_items.id JOIN asset_discovery_notebook_tags nt ON nt.id=nit.tag_id AND nt.tenant_id=nit.tenant_id AND nt.project_id=nit.project_id").Where("nt.name = ?", tag)
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		writeAssetDiscoveryNotebookError(c, normalizeAssetDiscoveryNotebookStoreError(store, err))
		return
	}
	var rows []struct {
		db.AssetDiscoveryNotebookItem
		ProjectName string
	}
	if err := query.Select("asset_discovery_notebook_items.*, projects.name AS project_name").Order("asset_discovery_notebook_items.updated_at DESC, asset_discovery_notebook_items.id DESC").Offset(off).Limit(size).Scan(&rows).Error; err != nil {
		writeAssetDiscoveryNotebookError(c, normalizeAssetDiscoveryNotebookStoreError(store, err))
		return
	}
	ids := make([]uint, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.ID)
	}
	tags := map[uint][]string{}
	type sourceAggregate struct {
		Count int64
		First time.Time
		Last  time.Time
	}
	sources := map[uint]sourceAggregate{}
	if len(ids) > 0 {
		var links []struct {
			NotebookItemID uint
			Name           string
		}
		if err := store.Table("asset_discovery_notebook_item_tags").Select("asset_discovery_notebook_item_tags.notebook_item_id, asset_discovery_notebook_tags.name").Joins("JOIN asset_discovery_notebook_tags ON asset_discovery_notebook_tags.id=asset_discovery_notebook_item_tags.tag_id AND asset_discovery_notebook_tags.tenant_id=asset_discovery_notebook_item_tags.tenant_id AND asset_discovery_notebook_tags.project_id=asset_discovery_notebook_item_tags.project_id").Where("asset_discovery_notebook_item_tags.tenant_id=? AND asset_discovery_notebook_item_tags.notebook_item_id IN ?", currentTenantID(c), ids).Order("asset_discovery_notebook_tags.name").Scan(&links).Error; err != nil {
			writeAssetDiscoveryNotebookError(c, normalizeAssetDiscoveryNotebookStoreError(store, err))
			return
		}
		for _, x := range links {
			tags[x.NotebookItemID] = append(tags[x.NotebookItemID], x.Name)
		}
		var sourceRows []db.AssetDiscoveryNotebookSource
		if err := store.Select("notebook_item_id", "archived_at").Where("tenant_id=? AND notebook_item_id IN ?", currentTenantID(c), ids).Order("archived_at ASC, id ASC").Find(&sourceRows).Error; err != nil {
			writeAssetDiscoveryNotebookError(c, normalizeAssetDiscoveryNotebookStoreError(store, err))
			return
		}
		for _, source := range sourceRows {
			aggregate := sources[source.NotebookItemID]
			aggregate.Count++
			if aggregate.First.IsZero() || source.ArchivedAt.Before(aggregate.First) {
				aggregate.First = source.ArchivedAt
			}
			if source.ArchivedAt.After(aggregate.Last) {
				aggregate.Last = source.ArchivedAt
			}
			sources[source.NotebookItemID] = aggregate
		}
	}
	out := make([]notebookOperationItem, 0, len(rows))
	for _, r := range rows {
		source := sources[r.ID]
		if source.Count == 0 {
			source.First = r.CreatedAt
			source.Last = r.UpdatedAt
		}
		itemTags := tags[r.ID]
		if itemTags == nil {
			itemTags = []string{}
		}
		out = append(out, notebookOperationItem{
			ID: r.ID, ProjectID: r.ProjectID, ProjectName: r.ProjectName, Target: r.NormalizedTarget,
			SourceCount: source.Count, FirstArchivedAt: source.First, LastArchivedAt: source.Last, CreatedBy: r.CreatedBy,
			Tags: itemTags, Note: r.Note, RemovedAt: r.RemovedAt, RemovedBy: r.RemovedBy, UpdatedBy: r.UpdatedBy,
		})
	}
	c.JSON(200, notebookOperationList{
		SchemaVersion: "argus.asset-discovery-notebook/v2", ProjectID: projectID, Items: out, Total: total,
		Page: page, PageSize: size, HasMore: assetDiscoveryHistoryHasMore(total, off, size), GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	})
}
func patchProjectDiscoveryNotebookItem(c *gin.Context) {
	var req notebookOperationRequest
	if err := decodeNotebookOperation(c, &req); err != nil {
		c.JSON(400, gin.H{"error": "invalid notebook request"})
		return
	}
	mutateNotebookItem(c, "update", &req)
}
func removeProjectDiscoveryNotebookItem(c *gin.Context)  { mutateNotebookItem(c, "remove", nil) }
func restoreProjectDiscoveryNotebookItem(c *gin.Context) { mutateNotebookItem(c, "restore", nil) }
func decodeNotebookOperation(c *gin.Context, r *notebookOperationRequest) error {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, assetDiscoveryRequestLimit)
	d := json.NewDecoder(c.Request.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(r); err != nil {
		return err
	}
	if err := d.Decode(&struct{}{}); err != io.EOF {
		return errors.New("extra")
	}
	if r.Tags == nil && r.Note == nil {
		return errors.New("empty")
	}
	if r.Note != nil && !utf8.ValidString(*r.Note) || r.Note != nil && len(*r.Note) > 4096 {
		return errors.New("note")
	}
	if r.Tags != nil && len(*r.Tags) > 20 {
		return errors.New("tags")
	}
	return nil
}
func mutateNotebookItem(c *gin.Context, action string, req *notebookOperationRequest) {
	if db.DB == nil {
		c.JSON(500, gin.H{"error": "asset discovery database is unavailable"})
		return
	}
	id, e := strconv.ParseUint(c.Param("item_id"), 10, 64)
	if e != nil || id == 0 {
		c.JSON(400, gin.H{"error": "invalid notebook item id"})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), assetDiscoveryNotebookTimeout)
	defer cancel()
	store := db.DB.WithContext(ctx)
	p, ok := requireAssetDiscoveryNotebookProjectAccess(c, store, c.Param("id"))
	if !ok {
		return
	}
	if strings.EqualFold(p.Status, "archived") {
		c.JSON(409, gin.H{"error": "archived projects are read-only"})
		return
	}
	var tagNames []string
	if action == "update" && req.Tags != nil {
		var err error
		tagNames, err = normalizeNotebookTags(*req.Tags)
		if err != nil {
			c.JSON(400, gin.H{"error": "invalid notebook request"})
			return
		}
	}
	tenant, user := currentTenantID(c), currentUserID(c)
	err := store.Transaction(func(tx *gorm.DB) error {
		var project db.Project
		if e := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id=? AND tenant_id=?", p.ID, tenant).First(&project).Error; e != nil {
			return e
		}
		if strings.EqualFold(project.Status, "archived") {
			return errAssetDiscoveryNotebookProjectReadOnly
		}
		var item db.AssetDiscoveryNotebookItem
		if e := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id=? AND tenant_id=? AND project_id=?", id, tenant, p.ID).First(&item).Error; e != nil {
			return e
		}
		now := time.Now().UTC()
		changes := map[string]any{"updated_at": now, "updated_by": user}
		if action == "remove" {
			changes["removed_at"] = now
			changes["removed_by"] = user
		} else if action == "restore" {
			changes["removed_at"] = nil
			changes["removed_by"] = ""
		} else {
			if req.Note != nil {
				changes["note"] = *req.Note
			}
			if req.Tags != nil {
				if err := tx.Where("tenant_id=? AND project_id=? AND notebook_item_id=?", tenant, p.ID, id).Delete(&db.AssetDiscoveryNotebookItemTag{}).Error; err != nil {
					return err
				}
				for _, name := range tagNames {
					tag := db.AssetDiscoveryNotebookTag{TenantID: tenant, ProjectID: p.ID, Name: name, CreatedAt: now}
					if err := tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "tenant_id"}, {Name: "project_id"}, {Name: "name"}}, DoNothing: true}).Create(&tag).Error; err != nil {
						return err
					}
					if tag.ID == 0 {
						if err := tx.Where("tenant_id=? AND project_id=? AND name=?", tenant, p.ID, name).First(&tag).Error; err != nil {
							return err
						}
					}
					if err := tx.Create(&db.AssetDiscoveryNotebookItemTag{TenantID: tenant, ProjectID: p.ID, NotebookItemID: uint(id), TagID: tag.ID, CreatedAt: now}).Error; err != nil {
						return err
					}
				}
			}
		}
		if e := tx.Model(&item).Updates(changes).Error; e != nil {
			return e
		}
		notebookItemID := item.ID
		return tx.Create(&db.AssetDiscoveryAudit{
			TenantID: tenant, ProjectID: p.ID, NotebookItemID: &notebookItemID, Provider: "notebook",
			Action: "notebook_" + action, OperatorID: user, QueryHash: item.TargetHash,
			ConfigHash: notebookOperationChangeHash(item.ID, action, item.RemovedAt != nil, req, tagNames),
			Status:     "success", CreatedAt: now,
		}).Error
	})
	if err != nil {
		writeAssetDiscoveryNotebookError(c, normalizeAssetDiscoveryNotebookStoreError(store, err))
		return
	}
	c.Status(204)
}

func notebookOperationChangeHash(itemID uint, action string, beforeRemoved bool, req *notebookOperationRequest, tagNames []string) string {
	noteChanged, tagsChanged := false, false
	noteHash := ""
	if req != nil {
		noteChanged = req.Note != nil
		tagsChanged = req.Tags != nil
		if req.Note != nil {
			digest := sha256.Sum256([]byte(*req.Note))
			noteHash = fmt.Sprintf("%x", digest[:])
		}
	}
	sortedTags := append([]string(nil), tagNames...)
	slices.Sort(sortedTags)
	tagsDigest := sha256.Sum256([]byte(strings.Join(sortedTags, "\x00")))
	afterRemoved := beforeRemoved
	if action == "remove" {
		afterRemoved = true
	} else if action == "restore" {
		afterRemoved = false
	}
	payload := fmt.Sprintf("argus.notebook-operation/v1\x00%d\x00%s\x00%t\x00%t\x00%t\x00%s\x00%t\x00%x", itemID, action, beforeRemoved, afterRemoved, noteChanged, noteHash, tagsChanged, tagsDigest)
	digest := sha256.Sum256([]byte(payload))
	return fmt.Sprintf("%x", digest[:])
}
func normalizeNotebookTags(v []string) ([]string, error) {
	seen := map[string]bool{}
	out := []string{}
	for _, x := range v {
		x = strings.ToLower(strings.TrimSpace(x))
		if x == "" || len(x) > 64 {
			return nil, errors.New("tag")
		}
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out, nil
}
