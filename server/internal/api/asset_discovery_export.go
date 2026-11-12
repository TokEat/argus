package api

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/TokEat/argus/server/internal/db"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const (
	assetDiscoveryExportMaxBytes  = 32 << 20
	assetDiscoveryExportBatchSize = 500
)

var errAssetDiscoveryExportLimit = errors.New("asset discovery export limit exceeded")

type assetDiscoveryExportBuffer struct {
	bytes.Buffer
	limit int
}

func (buffer *assetDiscoveryExportBuffer) Write(data []byte) (int, error) {
	if len(data) > buffer.limit-buffer.Len() {
		return 0, errAssetDiscoveryExportLimit
	}
	return buffer.Buffer.Write(data)
}

func exportProjectDiscoveryQuery(c *gin.Context) {
	startedAt := time.Now()
	if db.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "asset discovery database is unavailable"})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), assetDiscoveryHistoryQueryTimeout)
	defer cancel()
	store := db.DB.WithContext(ctx)
	project, ok := requireAssetDiscoveryExportProjectAccess(c, store, c.Param("id"))
	if !ok {
		return
	}
	c.Header("Cache-Control", "no-store")

	snapshotID, err := strconv.ParseUint(strings.TrimSpace(c.Param("snapshot_id")), 10, strconv.IntSize)
	if err != nil || snapshotID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid asset discovery query id"})
		return
	}

	var snapshot db.AssetDiscoverySnapshot
	if err := store.Select(assetDiscoverySnapshotExportColumns()).
		Where("id = ? AND tenant_id = ? AND project_id = ?", uint(snapshotID), currentTenantID(c), project.ID).
		First(&snapshot).Error; err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || ctx.Err() != nil {
			c.JSON(http.StatusGatewayTimeout, gin.H{"error": "asset discovery export timed out"})
			return
		}
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "asset discovery query not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load asset discovery query"})
		return
	}

	content, exportedRows, err := buildAssetDiscoverySnapshotCSV(store, snapshot)
	if err != nil {
		errorCode := "export_failed"
		statusCode := http.StatusInternalServerError
		message := "failed to export asset discovery query"
		if errors.Is(err, errAssetDiscoveryExportLimit) {
			errorCode = "export_limit_exceeded"
			statusCode = http.StatusRequestEntityTooLarge
			message = "asset discovery query is too large to export"
		} else if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			errorCode = "export_timeout"
			statusCode = http.StatusGatewayTimeout
			message = "asset discovery export timed out"
		}
		_ = store.Create(newAssetDiscoveryExportAudit(c, snapshot, "failed", errorCode, 0, startedAt)).Error
		c.JSON(statusCode, gin.H{"error": message})
		return
	}

	if err := store.Create(newAssetDiscoveryExportAudit(c, snapshot, "success", "", exportedRows, startedAt)).Error; err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || ctx.Err() != nil {
			c.JSON(http.StatusGatewayTimeout, gin.H{"error": "asset discovery export timed out"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to audit asset discovery export"})
		return
	}

	filename := fmt.Sprintf("argus-asset-discovery-%d.csv", snapshot.ID)
	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	c.Header("X-Content-Type-Options", "nosniff")
	c.Data(http.StatusOK, "text/csv; charset=utf-8", content)
}

func requireAssetDiscoveryExportProjectAccess(c *gin.Context, store *gorm.DB, projectID string) (db.Project, bool) {
	var project db.Project
	if strings.TrimSpace(projectID) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "project_id is required"})
		return project, false
	}
	if err := scopedProjectsQuery(c).WithContext(store.Statement.Context).Where("id = ?", projectID).First(&project).Error; err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || store.Statement.Context.Err() != nil {
			c.JSON(http.StatusGatewayTimeout, gin.H{"error": "asset discovery export timed out"})
			return project, false
		}
		c.JSON(http.StatusForbidden, gin.H{"error": "project not accessible"})
		return project, false
	}
	return project, true
}

func assetDiscoverySnapshotExportColumns() []string {
	return append(assetDiscoverySnapshotPublicColumns(), "tenant_id", "project_id", "query_hash", "config_hash")
}

func buildAssetDiscoverySnapshotCSV(store *gorm.DB, snapshot db.AssetDiscoverySnapshot) ([]byte, int, error) {
	if err := store.Statement.Context.Err(); err != nil {
		return nil, 0, err
	}
	itemQuery := store.Model(&db.AssetDiscoverySnapshotItem{}).
		Where("tenant_id = ? AND project_id = ? AND snapshot_id = ?", snapshot.TenantID, snapshot.ProjectID, snapshot.ID)
	var total int64
	if err := itemQuery.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	if total > assetDiscoverySnapshotItemLimit {
		return nil, 0, errAssetDiscoveryExportLimit
	}

	buffer := &assetDiscoveryExportBuffer{limit: assetDiscoveryExportMaxBytes}
	if _, err := buffer.Write([]byte{0xef, 0xbb, 0xbf}); err != nil {
		return nil, 0, err
	}
	writer := csv.NewWriter(buffer)
	if err := writer.Write([]string{
		"SnapshotID", "Provider", "SnapshotCreatedAt", "Position", "Target", "IP", "Port", "Domain",
		"Protocol", "Title", "ICP", "Country", "City", "Company", "StatusCode", "Source", "ObservedAt",
	}); err != nil {
		return nil, 0, err
	}

	exportedRows := 0
	for offset := 0; offset < int(total); offset += assetDiscoveryExportBatchSize {
		if err := store.Statement.Context.Err(); err != nil {
			return nil, 0, err
		}
		var items []db.AssetDiscoverySnapshotItem
		if err := itemQuery.Select(assetDiscoverySnapshotItemPublicColumns()).
			Order("position ASC, id ASC").Offset(offset).Limit(assetDiscoveryExportBatchSize).Find(&items).Error; err != nil {
			return nil, 0, err
		}
		for _, item := range items {
			if err := store.Statement.Context.Err(); err != nil {
				return nil, 0, err
			}
			if err := writer.Write([]string{
				strconv.FormatUint(uint64(snapshot.ID), 10),
				protectAssetDiscoveryCSVCell(snapshot.Provider),
				snapshot.CreatedAt.UTC().Format(time.RFC3339),
				strconv.Itoa(item.Position),
				protectAssetDiscoveryCSVCell(item.NormalizedTarget),
				protectAssetDiscoveryCSVCell(item.IP),
				strconv.Itoa(item.Port),
				protectAssetDiscoveryCSVCell(item.Domain),
				protectAssetDiscoveryCSVCell(item.Protocol),
				protectAssetDiscoveryCSVCell(item.Title),
				protectAssetDiscoveryCSVCell(item.ICP),
				protectAssetDiscoveryCSVCell(item.Country),
				protectAssetDiscoveryCSVCell(item.City),
				protectAssetDiscoveryCSVCell(item.Company),
				strconv.Itoa(item.StatusCode),
				protectAssetDiscoveryCSVCell(item.Source),
				item.ObservedAt.UTC().Format(time.RFC3339),
			}); err != nil {
				return nil, 0, err
			}
			exportedRows++
		}
		writer.Flush()
		if err := writer.Error(); err != nil {
			return nil, 0, err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, 0, err
	}
	return buffer.Bytes(), exportedRows, nil
}

func protectAssetDiscoveryCSVCell(value string) string {
	if value == "" {
		return value
	}
	trimmed := strings.TrimLeftFunc(value, unicode.IsSpace)
	leading := value[:len(value)-len(trimmed)]
	if strings.ContainsAny(leading, "\t\r\n") {
		return "'" + value
	}
	if trimmed == "" {
		return value
	}
	switch trimmed[0] {
	case '=', '+', '-', '@':
		return "'" + value
	default:
		return value
	}
}

func newAssetDiscoveryExportAudit(c *gin.Context, snapshot db.AssetDiscoverySnapshot, status, errorCode string, exportedRows int, startedAt time.Time) *db.AssetDiscoveryAudit {
	return &db.AssetDiscoveryAudit{
		TenantID:       snapshot.TenantID,
		ProjectID:      snapshot.ProjectID,
		Provider:       snapshot.Provider,
		Action:         "export_snapshot",
		OperatorID:     currentUserID(c),
		QueryHash:      snapshot.QueryHash,
		ConfigVersion:  snapshot.ConfigVersion,
		ConfigHash:     snapshot.ConfigHash,
		RequestedLimit: snapshot.RequestedLimit,
		ProviderTotal:  snapshot.ProviderTotal,
		ReturnedCount:  exportedRows,
		SkippedRows:    snapshot.SkippedRows,
		Truncated:      snapshot.Truncated,
		Status:         status,
		ErrorCode:      errorCode,
		DurationMS:     time.Since(startedAt).Milliseconds(),
		CreatedAt:      time.Now().UTC(),
	}
}
