package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/TokEat/argus/server/internal/assetdiscovery"
	"github.com/TokEat/argus/server/internal/db"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	assetDiscoverySnapshotTimeout   = 10 * time.Second
	assetDiscoverySnapshotBatchSize = 500
	assetDiscoverySnapshotItemLimit = 10000
)

var errInvalidAssetDiscoverySnapshot = errors.New("invalid asset discovery snapshot")

func completeProjectDiscoveryQuery(c *gin.Context, projectID string, request projectDiscoveryQueryRequest, result assetdiscovery.Result, audit *db.AssetDiscoveryAudit) {
	if request.Page > 1 {
		completeProjectDiscoveryPage(c, projectID, request, result, audit)
		return
	}
	completeProjectDiscoveryPreview(c, projectID, request, result, audit)
}

func completeProjectDiscoveryPreview(c *gin.Context, projectID string, request projectDiscoveryQueryRequest, result assetdiscovery.Result, audit *db.AssetDiscoveryAudit) {
	if result.Assets == nil {
		result.Assets = []assetdiscovery.Asset{}
	}
	audit.Status = "success"
	audit.ProviderTotal = result.ProviderTotal
	audit.ReturnedCount = len(result.Assets)
	audit.SkippedRows = result.SkippedRows
	audit.Truncated = result.Truncated

	snapshotID, err := persistAssetDiscoverySnapshot(audit, request, result)
	if err != nil {
		// The successful audit belongs to the rolled-back transaction. Record a
		// separate stable failure audit when possible, but never expose results
		// if either the snapshot or audit path is unavailable.
		audit.ID = 0
		audit.Status = "failed"
		audit.ReturnedCount = 0
		if errors.Is(err, errInvalidAssetDiscoverySnapshot) {
			audit.ErrorCode = "snapshot_validation_failed"
		} else {
			audit.ErrorCode = "snapshot_persistence_failed"
		}
		_ = saveAssetDiscoveryAudit(audit)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to persist asset discovery result"})
		return
	}

	c.JSON(http.StatusOK, projectDiscoveryQueryResponse{
		SchemaVersion: assetDiscoveryPreviewSchema,
		ProjectID:     projectID,
		AuditID:       audit.ID,
		SnapshotID:    snapshotID,
		Provider:      result.Provider,
		ProviderTotal: result.ProviderTotal,
		ReturnedCount: len(result.Assets),
		Page:          request.Page,
		PageSize:      result.PageSize,
		HasMore:       result.Truncated,
		SkippedRows:   result.SkippedRows,
		Truncated:     result.Truncated,
		Assets:        result.Assets,
	})
}

func persistAssetDiscoverySnapshot(audit *db.AssetDiscoveryAudit, request projectDiscoveryQueryRequest, result assetdiscovery.Result) (uint, error) {
	if db.DB == nil || audit == nil {
		return 0, errors.New("asset discovery database is unavailable")
	}
	snapshot, items, err := buildAssetDiscoverySnapshot(audit, request, result, time.Now().UTC())
	if err != nil {
		return 0, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), assetDiscoverySnapshotTimeout)
	defer cancel()
	err = db.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(audit).Error; err != nil {
			return fmt.Errorf("create asset discovery audit: %w", err)
		}
		snapshot.AuditID = audit.ID
		if err := tx.Create(&snapshot).Error; err != nil {
			return fmt.Errorf("create asset discovery snapshot: %w", err)
		}
		for index := range items {
			items[index].SnapshotID = snapshot.ID
		}
		if len(items) > 0 {
			if err := tx.CreateInBatches(&items, assetDiscoverySnapshotBatchSize).Error; err != nil {
				return fmt.Errorf("create asset discovery snapshot items: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return snapshot.ID, nil
}

func completeProjectDiscoveryPage(c *gin.Context, projectID string, request projectDiscoveryQueryRequest, result assetdiscovery.Result, audit *db.AssetDiscoveryAudit) {
	if result.Assets == nil {
		result.Assets = []assetdiscovery.Asset{}
	}
	audit.Status = "success"
	audit.ProviderTotal = result.ProviderTotal
	audit.ReturnedCount = len(result.Assets)
	audit.SkippedRows = result.SkippedRows
	audit.Truncated = result.Truncated

	snapshot, appended, err := appendAssetDiscoverySnapshotPage(audit, request, result, time.Now().UTC())
	if err != nil {
		audit.ID = 0
		audit.Status = "failed"
		audit.ReturnedCount = 0
		if errors.Is(err, errInvalidAssetDiscoverySnapshot) {
			audit.ErrorCode = "snapshot_validation_failed"
		} else {
			audit.ErrorCode = "snapshot_persistence_failed"
		}
		_ = saveAssetDiscoveryAudit(audit)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to persist asset discovery result"})
		return
	}

	c.JSON(http.StatusOK, projectDiscoveryQueryResponse{
		SchemaVersion: assetDiscoveryPreviewSchema,
		ProjectID:     projectID,
		AuditID:       audit.ID,
		SnapshotID:    request.SnapshotID,
		Provider:      result.Provider,
		ProviderTotal: result.ProviderTotal,
		ReturnedCount: snapshot.ReturnedCount,
		Page:          request.Page,
		PageSize:      result.PageSize,
		HasMore:       result.Truncated && !assetDiscoverySnapshotIsFull(snapshot),
		SkippedRows:   result.SkippedRows,
		Truncated:     result.Truncated,
		Assets:        appended,
	})
}

// appendAssetDiscoverySnapshotPage adds one provider page to an existing
// immutable snapshot. Positions continue after the stored items, targets are
// deduplicated by hash, and any insert race is absorbed by the unique index
// with OnConflict DoNothing. A stable snapshot-item cap keeps the snapshot,
// export and notebook budgets unchanged; the page response then reports no
// more pages so callers stop paging.
func appendAssetDiscoverySnapshotPage(audit *db.AssetDiscoveryAudit, request projectDiscoveryQueryRequest, result assetdiscovery.Result, observedAt time.Time) (*db.AssetDiscoverySnapshot, []assetdiscovery.Asset, error) {
	if db.DB == nil || audit == nil {
		return nil, nil, errors.New("asset discovery database is unavailable")
	}
	provider := strings.ToLower(strings.TrimSpace(audit.Provider))
	if audit.TenantID == "" || audit.ProjectID == "" || audit.OperatorID == "" || provider == "" || request.SnapshotID == 0 ||
		provider != strings.ToLower(strings.TrimSpace(result.Provider)) || len(provider) > 32 ||
		request.Limit < 1 || result.ProviderTotal < 0 || result.SkippedRows < 0 {
		return nil, nil, errInvalidAssetDiscoverySnapshot
	}

	ctx, cancel := context.WithTimeout(context.Background(), assetDiscoverySnapshotTimeout)
	defer cancel()
	var persistedSnapshot *db.AssetDiscoverySnapshot
	appended := make([]assetdiscovery.Asset, 0, len(result.Assets))
	err := db.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(audit).Error; err != nil {
			return fmt.Errorf("create asset discovery audit: %w", err)
		}
		var snapshot db.AssetDiscoverySnapshot
		if err := tx.Select("id", "tenant_id", "project_id", "provider", "expression", "returned_count", "provider_total", "skipped_rows", "truncated").
			Where("id = ? AND tenant_id = ? AND project_id = ?", request.SnapshotID, audit.TenantID, audit.ProjectID).
			First(&snapshot).Error; err != nil {
			return fmt.Errorf("load asset discovery snapshot: %w", err)
		}
		if snapshot.Provider != provider {
			return fmt.Errorf("%w: provider mismatch", errInvalidAssetDiscoverySnapshot)
		}

		var existingItems []string
		if err := tx.Model(&db.AssetDiscoverySnapshotItem{}).
			Where("snapshot_id = ?", snapshot.ID).Pluck("target_hash", &existingItems).Error; err != nil {
			return fmt.Errorf("load asset discovery snapshot items: %w", err)
		}
		existing := make(map[string]struct{}, len(existingItems))
		for _, targetHash := range existingItems {
			existing[targetHash] = struct{}{}
		}
		nextPosition := len(existingItems)
		items := make([]db.AssetDiscoverySnapshotItem, 0, len(result.Assets))
		assetByHash := make([]assetdiscovery.Asset, 0, len(result.Assets))
		atCap := false
		for _, asset := range result.Assets {
			item, err := buildAssetDiscoverySnapshotItem(audit, provider, asset, nextPosition, observedAt)
			if err != nil {
				return err
			}
			if _, duplicate := existing[item.TargetHash]; duplicate {
				continue
			}
			if nextPosition >= assetDiscoverySnapshotItemLimit {
				atCap = true
				break
			}
			item.SnapshotID = snapshot.ID
			existing[item.TargetHash] = struct{}{}
			items = append(items, item)
			assetByHash = append(assetByHash, asset)
			nextPosition++
		}
		if len(items) > 0 {
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).CreateInBatches(&items, assetDiscoverySnapshotBatchSize).Error; err != nil {
				return fmt.Errorf("create asset discovery snapshot items: %w", err)
			}
		}
		var totalCount int64
		if err := tx.Model(&db.AssetDiscoverySnapshotItem{}).Where("snapshot_id = ?", snapshot.ID).Count(&totalCount).Error; err != nil {
			return fmt.Errorf("count asset discovery snapshot items: %w", err)
		}
		snapshot.ReturnedCount = int(totalCount)
		if result.ProviderTotal > snapshot.ProviderTotal {
			snapshot.ProviderTotal = result.ProviderTotal
		}
		snapshot.SkippedRows += result.SkippedRows
		snapshot.Truncated = snapshot.Truncated || result.Truncated || atCap
		if err := tx.Model(&db.AssetDiscoverySnapshot{}).Where("id = ?", snapshot.ID).Updates(map[string]interface{}{
			"returned_count": snapshot.ReturnedCount,
			"provider_total": snapshot.ProviderTotal,
			"skipped_rows":   snapshot.SkippedRows,
			"truncated":      snapshot.Truncated,
		}).Error; err != nil {
			return fmt.Errorf("update asset discovery snapshot: %w", err)
		}
		persistedSnapshot = &snapshot
		appended = assetByHash
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return persistedSnapshot, appended, nil
}

// loadDiscoverySnapshotExpression re-reads the stored expression before a
// paged provider fetch. Callers must not send the expression again for pages
// after the first, so this is also the tenant/project ownership and provider
// compatibility check that runs before any provider network call.
func loadDiscoverySnapshotExpression(c *gin.Context, projectID, provider string, request projectDiscoveryQueryRequest, audit *db.AssetDiscoveryAudit, startedAt time.Time) (string, bool) {
	if request.Page == 1 {
		return request.Expression, true
	}
	audit.DurationMS = time.Since(startedAt).Milliseconds()
	if db.DB == nil {
		audit.ErrorCode = "snapshot_unavailable"
		if !saveAssetDiscoveryAudit(audit) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to record asset discovery audit"})
			return "", false
		}
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "asset discovery database is unavailable"})
		return "", false
	}
	ctx, cancel := context.WithTimeout(context.Background(), assetDiscoverySnapshotTimeout)
	defer cancel()
	var snapshot db.AssetDiscoverySnapshot
	if err := db.DB.WithContext(ctx).Select("id", "tenant_id", "project_id", "provider", "expression", "query_hash", "returned_count").
		Where("id = ? AND tenant_id = ? AND project_id = ?", request.SnapshotID, currentTenantID(c), projectID).
		First(&snapshot).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			audit.ErrorCode = "snapshot_not_found"
			if !saveAssetDiscoveryAudit(audit) {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to record asset discovery audit"})
				return "", false
			}
			c.JSON(http.StatusNotFound, gin.H{"error": "asset discovery query not found"})
			return "", false
		}
		audit.ErrorCode = "snapshot_unavailable"
		if !saveAssetDiscoveryAudit(audit) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to record asset discovery audit"})
			return "", false
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load asset discovery query"})
		return "", false
	}
	if snapshot.Provider != provider {
		audit.ErrorCode = "snapshot_provider_mismatch"
		if !saveAssetDiscoveryAudit(audit) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to record asset discovery audit"})
			return "", false
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "asset discovery query provider does not match"})
		return "", false
	}
	// Later pages carry no expression, so the audit keeps correlating with the
	// original query through the snapshot's expression hash.
	audit.QueryHash = snapshot.QueryHash
	if snapshot.ReturnedCount >= assetDiscoverySnapshotItemLimit {
		audit.ErrorCode = "snapshot_limit_reached"
		audit.ProviderTotal = snapshot.ProviderTotal
		if !saveAssetDiscoveryAudit(audit) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to record asset discovery audit"})
			return "", false
		}
		c.JSON(http.StatusConflict, gin.H{"error": "asset discovery query already reached the snapshot limit"})
		return "", false
	}
	return snapshot.Expression, true
}

// assetDiscoverySnapshotIsFull reports whether the snapshot reached the
// per-query storage cap.
func assetDiscoverySnapshotIsFull(snapshot *db.AssetDiscoverySnapshot) bool {
	return snapshot != nil && snapshot.ReturnedCount >= assetDiscoverySnapshotItemLimit
}

func buildAssetDiscoverySnapshot(audit *db.AssetDiscoveryAudit, request projectDiscoveryQueryRequest, result assetdiscovery.Result, observedAt time.Time) (db.AssetDiscoverySnapshot, []db.AssetDiscoverySnapshotItem, error) {
	var snapshot db.AssetDiscoverySnapshot
	provider := strings.ToLower(strings.TrimSpace(audit.Provider))
	if audit.TenantID == "" || audit.ProjectID == "" || audit.OperatorID == "" || provider == "" ||
		provider != strings.ToLower(strings.TrimSpace(result.Provider)) || len(provider) > 32 ||
		request.Expression == "" || len(request.Expression) > assetdiscovery.MaxFOFAQueryBytes ||
		!validSnapshotText(request.Expression, assetdiscovery.MaxFOFAQueryBytes, true) || strings.ContainsAny(request.Expression, "\r\n\x00") ||
		request.Limit < 1 || result.ProviderTotal < 0 || result.SkippedRows < 0 || len(result.Assets) > assetDiscoverySnapshotItemLimit {
		return snapshot, nil, errInvalidAssetDiscoverySnapshot
	}
	if !validSHA256Hex(audit.QueryHash) || !validSHA256Hex(audit.ConfigHash) {
		return snapshot, nil, errInvalidAssetDiscoverySnapshot
	}

	snapshot = db.AssetDiscoverySnapshot{
		SchemaVersion:  db.AssetDiscoverySnapshotSchemaVersion,
		TenantID:       audit.TenantID,
		ProjectID:      audit.ProjectID,
		Provider:       provider,
		Expression:     request.Expression,
		QueryHash:      audit.QueryHash,
		ConfigVersion:  audit.ConfigVersion,
		ConfigHash:     audit.ConfigHash,
		RequestedLimit: request.Limit,
		ProviderTotal:  result.ProviderTotal,
		ReturnedCount:  len(result.Assets),
		SkippedRows:    result.SkippedRows,
		Truncated:      result.Truncated,
		CreatedBy:      audit.OperatorID,
		CreatedAt:      observedAt,
	}
	items := make([]db.AssetDiscoverySnapshotItem, 0, len(result.Assets))
	targetsByHash := make(map[string]string, len(result.Assets))
	for position, asset := range result.Assets {
		item, err := buildAssetDiscoverySnapshotItem(audit, provider, asset, position, observedAt)
		if err != nil {
			return db.AssetDiscoverySnapshot{}, nil, err
		}
		if _, exists := targetsByHash[item.TargetHash]; exists {
			return db.AssetDiscoverySnapshot{}, nil, errInvalidAssetDiscoverySnapshot
		}
		targetsByHash[item.TargetHash] = item.NormalizedTarget
		items = append(items, item)
	}
	return snapshot, items, nil
}

func buildAssetDiscoverySnapshotItem(audit *db.AssetDiscoveryAudit, provider string, asset assetdiscovery.Asset, position int, observedAt time.Time) (db.AssetDiscoverySnapshotItem, error) {
	target := strings.TrimSpace(asset.Target)
	source := strings.ToLower(strings.TrimSpace(asset.Source))
	if !validStructuredSnapshotText(target, 8192, false) || source != provider || !validStructuredSnapshotText(source, 32, false) ||
		!validStructuredSnapshotText(asset.IP, 64, true) || !validStructuredSnapshotText(asset.Domain, 255, true) ||
		!validStructuredSnapshotText(asset.Protocol, 32, true) || !validSnapshotText(asset.Title, 1024, true) ||
		!validSnapshotText(asset.ICP, 1024, true) || !validSnapshotText(asset.Country, 128, true) ||
		!validSnapshotText(asset.City, 128, true) || !validSnapshotText(asset.Company, 1024, true) ||
		asset.Port < 0 || asset.Port > 65535 || asset.StatusCode < 0 || asset.StatusCode > 999 {
		return db.AssetDiscoverySnapshotItem{}, errInvalidAssetDiscoverySnapshot
	}
	digest := sha256.Sum256([]byte(target))
	return db.AssetDiscoverySnapshotItem{
		TenantID:         audit.TenantID,
		ProjectID:        audit.ProjectID,
		Position:         position,
		NormalizedTarget: target,
		TargetHash:       hex.EncodeToString(digest[:]),
		IP:               asset.IP,
		Port:             asset.Port,
		Domain:           asset.Domain,
		Protocol:         asset.Protocol,
		Title:            asset.Title,
		ICP:              asset.ICP,
		Country:          asset.Country,
		City:             asset.City,
		Company:          asset.Company,
		StatusCode:       asset.StatusCode,
		Source:           source,
		ObservedAt:       observedAt,
		CreatedAt:        observedAt,
	}, nil
}

func validSHA256Hex(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validStructuredSnapshotText(value string, maxBytes int, allowEmpty bool) bool {
	return validSnapshotText(value, maxBytes, allowEmpty) && !hasControlCharacters(value)
}

func validSnapshotText(value string, maxBytes int, allowEmpty bool) bool {
	if (!allowEmpty && value == "") || len(value) > maxBytes || !utf8.ValidString(value) || strings.ContainsRune(value, '\x00') {
		return false
	}
	return true
}
