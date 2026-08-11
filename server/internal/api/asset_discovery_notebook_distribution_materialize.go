package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const assetDiscoveryNotebookDistributionMaterializeSchema = "argus.asset-discovery-notebook-distribution/v1"

var (
	errNotebookDistributionPreviewExpired = errors.New("notebook distribution preview expired")
)

type notebookDistributionMaterializeRequest struct {
	TaskID   string `json:"task_id"`
	ItemIDs  []uint `json:"item_ids"`
	PlanHash string `json:"plan_hash"`
}

type notebookDistributionMaterializeResponse struct {
	SchemaVersion string `json:"schema_version"`
	ProjectID     string `json:"project_id"`
	Task          struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	} `json:"task"`
	IntentID uint   `json:"intent_id"`
	Replayed bool   `json:"replayed"`
	Outcome  string `json:"outcome"`
	Counts   struct {
		Requested               int `json:"requested"`
		Fresh                   int `json:"fresh"`
		Duplicates              int `json:"duplicates"`
		ProjectScopeAdded       int `json:"project_scope_added"`
		ProjectSeedTargetsAdded int `json:"project_seed_targets_added"`
		BatchesCreated          int `json:"batches_created"`
		AttemptsCreated         int `json:"attempts_created"`
	} `json:"counts"`
	BatchIDs   []string `json:"batch_ids"`
	AttemptIDs []string `json:"attempt_ids"`
	Dispatch   struct {
		Dispatched int `json:"dispatched"`
		Pending    int `json:"pending"`
	} `json:"dispatch"`
}

func materializeProjectNotebookDistribution(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	if db.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "asset discovery notebook distribution unavailable"})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), assetDiscoveryNotebookTimeout)
	defer cancel()
	store := db.DB.WithContext(ctx)
	project, ok := requireAssetDiscoveryNotebookProjectAccess(c, store, c.Param("id"))
	if !ok {
		return
	}
	req, err := decodeNotebookDistributionMaterializeRequest(c)
	if err != nil {
		status := http.StatusBadRequest
		if errors.As(err, new(*http.MaxBytesError)) {
			status = http.StatusRequestEntityTooLarge
		}
		c.JSON(status, gin.H{"error": "invalid asset discovery notebook distribution confirmation"})
		return
	}
	key := strings.TrimSpace(c.GetHeader("Idempotency-Key"))
	if !validNotebookDistributionIdempotencyKey(key) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "valid Idempotency-Key is required"})
		return
	}
	result := notebookDistributionMaterializeResponse{SchemaVersion: assetDiscoveryNotebookDistributionMaterializeSchema, ProjectID: project.ID}
	var prepared []db.SubTask
	shouldDispatch := false
	err = store.Transaction(func(tx *gorm.DB) error {
		if intent, materialization, replayed, err := db.FindAssetDiscoveryNotebookDistributionReplayTx(tx, currentTenantID(c), project.ID, taskOperatorID(c), key, req.TaskID, req.PlanHash, req.ItemIDs); err != nil {
			return err
		} else if replayed {
			var responseErr error
			result, responseErr = materializeResponseFromIntentAndResult(tx, intent, materialization, true)
			return responseErr
		}
		var task db.RootTask
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ? AND tenant_id = ? AND project_id = ?", req.TaskID, currentTenantID(c), project.ID).
			First(&task).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return errNotebookDistributionTaskNotFound
			}
			return err
		}
		if task.ArchivedAt != nil || !taskCanAppendPreview(task.Status) {
			return errNotebookDistributionConflict
		}
		if intent, materialization, replayed, err := db.FindAssetDiscoveryNotebookDistributionReplayTx(tx, currentTenantID(c), project.ID, taskOperatorID(c), key, req.TaskID, req.PlanHash, req.ItemIDs); err != nil {
			return err
		} else if replayed {
			var responseErr error
			result, responseErr = materializeResponseFromIntentAndResult(tx, intent, materialization, true)
			return responseErr
		}
		var currentProject db.Project
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ? AND tenant_id = ?", project.ID, currentTenantID(c)).First(&currentProject).Error; err != nil {
			return err
		}
		if !strings.EqualFold(strings.TrimSpace(currentProject.Status), "active") {
			return errProjectInactive
		}

		preview, err := buildNotebookDistributionPreview(tx, c, currentProject, notebookDistributionPreviewRequest{TaskID: req.TaskID, ItemIDs: append([]uint(nil), req.ItemIDs...)})
		if err != nil {
			return err
		}
		if !constantNotebookDistributionHashEqual(preview.PlanHash, req.PlanHash) {
			return errNotebookDistributionPreviewExpired
		}
		revision, err := db.CurrentTaskConfigRevision(tx, task)
		if err != nil {
			return err
		}
		if _, mode, err := normalizeTaskConfigPayload(json.RawMessage(revision.Config)); err != nil || mode != taskTargetModeDirect {
			return errNotebookDistributionConflict
		}

		snapshots := make([]db.AssetDiscoveryNotebookDistributionIntentItemSnapshot, 0, len(preview.Items))
		freshTargets := make([]string, 0, preview.Counts.Fresh)
		for _, item := range preview.Items {
			disposition := item.Disposition
			if disposition != "new" && disposition != "duplicate" {
				return errNotebookDistributionConflict
			}
			snapshots = append(snapshots, db.AssetDiscoveryNotebookDistributionIntentItemSnapshot{
				NotebookItemID: item.ItemID, NormalizedTarget: item.Target,
				TargetHash: notebookDistributionTargetHash(item.Target), Disposition: disposition,
			})
			if disposition == "new" {
				freshTargets = append(freshTargets, item.Target)
			}
		}
		intentResult, err := db.RecordAssetDiscoveryNotebookDistributionIntentTx(tx, db.AssetDiscoveryNotebookDistributionIntentDraft{
			SchemaVersion: db.AssetDiscoveryNotebookDistributionIntentSchemaVersion, PreviewSchemaVersion: db.AssetDiscoveryNotebookDistributionPreviewSchemaVersion,
			TenantID: task.TenantID, ProjectID: task.ProjectID, RootTaskID: task.ID, OperatorID: taskOperatorID(c), IdempotencyKey: key,
			PlanHash: preview.PlanHash, TaskStatus: task.Status, ConfigVersion: revision.Version, ConfigHash: revision.ConfigHash, RuleVersion: preview.Task.RuleVersion,
			Selected: preview.Counts.Selected, Fresh: preview.Counts.Fresh, Duplicate: preview.Counts.Duplicates,
			ScopeAdded: preview.Counts.ProjectScopeAdded, SeedTargetsAdded: preview.Counts.ProjectSeedTargetsAdded, BatchCount: preview.BatchProfile.TotalBatches,
		}, snapshots)
		if err != nil {
			return err
		}
		result = materializeResponseFromIntent(intentResult.Intent, intentResult.Replayed)
		if intentResult.Replayed {
			var materialization db.AssetDiscoveryNotebookDistributionMaterialization
			if err := tx.Where("tenant_id = ? AND project_id = ? AND intent_id = ?", task.TenantID, task.ProjectID, intentResult.Intent.ID).First(&materialization).Error; err != nil {
				return err
			}
			result, err = materializeResponseFromIntentAndResult(tx, intentResult.Intent, materialization, true)
			if err != nil {
				return err
			}
			return nil
		}
		if len(freshTargets) == 0 {
			encodedEmpty, err := json.Marshal([]string{})
			if err != nil {
				return err
			}
			if err := tx.Create(&db.AssetDiscoveryNotebookDistributionMaterialization{TenantID: task.TenantID, ProjectID: task.ProjectID, IntentID: intentResult.Intent.ID, RootTaskID: task.ID, Status: "unchanged", TaskStatus: task.Status, BatchIDs: string(encodedEmpty), AttemptIDs: string(encodedEmpty)}).Error; err != nil {
				return err
			}
			result.Task.Status = task.Status
			result.Outcome = "unchanged"
			return nil
		}

		var batches []db.TaskBatch
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("tenant_id = ? AND root_task_id = ?", task.TenantID, task.ID).Order("sequence ASC").Find(&batches).Error; err != nil {
			return err
		}
		maxSequence := -1
		for _, batch := range batches {
			if batch.Sequence > maxSequence {
				maxSequence = batch.Sequence
			}
		}
		groups := groupAndBatchTargets(freshTargets, taskTargetModeDirect)
		if len(groups) != preview.BatchProfile.TotalBatches {
			return errNotebookDistributionPreviewExpired
		}
		attemptStatus, afterStatus := subTaskStatusDispatching, "Running"
		if db.CanonicalTaskState(task.Status) == db.TaskStatePaused {
			attemptStatus, afterStatus = "Paused", "Paused"
		} else {
			shouldDispatch = true
		}
		userSelector := parseSelectorJSONString(revision.AgentSelector)
		userRules := db.ParseSelectorRulesJSON(revision.AgentSelectorRules)
		newBatches := make([]db.TaskBatch, 0, len(groups))
		newAttempts := make([]db.SubTask, 0, len(groups))
		batchIDs := make([]string, 0, len(groups))
		for index, group := range groups {
			chunkJSON, err := json.Marshal(group.Targets)
			if err != nil {
				return err
			}
			sequence := maxSequence + 1 + index
			batchID := fmt.Sprintf("%s-batch-%d-%s", task.ID, sequence, group.TargetType)
			attemptID := fmt.Sprintf("%s-attempt-1", batchID)
			effectiveSelector := mergeAgentSelector(group.SelectorJSON, userSelector)
			_, _, rulesJSON := effectiveSelectorRules(group.SelectorJSON, userSelector, userRules)
			newBatches = append(newBatches, db.TaskBatch{ID: batchID, TenantID: task.TenantID, ProjectID: task.ProjectID, RootTaskID: task.ID, Sequence: sequence, Kind: "asset_scan", TargetType: group.TargetType, Targets: string(chunkJSON), TargetCount: len(group.Targets), Status: attemptStatus, ConfigVersion: revision.Version, RuleVersion: preview.Task.RuleVersion, Priority: revision.Priority, TimeoutSec: revision.TimeoutSec, AgentSelector: effectiveSelector, AgentSelectorRules: rulesJSON, CurrentAttemptNo: 1, AttemptCount: 1, LatestAttemptID: attemptID, CreatedBy: taskOperatorID(c)})
			newAttempts = append(newAttempts, db.SubTask{ID: attemptID, TenantID: task.TenantID, ProjectID: task.ProjectID, RootTaskID: task.ID, BatchID: batchID, AttemptNo: 1, Trigger: db.AttemptTriggerInitial, ChunkTargets: string(chunkJSON), Status: attemptStatus, Config: revision.Config, Priority: revision.Priority, TimeoutSec: revision.TimeoutSec, MaxRetry: 3, ConfigVersion: revision.Version, RuleVersion: preview.Task.RuleVersion, AgentSelector: effectiveSelector, AgentSelectorRules: rulesJSON})
			batchIDs = append(batchIDs, batchID)
		}
		seedTargets, seedAdded, _, err := mergeStoredTargetList(currentProject.SeedTargets, freshTargets, false)
		if err != nil {
			return err
		}
		scopeTargets, scopeAdded, _, err := mergeStoredTargetList(currentProject.Scope, freshTargets, false)
		if err != nil {
			return err
		}
		originalTargets, _, _, err := mergeStoredTargetList(task.OriginalTargets, freshTargets, true)
		if err != nil {
			return err
		}
		if err := tx.CreateInBatches(newBatches, 100).Error; err != nil {
			return err
		}
		if err := tx.CreateInBatches(newAttempts, 100).Error; err != nil {
			return err
		}
		updateRoot := tx.Model(&db.RootTask{}).Where("id = ? AND tenant_id = ? AND status = ? AND archived_at IS NULL", task.ID, task.TenantID, task.Status).Updates(map[string]interface{}{"original_targets": originalTargets, "total_chunks": task.TotalChunks + len(newBatches), "total_targets": task.TotalTargets + len(freshTargets), "rule_version": preview.Task.RuleVersion, "status": afterStatus})
		if updateRoot.Error != nil {
			return updateRoot.Error
		}
		if updateRoot.RowsAffected != 1 {
			return errTaskStateChanged
		}
		updateProject := tx.Model(&db.Project{}).Where("id = ? AND tenant_id = ? AND status = ?", currentProject.ID, task.TenantID, currentProject.Status).Updates(map[string]interface{}{"seed_targets": seedTargets, "scope": scopeTargets})
		if updateProject.Error != nil {
			return updateProject.Error
		}
		if updateProject.RowsAffected != 1 {
			return errTaskStateChanged
		}
		if err := recordTaskAudit(tx, task, "notebook_distribution_materialize", task.Status, afterStatus, taskOperatorID(c), map[string]interface{}{"intent_id": intentResult.Intent.ID, "plan_hash": preview.PlanHash, "selected": preview.Counts.Selected, "fresh": len(freshTargets), "duplicates": preview.Counts.Duplicates, "batches": len(newBatches), "batch_ids": batchIDs, "config_version": revision.Version, "rule_version": preview.Task.RuleVersion, "scope_added": len(scopeAdded), "seed_targets_added": len(seedAdded)}); err != nil {
			return err
		}
		attemptIDs := make([]string, 0, len(newAttempts))
		for _, attempt := range newAttempts {
			attemptIDs = append(attemptIDs, attempt.ID)
		}
		encodedBatchIDs, err := json.Marshal(batchIDs)
		if err != nil {
			return err
		}
		encodedAttemptIDs, err := json.Marshal(attemptIDs)
		if err != nil {
			return err
		}
		if err := tx.Create(&db.AssetDiscoveryNotebookDistributionMaterialization{TenantID: task.TenantID, ProjectID: task.ProjectID, IntentID: intentResult.Intent.ID, RootTaskID: task.ID, Status: "materialized", TaskStatus: afterStatus, BatchIDs: string(encodedBatchIDs), AttemptIDs: string(encodedAttemptIDs)}).Error; err != nil {
			return err
		}
		result.BatchIDs, result.AttemptIDs = batchIDs, attemptIDs
		result.Task.Status = afterStatus
		prepared = newAttempts
		return nil
	})
	if err != nil {
		writeNotebookDistributionMaterializeError(c, store, err)
		return
	}
	if result.Replayed {
		c.JSON(http.StatusOK, result)
		return
	}
	if shouldDispatch {
		pushed, pending := dispatchSubTasks(context.Background(), routerRuntime().TaskQueue, prepared)
		result.Dispatch.Dispatched, result.Dispatch.Pending = totalDispatchedTasks(pushed), pending
		broadcastDispatchedTasks(pushed)
	}
	c.JSON(http.StatusOK, result)
}

func decodeNotebookDistributionMaterializeRequest(c *gin.Context) (notebookDistributionMaterializeRequest, error) {
	var req notebookDistributionMaterializeRequest
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, assetDiscoveryRequestLimit)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		return req, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return req, errors.New("expected one JSON object")
	}
	req.TaskID, req.PlanHash = strings.TrimSpace(req.TaskID), strings.TrimSpace(req.PlanHash)
	if req.TaskID == "" || !validNotebookDistributionHash(req.PlanHash) || len(req.ItemIDs) < 1 || len(req.ItemIDs) > assetDiscoveryNotebookArchiveMaxItems {
		return req, errors.New("invalid confirmation binding")
	}
	seen := make(map[uint]struct{}, len(req.ItemIDs))
	for _, id := range req.ItemIDs {
		if id == 0 {
			return req, errors.New("invalid notebook item id")
		}
		if _, ok := seen[id]; ok {
			return req, errors.New("duplicate notebook item id")
		}
		seen[id] = struct{}{}
	}
	sort.Slice(req.ItemIDs, func(i, j int) bool { return req.ItemIDs[i] < req.ItemIDs[j] })
	return req, nil
}

func materializeResponseFromIntent(intent db.AssetDiscoveryNotebookDistributionIntent, replayed bool) notebookDistributionMaterializeResponse {
	result := notebookDistributionMaterializeResponse{SchemaVersion: assetDiscoveryNotebookDistributionMaterializeSchema, ProjectID: intent.ProjectID, IntentID: intent.ID, Replayed: replayed, Outcome: "materialized"}
	result.Task.ID = intent.RootTaskID
	result.Counts.Requested, result.Counts.Fresh, result.Counts.Duplicates = intent.Selected, intent.Fresh, intent.Duplicate
	result.Counts.ProjectScopeAdded, result.Counts.ProjectSeedTargetsAdded = intent.ScopeAdded, intent.SeedTargetsAdded
	result.Counts.BatchesCreated, result.Counts.AttemptsCreated = intent.BatchCount, intent.BatchCount
	return result
}

func materializeResponseFromIntentAndResult(store *gorm.DB, intent db.AssetDiscoveryNotebookDistributionIntent, materialization db.AssetDiscoveryNotebookDistributionMaterialization, replayed bool) (notebookDistributionMaterializeResponse, error) {
	if (materialization.Status != "materialized" && materialization.Status != "unchanged") || materialization.RootTaskID != intent.RootTaskID {
		return notebookDistributionMaterializeResponse{}, errors.New("invalid notebook distribution materialization result")
	}
	result := materializeResponseFromIntent(intent, replayed)
	if err := json.Unmarshal([]byte(materialization.BatchIDs), &result.BatchIDs); err != nil {
		return result, err
	}
	if err := json.Unmarshal([]byte(materialization.AttemptIDs), &result.AttemptIDs); err != nil {
		return result, err
	}
	if len(result.BatchIDs) != intent.BatchCount || len(result.AttemptIDs) != intent.BatchCount {
		return result, errors.New("invalid notebook distribution materialization result")
	}
	result.Task.Status = materialization.TaskStatus
	if materialization.Status == "unchanged" {
		result.Outcome = "unchanged"
	}
	if len(result.AttemptIDs) > 0 {
		var attempts []db.SubTask
		if err := store.Select("id", "status").
			Where("tenant_id = ? AND project_id = ? AND root_task_id = ? AND id IN ?", intent.TenantID, intent.ProjectID, intent.RootTaskID, result.AttemptIDs).
			Find(&attempts).Error; err != nil {
			return result, err
		}
		statusByID := make(map[string]string, len(attempts))
		for _, attempt := range attempts {
			statusByID[attempt.ID] = attempt.Status
		}
		if len(statusByID) != len(result.AttemptIDs) {
			return result, errors.New("invalid notebook distribution materialization attempts")
		}
		for _, attemptID := range result.AttemptIDs {
			switch strings.ToLower(strings.TrimSpace(statusByID[attemptID])) {
			case strings.ToLower(subTaskStatusDispatching):
				result.Dispatch.Pending++
			case "paused":
				// Paused attempts have intentionally not entered the dispatch queue.
			default:
				result.Dispatch.Dispatched++
			}
		}
	}
	return result, nil
}

func validNotebookDistributionIdempotencyKey(key string) bool {
	if len(key) < 1 || len(key) > 128 {
		return false
	}
	for _, r := range key {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}
func validNotebookDistributionHash(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
func constantNotebookDistributionHashEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
func notebookDistributionTargetHash(target string) string {
	sum := sha256.Sum256([]byte(target))
	return hex.EncodeToString(sum[:])
}

func writeNotebookDistributionMaterializeError(c *gin.Context, store *gorm.DB, err error) {
	if store != nil && store.Statement != nil && store.Statement.Context != nil && store.Statement.Context.Err() != nil {
		c.JSON(http.StatusGatewayTimeout, gin.H{"error": "asset discovery notebook distribution request timed out"})
		return
	}
	switch {
	case errors.Is(err, errNotebookDistributionPreviewExpired):
		c.JSON(http.StatusConflict, gin.H{"error": "notebook distribution preview expired; preview again"})
	case errors.Is(err, db.ErrAssetDiscoveryNotebookDistributionIdempotencyConflict):
		c.JSON(http.StatusConflict, gin.H{"error": "Idempotency-Key conflicts with a different confirmation"})
	case errors.Is(err, errNotebookDistributionTaskNotFound), errors.Is(err, errNotebookDistributionItemsNotFound), errors.Is(err, gorm.ErrRecordNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "asset discovery notebook distribution source not found"})
	case errors.Is(err, errNotebookDistributionConflict), errors.Is(err, errProjectInactive), errors.Is(err, errTaskStateChanged):
		c.JSON(http.StatusConflict, gin.H{"error": "notebook distribution cannot be materialized"})
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		c.JSON(http.StatusGatewayTimeout, gin.H{"error": "asset discovery notebook distribution request timed out"})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to materialize asset discovery notebook distribution"})
	}
}
