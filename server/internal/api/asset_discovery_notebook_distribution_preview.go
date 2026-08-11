package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const assetDiscoveryNotebookDistributionPreviewSchema = "argus.asset-discovery-notebook-distribution-preview/v1"

var (
	errNotebookDistributionTaskNotFound  = errors.New("notebook distribution task not found")
	errNotebookDistributionItemsNotFound = errors.New("notebook distribution items not found")
	errNotebookDistributionConflict      = errors.New("notebook distribution cannot be appended")
)

type notebookDistributionPreviewRequest struct {
	TaskID  string `json:"task_id"`
	ItemIDs []uint `json:"item_ids"`
}

type notebookDistributionPreviewItem struct {
	ItemID      uint   `json:"item_id"`
	Target      string `json:"target"`
	Disposition string `json:"disposition"`
}

type notebookDistributionPreviewResponse struct {
	SchemaVersion string                             `json:"schema_version"`
	Project       notebookDistributionPreviewProject `json:"project"`
	Task          notebookDistributionPreviewTask    `json:"task"`
	Items         []notebookDistributionPreviewItem  `json:"items"`
	Counts        notebookDistributionPreviewCounts  `json:"counts"`
	TargetSummary taskTargetSummary                  `json:"target_summary"`
	BatchProfile  batchProfile                       `json:"batch_profile"`
	PlanHash      string                             `json:"plan_hash"`
	GeneratedAt   string                             `json:"generated_at"`
}

type notebookDistributionPreviewProject struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}
type notebookDistributionPreviewTask struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Status        string `json:"status"`
	ConfigVersion int    `json:"config_version"`
	RuleVersion   string `json:"rule_version"`
}
type notebookDistributionPreviewCounts struct {
	Requested               int `json:"requested"`
	Selected                int `json:"selected"`
	Fresh                   int `json:"fresh"`
	Duplicates              int `json:"duplicates"`
	ProjectScopeAdded       int `json:"project_scope_added"`
	ProjectSeedTargetsAdded int `json:"project_seed_targets_added"`
}

func previewProjectNotebookDistribution(c *gin.Context) {
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
	if !strings.EqualFold(strings.TrimSpace(project.Status), "active") {
		c.JSON(http.StatusConflict, gin.H{"error": "project is not active"})
		return
	}
	req, err := decodeNotebookDistributionPreviewRequest(c)
	if err != nil {
		status := http.StatusBadRequest
		if errors.As(err, new(*http.MaxBytesError)) {
			status = http.StatusRequestEntityTooLarge
		}
		c.JSON(status, gin.H{"error": "invalid asset discovery notebook distribution request"})
		return
	}
	response, err := buildNotebookDistributionPreview(store, c, project, req)
	if err != nil {
		writeNotebookDistributionPreviewError(c, store, err)
		return
	}
	c.JSON(http.StatusOK, response)
}

func decodeNotebookDistributionPreviewRequest(c *gin.Context) (notebookDistributionPreviewRequest, error) {
	var req notebookDistributionPreviewRequest
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, assetDiscoveryRequestLimit)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		return req, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return req, errors.New("expected one JSON object")
	}
	req.TaskID = strings.TrimSpace(req.TaskID)
	if req.TaskID == "" || len(req.ItemIDs) < 1 || len(req.ItemIDs) > assetDiscoveryNotebookArchiveMaxItems {
		return req, errors.New("invalid task or notebook items")
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

func buildNotebookDistributionPreview(store *gorm.DB, c *gin.Context, project db.Project, req notebookDistributionPreviewRequest) (notebookDistributionPreviewResponse, error) {
	tenantID := currentTenantID(c)
	var task db.RootTask
	if err := store.Where("id = ? AND tenant_id = ? AND project_id = ?", req.TaskID, tenantID, project.ID).First(&task).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return notebookDistributionPreviewResponse{}, errNotebookDistributionTaskNotFound
		}
		return notebookDistributionPreviewResponse{}, fmt.Errorf("load task: %w", err)
	}
	if task.ArchivedAt != nil || !taskCanAppendPreview(task.Status) {
		return notebookDistributionPreviewResponse{}, errNotebookDistributionConflict
	}
	revision, err := db.CurrentTaskConfigRevision(store, task)
	if err != nil {
		return notebookDistributionPreviewResponse{}, fmt.Errorf("load task config revision: %w", err)
	}
	_, mode, err := normalizeTaskConfigPayload(json.RawMessage(revision.Config))
	if err != nil {
		return notebookDistributionPreviewResponse{}, errNotebookDistributionConflict
	}
	if mode != taskTargetModeDirect {
		return notebookDistributionPreviewResponse{}, errNotebookDistributionConflict
	}
	effectiveRuleVersion, err := currentNotebookDistributionRuleVersion(store)
	if err != nil {
		return notebookDistributionPreviewResponse{}, fmt.Errorf("load rule version: %w", err)
	}
	if strings.TrimSpace(effectiveRuleVersion) == "" || strings.EqualFold(effectiveRuleVersion, "unknown") {
		effectiveRuleVersion = task.RuleVersion
	}
	var items []db.AssetDiscoveryNotebookItem
	if err := store.Where("tenant_id = ? AND project_id = ? AND removed_at IS NULL AND id IN ?", tenantID, project.ID, req.ItemIDs).Find(&items).Error; err != nil {
		return notebookDistributionPreviewResponse{}, fmt.Errorf("load notebook items: %w", err)
	}
	if len(items) != len(req.ItemIDs) {
		return notebookDistributionPreviewResponse{}, errNotebookDistributionItemsNotFound
	}
	byID := make(map[uint]db.AssetDiscoveryNotebookItem, len(items))
	for _, item := range items {
		byID[item.ID] = item
	}
	requested := make([]string, 0, len(req.ItemIDs))
	previewItems := make([]notebookDistributionPreviewItem, 0, len(req.ItemIDs))
	for _, id := range req.ItemIDs {
		item := byID[id]
		normalized := normalizeTargetsForMode([]string{item.NormalizedTarget}, mode)
		if len(normalized) != 1 {
			return notebookDistributionPreviewResponse{}, errNotebookDistributionConflict
		}
		requested = append(requested, normalized[0])
		previewItems = append(previewItems, notebookDistributionPreviewItem{ItemID: id, Target: normalized[0]})
	}
	if _, _, err := validateTargetsByMode(requested, mode); err != nil {
		return notebookDistributionPreviewResponse{}, errNotebookDistributionConflict
	}
	var batches []db.TaskBatch
	if err := store.Where("root_task_id = ? AND tenant_id = ?", task.ID, tenantID).Order("sequence asc").Find(&batches).Error; err != nil {
		return notebookDistributionPreviewResponse{}, fmt.Errorf("load task batches: %w", err)
	}
	existing, err := existingTaskTargetSet(batches)
	if err != nil {
		return notebookDistributionPreviewResponse{}, err
	}
	original, err := decodeStoredTargetList(task.OriginalTargets, true)
	if err != nil {
		return notebookDistributionPreviewResponse{}, err
	}
	for _, target := range normalizeTargetsForMode(original, mode) {
		existing[target] = struct{}{}
	}
	existingSnapshot := sortedTaskTargetSnapshot(existing)
	fresh, duplicates := filterNewTaskTargets(requested, existing)
	freshSet := make(map[string]struct{}, len(fresh))
	for _, target := range fresh {
		freshSet[target] = struct{}{}
	}
	for i := range previewItems {
		if _, ok := freshSet[previewItems[i].Target]; ok {
			previewItems[i].Disposition = "new"
		} else {
			previewItems[i].Disposition = "duplicate"
		}
	}
	_, seedAdded, _, err := mergeStoredTargetList(project.SeedTargets, fresh, false)
	if err != nil {
		return notebookDistributionPreviewResponse{}, err
	}
	_, scopeAdded, _, err := mergeStoredTargetList(project.Scope, fresh, false)
	if err != nil {
		return notebookDistributionPreviewResponse{}, err
	}
	_, _, summary := classifyTargets(fresh, mode)
	profile := batchProfile{TotalTargets: len(fresh), BatchesByType: map[string]int{}, BatchSize: map[string]int{}}
	for _, group := range groupAndBatchTargets(fresh, mode) {
		profile.TotalBatches++
		profile.BatchesByType[group.TargetType]++
		profile.BatchSize[group.TargetType] = batchSizeForTargetType(group.TargetType)
	}
	return notebookDistributionPreviewResponse{SchemaVersion: assetDiscoveryNotebookDistributionPreviewSchema, Project: notebookDistributionPreviewProject{ID: project.ID, Status: project.Status}, Task: notebookDistributionPreviewTask{ID: task.ID, Name: task.Name, Status: task.Status, ConfigVersion: revision.Version, RuleVersion: effectiveRuleVersion}, Items: previewItems, Counts: notebookDistributionPreviewCounts{Requested: len(req.ItemIDs), Selected: len(req.ItemIDs), Fresh: len(fresh), Duplicates: len(duplicates), ProjectScopeAdded: len(scopeAdded), ProjectSeedTargetsAdded: len(seedAdded)}, TargetSummary: summary, BatchProfile: profile, PlanHash: notebookDistributionPlanHash(tenantID, project, task, revision, effectiveRuleVersion, req.ItemIDs, requested, existingSnapshot, fresh, duplicates, scopeAdded, seedAdded, profile), GeneratedAt: time.Now().UTC().Format(time.RFC3339)}, nil
}

func taskCanAppendPreview(status string) bool {
	switch db.CanonicalTaskState(status) {
	case db.TaskStateStopping, db.TaskStateCreated, db.TaskStateUnknown:
		return false
	}
	return true
}

func currentNotebookDistributionRuleVersion(store *gorm.DB) (string, error) {
	var config db.SystemConfig
	err := store.Where("key = ?", "rule_version").First(&config).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(config.Value), nil
}

func sortedTaskTargetSnapshot(targets map[string]struct{}) []string {
	result := make([]string, 0, len(targets))
	for target := range targets {
		result = append(result, target)
	}
	sort.Strings(result)
	return result
}

func normalizedProjectTargetSnapshot(raw string) ([]string, error) {
	targets, err := decodeStoredTargetList(raw, false)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(targets))
	for _, target := range normalizeTargetsForMode(targets, taskTargetModeDirect) {
		seen[target] = struct{}{}
	}
	return sortedTaskTargetSnapshot(seen), nil
}

func notebookDistributionPlanHash(tenantID string, project db.Project, task db.RootTask, revision db.TaskConfigRevision, ruleVersion string, ids []uint, targets, existingTargets, freshTargets, duplicateTargets, scopeAdded, seedsAdded []string, profile batchProfile) string {
	scope, _ := normalizedProjectTargetSnapshot(project.Scope)
	seeds, _ := normalizedProjectTargetSnapshot(project.SeedTargets)
	payload := struct {
		SchemaVersion                                          string
		Tenant, Project, Task, Status, ConfigHash, RuleVersion string
		ConfigVersion                                          int
		IDs                                                    []uint
		Targets, ExistingTargets, FreshTargets                 []string
		DuplicateTargets, Scope, Seeds                         []string
		ScopeAdded, SeedsAdded                                 []string
		BatchProfile                                           batchProfile
	}{assetDiscoveryNotebookDistributionPreviewSchema, tenantID, project.ID, task.ID, task.Status, revision.ConfigHash, ruleVersion, revision.Version, ids, targets, existingTargets, freshTargets, duplicateTargets, scope, seeds, scopeAdded, seedsAdded, profile}
	encoded, _ := json.Marshal(payload)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func writeNotebookDistributionPreviewError(c *gin.Context, store *gorm.DB, err error) {
	if store != nil && store.Statement != nil && store.Statement.Context != nil && store.Statement.Context.Err() != nil {
		c.JSON(http.StatusGatewayTimeout, gin.H{"error": "asset discovery notebook distribution request timed out"})
		return
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		c.JSON(http.StatusGatewayTimeout, gin.H{"error": "asset discovery notebook distribution request timed out"})
	case errors.Is(err, errNotebookDistributionTaskNotFound), errors.Is(err, errNotebookDistributionItemsNotFound), errors.Is(err, gorm.ErrRecordNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "asset discovery notebook distribution source not found"})
	case errors.Is(err, errNotebookDistributionConflict):
		c.JSON(http.StatusConflict, gin.H{"error": "notebook distribution cannot be appended"})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to preview asset discovery notebook distribution"})
	}
}
