package db

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	AssetDiscoveryNotebookDistributionIntentSchemaVersion  = "argus.asset-discovery-notebook-distribution-intent/v1"
	AssetDiscoveryNotebookDistributionPreviewSchemaVersion = "argus.asset-discovery-notebook-distribution-preview/v1"

	assetDiscoveryNotebookDistributionOperation = "materialize"
	assetDiscoveryNotebookDistributionStatus    = "recorded"
)

// AssetDiscoveryNotebookDistributionIntent is an immutable, internal record
// of a future distribution request. It does not authorize or enqueue work.
type AssetDiscoveryNotebookDistributionIntent struct {
	ID                   uint      `gorm:"primaryKey;autoIncrement;uniqueIndex:idx_addi_scope_id,priority:3"`
	SchemaVersion        string    `gorm:"not null;size:64"`
	TenantID             string    `gorm:"not null;default:'default';uniqueIndex:idx_addi_scope_id,priority:1;uniqueIndex:idx_addi_idempotency,priority:1;index:idx_addi_task_created,priority:1;index:idx_addi_operator_created,priority:1;index:idx_addi_status_created,priority:1"`
	ProjectID            string    `gorm:"not null;uniqueIndex:idx_addi_scope_id,priority:2;uniqueIndex:idx_addi_idempotency,priority:2;index:idx_addi_task_created,priority:2;index:idx_addi_operator_created,priority:2;index:idx_addi_status_created,priority:2"`
	RootTaskID           string    `gorm:"not null;index:idx_addi_task_created,priority:3"`
	OperatorID           string    `gorm:"not null;uniqueIndex:idx_addi_idempotency,priority:3;index:idx_addi_operator_created,priority:3"`
	Operation            string    `gorm:"not null;size:32;uniqueIndex:idx_addi_idempotency,priority:4"`
	IdempotencyKeyHash   string    `gorm:"not null;size:64;uniqueIndex:idx_addi_idempotency,priority:5"`
	RequestHash          string    `gorm:"not null;size:64"`
	PlanHash             string    `gorm:"not null;size:64"`
	PreviewSchemaVersion string    `gorm:"not null;size:64"`
	TaskStatus           string    `gorm:"not null;size:64"`
	ConfigVersion        int       `gorm:"not null"`
	ConfigHash           string    `gorm:"not null;size:64"`
	RuleVersion          string    `gorm:"not null;type:text"`
	Selected             int       `gorm:"not null"`
	Fresh                int       `gorm:"not null"`
	Duplicate            int       `gorm:"not null"`
	ScopeAdded           int       `gorm:"not null"`
	SeedTargetsAdded     int       `gorm:"not null"`
	BatchCount           int       `gorm:"not null"`
	Status               string    `gorm:"not null;size:32;index:idx_addi_status_created,priority:3"`
	CreatedAt            time.Time `gorm:"not null;index:idx_addi_task_created,priority:4;index:idx_addi_operator_created,priority:4;index:idx_addi_status_created,priority:4"`
}

func (AssetDiscoveryNotebookDistributionIntent) TableName() string {
	return "asset_discovery_notebook_distribution_intents"
}

// AssetDiscoveryNotebookDistributionIntentItem freezes a selected notebook
// item without retaining any provider request or response fields.
type AssetDiscoveryNotebookDistributionIntentItem struct {
	ID               uint      `gorm:"primaryKey;autoIncrement;uniqueIndex:idx_addii_scope_id,priority:3"`
	TenantID         string    `gorm:"not null;default:'default';uniqueIndex:idx_addii_scope_id,priority:1;uniqueIndex:idx_addii_intent_position,priority:1;uniqueIndex:idx_addii_intent_notebook_item,priority:1;uniqueIndex:idx_addii_intent_target_hash,priority:1;index:idx_addii_notebook_item,priority:1;index:idx_addii_target_hash,priority:1"`
	ProjectID        string    `gorm:"not null;uniqueIndex:idx_addii_scope_id,priority:2;uniqueIndex:idx_addii_intent_position,priority:2;uniqueIndex:idx_addii_intent_notebook_item,priority:2;uniqueIndex:idx_addii_intent_target_hash,priority:2;index:idx_addii_notebook_item,priority:2;index:idx_addii_target_hash,priority:2"`
	IntentID         uint      `gorm:"not null;uniqueIndex:idx_addii_intent_position,priority:3;uniqueIndex:idx_addii_intent_notebook_item,priority:3;uniqueIndex:idx_addii_intent_target_hash,priority:3"`
	Position         int       `gorm:"not null;uniqueIndex:idx_addii_intent_position,priority:4"`
	NotebookItemID   uint      `gorm:"not null;uniqueIndex:idx_addii_intent_notebook_item,priority:4;index:idx_addii_notebook_item,priority:3"`
	NormalizedTarget string    `gorm:"not null;type:text"`
	TargetHash       string    `gorm:"not null;size:64;uniqueIndex:idx_addii_intent_target_hash,priority:4;index:idx_addii_target_hash,priority:3"`
	Disposition      string    `gorm:"not null;size:32"`
	CreatedAt        time.Time `gorm:"not null"`
}

// AssetDiscoveryNotebookDistributionMaterialization is the immutable typed
// result of a confirmed intent. It makes an idempotent replay independent of
// mutable task targets, scope, and lifecycle state.
type AssetDiscoveryNotebookDistributionMaterialization struct {
	ID         uint      `gorm:"primaryKey;autoIncrement;uniqueIndex:idx_addm_scope_id,priority:3"`
	TenantID   string    `gorm:"not null;default:'default';uniqueIndex:idx_addm_scope_id,priority:1;uniqueIndex:idx_addm_intent,priority:1;index:idx_addm_task_created,priority:1"`
	ProjectID  string    `gorm:"not null;uniqueIndex:idx_addm_scope_id,priority:2;uniqueIndex:idx_addm_intent,priority:2;index:idx_addm_task_created,priority:2"`
	IntentID   uint      `gorm:"not null;uniqueIndex:idx_addm_intent,priority:3"`
	RootTaskID string    `gorm:"not null;index:idx_addm_task_created,priority:3"`
	Status     string    `gorm:"not null;size:32"`
	TaskStatus string    `gorm:"not null;size:64"`
	BatchIDs   string    `gorm:"not null;type:jsonb"`
	AttemptIDs string    `gorm:"not null;type:jsonb"`
	CreatedAt  time.Time `gorm:"not null;index:idx_addm_task_created,priority:4"`
}

func (AssetDiscoveryNotebookDistributionMaterialization) TableName() string {
	return "asset_discovery_notebook_distribution_materializations"
}

func (AssetDiscoveryNotebookDistributionIntentItem) TableName() string {
	return "asset_discovery_notebook_distribution_intent_items"
}

type AssetDiscoveryNotebookDistributionIntentDraft struct {
	SchemaVersion, PreviewSchemaVersion           string
	ConfigVersion                                 int
	TenantID, ProjectID, RootTaskID, OperatorID   string
	IdempotencyKey                                string // never persisted raw
	PlanHash, TaskStatus, ConfigHash, RuleVersion string
	Selected, Fresh, Duplicate, ScopeAdded        int
	SeedTargetsAdded, BatchCount                  int
}

type AssetDiscoveryNotebookDistributionIntentItemSnapshot struct {
	NotebookItemID          uint
	NormalizedTarget        string
	TargetHash, Disposition string
}

type AssetDiscoveryNotebookDistributionIntentRecordResult struct {
	Intent   AssetDiscoveryNotebookDistributionIntent
	Items    []AssetDiscoveryNotebookDistributionIntentItem
	Replayed bool
}

var ErrAssetDiscoveryNotebookDistributionIdempotencyConflict = errors.New("asset discovery notebook distribution idempotency conflict")

// FindAssetDiscoveryNotebookDistributionReplayTx checks a scoped key before
// a mutable plan is rebuilt. It compares only client-supplied confirmation
// bindings and returns the typed immutable result when the original request
// already committed.
func FindAssetDiscoveryNotebookDistributionReplayTx(tx *gorm.DB, tenantID, projectID, operatorID, key, rootTaskID, planHash string, itemIDs []uint) (AssetDiscoveryNotebookDistributionIntent, AssetDiscoveryNotebookDistributionMaterialization, bool, error) {
	var intent AssetDiscoveryNotebookDistributionIntent
	var materialization AssetDiscoveryNotebookDistributionMaterialization
	if tx == nil || !validIdempotencyKey(key) || !validHash(planHash) {
		return intent, materialization, false, errors.New("invalid distribution replay lookup")
	}
	keyHash := distributionHash(key)
	err := tx.Where("tenant_id = ? AND project_id = ? AND operator_id = ? AND operation = ? AND idempotency_key_hash = ?", tenantID, projectID, operatorID, assetDiscoveryNotebookDistributionOperation, keyHash).First(&intent).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return intent, materialization, false, nil
	}
	if err != nil {
		return intent, materialization, false, err
	}
	if intent.RootTaskID != rootTaskID || !constantEqual(intent.PlanHash, planHash) {
		return intent, materialization, false, ErrAssetDiscoveryNotebookDistributionIdempotencyConflict
	}
	var items []AssetDiscoveryNotebookDistributionIntentItem
	if err := tx.Where("tenant_id = ? AND project_id = ? AND intent_id = ?", tenantID, projectID, intent.ID).Order("position ASC").Find(&items).Error; err != nil {
		return intent, materialization, false, err
	}
	ids := append([]uint(nil), itemIDs...)
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	if len(items) != len(ids) {
		return intent, materialization, false, ErrAssetDiscoveryNotebookDistributionIdempotencyConflict
	}
	for i, item := range items {
		if item.NotebookItemID != ids[i] {
			return intent, materialization, false, ErrAssetDiscoveryNotebookDistributionIdempotencyConflict
		}
	}
	if err := tx.Where("tenant_id = ? AND project_id = ? AND intent_id = ? AND root_task_id = ?", tenantID, projectID, intent.ID, rootTaskID).First(&materialization).Error; err != nil {
		return intent, materialization, false, err
	}
	return intent, materialization, true, nil
}

// RecordAssetDiscoveryNotebookDistributionIntent atomically records the
// immutable intent and item snapshot. It has no queue or authorization side
// effects; callers must separately enforce those policies before materializing.
func RecordAssetDiscoveryNotebookDistributionIntent(store *gorm.DB, draft AssetDiscoveryNotebookDistributionIntentDraft, snapshots []AssetDiscoveryNotebookDistributionIntentItemSnapshot) (AssetDiscoveryNotebookDistributionIntentRecordResult, error) {
	var result AssetDiscoveryNotebookDistributionIntentRecordResult
	if store == nil {
		return result, errors.New("distribution intent store is unavailable")
	}
	err := store.Transaction(func(tx *gorm.DB) error {
		var err error
		result, err = RecordAssetDiscoveryNotebookDistributionIntentTx(tx, draft, snapshots)
		return err
	})
	return result, err
}

// RecordAssetDiscoveryNotebookDistributionIntentTx records an immutable
// distribution intent in the caller's transaction. Callers materializing a
// plan must use this form so the intent and resulting task mutation either
// commit together or are both rolled back.
func RecordAssetDiscoveryNotebookDistributionIntentTx(tx *gorm.DB, draft AssetDiscoveryNotebookDistributionIntentDraft, snapshots []AssetDiscoveryNotebookDistributionIntentItemSnapshot) (AssetDiscoveryNotebookDistributionIntentRecordResult, error) {
	var result AssetDiscoveryNotebookDistributionIntentRecordResult
	if tx == nil {
		return result, errors.New("distribution intent transaction is unavailable")
	}
	if err := validateDistributionDraft(draft); err != nil {
		return result, err
	}
	items, err := normalizeDistributionIntentItems(draft, snapshots)
	if err != nil {
		return result, err
	}
	keyHash := distributionHash(draft.IdempotencyKey)
	requestHash := distributionRequestHash(draft, items)
	candidate := AssetDiscoveryNotebookDistributionIntent{SchemaVersion: draft.SchemaVersion, TenantID: draft.TenantID, ProjectID: draft.ProjectID, RootTaskID: draft.RootTaskID, OperatorID: draft.OperatorID, Operation: assetDiscoveryNotebookDistributionOperation, IdempotencyKeyHash: keyHash, RequestHash: requestHash, PlanHash: draft.PlanHash, PreviewSchemaVersion: draft.PreviewSchemaVersion, TaskStatus: draft.TaskStatus, ConfigVersion: draft.ConfigVersion, ConfigHash: draft.ConfigHash, RuleVersion: draft.RuleVersion, Selected: draft.Selected, Fresh: draft.Fresh, Duplicate: draft.Duplicate, ScopeAdded: draft.ScopeAdded, SeedTargetsAdded: draft.SeedTargetsAdded, BatchCount: draft.BatchCount, Status: assetDiscoveryNotebookDistributionStatus, CreatedAt: time.Now().UTC()}
	created := tx.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "tenant_id"}, {Name: "project_id"}, {Name: "operator_id"}, {Name: "operation"}, {Name: "idempotency_key_hash"}},
		DoNothing: true,
	}).Create(&candidate)
	if created.Error != nil {
		return result, fmt.Errorf("record distribution intent: %w", created.Error)
	}
	if created.RowsAffected == 1 {
		for i := range items {
			items[i].IntentID = candidate.ID
			items[i].CreatedAt = candidate.CreatedAt
		}
		if len(items) > 0 {
			insertedItems := tx.Create(&items)
			if insertedItems.Error != nil {
				return result, fmt.Errorf("record distribution intent items: %w", insertedItems.Error)
			}
			if insertedItems.RowsAffected != int64(len(items)) {
				return result, errors.New("distribution intent item conflict")
			}
		}
		result.Intent, result.Items = candidate, items
		return result, nil
	}
	var existing AssetDiscoveryNotebookDistributionIntent
	if err := tx.Where("tenant_id = ? AND project_id = ? AND operator_id = ? AND operation = ? AND idempotency_key_hash = ?", draft.TenantID, draft.ProjectID, draft.OperatorID, assetDiscoveryNotebookDistributionOperation, keyHash).First(&existing).Error; err != nil {
		return result, fmt.Errorf("load idempotent distribution intent: %w", err)
	}
	var existingItems []AssetDiscoveryNotebookDistributionIntentItem
	if err := tx.Where("tenant_id = ? AND project_id = ? AND intent_id = ?", existing.TenantID, existing.ProjectID, existing.ID).Order("position ASC").Find(&existingItems).Error; err != nil {
		return result, fmt.Errorf("load idempotent distribution intent items: %w", err)
	}
	if !sameDistributionIntent(existing, candidate) || !sameDistributionItems(existingItems, items) {
		return result, ErrAssetDiscoveryNotebookDistributionIdempotencyConflict
	}
	result.Intent, result.Items, result.Replayed = existing, existingItems, true
	return result, nil
}

func validateDistributionDraft(d AssetDiscoveryNotebookDistributionIntentDraft) error {
	if d.SchemaVersion != AssetDiscoveryNotebookDistributionIntentSchemaVersion || d.PreviewSchemaVersion != AssetDiscoveryNotebookDistributionPreviewSchemaVersion || d.ConfigVersion < 1 {
		return errors.New("invalid distribution intent version binding")
	}
	for _, value := range []string{d.TenantID, d.ProjectID, d.RootTaskID, d.OperatorID} {
		if strings.TrimSpace(value) == "" || strings.TrimSpace(value) != value || len(value) > 1024 {
			return errors.New("distribution intent scope and binding fields are required")
		}
	}
	if strings.TrimSpace(d.TaskStatus) == "" || strings.TrimSpace(d.TaskStatus) != d.TaskStatus || len(d.TaskStatus) > 64 || strings.TrimSpace(d.RuleVersion) != d.RuleVersion || len(d.RuleVersion) > 8192 {
		return errors.New("invalid distribution intent task or rule binding")
	}
	if !validIdempotencyKey(d.IdempotencyKey) {
		return errors.New("invalid distribution intent idempotency key")
	}
	if !validHash(d.PlanHash) || !validHash(d.ConfigHash) {
		return errors.New("invalid distribution intent hash")
	}
	if d.Selected < 1 || d.Selected > 100 || d.Fresh < 0 || d.Duplicate < 0 || d.ScopeAdded < 0 || d.SeedTargetsAdded < 0 || d.BatchCount < 0 || d.Selected != d.Fresh+d.Duplicate || d.ScopeAdded > d.Fresh || d.SeedTargetsAdded > d.Fresh || d.BatchCount > d.Fresh {
		return errors.New("invalid distribution intent counts")
	}
	return nil
}

func normalizeDistributionIntentItems(d AssetDiscoveryNotebookDistributionIntentDraft, in []AssetDiscoveryNotebookDistributionIntentItemSnapshot) ([]AssetDiscoveryNotebookDistributionIntentItem, error) {
	if len(in) != d.Selected {
		return nil, errors.New("distribution intent item count does not match selected count")
	}
	copyIn := append([]AssetDiscoveryNotebookDistributionIntentItemSnapshot(nil), in...)
	sort.Slice(copyIn, func(i, j int) bool { return copyIn[i].NotebookItemID < copyIn[j].NotebookItemID })
	items := make([]AssetDiscoveryNotebookDistributionIntentItem, len(copyIn))
	seenID, seenHash := map[uint]bool{}, map[string]bool{}
	for i, s := range copyIn {
		if s.NotebookItemID == 0 || seenID[s.NotebookItemID] || seenHash[s.TargetHash] || strings.TrimSpace(s.NormalizedTarget) == "" || strings.TrimSpace(s.NormalizedTarget) != s.NormalizedTarget || len(s.NormalizedTarget) > 8192 || !validHash(s.TargetHash) || (s.Disposition != "new" && s.Disposition != "duplicate") {
			return nil, errors.New("invalid distribution intent item snapshot")
		}
		seenID[s.NotebookItemID], seenHash[s.TargetHash] = true, true
		items[i] = AssetDiscoveryNotebookDistributionIntentItem{TenantID: d.TenantID, ProjectID: d.ProjectID, Position: i, NotebookItemID: s.NotebookItemID, NormalizedTarget: s.NormalizedTarget, TargetHash: s.TargetHash, Disposition: s.Disposition}
	}
	fresh := 0
	for _, item := range items {
		if item.Disposition == "new" {
			fresh++
		}
	}
	if d.Selected != len(items) || d.Fresh != fresh || d.Duplicate != len(items)-fresh {
		return nil, errors.New("distribution intent counts do not match item dispositions")
	}
	return items, nil
}

func distributionRequestHash(d AssetDiscoveryNotebookDistributionIntentDraft, items []AssetDiscoveryNotebookDistributionIntentItem) string {
	var b strings.Builder
	write := func(value string) { b.WriteString(strconv.Quote(value)); b.WriteByte('|') }
	for _, value := range []string{d.SchemaVersion, d.TenantID, d.ProjectID, d.RootTaskID, d.OperatorID, assetDiscoveryNotebookDistributionOperation, d.PlanHash, d.PreviewSchemaVersion, d.TaskStatus, strconv.Itoa(d.ConfigVersion), d.ConfigHash, d.RuleVersion, strconv.Itoa(d.Selected), strconv.Itoa(d.Fresh), strconv.Itoa(d.Duplicate), strconv.Itoa(d.ScopeAdded), strconv.Itoa(d.SeedTargetsAdded), strconv.Itoa(d.BatchCount)} {
		write(value)
	}
	for _, item := range items {
		write(strconv.FormatUint(uint64(item.NotebookItemID), 10))
		write(item.TargetHash)
		write(item.NormalizedTarget)
		write(item.Disposition)
	}
	return distributionHash(b.String())
}

func sameDistributionIntent(a, b AssetDiscoveryNotebookDistributionIntent) bool {
	return a.SchemaVersion == b.SchemaVersion && a.TenantID == b.TenantID && a.ProjectID == b.ProjectID && a.RootTaskID == b.RootTaskID && a.OperatorID == b.OperatorID && a.Operation == b.Operation && constantEqual(a.IdempotencyKeyHash, b.IdempotencyKeyHash) && constantEqual(a.RequestHash, b.RequestHash) && constantEqual(a.PlanHash, b.PlanHash) && a.PreviewSchemaVersion == b.PreviewSchemaVersion && a.TaskStatus == b.TaskStatus && a.ConfigVersion == b.ConfigVersion && constantEqual(a.ConfigHash, b.ConfigHash) && a.RuleVersion == b.RuleVersion && a.Selected == b.Selected && a.Fresh == b.Fresh && a.Duplicate == b.Duplicate && a.ScopeAdded == b.ScopeAdded && a.SeedTargetsAdded == b.SeedTargetsAdded && a.BatchCount == b.BatchCount && a.Status == b.Status
}
func sameDistributionItems(a, b []AssetDiscoveryNotebookDistributionIntentItem) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Position != b[i].Position || a[i].NotebookItemID != b[i].NotebookItemID || !constantEqual(a[i].TargetHash, b[i].TargetHash) || !constantEqual(a[i].NormalizedTarget, b[i].NormalizedTarget) || a[i].Disposition != b[i].Disposition {
			return false
		}
	}
	return true
}
func validIdempotencyKey(key string) bool {
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
func validHash(value string) bool {
	return len(value) == 64 && strings.ToLower(value) == value && func() bool { _, err := hex.DecodeString(value); return err == nil }()
}
func distributionHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
func constantEqual(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
