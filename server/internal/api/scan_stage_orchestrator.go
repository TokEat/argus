package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/server/internal/credentialbundle"
	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/P0lar1ght/argus/shared/proto/go/scanpolicy"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	automaticRiskStage       = "risk_validation"
	automaticCredentialStage = "credential_validation"
)

type ScanStageOrchestrator struct{}

type validationAffinity struct {
	AgentID          string `json:"preferred_agent_id,omitempty"`
	NetworkZone      string `json:"preferred_network_zone,omitempty"`
	AgentUntilUnix   int64  `json:"preferred_agent_until_unix,omitempty"`
	NetworkUntilUnix int64  `json:"preferred_network_until_unix,omitempty"`
}

type validationExecutionAllocation struct {
	BudgetID          string `json:"budget_id"`
	TargetConcurrency int    `json:"target_concurrency"`
	RateLimit         int    `json:"rate_limit"`
	RequestBudget     int64  `json:"request_budget"`
	EstimatedRequests int64  `json:"estimated_requests"`
}

func NewScanStageOrchestrator() *ScanStageOrchestrator { return &ScanStageOrchestrator{} }

// HandleAttemptTerminal is invoked after the attempt and batch terminal state
// are durable, but before the root status is refreshed.
func (o *ScanStageOrchestrator) HandleAttemptTerminal(ctx context.Context, attempt db.SubTask) error {
	if strings.TrimSpace(attempt.RootTaskID) == "" || strings.TrimSpace(attempt.BatchID) == "" {
		return nil
	}
	var batch db.TaskBatch
	if err := db.DB.WithContext(ctx).Where("id = ? AND tenant_id = ?", attempt.BatchID, attempt.TenantID).First(&batch).Error; err != nil {
		return err
	}
	if batch.Kind == automaticRiskStage || batch.Kind == automaticCredentialStage {
		return updateAutomaticStageStatus(ctx, batch, attempt)
	}
	if batch.Kind != "asset_scan" {
		return nil
	}
	// 流水线化衔接：单个资产批次终态后立即派生它的风险验证兄弟批次，
	// 不等待其余资产批次；凭据验证仍等全局就绪后单批派生。
	var queued []db.SubTask
	if err := db.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var intent db.ScanPolicyIntent
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("tenant_id = ? AND root_task_id = ?", attempt.TenantID, attempt.RootTaskID).First(&intent).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return nil
			}
			return err
		}
		var root db.RootTask
		if err := tx.Where("id = ? AND tenant_id = ?", attempt.RootTaskID, attempt.TenantID).First(&root).Error; err != nil {
			return err
		}
		if intent.RiskStatus == db.ScanStageIntentPending || intent.RiskStatus == db.ScanStageIntentDerived {
			sibling, err := o.deriveRiskSiblingForAssetBatch(ctx, tx, &intent, root, batch, attempt.AgentID)
			if err != nil {
				return err
			}
			if sibling != nil {
				queued = append(queued, *sibling)
			}
		}
		return tx.Save(&intent).Error
	}); err != nil {
		return err
	}
	credential, err := o.deriveCredentialIfReady(ctx, attempt.TenantID, attempt.RootTaskID)
	if err != nil {
		return err
	}
	if credential != nil {
		queued = append(queued, *credential)
	}
	return o.dispatchQueuedValidations(ctx, queued)
}

// deriveCredentialIfReady 在全部资产批次终态且策略开启弱口令验证时派生全局
// 单批凭据验证；否则返回 nil。
func (o *ScanStageOrchestrator) deriveCredentialIfReady(ctx context.Context, tenantID, rootTaskID string) (*db.SubTask, error) {
	var intent db.ScanPolicyIntent
	if err := db.DB.Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("tenant_id = ? AND root_task_id = ?", tenantID, rootTaskID).First(&intent).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	if intent.CredentialStatus != db.ScanStageIntentPending {
		return nil, nil
	}
	ready, err := assetDiscoveryBatchesTerminal(db.DB, tenantID, rootTaskID)
	if err != nil || !ready {
		return nil, err
	}
	var root db.RootTask
	if err := db.DB.Where("id = ? AND tenant_id = ?", rootTaskID, tenantID).First(&root).Error; err != nil {
		return nil, err
	}
	return o.deriveCredentialValidation(ctx, db.DB, &intent, root)
}

func (o *ScanStageOrchestrator) dispatchQueuedValidations(ctx context.Context, queued []db.SubTask) error {
	if len(queued) == 0 {
		return nil
	}
	if routerRuntime().TaskQueue == nil {
		return errTaskCreateQueueUnavailable
	}
	for i := range queued {
		protoTask, err := db.SubTaskToProto(&queued[i])
		if err != nil {
			return err
		}
		if err := routerRuntime().TaskQueue.PushTask(ctx, protoTask); err != nil {
			return err
		}
		batchID := queued[i].BatchID
		attemptID := queued[i].ID
		if err := db.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			if err := tx.Model(&db.SubTask{}).Where("id = ? AND tenant_id = ? AND status = ?", attemptID, queued[i].TenantID, subTaskStatusDispatching).Updates(map[string]interface{}{"status": "Pending", "stream_msg_id": subTaskQueuedMarker}).Error; err != nil {
				return err
			}
			return tx.Model(&db.TaskBatch{}).Where("id = ? AND tenant_id = ? AND latest_attempt_id = ?", batchID, queued[i].TenantID, attemptID).Update("status", "Pending").Error
		}); err != nil {
			return err
		}
	}
	return nil
}

func updateAutomaticStageStatus(ctx context.Context, batch db.TaskBatch, completed db.SubTask) error {
	return db.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var root db.RootTask
		if err := tx.Where("id = ? AND tenant_id = ?", batch.RootTaskID, batch.TenantID).First(&root).Error; err != nil {
			return err
		}
		var latest db.SubTask
		if err := tx.Where("id = ? AND tenant_id = ?", batch.LatestAttemptID, batch.TenantID).First(&latest).Error; err != nil {
			return err
		}
		statusValue := db.ScanStageIntentDerived
		if db.IsTerminalAttemptStatus(latest.Status) {
			if db.CanonicalAttemptState(latest.Status) == db.AttemptStateCompleted {
				statusValue = db.ScanStageIntentComplete
			} else {
				statusValue = db.ScanStageIntentFailed
			}
		}

		column := "risk_status"
		if batch.Kind == automaticCredentialStage {
			column = "credential_status"
		}
		if batch.Kind == automaticRiskStage {
			aggregated, ready, err := aggregateAutomaticRiskStatus(tx, batch.TenantID, batch.RootTaskID)
			if err != nil {
				return err
			}
			if !ready {
				if aggregated == db.ScanStageIntentDerived {
					return recordTaskAudit(tx, root, "automatic_"+batch.Kind+"_terminal", completed.Status, latest.Status, "system", map[string]interface{}{"stage": batch.Kind, "batch_id": batch.ID, "attempt_id": latest.ID, "stage_status": aggregated, "aggregated": false})
				}
			} else {
				statusValue = aggregated
			}
		}
		if err := tx.Model(&db.ScanPolicyIntent{}).Where("tenant_id = ? AND root_task_id = ?", batch.TenantID, batch.RootTaskID).Update(column, statusValue).Error; err != nil {
			return err
		}
		// 阶段级派生行同步最新状态（行在首次派生时已创建）。
		if err := tx.Model(&db.ScanStageDerivation{}).
			Where("tenant_id = ? AND root_task_id = ? AND stage = ?", batch.TenantID, batch.RootTaskID, batch.Kind).
			Updates(map[string]interface{}{"status": statusValue, "batch_id": batch.ID, "attempt_id": latest.ID, "updated_at": time.Now().UTC()}).Error; err != nil {
			return err
		}
		return recordTaskAudit(tx, root, "automatic_"+batch.Kind+"_terminal", completed.Status, latest.Status, "system", map[string]interface{}{"stage": batch.Kind, "batch_id": batch.ID, "attempt_id": latest.ID, "stage_status": statusValue})
	})
}

func riskSiblingBatchID(assetBatchID string) string {
	return assetBatchID + "-risk"
}

func aggregateAutomaticRiskStatus(tx *gorm.DB, tenantID, rootTaskID string) (string, bool, error) {
	var assetBatches []db.TaskBatch
	if err := tx.Where("tenant_id = ? AND root_task_id = ? AND kind = ? AND archived_at IS NULL", tenantID, rootTaskID, "asset_scan").
		Order("id ASC").Find(&assetBatches).Error; err != nil {
		return "", false, err
	}
	if len(assetBatches) == 0 {
		return "", false, nil
	}
	failed := false
	for _, assetBatch := range assetBatches {
		var sibling db.TaskBatch
		err := tx.Where("id = ? AND tenant_id = ? AND kind = ? AND archived_at IS NULL", riskSiblingBatchID(assetBatch.ID), tenantID, automaticRiskStage).
			First(&sibling).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return db.ScanStageIntentDerived, false, nil
		}
		if err != nil {
			return "", false, err
		}
		var latest db.SubTask
		if err := tx.Where("id = ? AND tenant_id = ?", sibling.LatestAttemptID, tenantID).First(&latest).Error; err != nil {
			return "", false, err
		}
		if !db.IsTerminalAttemptStatus(latest.Status) {
			return db.ScanStageIntentDerived, false, nil
		}
		if db.CanonicalAttemptState(latest.Status) != db.AttemptStateCompleted {
			failed = true
		}
	}
	if failed {
		return db.ScanStageIntentFailed, true, nil
	}
	return db.ScanStageIntentComplete, true, nil
}

func taskBatchLatestAttemptTerminal(tx *gorm.DB, batch db.TaskBatch) (bool, error) {
	if strings.TrimSpace(batch.LatestAttemptID) == "" {
		return false, nil
	}
	var latest db.SubTask
	if err := tx.Where("id = ? AND tenant_id = ?", batch.LatestAttemptID, batch.TenantID).First(&latest).Error; err != nil {
		return false, err
	}
	return db.IsTerminalAttemptStatus(latest.Status), nil
}

func assetDiscoveryBatchesTerminal(tx *gorm.DB, tenantID, rootTaskID string) (bool, error) {
	var count, terminal int64
	if err := tx.Model(&db.TaskBatch{}).Where("tenant_id = ? AND root_task_id = ? AND kind = ? AND archived_at IS NULL", tenantID, rootTaskID, "asset_scan").Count(&count).Error; err != nil {
		return false, err
	}
	if count == 0 {
		return false, nil
	}
	err := tx.Table("task_batches AS b").Joins("JOIN sub_tasks s ON s.id = b.latest_attempt_id AND s.tenant_id = b.tenant_id").
		Where("b.tenant_id = ? AND b.root_task_id = ? AND b.kind = ? AND b.archived_at IS NULL AND UPPER(s.status) IN ?", tenantID, rootTaskID, "asset_scan", []string{"DONE", "FINISHED", "COMPLETED", "SUCCESS", "SUCCEEDED", "FAILED", "TIMEOUT", "CANCELLED", "CANCELED", "STOPPED"}).Count(&terminal).Error
	return terminal == count, err
}

// DeriveRoot 是补漏清扫器：为"已终态但没有风险兄弟批次"的资产批次补派生
// （服务重启、手动重置、历史遗留等场景）；实时衔接由 HandleAttemptTerminal
// 的流水线化路径完成。凭据验证保持全局单批语义。
func (o *ScanStageOrchestrator) DeriveRoot(ctx context.Context, tenantID, rootTaskID string) error {
	var queued []db.SubTask
	err := db.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var intent db.ScanPolicyIntent
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("tenant_id = ? AND root_task_id = ?", tenantID, rootTaskID).First(&intent).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return nil
			}
			return err
		}
		var root db.RootTask
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ? AND tenant_id = ?", rootTaskID, tenantID).First(&root).Error; err != nil {
			return err
		}
		if intent.RiskStatus == db.ScanStageIntentPending || intent.RiskStatus == db.ScanStageIntentDerived {
			siblings, err := o.sweepRiskSiblingsForTerminalAssetBatches(ctx, tx, &intent, root)
			if err != nil {
				return err
			}
			queued = append(queued, siblings...)
		}
		if intent.CredentialStatus == db.ScanStageIntentPending {
			ready, err := assetDiscoveryBatchesTerminal(tx, tenantID, rootTaskID)
			if err != nil {
				return err
			}
			if ready {
				attempt, err := o.deriveCredentialValidation(ctx, tx, &intent, root)
				if err != nil {
					return err
				}
				if attempt != nil {
					queued = append(queued, *attempt)
				}
			}
		}
		return tx.Save(&intent).Error
	})
	if err != nil {
		return err
	}
	return o.dispatchQueuedValidations(ctx, queued)
}

// sweepRiskSiblingsForTerminalAssetBatches 为缺少风险兄弟批次的终态资产批次
// 逐个补派生，返回新建的兄弟批次尝试列表。
func (o *ScanStageOrchestrator) sweepRiskSiblingsForTerminalAssetBatches(ctx context.Context, tx *gorm.DB, intent *db.ScanPolicyIntent, root db.RootTask) ([]db.SubTask, error) {
	var assetBatches []db.TaskBatch
	if err := tx.Where("tenant_id = ? AND root_task_id = ? AND kind = ? AND archived_at IS NULL", root.TenantID, root.ID, "asset_scan").
		Order("id ASC").Find(&assetBatches).Error; err != nil {
		return nil, err
	}
	created := make([]db.SubTask, 0)
	for _, assetBatch := range assetBatches {
		terminal, err := taskBatchLatestAttemptTerminal(tx, assetBatch)
		if err != nil {
			return nil, err
		}
		if !terminal {
			continue
		}
		sibling, err := o.deriveRiskSiblingForAssetBatchTx(ctx, tx, intent, root, assetBatch, "")
		if err != nil {
			return nil, err
		}
		if sibling != nil {
			created = append(created, *sibling)
		}
	}
	return created, nil
}

// deriveRiskSiblingForAssetBatch 为单个资产批次派生其专属的风险验证兄弟
// 批次（流水线化衔接）：目标与指纹均限定在该资产批次范围内，Agent 本地完成
// workflow→POC 匹配。空指纹的资产批次也会创建空兄弟批次（原生路径立即正常
// 完结），保证"每个资产批次恰好对应一个风险兄弟批次"的聚合判定语义。
// preferredAgentID 非空时作为亲和提示（发现该资产的 Agent 优先续扫）。
func (o *ScanStageOrchestrator) deriveRiskSiblingForAssetBatch(ctx context.Context, tx *gorm.DB, intent *db.ScanPolicyIntent, root db.RootTask, assetBatch db.TaskBatch, preferredAgentID string) (*db.SubTask, error) {
	return o.deriveRiskSiblingForAssetBatchTx(ctx, tx, intent, root, assetBatch, preferredAgentID)
}

func (o *ScanStageOrchestrator) deriveRiskSiblingForAssetBatchTx(ctx context.Context, tx *gorm.DB, intent *db.ScanPolicyIntent, root db.RootTask, assetBatch db.TaskBatch, preferredAgentID string) (*db.SubTask, error) {
	if currentRuleVersionTx(tx) != root.RuleVersion {
		// 规则版本漂移时跳过派生：旧版本计划对已升级的规则包没有意义。
		return nil, recordSkippedDerivation(tx, intent, automaticRiskStage, "rule_version_drift")
	}
	var policy scanpolicy.Policy
	if err := json.Unmarshal([]byte(intent.PolicyJSON), &policy); err != nil {
		return nil, fmt.Errorf("decode task policy intent: %w", err)
	}

	riskBatchID := riskSiblingBatchID(assetBatch.ID)
	var existing db.TaskBatch
	if err := tx.Where("id = ?", riskBatchID).First(&existing).Error; err == nil {
		return nil, nil // 幂等：兄弟批次已存在（重放/清扫竞态）
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	targetPrints, err := loadBatchFingerprintMap(ctx, tx, root, assetBatch.ID)
	if err != nil {
		return nil, err
	}
	// 零指纹命中的批次同样创建空兄弟批次（原生路径立即正常完结），
	// 保持"每个资产批次恰好对应一个风险兄弟批次"的稳定聚合语义。
	targets := make([]string, 0, len(targetPrints))
	for target := range targetPrints {
		targets = append(targets, target)
	}
	sort.Strings(targets)

	matchedProducts := 0
	for _, prints := range targetPrints {
		matchedProducts += len(prints)
	}
	var allocation validationExecutionAllocation
	if estimatedRequests := int64(len(targets)) * riskValidationEstRequestsPerTarget; estimatedRequests > 0 {
		alloc, allocErr := validationAllocation(*intent, root.ID, automaticRiskStage, estimatedRequests)
		if allocErr != nil {
			return nil, allocErr
		}
		allocation = alloc
	} else {
		// 零目标空批次：原生路径立即完结，预算字段给最小占位即可。
		allocation = validationExecutionAllocation{BudgetID: riskBatchID + "-budget", TargetConcurrency: 1, RateLimit: 30, RequestBudget: 1}
	}
	revision, err := db.CurrentTaskConfigRevision(tx, root)
	if err != nil {
		return nil, err
	}
	config := make(map[string]interface{})
	if strings.TrimSpace(revision.Config) != "" {
		if err := json.Unmarshal([]byte(revision.Config), &config); err != nil {
			return nil, fmt.Errorf("decode current task config: %w", err)
		}
	}
	config["ExecutionMode"] = automaticRiskStage
	config["RequiredRuleVersion"] = strings.TrimSpace(root.RuleVersion)
	config["NoPoc"] = false
	config["GolangPoc"] = false
	config["PocNameForSearch"] = ""
	config["Hunter"], config["Fofa"], config["Quake"] = false, false, false
	config["TargetFingerprints"] = targetPrints
	config["AllowHighRiskAutoExecution"] = policy.Authorization.AllowHighRiskAutoExecution
	config["ValidationBudgetID"] = allocation.BudgetID
	config["ValidationTargetConcurrency"] = allocation.TargetConcurrency
	config["ValidationRateLimit"] = allocation.RateLimit
	config["ValidationRequestBudget"] = allocation.RequestBudget
	config["ValidationEstimatedRequests"] = allocation.EstimatedRequests
	if preferredAgentID != "" {
		applyValidationAffinity(config, validationAffinity{
			AgentID:          preferredAgentID,
			AgentUntilUnix:   time.Now().UTC().Add(60 * time.Second).Unix(),
			NetworkUntilUnix: time.Now().UTC().Add(120 * time.Second).Unix(),
		})
	}
	configJSON, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	rules := db.ParseSelectorRulesJSON(revision.AgentSelectorRules)
	if rules.Match == nil {
		rules.Match = db.SelectorValues{}
	}
	rules.Match["risk_validation"] = []string{"v1"}
	rules.Match["gopoc_scoped"] = []string{"v1"}
	observationHash := hashJSON(targetPrints)
	planHash := hashJSON(struct {
		RuleVersion        string              `json:"rule_version"`
		Fingerprints       map[string][]string `json:"fingerprints"`
		AllowHighRiskAuto  bool                `json:"allow_high_risk_auto"`
		GoPocCatalogSHA256 string              `json:"gopoc_catalog"`
	}{root.RuleVersion, targetPrints, policy.Authorization.AllowHighRiskAutoExecution, scanpolicy.GoPocCatalogSHA256()})
	timeoutSec := automaticStageTimeoutSec(revision.TimeoutSec, len(targets))
	return createAutomaticStageBatchWithIDs(tx, intent, root, automaticRiskStage, string(configJSON), targets, observationHash, planHash, revision, rules, timeoutSec, matchedProducts, map[string]interface{}{"matched_products": matchedProducts, "target_count": len(targets), "timeout_sec": timeoutSec, "workflow_scoped": true, "preferred_agent": preferredAgentID, "execution_allocation": allocation, "high_risk_auto_authorized": policy.Authorization.AllowHighRiskAutoExecution, "matching": "agent_native", "source_asset_batch": assetBatch.ID}, riskBatchID, riskBatchID+"-attempt-1")
}

// loadBatchFingerprintMap 汇总指定资产批次上报的指纹（按其全部尝试聚合），
// 返回目标 → 去重排序的产品名列表。
func loadBatchFingerprintMap(ctx context.Context, tx *gorm.DB, root db.RootTask, assetBatchID string) (map[string][]string, error) {
	prints := make(map[string][]string)
	var hits []db.FingerprintHit
	if err := tx.WithContext(ctx).
		Where("tenant_id = ? AND project_id = ? AND root_task_id = ? AND task_id IN (?)",
			root.TenantID, root.ProjectID, root.ID,
			tx.Model(&db.SubTask{}).Select("id").Where("tenant_id = ? AND root_task_id = ? AND batch_id = ?", root.TenantID, root.ID, assetBatchID)).
		Order("target, product_name").Find(&hits).Error; err != nil {
		return nil, fmt.Errorf("load fingerprint hits for batch %s: %w", assetBatchID, err)
	}
	for _, hit := range hits {
		target := strings.TrimSpace(hit.Target)
		product := strings.TrimSpace(hit.ProductName)
		if target == "" || product == "" {
			continue
		}
		list := prints[target]
		dup := false
		for _, existing := range list {
			if existing == product {
				dup = true
				break
			}
		}
		if !dup {
			list = append(list, product)
		}
		prints[target] = list
	}
	return prints, nil
}

func behaviorProbeSignal(evidence string) string {
	var payload struct {
		AdditionalMsg string `json:"additional_msg"`
	}
	if json.Unmarshal([]byte(evidence), &payload) != nil {
		return ""
	}
	const prefix = "[behavior-probe:"
	message := strings.TrimSpace(payload.AdditionalMsg)
	if !strings.HasPrefix(message, prefix) || !strings.HasSuffix(message, "]") || strings.Count(message, prefix) != 1 {
		return ""
	}
	signal := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(message, prefix), "]")))
	if signal == "" || len(signal) > 128 {
		return ""
	}
	for _, char := range signal {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '.' && char != '_' && char != '-' {
			return ""
		}
	}
	return signal
}

func containsFold(values []string, expected string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(expected)) {
			return true
		}
	}
	return false
}

type credentialTargetEnvelope struct {
	Endpoint          string `json:"endpoint"`
	Service           string `json:"service"`
	Plugin            string `json:"plugin"`
	Eligibility       string `json:"eligibility"`
	ObservationSHA256 string `json:"observation_sha256"`
}

type credentialPair = credentialbundle.Pair

func (o *ScanStageOrchestrator) deriveCredentialValidation(ctx context.Context, tx *gorm.DB, intent *db.ScanPolicyIntent, root db.RootTask) (*db.SubTask, error) {
	var policy scanpolicy.Policy
	if err := json.Unmarshal([]byte(intent.PolicyJSON), &policy); err != nil {
		return nil, err
	}
	var assets []db.Asset
	if err := tx.WithContext(ctx).Where("tenant_id = ? AND project_id = ? AND root_task_id = ?", root.TenantID, root.ProjectID, root.ID).Order("target, port").Find(&assets).Error; err != nil {
		return nil, err
	}
	targets, endpoints := credentialTargetsFromAssets(assets)
	if len(targets) == 0 {
		return nil, recordSkippedDerivation(tx, intent, automaticCredentialStage, "no_eligible_services")
	}
	pairs, err := loadCustomCredentialPairs(tx, policy, root.TenantID, root.ProjectID, policy.Credentials.PairLimit)
	if err != nil {
		return nil, err
	}
	revision, err := db.CurrentTaskConfigRevision(tx, root)
	if err != nil {
		return nil, err
	}
	config := map[string]interface{}{}
	if err := json.Unmarshal([]byte(revision.Config), &config); err != nil {
		return nil, err
	}
	config["ExecutionMode"] = automaticCredentialStage
	config["RequiredRuleVersion"] = root.RuleVersion
	config["CredentialValidationTargets"] = targets
	config["CredentialPairLimit"] = policy.Credentials.PairLimit
	estimatedRequests := int64(len(targets)) * int64(policy.Credentials.PairLimit)
	allocation, err := validationAllocation(*intent, root.ID, automaticCredentialStage, estimatedRequests)
	if err != nil {
		return nil, err
	}
	config["ValidationBudgetID"] = allocation.BudgetID
	config["ValidationTargetConcurrency"] = allocation.TargetConcurrency
	config["ValidationRateLimit"] = allocation.RateLimit
	config["ValidationRequestBudget"] = allocation.RequestBudget
	config["ValidationEstimatedRequests"] = allocation.EstimatedRequests
	config["GoPocThreads"] = allocation.TargetConcurrency
	config["NoPoc"] = true
	config["GolangPoc"] = false
	config["Password"] = ""
	config["PasswordFile"] = ""
	affinity := deriveValidationAffinity(tx, root)
	applyValidationAffinity(config, affinity)
	batchID := root.ID + "-auto-credential"
	attemptID := batchID + "-attempt-1"
	if len(pairs) > 0 {
		bundle, err := sealCredentialBundle(root, batchID, attemptID, pairs)
		if err != nil {
			return nil, err
		}
		if err := tx.Create(&bundle).Error; err != nil {
			return nil, err
		}
		config["CredentialBundleRef"] = bundle.Ref
		config["CredentialBundleSHA256"] = bundle.SHA256
		config["CredentialBundleCount"] = bundle.PairCount
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	rules := db.ParseSelectorRulesJSON(revision.AgentSelectorRules)
	if rules.Match == nil {
		rules.Match = db.SelectorValues{}
	}
	rules.Match["credential_validation"] = []string{"v1"}
	rules.Match["transport_tls"] = []string{"verified"}
	observationHash := hashJSON(targets)
	return createAutomaticStageBatchWithIDs(tx, intent, root, automaticCredentialStage, string(encoded), endpoints, observationHash, intent.PlanHash, revision, rules, revision.TimeoutSec, len(targets), map[string]interface{}{"service_count": len(targets), "custom_pair_count": len(pairs), "built_in_dictionary": true, "affinity": affinity, "execution_allocation": allocation}, batchID, attemptID)
}

func validationAllocation(intent db.ScanPolicyIntent, budgetID, stage string, estimated int64) (validationExecutionAllocation, error) {
	var policy scanpolicy.Policy
	if err := json.Unmarshal([]byte(intent.PolicyJSON), &policy); err != nil {
		return validationExecutionAllocation{}, err
	}
	totalConcurrency, totalRate := validationBudgetLimits(policy.Intensity)
	activeStages := 0
	if policy.Capabilities.RiskValidation {
		activeStages++
	}
	if policy.Capabilities.CredentialValidation {
		activeStages++
	}
	if activeStages == 0 || (stage != automaticRiskStage && stage != automaticCredentialStage) {
		return validationExecutionAllocation{}, fmt.Errorf("validation stage %q has no authorized budget", stage)
	}
	concurrency, rate := totalConcurrency/activeStages, totalRate/activeStages
	if concurrency < 1 || rate < 1 || estimated < 1 {
		return validationExecutionAllocation{}, fmt.Errorf("validation stage %q has an invalid execution estimate", stage)
	}
	return validationExecutionAllocation{BudgetID: budgetID, TargetConcurrency: concurrency, RateLimit: rate, RequestBudget: estimated, EstimatedRequests: estimated}, nil
}

func validationBudgetLimits(intensity scanpolicy.Intensity) (targetConcurrency, rateLimit int) {
	switch intensity {
	case scanpolicy.IntensityLow:
		return 2, 10
	case scanpolicy.IntensityHigh:
		return 12, 60
	default:
		return 6, 30
	}
}

func configWithValidationAllocation(raw string, allocation validationExecutionAllocation) (string, error) {
	var config map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &config); err != nil {
		return "", err
	}
	config["ValidationBudgetID"] = allocation.BudgetID
	config["ValidationTargetConcurrency"] = allocation.TargetConcurrency
	config["ValidationRateLimit"] = allocation.RateLimit
	config["ValidationRequestBudget"] = allocation.RequestBudget
	config["ValidationEstimatedRequests"] = allocation.EstimatedRequests
	encoded, err := json.Marshal(config)
	return string(encoded), err
}

func deriveValidationAffinity(tx *gorm.DB, root db.RootTask) validationAffinity {
	var rows []struct {
		AgentID string
		Count   int64
	}
	_ = tx.Table("sub_tasks AS s").Select("s.agent_id, COUNT(*) AS count").
		Joins("JOIN task_batches b ON b.id = s.batch_id AND b.tenant_id = s.tenant_id").
		Where("s.tenant_id = ? AND s.root_task_id = ? AND b.kind = ? AND s.agent_id <> '' AND UPPER(s.status) IN ?", root.TenantID, root.ID, "asset_scan", []string{"DONE", "FINISHED", "COMPLETED", "SUCCESS", "SUCCEEDED"}).
		Group("s.agent_id").Order("count DESC, s.agent_id ASC").Limit(1).Scan(&rows).Error
	if len(rows) == 0 {
		return validationAffinity{}
	}
	now := time.Now().UTC()
	affinity := validationAffinity{AgentID: rows[0].AgentID, AgentUntilUnix: now.Add(15 * time.Second).Unix(), NetworkUntilUnix: now.Add(30 * time.Second).Unix()}
	var node db.Node
	if tx.Select("tags").Where("tenant_id = ? AND agent_id = ?", root.TenantID, affinity.AgentID).First(&node).Error == nil {
		var tags map[string]string
		if json.Unmarshal([]byte(node.Tags), &tags) == nil {
			affinity.NetworkZone = strings.TrimSpace(tags["network_zone"])
		}
	}
	if affinity.NetworkZone == "" {
		affinity.NetworkUntilUnix = 0
	}
	return affinity
}

func applyValidationAffinity(config map[string]interface{}, affinity validationAffinity) {
	if affinity.AgentID == "" {
		return
	}
	config["PreferredAgentID"] = affinity.AgentID
	config["PreferredAgentUntilUnix"] = affinity.AgentUntilUnix
	if affinity.NetworkZone != "" {
		config["PreferredNetworkZone"] = affinity.NetworkZone
		config["PreferredNetworkUntilUnix"] = affinity.NetworkUntilUnix
	}
}

func configWithValidationAffinity(raw string, affinity validationAffinity) (string, error) {
	if affinity.AgentID == "" {
		return raw, nil
	}
	var config map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &config); err != nil {
		return "", err
	}
	applyValidationAffinity(config, affinity)
	encoded, err := json.Marshal(config)
	return string(encoded), err
}

func credentialTargetsFromAssets(assets []db.Asset) ([]credentialTargetEnvelope, []string) {
	seen := map[string]struct{}{}
	plans := make([]credentialTargetEnvelope, 0)
	endpoints := make([]string, 0)
	for _, asset := range assets {
		host := assetHost(asset)
		if host == "" || asset.Port < 1 {
			continue
		}
		observedService := firstNonEmpty(asset.Service, asset.Protocol)
		switch strings.ToLower(strings.TrimSpace(observedService)) {
		case "tcp", "protocol", "portscan", "unknown protocol", "":
			observedService = "unknown"
		}
		plan, ok := scanpolicy.ResolveCredentialTarget(host, asset.Port, observedService)
		if !ok {
			continue
		}
		key := strings.ToLower(plan.Endpoint) + "\x00" + plan.Plugin
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		observation := sha256.Sum256([]byte(strings.Join([]string{asset.Target, asset.URL, asset.Protocol, asset.Service, strconv.Itoa(asset.Port)}, "\x00")))
		plans = append(plans, credentialTargetEnvelope{Endpoint: plan.Endpoint, Service: plan.Service, Plugin: plan.Plugin, Eligibility: plan.Eligibility, ObservationSHA256: hex.EncodeToString(observation[:])})
		endpoints = append(endpoints, plan.Endpoint)
	}
	sort.Slice(plans, func(i, j int) bool {
		if plans[i].Endpoint == plans[j].Endpoint {
			return plans[i].Plugin < plans[j].Plugin
		}
		return plans[i].Endpoint < plans[j].Endpoint
	})
	sort.Strings(endpoints)
	return plans, endpoints
}

func assetHost(asset db.Asset) string {
	for _, raw := range []string{asset.URL, asset.Target} {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if parsed, err := url.Parse(raw); err == nil && parsed.Hostname() != "" {
			return parsed.Hostname()
		}
		if host, _, err := net.SplitHostPort(raw); err == nil {
			return host
		}
		if !strings.Contains(raw, "/") && !strings.Contains(raw, "://") {
			return strings.Trim(raw, "[]")
		}
	}
	return ""
}

func loadCustomCredentialPairs(tx *gorm.DB, policy scanpolicy.Policy, tenantID, projectID string, limit int) ([]credentialPair, error) {
	return credentialbundle.LoadCustomPairs(tx, policy, tenantID, projectID, limit)
}

func sealCredentialBundle(root db.RootTask, batchID, attemptID string, pairs []credentialPair) (db.CredentialBundle, error) {
	return credentialbundle.Seal(root, batchID, attemptID, pairs)
}

func reissueCredentialBundle(tx *gorm.DB, root db.RootTask, batch db.TaskBatch, previous db.SubTask, next *db.SubTask) error {
	return credentialbundle.ReissueForAttempt(tx, root, batch, previous, next)
}

func automaticValidationRetryOptions(trigger string, batch *db.TaskBatch, allowControlled bool) (db.AttemptRetryOptions, bool, bool) {
	isRisk := batch != nil && strings.EqualFold(strings.TrimSpace(batch.Kind), automaticRiskStage)
	isCredential := batch != nil && strings.EqualFold(strings.TrimSpace(batch.Kind), automaticCredentialStage)
	return db.AttemptRetryOptions{
		Trigger: trigger, UseCurrentTaskConfig: !isRisk && !isCredential,
		PreserveRuleVersion: isRisk || isCredential, AllowTerminalRoot: true,
		AllowControlledBatch: allowControlled, PreparedStatus: subTaskStatusDispatching,
		PreparedControlState: db.BatchControlActive,
	}, isRisk, isCredential
}

func prepareRetriedAutomaticValidation(tx *gorm.DB, root db.RootTask, batch *db.TaskBatch, previous db.SubTask, next *db.SubTask) error {
	if batch == nil {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(batch.Kind), automaticCredentialStage) {
		if err := reissueCredentialBundle(tx, root, *batch, previous, next); err != nil {
			return err
		}
	}
	return db.MarkAutomaticValidationStageDerived(tx, root, *batch, next.ID)
}

// riskValidationEstRequestsPerTarget 是无显式映射时的粗粒度请求预算基数：
// Agent 本地匹配后实际消耗由 sealed request budget 兜底限流。
const riskValidationEstRequestsPerTarget = 25

// automaticStageTimeoutScaleThreshold / Ceil 控制验证阶段超时伸缩：
// 小批次维持操作员设定的基础超时；大批次按目标规模线性放大并封顶，
// 避免"健康但缓慢"的执行被反复杀死后进入超时循环。
const (
	automaticStageTimeoutScaleThreshold = 500
	automaticStageTimeoutCeil           = 24 * 3600
)

func automaticStageTimeoutSec(base int, targetCount int) int {
	if base <= 0 {
		base = 3600
	}
	if targetCount <= automaticStageTimeoutScaleThreshold {
		return base
	}
	scaled := base * (targetCount/automaticStageTimeoutScaleThreshold + 1)
	if scaled > automaticStageTimeoutCeil {
		scaled = automaticStageTimeoutCeil
	}
	return scaled
}

// loadTaskFingerprintMap 汇总本任务资产发现阶段上报的指纹，返回
// 目标 → 去重排序的产品名列表。
func createAutomaticStageBatch(tx *gorm.DB, intent *db.ScanPolicyIntent, root db.RootTask, stage, config string, targets []string, observationHash, planHash string, revision db.TaskConfigRevision, rules db.AgentSelectorRules, timeoutSec int, itemCount int, summary map[string]interface{}) (*db.SubTask, error) {
	batchID := root.ID + "-auto-" + strings.ReplaceAll(stage, "_validation", "")
	return createAutomaticStageBatchWithIDs(tx, intent, root, stage, config, targets, observationHash, planHash, revision, rules, timeoutSec, itemCount, summary, batchID, batchID+"-attempt-1")
}

func createAutomaticStageBatchWithIDs(tx *gorm.DB, intent *db.ScanPolicyIntent, root db.RootTask, stage, config string, targets []string, observationHash, planHash string, revision db.TaskConfigRevision, rules db.AgentSelectorRules, timeoutSec int, itemCount int, summary map[string]interface{}, batchID, attemptID string) (*db.SubTask, error) {
	var sequence int
	if err := tx.Model(&db.TaskBatch{}).Select("COALESCE(MAX(sequence), -1) + 1").Where("tenant_id = ? AND root_task_id = ?", root.TenantID, root.ID).Scan(&sequence).Error; err != nil {
		return nil, err
	}
	targetJSON, _ := json.Marshal(targets)
	summaryJSON, _ := json.Marshal(summary)
	batch := db.TaskBatch{ID: batchID, TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, Sequence: sequence, Kind: stage, TargetType: stage, Targets: string(targetJSON), TargetCount: len(targets), Status: subTaskStatusDispatching, ControlState: string(db.BatchControlActive), ConfigVersion: revision.Version, RuleVersion: root.RuleVersion, Priority: revision.Priority, TimeoutSec: timeoutSec, AgentSelector: revision.AgentSelector, AgentSelectorRules: db.SelectorRulesToJSON(rules), CurrentAttemptNo: 1, AttemptCount: 1, LatestAttemptID: attemptID, CreatedBy: intent.AuthorizationActorID}
	attempt := db.SubTask{ID: attemptID, TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, BatchID: batchID, AttemptNo: 1, Trigger: "automatic_" + stage, ChunkTargets: string(targetJSON), Status: subTaskStatusDispatching, Config: config, Priority: revision.Priority, TimeoutSec: timeoutSec, MaxRetry: 1, ConfigVersion: revision.Version, RuleVersion: root.RuleVersion, AgentSelector: revision.AgentSelector, AgentSelectorRules: db.SelectorRulesToJSON(rules)}
	if err := tx.Create(&batch).Error; err != nil {
		return nil, err
	}
	if err := tx.Create(&attempt).Error; err != nil {
		return nil, err
	}
	// 派生行是阶段级摘要（tenant+root+stage 唯一）：多兄弟批次时仅在首次
	// 创建，后续兄弟批次只追加 task_batches/sub_tasks 行。
	var stageRows int64
	if err := tx.Model(&db.ScanStageDerivation{}).
		Where("tenant_id = ? AND root_task_id = ? AND stage = ?", root.TenantID, root.ID, stage).
		Count(&stageRows).Error; err != nil {
		return nil, err
	}
	if stageRows == 0 {
		derivation := db.ScanStageDerivation{TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, Stage: stage, Status: db.ScanStageIntentDerived, PlanHash: planHash, ObservationHash: observationHash, BatchID: batchID, AttemptID: attemptID, ItemCount: itemCount, Summary: string(summaryJSON)}
		if err := tx.Create(&derivation).Error; err != nil {
			return nil, err
		}
	}
	if stage == automaticRiskStage {
		intent.RiskStatus = db.ScanStageIntentDerived
	} else {
		intent.CredentialStatus = db.ScanStageIntentDerived
	}
	if err := recordTaskAudit(tx, root, "automatic_"+stage+"_derived", root.Status, root.Status, intent.AuthorizationActorID, map[string]interface{}{"stage": stage, "item_count": itemCount, "plan_hash": planHash, "observation_hash": observationHash}); err != nil {
		return nil, err
	}
	return &attempt, nil
}

func recordSkippedDerivation(tx *gorm.DB, intent *db.ScanPolicyIntent, stage, reason string) error {
	summary, _ := json.Marshal(map[string]string{"reason": reason})
	row := db.ScanStageDerivation{TenantID: intent.TenantID, ProjectID: intent.ProjectID, RootTaskID: intent.RootTaskID, Stage: stage, Status: db.ScanStageIntentSkipped, PlanHash: intent.PlanHash, Summary: string(summary)}
	if err := tx.Create(&row).Error; err != nil {
		return err
	}
	if stage == automaticRiskStage {
		intent.RiskStatus = db.ScanStageIntentSkipped
	} else {
		intent.CredentialStatus = db.ScanStageIntentSkipped
	}
	return nil
}

func hashJSON(value interface{}) string {
	encoded, _ := json.Marshal(value)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func (o *ScanStageOrchestrator) Reconcile(ctx context.Context) error {
	// Expired capability material has no recovery value: a retry receives a
	// newly sealed bundle bound to its new Attempt.
	if err := db.DB.WithContext(ctx).Where("expires_at < ?", time.Now().UTC()).Delete(&db.CredentialBundle{}).Error; err != nil {
		return err
	}
	var intents []db.ScanPolicyIntent
	if err := db.DB.WithContext(ctx).Where(
		"risk_status IN ? OR credential_status = ?",
		[]string{db.ScanStageIntentPending, db.ScanStageIntentDerived},
		db.ScanStageIntentPending,
	).Limit(100).Find(&intents).Error; err != nil {
		return err
	}
	for _, intent := range intents {
		if err := o.DeriveRoot(ctx, intent.TenantID, intent.RootTaskID); err != nil {
			return err
		}
	}
	return nil
}
