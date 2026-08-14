package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
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
	return o.DeriveRoot(ctx, attempt.TenantID, attempt.RootTaskID)
}

func updateAutomaticStageStatus(ctx context.Context, batch db.TaskBatch, completed db.SubTask) error {
	return db.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var derivation db.ScanStageDerivation
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("tenant_id = ? AND root_task_id = ? AND batch_id = ? AND stage = ?", batch.TenantID, batch.RootTaskID, batch.ID, batch.Kind).First(&derivation).Error; err != nil {
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
		if derivation.Status == statusValue && derivation.AttemptID == latest.ID {
			return nil
		}
		updates := map[string]interface{}{"status": statusValue, "attempt_id": latest.ID, "updated_at": time.Now().UTC()}
		if err := tx.Model(&derivation).Updates(updates).Error; err != nil {
			return err
		}
		column := "risk_status"
		if batch.Kind == automaticCredentialStage {
			column = "credential_status"
		}
		if err := tx.Model(&db.ScanPolicyIntent{}).Where("tenant_id = ? AND root_task_id = ?", batch.TenantID, batch.RootTaskID).Update(column, statusValue).Error; err != nil {
			return err
		}
		var root db.RootTask
		if err := tx.Where("id = ? AND tenant_id = ?", batch.RootTaskID, batch.TenantID).First(&root).Error; err != nil {
			return err
		}
		return recordTaskAudit(tx, root, "automatic_"+batch.Kind+"_terminal", completed.Status, latest.Status, "system", map[string]interface{}{"stage": batch.Kind, "batch_id": batch.ID, "attempt_id": latest.ID, "stage_status": statusValue})
	})
}

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
		ready, err := assetDiscoveryBatchesTerminal(tx, tenantID, rootTaskID)
		if err != nil || !ready {
			return err
		}
		var root db.RootTask
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ? AND tenant_id = ?", rootTaskID, tenantID).First(&root).Error; err != nil {
			return err
		}
		if intent.RiskStatus == db.ScanStageIntentPending {
			attempt, err := o.deriveRiskValidation(ctx, tx, &intent, root)
			if err != nil {
				return err
			}
			if attempt != nil {
				queued = append(queued, *attempt)
			}
		}
		if intent.CredentialStatus == db.ScanStageIntentPending {
			attempt, err := o.deriveCredentialValidation(ctx, tx, &intent, root)
			if err != nil {
				return err
			}
			if attempt != nil {
				queued = append(queued, *attempt)
			}
		}
		return tx.Save(&intent).Error
	})
	if err != nil {
		return err
	}
	if len(queued) == 0 {
		return nil
	}
	if routerRuntime().TaskQueue == nil {
		return errTaskCreateQueueUnavailable
	}
	for _, attempt := range queued {
		protoTask, err := db.SubTaskToProto(&attempt)
		if err != nil {
			return err
		}
		if err := routerRuntime().TaskQueue.PushTask(ctx, protoTask); err != nil {
			return err
		}
		if err := db.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			if err := tx.Model(&db.SubTask{}).Where("id = ? AND tenant_id = ? AND status = ?", attempt.ID, attempt.TenantID, subTaskStatusDispatching).Updates(map[string]interface{}{"status": "Pending", "stream_msg_id": subTaskQueuedMarker}).Error; err != nil {
				return err
			}
			return tx.Model(&db.TaskBatch{}).Where("id = ? AND tenant_id = ? AND latest_attempt_id = ?", attempt.BatchID, attempt.TenantID, attempt.ID).Update("status", "Pending").Error
		}); err != nil {
			return err
		}
	}
	return nil
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

func (o *ScanStageOrchestrator) deriveRiskValidation(ctx context.Context, tx *gorm.DB, intent *db.ScanPolicyIntent, root db.RootTask) (*db.SubTask, error) {
	if currentRuleVersionTx(tx) != root.RuleVersion {
		return nil, recordSkippedDerivation(tx, intent, automaticRiskStage, "rule_version_drift")
	}
	preview, err := buildTaskRiskValidationPreview(ctx, root.TenantID, root, riskValidationPreviewOptions{})
	if err != nil {
		return nil, err
	}
	selected := make([]riskValidationCandidate, 0, len(preview.Candidates))
	var estimatedRequests int64
	for _, candidate := range preview.Candidates {
		if len(candidate.WorkflowSources) > 0 {
			selected = append(selected, candidate)
			estimatedRequests = saturatingAdd(estimatedRequests, candidate.EstimatedRequests)
		}
	}
	var assets []db.Asset
	if err := tx.WithContext(ctx).Where("tenant_id = ? AND project_id = ? AND root_task_id = ?", root.TenantID, root.ProjectID, root.ID).Order("target, port").Find(&assets).Error; err != nil {
		return nil, err
	}
	var activeFingerprintHits []db.FingerprintHit
	if err := tx.WithContext(ctx).Where("tenant_id = ? AND project_id = ? AND root_task_id = ?", root.TenantID, root.ProjectID, root.ID).Order("target, product_name").Find(&activeFingerprintHits).Error; err != nil {
		return nil, err
	}
	var activeFingerprintRules []db.ActiveFingerprintRule
	if err := tx.WithContext(ctx).
		Where("tenant_id = ? AND enabled = ? AND auto_eligible = ? AND LOWER(state) = ?", root.TenantID, true, true, "approved").
		Order("source_file").Find(&activeFingerprintRules).Error; err != nil {
		return nil, err
	}
	goPocTargets, goPocEstimated := riskGoPocTargetsFromObservations(assets, selected, activeFingerprintHits, activeFingerprintRules)
	if len(selected) == 0 && len(goPocTargets) == 0 {
		return nil, recordSkippedDerivation(tx, intent, automaticRiskStage, "no_approved_workflow_matches")
	}
	revision, err := db.CurrentTaskConfigRevision(tx, root)
	if err != nil {
		return nil, err
	}
	var config string
	var targets []string
	if len(selected) > 0 {
		config, targets, _, _, err = buildRiskValidationAttemptConfig(revision, root.RuleVersion, selected)
	} else {
		config, err = buildGoPocOnlyRiskValidationAttemptConfig(revision, root.RuleVersion)
	}
	if err != nil {
		return nil, err
	}
	config, targets, err = configWithRiskGoPocTargets(config, targets, goPocTargets)
	if err != nil {
		return nil, err
	}
	estimatedRequests = saturatingAdd(estimatedRequests, goPocEstimated)
	allocation, err := validationAllocation(*intent, root.ID, automaticRiskStage, estimatedRequests)
	if err != nil {
		return nil, err
	}
	config, err = configWithValidationAllocation(config, allocation)
	if err != nil {
		return nil, err
	}
	affinity := deriveValidationAffinity(tx, root)
	config, err = configWithValidationAffinity(config, affinity)
	if err != nil {
		return nil, err
	}
	rules := db.ParseSelectorRulesJSON(revision.AgentSelectorRules)
	if rules.Match == nil {
		rules.Match = db.SelectorValues{}
	}
	rules.Match["risk_validation"] = []string{"v1"}
	rules.Match["gopoc_scoped"] = []string{"v1"}
	observationHash := hashJSON(struct {
		Nuclei []riskValidationCandidate `json:"nuclei"`
		GoPoc  []scanpolicy.GoPocTarget  `json:"gopoc"`
	}{selected, goPocTargets})
	planHash := hashJSON(struct {
		NucleiPlan string                   `json:"nuclei_plan"`
		Catalog    string                   `json:"gopoc_catalog"`
		Targets    []scanpolicy.GoPocTarget `json:"gopoc_targets"`
	}{preview.PlanHash, scanpolicy.GoPocCatalogSHA256(), goPocTargets})
	return createAutomaticStageBatch(tx, intent, root, automaticRiskStage, config, targets, observationHash, planHash, revision, rules, len(selected)+len(goPocTargets), map[string]interface{}{"nuclei_candidate_count": len(selected), "gopoc_candidate_count": len(goPocTargets), "workflow_scoped": true, "affinity": affinity, "execution_allocation": allocation})
}

func buildGoPocOnlyRiskValidationAttemptConfig(revision db.TaskConfigRevision, ruleVersion string) (string, error) {
	config := make(map[string]interface{})
	if strings.TrimSpace(revision.Config) != "" {
		if err := json.Unmarshal([]byte(revision.Config), &config); err != nil {
			return "", fmt.Errorf("decode current task config: %w", err)
		}
	}
	config["ExecutionMode"] = automaticRiskStage
	config["RequiredRuleVersion"] = strings.TrimSpace(ruleVersion)
	config["RiskValidationTargets"] = map[string][]string{}
	config["RiskValidationPocHashes"] = map[string]string{}
	config["NoPoc"] = false
	config["GolangPoc"] = false
	config["PocNameForSearch"] = ""
	config["Hunter"], config["Fofa"], config["Quake"] = false, false, false
	encoded, err := json.Marshal(config)
	return string(encoded), err
}

func riskGoPocTargetsFromObservations(assets []db.Asset, selected []riskValidationCandidate, activeHits []db.FingerprintHit, activeRules []db.ActiveFingerprintRule) ([]scanpolicy.GoPocTarget, int64) {
	items := make([]scanpolicy.GoPocTarget, 0)
	for _, asset := range assets {
		host := assetHost(asset)
		if host == "" || asset.Port < 1 || asset.Port > 65535 {
			continue
		}
		service := strings.ToLower(strings.TrimSpace(firstNonEmpty(asset.Service, asset.Protocol)))
		switch service {
		case "tcp", "protocol", "portscan", "unknown protocol", "":
			service = "unknown"
		}
		observation := sha256.Sum256([]byte(strings.Join([]string{asset.Target, asset.URL, asset.Protocol, asset.Service, strconv.Itoa(asset.Port)}, "\x00")))
		items = append(items, scanpolicy.GoPocTargetsForEndpoint(net.JoinHostPort(host, strconv.Itoa(asset.Port)), service, asset.Port, hex.EncodeToString(observation[:]), scanpolicy.GoPocVulnerabilityCheck)...)
	}
	for _, candidate := range selected {
		pocID := strings.TrimSuffix(strings.ToLower(filepath.Base(candidate.PocFile)), strings.ToLower(filepath.Ext(candidate.PocFile)))
		plugin := ""
		switch pocID {
		case "yongyou_u9_viewstate":
			plugin = "ViewState-Key-Crack"
		}
		if plugin == "" {
			continue
		}
		observation := sha256.Sum256([]byte(hashJSON(candidate)))
		item, err := scanpolicy.GoPocTargetForSignal(candidate.Endpoint, plugin, "nuclei", pocID, hex.EncodeToString(observation[:]))
		if err == nil {
			items = append(items, item)
		}
	}
	items = append(items, riskGoPocTargetsFromActiveFingerprints(activeHits, activeRules)...)
	seen := make(map[string]struct{}, len(items))
	result := make([]scanpolicy.GoPocTarget, 0, len(items))
	var estimated int64
	sort.Slice(items, func(i, j int) bool {
		if items[i].Target == items[j].Target {
			return items[i].Plugin < items[j].Plugin
		}
		return items[i].Target < items[j].Target
	})
	for _, item := range items {
		key := strings.ToLower(item.Target) + "\x00" + item.Plugin
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, item)
		estimated = saturatingAdd(estimated, int64(item.RequestCost))
	}
	return result, estimated
}

func riskGoPocTargetsFromActiveFingerprints(hits []db.FingerprintHit, rules []db.ActiveFingerprintRule) []scanpolicy.GoPocTarget {
	rulesBySignal := make(map[string]db.ActiveFingerprintRule, len(rules))
	ambiguousSignals := make(map[string]struct{})
	for _, rule := range rules {
		signal := strings.ToLower(strings.TrimSuffix(filepath.Base(strings.TrimSpace(rule.SourceFile)), filepath.Ext(rule.SourceFile)))
		if signal == "" || strings.TrimSpace(rule.Name) == "" || strings.TrimSpace(rule.ContentHash) == "" {
			continue
		}
		if _, ambiguous := ambiguousSignals[signal]; ambiguous {
			continue
		}
		if _, duplicate := rulesBySignal[signal]; duplicate {
			delete(rulesBySignal, signal)
			ambiguousSignals[signal] = struct{}{}
			continue
		}
		rulesBySignal[signal] = rule
	}

	descriptors := scanpolicy.GoPocDescriptors()
	result := make([]scanpolicy.GoPocTarget, 0)
	for _, hit := range hits {
		signal := behaviorProbeSignal(hit.Evidence)
		rule, ok := rulesBySignal[signal]
		if !ok || !strings.EqualFold(strings.TrimSpace(hit.ProductName), strings.TrimSpace(rule.ProductName)) {
			continue
		}
		observation := sha256.Sum256([]byte(strings.Join([]string{
			strconv.FormatUint(uint64(hit.ID), 10), hit.Target, hit.ProductName, hit.Evidence,
			rule.Name, rule.ContentHash, strconv.Itoa(rule.Version),
		}, "\x00")))
		for _, descriptor := range descriptors {
			if descriptor.Capability != scanpolicy.GoPocVulnerabilityCheck || !containsFold(descriptor.NucleiTemplates, rule.Name) {
				continue
			}
			item, err := scanpolicy.GoPocTargetForSignal(hit.Target, descriptor.Plugin, "nuclei", rule.Name, hex.EncodeToString(observation[:]))
			if err == nil {
				result = append(result, item)
			}
		}
	}
	return result
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

func configWithRiskGoPocTargets(raw string, targets []string, goPocTargets []scanpolicy.GoPocTarget) (string, []string, error) {
	var config map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &config); err != nil {
		return "", nil, err
	}
	config["RiskValidationGoPocTargets"] = goPocTargets
	config["GoPocCatalogSHA256"] = scanpolicy.GoPocCatalogSHA256()
	seen := make(map[string]struct{}, len(targets)+len(goPocTargets))
	merged := make([]string, 0, len(targets)+len(goPocTargets))
	for _, target := range targets {
		if _, ok := seen[target]; !ok {
			seen[target] = struct{}{}
			merged = append(merged, target)
		}
	}
	for _, item := range goPocTargets {
		if _, ok := seen[item.Target]; !ok {
			seen[item.Target] = struct{}{}
			merged = append(merged, item.Target)
		}
	}
	sort.Strings(merged)
	encoded, err := json.Marshal(config)
	return string(encoded), merged, err
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
	return createAutomaticStageBatchWithIDs(tx, intent, root, automaticCredentialStage, string(encoded), endpoints, observationHash, intent.PlanHash, revision, rules, len(targets), map[string]interface{}{"service_count": len(targets), "custom_pair_count": len(pairs), "built_in_dictionary": true, "affinity": affinity, "execution_allocation": allocation}, batchID, attemptID)
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

func createAutomaticStageBatch(tx *gorm.DB, intent *db.ScanPolicyIntent, root db.RootTask, stage, config string, targets []string, observationHash, planHash string, revision db.TaskConfigRevision, rules db.AgentSelectorRules, itemCount int, summary map[string]interface{}) (*db.SubTask, error) {
	batchID := root.ID + "-auto-" + strings.ReplaceAll(stage, "_validation", "")
	return createAutomaticStageBatchWithIDs(tx, intent, root, stage, config, targets, observationHash, planHash, revision, rules, itemCount, summary, batchID, batchID+"-attempt-1")
}

func createAutomaticStageBatchWithIDs(tx *gorm.DB, intent *db.ScanPolicyIntent, root db.RootTask, stage, config string, targets []string, observationHash, planHash string, revision db.TaskConfigRevision, rules db.AgentSelectorRules, itemCount int, summary map[string]interface{}, batchID, attemptID string) (*db.SubTask, error) {
	var sequence int
	if err := tx.Model(&db.TaskBatch{}).Select("COALESCE(MAX(sequence), -1) + 1").Where("tenant_id = ? AND root_task_id = ?", root.TenantID, root.ID).Scan(&sequence).Error; err != nil {
		return nil, err
	}
	targetJSON, _ := json.Marshal(targets)
	summaryJSON, _ := json.Marshal(summary)
	batch := db.TaskBatch{ID: batchID, TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, Sequence: sequence, Kind: stage, TargetType: stage, Targets: string(targetJSON), TargetCount: len(targets), Status: subTaskStatusDispatching, ControlState: string(db.BatchControlActive), ConfigVersion: revision.Version, RuleVersion: root.RuleVersion, Priority: revision.Priority, TimeoutSec: revision.TimeoutSec, AgentSelector: revision.AgentSelector, AgentSelectorRules: db.SelectorRulesToJSON(rules), CurrentAttemptNo: 1, AttemptCount: 1, LatestAttemptID: attemptID, CreatedBy: intent.AuthorizationActorID}
	attempt := db.SubTask{ID: attemptID, TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, BatchID: batchID, AttemptNo: 1, Trigger: "automatic_" + stage, ChunkTargets: string(targetJSON), Status: subTaskStatusDispatching, Config: config, Priority: revision.Priority, TimeoutSec: revision.TimeoutSec, MaxRetry: 1, ConfigVersion: revision.Version, RuleVersion: root.RuleVersion, AgentSelector: revision.AgentSelector, AgentSelectorRules: db.SelectorRulesToJSON(rules)}
	derivation := db.ScanStageDerivation{TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, Stage: stage, Status: db.ScanStageIntentDerived, PlanHash: planHash, ObservationHash: observationHash, BatchID: batchID, AttemptID: attemptID, ItemCount: itemCount, Summary: string(summaryJSON)}
	if err := tx.Create(&batch).Error; err != nil {
		return nil, err
	}
	if err := tx.Create(&attempt).Error; err != nil {
		return nil, err
	}
	if err := tx.Create(&derivation).Error; err != nil {
		return nil, err
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
	if err := db.DB.WithContext(ctx).Where("risk_status = ? OR credential_status = ?", db.ScanStageIntentPending, db.ScanStageIntentPending).Limit(100).Find(&intents).Error; err != nil {
		return err
	}
	for _, intent := range intents {
		if err := o.DeriveRoot(ctx, intent.TenantID, intent.RootTaskID); err != nil {
			return err
		}
	}
	return nil
}
