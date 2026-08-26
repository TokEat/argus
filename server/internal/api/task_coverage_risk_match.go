package api

import (
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/P0lar1ght/argus/shared/proto/go/scanplan"
	"gorm.io/gorm"
)

const (
	taskCoverageRiskFingerprintLimit = 16
	taskCoverageRiskPOCLimit         = 24
	taskCoverageWAFFingerprintSkip   = 10
)

type riskCoverageAttemptSnapshot struct {
	DisableGeneralPoc          bool
	AllowHighRiskAutoExecution bool
	WAFSkipOnManyFingerprints  bool
	TargetFingerprints         map[string][]string
	RiskValidationTargets      map[string][]string
	RiskValidationGoPocTargets []riskCoverageGoPocTarget
}

type riskCoverageGoPocTarget struct {
	Target string
	Plugin string
}

func attachTaskCoverageRiskMatches(store *gorm.DB, root db.RootTask, items []taskCoverageInvalidationItem) error {
	if store == nil || len(items) == 0 {
		return nil
	}
	attemptIDs := make([]string, 0, len(items))
	seenAttempts := make(map[string]struct{}, len(items))
	hitTargets := make([]string, 0, len(items))
	seenTargets := make(map[string]struct{}, len(items))
	for _, item := range items {
		if item.Stage != string(scanplan.StageRiskValidation) {
			continue
		}
		if id := strings.TrimSpace(item.Source.AttemptID); id != "" {
			if _, exists := seenAttempts[id]; !exists {
				seenAttempts[id] = struct{}{}
				attemptIDs = append(attemptIDs, id)
			}
		}
		if target := strings.TrimSpace(item.NormalizedTarget); target != "" {
			if _, exists := seenTargets[target]; !exists {
				seenTargets[target] = struct{}{}
				hitTargets = append(hitTargets, target)
			}
		}
	}
	if len(attemptIDs) == 0 && len(hitTargets) == 0 {
		return nil
	}

	snapshots := map[string]riskCoverageAttemptSnapshot{}
	if len(attemptIDs) > 0 {
		var attempts []db.SubTask
		if err := store.Select("id", "config").Where(
			"tenant_id = ? AND project_id = ? AND id IN ?", root.TenantID, root.ProjectID, attemptIDs,
		).Find(&attempts).Error; err != nil {
			return err
		}
		for _, attempt := range attempts {
			if snapshot, ok := parseRiskCoverageAttemptSnapshot(attempt.Config); ok {
				snapshots[attempt.ID] = snapshot
			}
		}
	}

	hitsByTarget := map[string][]string{}
	if len(hitTargets) > 0 {
		var hits []db.FingerprintHit
		if err := store.Select("target", "product_name").Where(
			"tenant_id = ? AND project_id = ? AND root_task_id = ? AND target IN ?",
			root.TenantID, root.ProjectID, root.ID, hitTargets,
		).Order("target, product_name").Find(&hits).Error; err != nil {
			return err
		}
		for _, hit := range hits {
			if name := publicCoverageLabel(hit.ProductName); name != "" {
				hitsByTarget[hit.Target] = append(hitsByTarget[hit.Target], name)
			}
		}
	}

	neededProducts := make(map[string]struct{})
	for index, item := range items {
		if item.Stage != string(scanplan.StageRiskValidation) {
			continue
		}
		fingerprints := riskCoverageFingerprints(snapshots[item.Source.AttemptID], hitsByTarget[item.NormalizedTarget], item.NormalizedTarget)
		items[index].Fingerprints = fingerprints
		for _, product := range fingerprints {
			neededProducts[strings.ToLower(product)] = struct{}{}
		}
	}

	workflowsByProduct, err := loadRiskCoverageWorkflows(store, root.TenantID, neededProducts)
	if err != nil {
		return err
	}
	blockedHighRisk, err := loadRiskCoverageHighRiskPOCs(store, root.TenantID, workflowsByProduct)
	if err != nil {
		return err
	}

	for index, item := range items {
		if item.Stage != string(scanplan.StageRiskValidation) {
			continue
		}
		snapshot := snapshots[item.Source.AttemptID]
		pocs := riskCoverageMatchedPOCs(snapshot, item.NormalizedTarget, items[index].Fingerprints, workflowsByProduct, blockedHighRisk)
		items[index].MatchedPocs = pocs
		items[index].Reason = refineRiskCoverageReason(item.Reason, items[index].Fingerprints, pocs)
	}
	return nil
}

func parseRiskCoverageAttemptSnapshot(raw string) (riskCoverageAttemptSnapshot, bool) {
	var internal struct {
		DisableGeneralPoc          bool
		AllowHighRiskAutoExecution bool
		WAFSkipOnManyFingerprints  bool
		TargetFingerprints         map[string][]string
		RiskValidationTargets      map[string][]string
		RiskValidationGoPocTargets []riskCoverageGoPocTarget
	}
	if json.Unmarshal([]byte(raw), &internal) != nil {
		return riskCoverageAttemptSnapshot{}, false
	}
	return riskCoverageAttemptSnapshot{
		DisableGeneralPoc:          internal.DisableGeneralPoc,
		AllowHighRiskAutoExecution: internal.AllowHighRiskAutoExecution,
		WAFSkipOnManyFingerprints:  internal.WAFSkipOnManyFingerprints,
		TargetFingerprints:         internal.TargetFingerprints,
		RiskValidationTargets:      internal.RiskValidationTargets,
		RiskValidationGoPocTargets: internal.RiskValidationGoPocTargets,
	}, true
}

func riskCoverageFingerprints(snapshot riskCoverageAttemptSnapshot, hitProducts []string, target string) []string {
	names := make([]string, 0, len(snapshot.TargetFingerprints[target])+len(hitProducts))
	for _, product := range snapshot.TargetFingerprints[target] {
		if name := publicCoverageLabel(product); name != "" {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		names = append(names, hitProducts...)
	}
	return cappedUniqueNames(names, taskCoverageRiskFingerprintLimit)
}

func riskCoverageMatchedPOCs(snapshot riskCoverageAttemptSnapshot, target string, fingerprints []string, workflowsByProduct map[string][]string, blockedHighRisk map[string]struct{}) []string {
	if snapshot.WAFSkipOnManyFingerprints && len(fingerprints) > taskCoverageWAFFingerprintSkip {
		return nil
	}
	names := make([]string, 0, 8)
	for _, poc := range snapshot.RiskValidationTargets[target] {
		if name := publicCoveragePOCName(poc); name != "" {
			names = append(names, name)
		}
	}
	for _, item := range snapshot.RiskValidationGoPocTargets {
		if strings.TrimSpace(item.Target) != target {
			continue
		}
		if name := publicCoverageLabel(item.Plugin); name != "" {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		for _, product := range fingerprints {
			if snapshot.DisableGeneralPoc && isGeneralPOCWorkflowProduct(product) {
				continue
			}
			for _, poc := range workflowsByProduct[strings.ToLower(product)] {
				if !snapshot.AllowHighRiskAutoExecution {
					if _, blocked := blockedHighRisk[strings.ToLower(poc)]; blocked {
						continue
					}
				}
				names = append(names, poc)
			}
		}
	}
	return cappedUniqueNames(names, taskCoverageRiskPOCLimit)
}

func loadRiskCoverageWorkflows(store *gorm.DB, tenantID string, products map[string]struct{}) (map[string][]string, error) {
	result := map[string][]string{}
	if len(products) == 0 {
		return result, nil
	}
	keys := make([]string, 0, len(products))
	for product := range products {
		keys = append(keys, product)
	}
	var workflows []db.WorkflowRule
	if err := store.Select("product_name", "poc_name").Where(
		"tenant_id = ? AND enabled = ? AND LOWER(state) = ? AND LOWER(product_name) IN ?",
		tenantID, true, "approved", keys,
	).Order("product_name asc, poc_name asc").Find(&workflows).Error; err != nil {
		return nil, err
	}
	for _, workflow := range workflows {
		poc := publicCoveragePOCName(workflow.PocName)
		if poc == "" {
			poc = publicCoverageLabel(workflow.PocName)
		}
		if poc == "" {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(workflow.ProductName))
		result[key] = append(result[key], poc)
	}
	return result, nil
}

func loadRiskCoverageHighRiskPOCs(store *gorm.DB, tenantID string, workflowsByProduct map[string][]string) (map[string]struct{}, error) {
	blocked := map[string]struct{}{}
	aliases := make([]string, 0)
	seen := map[string]struct{}{}
	for _, pocs := range workflowsByProduct {
		for _, poc := range pocs {
			for _, alias := range pocReferenceAliases(poc) {
				if _, exists := seen[alias]; exists {
					continue
				}
				seen[alias] = struct{}{}
				aliases = append(aliases, alias)
			}
		}
	}
	if len(aliases) == 0 {
		return blocked, nil
	}
	var rules []db.PocRule
	if err := store.Select("name", "source_file", "risk_level").Where(
		"tenant_id = ? AND (LOWER(name) IN ? OR LOWER(source_file) IN ?)", tenantID, aliases, aliases,
	).Find(&rules).Error; err != nil {
		return nil, err
	}
	for _, rule := range rules {
		if !db.PocRequiresSecondConfirmation(rule.RiskLevel) {
			continue
		}
		for _, alias := range pocRuleAliases(rule) {
			blocked[alias] = struct{}{}
		}
		if name := publicCoveragePOCName(rule.SourceFile); name != "" {
			blocked[strings.ToLower(name)] = struct{}{}
		}
		if name := publicCoveragePOCName(rule.Name); name != "" {
			blocked[strings.ToLower(name)] = struct{}{}
		}
	}
	return blocked, nil
}

func refineRiskCoverageReason(reason string, fingerprints, pocs []string) string {
	parts := splitCoverageReasonParts(reason)
	kept := make([]string, 0, len(parts))
	reuseParts := make([]string, 0, 2)
	for _, part := range parts {
		if part == "poc_set_unknown" || part == "endpoint_content_unknown" {
			reuseParts = append(reuseParts, part)
			continue
		}
		kept = append(kept, part)
	}
	if len(fingerprints) > 0 && len(pocs) == 0 && !hasRiskExecutionFailure(kept) {
		return "fingerprint_unmatched_pocs"
	}
	if len(kept) > 0 {
		return strings.Join(kept, ",")
	}
	if len(reuseParts) > 0 {
		return strings.Join(reuseParts, ",")
	}
	return strings.TrimSpace(reason)
}

func splitCoverageReasonParts(reason string) []string {
	parts := strings.Split(reason, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func hasRiskExecutionFailure(parts []string) bool {
	for _, part := range parts {
		switch part {
		case "nuclei_execution_failed", "phase_failed", "pipeline_failed", "phase_incomplete", "pipeline_cancelled":
			return true
		}
	}
	return false
}

func publicCoverageLabel(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" || len(value) > 128 {
		return ""
	}
	if value != filepath.Base(value) || strings.ContainsAny(value, "/\\\r\n\x00") {
		return ""
	}
	return value
}

func publicCoveragePOCName(raw string) string {
	value := publicCoverageLabel(raw)
	if value == "" {
		return ""
	}
	if isSafeRiskValidationPocFile(value) {
		return value
	}
	return publicCoverageLabel(value)
}

func cappedUniqueNames(values []string, limit int) []string {
	if limit < 1 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	unique := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, value)
	}
	sort.Slice(unique, func(i, j int) bool { return strings.ToLower(unique[i]) < strings.ToLower(unique[j]) })
	if len(unique) == 0 {
		return nil
	}
	if len(unique) > limit {
		return unique[:limit]
	}
	return unique
}
