package api

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/TokEat/argus/server/internal/db"
	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

const maxEstimatedTemplateRequests int64 = 1_000_000_000

type riskValidationAssetPreview struct {
	Target   string `json:"target"`
	URL      string `json:"url"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Title    string `json:"title"`
	Service  string `json:"service"`
}

type riskValidationCandidate struct {
	Asset                      riskValidationAssetPreview `json:"asset"`
	Endpoint                   string                     `json:"endpoint"`
	Products                   []string                   `json:"products"`
	MatchTypes                 []string                   `json:"match_types"`
	WorkflowSources            []string                   `json:"workflow_sources"`
	PocName                    string                     `json:"poc_name"`
	PocFile                    string                     `json:"poc_file"`
	Severity                   string                     `json:"severity"`
	ExecutionClass             string                     `json:"execution_class"`
	RiskLevel                  string                     `json:"risk_level"`
	RequiresSecondConfirmation bool                       `json:"requires_second_confirmation"`
	PocContentHash             string                     `json:"poc_content_hash"`
	TemplateRequestEstimate    int64                      `json:"template_request_estimate"`
	EstimatedRequests          int64                      `json:"estimated_requests"`
	EstimateBasis              string                     `json:"estimate_basis"`
}

type riskValidationExcluded struct {
	Product  string `json:"product"`
	PocName  string `json:"poc_name"`
	Reason   string `json:"reason"`
	Workflow string `json:"workflow"`
}

type riskValidationSummary struct {
	FingerprintHits            int   `json:"fingerprint_hits"`
	UniqueAssets               int   `json:"unique_assets"`
	Products                   int   `json:"products"`
	WorkflowRules              int   `json:"workflow_rules"`
	PocRules                   int   `json:"poc_rules"`
	Candidates                 int   `json:"candidates"`
	EstimatedRequests          int64 `json:"estimated_requests"`
	SecondConfirmationRequired bool  `json:"second_confirmation_required"`
	SecondConfirmationItems    int   `json:"second_confirmation_items"`
	UnmatchedProducts          int   `json:"unmatched_products"`
	ExcludedMappings           int   `json:"excluded_mappings"`
}

type riskValidationPreview struct {
	TaskID            string
	TaskName          string
	ProjectID         string
	TaskRuleVersion   string
	RuleVersion       string
	ConfigVersion     int
	GeneratedAt       time.Time
	PlanHash          string
	Summary           riskValidationSummary
	Candidates        []riskValidationCandidate
	UnmatchedProducts []string
	Excluded          []riskValidationExcluded
}

type riskValidationPreviewRequest struct {
	SpecifiedPocs []string `json:"specified_pocs"`
}

type riskValidationPreviewOptions struct {
	SpecifiedPocs []string
}

func normalizeSpecifiedPocReferences(values []string) ([]string, error) {
	if len(values) > 100 {
		return nil, fmt.Errorf("specified_pocs cannot contain more than 100 rules")
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if strings.ContainsAny(value, "\r\n\x00") || len(value) > 255 {
			return nil, fmt.Errorf("specified_pocs contains an invalid rule reference")
		}
		key := strings.ToLower(value)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i]) < strings.ToLower(out[j]) })
	return out, nil
}

func decodeRiskValidationPreviewOptions(c *gin.Context) (riskValidationPreviewOptions, error) {
	var request riskValidationPreviewRequest
	if c.Request.Body != nil {
		decoder := json.NewDecoder(c.Request.Body)
		decoder.DisallowUnknownFields()
		decodeErr := decoder.Decode(&request)
		if decodeErr != nil && decodeErr != io.EOF {
			return riskValidationPreviewOptions{}, fmt.Errorf("invalid preview request: %w", decodeErr)
		}
		if decodeErr == nil {
			if err := decoder.Decode(&struct{}{}); err != io.EOF {
				return riskValidationPreviewOptions{}, fmt.Errorf("invalid preview request: expected one JSON object")
			}
		}
	}
	specified, err := normalizeSpecifiedPocReferences(request.SpecifiedPocs)
	if err != nil {
		return riskValidationPreviewOptions{}, err
	}
	return riskValidationPreviewOptions{SpecifiedPocs: specified}, nil
}

func previewTaskRiskValidation(c *gin.Context) {
	tenantID := currentTenantID(c)
	var task db.RootTask
	if err := db.DB.WithContext(c.Request.Context()).Where("id = ? AND tenant_id = ?", c.Param("id"), tenantID).First(&task).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
		return
	}
	if !canAccessProject(c, task.ProjectID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "project not accessible"})
		return
	}
	options, err := decodeRiskValidationPreviewOptions(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	preview, err := buildTaskRiskValidationPreview(c.Request.Context(), tenantID, task, options)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	page, pageSize := parsePagination(c, 50, 200)
	start := (page - 1) * pageSize
	if start > len(preview.Candidates) {
		start = len(preview.Candidates)
	}
	end := start + pageSize
	if end > len(preview.Candidates) {
		end = len(preview.Candidates)
	}

	c.JSON(http.StatusOK, gin.H{
		"task": gin.H{
			"id":         preview.TaskID,
			"name":       preview.TaskName,
			"project_id": preview.ProjectID,
		},
		"task_rule_version":  preview.TaskRuleVersion,
		"rule_version":       preview.RuleVersion,
		"config_version":     preview.ConfigVersion,
		"generated_at":       preview.GeneratedAt,
		"plan_hash":          preview.PlanHash,
		"summary":            preview.Summary,
		"items":              preview.Candidates[start:end],
		"unmatched_products": preview.UnmatchedProducts,
		"excluded":           preview.Excluded,
		"page":               page,
		"page_size":          pageSize,
		"total":              len(preview.Candidates),
		"has_more":           end < len(preview.Candidates),
	})
}

func buildTaskRiskValidationPreview(ctx context.Context, tenantID string, task db.RootTask, options riskValidationPreviewOptions) (riskValidationPreview, error) {
	// Keep the builder read-only. It intentionally does not create a batch,
	// attempt, audit row, queue message, or Agent command.
	preview := riskValidationPreview{
		TaskID:            task.ID,
		TaskName:          task.Name,
		ProjectID:         task.ProjectID,
		TaskRuleVersion:   task.RuleVersion,
		RuleVersion:       currentRuleVersionValue(),
		ConfigVersion:     task.CurrentConfigVersion,
		GeneratedAt:       time.Now().UTC(),
		Candidates:        []riskValidationCandidate{},
		UnmatchedProducts: []string{},
		Excluded:          []riskValidationExcluded{},
	}
	if preview.ConfigVersion < 1 {
		preview.ConfigVersion = 1
	}

	if err := ctx.Err(); err != nil {
		return preview, err
	}

	subTaskIDs, err := taskAttemptIDs(ctx, tenantID, task.ID)
	if err != nil {
		return preview, err
	}
	reuseSources, err := taskFingerprintReuseSources(ctx, tenantID, task)
	if err != nil {
		return preview, err
	}

	var hits []db.FingerprintHit
	hitQuery := db.DB.WithContext(ctx).Where("tenant_id = ? AND project_id = ?", tenantID, task.ProjectID)
	if len(subTaskIDs) > 0 {
		hitQuery = hitQuery.Where("(root_task_id = ? OR task_id IN ?)", task.ID, subTaskIDs)
	} else {
		hitQuery = hitQuery.Where("root_task_id = ?", task.ID)
	}
	if err := hitQuery.Order("target asc, product_name asc").Find(&hits).Error; err != nil {
		return preview, fmt.Errorf("load task fingerprints: %w", err)
	}
	reusedHits, err := loadReusedFingerprintHits(ctx, tenantID, task.ProjectID, reuseSources)
	if err != nil {
		return preview, err
	}
	hits = append(hits, reusedHits...)
	hits = uniqueRiskValidationHits(hits)
	preview.Summary.FingerprintHits = len(hits)

	assetTargetSet := make(map[string]struct{}, len(hits))
	productLookup := make(map[string]string)
	for _, hit := range hits {
		target := strings.TrimSpace(hit.Target)
		if target != "" {
			if _, exists := assetTargetSet[target]; !exists {
				assetTargetSet[target] = struct{}{}
			}
		}
		product := strings.TrimSpace(hit.ProductName)
		if product != "" {
			productLookup[strings.ToLower(product)] = product
		}
	}
	preview.Summary.Products = len(productLookup)

	assets, assetsByTarget, err := loadRiskValidationAssets(ctx, tenantID, task, subTaskIDs, reuseSources)
	if err != nil {
		return preview, err
	}
	for _, asset := range assets {
		if target := strings.TrimSpace(asset.Target); target != "" {
			assetTargetSet[target] = struct{}{}
		}
	}
	preview.Summary.UniqueAssets = len(assetTargetSet)

	if (len(hits) == 0 || len(productLookup) == 0) && len(options.SpecifiedPocs) == 0 {
		preview.PlanHash = riskValidationPlanHash(tenantID, preview)
		return preview, nil
	}

	productKeys := sortedStringMapKeys(productLookup)
	var workflows []db.WorkflowRule
	if len(productKeys) > 0 {
		if err := db.DB.WithContext(ctx).Where("tenant_id = ? AND enabled = ? AND LOWER(state) = ? AND LOWER(product_name) IN ?", tenantID, true, "approved", productKeys).
			Order("product_name asc, poc_name asc, match_type asc").Find(&workflows).Error; err != nil {
			return preview, fmt.Errorf("load approved workflows: %w", err)
		}
	}
	preview.Summary.WorkflowRules = len(workflows)

	workflowsByProduct := make(map[string][]db.WorkflowRule)
	pocReferenceSet := make(map[string]struct{})
	for _, workflow := range workflows {
		productKey := strings.ToLower(strings.TrimSpace(workflow.ProductName))
		workflowsByProduct[productKey] = append(workflowsByProduct[productKey], workflow)
		for _, alias := range pocReferenceAliases(workflow.PocName) {
			pocReferenceSet[alias] = struct{}{}
		}
	}
	for _, specified := range options.SpecifiedPocs {
		for _, alias := range pocReferenceAliases(specified) {
			pocReferenceSet[alias] = struct{}{}
		}
	}

	for _, productKey := range productKeys {
		if len(workflowsByProduct[productKey]) == 0 {
			preview.UnmatchedProducts = append(preview.UnmatchedProducts, productLookup[productKey])
		}
	}
	sort.Strings(preview.UnmatchedProducts)

	pocReferences := sortedSetKeys(pocReferenceSet)
	var pocs []db.PocRule
	if len(pocReferences) > 0 {
		if err := db.DB.WithContext(ctx).Where("tenant_id = ? AND (LOWER(name) IN ? OR LOWER(source_file) IN ?)", tenantID, pocReferences, pocReferences).
			Order("updated_at desc, id desc").Find(&pocs).Error; err != nil {
			return preview, fmt.Errorf("load workflow POCs: %w", err)
		}
	}
	pocByAlias := make(map[string]db.PocRule)
	for _, poc := range pocs {
		for _, alias := range pocRuleAliases(poc) {
			if _, exists := pocByAlias[alias]; !exists {
				pocByAlias[alias] = poc
			}
		}
	}

	selectedPocs := make(map[uint]db.PocRule)
	excludedSet := make(map[string]struct{})
	type candidateBuilder struct {
		candidate riskValidationCandidate
		products  map[string]struct{}
		match     map[string]struct{}
		sources   map[string]struct{}
		poc       db.PocRule
	}
	candidateByKey := make(map[string]*candidateBuilder)

	for _, hit := range hits {
		productKey := strings.ToLower(strings.TrimSpace(hit.ProductName))
		for _, workflow := range workflowsByProduct[productKey] {
			poc, found := findPocRuleByReference(pocByAlias, workflow.PocName)
			if !found {
				appendRiskValidationExcluded(&preview.Excluded, excludedSet, workflow, "missing_poc")
				continue
			}
			if !poc.Enabled || !strings.EqualFold(strings.TrimSpace(poc.State), "Approved") {
				appendRiskValidationExcluded(&preview.Excluded, excludedSet, workflow, "poc_not_approved")
				continue
			}
			executionClass, executionErr := db.NormalizePocExecutionClass(poc.ExecutionClass)
			riskLevel, riskErr := db.NormalizePocRiskLevel(poc.RiskLevel)
			if executionErr != nil || riskErr != nil || !isSafeRiskValidationPocFile(poc.SourceFile) {
				appendRiskValidationExcluded(&preview.Excluded, excludedSet, workflow, "invalid_poc_governance")
				continue
			}
			endpoints := riskValidationEndpoints(hit.Target, workflow.MatchType)
			if len(endpoints) == 0 {
				if !isSupportedWorkflowMatchType(workflow.MatchType) {
					appendRiskValidationExcluded(&preview.Excluded, excludedSet, workflow, "unsupported_match_type")
				}
				continue
			}
			selectedPocs[poc.ID] = poc
			for _, endpoint := range endpoints {
				candidateKey := strings.ToLower(strings.TrimSpace(endpoint)) + "\x00" + fmt.Sprint(poc.ID) + "\x00" + poc.ContentHash
				builder := candidateByKey[candidateKey]
				if builder == nil {
					asset := assetsByTarget[hit.Target]
					if strings.TrimSpace(asset.Target) == "" {
						asset.Target = hit.Target
					}
					builder = &candidateBuilder{
						candidate: riskValidationCandidate{
							Asset:                      asset,
							Endpoint:                   endpoint,
							PocName:                    poc.Name,
							PocFile:                    poc.SourceFile,
							Severity:                   normalizePreviewSeverity(poc.Severity),
							ExecutionClass:             executionClass,
							RiskLevel:                  riskLevel,
							RequiresSecondConfirmation: db.PocRequiresSecondConfirmation(riskLevel),
							PocContentHash:             poc.ContentHash,
						},
						products: make(map[string]struct{}),
						match:    make(map[string]struct{}),
						sources:  make(map[string]struct{}),
						poc:      poc,
					}
					candidateByKey[candidateKey] = builder
				}
				builder.products[strings.TrimSpace(hit.ProductName)] = struct{}{}
				builder.match[strings.ToLower(strings.TrimSpace(workflow.MatchType))] = struct{}{}
				builder.sources[strings.TrimSpace(workflow.SourceFile)] = struct{}{}
			}
		}
	}

	for _, specified := range options.SpecifiedPocs {
		poc, found := findPocRuleByReference(pocByAlias, specified)
		if !found {
			appendSpecifiedRiskValidationExcluded(&preview.Excluded, excludedSet, specified, "missing_poc")
			continue
		}
		if !poc.Enabled || !strings.EqualFold(strings.TrimSpace(poc.State), "Approved") {
			appendSpecifiedRiskValidationExcluded(&preview.Excluded, excludedSet, specified, "poc_not_approved")
			continue
		}
		executionClass, executionErr := db.NormalizePocExecutionClass(poc.ExecutionClass)
		riskLevel, riskErr := db.NormalizePocRiskLevel(poc.RiskLevel)
		if executionErr != nil || riskErr != nil || !isSafeRiskValidationPocFile(poc.SourceFile) {
			appendSpecifiedRiskValidationExcluded(&preview.Excluded, excludedSet, specified, "invalid_poc_governance")
			continue
		}
		selectedPocs[poc.ID] = poc
		for _, asset := range assets {
			endpoint := strings.TrimSpace(asset.URL)
			if endpoint == "" {
				endpoint = strings.TrimSpace(asset.Target)
			}
			if endpoint == "" {
				continue
			}
			candidateKey := strings.ToLower(endpoint) + "\x00" + fmt.Sprint(poc.ID) + "\x00" + poc.ContentHash
			builder := candidateByKey[candidateKey]
			if builder == nil {
				builder = &candidateBuilder{
					candidate: riskValidationCandidate{
						Asset:                      asset,
						Endpoint:                   endpoint,
						PocName:                    poc.Name,
						PocFile:                    strings.TrimSpace(poc.SourceFile),
						Severity:                   normalizePreviewSeverity(poc.Severity),
						ExecutionClass:             executionClass,
						RiskLevel:                  riskLevel,
						RequiresSecondConfirmation: db.PocRequiresSecondConfirmation(riskLevel),
						PocContentHash:             poc.ContentHash,
					},
					products: make(map[string]struct{}),
					match:    make(map[string]struct{}),
					sources:  make(map[string]struct{}),
					poc:      poc,
				}
				candidateByKey[candidateKey] = builder
			}
			builder.match["specified"] = struct{}{}
		}
	}

	arsenalContent, err := loadPocArsenalContent(ctx, tenantID, selectedPocs)
	if err != nil {
		return preview, err
	}
	requestEstimateCache := make(map[uint]struct {
		count int64
		basis string
	})
	for _, builder := range candidateByKey {
		content, exists := arsenalContent[builder.poc.ArtifactID]
		if !exists || strings.TrimSpace(content) == "" {
			appendRiskValidationExcluded(&preview.Excluded, excludedSet, db.WorkflowRule{
				ProductName: strings.Join(sortedSetKeys(builder.products), ","),
				PocName:     builder.poc.SourceFile,
				SourceFile:  strings.Join(sortedSetKeys(builder.sources), ","),
			}, "missing_poc_content")
			continue
		}
		estimate, exists := requestEstimateCache[builder.poc.ID]
		if !exists {
			count, basis := estimateNucleiTemplateRequests(content)
			estimate = struct {
				count int64
				basis string
			}{count: count, basis: basis}
			requestEstimateCache[builder.poc.ID] = estimate
		}
		builder.candidate.Products = sortedSetKeys(builder.products)
		builder.candidate.MatchTypes = sortedSetKeys(builder.match)
		builder.candidate.WorkflowSources = sortedSetKeys(builder.sources)
		builder.candidate.PocContentHash = fmt.Sprintf("%x", md5.Sum([]byte(content)))
		builder.candidate.TemplateRequestEstimate = estimate.count
		builder.candidate.EstimatedRequests = estimate.count
		builder.candidate.EstimateBasis = estimate.basis
		preview.Candidates = append(preview.Candidates, builder.candidate)
	}

	sort.Slice(preview.Candidates, func(i, j int) bool {
		if preview.Candidates[i].Endpoint != preview.Candidates[j].Endpoint {
			return preview.Candidates[i].Endpoint < preview.Candidates[j].Endpoint
		}
		if preview.Candidates[i].PocName != preview.Candidates[j].PocName {
			return preview.Candidates[i].PocName < preview.Candidates[j].PocName
		}
		return preview.Candidates[i].PocFile < preview.Candidates[j].PocFile
	})
	sort.Slice(preview.Excluded, func(i, j int) bool {
		if preview.Excluded[i].Product != preview.Excluded[j].Product {
			return preview.Excluded[i].Product < preview.Excluded[j].Product
		}
		return preview.Excluded[i].PocName < preview.Excluded[j].PocName
	})

	preview.Summary.PocRules = len(selectedPocs)
	preview.Summary.Candidates = len(preview.Candidates)
	preview.Summary.UnmatchedProducts = len(preview.UnmatchedProducts)
	preview.Summary.ExcludedMappings = len(preview.Excluded)
	for _, candidate := range preview.Candidates {
		preview.Summary.EstimatedRequests = saturatingAdd(preview.Summary.EstimatedRequests, candidate.EstimatedRequests)
		if candidate.RequiresSecondConfirmation {
			preview.Summary.SecondConfirmationRequired = true
			preview.Summary.SecondConfirmationItems++
		}
	}
	preview.PlanHash = riskValidationPlanHash(tenantID, preview)
	return preview, nil
}

func taskAttemptIDs(ctx context.Context, tenantID, taskID string) ([]string, error) {
	var ids []string
	if err := db.DB.WithContext(ctx).Model(&db.SubTask{}).Where("tenant_id = ? AND root_task_id = ?", tenantID, taskID).Pluck("id", &ids).Error; err != nil {
		return nil, fmt.Errorf("load task attempts: %w", err)
	}
	return ids, nil
}

func uniqueRiskValidationHits(hits []db.FingerprintHit) []db.FingerprintHit {
	seen := make(map[string]struct{}, len(hits))
	out := make([]db.FingerprintHit, 0, len(hits))
	for _, hit := range hits {
		target := strings.TrimSpace(hit.Target)
		product := strings.TrimSpace(hit.ProductName)
		if target == "" || product == "" {
			continue
		}
		key := strings.ToLower(target) + "\x00" + strings.ToLower(product)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		hit.Target = target
		hit.ProductName = product
		out = append(out, hit)
	}
	return out
}

func pocReferenceAliases(raw string) []string {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		return nil
	}
	aliases := map[string]struct{}{value: {}}
	base := strings.ToLower(filepath.Base(value))
	aliases[base] = struct{}{}
	ext := strings.ToLower(filepath.Ext(base))
	withoutExt := strings.TrimSuffix(base, ext)
	aliases[withoutExt] = struct{}{}
	if ext == "" {
		aliases[base+".yaml"] = struct{}{}
		aliases[base+".yml"] = struct{}{}
	}
	return sortedSetKeys(aliases)
}

func pocRuleAliases(rule db.PocRule) []string {
	aliases := make(map[string]struct{})
	for _, value := range []string{rule.Name, rule.SourceFile} {
		for _, alias := range pocReferenceAliases(value) {
			aliases[alias] = struct{}{}
		}
	}
	return sortedSetKeys(aliases)
}

func findPocRuleByReference(byAlias map[string]db.PocRule, raw string) (db.PocRule, bool) {
	for _, alias := range pocReferenceAliases(raw) {
		if rule, exists := byAlias[alias]; exists {
			return rule, true
		}
	}
	return db.PocRule{}, false
}

func appendRiskValidationExcluded(items *[]riskValidationExcluded, seen map[string]struct{}, workflow db.WorkflowRule, reason string) {
	key := strings.ToLower(workflow.ProductName) + "\x00" + strings.ToLower(workflow.PocName) + "\x00" + reason
	if _, exists := seen[key]; exists {
		return
	}
	seen[key] = struct{}{}
	*items = append(*items, riskValidationExcluded{
		Product: strings.TrimSpace(workflow.ProductName), PocName: strings.TrimSpace(workflow.PocName),
		Reason: reason, Workflow: strings.TrimSpace(workflow.SourceFile),
	})
}

func appendSpecifiedRiskValidationExcluded(items *[]riskValidationExcluded, seen map[string]struct{}, pocReference, reason string) {
	key := "specified\x00" + strings.ToLower(strings.TrimSpace(pocReference)) + "\x00" + reason
	if _, exists := seen[key]; exists {
		return
	}
	seen[key] = struct{}{}
	*items = append(*items, riskValidationExcluded{
		Product: "specified", PocName: strings.TrimSpace(pocReference), Reason: reason,
	})
}

func isSafeRiskValidationPocFile(fileName string) bool {
	fileName = strings.TrimSpace(fileName)
	ext := strings.ToLower(filepath.Ext(fileName))
	return fileName != "" && fileName == filepath.Base(fileName) &&
		!strings.ContainsAny(fileName, "/\\\r\n\x00") && (ext == ".yaml" || ext == ".yml")
}

func isSupportedWorkflowMatchType(matchType string) bool {
	switch strings.ToLower(strings.TrimSpace(matchType)) {
	case "root", "base", "dir":
		return true
	default:
		return false
	}
}

func riskValidationEndpoints(target, matchType string) []string {
	target = strings.TrimSpace(target)
	matchType = strings.ToLower(strings.TrimSpace(matchType))
	if target == "" || !isSupportedWorkflowMatchType(matchType) {
		return nil
	}
	if !strings.Contains(target, "://") {
		if matchType == "root" {
			return []string{target}
		}
		return nil
	}
	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil
	}
	root := parsed.Scheme + "://" + parsed.Host
	switch matchType {
	case "root":
		return []string{root}
	case "base":
		if parsed.Path != "" && parsed.Path != "/" {
			return []string{target}
		}
	case "dir":
		if parsed.Path == "" || parsed.Path == "/" {
			return nil
		}
		parts := strings.Split(parsed.Path, "/")
		seen := make(map[string]struct{})
		endpoints := make([]string, 0, len(parts)-1)
		for i := 1; i < len(parts); i++ {
			endpoint := root + strings.Join(parts[:i], "/")
			if _, exists := seen[endpoint]; exists {
				continue
			}
			seen[endpoint] = struct{}{}
			endpoints = append(endpoints, endpoint)
		}
		return endpoints
	}
	return nil
}

func loadPocArsenalContent(ctx context.Context, tenantID string, pocs map[uint]db.PocRule) (map[string]string, error) {
	artifactSet := make(map[string]struct{})
	for _, poc := range pocs {
		if strings.TrimSpace(poc.ArtifactID) != "" {
			artifactSet[poc.ArtifactID] = struct{}{}
		}
	}
	artifactIDs := sortedSetKeys(artifactSet)
	out := make(map[string]string, len(artifactIDs))
	if len(artifactIDs) == 0 {
		return out, nil
	}
	var arsenals []db.Arsenal
	if err := db.DB.WithContext(ctx).Select("id", "content").Where("tenant_id = ? AND id IN ?", tenantID, artifactIDs).Find(&arsenals).Error; err != nil {
		return nil, fmt.Errorf("load POC template content: %w", err)
	}
	for _, arsenal := range arsenals {
		out[arsenal.ID] = arsenal.Content
	}
	return out, nil
}

func estimateNucleiTemplateRequests(content string) (int64, string) {
	if strings.TrimSpace(content) == "" {
		return 1, "fallback_one_request"
	}
	var document yaml.Node
	if err := yaml.Unmarshal([]byte(content), &document); err != nil || len(document.Content) == 0 {
		return 1, "fallback_one_request"
	}
	root := document.Content[0]
	if root.Kind != yaml.MappingNode {
		return 1, "fallback_one_request"
	}
	protocolKeys := map[string]struct{}{
		"http": {}, "requests": {}, "dns": {}, "tcp": {}, "network": {},
		"ssl": {}, "websocket": {}, "headless": {}, "code": {},
	}
	var total int64
	for i := 0; i+1 < len(root.Content); i += 2 {
		key := strings.ToLower(strings.TrimSpace(root.Content[i].Value))
		if _, supported := protocolKeys[key]; !supported {
			continue
		}
		total = saturatingAdd(total, estimateNucleiProtocolNode(root.Content[i+1]))
	}
	if total <= 0 {
		return 1, "fallback_one_request"
	}
	return total, "template_upper_bound"
}

func estimateNucleiProtocolNode(node *yaml.Node) int64 {
	if node == nil {
		return 0
	}
	if node.Kind != yaml.SequenceNode {
		return estimateNucleiRequestBlock(node)
	}
	var total int64
	for _, block := range node.Content {
		total = saturatingAdd(total, estimateNucleiRequestBlock(block))
	}
	return total
}

func estimateNucleiRequestBlock(node *yaml.Node) int64 {
	if node == nil || node.Kind != yaml.MappingNode {
		return 1
	}
	base := int64(1)
	attack := ""
	payloadSizes := make([]int64, 0)
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := strings.ToLower(strings.TrimSpace(node.Content[i].Value))
		value := node.Content[i+1]
		switch key {
		case "path", "raw", "inputs":
			if size := yamlNodeCardinality(value); size > base {
				base = size
			}
		case "attack", "attack-type":
			attack = strings.ToLower(strings.TrimSpace(value.Value))
		case "payloads":
			if value.Kind == yaml.MappingNode {
				for payloadIndex := 1; payloadIndex < len(value.Content); payloadIndex += 2 {
					payloadSizes = append(payloadSizes, yamlNodeCardinality(value.Content[payloadIndex]))
				}
			}
		}
	}
	multiplier := int64(1)
	if len(payloadSizes) > 0 {
		switch attack {
		case "clusterbomb":
			for _, size := range payloadSizes {
				multiplier = saturatingMultiply(multiplier, size)
			}
		default:
			for _, size := range payloadSizes {
				if size > multiplier {
					multiplier = size
				}
			}
		}
	}
	return saturatingMultiply(base, multiplier)
}

func yamlNodeCardinality(node *yaml.Node) int64 {
	if node == nil {
		return 1
	}
	if node.Kind == yaml.SequenceNode {
		if len(node.Content) == 0 {
			return 1
		}
		return int64(len(node.Content))
	}
	return 1
}

func normalizePreviewSeverity(raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		return "unknown"
	}
	return value
}

func saturatingAdd(left, right int64) int64 {
	if left >= maxEstimatedTemplateRequests || right >= maxEstimatedTemplateRequests-left {
		return maxEstimatedTemplateRequests
	}
	return left + right
}

func saturatingMultiply(left, right int64) int64 {
	if left <= 0 || right <= 0 {
		return 0
	}
	if left >= maxEstimatedTemplateRequests/right {
		return maxEstimatedTemplateRequests
	}
	return left * right
}

func sortedSetKeys(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

func sortedStringMapKeys(values map[string]string) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func riskValidationPlanHash(tenantID string, preview riskValidationPreview) string {
	type hashCandidate struct {
		Endpoint                   string   `json:"endpoint"`
		Products                   []string `json:"products"`
		MatchTypes                 []string `json:"match_types"`
		PocName                    string   `json:"poc_name"`
		PocFile                    string   `json:"poc_file"`
		PocContentHash             string   `json:"poc_content_hash"`
		Severity                   string   `json:"severity"`
		ExecutionClass             string   `json:"execution_class"`
		RiskLevel                  string   `json:"risk_level"`
		RequiresSecondConfirmation bool     `json:"requires_second_confirmation"`
		RequestEstimate            int64    `json:"request_estimate"`
	}
	payload := struct {
		TenantID      string          `json:"tenant_id"`
		ProjectID     string          `json:"project_id"`
		TaskID        string          `json:"task_id"`
		RuleVersion   string          `json:"rule_version"`
		ConfigVersion int             `json:"config_version"`
		Candidates    []hashCandidate `json:"candidates"`
	}{
		TenantID: tenantID, ProjectID: preview.ProjectID, TaskID: preview.TaskID,
		RuleVersion: preview.RuleVersion, ConfigVersion: preview.ConfigVersion,
		Candidates: make([]hashCandidate, 0, len(preview.Candidates)),
	}
	for _, candidate := range preview.Candidates {
		payload.Candidates = append(payload.Candidates, hashCandidate{
			Endpoint: candidate.Endpoint, Products: candidate.Products, MatchTypes: candidate.MatchTypes,
			PocName: candidate.PocName, PocFile: candidate.PocFile,
			PocContentHash: candidate.PocContentHash, Severity: candidate.Severity,
			ExecutionClass: candidate.ExecutionClass, RiskLevel: candidate.RiskLevel,
			RequiresSecondConfirmation: candidate.RequiresSecondConfirmation,
			RequestEstimate:            candidate.EstimatedRequests,
		})
	}
	encoded, _ := json.Marshal(payload)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
