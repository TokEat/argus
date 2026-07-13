package mcp

import (
	"context"
	"net/http"
	"strings"
)

const generalPOCWorkflowPrefix = "General-Poc-"

func isGeneralPOCWorkflowProduct(product string) bool {
	return strings.HasPrefix(strings.TrimSpace(product), generalPOCWorkflowPrefix)
}

func workflowKind(product string) string {
	if isGeneralPOCWorkflowProduct(product) {
		return "general_poc"
	}
	return "product_bound"
}

func mergeSafetyHint(product string) string {
	if isGeneralPOCWorkflowProduct(product) {
		return "General-Poc-* is a reserved general POC workflow group; do not merge it into a real product alias or create a same-name fingerprint."
	}
	return "review manually before saving fingerprint/workflow drafts; product_search is read-only"
}

func (c *Client) argusWorkflowContext(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	action := stringArg(args, "action")
	productFilter := strings.ToLower(stringArg(args, "product_name"))
	pocFilter := strings.ToLower(stringArg(args, "poc_name"))
	limit := intArgDefault(args, "limit", 12)
	if limit <= 0 {
		limit = 12
	}
	if limit > 50 {
		limit = 50
	}

	var fingerprints []catalogRecord
	if err := c.do(ctx, http.MethodGet, "/api/v1/dictionaries/fingerprint", nil, &fingerprints); err != nil {
		return nil, err
	}
	var workflows []catalogRecord
	if err := c.do(ctx, http.MethodGet, "/api/v1/dictionaries/workflow", nil, &workflows); err != nil {
		return nil, err
	}
	var pocs []catalogRecord
	if err := c.do(ctx, http.MethodGet, "/api/v1/poc-rules?all=1", nil, &pocs); err != nil {
		return nil, err
	}

	products := map[string]bool{}
	fingerprintItems := []map[string]interface{}{}
	for _, item := range fingerprints {
		product := item.Product
		if product == "" || !matchesFilter(product, productFilter) {
			continue
		}
		products[strings.ToLower(product)] = true
		fingerprintItems = appendLimited(fingerprintItems, map[string]interface{}{
			"product_name": product,
			"rules":        item.Rules,
		}, limit)
	}

	pocByName := map[string]map[string]interface{}{}
	pocItems := []map[string]interface{}{}
	for _, poc := range pocs {
		sourceFile := poc.EffectiveSourceFile()
		name := firstNonEmpty(poc.Name, sourceFile)
		if name == "" && sourceFile == "" {
			continue
		}
		if sourceFile != "" {
			pocByName[strings.ToLower(sourceFile)] = poc.Raw
		}
		if name != "" {
			pocByName[strings.ToLower(name)] = poc.Raw
		}
		if !matchesFilter(name, pocFilter) && !matchesFilter(sourceFile, pocFilter) {
			continue
		}
		pocItems = appendLimited(pocItems, map[string]interface{}{
			"name":        name,
			"source_file": sourceFile,
			"severity":    poc.Severity,
			"state":       poc.State,
			"enabled":     poc.Enabled,
		}, limit)
	}

	workflowItems := []map[string]interface{}{}
	conflicts := []map[string]interface{}{}
	existing := map[string]bool{}
	for _, workflow := range workflows {
		product := workflow.Product
		types := workflow.Types
		pocNames := workflow.POCs
		if product == "" || !matchesFilter(product, productFilter) {
			continue
		}
		for _, pocName := range pocNames {
			if !matchesFilter(pocName, pocFilter) {
				continue
			}
			for _, matchType := range types {
				item := map[string]interface{}{
					"product_name":  product,
					"poc_name":      pocName,
					"match_type":    matchType,
					"source_file":   "workflow.yaml",
					"state":         "Approved",
					"workflow_kind": workflowKind(product),
				}
				workflowItems = appendLimited(workflowItems, item, limit)
				key := strings.ToLower(product) + "|" + strings.ToLower(pocName)
				existing[key] = true
				if _, ok := pocByName[strings.ToLower(pocName)]; !ok {
					conflicts = appendLimited(conflicts, map[string]interface{}{
						"type":         "missing_poc",
						"severity":     "high",
						"message":      "Workflow references a POC that is not present in native /poc-rules.",
						"product_name": product,
						"poc_name":     pocName,
						"match_type":   matchType,
						"source_file":  "workflow.yaml",
					}, limit)
				}
				if !isGeneralPOCWorkflowProduct(product) && !products[strings.ToLower(product)] {
					conflicts = appendLimited(conflicts, map[string]interface{}{
						"type":         "missing_fingerprint",
						"severity":     "medium",
						"message":      "Workflow product has no fingerprint dictionary entry.",
						"product_name": product,
						"poc_name":     pocName,
						"match_type":   matchType,
						"source_file":  "workflow.yaml",
					}, limit)
				}
			}
		}
	}

	recommendations := workflowRecommendations(productFilter, pocFilter, fingerprintItems, pocItems, existing, limit)
	out := map[string]interface{}{
		"status":          "success",
		"source":          "native_api",
		"fingerprints":    fingerprintItems,
		"pocs":            pocItems,
		"workflows":       workflowItems,
		"recommendations": recommendations,
		"conflicts":       conflicts,
	}
	if action == "workflow_recommend" {
		return map[string]interface{}{"status": "success", "source": "native_api", "recommendations": recommendations, "existing_rules": workflowItems}, nil
	}
	if action == "workflow_conflicts" {
		return map[string]interface{}{"status": "success", "source": "native_api", "conflicts": conflicts, "checked_rules": len(workflowItems)}, nil
	}
	return out, nil
}
