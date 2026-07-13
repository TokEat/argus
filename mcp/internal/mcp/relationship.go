package mcp

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

type relationshipSnapshot struct {
	Fingerprints []map[string]interface{}
	Workflows    []map[string]interface{}
	POCs         []map[string]interface{}
	Exploits     []map[string]interface{}
}

type workflowRef struct {
	Product      string
	POCName      string
	MatchType    string
	WorkflowKind string
	SourceFile   string
}

func (c *Client) loadRelationshipSnapshot(ctx context.Context) (relationshipSnapshot, error) {
	var snap relationshipSnapshot
	if err := c.do(ctx, http.MethodGet, "/api/v1/dictionaries/fingerprint", nil, &snap.Fingerprints); err != nil {
		return snap, err
	}
	if err := c.do(ctx, http.MethodGet, "/api/v1/dictionaries/workflow", nil, &snap.Workflows); err != nil {
		return snap, err
	}
	if err := c.do(ctx, http.MethodGet, "/api/v1/poc-rules?all=1", nil, &snap.POCs); err != nil {
		return snap, err
	}
	// EXP catalog is useful context for governance, but older deployments may
	// disable it. Keep relationship stats available when that endpoint fails.
	_ = c.do(ctx, http.MethodGet, "/api/v1/exploits?all=1", nil, &snap.Exploits)
	return snap, nil
}

func (c *Client) argusRelationshipStats(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	snap, err := c.loadRelationshipSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	limit := clampRelationshipLimit(intArgDefault(args, "limit", 20))
	fpProducts, fpRuleCount := fingerprintProductSet(snap.Fingerprints)
	workflowProducts, refs := workflowProductSetAndRefs(snap.Workflows)
	pocNames := pocLookupSet(snap.POCs)

	linked := []string{}
	unlinked := []string{}
	for key, product := range fpProducts {
		if _, ok := workflowProducts[key]; ok {
			linked = append(linked, product)
		} else {
			unlinked = append(unlinked, product)
		}
	}
	sort.Strings(linked)
	sort.Strings(unlinked)

	workflowMissingFP := []string{}
	generalWorkflows := []string{}
	for key, product := range workflowProducts {
		if isGeneralPOCWorkflowProduct(product) {
			generalWorkflows = append(generalWorkflows, product)
			continue
		}
		if _, ok := fpProducts[key]; !ok {
			workflowMissingFP = append(workflowMissingFP, product)
		}
	}
	sort.Strings(workflowMissingFP)
	sort.Strings(generalWorkflows)

	missingPOCRefs := relationshipMissingPOCRefs(refs, pocNames, "", "")

	return map[string]interface{}{
		"status": "success",
		"source": "native_api",
		"totals": map[string]interface{}{
			"fingerprint_products":            len(fpProducts),
			"fingerprint_rules":               fpRuleCount,
			"workflow_products":               len(workflowProducts),
			"workflow_edges":                  len(refs),
			"pocs":                            len(snap.POCs),
			"pyexp_rules":                     len(snap.Exploits),
			"fingerprint_with_workflow":       len(linked),
			"fingerprint_without_workflow":    len(unlinked),
			"workflow_without_fingerprint":    len(workflowMissingFP),
			"general_poc_workflows":           len(generalWorkflows),
			"workflow_missing_poc_references": len(missingPOCRefs),
		},
		"samples": map[string]interface{}{
			"linked_fingerprints":          firstNStrings(linked, limit),
			"unlinked_fingerprints":        firstNStrings(unlinked, limit),
			"workflow_without_fingerprint": firstNStrings(workflowMissingFP, limit),
			"general_poc_workflows":        firstNStrings(generalWorkflows, limit),
			"missing_poc_refs":             firstNMaps(missingPOCRefs, limit),
		},
		"mcp_guidance": map[string]interface{}{
			"next_steps": []string{
				"use argus_context action=relationship_list with view=unlinked_fingerprints to page through missing workflow coverage",
				"use view=workflow_without_fingerprint to find workflow names that need a fingerprint or alias decision",
				"use view=missing_poc_refs before publishing workflow changes",
			},
			"warnings": []string{"General-Poc-* workflow products are counted separately and are not treated as missing fingerprints"},
		},
	}, nil
}

func (c *Client) argusRelationshipList(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	view := strings.ToLower(strings.TrimSpace(stringArg(args, "view")))
	if view == "" {
		return nil, fmt.Errorf("view is required for action=relationship_list")
	}
	start, end, err := normalizeRuleListRange(args)
	if err != nil {
		return nil, err
	}
	query := strings.ToLower(strings.TrimSpace(stringArg(args, "query")))
	productFilter := strings.ToLower(strings.TrimSpace(stringArg(args, "product_name")))
	pocFilter := strings.ToLower(strings.TrimSpace(stringArg(args, "poc_name")))

	snap, err := c.loadRelationshipSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	fpProducts, _ := fingerprintProductSet(snap.Fingerprints)
	workflowProducts, refs := workflowProductSetAndRefs(snap.Workflows)
	pocNames := pocLookupSet(snap.POCs)

	items := []map[string]interface{}{}
	switch view {
	case "linked_fingerprints":
		for key, product := range fpProducts {
			if _, ok := workflowProducts[key]; ok {
				items = appendRelationshipProductItem(items, product, "linked_fingerprint", productFilter, query)
			}
		}
	case "unlinked_fingerprints":
		for key, product := range fpProducts {
			if _, ok := workflowProducts[key]; !ok {
				items = appendRelationshipProductItem(items, product, "unlinked_fingerprint", productFilter, query)
			}
		}
	case "workflow_without_fingerprint":
		for key, product := range workflowProducts {
			if isGeneralPOCWorkflowProduct(product) {
				continue
			}
			if _, ok := fpProducts[key]; !ok {
				items = appendRelationshipProductItem(items, product, "workflow_without_fingerprint", productFilter, query)
			}
		}
	case "general_poc_workflows":
		for _, product := range workflowProducts {
			if isGeneralPOCWorkflowProduct(product) {
				items = appendRelationshipProductItem(items, product, "general_poc_workflow", productFilter, query)
			}
		}
	case "missing_poc_refs":
		items = relationshipMissingPOCRefs(refs, pocNames, productFilter, pocFilter)
		items = filterRelationshipItems(items, query)
	case "workflow_links":
		for _, ref := range refs {
			if productFilter != "" && !matchesFilter(ref.Product, productFilter) {
				continue
			}
			if pocFilter != "" && !matchesFilter(ref.POCName, pocFilter) {
				continue
			}
			item := workflowRefItem(ref)
			if query == "" || relationshipItemMatchesQuery(item, query) {
				items = append(items, item)
			}
		}
	default:
		return nil, fmt.Errorf("unsupported relationship_list view %q", view)
	}

	sortRelationshipItems(items)
	window, hasMore, nextStart, nextEnd := relationshipWindow(items, start, end)
	return map[string]interface{}{
		"status":           "success",
		"source":           "native_api",
		"action":           "relationship_list",
		"view":             view,
		"query":            query,
		"product_name":     stringArg(args, "product_name"),
		"poc_name":         stringArg(args, "poc_name"),
		"total":            len(items),
		"range_start":      start,
		"range_end":        end,
		"returned":         len(window),
		"has_more":         hasMore,
		"next_range_start": nextStart,
		"next_range_end":   nextEnd,
		"list_snapshot":    time.Now().UTC().Format(time.RFC3339),
		"items":            window,
		"mcp_guidance": map[string]interface{}{
			"next_steps": []string{
				"call argus_product_search on a candidate product before merging or renaming",
				"call argus_context action=rule_get before saving any changed fingerprint/workflow content",
			},
			"warnings": []string{"relationship_list is read-only and computed from native catalog endpoints"},
		},
	}, nil
}

func clampRelationshipLimit(limit int) int {
	if limit <= 0 {
		return 20
	}
	if limit > 50 {
		return 50
	}
	return limit
}

func fingerprintProductSet(rows []map[string]interface{}) (map[string]string, int) {
	products := map[string]string{}
	ruleCount := 0
	for _, row := range rows {
		product := firstNonEmpty(mapString(row, "product", "Product"), mapString(row, "product_name", "ProductName"))
		if product == "" {
			continue
		}
		products[product] = product
		ruleCount += len(stringSliceFromAny(firstPresent(row, "rules", "Rules")))
	}
	return products, ruleCount
}

func workflowProductSetAndRefs(rows []map[string]interface{}) (map[string]string, []workflowRef) {
	products := map[string]string{}
	refs := []workflowRef{}
	for _, row := range rows {
		product := firstNonEmpty(mapString(row, "product", "Product"), mapString(row, "product_name", "ProductName"))
		if product == "" {
			continue
		}
		products[product] = product
		types := stringSliceFromAny(firstPresent(row, "type", "Type", "workflow_types", "WorkflowTypes"))
		pocs := stringSliceFromAny(firstPresent(row, "pocs", "Pocs", "workflow_pocs", "WorkflowPocs"))
		for _, pocName := range pocs {
			for _, matchType := range types {
				matchType = strings.ToLower(strings.TrimSpace(matchType))
				if pocName == "" || matchType == "" {
					continue
				}
				refs = append(refs, workflowRef{
					Product:      product,
					POCName:      pocName,
					MatchType:    matchType,
					WorkflowKind: workflowKind(product),
					SourceFile:   "workflow.yaml",
				})
			}
		}
	}
	return products, refs
}

func pocLookupSet(rows []map[string]interface{}) map[string]bool {
	out := map[string]bool{}
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		out[value] = true
		out[strings.TrimSuffix(value, ".yaml")] = true
		out[strings.TrimSuffix(value, ".yml")] = true
	}
	for _, row := range rows {
		add(mapString(row, "name", "Name"))
		add(mapString(row, "source_file", "SourceFile", "file_name", "FileName"))
	}
	return out
}

func relationshipMissingPOCRefs(refs []workflowRef, pocNames map[string]bool, productFilter, pocFilter string) []map[string]interface{} {
	items := []map[string]interface{}{}
	for _, ref := range refs {
		if productFilter != "" && !matchesFilter(ref.Product, productFilter) {
			continue
		}
		if pocFilter != "" && !matchesFilter(ref.POCName, pocFilter) {
			continue
		}
		if pocNames[ref.POCName] {
			continue
		}
		item := workflowRefItem(ref)
		item["type"] = "missing_poc_ref"
		item["severity"] = "high"
		item["message"] = "Workflow references a POC that is not present in native /poc-rules."
		items = append(items, item)
	}
	return items
}

func workflowRefItem(ref workflowRef) map[string]interface{} {
	return map[string]interface{}{
		"product_name":  ref.Product,
		"poc_name":      ref.POCName,
		"match_type":    ref.MatchType,
		"workflow_kind": ref.WorkflowKind,
		"source_file":   ref.SourceFile,
	}
}

func appendRelationshipProductItem(items []map[string]interface{}, product, itemType, productFilter, query string) []map[string]interface{} {
	if productFilter != "" && !matchesFilter(product, productFilter) {
		return items
	}
	item := map[string]interface{}{
		"type":          itemType,
		"product_name":  product,
		"workflow_kind": workflowKind(product),
	}
	if query != "" && !relationshipItemMatchesQuery(item, query) {
		return items
	}
	return append(items, item)
}

func filterRelationshipItems(items []map[string]interface{}, query string) []map[string]interface{} {
	if query == "" {
		return items
	}
	out := []map[string]interface{}{}
	for _, item := range items {
		if relationshipItemMatchesQuery(item, query) {
			out = append(out, item)
		}
	}
	return out
}

func relationshipItemMatchesQuery(item map[string]interface{}, query string) bool {
	if query == "" {
		return true
	}
	query = strings.ToLower(strings.TrimSpace(query))
	for _, key := range []string{"type", "product_name", "poc_name", "match_type", "workflow_kind", "source_file", "message"} {
		if strings.Contains(strings.ToLower(mapString(item, key)), query) {
			return true
		}
	}
	return false
}

func sortRelationshipItems(items []map[string]interface{}) {
	sort.SliceStable(items, func(i, j int) bool {
		left := strings.ToLower(mapString(items[i], "product_name")) + "|" + strings.ToLower(mapString(items[i], "poc_name")) + "|" + strings.ToLower(mapString(items[i], "match_type")) + "|" + strings.ToLower(mapString(items[i], "type"))
		right := strings.ToLower(mapString(items[j], "product_name")) + "|" + strings.ToLower(mapString(items[j], "poc_name")) + "|" + strings.ToLower(mapString(items[j], "match_type")) + "|" + strings.ToLower(mapString(items[j], "type"))
		return left < right
	})
}

func relationshipWindow(items []map[string]interface{}, start, end int) ([]map[string]interface{}, bool, int, int) {
	total := len(items)
	windowStart := start - 1
	if windowStart > total {
		windowStart = total
	}
	windowEnd := end
	if windowEnd > total {
		windowEnd = total
	}
	window := []map[string]interface{}{}
	if windowStart < windowEnd {
		window = items[windowStart:windowEnd]
	}
	hasMore := end < total
	nextStart := 0
	nextEnd := 0
	if hasMore {
		width := end - start + 1
		nextStart = end + 1
		nextEnd = nextStart + width - 1
		if nextEnd > total {
			nextEnd = total
		}
	}
	return window, hasMore, nextStart, nextEnd
}

func firstNStrings(items []string, limit int) []string {
	if limit < 0 {
		limit = 0
	}
	if len(items) <= limit {
		return items
	}
	return items[:limit]
}

func firstNMaps(items []map[string]interface{}, limit int) []map[string]interface{} {
	if limit < 0 {
		limit = 0
	}
	if len(items) <= limit {
		return items
	}
	return items[:limit]
}

func workflowRecommendations(productFilter, pocFilter string, fingerprints, pocs []map[string]interface{}, existing map[string]bool, limit int) []string {
	products := []string{}
	for _, item := range fingerprints {
		if product := mapString(item, "product_name"); product != "" {
			products = append(products, product)
		}
	}
	if productFilter != "" {
		products = append([]string{productFilter}, products...)
	}
	pocNames := []string{}
	for _, item := range pocs {
		if poc := firstNonEmpty(mapString(item, "source_file"), mapString(item, "name")); poc != "" {
			pocNames = append(pocNames, poc)
		}
	}
	if pocFilter != "" {
		pocNames = append([]string{pocFilter}, pocNames...)
	}
	out := []string{}
	seen := map[string]bool{}
	for _, product := range products {
		for _, poc := range pocNames {
			if len(out) >= limit {
				return out
			}
			key := strings.ToLower(product) + "|" + strings.ToLower(poc)
			if product == "" || poc == "" || seen[key] || existing[key] {
				continue
			}
			seen[key] = true
			out = append(out, fmt.Sprintf("Consider workflow product=%q poc=%q match_type=root.", product, poc))
		}
	}
	return out
}
