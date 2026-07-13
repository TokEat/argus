package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

func (c *Client) argusRuleGet(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	ruleType := normalizeRuleType(stringArg(args, "rule_type"))
	if ruleType == "" {
		return nil, fmt.Errorf("rule_type is required for action=rule_get")
	}
	fileName := stringArg(args, "file_name")
	artifactID := stringArg(args, "artifact_id")
	ruleID := stringArg(args, "rule_id")
	productName := stringArg(args, "product_name")
	if fileName == "" && ruleType == "finger" {
		fileName = "finger.yaml"
	}
	if fileName == "" && ruleType == "workflow" {
		fileName = "workflow.yaml"
	}
	if fileName == "" && artifactID == "" && ruleID == "" {
		return nil, fmt.Errorf("rule_get requires file_name, artifact_id or rule_id")
	}

	catalog, err := c.loadRuleCatalog(ctx, ruleType)
	if err != nil {
		return nil, err
	}
	if fileName == "" || artifactID == "" {
		for _, row := range catalog {
			if ruleID != "" && !catalogRowMatchesRuleID(row, ruleType, ruleID) {
				continue
			}
			if ruleID == "" && fileName != "" {
				rowFileName := mapString(row, "source_file", "SourceFile", "file_name", "FileName")
				if rowFileName != "" && rowFileName != fileName {
					continue
				}
			}
			if ruleID == "" && artifactID != "" {
				rowArtifactID := mapString(row, "artifact_id", "ArtifactID")
				if rowArtifactID != "" && rowArtifactID != artifactID {
					continue
				}
			}
			if fileName == "" {
				fileName = firstNonEmpty(mapString(row, "source_file", "SourceFile"), mapString(row, "file_name", "FileName"))
			}
			if artifactID == "" {
				artifactID = mapString(row, "artifact_id", "ArtifactID")
			}
			if fileName != "" || artifactID != "" {
				break
			}
		}
	}

	rows, err := c.loadArsenalRows(ctx, ruleType, false)
	if err != nil {
		return nil, err
	}
	var found map[string]interface{}
	for _, row := range rows {
		if artifactID != "" && mapString(row, "id", "ID", "artifact_id", "ArtifactID") == artifactID {
			found = row
			break
		}
		if fileName != "" && mapString(row, "file_name", "FileName", "source_file", "SourceFile") == fileName {
			found = row
			break
		}
	}
	if found == nil {
		return nil, fmt.Errorf("rule not found for rule_type=%s file_name=%q artifact_id=%q rule_id=%q", publicRuleType(ruleType), fileName, artifactID, ruleID)
	}
	fileName = mapString(found, "file_name", "FileName")
	artifactID = mapString(found, "id", "ID", "artifact_id", "ArtifactID")
	content := mapString(found, "content", "Content")
	catalogMatches := filterCatalogForArtifact(catalog, ruleType, artifactID, fileName, ruleID, productName)
	out := map[string]interface{}{
		"status":        "success",
		"source":        "native_api",
		"rule_type":     publicRuleType(ruleType),
		"file_name":     fileName,
		"artifact_id":   artifactID,
		"state":         mapString(found, "state", "State"),
		"hash":          mapString(found, "hash", "Hash"),
		"version":       firstPresent(found, "version", "Version"),
		"content":       content,
		"content_size":  len(content),
		"catalog":       catalogMatches,
		"references":    c.ruleReferences(ctx, ruleType, fileName, productName, catalogMatches),
		"mcp_guidance":  ruleGetGuidance(publicRuleType(ruleType)),
		"last_updated":  firstNonEmpty(mapString(found, "updated_at", "UpdatedAt"), mapString(found, "created_at", "CreatedAt")),
		"stable_ref":    stableRefFromArsenal(found, publicRuleType(ruleType)),
		"product_entry": productEntryFromContent(ruleType, content, productName),
	}
	return out, nil
}

func (c *Client) argusRuleList(ctx context.Context, args map[string]interface{}, draftsOnly bool) (interface{}, error) {
	ruleTypes := []string{}
	if raw := normalizeRuleType(stringArg(args, "rule_type")); raw != "" {
		ruleTypes = append(ruleTypes, raw)
	} else {
		ruleTypes = []string{"finger", "poc", "workflow", "exp"}
	}
	state := stringArg(args, "state")
	if draftsOnly {
		state = "Draft"
	}
	query := strings.ToLower(strings.TrimSpace(stringArg(args, "query")))
	start, end, err := normalizeRuleListRange(args)
	if err != nil {
		return nil, err
	}
	items := []map[string]interface{}{}
	for _, ruleType := range ruleTypes {
		rows, err := c.loadArsenalRows(ctx, ruleType, true)
		if err != nil {
			return nil, err
		}
		catalog, _ := c.loadRuleCatalog(ctx, ruleType)
		for _, row := range rows {
			if state != "" && !strings.EqualFold(mapString(row, "state", "State"), state) {
				continue
			}
			item := summarizeArsenalForList(row, ruleType, catalog)
			if query != "" && !ruleListItemMatchesQuery(item, query) {
				continue
			}
			items = append(items, item)
		}
	}
	sortRuleListItems(items)
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
	return map[string]interface{}{
		"status":           "success",
		"source":           "native_api",
		"action":           map[bool]string{true: "drafts", false: "rule_list"}[draftsOnly],
		"rule_type":        publicRuleTypeForList(ruleTypes),
		"state":            state,
		"query":            query,
		"total":            total,
		"range_start":      start,
		"range_end":        end,
		"returned":         len(window),
		"has_more":         hasMore,
		"next_range_start": nextStart,
		"next_range_end":   nextEnd,
		"list_snapshot":    time.Now().UTC().Format(time.RFC3339),
		"items":            window,
		"mcp_guidance":     ruleListGuidance(draftsOnly),
	}, nil
}

func (c *Client) loadArsenalContent(ctx context.Context, ruleType, fileName string) (string, error) {
	var rows []map[string]interface{}
	if err := c.do(ctx, http.MethodGet, "/api/v1/arsenals/"+url.PathEscape(ruleType)+"?all=1", nil, &rows); err != nil {
		return "", err
	}
	for _, row := range rows {
		if mapString(row, "file_name", "FileName") == fileName {
			return mapString(row, "content", "Content"), nil
		}
	}
	return "", nil
}

func (c *Client) loadArsenalRows(ctx context.Context, ruleType string, lite bool) ([]map[string]interface{}, error) {
	path := "/api/v1/arsenals/" + url.PathEscape(ruleType) + "?all=1"
	if lite {
		path += "&lite=1"
	}
	var rows []map[string]interface{}
	if err := c.do(ctx, http.MethodGet, path, nil, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func (c *Client) loadRuleCatalog(ctx context.Context, ruleType string) ([]map[string]interface{}, error) {
	switch ruleType {
	case "poc":
		var rows []map[string]interface{}
		return rows, c.do(ctx, http.MethodGet, "/api/v1/poc-rules?all=1", nil, &rows)
	case "exp":
		var rows []map[string]interface{}
		return rows, c.do(ctx, http.MethodGet, "/api/v1/exploits?all=1", nil, &rows)
	case "finger":
		var rows []map[string]interface{}
		return rows, c.do(ctx, http.MethodGet, "/api/v1/dictionaries/fingerprint", nil, &rows)
	case "workflow":
		var rows []map[string]interface{}
		return rows, c.do(ctx, http.MethodGet, "/api/v1/dictionaries/workflow", nil, &rows)
	default:
		return nil, nil
	}
}

func normalizeRuleListRange(args map[string]interface{}) (int, int, error) {
	start := intArgDefault(args, "range_start", 1)
	end := intArgDefault(args, "range_end", 50)
	if start <= 0 {
		start = 1
	}
	if end <= 0 {
		end = start + 49
	}
	if end < start {
		return 0, 0, fmt.Errorf("range_end must be greater than or equal to range_start")
	}
	if end-start+1 > 200 {
		end = start + 199
	}
	return start, end, nil
}

func summarizeArsenalForList(row map[string]interface{}, ruleType string, catalog []map[string]interface{}) map[string]interface{} {
	content := mapString(row, "content", "Content")
	contentSize := len(content)
	if contentSize == 0 {
		if size, ok := intFromAny(firstPresent(row, "content_size", "ContentSize")); ok {
			contentSize = size
		}
	}
	fileName := mapString(row, "file_name", "FileName")
	artifactID := mapString(row, "id", "ID", "artifact_id", "ArtifactID")
	summary := filterCatalogForArtifact(catalog, ruleType, artifactID, fileName, "", "")
	item := map[string]interface{}{
		"rule_type":       publicRuleType(ruleType),
		"file_name":       fileName,
		"artifact_id":     artifactID,
		"state":           mapString(row, "state", "State"),
		"hash":            mapString(row, "hash", "Hash"),
		"version":         firstPresent(row, "version", "Version"),
		"content_size":    contentSize,
		"content_preview": contentPreview(content, 280),
		"catalog_summary": summary,
		"updated_at":      mapString(row, "updated_at", "UpdatedAt"),
		"created_at":      mapString(row, "created_at", "CreatedAt"),
	}
	if item["updated_at"] == "" {
		item["updated_at"] = item["created_at"]
	}
	return item
}

func ruleListItemMatchesQuery(item map[string]interface{}, query string) bool {
	if query == "" {
		return true
	}
	blob, _ := json.Marshal(item)
	return strings.Contains(strings.ToLower(string(blob)), query)
}

func sortRuleListItems(items []map[string]interface{}) {
	sort.SliceStable(items, func(i, j int) bool {
		leftUpdated := mapString(items[i], "updated_at")
		rightUpdated := mapString(items[j], "updated_at")
		if leftUpdated != rightUpdated {
			return leftUpdated > rightUpdated
		}
		leftFile := mapString(items[i], "file_name")
		rightFile := mapString(items[j], "file_name")
		if leftFile != rightFile {
			return leftFile < rightFile
		}
		return mapString(items[i], "artifact_id") < mapString(items[j], "artifact_id")
	})
}

func publicRuleTypeForList(ruleTypes []string) interface{} {
	if len(ruleTypes) == 1 {
		return publicRuleType(ruleTypes[0])
	}
	out := make([]string, 0, len(ruleTypes))
	for _, ruleType := range ruleTypes {
		out = append(out, publicRuleType(ruleType))
	}
	return out
}

func catalogRowMatchesRuleID(row map[string]interface{}, ruleType, ruleID string) bool {
	if ruleID == "" {
		return true
	}
	switch ruleType {
	case "exp":
		return mapString(row, "rule_id", "RuleID") == ruleID
	case "poc":
		return mapString(row, "name", "Name") == ruleID || mapString(row, "source_file", "SourceFile") == ruleID
	case "finger", "workflow":
		return mapString(row, "product", "Product", "product_name", "ProductName") == ruleID
	default:
		return false
	}
}

func filterCatalogForArtifact(catalog []map[string]interface{}, ruleType, artifactID, fileName, ruleID, productName string) []map[string]interface{} {
	out := []map[string]interface{}{}
	for _, row := range catalog {
		if artifactID != "" {
			if got := mapString(row, "artifact_id", "ArtifactID"); got != "" && got == artifactID {
				out = append(out, row)
				continue
			}
		}
		if fileName != "" {
			if got := mapString(row, "source_file", "SourceFile", "file_name", "FileName"); got != "" && got == fileName {
				out = append(out, row)
				continue
			}
		}
		if ruleID != "" && catalogRowMatchesRuleID(row, ruleType, ruleID) {
			out = append(out, row)
			continue
		}
		if productName != "" && mapString(row, "product", "Product", "product_name", "ProductName") == productName {
			out = append(out, row)
			continue
		}
	}
	return out
}

func stableRefFromArsenal(row map[string]interface{}, publicType string) map[string]interface{} {
	return map[string]interface{}{
		"artifact_id": mapString(row, "id", "ID", "artifact_id", "ArtifactID"),
		"file_name":   mapString(row, "file_name", "FileName"),
		"hash":        mapString(row, "hash", "Hash"),
		"version":     firstPresent(row, "version", "Version"),
		"rule_type":   publicType,
	}
}

func productEntryFromContent(ruleType, content, productName string) interface{} {
	if strings.TrimSpace(productName) == "" || strings.TrimSpace(content) == "" {
		return nil
	}
	switch ruleType {
	case "finger":
		data := map[string][]string{}
		if yaml.Unmarshal([]byte(content), &data) == nil {
			if rules, ok := data[productName]; ok {
				return map[string]interface{}{"product_name": productName, "rules": rules}
			}
		}
	case "workflow":
		data := map[string]workflowEntry{}
		if yaml.Unmarshal([]byte(content), &data) == nil {
			if entry, ok := data[productName]; ok {
				return map[string]interface{}{"product_name": productName, "workflow_types": entry.Type, "workflow_pocs": entry.Pocs}
			}
		}
	}
	return nil
}

func (c *Client) ruleReferences(ctx context.Context, ruleType, fileName, productName string, catalog []map[string]interface{}) map[string]interface{} {
	refs := map[string]interface{}{}
	workflows, err := c.loadRuleCatalog(ctx, "workflow")
	if err == nil {
		switch ruleType {
		case "poc":
			matches := []map[string]interface{}{}
			for _, wf := range workflows {
				for _, poc := range stringSliceFromAny(firstPresent(wf, "pocs", "Pocs", "workflow_pocs", "WorkflowPocs")) {
					if poc == fileName || strings.TrimSuffix(poc, ".yaml") == strings.TrimSuffix(fileName, ".yaml") {
						matches = append(matches, wf)
						break
					}
				}
			}
			refs["workflows"] = matches
		case "finger", "workflow":
			if productName != "" {
				matches := []map[string]interface{}{}
				for _, wf := range workflows {
					if mapString(wf, "product", "Product", "product_name", "ProductName") == productName {
						matches = append(matches, wf)
					}
				}
				refs["workflows"] = matches
			}
		}
	}
	if ruleType == "exp" && len(catalog) > 0 {
		refs["linked_pocs"] = firstPresent(catalog[0], "linked_pocs", "LinkedPocs")
	}
	return refs
}

func ruleGetGuidance(ruleType string) map[string]interface{} {
	return map[string]interface{}{
		"next_steps": []string{"use this content/hash/version as the source of truth before editing", "after modifying content call argus_rule_save", "publish with argus_rule_apply using the returned hash/version"},
		"warnings":   []string{"argus_product_search is fuzzy; rule_get is the exact read path before save/publish"},
		"rule_type":  ruleType,
	}
}

func ruleListGuidance(draftsOnly bool) map[string]interface{} {
	next := []string{"if the desired rule is not in this range, call again with next_range_start and next_range_end", "call argus_context action=rule_get before editing any listed item"}
	if draftsOnly {
		next = append([]string{"review existing Drafts before saving to avoid overwriting unreviewed work"}, next...)
	}
	return map[string]interface{}{
		"next_steps": next,
		"warnings":   []string{"rule_list and drafts are exact range lists, not fuzzy product search; use argus_product_search for fuzzy discovery"},
	}
}

func contentPreview(content string, maxLen int) string {
	content = strings.TrimSpace(content)
	if len(content) <= maxLen {
		return content
	}
	return strings.TrimSpace(content[:maxLen]) + "..."
}
