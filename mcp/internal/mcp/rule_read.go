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

const maxRuleGetContentBytes = 64 * 1024

func (c *Client) argusRuleGet(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	ruleType := normalizeRuleType(stringArg(args, "rule_type"))
	if ruleType == "" {
		return nil, fmt.Errorf("rule_type is required for action=rule_get")
	}
	fileName := stringArg(args, "file_name")
	artifactID := stringArg(args, "artifact_id")
	productName := stringArg(args, "product_name")
	if fileName == "" {
		switch ruleType {
		case "finger":
			fileName = "finger.yaml"
		case "workflow":
			fileName = "workflow.yaml"
		case "dir":
			fileName = "dir.yaml"
		}
	}
	if fileName == "" && artifactID == "" {
		return nil, fmt.Errorf("rule_get requires file_name or artifact_id")
	}

	found, err := c.resolveArsenal(ctx, ruleType, fileName, artifactID)
	if err != nil {
		return nil, err
	}
	content := found.Content
	contentSize := len(content)
	if contentSize == 0 && found.ContentSize > 0 {
		contentSize = found.ContentSize
	}

	out := map[string]interface{}{
		"status":           "success",
		"rule_type":        publicRuleType(ruleType),
		"file_name":        found.EffectiveFileName(),
		"artifact_id":      found.StableID(),
		"state":            found.State,
		"hash":             found.Hash,
		"version":          found.Version,
		"content_size":     contentSize,
		"content_included": false,
		"last_updated":     firstNonEmpty(found.UpdatedAt, found.CreatedAt),
		"stable_ref":       stableRefFromArsenal(found, publicRuleType(ruleType)),
	}

	names := dictProductNames(ruleType, content)
	if len(names) > 0 && productName == "" {
		start, end, paged, err := optionalStringRange(args, len(names))
		if err != nil {
			return nil, err
		}
		window := names
		if paged {
			if start > len(names) {
				window = []string{}
			} else {
				window = names[start-1 : end]
			}
			out["range_start"] = start
			out["range_end"] = end
			out["has_more"] = end < len(names)
		}
		out["product_count"] = len(names)
		out["returned"] = len(window)
		out["products"] = window
	}
	if ruleType == "poc" || ruleType == "active_fingerprint" {
		if id, name := nucleiIdentityFromContent(content); id != "" || name != "" {
			if id != "" {
				out["template_id"] = id
			}
			if name != "" {
				out["template_name"] = name
			}
		}
	}
	if productName != "" {
		out["product_name"] = productName
		if entry := productEntryFromContent(ruleType, content, productName); entry != nil {
			out["product_entry"] = entry
		} else {
			out["product_entry"] = map[string]interface{}{"product_name": productName, "found": false}
		}
	}

	if boolArg(args, "include_content") {
		if contentSize > maxRuleGetContentBytes {
			out["content_refused"] = fmt.Sprintf("YAML is %d bytes; include_content is capped at %d. Use products (name array), product_name for one mapping, or action=coverage for catalog stats.", contentSize, maxRuleGetContentBytes)
		} else {
			out["content"] = content
			out["content_included"] = true
		}
	} else if ruleType == "poc" || ruleType == "active_fingerprint" {
		out["content_preview"] = contentPreview(content, 280)
	}
	if _, ok := out["content"]; !ok {
		out["hint"] = "YAML omitted. Fingerprint/workflow/dir return products as a string array of names. POC returns template_id/template_name, not YAML keys. Pass product_name for one mapping or include_content=true for files under 64KiB."
	}
	return out, nil
}

func (c *Client) resolveArsenal(ctx context.Context, ruleType, fileName, artifactID string) (arsenalRecord, error) {
	if fileName != "" && artifactID == "" {
		row, err := c.loadArsenalFile(ctx, ruleType, fileName)
		if err != nil {
			return arsenalRecord{}, err
		}
		return row, nil
	}
	rows, err := c.loadArsenalRows(ctx, ruleType, true)
	if err != nil {
		return arsenalRecord{}, err
	}
	var found arsenalRecord
	foundOK := false
	for _, row := range rows {
		if artifactID != "" && row.StableID() == artifactID {
			found = row
			foundOK = true
			break
		}
		if fileName != "" && row.EffectiveFileName() == fileName {
			found = row
			foundOK = true
			break
		}
	}
	if !foundOK {
		return arsenalRecord{}, fmt.Errorf("rule not found for rule_type=%s file_name=%q artifact_id=%q", publicRuleType(ruleType), fileName, artifactID)
	}
	if found.Content != "" {
		return found, nil
	}
	name := found.EffectiveFileName()
	if name == "" {
		return arsenalRecord{}, fmt.Errorf("rule not found for rule_type=%s file_name=%q artifact_id=%q", publicRuleType(ruleType), fileName, artifactID)
	}
	row, err := c.loadArsenalFile(ctx, ruleType, name)
	if err != nil {
		return arsenalRecord{}, err
	}
	return row, nil
}

func (c *Client) loadArsenalFile(ctx context.Context, ruleType, fileName string) (arsenalRecord, error) {
	path := "/api/v1/arsenals/" + url.PathEscape(ruleType) + "/" + url.PathEscape(fileName)
	var row arsenalRecord
	if err := c.do(ctx, http.MethodGet, path, nil, &row); err != nil {
		return arsenalRecord{}, err
	}
	if row.EffectiveFileName() == "" && row.StableID() == "" {
		return arsenalRecord{}, fmt.Errorf("rule not found for rule_type=%s file_name=%q", publicRuleType(ruleType), fileName)
	}
	return row, nil
}

func (c *Client) argusRuleList(ctx context.Context, args map[string]interface{}, draftsOnly bool) (interface{}, error) {
	ruleTypes := []string{}
	if raw := normalizeRuleType(stringArg(args, "rule_type")); raw != "" {
		ruleTypes = append(ruleTypes, raw)
	} else {
		ruleTypes = []string{"finger", "active_fingerprint", "poc", "workflow", "dir"}
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
		for _, row := range rows {
			if state != "" && !strings.EqualFold(row.State, state) {
				continue
			}
			item := summarizeArsenalForList(row, ruleType)
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
	}, nil
}

func (c *Client) loadArsenalRows(ctx context.Context, ruleType string, lite bool) ([]arsenalRecord, error) {
	path := "/api/v1/arsenals/" + url.PathEscape(ruleType) + "?all=1"
	if lite {
		path += "&lite=1"
	}
	var rows []arsenalRecord
	if err := c.do(ctx, http.MethodGet, path, nil, &rows); err != nil {
		return nil, err
	}
	return rows, nil
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
	if hasArg(args, "range_start") && hasArg(args, "range_end") && end < start {
		return 0, 0, fmt.Errorf("range_end must be greater than or equal to range_start")
	}
	if end < start {
		end = start + 49
	}
	if end-start+1 > 200 {
		end = start + 199
	}
	return start, end, nil
}

func summarizeArsenalForList(row arsenalRecord, ruleType string) map[string]interface{} {
	content := row.Content
	contentSize := len(content)
	if contentSize == 0 && row.ContentSize > 0 {
		contentSize = row.ContentSize
	}
	item := map[string]interface{}{
		"rule_type":       publicRuleType(ruleType),
		"file_name":       row.EffectiveFileName(),
		"artifact_id":     row.StableID(),
		"state":           row.State,
		"hash":            row.Hash,
		"version":         row.Version,
		"content_size":    contentSize,
		"content_preview": contentPreview(content, 280),
		"updated_at":      row.UpdatedAt,
		"created_at":      row.CreatedAt,
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

func stableRefFromArsenal(row arsenalRecord, publicType string) map[string]interface{} {
	return map[string]interface{}{
		"artifact_id": row.StableID(),
		"file_name":   row.EffectiveFileName(),
		"hash":        row.Hash,
		"version":     row.Version,
		"rule_type":   publicType,
	}
}

type workflowEntry struct {
	Type      []string `yaml:"type"`
	Pocs      []string `yaml:"pocs"`
	RiskLevel string   `yaml:"risk_level"`
}

func dictProductNames(ruleType, content string) []string {
	switch ruleType {
	case "finger", "workflow", "dir":
		return yamlMappingKeys(content)
	default:
		return nil
	}
}

func nucleiIdentityFromContent(content string) (id, name string) {
	var doc struct {
		ID   string `yaml:"id"`
		Info struct {
			Name string `yaml:"name"`
		} `yaml:"info"`
	}
	if yaml.Unmarshal([]byte(content), &doc) != nil {
		return "", ""
	}
	return strings.TrimSpace(doc.ID), strings.TrimSpace(doc.Info.Name)
}

func yamlMappingKeys(content string) []string {
	if strings.TrimSpace(content) == "" {
		return nil
	}
	data := map[string]interface{}{}
	if yaml.Unmarshal([]byte(content), &data) != nil {
		return nil
	}
	names := make([]string, 0, len(data))
	for name := range data {
		if strings.TrimSpace(name) == "" {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func optionalStringRange(args map[string]interface{}, total int) (int, int, bool, error) {
	if !hasArg(args, "range_start") && !hasArg(args, "range_end") {
		return 0, 0, false, nil
	}
	start := intArgDefault(args, "range_start", 1)
	end := intArgDefault(args, "range_end", total)
	if start <= 0 {
		start = 1
	}
	if end <= 0 {
		end = total
	}
	if end < start {
		if total == 0 {
			return 1, 0, true, nil
		}
		return 0, 0, false, fmt.Errorf("range_end must be greater than or equal to range_start")
	}
	if start > total {
		return total + 1, total, true, nil
	}
	if end > total {
		end = total
	}
	return start, end, true, nil
}

func productEntryFromContent(ruleType, content, productName string) interface{} {
	if strings.TrimSpace(productName) == "" || strings.TrimSpace(content) == "" {
		return nil
	}
	switch ruleType {
	case "finger", "dir":
		data := map[string][]string{}
		if yaml.Unmarshal([]byte(content), &data) == nil {
			if rules, ok := data[productName]; ok {
				key := "rules"
				if ruleType == "dir" {
					key = "paths"
				}
				return map[string]interface{}{"product_name": productName, key: rules}
			}
		}
	case "workflow":
		data := map[string]workflowEntry{}
		if yaml.Unmarshal([]byte(content), &data) == nil {
			if entry, ok := data[productName]; ok {
				return map[string]interface{}{"product_name": productName, "workflow_types": entry.Type, "workflow_pocs": entry.Pocs, "risk_level": entry.RiskLevel}
			}
		}
	}
	return nil
}

func contentPreview(content string, maxLen int) string {
	content = strings.TrimSpace(content)
	if len(content) <= maxLen {
		return content
	}
	return strings.TrimSpace(content[:maxLen]) + "..."
}
