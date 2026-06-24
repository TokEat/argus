package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"
)

type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

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

func NewClient(baseURL, token string) *Client {
	return &Client{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		token:   strings.TrimSpace(token),
		http:    &http.Client{Timeout: 5 * time.Minute},
	}
}

func (c *Client) Resource(ctx context.Context, uri string) (resourcePayload, error) {
	endpoint, ok := resourceEndpoints[uri]
	if !ok {
		return resourcePayload{}, fmt.Errorf("unknown resource uri %q", uri)
	}
	var payload resourcePayload
	if err := c.do(ctx, http.MethodGet, endpoint, nil, &payload); err != nil {
		return resourcePayload{}, err
	}
	return payload, nil
}

func (c *Client) CallTool(ctx context.Context, name string, args map[string]interface{}) (interface{}, error) {
	switch name {
	case "argus_context":
		return c.argusContext(ctx, args)
	case "argus_product_search":
		return c.argusProductSearch(ctx, args)
	case "argus_rule_debug":
		return c.argusRuleDebug(ctx, args)
	case "argus_rule_save":
		return c.argusRuleSave(ctx, args)
	case "argus_rule_apply":
		return c.argusRuleApply(ctx, args)
	default:
		return nil, fmt.Errorf("unknown tool %q", name)
	}
}

func (c *Client) argusRuleDebug(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	ruleType := normalizeRuleType(stringArg(args, "rule_type"))
	if ruleType != "exp" {
		// Fingerprint and POC native debug endpoints currently start an async
		// session only; keep the compatibility path for synchronous transcripts.
		return c.postTool(ctx, "/api/v1/mcp/tools/rule/debug", args)
	}
	source := stringArg(args, "source")
	if source == "" {
		source = stringArg(args, "content")
	}
	if source == "" {
		source = stringArg(args, "poc_content")
	}
	if source != "" {
		action := strings.ToLower(strings.TrimSpace(stringArg(args, "action")))
		if action == "dry_run" {
			body := map[string]interface{}{
				"source": source,
				"target": firstNonEmptyString(stringArg(args, "target"), stringArg(args, "target_url")),
				"params": args["params"],
			}
			var out map[string]interface{}
			if err := c.do(ctx, http.MethodPost, "/api/v1/exploits/source/dry-run", body, &out); err != nil {
				return nil, err
			}
			out["rule_type"] = "pyexp"
			out["source_level"] = true
			out["dry_run"] = true
			if _, ok := out["rule_id"]; !ok {
				if exploitID, ok := out["exploit_id"]; ok {
					out["rule_id"] = exploitID
				}
			}
			out["mcp_guidance"] = map[string]interface{}{
				"next_steps": []string{"if params_valid is true, run source-level debug against an online Agent", "save a Draft only after source-level debug succeeds"},
				"warnings":   []string{"dry_run does not save or publish artifacts", "dry_run does not execute Python or check installed Agent dependencies"},
			}
			return out, nil
		}
		body := copyArgs(args)
		body["source"] = source
		body["rule_type"] = "pyexp"
		var out map[string]interface{}
		if err := c.do(ctx, http.MethodPost, "/api/v1/exploits/source/debug", body, &out); err != nil {
			return nil, err
		}
		out["rule_type"] = "pyexp"
		out["source_level"] = true
		return out, nil
	}
	ruleID, err := c.resolveExploitRuleID(ctx, args)
	if err != nil {
		return nil, err
	}
	body := map[string]interface{}{
		"agent_id":   args["agent_id"],
		"target_url": args["target_url"],
		"params":     args["params"],
		"proxy":      args["proxy"],
		"action":     args["action"],
	}
	if timeout, ok := args["timeout_sec"]; ok {
		body["timeout_sec"] = timeout
	}
	var out map[string]interface{}
	if err := c.do(ctx, http.MethodPost, "/api/v1/exploits/"+url.PathEscape(fmt.Sprint(ruleID))+"/debug", body, &out); err != nil {
		return nil, err
	}
	out["rule_type"] = "pyexp"
	return stripLegacyExploitRef(withStableRef(out, ruleType, stringArg(args, "file_name"))), nil
}

func (c *Client) argusContext(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	switch stringArg(args, "action") {
	case "resources":
		items := make([]map[string]interface{}, 0, len(resourceEndpoints))
		for _, resource := range resources() {
			items = append(items, map[string]interface{}{
				"uri":         resource.URI,
				"name":        resource.Name,
				"mime_type":   resource.MIMEType,
				"description": resource.Description,
			})
		}
		return map[string]interface{}{
			"status":                 "success",
			"resources":              items,
			"recommended_read_order": []string{"argus://argus-mcp/quickstart", "argus://argus-mcp/tool-guide", "argus://fingerprint/spec", "argus://poc/spec", "argus://workflow/spec", "argus://pyexp/spec"},
		}, nil
	case "quickstart":
		return c.Resource(ctx, "argus://argus-mcp/quickstart")
	case "lifecycle_policy":
		return c.postTool(ctx, "/api/v1/mcp/tools/rule/context", args)
	case "resource":
		uri := stringArg(args, "uri")
		if uri == "" {
			return nil, fmt.Errorf("uri is required for action=resource")
		}
		return c.Resource(ctx, uri)
	case "agents":
		var out interface{}
		err := c.do(ctx, http.MethodGet, "/api/v1/nodes", nil, &out)
		return out, err
	case "agent_pyenv":
		agentID := stringArg(args, "agent_id")
		if agentID == "" {
			return nil, fmt.Errorf("agent_id is required for action=agent_pyenv")
		}
		var out interface{}
		err := c.do(ctx, http.MethodGet, "/api/v1/agents/"+url.PathEscape(agentID)+"/pyenv", nil, &out)
		return out, err
	case "rule_get":
		return c.argusRuleGet(ctx, args)
	case "rule_list":
		return c.argusRuleList(ctx, args, false)
	case "drafts":
		return c.argusRuleList(ctx, args, true)
	case "relationship_stats":
		return c.argusRelationshipStats(ctx, args)
	case "relationship_list":
		return c.argusRelationshipList(ctx, args)
	case "workflow_links", "workflow_recommend", "workflow_conflicts":
		return c.argusWorkflowContext(ctx, args)
	default:
		return nil, fmt.Errorf("unsupported argus_context action %q", stringArg(args, "action"))
	}
}

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

type productSearchAsset struct {
	Name        string
	SourceFile  string
	Target      string
	State       string
	Severity    string
	Kind        string
	Description string
	Tags        string
}

type productSearchBucket struct {
	Name        string
	Fingerprint []map[string]interface{}
	Workflows   []map[string]interface{}
	POCs        []map[string]interface{}
	EXPs        []map[string]interface{}
	SearchText  []string
	Evidence    map[string]bool
}

func (c *Client) argusProductSearch(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	query := stringArg(args, "query")
	if query == "" {
		query = firstNonEmpty(stringArg(args, "product_name"), stringArg(args, "poc_name"))
	}
	if query == "" {
		return nil, fmt.Errorf("query is required for action=product_search")
	}
	limit := intArgDefault(args, "limit", 20)
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	var fingerprints []map[string]interface{}
	if err := c.do(ctx, http.MethodGet, "/api/v1/dictionaries/fingerprint", nil, &fingerprints); err != nil {
		return nil, err
	}
	var workflows []map[string]interface{}
	if err := c.do(ctx, http.MethodGet, "/api/v1/dictionaries/workflow", nil, &workflows); err != nil {
		return nil, err
	}
	var pocs []map[string]interface{}
	if err := c.do(ctx, http.MethodGet, "/api/v1/poc-rules?all=1", nil, &pocs); err != nil {
		return nil, err
	}
	var exps []map[string]interface{}
	if err := c.do(ctx, http.MethodGet, "/api/v1/exploits?all=1", nil, &exps); err != nil {
		return nil, err
	}

	buckets := map[string]*productSearchBucket{}
	bucket := func(product string) *productSearchBucket {
		product = strings.TrimSpace(product)
		if product == "" {
			product = "(unmapped)"
		}
		key := strings.ToLower(product)
		if buckets[key] == nil {
			buckets[key] = &productSearchBucket{Name: product, Evidence: map[string]bool{}}
		}
		return buckets[key]
	}

	for _, fp := range fingerprints {
		product := mapString(fp, "product", "Product", "product_name", "ProductName")
		if product == "" {
			continue
		}
		b := bucket(product)
		rules := stringSliceFromAny(firstPresent(fp, "rules", "Rules"))
		b.Fingerprint = append(b.Fingerprint, map[string]interface{}{"product_name": product, "rules": rules})
		b.SearchText = append(b.SearchText, product)
		b.SearchText = append(b.SearchText, rules...)
	}

	pocByName := map[string]map[string]interface{}{}
	for _, poc := range pocs {
		name := firstNonEmpty(mapString(poc, "name", "Name"), mapString(poc, "source_file", "SourceFile"))
		sourceFile := mapString(poc, "source_file", "SourceFile")
		targetProduct := mapString(poc, "target_product", "TargetProduct")
		if sourceFile != "" {
			pocByName[strings.ToLower(sourceFile)] = poc
		}
		if name != "" {
			pocByName[strings.ToLower(name)] = poc
		}
		if targetProduct != "" {
			item := productSearchPOCItem(poc)
			b := bucket(targetProduct)
			b.POCs = appendLimited(b.POCs, item, 50)
			b.SearchText = append(b.SearchText, targetProduct, name, sourceFile, mapString(poc, "tags", "Tags"), mapString(poc, "description", "Description"), mapString(poc, "cve", "CVE"))
			b.Evidence["poc_target_product"] = true
		}
	}

	for _, wf := range workflows {
		product := mapString(wf, "product", "Product", "product_name", "ProductName")
		if product == "" {
			continue
		}
		types := stringSliceFromAny(firstPresent(wf, "type", "Type", "workflow_types", "WorkflowTypes"))
		pocNames := stringSliceFromAny(firstPresent(wf, "pocs", "Pocs", "workflow_pocs", "WorkflowPocs"))
		b := bucket(product)
		b.Workflows = appendLimited(b.Workflows, map[string]interface{}{
			"product_name":  product,
			"match_types":   types,
			"pocs":          pocNames,
			"source_file":   "workflow.yaml",
			"workflow_kind": workflowKind(product),
		}, 50)
		b.SearchText = append(b.SearchText, product)
		b.SearchText = append(b.SearchText, types...)
		b.SearchText = append(b.SearchText, pocNames...)
		if isGeneralPOCWorkflowProduct(product) {
			b.Evidence["general_poc_workflow"] = true
		}
		for _, pocName := range pocNames {
			if poc, ok := pocByName[strings.ToLower(pocName)]; ok {
				item := productSearchPOCItem(poc)
				b.POCs = appendLimited(b.POCs, item, 50)
				b.SearchText = append(b.SearchText, mapString(poc, "name", "Name"), mapString(poc, "source_file", "SourceFile"), mapString(poc, "tags", "Tags"), mapString(poc, "description", "Description"), mapString(poc, "cve", "CVE"))
				b.Evidence["workflow_linked_poc"] = true
			}
		}
	}

	for _, exp := range exps {
		product := mapString(exp, "target_product", "TargetProduct")
		if product == "" {
			continue
		}
		item := map[string]interface{}{
			"rule_id":      mapString(exp, "rule_id", "RuleID"),
			"name":         mapString(exp, "name", "Name"),
			"source_file":  mapString(exp, "source_file", "SourceFile"),
			"risk_level":   mapString(exp, "risk_level", "RiskLevel"),
			"state":        mapString(exp, "state", "State"),
			"enabled":      mapBool(exp, "enabled", "Enabled"),
			"linked_pocs":  firstPresent(exp, "linked_pocs", "LinkedPocs"),
			"artifact_id":  mapString(exp, "artifact_id", "ArtifactID"),
			"content_hash": mapString(exp, "content_hash", "ContentHash"),
			"requirements": firstPresent(exp, "requirements", "Requirements"),
		}
		b := bucket(product)
		b.EXPs = appendLimited(b.EXPs, item, 50)
		b.SearchText = append(b.SearchText, product, mapString(exp, "rule_id", "RuleID"), mapString(exp, "name", "Name"), mapString(exp, "source_file", "SourceFile"), mapString(exp, "description", "Description"))
		b.Evidence["exp_target_product"] = true
	}

	type scoredBucket struct {
		bucket *productSearchBucket
		score  float64
		reason []string
	}
	scored := []scoredBucket{}
	for _, b := range buckets {
		score, reason := scoreProductSearchBucket(query, b)
		if score <= 0 {
			continue
		}
		scored = append(scored, scoredBucket{bucket: b, score: score, reason: reason})
	}
	sort.Slice(scored, func(i, j int) bool {
		if scored[i].score == scored[j].score {
			return scored[i].bucket.Name < scored[j].bucket.Name
		}
		return scored[i].score > scored[j].score
	})
	if len(scored) > limit {
		scored = scored[:limit]
	}

	matches := make([]map[string]interface{}, 0, len(scored))
	for _, item := range scored {
		b := item.bucket
		evidence := item.reason
		for key := range b.Evidence {
			evidence = append(evidence, key)
		}
		sort.Strings(evidence)
		matches = append(matches, map[string]interface{}{
			"name":              b.Name,
			"workflow_kind":     workflowKind(b.Name),
			"score":             math.Round(item.score*1000) / 1000,
			"sources":           productSearchSources(b),
			"fingerprint_count": len(b.Fingerprint),
			"workflow_count":    len(b.Workflows),
			"poc_count":         len(b.POCs),
			"exp_count":         len(b.EXPs),
			"fingerprints":      b.Fingerprint,
			"workflows":         b.Workflows,
			"pocs":              b.POCs,
			"exps":              b.EXPs,
			"evidence":          uniqueStrings(evidence),
			"canonical_hint":    b.Name,
			"merge_safety_hint": mergeSafetyHint(b.Name),
		})
	}
	return map[string]interface{}{"status": "success", "source": "native_api", "query": query, "limit": limit, "matches": matches}, nil
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

	var fingerprints []map[string]interface{}
	if err := c.do(ctx, http.MethodGet, "/api/v1/dictionaries/fingerprint", nil, &fingerprints); err != nil {
		return nil, err
	}
	var workflows []map[string]interface{}
	if err := c.do(ctx, http.MethodGet, "/api/v1/dictionaries/workflow", nil, &workflows); err != nil {
		return nil, err
	}
	var pocs []map[string]interface{}
	if err := c.do(ctx, http.MethodGet, "/api/v1/poc-rules?all=1", nil, &pocs); err != nil {
		return nil, err
	}

	products := map[string]bool{}
	fingerprintItems := []map[string]interface{}{}
	for _, item := range fingerprints {
		product := mapString(item, "product", "Product", "product_name", "ProductName")
		if product == "" || !matchesFilter(product, productFilter) {
			continue
		}
		products[strings.ToLower(product)] = true
		fingerprintItems = appendLimited(fingerprintItems, map[string]interface{}{
			"product_name": product,
			"rules":        item["rules"],
		}, limit)
	}

	pocByName := map[string]map[string]interface{}{}
	pocItems := []map[string]interface{}{}
	for _, poc := range pocs {
		name := firstNonEmpty(mapString(poc, "name", "Name"), mapString(poc, "source_file", "SourceFile"))
		sourceFile := mapString(poc, "source_file", "SourceFile")
		if name == "" && sourceFile == "" {
			continue
		}
		if sourceFile != "" {
			pocByName[strings.ToLower(sourceFile)] = poc
		}
		if name != "" {
			pocByName[strings.ToLower(name)] = poc
		}
		if !matchesFilter(name, pocFilter) && !matchesFilter(sourceFile, pocFilter) {
			continue
		}
		pocItems = appendLimited(pocItems, map[string]interface{}{
			"name":        name,
			"source_file": sourceFile,
			"severity":    mapString(poc, "severity", "Severity"),
			"state":       mapString(poc, "state", "State"),
			"enabled":     mapBool(poc, "enabled", "Enabled"),
		}, limit)
	}

	workflowItems := []map[string]interface{}{}
	conflicts := []map[string]interface{}{}
	existing := map[string]bool{}
	for _, workflow := range workflows {
		product := mapString(workflow, "product", "Product", "product_name", "ProductName")
		types := stringSliceFromAny(firstPresent(workflow, "type", "Type", "workflow_types", "WorkflowTypes"))
		pocNames := stringSliceFromAny(firstPresent(workflow, "pocs", "Pocs", "workflow_pocs", "WorkflowPocs"))
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

func (c *Client) argusRuleSave(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	ruleType := normalizeRuleType(stringArg(args, "rule_type"))
	fileName := stringArg(args, "file_name")
	content := stringArg(args, "content")
	if ruleType == "" {
		return nil, fmt.Errorf("rule_type is required")
	}
	switch ruleType {
	case "poc", "exp", "finger", "workflow":
	default:
		return nil, fmt.Errorf("unsupported rule_type %q", stringArg(args, "rule_type"))
	}
	if fileName == "" {
		switch ruleType {
		case "finger":
			fileName = "finger.yaml"
		case "workflow":
			fileName = "workflow.yaml"
		default:
			return nil, fmt.Errorf("file_name is required for %s save", publicRuleType(ruleType))
		}
	}
	if content == "" {
		var err error
		switch ruleType {
		case "finger":
			content, err = c.composeFingerprintArtifact(ctx, args)
		case "workflow":
			content, err = c.composeWorkflowArtifact(ctx, args)
		default:
			return nil, fmt.Errorf("content is required for %s save", publicRuleType(ruleType))
		}
		if err != nil {
			return nil, err
		}
	}
	var out map[string]interface{}
	if err := c.do(ctx, http.MethodPost, "/api/v1/arsenals/"+url.PathEscape(ruleType)+"/"+url.PathEscape(fileName), map[string]interface{}{"content": content}, &out); err != nil {
		return nil, err
	}
	if ruleType == "exp" {
		c.enrichSavedPyexp(ctx, out, fileName)
	}
	return withStableRef(out, ruleType, fileName), nil
}

func (c *Client) enrichSavedPyexp(ctx context.Context, out map[string]interface{}, fileName string) {
	var rules []map[string]interface{}
	if err := c.do(ctx, http.MethodGet, "/api/v1/exploits?all=1", nil, &rules); err != nil {
		return
	}
	for _, rule := range rules {
		if mapString(rule, "source_file", "SourceFile", "file_name", "FileName") != fileName {
			continue
		}
		for _, key := range []string{"artifact_id", "rule_id", "requirements_hash", "requirements", "state"} {
			if value := mapAny(rule, key); value != nil {
				out[key] = value
			}
		}
		if value := mapAny(rule, "content_hash"); value != nil {
			out["hash"] = value
		}
		if value := mapAny(rule, "version"); value != nil {
			out["version"] = value
		}
		return
	}
}

func (c *Client) composeFingerprintArtifact(ctx context.Context, args map[string]interface{}) (string, error) {
	productName := stringArg(args, "product_name")
	rules := stringSliceArg(args, "rules")
	if productName == "" || len(rules) == 0 {
		return "", fmt.Errorf("product_name and rules are required for fingerprint save")
	}
	content, err := c.loadArsenalContent(ctx, "finger", "finger.yaml")
	if err != nil {
		return "", err
	}
	data := map[string][]string{}
	if strings.TrimSpace(content) != "" {
		if err := yaml.Unmarshal([]byte(content), &data); err != nil {
			return "", fmt.Errorf("parse existing finger.yaml: %w", err)
		}
	}
	data[productName] = rules
	out, err := yaml.Marshal(data)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

type workflowEntry struct {
	Type []string `yaml:"type" json:"type"`
	Pocs []string `yaml:"pocs" json:"pocs"`
}

func (c *Client) composeWorkflowArtifact(ctx context.Context, args map[string]interface{}) (string, error) {
	productName := stringArg(args, "product_name")
	types := stringSliceArg(args, "workflow_types")
	pocs := stringSliceArg(args, "workflow_pocs")
	if productName == "" || len(types) == 0 || len(pocs) == 0 {
		return "", fmt.Errorf("product_name, workflow_types and workflow_pocs are required for workflow save")
	}
	content, err := c.loadArsenalContent(ctx, "workflow", "workflow.yaml")
	if err != nil {
		return "", err
	}
	data := map[string]workflowEntry{}
	if strings.TrimSpace(content) != "" {
		if err := yaml.Unmarshal([]byte(content), &data); err != nil {
			return "", fmt.Errorf("parse existing workflow.yaml: %w", err)
		}
	}
	data[productName] = workflowEntry{Type: types, Pocs: pocs}
	out, err := yaml.Marshal(data)
	if err != nil {
		return "", err
	}
	return string(out), nil
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

func (c *Client) argusRuleApply(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	action := stringArg(args, "action")
	ruleType := normalizeRuleType(stringArg(args, "rule_type"))
	switch action {
	case "publish":
		return c.argusRulePublish(ctx, ruleType, args)
	case "install_requirements":
		if ruleType != "exp" {
			return nil, fmt.Errorf("install_requirements only supports pyexp")
		}
		agentID := stringArg(args, "agent_id")
		if agentID == "" {
			return nil, fmt.Errorf("agent_id is required")
		}
		ruleID, err := c.resolveExploitRuleID(ctx, args)
		if err != nil {
			return nil, err
		}
		out, err := c.postTool(ctx, "/api/v1/agents/"+url.PathEscape(agentID)+"/pyenv/install", map[string]interface{}{"exploit_rule_id": ruleID})
		if err != nil {
			return nil, err
		}
		if mapped, ok := out.(map[string]interface{}); ok {
			return stripLegacyExploitRef(mapped), nil
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported argus_rule_apply action %q", action)
	}
}

func (c *Client) argusRulePublish(ctx context.Context, ruleType string, args map[string]interface{}) (interface{}, error) {
	if ruleType == "" {
		return nil, fmt.Errorf("rule_type is required")
	}
	if ruleType == "exp" {
		ruleID, err := c.resolveExploitRuleID(ctx, args)
		if err != nil {
			return nil, err
		}
		var out map[string]interface{}
		if err := c.do(ctx, http.MethodPost, "/api/v1/exploits/"+url.PathEscape(fmt.Sprint(ruleID))+"/approve", nil, &out); err != nil {
			return nil, err
		}
		out["rule_type"] = "pyexp"
		return stripLegacyExploitRef(withStableRef(out, ruleType, stringArg(args, "file_name"))), nil
	}
	fileName := stringArg(args, "file_name")
	if fileName == "" {
		switch ruleType {
		case "finger":
			fileName = "finger.yaml"
		case "workflow":
			fileName = "workflow.yaml"
		default:
			return nil, fmt.Errorf("file_name is required for %s publish", publicRuleType(ruleType))
		}
	}
	if err := c.ensureArtifactFresh(ctx, ruleType, fileName, stringArg(args, "artifact_id"), stringArg(args, "hash"), args["version"]); err != nil {
		return nil, err
	}
	var out map[string]interface{}
	if err := c.do(ctx, http.MethodPost, "/api/v1/arsenals/"+url.PathEscape(ruleType)+"/"+url.PathEscape(fileName)+"/approve", nil, &out); err != nil {
		return nil, err
	}
	return withStableRef(out, ruleType, fileName), nil
}

func (c *Client) ensureArtifactFresh(ctx context.Context, ruleType, fileName, artifactID, expectedHash string, expectedVersion interface{}) error {
	if expectedHash == "" && expectedVersion == nil {
		return nil
	}
	var rows []map[string]interface{}
	if err := c.do(ctx, http.MethodGet, "/api/v1/arsenals/"+url.PathEscape(ruleType)+"?all=1&lite=1", nil, &rows); err != nil {
		return err
	}
	for _, row := range rows {
		if !arsenalRowMatches(row, ruleType, fileName, artifactID) {
			continue
		}
		currentHash := mapString(row, "hash", "Hash")
		if expectedHash != "" && currentHash != expectedHash {
			return fmt.Errorf("artifact hash mismatch for %s: current=%s expected=%s", fileName, currentHash, expectedHash)
		}
		if expectedVersion != nil {
			current, ok := mapInt(row, "version", "Version")
			if !ok {
				return fmt.Errorf("artifact version is missing for %s", fileName)
			}
			expected, ok := intFromAny(expectedVersion)
			if !ok {
				return fmt.Errorf("expected version is invalid for %s", fileName)
			}
			if current != expected {
				return fmt.Errorf("artifact version mismatch for %s: current=%d expected=%d", fileName, current, expected)
			}
		}
		return nil
	}
	return fmt.Errorf("artifact %s/%s not found", ruleType, fileName)
}

func arsenalRowMatches(row map[string]interface{}, ruleType, fileName, artifactID string) bool {
	if artifactID != "" && mapString(row, "artifact_id", "ID", "id") == artifactID {
		return true
	}
	if mapString(row, "file_name", "FileName") == fileName {
		return true
	}
	path := strings.TrimPrefix(mapString(row, "path", "Path"), "/")
	return path == ruleType+"/"+fileName
}

func (c *Client) resolveExploitRuleID(ctx context.Context, args map[string]interface{}) (int, error) {
	if id, ok := numberArg(args, "exploit_rule_id"); ok && id > 0 {
		return id, nil
	}
	artifactID := stringArg(args, "artifact_id")
	ruleID := stringArg(args, "rule_id")
	fileName := stringArg(args, "file_name")
	var rules []map[string]interface{}
	if err := c.do(ctx, http.MethodGet, "/api/v1/exploits?all=1", nil, &rules); err != nil {
		return 0, err
	}
	for _, rule := range rules {
		if artifactID != "" && mapString(rule, "artifact_id", "ArtifactID", "ID") == artifactID {
			if id, ok := mapInt(rule, "id", "ID"); ok {
				if err := ensureExploitFresh(rule, stringArg(args, "hash"), args["version"]); err != nil {
					return 0, err
				}
				return id, nil
			}
		}
		if ruleID != "" && mapString(rule, "rule_id", "RuleID") == ruleID {
			if id, ok := mapInt(rule, "id", "ID"); ok {
				if err := ensureExploitFresh(rule, stringArg(args, "hash"), args["version"]); err != nil {
					return 0, err
				}
				return id, nil
			}
		}
		if fileName != "" && mapString(rule, "source_file", "SourceFile", "file_name", "FileName") == fileName {
			if id, ok := mapInt(rule, "id", "ID"); ok {
				if err := ensureExploitFresh(rule, stringArg(args, "hash"), args["version"]); err != nil {
					return 0, err
				}
				return id, nil
			}
		}
	}
	return 0, fmt.Errorf("EXP rule not found for artifact_id=%q rule_id=%q file_name=%q", artifactID, ruleID, fileName)
}

func ensureExploitFresh(rule map[string]interface{}, expectedHash string, expectedVersion interface{}) error {
	sourceFile := mapString(rule, "source_file", "SourceFile", "file_name", "FileName")
	currentHash := mapString(rule, "content_hash", "ContentHash", "hash", "Hash")
	if expectedHash != "" && currentHash != expectedHash {
		return fmt.Errorf("EXP content hash mismatch for %s: current=%s expected=%s", sourceFile, currentHash, expectedHash)
	}
	if expectedVersion != nil {
		current, ok := mapInt(rule, "version", "Version")
		if !ok {
			return fmt.Errorf("EXP version is missing for %s", sourceFile)
		}
		expected, ok := intFromAny(expectedVersion)
		if !ok {
			return fmt.Errorf("expected EXP version is invalid for %s", sourceFile)
		}
		if current != expected {
			return fmt.Errorf("EXP version mismatch for %s: current=%d expected=%d", sourceFile, current, expected)
		}
	}
	return nil
}

func (c *Client) postTool(ctx context.Context, path string, args map[string]interface{}) (interface{}, error) {
	var out interface{}
	err := c.do(ctx, http.MethodPost, path, args, &out)
	return out, err
}

func (c *Client) do(ctx context.Context, method, path string, body interface{}, out interface{}) error {
	if c.baseURL == "" {
		return fmt.Errorf("ARGUS_BASE_URL is required")
	}
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024*1024))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("argus API %s %s returned %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if out == nil {
		return nil
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	return json.Unmarshal(data, out)
}

func stringArg(args map[string]interface{}, key string) string {
	if args == nil {
		return ""
	}
	if value, ok := args[key].(string); ok {
		return strings.TrimSpace(value)
	}
	return ""
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func copyArgs(args map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{}
	for key, value := range args {
		out[key] = value
	}
	return out
}

func stringSliceArg(args map[string]interface{}, key string) []string {
	if args == nil {
		return nil
	}
	raw, ok := args[key]
	if !ok {
		return nil
	}
	out := []string{}
	add := func(value interface{}) {
		item := strings.TrimSpace(fmt.Sprint(value))
		if item != "" {
			out = append(out, item)
		}
	}
	switch values := raw.(type) {
	case []interface{}:
		for _, value := range values {
			add(value)
		}
	case []string:
		for _, value := range values {
			add(value)
		}
	case string:
		for _, value := range strings.Split(values, ",") {
			add(value)
		}
	}
	return out
}

func stringSliceFromAny(raw interface{}) []string {
	out := []string{}
	add := func(value interface{}) {
		item := strings.TrimSpace(fmt.Sprint(value))
		if item != "" {
			out = append(out, item)
		}
	}
	switch values := raw.(type) {
	case []interface{}:
		for _, value := range values {
			add(value)
		}
	case []string:
		for _, value := range values {
			add(value)
		}
	case string:
		for _, value := range strings.Split(values, ",") {
			add(value)
		}
	}
	return out
}

func numberArg(args map[string]interface{}, key string) (int, bool) {
	if args == nil {
		return 0, false
	}
	return intFromAny(args[key])
}

func intArgDefault(args map[string]interface{}, key string, fallback int) int {
	if value, ok := numberArg(args, key); ok {
		return value
	}
	return fallback
}

func intFromAny(value interface{}) (int, bool) {
	switch v := value.(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	case json.Number:
		i, err := v.Int64()
		return int(i), err == nil
	default:
		return 0, false
	}
}

func mapString(values map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if value, ok := values[key]; ok && value != nil {
			return strings.TrimSpace(fmt.Sprint(value))
		}
	}
	return ""
}

func mapAny(values map[string]interface{}, keys ...string) interface{} {
	for _, key := range keys {
		if value, ok := values[key]; ok && value != nil {
			return value
		}
	}
	return nil
}

func mapInt(values map[string]interface{}, keys ...string) (int, bool) {
	for _, key := range keys {
		if value, ok := values[key]; ok {
			return intFromAny(value)
		}
	}
	return 0, false
}

func mapBool(values map[string]interface{}, keys ...string) bool {
	for _, key := range keys {
		if value, ok := values[key]; ok {
			switch v := value.(type) {
			case bool:
				return v
			case string:
				return strings.EqualFold(v, "true")
			default:
				return fmt.Sprint(v) == "1"
			}
		}
	}
	return false
}

func firstPresent(values map[string]interface{}, keys ...string) interface{} {
	for _, key := range keys {
		if value, ok := values[key]; ok {
			return value
		}
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func matchesFilter(value, filter string) bool {
	if filter == "" {
		return true
	}
	return strings.Contains(strings.ToLower(strings.TrimSpace(value)), filter)
}

func appendLimited(items []map[string]interface{}, item map[string]interface{}, limit int) []map[string]interface{} {
	if limit <= 0 || len(items) >= limit {
		return items
	}
	return append(items, item)
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

func productSearchPOCItem(poc map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"name":           mapString(poc, "name", "Name"),
		"source_file":    mapString(poc, "source_file", "SourceFile"),
		"target_product": mapString(poc, "target_product", "TargetProduct"),
		"severity":       mapString(poc, "severity", "Severity"),
		"state":          mapString(poc, "state", "State"),
		"enabled":        mapBool(poc, "enabled", "Enabled"),
		"tags":           mapString(poc, "tags", "Tags"),
		"cve":            mapString(poc, "cve", "CVE"),
	}
}

func scoreProductSearchBucket(query string, b *productSearchBucket) (float64, []string) {
	query = strings.TrimSpace(query)
	queryNorm := normalizeSearchText(query)
	queryTokens := searchTokens(query)
	if queryNorm == "" || len(queryTokens) == 0 {
		return 0, nil
	}

	best := 0.0
	reasons := []string{}
	scoreCandidate := func(value, reason string, weight float64) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		valueNorm := normalizeSearchText(value)
		valueTokens := searchTokens(value)
		score := 0.0
		switch {
		case valueNorm == queryNorm:
			score = 1.0
		case strings.Contains(valueNorm, queryNorm) || strings.Contains(queryNorm, valueNorm):
			score = 0.86
		default:
			score = 0.55*jaccardTokens(queryTokens, valueTokens) + 0.45*normalizedEditSimilarity(queryNorm, valueNorm)
		}
		score *= weight
		if score > best {
			best = score
		}
		if score >= 0.42 {
			reasons = append(reasons, reason)
		}
	}

	scoreCandidate(b.Name, "product_name_similarity", 1.0)
	for _, text := range b.SearchText {
		scoreCandidate(text, "asset_text_similarity", 0.82)
	}
	if len(b.Workflows) > 0 {
		reasons = append(reasons, "has_workflow")
	}
	if len(b.POCs) > 0 {
		reasons = append(reasons, "has_poc")
	}
	if len(b.Fingerprint) > 0 {
		reasons = append(reasons, "has_fingerprint")
	}
	if len(b.EXPs) > 0 {
		reasons = append(reasons, "has_pyexp")
	}
	if best < 0.35 {
		return 0, nil
	}
	return best, uniqueStrings(reasons)
}

func normalizeSearchText(value string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(value) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func searchTokens(value string) []string {
	fields := strings.FieldsFunc(strings.ToLower(value), func(r rune) bool {
		return !(unicode.IsLetter(r) || unicode.IsDigit(r))
	})
	out := []string{}
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if len([]rune(field)) < 2 || weakSearchToken(field) {
			continue
		}
		out = append(out, field)
	}
	return uniqueStrings(out)
}

func weakSearchToken(token string) bool {
	switch token {
	case "cms", "system", "platform", "web", "server", "app", "application", "the", "and", "for":
		return true
	default:
		return false
	}
}

func jaccardTokens(a, b []string) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	set := map[string]bool{}
	for _, item := range a {
		set[item] = true
	}
	inter := 0
	union := len(set)
	for _, item := range b {
		if set[item] {
			inter++
			continue
		}
		union++
	}
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

func normalizedEditSimilarity(a, b string) float64 {
	if a == "" || b == "" {
		return 0
	}
	dist := levenshtein(a, b)
	maxLen := len([]rune(a))
	if lb := len([]rune(b)); lb > maxLen {
		maxLen = lb
	}
	if maxLen == 0 {
		return 0
	}
	score := 1 - float64(dist)/float64(maxLen)
	if score < 0 {
		return 0
	}
	return score
}

func levenshtein(a, b string) int {
	ar := []rune(a)
	br := []rune(b)
	if len(ar) == 0 {
		return len(br)
	}
	if len(br) == 0 {
		return len(ar)
	}
	prev := make([]int, len(br)+1)
	for j := range prev {
		prev[j] = j
	}
	for i, ra := range ar {
		cur := make([]int, len(br)+1)
		cur[0] = i + 1
		for j, rb := range br {
			cost := 0
			if ra != rb {
				cost = 1
			}
			cur[j+1] = minInt(cur[j]+1, prev[j+1]+1, prev[j]+cost)
		}
		prev = cur
	}
	return prev[len(br)]
}

func minInt(values ...int) int {
	min := values[0]
	for _, value := range values[1:] {
		if value < min {
			min = value
		}
	}
	return min
}

func productSearchSources(b *productSearchBucket) []string {
	sources := []string{}
	if len(b.Fingerprint) > 0 {
		sources = append(sources, "fingerprint")
	}
	if len(b.Workflows) > 0 {
		sources = append(sources, "workflow")
	}
	if len(b.POCs) > 0 {
		sources = append(sources, "poc")
	}
	if len(b.EXPs) > 0 {
		sources = append(sources, "pyexp")
	}
	return sources
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func normalizeRuleType(ruleType string) string {
	switch strings.ToLower(strings.TrimSpace(ruleType)) {
	case "fingerprint", "finger":
		return "finger"
	case "workflow":
		return "workflow"
	case "poc":
		return "poc"
	case "pyexp", "exp", "exploit":
		return "exp"
	default:
		return strings.ToLower(strings.TrimSpace(ruleType))
	}
}

func publicRuleType(ruleType string) string {
	if ruleType == "finger" {
		return "fingerprint"
	}
	if ruleType == "exp" {
		return "pyexp"
	}
	return ruleType
}

func withStableRef(out map[string]interface{}, ruleType, fileName string) map[string]interface{} {
	if out == nil {
		out = map[string]interface{}{}
	}
	if _, ok := out["file_name"]; !ok && fileName != "" {
		out["file_name"] = fileName
	}
	if _, ok := out["artifact_id"]; !ok && fileName != "" {
		out["artifact_id"] = ruleType + "_" + fileName
	}
	out["rule_type"] = publicRuleType(ruleType)
	stable := map[string]interface{}{}
	for _, key := range []string{"artifact_id", "rule_id", "file_name", "hash", "version"} {
		if value, ok := out[key]; ok && fmt.Sprint(value) != "" {
			stable[key] = value
		}
	}
	out["stable_ref"] = stable
	return out
}

func stripLegacyExploitRef(out map[string]interface{}) map[string]interface{} {
	if out == nil {
		return out
	}
	delete(out, "exploit_rule_id")
	delete(out, "legacy_ref")
	return out
}
