package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"
	"unicode"
)

type catalogRecord struct {
	ArtifactID    string
	RuleID        string
	Name          string
	FileName      string
	SourceFile    string
	Product       string
	TargetProduct string
	Description   string
	Tags          string
	CVE           string
	Severity      string
	RiskLevel     string
	State         string
	Hash          string
	Version       interface{}
	Enabled       bool
	Rules         []string
	Types         []string
	POCs          []string
	LinkedPOCs    interface{}
	Requirements  interface{}
	Raw           map[string]interface{}
}

func (r *catalogRecord) UnmarshalJSON(data []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	r.Raw = raw
	r.ArtifactID = mapString(raw, "artifact_id", "ArtifactID")
	r.RuleID = mapString(raw, "rule_id", "RuleID")
	r.Name = mapString(raw, "name", "Name")
	r.FileName = mapString(raw, "file_name", "FileName")
	r.SourceFile = mapString(raw, "source_file", "SourceFile")
	r.Product = firstNonEmpty(mapString(raw, "product", "Product"), mapString(raw, "product_name", "ProductName"))
	r.TargetProduct = mapString(raw, "target_product", "TargetProduct")
	r.Description = mapString(raw, "description", "Description")
	r.Tags = mapString(raw, "tags", "Tags")
	r.CVE = mapString(raw, "cve", "CVE")
	r.Severity = mapString(raw, "severity", "Severity")
	r.RiskLevel = mapString(raw, "risk_level", "RiskLevel")
	r.State = mapString(raw, "state", "State")
	r.Hash = firstNonEmpty(mapString(raw, "hash", "Hash"), mapString(raw, "content_hash", "ContentHash"))
	r.Version = firstPresent(raw, "version", "Version")
	r.Enabled = mapBool(raw, "enabled", "Enabled")
	r.Rules = stringSliceFromAny(firstPresent(raw, "rules", "Rules"))
	r.Types = stringSliceFromAny(firstPresent(raw, "type", "Type", "workflow_types", "WorkflowTypes"))
	r.POCs = stringSliceFromAny(firstPresent(raw, "pocs", "Pocs", "POCs", "workflow_pocs", "WorkflowPocs", "WorkflowPOCs"))
	r.LinkedPOCs = firstPresent(raw, "linked_pocs", "LinkedPocs", "LinkedPOCs")
	r.Requirements = firstPresent(raw, "requirements", "Requirements")
	return nil
}

func (r catalogRecord) EffectiveSourceFile() string {
	return firstNonEmpty(r.SourceFile, r.FileName)
}

const generalPOCWorkflowPrefix = "General-Poc-"

func workflowKind(product string) string {
	if isGeneralPOCWorkflowProduct(product) {
		return "general_poc"
	}
	return "product_bound"
}

func isGeneralPOCWorkflowProduct(product string) bool {
	return strings.HasPrefix(strings.TrimSpace(product), generalPOCWorkflowPrefix)
}

func mergeSafetyHint(product string) string {
	if isGeneralPOCWorkflowProduct(product) {
		return "General-Poc-* is a reserved general POC workflow group; do not merge it into a real product alias or create a same-name fingerprint."
	}
	return "review manually before saving fingerprint/workflow drafts; product_search is read-only"
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
	Name           string
	Fingerprint    []map[string]interface{}
	BehaviorProbes []map[string]interface{}
	Workflows      []map[string]interface{}
	POCs           []map[string]interface{}
	SearchText     []string
	Evidence       map[string]bool
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

	var fingerprints []catalogRecord
	if err := c.do(ctx, http.MethodGet, "/api/v1/dictionaries/fingerprint", nil, &fingerprints); err != nil {
		return nil, err
	}
	var workflows []catalogRecord
	if err := c.do(ctx, http.MethodGet, "/api/v1/dictionaries/workflow", nil, &workflows); err != nil {
		return nil, err
	}
	var behaviorProbes []catalogRecord
	if err := c.do(ctx, http.MethodGet, "/api/v1/active-fingerprint-rules?all=1", nil, &behaviorProbes); err != nil {
		return nil, err
	}
	var pocs []catalogRecord
	if err := c.do(ctx, http.MethodGet, "/api/v1/poc-rules?all=1", nil, &pocs); err != nil {
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
		product := fp.Product
		if product == "" {
			continue
		}
		b := bucket(product)
		rules := fp.Rules
		b.Fingerprint = append(b.Fingerprint, map[string]interface{}{"product_name": product, "rules": rules})
		b.SearchText = append(b.SearchText, product)
		b.SearchText = append(b.SearchText, rules...)
	}

	for _, probe := range behaviorProbes {
		product := probe.Product
		if product == "" {
			continue
		}
		b := bucket(product)
		b.BehaviorProbes = append(b.BehaviorProbes, map[string]interface{}{
			"name": probe.Name, "source_file": probe.EffectiveSourceFile(), "state": probe.State,
			"enabled": probe.Enabled, "classification": firstPresent(probe.Raw, "ComputedAutoProfile", "computed_auto_profile"),
			"auto_eligible": firstPresent(probe.Raw, "AutoEligible", "auto_eligible"),
		})
		b.SearchText = append(b.SearchText, product, probe.Name, probe.EffectiveSourceFile())
		b.Evidence["behavior_probe"] = true
	}

	pocByName := map[string]catalogRecord{}
	for _, poc := range pocs {
		sourceFile := poc.EffectiveSourceFile()
		name := firstNonEmpty(poc.Name, sourceFile)
		targetProduct := poc.TargetProduct
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
			b.SearchText = append(b.SearchText, targetProduct, name, sourceFile, poc.Tags, poc.Description, poc.CVE)
			b.Evidence["poc_target_product"] = true
		}
	}

	for _, wf := range workflows {
		product := wf.Product
		if product == "" {
			continue
		}
		types := wf.Types
		pocNames := wf.POCs
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
				b.SearchText = append(b.SearchText, poc.Name, poc.SourceFile, poc.Tags, poc.Description, poc.CVE)
				b.Evidence["workflow_linked_poc"] = true
			}
		}
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
			"name":                 b.Name,
			"workflow_kind":        workflowKind(b.Name),
			"score":                math.Round(item.score*1000) / 1000,
			"sources":              productSearchSources(b),
			"fingerprint_count":    len(b.Fingerprint),
			"behavior_probe_count": len(b.BehaviorProbes),
			"workflow_count":       len(b.Workflows),
			"poc_count":            len(b.POCs),
			"fingerprints":         b.Fingerprint,
			"behavior_probes":      b.BehaviorProbes,
			"workflows":            b.Workflows,
			"pocs":                 b.POCs,
			"evidence":             uniqueStrings(evidence),
			"canonical_hint":       b.Name,
			"merge_safety_hint":    mergeSafetyHint(b.Name),
		})
	}
	return map[string]interface{}{"status": "success", "source": "native_api", "query": query, "limit": limit, "matches": matches}, nil
}

func productSearchPOCItem(poc catalogRecord) map[string]interface{} {
	sourceFile := poc.EffectiveSourceFile()
	return map[string]interface{}{
		"name":           firstNonEmpty(poc.Name, sourceFile),
		"source_file":    sourceFile,
		"target_product": poc.TargetProduct,
		"severity":       poc.Severity,
		"state":          poc.State,
		"enabled":        poc.Enabled,
		"tags":           poc.Tags,
		"cve":            poc.CVE,
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
	if len(b.BehaviorProbes) > 0 {
		reasons = append(reasons, "has_behavior_probe")
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
	if len(b.BehaviorProbes) > 0 {
		sources = append(sources, "behavior_probe")
	}
	if len(b.Workflows) > 0 {
		sources = append(sources, "workflow")
	}
	if len(b.POCs) > 0 {
		sources = append(sources, "poc")
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
