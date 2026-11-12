package mcp

import sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

const sourceLessMCPInstructions = "You do not have the Argus source tree. Argus MCP is the only API. First call argus_help, then argus_resource with the spec and template URIs for the rule_type. Sequence: argus_help -> spec/template -> argus_agents -> debug on a user-authorized target (argus_debug_*) -> save Draft (argus_save_*) -> admin publish with argus_rule_apply using exact stable_ref hash/version -> verify with argus_rule_get. argus_rule_get omits YAML by default and returns fingerprint/workflow/dir product names as a compact string array; pass product_name for one mapping, or include_content=true only for small POC/behavior_probe files. POC rule_get does not treat YAML keys as products. Catalog coverage is argus_coverage; query is a substring and hyphens are literal. Do not guess YAML or invent tools. Nuclei YAML requires info.author. Controlled behavior probes need operator confirmation (host elicitation when available; otherwise risk_confirmed=true). A risk_confirmed argument is not operator confirmation. EXP: argus_yaksha_exp and argus_exp_workspace. Scans: argus_scan_preview then argus_scan_create with the returned plan_hash."

func focusedMCPToolNames() []string {
	return []string{
		"argus_help",
		"argus_resource",
		"argus_agents",
		"argus_coverage",
		"argus_rule_get",
		"argus_rule_list",
		"argus_debug_fingerprint",
		"argus_debug_dir",
		"argus_debug_poc",
		"argus_debug_workflow",
		"argus_debug_behavior_probe",
		"argus_save_fingerprint",
		"argus_save_dir",
		"argus_save_poc",
		"argus_save_workflow",
		"argus_save_behavior_probe",
		"argus_rule_apply",
		"argus_yaksha_exp",
		"argus_exp_workspace",
		"argus_scan_preview",
		"argus_scan_create",
		"argus_findings",
		"argus_results",
		"argus_product_search",
	}
}

func tools() []*sdkmcp.Tool {
	return []*sdkmcp.Tool{
		{Name: "argus_help", Title: "入门手册", Description: "Playbook, resource catalog, required fields and lifecycle intents for a source-less client. Call this first. Do not guess YAML or invent tools.", InputSchema: objectSchema(map[string]interface{}{}, nil)},
		{Name: "argus_resource", Title: "拉取规范或模板", Description: "Fetch one spec or template by URI from argus_help resources[], for example argus://fingerprint/spec.", InputSchema: objectSchema(map[string]interface{}{"uri": stringSchema("Resource URI, for example argus://fingerprint/spec")}, []string{"uri"})},
		{Name: "argus_agents", Title: "在线 Agent 列表", Description: "List Alive Agents without session secrets. Fingerprint, dir and workflow debug need Agent v2.3.0+.", InputSchema: objectSchema(map[string]interface{}{}, nil)},
		{Name: "argus_coverage", Title: "指纹与 POC 覆盖", Description: "Fingerprint vs workflow POC catalog counts and missing product names. Empty matches return an empty list, not an error.", InputSchema: objectSchema(map[string]interface{}{
			"query":         stringSchema("Substring filter over product names. Hyphens are literal; query=MCP-Server is not a range."),
			"include_names": map[string]interface{}{"type": "boolean", "description": "Include compact product name array; default true"},
			"missing":       enumSchema([]string{"fingerprint_without_poc", "workflow_without_fingerprint"}),
			"limit":         integerSchema("Maximum missing names to return"),
		}, nil)},
		{Name: "argus_rule_get", Title: "读取规则", Description: "Read one artifact by file_name or artifact_id. Omits YAML unless include_content=true. Fingerprint/workflow/dir return product names as a string array. POC returns template_id/template_name, not YAML keys.", InputSchema: objectSchema(map[string]interface{}{
			"rule_type":       ruleTypeSchema(),
			"file_name":       stringSchema("Exact artifact file name"),
			"artifact_id":     stringSchema("Exact artifact id"),
			"product_name":    stringSchema("Return that one mapping entry instead of the full name list"),
			"include_content": map[string]interface{}{"type": "boolean", "description": "Include YAML; refused for files larger than 64KiB"},
			"range_start":     integerSchema("1-based inclusive first product name; not parsed from query"),
			"range_end":       integerSchema("1-based inclusive last product name"),
		}, []string{"rule_type"})},
		{Name: "argus_rule_list", Title: "列出规则", Description: "Paged artifact lists. Use state=Draft for drafts-only listing. Max window 200.", InputSchema: objectSchema(map[string]interface{}{
			"rule_type":   ruleTypeSchema(),
			"state":       enumSchema([]string{"Draft", "Approved", "Deprecated"}),
			"query":       stringSchema("Substring filter over listed fields. Hyphens are literal."),
			"range_start": integerSchema("1-based inclusive first row"),
			"range_end":   integerSchema("1-based inclusive last row; max window 200"),
		}, nil)},
		{Name: "argus_debug_fingerprint", Title: "调试指纹", Description: "Debug one fingerprint expression through an authorized online Agent. Concurrent debug is per Agent, not per tenant.", InputSchema: objectSchema(mergeProps(debugCommonProperties(), map[string]interface{}{
			"product_name":     stringSchema("Fingerprint product"),
			"rule":             stringSchema("One fingerprint expression to inject"),
			"include_dir":      map[string]interface{}{"type": "boolean"},
			"include_poc":      map[string]interface{}{"type": "boolean"},
			"workflow_product": stringSchema("Optional workflow product for fingerprint -> POC chain"),
			"workflow_types":   stringArraySchema("Workflow match types"),
			"workflow_pocs":    stringArraySchema("Workflow POC file names"),
			"poc_content":      stringSchema("Optional injected POC YAML"),
		}), []string{"agent_id", "target_url"})},
		{Name: "argus_debug_dir", Title: "调试目录探测", Description: "Debug dir probes through an authorized online Agent. paths replace tenant dir.yaml for that call and return per-path status/body.", InputSchema: objectSchema(mergeProps(debugCommonProperties(), map[string]interface{}{
			"product_name": stringSchema("Dir product"),
			"paths":        stringArraySchema("Dir probe paths that replace tenant dir.yaml for this debug call"),
		}), []string{"agent_id", "target_url"})},
		{Name: "argus_debug_poc", Title: "调试 POC", Description: "Debug one Nuclei POC through an authorized online Agent. Look at result.matched / top-level matched, not Nuclei catalog log noise.", InputSchema: objectSchema(mergeProps(debugCommonProperties(), map[string]interface{}{
			"file_name":   stringSchema("POC YAML file name ending in .yaml"),
			"poc_content": stringSchema("Complete Nuclei POC YAML"),
			"content":     stringSchema("Alias for poc_content"),
		}), []string{"agent_id", "target_url"})},
		{Name: "argus_debug_workflow", Title: "调试 Workflow", Description: "Debug a workflow product mapping through an authorized online Agent.", InputSchema: objectSchema(mergeProps(debugCommonProperties(), map[string]interface{}{
			"workflow_product": stringSchema("Workflow product or General-Poc-* group"),
			"workflow_types":   stringArraySchema("Workflow match types"),
			"workflow_pocs":    stringArraySchema("Workflow POC file names"),
			"poc_content":      stringSchema("Optional injected POC YAML"),
			"include_poc":      map[string]interface{}{"type": "boolean"},
		}), []string{"agent_id", "target_url"})},
		{Name: "argus_debug_behavior_probe", Title: "调试行为探针", Description: "Debug a Nuclei behavior probe through an authorized online Agent. Controlled probes are never included in automatic scanning. Hosts with elicitation confirm via the operator prompt; other clients must set risk_confirmed=true. A risk_confirmed argument is not operator confirmation.", InputSchema: objectSchema(mergeProps(debugCommonProperties(), map[string]interface{}{
			"file_name":      stringSchema("Behavior probe YAML file name"),
			"content":        stringSchema("Complete Nuclei behavior probe YAML"),
			"risk_confirmed": map[string]interface{}{"type": "boolean", "description": "Server governance flag. Hosts with elicitation ignore this argument and confirm via the operator prompt; other clients must set true for controlled probes."},
		}), []string{"agent_id", "target_url"})},
		{Name: "argus_save_fingerprint", Title: "保存指纹草稿", Description: "Save a fingerprint product mapping as a Draft and return stable_ref. Product patches do not rewrite the rest of finger.yaml.", InputSchema: objectSchema(mergeProps(saveCommonProperties(), map[string]interface{}{
			"product_name": stringSchema("Fingerprint product"),
			"rules":        stringArraySchema("Fingerprint expressions such as body=\"marker\""),
		}), nil)},
		{Name: "argus_save_dir", Title: "保存目录探测草稿", Description: "Save a dir product mapping as a Draft and return stable_ref. Product patches do not rewrite the rest of dir.yaml. Isolated drafts should use a unique file_name.", InputSchema: objectSchema(mergeProps(saveCommonProperties(), map[string]interface{}{
			"product_name": stringSchema("Dir product"),
			"paths":        stringArraySchema("URL paths such as /admin"),
		}), nil)},
		{Name: "argus_save_poc", Title: "保存 POC 草稿", Description: "Save a complete Nuclei POC YAML as a Draft and return stable_ref. file_name must end in .yaml. info.author is mandatory.", InputSchema: objectSchema(saveCommonProperties(), []string{"file_name", "content"})},
		{Name: "argus_save_workflow", Title: "保存 Workflow 草稿", Description: "Save a workflow product mapping as a Draft and return stable_ref. Product patches do not rewrite the rest of workflow.yaml.", InputSchema: objectSchema(mergeProps(saveCommonProperties(), map[string]interface{}{
			"product_name":   stringSchema("Fingerprint product or General-Poc-* group"),
			"workflow_types": stringArraySchema("Match types such as root"),
			"workflow_pocs":  stringArraySchema("POC file names"),
			"risk_level":     enumSchema([]string{"unknown", "info", "low", "medium", "high"}),
		}), nil)},
		{Name: "argus_save_behavior_probe", Title: "保存行为探针草稿", Description: "Save a complete Nuclei behavior probe YAML as a Draft and return stable_ref. info.author is mandatory.", InputSchema: objectSchema(saveCommonProperties(), []string{"file_name", "content"})},
		{Name: "argus_rule_apply", Title: "发布 / 废弃 / 回滚", Description: "Admin-only publish, deprecate or rollback using exact stable_ref hash/version guards.", InputSchema: objectSchema(map[string]interface{}{
			"action":      enumSchema([]string{"publish", "deprecate", "rollback"}),
			"rule_type":   ruleTypeSchema(),
			"artifact_id": stringSchema("Stable DB artifact id from stable_ref"),
			"file_name":   stringSchema("Draft file name"),
			"hash":        stringSchema("Expected artifact hash"),
			"version":     integerSchema("Expected artifact version"),
		}, []string{"action", "rule_type"})},
		{Name: "argus_yaksha_exp", Title: "Yaksha EXP 运行时", Description: "Operate one sealed single-file Yaklang EXP through the persistent independent Yaksha runtime. Transient script is limited to inspect, validate, and offline Fixture test. Network-capable debug/run require a Server-saved Revision bound by exp_id + revision + source_sha256 as an immutable source identity, so tenant authorization, risk confirmation, and run audit cannot be bypassed. inspect derives the official cli.* UI plus literal yaksha.call/yaksha.asset references; validate checks source, params, dependencies, assets, exact network targets, and egress shape; test is fixture-only and always offline; debug returns complete unredacted HTTP/TCP Trace; run executes once. Dependencies are pinned child revisions and assets are hash-bound content. Egress explicitly selects disabled, direct, a per-call write-only SOCKS5 route, or an authorized Agent using agent_id plus risk_confirmed=true. Agent mode creates a single-use Server Route and never exposes route_id or Gateway credentials. This tool does not expose filesystem or object-storage paths.", Meta: sdkmcp.Meta{"ui": map[string]interface{}{"resourceUri": expConsoleURI, "visibility": []string{"model", "app"}}}, InputSchema: yakshaInputSchema(), OutputSchema: map[string]interface{}{"type": "object"}},
		{Name: "argus_exp_workspace", Title: "Yaksha EXP Studio 工作区", Description: "Manage the Server-authoritative Yaksha EXP Studio workspace: EXP metadata, immutable revisions, hash-bound Assets, Fixture acceptance cases, publication, rollback pointers and run history. All operations are tenant-scoped and require EXP authorization; publication/deprecation/rollback remain Admin-only. Source, Asset content and full run artifacts are stored in private MinIO and no object key, credential or host path is exposed.", Meta: sdkmcp.Meta{"ui": map[string]interface{}{"resourceUri": expConsoleURI, "visibility": []string{"model", "app"}}}, InputSchema: expWorkspaceInputSchema(), OutputSchema: map[string]interface{}{"type": "object"}},
		{Name: "argus_scan_preview", Title: "扫描预览", Description: "Preview one authorized scan through the Server-authoritative argus.scan-policy/v1 compiler. Show stages, port count, Agent capacity, POC scope and credential budget to the user, then pass the exact returned plan_hash to argus_scan_create. This tool never accepts Scanner raw config, Agent file paths or an independent manual POC phase.", InputSchema: scanPreviewInputSchema(), OutputSchema: map[string]interface{}{"type": "object"}},
		{Name: "argus_scan_create", Title: "创建扫描", Description: "Create one authorized scan using the exact plan_hash returned by argus_scan_preview. POC and credential validation share one explicit authorization confirmation. This tool never accepts Scanner raw config, Agent file paths or an independent manual POC phase.", InputSchema: scanCreateInputSchema(), OutputSchema: map[string]interface{}{"type": "object"}},
		{Name: "argus_product_search", Title: "模糊产品搜索", Description: "Read-only fuzzy product search across fingerprint, workflow and POC indexes by product, alias, POC name, CVE, tag or keyword. Use argus_rule_get for the exact read path before save/publish. It never saves, deletes, or publishes.", InputSchema: objectSchema(map[string]interface{}{
			"query": stringSchema("Product, alias, POC name, CVE, tag or keyword"),
			"limit": map[string]interface{}{"type": "integer", "maximum": 100},
		}, []string{"query"})},
		{Name: "argus_findings", Title: "内容分析发现", Description: "Read-only query of scan content-analysis findings: crawl-site asset candidates (including path_app/hidden_path sites) and sensitive-info findings (email/phone/idcard/account/username/apikey/token/secret). action=summary aggregates counts by kind/site_type/ai_status; action=crawl_sites or sensitive returns the filtered rows. Results stay scoped to the caller's tenant/RBAC projects. It never modifies findings.", InputSchema: objectSchema(map[string]interface{}{
			"action":     enumSchema([]string{"summary", "crawl_sites", "sensitive"}),
			"project_id": stringSchema("Tenant-scoped project ID; omit to span all accessible projects"),
			"task_id":    stringSchema("Root task ID; expands to its subtasks"),
			"kind":       enumSchema([]string{"email", "phone", "idcard", "account", "username", "apikey", "token", "secret", "keyword", "custom"}),
			"site_type":  enumSchema([]string{"path_app", "hidden_path"}),
			"ai_status":  enumSchema([]string{"pending", "confirmed", "rejected"}),
			"search":     stringSchema("Substring match on url/host (crawl_sites) or value/host (sensitive)"),
			"page":       map[string]interface{}{"type": "integer", "minimum": 1},
			"page_size":  map[string]interface{}{"type": "integer", "minimum": 1, "maximum": 200},
		}, []string{"action"})},
		{Name: "argus_results", Title: "扫描结果", Description: "Read-only query of dispatched-scan results: vulnerabilities (POC findings with request/response evidence), assets, and fingerprint hits. action=summary aggregates counts (vulns by severity/status, assets by protocol, fingerprints by product); action=vulns/assets/fingerprints list filtered rows; action=vuln_detail returns one vulnerability's full evidence bundle (Request/Response原文, AI review, asset lineage) by id + project_id. Results stay scoped to the caller's tenant/RBAC projects. It never modifies results.", InputSchema: objectSchema(map[string]interface{}{
			"action":     enumSchema([]string{"summary", "vulns", "vuln_detail", "assets", "fingerprints"}),
			"project_id": stringSchema("Tenant-scoped project ID; required for vuln_detail, otherwise spans accessible projects"),
			"task_id":    stringSchema("Root task ID; expands to its subtasks"),
			"id":         stringSchema("Vulnerability numeric ID; required for vuln_detail"),
			"search":     stringSchema("Substring match on target (vulns/assets) or product_name/target (fingerprints)"),
			"sort":       enumSchema([]string{"severity", "created_at", "updated_at"}),
			"order":      enumSchema([]string{"asc", "desc"}),
			"group_by":   enumSchema([]string{"product"}),
			"page":       map[string]interface{}{"type": "integer", "minimum": 1},
			"page_size":  map[string]interface{}{"type": "integer", "minimum": 1, "maximum": 200},
		}, []string{"action"})},
	}
}

func scanPolicyProperties() map[string]interface{} {
	return map[string]interface{}{
		"project_id":  stringSchema("Tenant-scoped project ID"),
		"name":        stringSchema("Optional task name"),
		"targets":     map[string]interface{}{"oneOf": []interface{}{map[string]interface{}{"type": "string"}, map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}}}, "description": "Authorized targets as newline text or a string array"},
		"policy":      map[string]interface{}{"type": "object", "description": "Complete argus.scan-policy/v1 policy; Server normalizes it and verifies dictionary revisions, authorization and Agent capacity"},
		"priority":    map[string]interface{}{"type": "integer", "minimum": 0, "maximum": 2},
		"timeout_sec": map[string]interface{}{"type": "integer", "minimum": 0},
	}
}

func scanPreviewInputSchema() map[string]interface{} {
	return objectSchema(scanPolicyProperties(), []string{"project_id", "targets", "policy"})
}

func scanCreateInputSchema() map[string]interface{} {
	return objectSchema(mergeProps(scanPolicyProperties(), map[string]interface{}{
		"plan_hash":       stringSchema("Exact plan_hash returned by argus_scan_preview"),
		"idempotency_key": stringSchema("Stable UUID-like key for this create intent; reused only when retrying the identical request"),
	}), []string{"project_id", "targets", "policy", "plan_hash", "idempotency_key"})
}

func debugCommonProperties() map[string]interface{} {
	return map[string]interface{}{
		"agent_id":    stringSchema("Alive Agent ID"),
		"target_url":  stringSchema("Authorized target URL"),
		"proxy":       stringSchema("Write-only proxy URL"),
		"timeout_sec": integerSchema("Debug timeout in seconds"),
	}
}

func saveCommonProperties() map[string]interface{} {
	return map[string]interface{}{
		"intent":    enumSchema([]string{"test_only", "production_candidate", "approved_reusable"}),
		"file_name": stringSchema("Draft file name"),
		"content":   stringSchema("Complete rule source YAML"),
	}
}

func ruleTypeSchema() map[string]interface{} {
	return enumSchema([]string{"fingerprint", "behavior_probe", "poc", "workflow", "dir"})
}

func integerSchema(description string) map[string]interface{} {
	schema := map[string]interface{}{"type": "integer"}
	if description != "" {
		schema["description"] = description
	}
	return schema
}

func stringArraySchema(description string) map[string]interface{} {
	schema := map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}}
	if description != "" {
		schema["description"] = description
	}
	return schema
}

func mergeProps(parts ...map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{}
	for _, part := range parts {
		for key, value := range part {
			out[key] = value
		}
	}
	return out
}

func isStructuredContentTool(name string) bool {
	switch name {
	case "argus_yaksha_exp", "argus_exp_workspace", "argus_scan_preview", "argus_scan_create":
		return true
	default:
		return false
	}
}
