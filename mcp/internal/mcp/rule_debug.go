package mcp

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

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
