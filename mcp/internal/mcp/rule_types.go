package mcp

import (
	"fmt"
	"strings"
)

func normalizeRuleType(ruleType string) string {
	switch strings.ToLower(strings.TrimSpace(ruleType)) {
	case "fingerprint", "finger":
		return "finger"
	case "workflow":
		return "workflow"
	case "poc":
		return "poc"
	default:
		return strings.ToLower(strings.TrimSpace(ruleType))
	}
}

func publicRuleType(ruleType string) string {
	if ruleType == "finger" {
		return "fingerprint"
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
