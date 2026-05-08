package db

import (
	"encoding/json"
	"fmt"
	"strings"
)

type SelectorValues map[string][]string

type AgentSelectorRules struct {
	Match    SelectorValues `json:"match,omitempty"`
	NotMatch SelectorValues `json:"not_match,omitempty"`
}

func ParseSelectorRulesJSON(raw string) AgentSelectorRules {
	var rules AgentSelectorRules
	if strings.TrimSpace(raw) == "" || strings.TrimSpace(raw) == "{}" {
		return rules
	}
	_ = json.Unmarshal([]byte(raw), &rules)
	return rules
}

func ParseSelectorRulesBytes(raw []byte) (AgentSelectorRules, error) {
	if len(raw) == 0 || strings.TrimSpace(string(raw)) == "" || strings.TrimSpace(string(raw)) == "null" {
		return AgentSelectorRules{}, nil
	}
	var src map[string]map[string]interface{}
	if err := json.Unmarshal(raw, &src); err != nil {
		return AgentSelectorRules{}, fmt.Errorf("agent_selector_rules must contain match/not_match string maps")
	}
	rules := AgentSelectorRules{}
	for section, values := range src {
		target := SelectorValues{}
		switch section {
		case "match", "not_match":
		default:
			return AgentSelectorRules{}, fmt.Errorf("agent_selector_rules.%s is not supported", section)
		}
		for key, val := range values {
			k := strings.TrimSpace(key)
			if k == "" {
				return AgentSelectorRules{}, fmt.Errorf("agent_selector_rules.%s contains empty key", section)
			}
			parsed, err := parseSelectorRuleValues(val)
			if err != nil {
				return AgentSelectorRules{}, fmt.Errorf("agent_selector_rules.%s.%s %w", section, k, err)
			}
			target[k] = parsed
		}
		if section == "match" {
			rules.Match = target
		} else {
			rules.NotMatch = target
		}
	}
	return rules, nil
}

func parseSelectorRuleValues(val interface{}) ([]string, error) {
	switch typed := val.(type) {
	case string:
		v := strings.TrimSpace(typed)
		if v == "" {
			return nil, fmt.Errorf("must not be empty")
		}
		return []string{v}, nil
	case []interface{}:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("array values must be strings")
			}
			s = strings.TrimSpace(s)
			if s == "" {
				return nil, fmt.Errorf("array values must not be empty")
			}
			out = append(out, s)
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("array must not be empty")
		}
		return out, nil
	default:
		return nil, fmt.Errorf("must be a string or string array")
	}
}

func MergeSelectorRules(base map[string]string, extra AgentSelectorRules) AgentSelectorRules {
	rules := AgentSelectorRules{Match: SelectorValues{}}
	for key, val := range base {
		rules.Match[key] = []string{val}
	}
	for key, values := range extra.Match {
		rules.Match[key] = append([]string{}, values...)
	}
	if len(rules.Match) == 0 {
		rules.Match = nil
	}
	if len(extra.NotMatch) > 0 {
		rules.NotMatch = SelectorValues{}
		for key, values := range extra.NotMatch {
			rules.NotMatch[key] = append([]string{}, values...)
		}
	}
	return rules
}

func SelectorRulesToJSON(rules AgentSelectorRules) string {
	if len(rules.Match) == 0 && len(rules.NotMatch) == 0 {
		return "{}"
	}
	data, err := json.Marshal(rules)
	if err != nil {
		return "{}"
	}
	return string(data)
}

func NodeMatchesSelectorRules(legacy map[string]string, rules AgentSelectorRules, nodeTags string) (bool, string) {
	if len(legacy) > 0 && len(rules.Match) == 0 && len(rules.NotMatch) == 0 {
		rules = MergeSelectorRules(legacy, AgentSelectorRules{})
	}
	if len(rules.Match) == 0 && len(rules.NotMatch) == 0 {
		return true, ""
	}
	if strings.TrimSpace(nodeTags) == "" {
		return false, "节点缺少标签"
	}
	tagMap := map[string]string{}
	if err := json.Unmarshal([]byte(nodeTags), &tagMap); err != nil {
		return false, "节点标签不是合法 JSON"
	}
	if len(tagMap) == 0 {
		return false, "节点缺少标签"
	}
	for key, values := range rules.Match {
		nodeVal, ok := tagMap[key]
		if !ok {
			return false, fmt.Sprintf("缺少标签 %s=%s", key, strings.Join(values, "|"))
		}
		if tagValueMatches(nodeVal, values) {
			continue
		}
		return false, fmt.Sprintf("标签 %s=%s 不匹配 %s", key, nodeVal, strings.Join(values, "|"))
	}
	for key, values := range rules.NotMatch {
		nodeVal, ok := tagMap[key]
		if !ok {
			continue
		}
		if tagValueMatches(nodeVal, values) {
			return false, fmt.Sprintf("标签 %s=%s 命中排除规则", key, nodeVal)
		}
	}
	return true, ""
}

func tagValueMatches(nodeVal string, values []string) bool {
	n := strings.ToLower(strings.TrimSpace(nodeVal))
	if n == "all" || n == "any" || n == "*" {
		return true
	}
	for _, val := range values {
		if nodeVal == val {
			return true
		}
	}
	return false
}
