package arsenal

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// ExportFingerYAML 将数据库中启用的指纹导出为 finger.yaml 格式。
// 格式: map[productName][]ruleExpr
func ExportFingerYAML() ([]byte, error) {
	fingers, err := GetAllEnabledFingerprints()
	if err != nil {
		return nil, fmt.Errorf("查询指纹失败: %w", err)
	}

	grouped := make(map[string][]string)
	for _, f := range fingers {
		grouped[f.ProductName] = append(grouped[f.ProductName], f.RuleExpr)
	}

	// 按产品名排序
	return marshalOrderedMap(grouped)
}

// ExportWorkflowYAML 将数据库中启用的 Workflow 导出为 workflow.yaml 格式。
// 格式: map[productName]{type: []string, pocs: []string}
func ExportWorkflowYAML() ([]byte, error) {
	workflows, err := GetAllEnabledWorkflows()
	if err != nil {
		return nil, fmt.Errorf("查询 Workflow 失败: %w", err)
	}
	// 关联 POC 风险等级（重名取最严格），供 Agent 本地预授权门过滤。
	pocs, err := GetAllEnabledPocs()
	if err != nil {
		return nil, fmt.Errorf("查询 POC 风险等级失败: %w", err)
	}
	riskByPoc := make(map[string]string, len(pocs))
	for _, p := range pocs {
		existing, exists := riskByPoc[p.Name]
		if !exists || pocRiskRank(p.RiskLevel) > pocRiskRank(existing) {
			existing = p.RiskLevel
		}
		riskByPoc[p.Name] = existing
	}

	type exportEntry struct {
		Type      []string `yaml:"type"`
		Pocs      []string `yaml:"pocs"`
		RiskLevel string   `yaml:"risk_level"`
	}

	grouped := make(map[string]*exportEntry)
	for _, w := range workflows {
		entry, ok := grouped[w.ProductName]
		if !ok {
			entry = &exportEntry{}
			grouped[w.ProductName] = entry
		}
		if pocRiskRank(w.RiskLevel) > pocRiskRank(entry.RiskLevel) {
			entry.RiskLevel = strings.ToLower(strings.TrimSpace(w.RiskLevel))
		}
		// 添加 match type（去重）
		found := false
		for _, t := range entry.Type {
			if t == w.MatchType {
				found = true
				break
			}
		}
		if !found {
			entry.Type = append(entry.Type, w.MatchType)
		}
		// 添加 poc name（去重）
		pocFound := false
		for _, p := range entry.Pocs {
			if p == w.PocName {
				pocFound = true
				break
			}
		}
		if !pocFound {
			entry.Pocs = append(entry.Pocs, w.PocName)
		}
	}

	// 按产品名排序输出
	keys := make([]string, 0, len(grouped))
	for k := range grouped {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	ordered := yaml.Node{Kind: yaml.MappingNode}
	for _, k := range keys {
		entry := grouped[k]
		keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: k}
		sort.Strings(entry.Type)
		sort.Strings(entry.Pocs)
		typeNode := &yaml.Node{Kind: yaml.SequenceNode}
		for _, t := range entry.Type {
			typeNode.Content = append(typeNode.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: t})
		}
		pocNode := &yaml.Node{Kind: yaml.SequenceNode}
		for _, p := range entry.Pocs {
			pocNode.Content = append(pocNode.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: p})
		}
		valNode := &yaml.Node{Kind: yaml.MappingNode}
		if entry.RiskLevel == "" {
			entry.RiskLevel = "unknown"
		}
		valNode.Content = append(valNode.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: "type"}, typeNode,
			&yaml.Node{Kind: yaml.ScalarNode, Value: "pocs"}, pocNode,
			&yaml.Node{Kind: yaml.ScalarNode, Value: "risk_level"}, &yaml.Node{Kind: yaml.ScalarNode, Value: entry.RiskLevel},
		)
		ordered.Content = append(ordered.Content, keyNode, valNode)
	}

	return yaml.Marshal(&ordered)
}

// pocRiskRank 将风险等级映射为严重度序（重名模板取最严格等级）。
func pocRiskRank(riskLevel string) int {
	switch strings.ToLower(strings.TrimSpace(riskLevel)) {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// ExportDirYAML 将数据库中启用的探测路径导出为 dir.yaml 格式。
// 格式: map[productName][]path
func ExportDirYAML() ([]byte, error) {
	probes, err := GetAllEnabledDirProbes()
	if err != nil {
		return nil, fmt.Errorf("查询探测路径失败: %w", err)
	}

	grouped := make(map[string][]string)
	for _, p := range probes {
		grouped[p.ProductName] = append(grouped[p.ProductName], p.Path)
	}

	return marshalOrderedMap(grouped)
}

// marshalOrderedMap 将 map[string][]string 按 key 排序后输出 YAML。
func marshalOrderedMap(m map[string][]string) ([]byte, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteString(":\n")
		for _, v := range m[k] {
			sb.WriteString("  - '")
			sb.WriteString(strings.ReplaceAll(v, "'", "''"))
			sb.WriteString("'\n")
		}
	}
	return []byte(sb.String()), nil
}
