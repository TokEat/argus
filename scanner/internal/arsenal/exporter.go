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

	type exportEntry struct {
		Type []string `yaml:"type"`
		Pocs []string `yaml:"pocs"`
	}

	grouped := make(map[string]*exportEntry)
	for _, w := range workflows {
		entry, ok := grouped[w.ProductName]
		if !ok {
			entry = &exportEntry{}
			grouped[w.ProductName] = entry
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
		valNode := &yaml.Node{}
		b, _ := yaml.Marshal(entry)
		_ = yaml.Unmarshal(b, valNode)
		ordered.Content = append(ordered.Content, keyNode, valNode)
	}

	return yaml.Marshal(&ordered)
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
