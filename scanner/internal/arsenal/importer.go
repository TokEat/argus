package arsenal

import (
	"crypto/md5"
	"embed"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/TokEat/argus/shared/proto/go/activefingerprint"
	"gopkg.in/yaml.v3"
)

// ImportFingerYAML 从 finger.yaml 格式的数据导入指纹。
// 格式: map[productName][]ruleExpr
// 返回新增数、跳过数。
func ImportFingerYAML(data []byte, source string) (added, skipped int, err error) {
	var raw map[string][]string
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return 0, 0, fmt.Errorf("YAML 解析失败: %w", err)
	}

	if source == "" {
		source = "builtin"
	}

	for productName, rules := range raw {
		for _, rule := range rules {
			rule = strings.TrimSpace(rule)
			if rule == "" {
				continue
			}
			f := &Fingerprint{
				ProductName: productName,
				RuleExpr:    rule,
				Category:    "web", // 默认分类
				Source:      source,
				Enabled:     true,
			}
			created, addErr := AddFingerprint(f)
			if addErr != nil {
				skipped++
				continue
			}
			if created {
				added++
			} else {
				skipped++
			}
		}
	}
	return added, skipped, nil
}

// ImportWorkflowYAML 从 workflow.yaml 格式的数据导入 Workflow 映射。
// 格式: map[productName]{type: []string, pocs: []string}
func ImportWorkflowYAML(data []byte) (added, skipped int, err error) {
	type workflowRule struct {
		Type []string `yaml:"type"`
		Pocs []string `yaml:"pocs"`
	}
	var raw map[string]workflowRule
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return 0, 0, fmt.Errorf("YAML 解析失败: %w", err)
	}

	for productName, rule := range raw {
		for _, pocName := range rule.Pocs {
			pocName = strings.TrimSpace(pocName)
			if pocName == "" {
				continue
			}
			for _, matchType := range rule.Type {
				matchType = strings.ToLower(strings.TrimSpace(matchType))
				if matchType == "" {
					continue
				}
				w := &Workflow{
					ProductName: productName,
					PocName:     pocName,
					MatchType:   matchType,
					Enabled:     true,
				}
				created, addErr := AddWorkflow(w)
				if addErr != nil {
					skipped++
					continue
				}
				if created {
					added++
				} else {
					skipped++
				}
			}
		}
	}
	return added, skipped, nil
}

// ImportDirYAML 从 dir.yaml 格式的数据导入主动探测路径。
// 格式: map[productName][]path
func ImportDirYAML(data []byte) (added, skipped int, err error) {
	var raw map[string][]string
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return 0, 0, fmt.Errorf("YAML 解析失败: %w", err)
	}

	for productName, paths := range raw {
		for _, p := range paths {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			d := &DirProbe{
				Path:        p,
				ProductName: productName,
				Enabled:     true,
			}
			created, addErr := AddDirProbe(d)
			if addErr != nil {
				skipped++
				continue
			}
			if created {
				added++
			} else {
				skipped++
			}
		}
	}
	return added, skipped, nil
}

// ImportPocsFromFS 从 embed.FS 或实际路径导入 Nuclei POC 模板。
// 遍历所有 .yaml 文件，解析基础元数据后存入数据库。
func ImportPocsFromFS(pocFS embed.FS, source string) (added, skipped int, err error) {
	if source == "" {
		source = "builtin"
	}

	err = fs.WalkDir(pocFS, ".", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil // 跳过错误
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".yaml") {
			return nil
		}

		content, readErr := fs.ReadFile(pocFS, path)
		if readErr != nil {
			skipped++
			return nil
		}

		meta := parsePocMeta(content)
		if governanceErr := validatePocGovernanceMeta(meta); governanceErr != nil {
			skipped++
			return nil
		}
		name := meta.id
		if name == "" {
			name = strings.TrimSuffix(d.Name(), ".yaml")
		}

		hash := fmt.Sprintf("%x", md5.Sum(content))

		p := &Poc{
			Name:           name,
			FileName:       d.Name(),
			Content:        string(content),
			ContentHash:    hash,
			Severity:       meta.severity,
			ExecutionClass: meta.executionClass,
			RiskLevel:      meta.riskLevel,
			Tags:           meta.tags,
			Author:         meta.author,
			Description:    meta.description,
			Source:         source,
			Enabled:        true,
		}

		created, addErr := AddPoc(p)
		if addErr != nil {
			skipped++
			return nil
		}
		if created {
			added++
		} else {
			skipped++
		}
		return nil
	})
	return
}

// ImportActiveFingerprintsFromFS imports one complete Nuclei HTTP template per
// YAML file. Invalid or controlled templates are not silently promoted into
// the automatic scanner package.
func ImportActiveFingerprintsFromFS(ruleFS embed.FS, source string) (added, skipped int, err error) {
	if source == "" {
		source = "builtin"
	}
	err = fs.WalkDir(ruleFS, ".", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() || (!strings.HasSuffix(strings.ToLower(d.Name()), ".yaml") && !strings.HasSuffix(strings.ToLower(d.Name()), ".yml")) {
			return nil
		}
		content, readErr := fs.ReadFile(ruleFS, path)
		if readErr != nil {
			skipped++
			return nil
		}
		classification, inspectErr := activefingerprint.Inspect(d.Name(), content)
		if inspectErr != nil {
			skipped++
			return nil
		}
		rule := &ActiveFingerprint{
			Name: classification.ID, FileName: d.Name(), ProductName: classification.Product,
			Content: string(content), ContentHash: fmt.Sprintf("%x", md5.Sum(content)),
			AutoEligible: classification.AutoEligible, Enabled: true, Source: source,
		}
		created, addErr := AddActiveFingerprint(rule)
		if addErr != nil {
			skipped++
			return nil
		}
		if created {
			added++
		} else {
			skipped++
		}
		return nil
	})
	return
}

// ImportPocFile 从单个 YAML 文件导入 POC。
func ImportPocFile(content []byte, fileName, source string) (name string, created bool, err error) {
	if source == "" {
		source = "user"
	}

	meta := parsePocMeta(content)
	if err := validatePocGovernanceMeta(meta); err != nil {
		return "", false, err
	}
	name = meta.id
	if name == "" {
		name = strings.TrimSuffix(filepath.Base(fileName), ".yaml")
	}

	hash := fmt.Sprintf("%x", md5.Sum(content))

	p := &Poc{
		Name:           name,
		FileName:       filepath.Base(fileName),
		Content:        string(content),
		ContentHash:    hash,
		Severity:       meta.severity,
		ExecutionClass: meta.executionClass,
		RiskLevel:      meta.riskLevel,
		Tags:           meta.tags,
		Author:         meta.author,
		Description:    meta.description,
		Source:         source,
		Enabled:        true,
	}

	created, err = AddPoc(p)
	return name, created, err
}

// pocMeta 从 YAML 模板提取的基础元数据。
type pocMeta struct {
	id             string
	severity       string
	tags           string
	author         string
	description    string
	executionClass string
	riskLevel      string
}

// parsePocMeta 快速从 Nuclei 模板提取元数据（避免完整 YAML 解析）。
func parsePocMeta(content []byte) pocMeta {
	m := pocMeta{executionClass: "detection", riskLevel: "unknown"}
	var parsed struct {
		Info struct {
			Severity string                 `yaml:"severity"`
			Metadata map[string]interface{} `yaml:"metadata"`
		} `yaml:"info"`
	}
	if err := yaml.Unmarshal(content, &parsed); err == nil {
		m.severity = strings.ToLower(strings.TrimSpace(parsed.Info.Severity))
		for key, value := range parsed.Info.Metadata {
			normalizedKey := strings.ToLower(strings.ReplaceAll(key, "_", "-"))
			switch normalizedKey {
			case "argus-execution-class", "execution-class":
				m.executionClass = strings.ToLower(strings.TrimSpace(fmt.Sprint(value)))
			}
		}
	}
	// 简易行解析，提取 id/severity/tags/author/description
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "id:") {
			m.id = strings.TrimSpace(strings.TrimPrefix(line, "id:"))
		} else if strings.HasPrefix(line, "severity:") {
			if m.severity == "" || m.severity == "info" {
				m.severity = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(line, "severity:")))
			}
		} else if strings.HasPrefix(line, "tags:") {
			m.tags = strings.TrimSpace(strings.TrimPrefix(line, "tags:"))
		} else if strings.HasPrefix(line, "author:") {
			m.author = strings.TrimSpace(strings.TrimPrefix(line, "author:"))
		} else if strings.HasPrefix(line, "description:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "description:"))
			if len(val) > 200 {
				val = val[:200]
			}
			m.description = val
		}
	}
	m.riskLevel = pocRiskLevelFromNucleiSeverity(m.severity)
	if m.severity == "" {
		m.severity = "info"
	}
	if m.executionClass == "" {
		m.executionClass = "detection"
	}
	return m
}

// pocRiskLevelFromNucleiSeverity 与服务端 db.PocRiskLevelFromNucleiSeverity 对齐：
// 执行风险跟 Nuclei info.severity；critical 存成 high；缺省为 unknown。
func pocRiskLevelFromNucleiSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "info":
		return "info"
	case "low":
		return "low"
	case "medium":
		return "medium"
	case "high", "critical":
		return "high"
	default:
		return "unknown"
	}
}

func validatePocGovernanceMeta(meta pocMeta) error {
	switch meta.executionClass {
	case "detection", "verification":
	case "exploit", "exp":
		return fmt.Errorf("POC execution_class %q is not allowed; use a separate EXP package", meta.executionClass)
	default:
		return fmt.Errorf("POC execution_class must be detection or verification")
	}
	switch meta.riskLevel {
	case "unknown", "info", "low", "medium", "high":
		return nil
	default:
		return fmt.Errorf("POC risk_level must be unknown, info, low, medium, or high")
	}
}
