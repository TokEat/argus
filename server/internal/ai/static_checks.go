package ai

import (
	"context"
	"crypto/md5"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/TokEat/argus/server/internal/db"
	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
)

type staticResult struct {
	Issues              []Issue
	DuplicateCandidates []DuplicateCandidate
	TemplateID          string
	Severity            string
	Tags                string
}

var nucleiProtocolKeys = []string{
	"http", "requests", "network", "dns", "tcp", "ssl", "file", "headless", "javascript", "code", "websocket",
}

func runStaticChecks(ctx context.Context, store *gorm.DB, tenantID, fileName, content, contentHash string) staticResult {
	result := staticResult{}
	content = strings.TrimSpace(content)
	if content == "" {
		result.Issues = append(result.Issues, Issue{
			Severity:   "error",
			Category:   "syntax",
			Message:    "POC 内容为空。",
			Suggestion: "补充 Nuclei YAML 模板内容后再分析。",
		})
		return result
	}

	var root yaml.Node
	if err := yaml.Unmarshal([]byte(content), &root); err != nil {
		result.Issues = append(result.Issues, Issue{
			Severity:   "error",
			Category:   "syntax",
			Message:    "YAML 解析失败：" + err.Error(),
			Suggestion: "先修复缩进、冒号、列表等 YAML 语法问题。",
		})
		return result
	}
	doc := documentNode(&root)
	if doc == nil || doc.Kind != yaml.MappingNode {
		result.Issues = append(result.Issues, Issue{
			Severity:   "error",
			Category:   "syntax",
			Message:    "POC 顶层必须是 YAML mapping。",
			Suggestion: "使用 Nuclei 模板结构，例如 id、info、http。",
		})
		return result
	}

	if idNode, ok := mappingValue(doc, "id"); ok {
		result.TemplateID = strings.TrimSpace(idNode.Value)
	}
	if result.TemplateID == "" {
		result.Issues = append(result.Issues, Issue{
			Severity:   "error",
			Category:   "metadata",
			Message:    "缺少顶层 id 字段。",
			Suggestion: "为模板补充稳定且唯一的 id。",
		})
	}

	infoNode, hasInfo := mappingValue(doc, "info")
	if !hasInfo || infoNode.Kind != yaml.MappingNode {
		result.Issues = append(result.Issues, Issue{
			Severity:   "error",
			Category:   "metadata",
			Message:    "缺少 info 元数据块。",
			Suggestion: "补充 info.name、info.author、info.severity 等字段。",
		})
	} else {
		checkInfoBlock(infoNode, &result)
	}

	protocols := protocolNodes(doc)
	if len(protocols) == 0 {
		result.Issues = append(result.Issues, Issue{
			Severity:   "error",
			Category:   "protocol",
			Message:    "未发现可执行的 Nuclei 协议块。",
			Suggestion: "至少补充 http、requests、network、dns 等协议块之一。",
		})
	}
	for key, node := range protocols {
		checkProtocolBlock(key, node, &result)
	}
	checkDangerousPayloads(doc, &result)

	if store != nil && contentHash != "" {
		result.DuplicateCandidates = findDuplicateCandidates(ctx, store, tenantID, fileName, result.TemplateID, contentHash)
		checkWorkflowUsage(ctx, store, tenantID, fileName, result.TemplateID, &result)
	}
	return result
}

func checkInfoBlock(infoNode *yaml.Node, result *staticResult) {
	if nameNode, ok := mappingValue(infoNode, "name"); !ok || strings.TrimSpace(nameNode.Value) == "" {
		result.Issues = append(result.Issues, Issue{
			Severity:   "warning",
			Category:   "metadata",
			Message:    "info.name 为空。",
			Suggestion: "补充清晰的漏洞或检测名称，方便运营检索。",
		})
	}
	if severityNode, ok := mappingValue(infoNode, "severity"); ok {
		result.Severity = strings.ToLower(strings.TrimSpace(severityNode.Value))
		if !validSeverity(result.Severity) {
			result.Issues = append(result.Issues, Issue{
				Severity:   "warning",
				Category:   "metadata",
				Message:    "info.severity 不在标准严重度集合中。",
				Suggestion: "使用 info、low、medium、high、critical 之一。",
			})
		}
	} else {
		result.Issues = append(result.Issues, Issue{
			Severity:   "warning",
			Category:   "metadata",
			Message:    "缺少 info.severity。",
			Suggestion: "补充 info.severity，避免规则进入默认 info 严重度。",
		})
	}
	if tagsNode, ok := mappingValue(infoNode, "tags"); ok {
		result.Tags = strings.TrimSpace(tagsNode.Value)
	}
}

func checkProtocolBlock(key string, node *yaml.Node, result *staticResult) {
	if (key == "http" || key == "requests") && !nodeHasAnyKey(node, "path", "raw") {
		result.Issues = append(result.Issues, Issue{
			Severity:   "warning",
			Category:   "protocol",
			Message:    fmt.Sprintf("%s 协议块缺少 path/raw 请求定义。", key),
			Suggestion: "确认模板包含明确的请求路径或 raw 请求。",
		})
	}
	if !nodeHasAnyKey(node, "matchers", "extractors") {
		result.Issues = append(result.Issues, Issue{
			Severity:   "error",
			Category:   "detection",
			Message:    fmt.Sprintf("%s 协议块缺少 matchers/extractors。", key),
			Suggestion: "至少补充一个 matcher 或 extractor，降低误报风险。",
		})
	}
}

func checkDangerousPayloads(doc *yaml.Node, result *staticResult) {
	criticalTerms := []string{"rm -rf", "drop table", "runtime.getruntime", "/bin/bash", "cmd.exe", "powershell", "nc -e", "bash -i"}
	warningTerms := []string{"{{interactsh-url}}", "interactsh", "dnslog", "ldap://", "rmi://"}

	seenCritical := false
	seenWarning := false
	walkScalars(doc, func(line int, value string) {
		lower := strings.ToLower(value)
		if !seenCritical {
			for _, term := range criticalTerms {
				if strings.Contains(lower, term) {
					result.Issues = append(result.Issues, Issue{
						Severity:   "critical",
						Category:   "safety",
						Message:    "检测到可能具有破坏性或命令执行副作用的 payload。",
						Line:       line,
						Suggestion: "确认该 payload 只用于授权验证，并优先改为无害验证方式。",
					})
					seenCritical = true
					break
				}
			}
		}
		if !seenWarning {
			for _, term := range warningTerms {
				if strings.Contains(lower, term) {
					result.Issues = append(result.Issues, Issue{
						Severity:   "warning",
						Category:   "callback",
						Message:    "模板依赖外部回连或 OOB 验证。",
						Line:       line,
						Suggestion: "确认运行环境已配置回连能力，并标注该依赖。",
					})
					seenWarning = true
					break
				}
			}
		}
	})
}

func findDuplicateCandidates(ctx context.Context, store *gorm.DB, tenantID, fileName, templateID, contentHash string) []DuplicateCandidate {
	names := candidateNames(fileName, templateID)
	var rules []db.PocRule
	query := store.WithContext(ctx).Where("tenant_id = ?", tenantID)
	if len(names) > 0 {
		query = query.Where("content_hash = ? OR lower(source_file) IN ? OR lower(name) IN ?", contentHash, names, names)
	} else {
		query = query.Where("content_hash = ?", contentHash)
	}
	if err := query.Limit(8).Find(&rules).Error; err != nil {
		return nil
	}

	out := make([]DuplicateCandidate, 0, len(rules))
	for _, rule := range rules {
		if strings.EqualFold(rule.SourceFile, fileName) && rule.ContentHash == contentHash {
			continue
		}
		reason := "名称或模板 id 相似"
		score := 0.82
		if rule.ContentHash == contentHash {
			reason = "内容 hash 完全一致"
			score = 1
		}
		out = append(out, DuplicateCandidate{
			FileName:    rule.SourceFile,
			Name:        rule.Name,
			Severity:    rule.Severity,
			ContentHash: rule.ContentHash,
			Reason:      reason,
			Score:       score,
		})
	}
	return out
}

func checkWorkflowUsage(ctx context.Context, store *gorm.DB, tenantID, fileName, templateID string, result *staticResult) {
	names := candidateNames(fileName, templateID)
	if len(names) == 0 {
		return
	}
	var count int64
	if err := store.WithContext(ctx).Model(&db.WorkflowRule{}).
		Where("tenant_id = ? AND lower(poc_name) IN ?", tenantID, names).
		Count(&count).Error; err != nil || count > 0 {
		return
	}
	result.Issues = append(result.Issues, Issue{
		Severity:   "warning",
		Category:   "workflow",
		Message:    "该 POC 当前未被任何 Workflow 引用。",
		Suggestion: "如需扫描器主动触发，请在 Workflow 中挂载该 POC。",
	})
}

func candidateNames(fileName, templateID string) []string {
	seen := map[string]bool{}
	var names []string
	add := func(value string) {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" || seen[value] {
			return
		}
		seen[value] = true
		names = append(names, value)
	}
	add(fileName)
	ext := filepath.Ext(fileName)
	if ext != "" {
		add(strings.TrimSuffix(fileName, ext))
	}
	add(templateID)
	if templateID != "" {
		add(templateID + ".yaml")
		add(templateID + ".yml")
	}
	return names
}

func protocolNodes(doc *yaml.Node) map[string]*yaml.Node {
	out := map[string]*yaml.Node{}
	for _, key := range nucleiProtocolKeys {
		if node, ok := mappingValue(doc, key); ok {
			out[key] = node
		}
	}
	return out
}

func documentNode(root *yaml.Node) *yaml.Node {
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		return root.Content[0]
	}
	return root
}

func mappingValue(node *yaml.Node, key string) (*yaml.Node, bool) {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil, false
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if strings.EqualFold(node.Content[i].Value, key) {
			return node.Content[i+1], true
		}
	}
	return nil, false
}

func nodeHasAnyKey(node *yaml.Node, keys ...string) bool {
	if node == nil {
		return false
	}
	switch node.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			for _, key := range keys {
				if strings.EqualFold(node.Content[i].Value, key) {
					return true
				}
			}
			if nodeHasAnyKey(node.Content[i+1], keys...) {
				return true
			}
		}
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, child := range node.Content {
			if nodeHasAnyKey(child, keys...) {
				return true
			}
		}
	}
	return false
}

func walkScalars(node *yaml.Node, visit func(line int, value string)) {
	if node == nil {
		return
	}
	if node.Kind == yaml.ScalarNode {
		visit(node.Line, node.Value)
	}
	for _, child := range node.Content {
		walkScalars(child, visit)
	}
}

func validSeverity(severity string) bool {
	switch severity {
	case "info", "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}

func contentMD5(content string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(content)))
}
