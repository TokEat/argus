// Package mapper 指纹到 PoC 的映射器。
package mapper

import (
	"fmt"
	"github.com/TokEat/argus/scanner/structs"
	"github.com/TokEat/argus/scanner/utils"
	"net/url"
	"strings"

	"github.com/projectdiscovery/gologger"
)

const wafFingerprintSkipThreshold = 10

// GetPocs 根据指纹匹配工作流，返回目标→PoC名称映射。
func GetPocs(resultMap map[string][]string, workFlowDB map[string]structs.WorkFlowEntity, disableGeneralPoc bool, wafSkipOnManyFingerprints bool) (map[string][]string, int) {
	gologger.AuditTimeLogger("根据指纹选择Poc")

	result := make(map[string][]string)
	count := 0

	var generalKeys []string
	if !disableGeneralPoc {
		for name, workflowEntity := range workFlowDB {
			if strings.Contains(name, "General-Poc-") && len(workflowEntity.PocsName) > 0 {
				generalKeys = append(generalKeys, name)
			}
		}
	}

	for target, fingerprints := range resultMap {
		if wafSkipOnManyFingerprints && len(fingerprints) > wafFingerprintSkipThreshold {
			gologger.AuditTimeLogger("[WAF] %s 指纹过多(%d) → 疑似蜜罐/WAF，跳过POC扫描", target, len(fingerprints))
			continue
		}
		gologger.AuditLogger("%s", target+":")
		for _, finger := range fingerprints {
			workflowEntity, ok := workFlowDB[finger]
			if !ok || len(workflowEntity.PocsName) == 0 {
				continue
			}
			count += applyWorkflow(target, workflowEntity, result)
		}

		for _, key := range generalKeys {
			workflowEntity, ok := workFlowDB[key]
			if !ok || len(workflowEntity.PocsName) == 0 {
				continue
			}
			count += applyWorkflow(target, workflowEntity, result)
		}
	}

	return result, count
}

func isHTTPTarget(target string) bool {
	parsed, err := url.Parse(strings.TrimSpace(target))
	if err != nil || parsed.Host == "" {
		return false
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
		return true
	default:
		return false
	}
}

func applyWorkflow(target string, workflowEntity structs.WorkFlowEntity, result map[string][]string) int {
	count := 0

	// Non-HTTP service fingerprints (ssh://, zookeeper://, smb:// ...) still
	// trigger root-level workflow templates. The workflow.yaml entries for
	// those products (SSH, ZooKeeper, SVN ...) point at TCP/network templates
	// (CVE-2001-1473, exposed-zookeeper, exposed-svn ...) which run fine
	// against a service URL; only HTTP path/base/dir expansion is HTTP-only.
	if !isHTTPTarget(target) {
		if !workflowEntity.RootType {
			return 0
		}
		if addPocs(target, result, workflowEntity) {
			count++
		}
		return count
	}

	parsedURL, err := url.Parse(target)
	if err != nil {
		return 0
	}

	if workflowEntity.RootType {
		rootURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
		if addPocs(rootURL, result, workflowEntity) {
			count++
		}
	}

	if parsedURL.Path != "/" && parsedURL.Path != "" && workflowEntity.BaseType {
		if addPocs(target, result, workflowEntity) {
			count++
		}
	}

	if parsedURL.Path != "/" && parsedURL.Path != "" && workflowEntity.DirType {
		splitPath := strings.Split(parsedURL.Path, "/")
		for i := 1; i < len(splitPath); i++ {
			newPath := strings.Join(splitPath[:i], "/")
			nextTarget := fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, newPath)
			if addPocs(nextTarget, result, workflowEntity) {
				count++
			}
		}
	}

	return count
}

func addPocs(target string, result map[string][]string, workflowEntity structs.WorkFlowEntity) bool {
	added := false
	existing := result[target]

	for _, pocName := range workflowEntity.PocsName {
		withSuffix := addYAMLSuffix(pocName)
		if utils.GetItemInArray(existing, withSuffix) != -1 {
			continue
		}
		existing = append(existing, withSuffix)
		gologger.AuditLogger("%s", "    - "+pocName)
		added = true
	}

	if len(existing) > 0 {
		result[target] = existing
	}
	return added
}

func addYAMLSuffix(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, ".yaml") {
		return s
	}
	return s + ".yaml"
}
