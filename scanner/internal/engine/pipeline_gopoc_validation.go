package engine

import (
	"fmt"
	"sort"
	"strings"

	"github.com/TokEat/argus/shared/proto/go/scanpolicy"
	nucleiOutput "github.com/projectdiscovery/nuclei/v3/pkg/output"
)

func normalizedRiskValidationGoPocTargets(cfg *Config) ([]scanpolicy.GoPocTarget, int64, error) {
	if cfg == nil || !strings.EqualFold(strings.TrimSpace(cfg.ExecutionMode), "risk_validation") {
		return nil, 0, fmt.Errorf("risk validation execution mode is required")
	}
	if len(cfg.RiskValidationGoPocTargets) == 0 {
		return nil, 0, nil
	}
	if strings.ToLower(strings.TrimSpace(cfg.GoPocCatalogSHA256)) != scanpolicy.GoPocCatalogSHA256() {
		return nil, 0, fmt.Errorf("GoPoc catalog changed after the risk plan was sealed")
	}
	allowed := make(map[string]struct{}, len(cfg.Targets))
	for _, target := range cfg.Targets {
		allowed[strings.TrimSpace(target)] = struct{}{}
	}
	items := append([]scanpolicy.GoPocTarget(nil), cfg.RiskValidationGoPocTargets...)
	seen := make(map[string]struct{}, len(items))
	var cost int64
	for _, item := range items {
		if _, ok := allowed[strings.TrimSpace(item.Target)]; !ok {
			return nil, 0, fmt.Errorf("GoPoc risk target %q is outside the dispatched batch", item.Target)
		}
		if err := scanpolicy.ValidateGoPocTarget(item, scanpolicy.GoPocVulnerabilityCheck); err != nil {
			return nil, 0, err
		}
		key := strings.ToLower(strings.TrimSpace(item.Target)) + "\x00" + item.Plugin
		if _, duplicate := seen[key]; duplicate {
			return nil, 0, fmt.Errorf("duplicate GoPoc risk target %q for plugin %q", item.Target, item.Plugin)
		}
		seen[key] = struct{}{}
		cost += int64(item.RequestCost)
	}
	if cost < 1 || cost > cfg.ValidationRequestBudget {
		return nil, 0, fmt.Errorf("GoPoc risk plan exceeds the sealed request budget")
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Target == items[j].Target {
			return items[i].Plugin < items[j].Plugin
		}
		return items[i].Target < items[j].Target
	})
	return items, cost, nil
}

func activatedRiskGoPocTargets(items []scanpolicy.GoPocTarget, results []nucleiOutput.ResultEvent) []scanpolicy.GoPocTarget {
	positive := make(map[string]struct{}, len(results))
	for _, result := range results {
		template := strings.ToLower(strings.TrimSpace(result.TemplateID))
		for _, target := range []string{result.Matched, result.URL} {
			target = strings.TrimSpace(target)
			if target != "" {
				positive[template+"\x00"+target] = struct{}{}
			}
		}
	}
	activated := make([]scanpolicy.GoPocTarget, 0, len(items))
	for _, item := range items {
		parts := strings.SplitN(strings.ToLower(strings.TrimSpace(item.Trigger)), ":", 2)
		if len(parts) == 2 && parts[0] == "nuclei" {
			if _, ok := positive[parts[1]+"\x00"+strings.TrimSpace(item.Target)]; !ok {
				continue
			}
		}
		activated = append(activated, item)
	}
	return activated
}
