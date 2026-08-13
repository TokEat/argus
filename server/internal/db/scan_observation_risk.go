package db

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

func riskValidationPOCSetHash(config, target string) (string, bool) {
	var internal struct {
		ExecutionMode              string
		RiskValidationTargets      map[string][]string
		RiskValidationPocHashes    map[string]string
		GoPocCatalogSHA256         string
		RiskValidationGoPocTargets []struct {
			Target, Plugin, Capability, Trigger, ObservationSHA256 string
			PluginRevision, RequestCost                            int
		}
	}
	if json.Unmarshal([]byte(config), &internal) != nil || !strings.EqualFold(strings.TrimSpace(internal.ExecutionMode), "risk_validation") {
		return "", false
	}
	pocs := append([]string(nil), internal.RiskValidationTargets[target]...)
	sort.Strings(pocs)
	parts := make([]string, 0, len(pocs)+len(internal.RiskValidationGoPocTargets))
	for _, poc := range pocs {
		poc = strings.TrimSpace(poc)
		hash := strings.ToLower(strings.TrimSpace(internal.RiskValidationPocHashes[poc]))
		if poc == "" || hash == "" {
			return "", false
		}
		parts = append(parts, strings.Join([]string{"nuclei", poc, hash}, "\x00"))
	}
	for _, item := range internal.RiskValidationGoPocTargets {
		if strings.TrimSpace(item.Target) != target {
			continue
		}
		if strings.TrimSpace(internal.GoPocCatalogSHA256) == "" || item.Plugin == "" || item.PluginRevision < 1 || item.RequestCost < 1 || item.ObservationSHA256 == "" {
			return "", false
		}
		parts = append(parts, strings.Join([]string{"gopoc", internal.GoPocCatalogSHA256, item.Plugin, item.Capability, item.Trigger, item.ObservationSHA256, fmt.Sprint(item.PluginRevision), fmt.Sprint(item.RequestCost)}, "\x00"))
	}
	if len(parts) == 0 {
		return "", false
	}
	sort.Strings(parts)
	return sha256Hex([]byte(strings.Join(parts, "\x00"))), true
}
