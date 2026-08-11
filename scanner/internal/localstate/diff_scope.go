package localstate

import (
	"encoding/binary"
	"net"
	"net/url"
	"strings"
	"time"

	"dddd/scanner/structs"
	"dddd/scanner/utils"
	"github.com/user/dddd-proto/go/scanplan"
)

type comparisonEvidence struct {
	target     string
	stage      string
	observedAt time.Time
	runID      string
}

func comparableEvidence(asset AssetRecord, input DifferenceInput) (comparisonEvidence, bool) {
	if !input.Completed || !input.TrustedPreviousRuns[asset.LastRunID] {
		return comparisonEvidence{}, false
	}
	for _, item := range input.Targets {
		target := safeTarget(item.NormalizedTarget)
		stage, owns := authoritativeStage(target, asset.NormalizedTarget)
		if !owns || !strings.EqualFold(strings.TrimSpace(item.Action), "full") {
			continue
		}
		if current, ok := stageEvidenceComparable(asset, target, stage, input); ok {
			return comparisonEvidence{target: target, stage: stage, observedAt: current.ObservedAt, runID: current.LastRunID}, true
		}
	}
	return comparisonEvidence{}, false
}

func contentComparableEvidence(asset AssetRecord, input DifferenceInput) (comparisonEvidence, bool) {
	if !input.Completed || !input.TrustedPreviousRuns[asset.LastRunID] {
		return comparisonEvidence{}, false
	}
	for _, item := range input.Targets {
		target := safeTarget(item.NormalizedTarget)
		action := strings.ToLower(strings.TrimSpace(item.Action))
		if action != "full" && action != "incremental" {
			continue
		}
		stages, owns := contentStages(target, asset.NormalizedTarget)
		if !owns {
			continue
		}
		comparable := true
		var latest RunCoverageRecord
		for _, stage := range stages {
			current, ok := stageEvidenceComparable(asset, target, stage, input)
			if !ok {
				comparable = false
				break
			}
			if current.ObservedAt.After(latest.ObservedAt) {
				latest = current
			}
		}
		if comparable {
			return comparisonEvidence{target: target, stage: strings.Join(stages, ","), observedAt: latest.ObservedAt, runID: latest.LastRunID}, true
		}
	}
	return comparisonEvidence{}, false
}

func stageEvidenceComparable(asset AssetRecord, target, stage string, input DifferenceInput) (RunCoverageRecord, bool) {
	currentRunID := strings.TrimSpace(input.CurrentRunID)
	if currentRunID == "" {
		return RunCoverageRecord{}, false
	}
	var latest RunCoverageRecord
	found := false
	for _, old := range input.PreviousCoverage {
		if old.LastRunID != asset.LastRunID || safeTarget(old.NormalizedTarget) != target || old.Stage != stage || !successfulOutcome(old.Outcome) {
			continue
		}
		for _, current := range input.Coverage {
			if !strings.EqualFold(strings.TrimSpace(current.Action), "executed") || current.LastRunID != currentRunID || safeTarget(current.NormalizedTarget) != target || current.Stage != stage || !successfulOutcome(current.Outcome) {
				continue
			}
			if current.ScopeHash == old.ScopeHash && current.ConfigHash == old.ConfigHash && current.RuleVersion == old.RuleVersion && current.ObservedAt.After(asset.LastSeen) {
				if !found || current.ObservedAt.After(latest.ObservedAt) {
					latest = current
					found = true
				}
			}
		}
	}
	return latest, found
}

func contentStages(inputTarget, assetTarget string) ([]string, bool) {
	stage, owns := authoritativeStage(inputTarget, assetTarget)
	if !owns {
		return nil, false
	}
	stages := []string{stage}
	switch utils.GetInputType(safeTarget(assetTarget)) {
	case structs.TypeURL:
		stages = append(stages, string(scanplan.StageFingerprint))
	case structs.TypeIPPort, structs.TypeDomainPort:
		if stage == string(scanplan.StagePortScan) {
			stages = append(stages, string(scanplan.StageProtocolIdentify))
		}
	}
	if len(stages) == 2 && stages[0] == stages[1] {
		stages = stages[:1]
	}
	return stages, true
}

func successfulOutcome(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "success" || value == "negative"
}

func assetInRunScope(asset AssetRecord, targets []RunTargetRecord) bool {
	_, ok := firstAssetScope(asset, targets)
	return ok
}

func firstAssetScope(asset AssetRecord, targets []RunTargetRecord) (comparisonEvidence, bool) {
	for _, target := range targets {
		normalized := safeTarget(target.NormalizedTarget)
		if stage, ok := authoritativeStage(normalized, asset.NormalizedTarget); ok {
			return comparisonEvidence{target: normalized, stage: stage}, true
		}
	}
	return comparisonEvidence{}, false
}

func authoritativeStage(inputTarget, assetTarget string) (string, bool) {
	inputTarget, assetTarget = safeTarget(inputTarget), safeTarget(assetTarget)
	if inputTarget == "" || assetTarget == "" {
		return "", false
	}
	inputType, assetType := utils.GetInputType(inputTarget), utils.GetInputType(assetTarget)
	if assetType == structs.TypeURL {
		assetURL, err := url.Parse(assetTarget)
		if err != nil || assetURL.Hostname() == "" {
			return "", false
		}
		stage := string(scanplan.StageHTTPProbe)
		if path := strings.TrimSpace(assetURL.EscapedPath()); path != "" && path != "/" {
			stage = string(scanplan.StageDirectoryProbe)
		}
		switch inputType {
		case structs.TypeURL:
			if sameURLScope(inputTarget, assetTarget) {
				return stage, true
			}
		case structs.TypeIP, structs.TypeCIDR, structs.TypeIPRange:
			if targetContainsIP(inputTarget, net.ParseIP(assetURL.Hostname())) {
				return stage, true
			}
		case structs.TypeIPPort, structs.TypeDomainPort:
			host, port, ok := splitPlainHostPort(inputTarget)
			if ok && strings.EqualFold(host, assetURL.Hostname()) && port == effectiveURLPort(assetURL) {
				return stage, true
			}
		case structs.TypeDomain:
			if strings.EqualFold(inputTarget, assetURL.Hostname()) {
				return stage, true
			}
		}
		return "", false
	}
	if assetType == structs.TypeIPPort || assetType == structs.TypeDomainPort {
		assetHost, assetPort, ok := splitPlainHostPort(assetTarget)
		if !ok {
			return "", false
		}
		switch inputType {
		case structs.TypeIP, structs.TypeCIDR, structs.TypeIPRange:
			if targetContainsIP(inputTarget, net.ParseIP(assetHost)) {
				return string(scanplan.StagePortScan), true
			}
		case structs.TypeIPPort, structs.TypeDomainPort:
			inputHost, inputPort, inputOK := splitPlainHostPort(inputTarget)
			if inputOK && strings.EqualFold(inputHost, assetHost) && inputPort == assetPort {
				return string(scanplan.StageProtocolIdentify), true
			}
		}
		return "", false
	}
	if assetType == structs.TypeIP && targetContainsIP(inputTarget, net.ParseIP(assetTarget)) {
		return string(scanplan.StagePortScan), true
	}
	return "", false
}

func sameURLScope(left, right string) bool {
	leftURL, leftErr := url.Parse(left)
	rightURL, rightErr := url.Parse(right)
	if leftErr != nil || rightErr != nil {
		return false
	}
	leftPath, rightPath := leftURL.EscapedPath(), rightURL.EscapedPath()
	if leftPath == "" {
		leftPath = "/"
	}
	if rightPath == "" {
		rightPath = "/"
	}
	return strings.EqualFold(leftURL.Scheme, rightURL.Scheme) && strings.EqualFold(leftURL.Hostname(), rightURL.Hostname()) &&
		effectiveURLPort(leftURL) == effectiveURLPort(rightURL) && leftPath == rightPath
}

func effectiveURLPort(parsed *url.URL) string {
	if port := parsed.Port(); port != "" {
		return port
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}

func splitPlainHostPort(value string) (string, string, bool) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return "", "", false
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), true
}

func targetContainsIP(target string, ip net.IP) bool {
	if ip == nil || ip.To4() == nil {
		return false
	}
	switch utils.GetInputType(target) {
	case structs.TypeIP:
		return net.ParseIP(target).Equal(ip)
	case structs.TypeCIDR:
		_, network, err := net.ParseCIDR(target)
		return err == nil && network.Contains(ip)
	case structs.TypeIPRange:
		parts := strings.SplitN(target, "-", 2)
		if len(parts) != 2 {
			return false
		}
		first, last := net.ParseIP(strings.TrimSpace(parts[0])).To4(), net.ParseIP(strings.TrimSpace(parts[1])).To4()
		if first == nil || last == nil {
			return false
		}
		value := binary.BigEndian.Uint32(ip.To4())
		return value >= binary.BigEndian.Uint32(first) && value <= binary.BigEndian.Uint32(last)
	default:
		return false
	}
}
