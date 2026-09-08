package db

import (
	"encoding/json"
	"strings"
)

const (
	FingerprintSourcePassive   = "passive"
	FingerprintSourceDirectory = "directory"
	FingerprintSourceBehavior  = "behavior"
	FingerprintSourceFallback  = "fallback"
)

var fingerprintSourceOrder = []string{
	FingerprintSourceDirectory,
	FingerprintSourceBehavior,
	FingerprintSourceFallback,
	FingerprintSourcePassive,
}

func FingerprintSourceLabel(source string) string {
	switch strings.TrimSpace(source) {
	case FingerprintSourceDirectory:
		return "主动路径"
	case FingerprintSourceBehavior:
		return "行为探针"
	case FingerprintSourceFallback:
		return "路径推断"
	default:
		return "被动命中"
	}
}

func fingerprintNote(payload map[string]interface{}) string {
	if payload == nil {
		return ""
	}
	return strings.TrimSpace(payloadString(payload, "am") + " " + payloadString(payload, "additional_msg"))
}

func fingerprintRuleName(payloadType string, payload map[string]interface{}) string {
	note := strings.ToLower(fingerprintNote(payload))
	if strings.Contains(note, "[dir-fallback]") {
		return "dir-fallback"
	}
	if strings.Contains(note, "[behavior-probe:") {
		return "behavior-probe"
	}
	switch payloadType {
	case "Active-Finger":
		return "Active-Finger"
	case "Finger":
		return "Finger"
	default:
		return payloadType
	}
}

func ClassifyFingerprintSource(ruleName, evidence string) string {
	blob := strings.ToLower(strings.TrimSpace(ruleName) + "\n" + strings.TrimSpace(evidence))
	if strings.Contains(blob, "[dir-fallback]") || strings.EqualFold(strings.TrimSpace(ruleName), "dir-fallback") {
		return FingerprintSourceFallback
	}
	if strings.Contains(blob, "[behavior-probe:") || strings.EqualFold(strings.TrimSpace(ruleName), "behavior-probe") {
		return FingerprintSourceBehavior
	}
	if strings.EqualFold(strings.TrimSpace(ruleName), "Active-Finger") ||
		strings.Contains(blob, `"type":"active-finger"`) ||
		strings.Contains(blob, `"type": "active-finger"`) {
		return FingerprintSourceDirectory
	}
	return FingerprintSourcePassive
}

func FingerprintMatchedURL(target, evidence string) string {
	target = strings.TrimSpace(target)
	if strings.TrimSpace(evidence) == "" {
		return target
	}
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(evidence), &payload); err != nil {
		return target
	}
	if uri := payloadString(payload, "uri"); uri != "" {
		return uri
	}
	return target
}

func UniqueFingerprintSources(sources []string) []string {
	seen := make(map[string]struct{}, len(sources))
	ordered := make([]string, 0, len(fingerprintSourceOrder))
	for _, source := range fingerprintSourceOrder {
		for _, candidate := range sources {
			if candidate != source {
				continue
			}
			if _, ok := seen[source]; ok {
				continue
			}
			seen[source] = struct{}{}
			ordered = append(ordered, source)
		}
	}
	return ordered
}

func FingerprintSourceLabels(sources []string) []string {
	labels := make([]string, 0, len(sources))
	for _, source := range UniqueFingerprintSources(sources) {
		labels = append(labels, FingerprintSourceLabel(source))
	}
	return labels
}
