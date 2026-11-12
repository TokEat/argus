package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

func validateTargets(c *gin.Context) {
	var req struct {
		Targets json.RawMessage `json:"targets"`
		Config  json.RawMessage `json:"config"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, targetMode, err := normalizeTaskConfigPayload(req.Config)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	targets, err := parseTargets(req.Targets)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	targets = normalizeTargetsForMode(targets, targetMode)
	valid, invalid, summary := classifyTargets(targets, targetMode)
	c.JSON(http.StatusOK, gin.H{"valid": valid, "invalid": invalid, "summary": summary})
}

func parseTargets(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}

	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}

	var targets []string
	switch trimmed[0] {
	case '"':
		var input string
		if err := json.Unmarshal(raw, &input); err != nil {
			return nil, err
		}
		targets = splitTargets(input)
	case '[':
		if err := json.Unmarshal(raw, &targets); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("targets must be a string or string array")
	}

	return dedupeStrings(targets), nil
}

func splitTargets(input string) []string {
	input = strings.ReplaceAll(input, "\r\n", "\n")
	input = strings.ReplaceAll(input, ",", "\n")
	parts := strings.Split(input, "\n")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func dedupeStrings(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func normalizeTargetsForMode(items []string, mode taskTargetMode) []string {
	seen := make(map[string]struct{}, len(items))
	normalized := make([]string, 0, len(items))
	for _, item := range items {
		item = normalizeTaskTarget(item, mode)
		if item == "" {
			continue
		}
		if _, exists := seen[item]; exists {
			continue
		}
		seen[item] = struct{}{}
		normalized = append(normalized, item)
	}
	return normalized
}

func normalizeTaskTarget(raw string, mode taskTargetMode) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || mode != taskTargetModeDirect {
		return raw
	}
	if canonical, ok := canonicalizeURLTarget(raw); ok {
		return canonical
	}

	targetType := detectDirectTargetType(raw)
	if targetType == "" {
		// The validators intentionally accept DNS labels case-insensitively, while
		// URL paths and search queries must retain their original case.
		targetType = detectDirectTargetType(strings.ToLower(raw))
	}
	switch targetType {
	case "ip":
		if parsed := net.ParseIP(raw); parsed != nil {
			return parsed.String()
		}
	case "cidr":
		if _, network, err := net.ParseCIDR(raw); err == nil {
			return network.String()
		}
	case "ip_range":
		parts := strings.SplitN(raw, "-", 2)
		if len(parts) == 2 {
			start := net.ParseIP(strings.TrimSpace(parts[0]))
			end := net.ParseIP(strings.TrimSpace(parts[1]))
			if start != nil && end != nil {
				return start.String() + "-" + end.String()
			}
		}
	case "ip_port":
		parts := strings.SplitN(raw, ":", 2)
		if len(parts) == 2 {
			ip := net.ParseIP(parts[0])
			port, err := strconv.Atoi(parts[1])
			if ip != nil && err == nil {
				return fmt.Sprintf("%s:%d", ip.String(), port)
			}
		}
	case "domain":
		return strings.ToLower(raw)
	case "domain_port":
		parts := strings.SplitN(raw, ":", 2)
		if len(parts) == 2 {
			port, err := strconv.Atoi(parts[1])
			if err == nil {
				return fmt.Sprintf("%s:%d", strings.ToLower(parts[0]), port)
			}
		}
	case "url":
		if canonical, ok := canonicalizeURLTarget(raw); ok {
			return canonical
		}
	}
	return raw
}

func canonicalizeURLTarget(raw string) (string, bool) {
	if !strings.Contains(raw, "://") {
		return "", false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil {
		return "", false
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	host := strings.ToLower(parsed.Hostname())
	if port := parsed.Port(); port != "" {
		host += ":" + port
	}
	parsed.Host = host
	parsed.Fragment = ""
	if parsed.Path == "/" && parsed.RawQuery == "" {
		parsed.Path = ""
	}
	canonical := parsed.String()
	if detectDirectTargetType(canonical) != "url" {
		return "", false
	}
	return canonical, true
}
