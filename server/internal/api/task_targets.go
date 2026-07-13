package api

import (
	"encoding/json"
	"fmt"
	"net/http"
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
