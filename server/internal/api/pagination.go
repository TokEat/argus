package api

import (
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type paginatedResponse struct {
	Items       interface{} `json:"items"`
	Total       int64       `json:"total"`
	Page        int         `json:"page"`
	PageSize    int         `json:"page_size"`
	HasMore     bool        `json:"has_more"`
	RuleVersion string      `json:"rule_version,omitempty"`
	GeneratedAt string      `json:"generated_at"`
}

func parsePagination(c *gin.Context, defaultPageSize, maxPageSize int) (int, int) {
	page := parsePositiveInt(c.Query("page"), 1)
	pageSize := parsePositiveInt(c.Query("page_size"), defaultPageSize)
	if maxPageSize > 0 && pageSize > maxPageSize {
		pageSize = maxPageSize
	}
	return page, pageSize
}

func parsePositiveInt(raw string, fallback int) int {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value < 1 {
		return fallback
	}
	return value
}

func pagedResponse(items interface{}, total int64, page, pageSize int, ruleVersion string) paginatedResponse {
	return paginatedResponse{
		Items:       items,
		Total:       total,
		Page:        page,
		PageSize:    pageSize,
		HasMore:     int64(page*pageSize) < total,
		RuleVersion: strings.TrimSpace(ruleVersion),
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

func currentRuleVersion() string {
	if version := strings.TrimSpace(GetCurrentRuleVersion()); version != "" {
		return version
	}
	return ""
}
