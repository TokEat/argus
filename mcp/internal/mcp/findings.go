package mcp

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// argus_findings 是只读结果查询工具：把 Phase-B 内容分析产物
// （爬取关联资产候选 + 敏感信息候选）暴露给外部 AI。所有请求原样转发到
// Server 的 RBAC 收敛端点，Server 仍是身份/租户/审计的权威。

const findingsSummarySampleSize = 200

type findingsFilter struct {
	ProjectID string
	TaskID    string
	Kind      string
	SiteType  string
	AIStatus  string
	Search    string
	Page      int
	PageSize  int
}

func findingsFilterFromArgs(args map[string]interface{}) findingsFilter {
	page := intArgDefault(args, "page", 1)
	if page < 1 {
		page = 1
	}
	pageSize := intArgDefault(args, "page_size", 20)
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 200 {
		pageSize = 200
	}
	return findingsFilter{
		ProjectID: stringArg(args, "project_id"),
		TaskID:    stringArg(args, "task_id"),
		Kind:      stringArg(args, "kind"),
		SiteType:  stringArg(args, "site_type"),
		AIStatus:  stringArg(args, "ai_status"),
		Search:    stringArg(args, "search"),
		Page:      page,
		PageSize:  pageSize,
	}
}

func (f findingsFilter) values() url.Values {
	query := url.Values{}
	if f.ProjectID != "" {
		query.Set("project_id", f.ProjectID)
	}
	if f.TaskID != "" {
		query.Set("task_id", f.TaskID)
	}
	if f.Kind != "" {
		query.Set("kind", f.Kind)
	}
	if f.SiteType != "" {
		query.Set("site_type", f.SiteType)
	}
	if f.AIStatus != "" {
		query.Set("ai_status", f.AIStatus)
	}
	if f.Search != "" {
		query.Set("search", f.Search)
	}
	query.Set("page", strconv.Itoa(f.Page))
	query.Set("page_size", strconv.Itoa(f.PageSize))
	return query
}

type findingsPage struct {
	Items    []map[string]interface{} `json:"items"`
	Total    int64                    `json:"total"`
	Page     int                      `json:"page"`
	PageSize int                      `json:"page_size"`
}

func (c *Client) argusFindings(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	action := strings.ToLower(strings.TrimSpace(stringArg(args, "action")))
	if action == "" {
		action = "summary"
	}
	switch action {
	case "summary":
		return c.findingsSummary(ctx, args)
	case "crawl_sites":
		return c.findingsCrawlSites(ctx, args)
	case "sensitive":
		return c.findingsSensitive(ctx, args)
	default:
		return nil, fmt.Errorf("unsupported action %q for argus_findings (want summary|crawl_sites|sensitive)", action)
	}
}

func (c *Client) findingsCrawlSites(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	filter := findingsFilterFromArgs(args)
	page, err := c.fetchFindingsPage(ctx, "/api/v1/crawl-site-candidates", filter)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"status":     "success",
		"source":     "native_api",
		"action":     "crawl_sites",
		"project_id": filter.ProjectID,
		"task_id":    filter.TaskID,
		"items":      page.Items,
		"total":      page.Total,
		"page":       page.Page,
		"page_size":  page.PageSize,
	}, nil
}

func (c *Client) findingsSensitive(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	filter := findingsFilterFromArgs(args)
	page, err := c.fetchFindingsPage(ctx, "/api/v1/sensitive-findings", filter)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"status":     "success",
		"source":     "native_api",
		"action":     "sensitive",
		"project_id": filter.ProjectID,
		"task_id":    filter.TaskID,
		"items":      page.Items,
		"total":      page.Total,
		"page":       page.Page,
		"page_size":  page.PageSize,
	}, nil
}

func (c *Client) findingsSummary(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	filter := findingsFilterFromArgs(args)
	// summary 在已取窗口内做客户端聚合；total 仍是 Server 的精确计数。
	filter.Page = 1
	filter.PageSize = findingsSummarySampleSize

	crawl, err := c.fetchFindingsPage(ctx, "/api/v1/crawl-site-candidates", filter)
	if err != nil {
		return nil, err
	}
	sensitive, err := c.fetchFindingsPage(ctx, "/api/v1/sensitive-findings", filter)
	if err != nil {
		return nil, err
	}

	bySiteType := map[string]int{}
	byCrawlStatus := map[string]int{}
	for _, item := range crawl.Items {
		siteType := mapString(item, "site_type")
		if siteType == "" {
			siteType = "port_or_subdomain"
		}
		bySiteType[siteType]++
		byCrawlStatus[mapString(item, "ai_status")]++
	}
	byKind := map[string]int{}
	bySensitiveStatus := map[string]int{}
	for _, item := range sensitive.Items {
		byKind[mapString(item, "kind")]++
		bySensitiveStatus[mapString(item, "ai_status")]++
	}

	return map[string]interface{}{
		"status":     "success",
		"source":     "native_api",
		"action":     "summary",
		"project_id": filter.ProjectID,
		"task_id":    filter.TaskID,
		"crawl_sites": map[string]interface{}{
			"total":        crawl.Total,
			"sampled":      len(crawl.Items),
			"by_site_type": bySiteType,
			"by_ai_status": byCrawlStatus,
			"truncated":    crawl.Total > int64(len(crawl.Items)),
		},
		"sensitive": map[string]interface{}{
			"total":        sensitive.Total,
			"sampled":      len(sensitive.Items),
			"by_kind":      byKind,
			"by_ai_status": bySensitiveStatus,
			"truncated":    sensitive.Total > int64(len(sensitive.Items)),
		},
	}, nil
}

func (c *Client) fetchFindingsPage(ctx context.Context, basePath string, filter findingsFilter) (*findingsPage, error) {
	path := basePath
	if encoded := filter.values().Encode(); encoded != "" {
		path += "?" + encoded
	}
	var page findingsPage
	if err := c.do(ctx, http.MethodGet, path, nil, &page); err != nil {
		return nil, err
	}
	return &page, nil
}
