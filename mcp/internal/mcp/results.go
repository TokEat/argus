package mcp

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// argus_results 是只读扫描结果查询工具：把调度扫描的核心产物
// （漏洞 / 资产 / 指纹命中）暴露给外部 AI，其中 vuln_detail 携带完整
// POC 证据包（Request/Response 原文 + AI 研判 + 资产血缘）。所有请求
// 原样转发到 Server 的 RBAC 收敛端点，Server 仍是权威。

const resultsSummarySampleSize = 200

type resultsFilter struct {
	ProjectID string
	TaskID    string
	Search    string
	Sort      string
	Order     string
	GroupBy   string
	Page      int
	PageSize  int
}

func resultsFilterFromArgs(args map[string]interface{}) resultsFilter {
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
	return resultsFilter{
		ProjectID: stringArg(args, "project_id"),
		TaskID:    stringArg(args, "task_id"),
		Search:    stringArg(args, "search"),
		Sort:      stringArg(args, "sort"),
		Order:     stringArg(args, "order"),
		GroupBy:   stringArg(args, "group_by"),
		Page:      page,
		PageSize:  pageSize,
	}
}

func (f resultsFilter) values() url.Values {
	query := url.Values{}
	if f.ProjectID != "" {
		query.Set("project_id", f.ProjectID)
	}
	if f.TaskID != "" {
		query.Set("task_id", f.TaskID)
	}
	if f.Search != "" {
		query.Set("search", f.Search)
	}
	if f.Sort != "" {
		query.Set("sort", f.Sort)
	}
	if f.Order != "" {
		query.Set("order", f.Order)
	}
	if f.GroupBy != "" {
		query.Set("group_by", f.GroupBy)
	}
	query.Set("page", strconv.Itoa(f.Page))
	query.Set("page_size", strconv.Itoa(f.PageSize))
	return query
}

func (c *Client) argusResults(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	action := strings.ToLower(strings.TrimSpace(stringArg(args, "action")))
	if action == "" {
		action = "summary"
	}
	switch action {
	case "summary":
		return c.resultsSummary(ctx, args)
	case "vulns":
		return c.resultsList(ctx, args, "vulns", "/api/v1/vulns")
	case "assets":
		return c.resultsList(ctx, args, "assets", "/api/v1/assets")
	case "fingerprints":
		return c.resultsList(ctx, args, "fingerprints", "/api/v1/fingerprints")
	case "vuln_detail":
		return c.vulnDetail(ctx, args)
	default:
		return nil, fmt.Errorf("unsupported action %q for argus_results (want summary|vulns|vuln_detail|assets|fingerprints)", action)
	}
}

func (c *Client) resultsList(ctx context.Context, args map[string]interface{}, action, basePath string) (interface{}, error) {
	filter := resultsFilterFromArgs(args)
	page, err := c.fetchResultsPage(ctx, basePath, filter)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"status":     "success",
		"source":     "native_api",
		"action":     action,
		"project_id": filter.ProjectID,
		"task_id":    filter.TaskID,
		"items":      page.Items,
		"total":      page.Total,
		"page":       page.Page,
		"page_size":  page.PageSize,
	}, nil
}

func (c *Client) resultsSummary(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	filter := resultsFilterFromArgs(args)
	filter.Page = 1
	filter.PageSize = resultsSummarySampleSize

	vulns, err := c.fetchResultsPage(ctx, "/api/v1/vulns", filter)
	if err != nil {
		return nil, err
	}
	assets, err := c.fetchResultsPage(ctx, "/api/v1/assets", filter)
	if err != nil {
		return nil, err
	}
	fingerprints, err := c.fetchResultsPage(ctx, "/api/v1/fingerprints", filter)
	if err != nil {
		return nil, err
	}

	bySeverity := map[string]int{}
	byStatus := map[string]int{}
	for _, item := range vulns.Items {
		bySeverity[mapString(item, "Severity")]++
		byStatus[mapString(item, "Status")]++
	}
	byProtocol := map[string]int{}
	for _, item := range assets.Items {
		byProtocol[mapString(item, "Protocol")]++
	}
	byProduct := map[string]int{}
	for _, item := range fingerprints.Items {
		byProduct[mapString(item, "ProductName")]++
	}

	return map[string]interface{}{
		"status":     "success",
		"source":     "native_api",
		"action":     "summary",
		"project_id": filter.ProjectID,
		"task_id":    filter.TaskID,
		"vulns": map[string]interface{}{
			"total":       vulns.Total,
			"sampled":     len(vulns.Items),
			"by_severity": bySeverity,
			"by_status":   byStatus,
			"truncated":   vulns.Total > int64(len(vulns.Items)),
		},
		"assets": map[string]interface{}{
			"total":       assets.Total,
			"sampled":     len(assets.Items),
			"by_protocol": byProtocol,
			"truncated":   assets.Total > int64(len(assets.Items)),
		},
		"fingerprints": map[string]interface{}{
			"total":      fingerprints.Total,
			"sampled":    len(fingerprints.Items),
			"by_product": topNCounts(byProduct, 20),
			"truncated":  fingerprints.Total > int64(len(fingerprints.Items)),
		},
	}, nil
}

// vulnDetail 聚合单条漏洞的全量字段：POC 证据包（request/response 原文）、
// AI 研判结论与资产血缘。id + project_id 必填。
func (c *Client) vulnDetail(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	id := stringArg(args, "id")
	if id == "" {
		return nil, fmt.Errorf("id is required for action=vuln_detail")
	}
	projectID := stringArg(args, "project_id")
	if projectID == "" {
		return nil, fmt.Errorf("project_id is required for action=vuln_detail")
	}
	base := "/api/v1/vulns/" + url.PathEscape(id)

	var vuln map[string]interface{}
	if err := c.do(ctx, http.MethodGet, base+"?project_id="+url.QueryEscape(projectID), nil, &vuln); err != nil {
		return nil, err
	}

	var aiReview map[string]interface{}
	aiErr := c.do(ctx, http.MethodGet, base+"/ai-review", nil, &aiReview)
	var lineage map[string]interface{}
	lineageErr := c.do(ctx, http.MethodGet, base+"/lineage?project_id="+url.QueryEscape(projectID), nil, &lineage)

	result := map[string]interface{}{
		"status":        "success",
		"source":        "native_api",
		"action":        "vuln_detail",
		"project_id":    projectID,
		"id":            id,
		"vulnerability": vuln,
		"ai_review":     aiReview,
		"lineage":       mapAny(lineage, "nodes"),
	}
	if aiErr != nil || lineageErr != nil {
		result["detail_errors"] = map[string]string{
			"ai_review": errString(aiErr),
			"lineage":   errString(lineageErr),
		}
	}
	return result, nil
}

func (c *Client) fetchResultsPage(ctx context.Context, basePath string, filter resultsFilter) (*findingsPage, error) {
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

func topNCounts(counts map[string]int, n int) map[string]int {
	if len(counts) <= n {
		return counts
	}
	type kv struct {
		key   string
		value int
	}
	all := make([]kv, 0, len(counts))
	for key, value := range counts {
		all = append(all, kv{key, value})
	}
	for i := 0; i < len(all); i++ {
		for j := i + 1; j < len(all); j++ {
			if all[j].value > all[i].value || (all[j].value == all[i].value && all[j].key < all[i].key) {
				all[i], all[j] = all[j], all[i]
			}
		}
	}
	out := map[string]int{}
	for _, item := range all[:n] {
		out[item.key] = item.value
	}
	return out
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
