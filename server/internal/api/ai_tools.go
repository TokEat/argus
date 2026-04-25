package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	pb "github.com/user/dddd-proto/go/scan"
	aipkg "github.com/user/dddd-server/internal/ai"
	"github.com/user/dddd-server/internal/db"
)

type AIToolAuditContext struct {
	TenantID string
	UserID   string
	Module   string
}

type auditedTool struct {
	inner aipkg.Tool
	audit AIToolAuditContext
}

func auditedCopilotTool(inner aipkg.Tool, audit AIToolAuditContext) aipkg.Tool {
	return &auditedTool{inner: inner, audit: audit}
}

func (t *auditedTool) Name() string {
	return t.inner.Name()
}

func (t *auditedTool) Description() string {
	return t.inner.Description()
}

func (t *auditedTool) InputSchema() map[string]interface{} {
	return t.inner.InputSchema()
}

func (t *auditedTool) Execute(ctx context.Context, input json.RawMessage) (interface{}, error) {
	startedAt := time.Now()
	argsSummary, agentID, targetURL := summarizeToolArgs(input)
	result, err := t.inner.Execute(ctx, input)
	status, errorSummary := classifyToolResult(ctx, result, err)
	recordAIToolInvocation(t.audit, t.inner.Name(), argsSummary, agentID, targetURL, time.Since(startedAt), status, errorSummary)
	return result, err
}

func summarizeToolArgs(input json.RawMessage) (string, string, string) {
	var raw map[string]interface{}
	if err := json.Unmarshal(input, &raw); err != nil {
		return truncateString(string(input), 4096), "", ""
	}

	agentID, _ := raw["agent_id"].(string)
	targetURL, _ := raw["target_url"].(string)
	summary := make(map[string]interface{}, len(raw))
	for key, value := range raw {
		lower := strings.ToLower(key)
		switch {
		case lower == "poc_content":
			content, _ := value.(string)
			sum := sha256.Sum256([]byte(content))
			summary[key] = map[string]interface{}{
				"sha256": hex.EncodeToString(sum[:]),
				"length": len(content),
			}
		case strings.Contains(lower, "token") || strings.Contains(lower, "secret") || strings.Contains(lower, "password") || strings.Contains(lower, "api_key") || strings.Contains(lower, "authorization"):
			summary[key] = "[redacted]"
		default:
			summary[key] = compactAuditValue(value, 0)
		}
	}

	data, err := json.Marshal(summary)
	if err != nil {
		return "{}", agentID, targetURL
	}
	return truncateString(string(data), 4096), agentID, targetURL
}

func compactAuditValue(value interface{}, depth int) interface{} {
	if depth >= 3 {
		return "[truncated]"
	}
	switch v := value.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(v))
		for key, val := range v {
			out[key] = compactAuditValue(val, depth+1)
		}
		return out
	case []interface{}:
		limit := len(v)
		if limit > 10 {
			limit = 10
		}
		out := make([]interface{}, 0, limit+1)
		for i := 0; i < limit; i++ {
			out = append(out, compactAuditValue(v[i], depth+1))
		}
		if len(v) > limit {
			out = append(out, fmt.Sprintf("[truncated %d items]", len(v)-limit))
		}
		return out
	case string:
		return truncateString(v, 800)
	default:
		return v
	}
}

func classifyToolResult(ctx context.Context, result interface{}, err error) (string, string) {
	if err != nil {
		msg := truncateString(err.Error(), 1000)
		switch {
		case errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled):
			return "cancelled", msg
		case errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) || strings.Contains(strings.ToLower(msg), "timeout"):
			return "timeout", msg
		default:
			return "error", msg
		}
	}

	if m, ok := result.(map[string]interface{}); ok {
		if rawStatus, ok := m["status"].(string); ok {
			switch strings.ToLower(rawStatus) {
			case "hit", "success", "ok":
				return "success", ""
			case "miss":
				return "miss", ""
			case "failed", "error":
				if errText, _ := m["error"].(string); errText != "" {
					return "failed", truncateString(errText, 1000)
				}
				return "failed", ""
			}
		}
	}
	return "success", ""
}

func recordAIToolInvocation(audit AIToolAuditContext, toolName, argsSummary, agentID, targetURL string, duration time.Duration, status, errorSummary string) {
	if db.DB == nil {
		return
	}
	if audit.TenantID == "" {
		audit.TenantID = "default"
	}
	row := db.AIToolInvocation{
		TenantID:     audit.TenantID,
		UserID:       audit.UserID,
		Module:       audit.Module,
		ToolName:     toolName,
		ArgsSummary:  argsSummary,
		AgentID:      truncateString(agentID, 255),
		TargetURL:    truncateString(targetURL, 2000),
		DurationMS:   duration.Milliseconds(),
		Status:       status,
		ErrorSummary: errorSummary,
		CreatedAt:    time.Now(),
	}
	_ = db.DB.Create(&row).Error
}

func truncateString(value string, max int) string {
	if len(value) <= max {
		return value
	}
	if max <= 12 {
		return value[:max]
	}
	return value[:max-12] + "[truncated]"
}

type SearchAssetsTool struct {
	TenantID string
}

func (t *SearchAssetsTool) Name() string {
	return "SearchAssets"
}

func (t *SearchAssetsTool) Description() string {
	return "只读检索当前租户资产，返回目标、协议、端口、标题、服务和状态摘要。适合回答资产暴露面、端口和服务分布问题。"
}

func (t *SearchAssetsTool) InputSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"query": map[string]interface{}{
				"type":        "string",
				"description": "按 target、url、title 或 service 模糊搜索",
			},
			"protocol": map[string]interface{}{
				"type":        "string",
				"description": "可选协议过滤，如 http、https、tcp",
			},
			"status": map[string]interface{}{
				"type":        "string",
				"description": "可选资产状态过滤，如 alive",
			},
			"port": map[string]interface{}{
				"type":        "integer",
				"description": "可选端口过滤",
			},
			"limit": map[string]interface{}{
				"type":        "integer",
				"description": "返回数量，默认 8，最大 20",
			},
		},
	}
}

func (t *SearchAssetsTool) Execute(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var args struct {
		Query    string `json:"query"`
		Protocol string `json:"protocol"`
		Status   string `json:"status"`
		Port     int    `json:"port"`
		Limit    int    `json:"limit"`
	}
	if err := json.Unmarshal(input, &args); err != nil {
		return nil, err
	}
	limit := clampToolLimit(args.Limit, 8, 20)
	query := db.DB.WithContext(ctx).Model(&db.Asset{}).Where("tenant_id = ?", t.TenantID)
	if q := strings.TrimSpace(strings.ToLower(args.Query)); q != "" {
		like := "%" + q + "%"
		query = query.Where("LOWER(target) LIKE ? OR LOWER(url) LIKE ? OR LOWER(title) LIKE ? OR LOWER(service) LIKE ?", like, like, like, like)
	}
	if protocol := strings.TrimSpace(args.Protocol); protocol != "" {
		query = query.Where("protocol = ?", protocol)
	}
	if status := strings.TrimSpace(args.Status); status != "" {
		query = query.Where("status = ?", status)
	}
	if args.Port > 0 {
		query = query.Where("port = ?", args.Port)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, err
	}
	var assets []db.Asset
	if err := query.Order("updated_at desc").Limit(limit).Find(&assets).Error; err != nil {
		return nil, err
	}

	items := make([]map[string]interface{}, 0, len(assets))
	for _, asset := range assets {
		items = append(items, map[string]interface{}{
			"id":       asset.ID,
			"target":   asset.Target,
			"url":      asset.URL,
			"protocol": asset.Protocol,
			"port":     asset.Port,
			"title":    truncateString(asset.Title, 160),
			"service":  truncateString(asset.Service, 120),
			"status":   asset.Status,
			"updated":  asset.UpdatedAt,
		})
	}
	return map[string]interface{}{
		"status": "success",
		"total":  total,
		"items":  items,
	}, nil
}

type GetTaskInsightTool struct {
	TenantID string
}

func (t *GetTaskInsightTool) Name() string {
	return "GetTaskInsight"
}

func (t *GetTaskInsightTool) Description() string {
	return "只读获取扫描任务洞察，包括任务状态、子任务分布、结果数量和近期漏洞摘要。"
}

func (t *GetTaskInsightTool) InputSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"task_id": map[string]interface{}{
				"type":        "string",
				"description": "RootTask ID；为空时读取最近一个任务",
			},
		},
	}
}

func (t *GetTaskInsightTool) Execute(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var args struct {
		TaskID string `json:"task_id"`
	}
	if err := json.Unmarshal(input, &args); err != nil {
		return nil, err
	}

	query := db.DB.WithContext(ctx).Where("tenant_id = ?", t.TenantID)
	if taskID := strings.TrimSpace(args.TaskID); taskID != "" {
		query = query.Where("id = ?", taskID)
	}
	var task db.RootTask
	if err := query.Order("created_at desc").First(&task).Error; err != nil {
		return nil, fmt.Errorf("task not found")
	}

	var subTasks []db.SubTask
	if err := db.DB.WithContext(ctx).Where("tenant_id = ? AND root_task_id = ?", t.TenantID, task.ID).Find(&subTasks).Error; err != nil {
		return nil, err
	}
	statusDistribution := make(map[string]int)
	subTaskIDs := make([]string, 0, len(subTasks))
	for _, subTask := range subTasks {
		statusDistribution[subTask.Status]++
		subTaskIDs = append(subTaskIDs, subTask.ID)
	}

	assetCount, fpCount, vulnCount := countTaskResults(ctx, t.TenantID, task.ID, subTaskIDs)
	severityDistribution := make(map[string]int64)
	var severityRows []struct {
		Severity string
		Count    int64
	}
	if err := db.DB.WithContext(ctx).Model(&db.Vulnerability{}).
		Select("severity, count(*) as count").
		Where("tenant_id = ? AND root_task_id = ?", t.TenantID, task.ID).
		Group("severity").Scan(&severityRows).Error; err == nil {
		for _, row := range severityRows {
			severityDistribution[row.Severity] = row.Count
		}
	}

	return map[string]interface{}{
		"status": "success",
		"task": map[string]interface{}{
			"id":                task.ID,
			"name":              task.Name,
			"status":            task.Status,
			"total_chunks":      task.TotalChunks,
			"completed_chunks":  task.CompletedChunks,
			"total_targets":     task.TotalTargets,
			"completed_targets": task.CompletedTargets,
			"created_at":        task.CreatedAt,
			"updated_at":        task.UpdatedAt,
		},
		"subtask_status": statusDistribution,
		"result_counts": map[string]int64{
			"assets":          assetCount,
			"fingerprints":    fpCount,
			"vulnerabilities": vulnCount,
		},
		"severity_distribution": severityDistribution,
	}, nil
}

type RecommendWorkflowRulesTool struct {
	TenantID string
}

func (t *RecommendWorkflowRulesTool) Name() string {
	return "RecommendWorkflowRules"
}

func (t *RecommendWorkflowRulesTool) Description() string {
	return "只读推荐 Workflow 挂载关系，基于已有 POC、Workflow 和指纹/产品数据给出候选建议，不会写入或修改规则。"
}

func (t *RecommendWorkflowRulesTool) InputSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"product_name": map[string]interface{}{
				"type":        "string",
				"description": "产品名或指纹产品名，可为空",
			},
			"poc_name": map[string]interface{}{
				"type":        "string",
				"description": "POC 名称，可为空",
			},
			"limit": map[string]interface{}{
				"type":        "integer",
				"description": "返回数量，默认 8，最大 20",
			},
		},
	}
}

func (t *RecommendWorkflowRulesTool) Execute(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var args struct {
		ProductName string `json:"product_name"`
		PocName     string `json:"poc_name"`
		Limit       int    `json:"limit"`
	}
	if err := json.Unmarshal(input, &args); err != nil {
		return nil, err
	}
	limit := clampToolLimit(args.Limit, 8, 20)
	productName := strings.TrimSpace(args.ProductName)
	pocName := strings.TrimSpace(args.PocName)

	var workflows []db.WorkflowRule
	workflowQuery := db.DB.WithContext(ctx).Where("tenant_id = ? AND enabled = ?", t.TenantID, true)
	if productName != "" {
		workflowQuery = workflowQuery.Where("LOWER(product_name) LIKE ?", "%"+strings.ToLower(productName)+"%")
	}
	if pocName != "" {
		workflowQuery = workflowQuery.Where("LOWER(poc_name) LIKE ?", "%"+strings.ToLower(pocName)+"%")
	}
	if err := workflowQuery.Order("updated_at desc").Limit(limit).Find(&workflows).Error; err != nil {
		return nil, err
	}

	var pocs []db.PocRule
	pocQuery := db.DB.WithContext(ctx).Where("tenant_id = ? AND enabled = ?", t.TenantID, true)
	if pocName != "" {
		pocQuery = pocQuery.Where("LOWER(name) LIKE ? OR LOWER(source_file) LIKE ?", "%"+strings.ToLower(pocName)+"%", "%"+strings.ToLower(pocName)+"%")
	}
	if err := pocQuery.Order("updated_at desc").Limit(limit).Find(&pocs).Error; err != nil {
		return nil, err
	}

	var products []string
	productQuery := db.DB.WithContext(ctx).Model(&db.FingerprintHit{}).Where("tenant_id = ? AND product_name <> ''", t.TenantID)
	if productName != "" {
		productQuery = productQuery.Where("LOWER(product_name) LIKE ?", "%"+strings.ToLower(productName)+"%")
	}
	if err := productQuery.Distinct("product_name").Limit(limit).Pluck("product_name", &products).Error; err != nil {
		return nil, err
	}

	recommendations := buildWorkflowRecommendations(productName, pocName, products, pocs, workflows, limit)
	return map[string]interface{}{
		"status":          "success",
		"products":        products,
		"poc_candidates":  summarizePocRules(pocs),
		"existing_rules":  summarizeWorkflowRules(workflows),
		"recommendations": recommendations,
	}, nil
}

func clampToolLimit(value, fallback, max int) int {
	if value <= 0 {
		return fallback
	}
	if value > max {
		return max
	}
	return value
}

func countTaskResults(ctx context.Context, tenantID, rootTaskID string, subTaskIDs []string) (int64, int64, int64) {
	var assetCount, fpCount, vulnCount int64
	db.DB.WithContext(ctx).Model(&db.Asset{}).Where("tenant_id = ? AND root_task_id = ?", tenantID, rootTaskID).Count(&assetCount)
	db.DB.WithContext(ctx).Model(&db.FingerprintHit{}).Where("tenant_id = ? AND root_task_id = ?", tenantID, rootTaskID).Count(&fpCount)
	db.DB.WithContext(ctx).Model(&db.Vulnerability{}).Where("tenant_id = ? AND root_task_id = ?", tenantID, rootTaskID).Count(&vulnCount)
	if assetCount == 0 && fpCount == 0 && vulnCount == 0 && len(subTaskIDs) > 0 {
		db.DB.WithContext(ctx).Model(&db.Asset{}).Where("tenant_id = ? AND task_id IN ?", tenantID, subTaskIDs).Count(&assetCount)
		db.DB.WithContext(ctx).Model(&db.FingerprintHit{}).Where("tenant_id = ? AND task_id IN ?", tenantID, subTaskIDs).Count(&fpCount)
		db.DB.WithContext(ctx).Model(&db.Vulnerability{}).Where("tenant_id = ? AND task_id IN ?", tenantID, subTaskIDs).Count(&vulnCount)
	}
	return assetCount, fpCount, vulnCount
}

func summarizePocRules(pocs []db.PocRule) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(pocs))
	for _, poc := range pocs {
		out = append(out, map[string]interface{}{
			"name":        poc.Name,
			"source_file": poc.SourceFile,
			"severity":    poc.Severity,
			"tags":        truncateString(poc.Tags, 180),
			"state":       poc.State,
		})
	}
	return out
}

func summarizeWorkflowRules(rules []db.WorkflowRule) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(rules))
	for _, rule := range rules {
		out = append(out, map[string]interface{}{
			"product_name": rule.ProductName,
			"poc_name":     rule.PocName,
			"match_type":   rule.MatchType,
			"source_file":  rule.SourceFile,
			"state":        rule.State,
		})
	}
	return out
}

func buildWorkflowRecommendations(productName, pocName string, products []string, pocs []db.PocRule, existing []db.WorkflowRule, limit int) []string {
	existingKey := make(map[string]bool)
	for _, rule := range existing {
		existingKey[strings.ToLower(rule.ProductName)+"|"+strings.ToLower(rule.PocName)] = true
	}
	productCandidates := products
	if productName != "" {
		productCandidates = append([]string{productName}, productCandidates...)
	}
	if len(productCandidates) == 0 {
		productCandidates = []string{"待确认产品"}
	}

	pocCandidates := make([]string, 0, len(pocs)+1)
	if pocName != "" {
		pocCandidates = append(pocCandidates, pocName)
	}
	for _, poc := range pocs {
		pocCandidates = append(pocCandidates, poc.Name)
	}
	if len(pocCandidates) == 0 {
		pocCandidates = []string{"待选择 POC"}
	}

	var out []string
	seen := make(map[string]bool)
	for _, product := range productCandidates {
		product = strings.TrimSpace(product)
		if product == "" {
			continue
		}
		for _, poc := range pocCandidates {
			poc = strings.TrimSpace(poc)
			if poc == "" {
				continue
			}
			key := strings.ToLower(product) + "|" + strings.ToLower(poc)
			if seen[key] {
				continue
			}
			seen[key] = true
			if existingKey[key] {
				out = append(out, fmt.Sprintf("%s 已挂载 %s，可优先检查 match_type 是否仍准确。", product, poc))
			} else {
				out = append(out, fmt.Sprintf("建议评估将产品 %s 以 product 匹配方式挂载到 POC %s，发布前先用样本资产验证指纹命中。", product, poc))
			}
			if len(out) >= limit {
				return out
			}
		}
	}
	return out
}

type ExplainVulnerabilityTool struct {
	TenantID string
}

func (t *ExplainVulnerabilityTool) Name() string {
	return "ExplainVulnerability"
}

func (t *ExplainVulnerabilityTool) Description() string {
	return "只读解释漏洞证据，返回漏洞严重性、目标、插件、命中位置、请求/响应摘要和处置建议线索。"
}

func (t *ExplainVulnerabilityTool) InputSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"vulnerability_id": map[string]interface{}{
				"type":        "integer",
				"description": "漏洞 ID；为空时可用 task_id、target 或 severity 查询最近漏洞",
			},
			"task_id": map[string]interface{}{
				"type":        "string",
				"description": "任务 ID 或 RootTask ID",
			},
			"target": map[string]interface{}{
				"type":        "string",
				"description": "目标 URL 或主机名模糊查询",
			},
			"severity": map[string]interface{}{
				"type":        "string",
				"description": "严重性过滤，如 critical、high、medium",
			},
			"limit": map[string]interface{}{
				"type":        "integer",
				"description": "返回数量，默认 5，最大 12",
			},
		},
	}
}

func (t *ExplainVulnerabilityTool) Execute(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var args struct {
		VulnerabilityID uint   `json:"vulnerability_id"`
		TaskID          string `json:"task_id"`
		Target          string `json:"target"`
		Severity        string `json:"severity"`
		Limit           int    `json:"limit"`
	}
	if err := json.Unmarshal(input, &args); err != nil {
		return nil, err
	}
	limit := clampToolLimit(args.Limit, 5, 12)
	query := db.DB.WithContext(ctx).Model(&db.Vulnerability{}).Where("tenant_id = ?", t.TenantID)
	if args.VulnerabilityID > 0 {
		query = query.Where("id = ?", args.VulnerabilityID)
	}
	if taskID := strings.TrimSpace(args.TaskID); taskID != "" {
		query = query.Where("(task_id = ? OR root_task_id = ?)", taskID, taskID)
	}
	if target := strings.TrimSpace(strings.ToLower(args.Target)); target != "" {
		query = query.Where("LOWER(target) LIKE ? OR LOWER(matched_at) LIKE ?", "%"+target+"%", "%"+target+"%")
	}
	if severity := strings.TrimSpace(strings.ToLower(args.Severity)); severity != "" {
		query = query.Where("LOWER(severity) = ?", severity)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, err
	}
	var vulns []db.Vulnerability
	if err := query.Order("created_at desc").Limit(limit).Find(&vulns).Error; err != nil {
		return nil, err
	}
	items := make([]map[string]interface{}, 0, len(vulns))
	for _, vuln := range vulns {
		items = append(items, map[string]interface{}{
			"id":          vuln.ID,
			"target":      vuln.Target,
			"plugin":      vuln.Plugin,
			"severity":    vuln.Severity,
			"status":      vuln.Status,
			"matched_at":  truncateString(vuln.MatchedAt, 300),
			"description": truncateString(vuln.Description, 600),
			"payload":     truncateString(vuln.Payload, 500),
			"request":     truncateString(vuln.Request, 900),
			"response":    truncateString(vuln.Response, 900),
			"reference":   truncateString(vuln.Reference, 500),
			"created_at":  vuln.CreatedAt,
		})
	}
	return map[string]interface{}{
		"status": "success",
		"total":  total,
		"items":  items,
		"guidance": []string{
			"优先核对 request/response 中的命中证据是否能支撑漏洞结论。",
			"若响应摘要不足以确认影响，应建议用户进入详情页查看完整报文。",
			"处置建议需结合 severity、plugin、matched_at 和业务暴露面，不要假设不存在的利用条件。",
		},
	}, nil
}

type AnalyzeNodeCapacityTool struct {
	TenantID string
}

func (t *AnalyzeNodeCapacityTool) Name() string {
	return "AnalyzeNodeCapacity"
}

func (t *AnalyzeNodeCapacityTool) Description() string {
	return "只读分析 Agent 节点容量、在线状态、版本、运行任务数和 CPU/内存指标，用于解释任务堆积或节点瓶颈。"
}

func (t *AnalyzeNodeCapacityTool) InputSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"agent_id": map[string]interface{}{
				"type":        "string",
				"description": "可选 AgentID；为空时分析当前租户全部节点",
			},
			"limit": map[string]interface{}{
				"type":        "integer",
				"description": "返回节点数量，默认 20，最大 50",
			},
		},
	}
}

func (t *AnalyzeNodeCapacityTool) Execute(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var args struct {
		AgentID string `json:"agent_id"`
		Limit   int    `json:"limit"`
	}
	if err := json.Unmarshal(input, &args); err != nil {
		return nil, err
	}
	limit := clampToolLimit(args.Limit, 20, 50)
	query := db.DB.WithContext(ctx).Where("tenant_id = ?", t.TenantID)
	if agentID := strings.TrimSpace(args.AgentID); agentID != "" {
		query = query.Where("agent_id = ?", agentID)
	}
	var nodes []db.Node
	if err := query.Order("status asc, running_tasks desc, last_beat desc").Limit(limit).Find(&nodes).Error; err != nil {
		return nil, err
	}

	statusCounts := make(map[string]int)
	var totalCapacity, totalRunning int
	items := make([]map[string]interface{}, 0, len(nodes))
	nowMS := time.Now().UnixMilli()
	for _, node := range nodes {
		statusCounts[node.Status]++
		totalCapacity += node.Capacity
		totalRunning += node.RunningTasks
		ageSec := int64(0)
		if node.LastBeat > 0 {
			ageSec = (nowMS - node.LastBeat) / 1000
		}
		warnings := nodeCapacityWarnings(node, ageSec)
		items = append(items, map[string]interface{}{
			"agent_id":          node.AgentID,
			"status":            node.Status,
			"version":           node.Version,
			"os":                node.OS,
			"arch":              node.Arch,
			"capacity":          node.Capacity,
			"running_tasks":     node.RunningTasks,
			"cpu_usage":         node.CPUUsage,
			"mem_usage":         node.MemUsage,
			"last_beat_age_sec": ageSec,
			"warnings":          warnings,
		})
	}
	return map[string]interface{}{
		"status": "success",
		"summary": map[string]interface{}{
			"node_count":     len(nodes),
			"status_counts":  statusCounts,
			"total_capacity": totalCapacity,
			"running_tasks":  totalRunning,
			"utilization":    capacityUtilization(totalRunning, totalCapacity),
		},
		"nodes": items,
	}, nil
}

type SuggestDictionaryStrategyTool struct {
	TenantID string
}

func (t *SuggestDictionaryStrategyTool) Name() string {
	return "SuggestDictionaryStrategy"
}

func (t *SuggestDictionaryStrategyTool) Description() string {
	return "只读生成字典/目录探测策略建议，结合资产服务、指纹命中、目录规则和 POC/Workflow 覆盖情况。"
}

func (t *SuggestDictionaryStrategyTool) InputSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"product_name": map[string]interface{}{
				"type":        "string",
				"description": "产品名或服务名，可为空",
			},
			"target": map[string]interface{}{
				"type":        "string",
				"description": "资产目标模糊查询，可为空",
			},
			"limit": map[string]interface{}{
				"type":        "integer",
				"description": "返回数量，默认 8，最大 20",
			},
		},
	}
}

func (t *SuggestDictionaryStrategyTool) Execute(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var args struct {
		ProductName string `json:"product_name"`
		Target      string `json:"target"`
		Limit       int    `json:"limit"`
	}
	if err := json.Unmarshal(input, &args); err != nil {
		return nil, err
	}
	limit := clampToolLimit(args.Limit, 8, 20)
	product := strings.TrimSpace(args.ProductName)
	target := strings.TrimSpace(args.Target)

	assets := loadAssetStrategySamples(ctx, t.TenantID, product, target, limit)
	fingerprints := loadFingerprintProducts(ctx, t.TenantID, product, target, limit)
	dirRules := loadDirRuleSamples(ctx, t.TenantID, product, limit)
	pocRules := loadPocStrategySamples(ctx, t.TenantID, product, limit)
	workflowRules := loadWorkflowStrategySamples(ctx, t.TenantID, product, limit)
	suggestions := buildDictionarySuggestions(product, assets, fingerprints, dirRules, pocRules, workflowRules)

	return map[string]interface{}{
		"status":               "success",
		"asset_samples":        assets,
		"fingerprint_products": fingerprints,
		"dir_rules":            dirRules,
		"poc_candidates":       pocRules,
		"workflow_rules":       workflowRules,
		"suggestions":          suggestions,
	}, nil
}

type DetectWorkflowConflictsTool struct {
	TenantID string
}

func (t *DetectWorkflowConflictsTool) Name() string {
	return "DetectWorkflowConflicts"
}

func (t *DetectWorkflowConflictsTool) Description() string {
	return "只读检测 Workflow 配置风险，包括重复挂载、同一产品多 match_type、引用不存在或禁用的 POC，以及缺少指纹支撑的产品。"
}

func (t *DetectWorkflowConflictsTool) InputSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"product_name": map[string]interface{}{
				"type":        "string",
				"description": "产品名过滤，可为空",
			},
			"poc_name": map[string]interface{}{
				"type":        "string",
				"description": "POC 名称过滤，可为空",
			},
			"limit": map[string]interface{}{
				"type":        "integer",
				"description": "返回风险数量，默认 20，最大 50",
			},
		},
	}
}

func (t *DetectWorkflowConflictsTool) Execute(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var args struct {
		ProductName string `json:"product_name"`
		PocName     string `json:"poc_name"`
		Limit       int    `json:"limit"`
	}
	if err := json.Unmarshal(input, &args); err != nil {
		return nil, err
	}
	limit := clampToolLimit(args.Limit, 20, 50)
	productFilter := strings.TrimSpace(strings.ToLower(args.ProductName))
	pocFilter := strings.TrimSpace(strings.ToLower(args.PocName))

	var workflows []db.WorkflowRule
	query := db.DB.WithContext(ctx).Where("tenant_id = ?", t.TenantID)
	if productFilter != "" {
		query = query.Where("LOWER(product_name) LIKE ?", "%"+productFilter+"%")
	}
	if pocFilter != "" {
		query = query.Where("LOWER(poc_name) LIKE ?", "%"+pocFilter+"%")
	}
	if err := query.Order("product_name asc, poc_name asc").Limit(limit * 4).Find(&workflows).Error; err != nil {
		return nil, err
	}

	pocState := loadPocStateMap(ctx, t.TenantID)
	fingerprintProducts := loadFingerprintProductSet(ctx, t.TenantID)
	conflicts := detectWorkflowConflicts(workflows, pocState, fingerprintProducts, limit)

	return map[string]interface{}{
		"status":          "success",
		"checked_rules":   len(workflows),
		"conflict_count":  len(conflicts),
		"conflicts":       conflicts,
		"safe_next_steps": []string{"先修复 missing_poc 和 disabled_poc，再处理重复挂载或 match_type 分歧。", "发布前建议用样本资产验证产品指纹能否稳定命中。"},
	}, nil
}

func nodeCapacityWarnings(node db.Node, lastBeatAgeSec int64) []string {
	var warnings []string
	if !strings.EqualFold(node.Status, "Alive") {
		warnings = append(warnings, "节点非在线状态")
	}
	if node.Capacity > 0 && node.RunningTasks >= node.Capacity {
		warnings = append(warnings, "运行任务数已达到或超过容量")
	}
	if node.CPUUsage >= 85 {
		warnings = append(warnings, "CPU 使用率偏高")
	}
	if node.MemUsage >= 85 {
		warnings = append(warnings, "内存使用率偏高")
	}
	if lastBeatAgeSec > 120 {
		warnings = append(warnings, "心跳延迟超过 120 秒")
	}
	if node.Version == "" {
		warnings = append(warnings, "Agent 版本未知，可能影响调试或规则能力判断")
	}
	return warnings
}

func capacityUtilization(running, capacity int) float64 {
	if capacity <= 0 {
		return 0
	}
	return float64(running) / float64(capacity)
}

func loadAssetStrategySamples(ctx context.Context, tenantID, product, target string, limit int) []map[string]interface{} {
	query := db.DB.WithContext(ctx).Where("tenant_id = ?", tenantID)
	if product != "" {
		like := "%" + strings.ToLower(product) + "%"
		query = query.Where("LOWER(service) LIKE ? OR LOWER(title) LIKE ? OR LOWER(tags) LIKE ?", like, like, like)
	}
	if target != "" {
		like := "%" + strings.ToLower(target) + "%"
		query = query.Where("LOWER(target) LIKE ? OR LOWER(url) LIKE ?", like, like)
	}
	var assets []db.Asset
	if err := query.Order("updated_at desc").Limit(limit).Find(&assets).Error; err != nil {
		return nil
	}
	out := make([]map[string]interface{}, 0, len(assets))
	for _, asset := range assets {
		out = append(out, map[string]interface{}{
			"target":   asset.Target,
			"url":      asset.URL,
			"protocol": asset.Protocol,
			"port":     asset.Port,
			"title":    truncateString(asset.Title, 120),
			"service":  truncateString(asset.Service, 100),
			"status":   asset.Status,
		})
	}
	return out
}

func loadFingerprintProducts(ctx context.Context, tenantID, product, target string, limit int) []string {
	query := db.DB.WithContext(ctx).Model(&db.FingerprintHit{}).Where("tenant_id = ? AND product_name <> ''", tenantID)
	if product != "" {
		query = query.Where("LOWER(product_name) LIKE ?", "%"+strings.ToLower(product)+"%")
	}
	if target != "" {
		query = query.Where("LOWER(target) LIKE ?", "%"+strings.ToLower(target)+"%")
	}
	var products []string
	if err := query.Distinct("product_name").Limit(limit).Pluck("product_name", &products).Error; err != nil {
		return nil
	}
	return products
}

func loadDirRuleSamples(ctx context.Context, tenantID, product string, limit int) []map[string]interface{} {
	query := db.DB.WithContext(ctx).Where("tenant_id = ? AND enabled = ?", tenantID, true)
	if product != "" {
		query = query.Where("LOWER(product_name) LIKE ?", "%"+strings.ToLower(product)+"%")
	}
	var rules []db.DirRule
	if err := query.Order("updated_at desc").Limit(limit).Find(&rules).Error; err != nil {
		return nil
	}
	out := make([]map[string]interface{}, 0, len(rules))
	for _, rule := range rules {
		out = append(out, map[string]interface{}{
			"product_name": rule.ProductName,
			"path":         rule.Path,
			"source_file":  rule.SourceFile,
			"state":        rule.State,
		})
	}
	return out
}

func loadPocStrategySamples(ctx context.Context, tenantID, product string, limit int) []map[string]interface{} {
	query := db.DB.WithContext(ctx).Where("tenant_id = ? AND enabled = ?", tenantID, true)
	if product != "" {
		like := "%" + strings.ToLower(product) + "%"
		query = query.Where("LOWER(name) LIKE ? OR LOWER(tags) LIKE ? OR LOWER(description) LIKE ?", like, like, like)
	}
	var pocs []db.PocRule
	if err := query.Order("updated_at desc").Limit(limit).Find(&pocs).Error; err != nil {
		return nil
	}
	return summarizePocRules(pocs)
}

func loadWorkflowStrategySamples(ctx context.Context, tenantID, product string, limit int) []map[string]interface{} {
	query := db.DB.WithContext(ctx).Where("tenant_id = ? AND enabled = ?", tenantID, true)
	if product != "" {
		query = query.Where("LOWER(product_name) LIKE ?", "%"+strings.ToLower(product)+"%")
	}
	var workflows []db.WorkflowRule
	if err := query.Order("updated_at desc").Limit(limit).Find(&workflows).Error; err != nil {
		return nil
	}
	return summarizeWorkflowRules(workflows)
}

func buildDictionarySuggestions(product string, assets []map[string]interface{}, fingerprints []string, dirs, pocs, workflows []map[string]interface{}) []string {
	var suggestions []string
	if product != "" {
		suggestions = append(suggestions, fmt.Sprintf("围绕 %s 优先复用已有指纹命中和目录规则，先验证常见管理后台、API 文档、静态资源目录。", product))
	} else {
		suggestions = append(suggestions, "先按资产标题、服务和指纹命中聚类，再为高频产品维护小而准确的目录字典。")
	}
	if len(assets) > 0 && len(fingerprints) == 0 {
		suggestions = append(suggestions, "当前资产样本有服务信息但缺少指纹产品命中，建议先补强 Fingerprint 规则，再扩目录字典。")
	}
	if len(dirs) == 0 {
		suggestions = append(suggestions, "当前缺少匹配的目录规则，可先添加低风险只读路径，如 /login、/admin、/api、/swagger、/actuator。")
	}
	if len(pocs) > 0 && len(workflows) == 0 {
		suggestions = append(suggestions, "已有候选 POC 但缺少 Workflow 挂载，建议先建立产品到 POC 的草稿映射并用样本资产验证。")
	}
	if len(suggestions) == 1 {
		suggestions = append(suggestions, "保持字典小步迭代：先覆盖高置信产品，再根据任务结果补充路径，避免一次性加入过宽路径造成噪音。")
	}
	return suggestions
}

type pocRuleState struct {
	Exists  bool
	Enabled bool
	State   string
}

func loadPocStateMap(ctx context.Context, tenantID string) map[string]pocRuleState {
	var pocs []db.PocRule
	if err := db.DB.WithContext(ctx).Where("tenant_id = ?", tenantID).Find(&pocs).Error; err != nil {
		return map[string]pocRuleState{}
	}
	out := make(map[string]pocRuleState, len(pocs))
	for _, poc := range pocs {
		state := pocRuleState{Exists: true, Enabled: poc.Enabled, State: poc.State}
		out[strings.ToLower(poc.Name)] = state
		if poc.SourceFile != "" {
			out[strings.ToLower(poc.SourceFile)] = state
		}
	}
	return out
}

func loadFingerprintProductSet(ctx context.Context, tenantID string) map[string]bool {
	var products []string
	if err := db.DB.WithContext(ctx).Model(&db.FingerprintRule{}).
		Where("tenant_id = ? AND enabled = ?", tenantID, true).
		Distinct("product_name").Pluck("product_name", &products).Error; err != nil {
		return map[string]bool{}
	}
	out := make(map[string]bool, len(products))
	for _, product := range products {
		out[strings.ToLower(strings.TrimSpace(product))] = true
	}
	return out
}

func detectWorkflowConflicts(workflows []db.WorkflowRule, pocState map[string]pocRuleState, fingerprintProducts map[string]bool, limit int) []map[string]interface{} {
	byProductPoc := make(map[string][]db.WorkflowRule)
	byExact := make(map[string]int)
	for _, rule := range workflows {
		product := strings.ToLower(strings.TrimSpace(rule.ProductName))
		poc := strings.ToLower(strings.TrimSpace(rule.PocName))
		matchType := strings.ToLower(strings.TrimSpace(rule.MatchType))
		byProductPoc[product+"|"+poc] = append(byProductPoc[product+"|"+poc], rule)
		byExact[product+"|"+poc+"|"+matchType]++
	}

	var conflicts []map[string]interface{}
	add := func(kind, severity, message string, rule db.WorkflowRule) {
		if len(conflicts) >= limit {
			return
		}
		conflicts = append(conflicts, map[string]interface{}{
			"type":         kind,
			"severity":     severity,
			"message":      message,
			"product_name": rule.ProductName,
			"poc_name":     rule.PocName,
			"match_type":   rule.MatchType,
			"source_file":  rule.SourceFile,
			"enabled":      rule.Enabled,
			"state":        rule.State,
		})
	}

	reportedProductPoc := make(map[string]bool)
	for _, rule := range workflows {
		product := strings.ToLower(strings.TrimSpace(rule.ProductName))
		poc := strings.ToLower(strings.TrimSpace(rule.PocName))
		matchType := strings.ToLower(strings.TrimSpace(rule.MatchType))
		if product == "" || poc == "" || matchType == "" {
			add("incomplete_rule", "medium", "Workflow 存在空 product、poc 或 match_type 字段。", rule)
			continue
		}
		if byExact[product+"|"+poc+"|"+matchType] > 1 {
			add("duplicate_rule", "medium", "同一 product/poc/match_type 出现重复挂载。", rule)
		}
		key := product + "|" + poc
		if !reportedProductPoc[key] && len(byProductPoc[key]) > 1 {
			matchTypes := make(map[string]bool)
			for _, candidate := range byProductPoc[key] {
				matchTypes[strings.ToLower(candidate.MatchType)] = true
			}
			if len(matchTypes) > 1 {
				add("match_type_divergence", "low", "同一 product/poc 存在多个 match_type，请确认是否必要。", rule)
			}
			reportedProductPoc[key] = true
		}
		state, ok := pocState[poc]
		if !ok {
			add("missing_poc", "high", "Workflow 引用了不存在的 POC。", rule)
		} else if !state.Enabled {
			add("disabled_poc", "high", "Workflow 引用了已禁用的 POC。", rule)
		}
		if !fingerprintProducts[product] {
			add("missing_fingerprint", "medium", "Workflow 产品缺少启用的 FingerprintRule 支撑，可能无法稳定命中。", rule)
		}
		if len(conflicts) >= limit {
			break
		}
	}
	return conflicts
}

type RunSandboxDebugTool struct {
	TenantID string
}

func (t *RunSandboxDebugTool) Name() string {
	return "RunSandboxDebug"
}

func (t *RunSandboxDebugTool) Description() string {
	return "将修改后的 POC 代码丢入沙箱运行，并同步等待运行结果。如果你修改了代码，必须调用此工具进行验证。如果返回失败，请读取日志继续修复。"
}

func (t *RunSandboxDebugTool) InputSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"agent_id": map[string]interface{}{
				"type":        "string",
				"description": "调试节点的 AgentID",
			},
			"target_url": map[string]interface{}{
				"type":        "string",
				"description": "目标 URL，如 https://example.com",
			},
			"poc_content": map[string]interface{}{
				"type":        "string",
				"description": "完整的 POC YAML 代码",
			},
			"proxy": map[string]interface{}{
				"type":        "string",
				"description": "代理配置（可选）",
			},
		},
		"required": []string{"agent_id", "target_url", "poc_content"},
	}
}

func (t *RunSandboxDebugTool) Execute(ctx context.Context, input json.RawMessage) (interface{}, error) {
	if notifyHub == nil {
		return nil, fmt.Errorf("agent notify hub is not ready")
	}

	var args struct {
		AgentID    string `json:"agent_id"`
		TargetURL  string `json:"target_url"`
		PocContent string `json:"poc_content"`
		Proxy      string `json:"proxy"`
	}
	if err := json.Unmarshal(input, &args); err != nil {
		return nil, err
	}
	args.AgentID = strings.TrimSpace(args.AgentID)
	args.TargetURL = strings.TrimSpace(args.TargetURL)
	args.PocContent = strings.TrimSpace(args.PocContent)
	args.Proxy = strings.TrimSpace(args.Proxy)

	if args.AgentID == "" || args.TargetURL == "" || args.PocContent == "" {
		return nil, fmt.Errorf("agent_id, target_url and poc_content are required")
	}
	if len(args.PocContent) > 256*1024 {
		return nil, fmt.Errorf("poc_content is too large")
	}
	if err := validateDebugTargetURL(args.TargetURL); err != nil {
		return nil, err
	}
	if err := validateDebugProxy(args.Proxy); err != nil {
		return nil, err
	}

	var node db.Node
	if err := scopedNodeQuery(t.TenantID).Where("agent_id = ? AND status = ?", args.AgentID, "Alive").First(&node).Error; err != nil {
		return nil, fmt.Errorf("agent is not alive in this tenant")
	}
	if !isDebugCapableAgent(node.Version) {
		return nil, fmt.Errorf("agent does not support poc debug; please upgrade agent")
	}
	if !notifyHub.IsAgentOnline(args.AgentID) {
		return nil, fmt.Errorf("agent subscribe stream is offline")
	}

	resultChan := make(chan map[string]interface{}, 10)
	// 启动沙箱会话 (借用现有的 debug.go 逻辑)
	session, ok := pocDebugSessions.start(t.TenantID, args.AgentID, 30*time.Second, resultChan)
	if !ok {
		return nil, fmt.Errorf("tenant already has a running debug session")
	}
	defer pocDebugSessions.finish(session.SessionID)

	cmd := &pb.DebugCommand{
		Action:     "start_debug",
		SessionId:  session.SessionID,
		TenantId:   t.TenantID,
		PocContent: args.PocContent,
		TargetUrl:  args.TargetURL,
		Proxy:      args.Proxy,
		TimeoutSec: 30,
	}

	if err := notifyHub.SendDebugCommand(args.AgentID, cmd); err != nil {
		return nil, fmt.Errorf("failed to send debug command to agent")
	}

	// 等待完成
	timeout := time.After(35 * time.Second)
	var latestResult map[string]interface{}
	var completeEvent map[string]interface{}

	for {
		select {
		case msg := <-resultChan:
			if msg["type"] == "debug_result" {
				latestResult = msg
			} else if msg["type"] == "debug_complete" {
				completeEvent = msg
				goto Done
			}
		case <-timeout:
			return nil, fmt.Errorf("sandbox execution timeout after 35s")
		case <-ctx.Done():
			return nil, fmt.Errorf("context cancelled")
		}
	}

Done:
	if errStr, ok := completeEvent["error"].(string); ok && errStr != "" {
		return map[string]interface{}{
			"status": "failed",
			"error":  errStr,
		}, nil
	}

	if latestResult != nil {
		return map[string]interface{}{
			"status":    "hit",
			"matched":   true,
			"request":   latestResult["request"],
			"response":  latestResult["response"],
			"extracted": latestResult["extracted"],
		}, nil
	}

	return map[string]interface{}{
		"status":  "miss",
		"matched": false,
		"message": "POC 执行完成，但未匹配目标特征",
	}, nil
}
