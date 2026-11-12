package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/TokEat/argus/server/internal/db"
	"github.com/gin-gonic/gin"
)

func parseAgentSelector(raw json.RawMessage) (map[string]string, error) {
	if len(raw) == 0 || strings.TrimSpace(string(raw)) == "" || strings.TrimSpace(string(raw)) == "null" {
		return nil, nil
	}
	var values map[string]interface{}
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil, fmt.Errorf("agent_selector must be a flat object of string values")
	}
	selector := make(map[string]string, len(values))
	for key, val := range values {
		k := strings.TrimSpace(key)
		if k == "" {
			return nil, fmt.Errorf("agent_selector contains empty key")
		}
		s, ok := val.(string)
		if !ok {
			return nil, fmt.Errorf("agent_selector.%s must be a string", k)
		}
		s = strings.TrimSpace(s)
		if s == "" {
			return nil, fmt.Errorf("agent_selector.%s must not be empty", k)
		}
		selector[k] = s
	}
	return selector, nil
}

func parseAgentSelectorRules(raw json.RawMessage) (db.AgentSelectorRules, error) {
	return db.ParseSelectorRulesBytes(raw)
}

func mergeAgentSelector(baseJSON string, extra map[string]string) string {
	merged := make(map[string]string)
	if strings.TrimSpace(baseJSON) != "" {
		_ = json.Unmarshal([]byte(baseJSON), &merged)
	}
	for key, val := range extra {
		merged[key] = val
	}
	if len(merged) == 0 {
		return "{}"
	}
	data, err := json.Marshal(merged)
	if err != nil {
		return "{}"
	}
	return string(data)
}

func parseSelectorJSONString(raw string) map[string]string {
	selector := make(map[string]string)
	if strings.TrimSpace(raw) == "" || strings.TrimSpace(raw) == "{}" {
		return selector
	}
	_ = json.Unmarshal([]byte(raw), &selector)
	return selector
}

func effectiveSelectorRules(baseJSON string, userSelector map[string]string, userRules db.AgentSelectorRules) (map[string]string, db.AgentSelectorRules, string) {
	selectorJSON := mergeAgentSelector(baseJSON, userSelector)
	legacy := parseSelectorJSONString(selectorJSON)
	rules := db.MergeSelectorRules(legacy, userRules)
	return legacy, rules, db.SelectorRulesToJSON(rules)
}

func nodeMatchesSelector(selector map[string]string, nodeTags string) (bool, string) {
	return db.NodeMatchesSelectorRules(selector, db.AgentSelectorRules{}, nodeTags)
}

type selectorPreviewNode struct {
	AgentID        string `json:"agent_id"`
	Status         string `json:"status"`
	Capacity       int    `json:"capacity"`
	RunningTasks   int    `json:"running_tasks"`
	AvailableSlots int    `json:"available_slots"`
	Matched        bool   `json:"matched"`
	Reason         string `json:"reason,omitempty"`
}

type selectorPreviewGroup struct {
	TargetType       string                `json:"target_type"`
	TargetCount      int                   `json:"target_count"`
	BatchCount       int                   `json:"batch_count"`
	Selector         map[string]string     `json:"selector"`
	SelectorRules    db.AgentSelectorRules `json:"selector_rules"`
	MatchedNodes     int                   `json:"matched_nodes"`
	AvailableSlots   int                   `json:"available_slots"`
	ImmediateBatches int                   `json:"immediate_batches"`
	WaitingBatches   int                   `json:"waiting_batches"`
	Reasons          []string              `json:"reasons"`
	Nodes            []selectorPreviewNode `json:"nodes"`
}

func buildSelectorPreviewGroups(batches []targetBatchGroup, userSelector map[string]string, userRules db.AgentSelectorRules, nodes []db.Node) ([]selectorPreviewGroup, []map[string]string, int, int, []string) {
	type groupAccumulator struct {
		targetType string
		selector   map[string]string
		rules      db.AgentSelectorRules
		targets    int
		batches    int
	}
	groupsByKey := make(map[string]*groupAccumulator)
	groupOrder := make([]string, 0)
	effectiveSelectors := make([]map[string]string, 0)
	seenSelectors := make(map[string]struct{})

	for _, batch := range batches {
		selector, rules, rulesJSON := effectiveSelectorRules(batch.SelectorJSON, userSelector, userRules)
		key := batch.TargetType + "\x00" + rulesJSON
		if _, ok := groupsByKey[key]; !ok {
			groupsByKey[key] = &groupAccumulator{targetType: batch.TargetType, selector: selector, rules: rules}
			groupOrder = append(groupOrder, key)
		}
		groupsByKey[key].targets += len(batch.Targets)
		groupsByKey[key].batches++

		if _, ok := seenSelectors[rulesJSON]; !ok {
			seenSelectors[rulesJSON] = struct{}{}
			effectiveSelectors = append(effectiveSelectors, selector)
		}
	}
	if len(groupOrder) == 0 {
		selector := make(map[string]string)
		for key, val := range userSelector {
			selector[key] = val
		}
		rules := db.MergeSelectorRules(selector, userRules)
		groupsByKey["unknown\x00{}"] = &groupAccumulator{targetType: "unknown", selector: selector, rules: rules}
		groupOrder = append(groupOrder, "unknown\x00{}")
		effectiveSelectors = append(effectiveSelectors, selector)
	}

	overallMatched := make(map[string]int)
	overallReasons := make(map[string]struct{})
	addOverallReason := func(reason string) {
		if strings.TrimSpace(reason) != "" {
			overallReasons[reason] = struct{}{}
		}
	}

	groups := make([]selectorPreviewGroup, 0, len(groupOrder))
	for _, key := range groupOrder {
		acc := groupsByKey[key]
		reasonSet := make(map[string]struct{})
		addReason := func(reason string) {
			if strings.TrimSpace(reason) != "" {
				reasonSet[reason] = struct{}{}
			}
		}
		group := selectorPreviewGroup{
			TargetType:    acc.targetType,
			TargetCount:   acc.targets,
			BatchCount:    acc.batches,
			Selector:      acc.selector,
			SelectorRules: acc.rules,
			Nodes:         make([]selectorPreviewNode, 0, len(nodes)),
		}

		offlineNodes := 0
		mismatchedNodes := 0
		capacityExhausted := 0
		for _, node := range nodes {
			availableSlots := node.Capacity - node.RunningTasks
			if availableSlots < 0 {
				availableSlots = 0
			}
			nodePreview := selectorPreviewNode{
				AgentID:        node.AgentID,
				Status:         node.Status,
				Capacity:       node.Capacity,
				RunningTasks:   node.RunningTasks,
				AvailableSlots: availableSlots,
			}
			if node.Status != "Alive" {
				offlineNodes++
				nodePreview.Reason = "节点离线"
				group.Nodes = append(group.Nodes, nodePreview)
				continue
			}
			matched, reason := db.NodeMatchesSelectorRules(acc.selector, acc.rules, node.Tags)
			if !matched {
				mismatchedNodes++
				if reason == "" {
					reason = "不满足 selector"
				}
				nodePreview.Reason = reason
				group.Nodes = append(group.Nodes, nodePreview)
				continue
			}
			nodePreview.Matched = true
			if availableSlots == 0 {
				capacityExhausted++
				nodePreview.Reason = "容量已满"
			}
			group.MatchedNodes++
			group.AvailableSlots += availableSlots
			overallMatched[node.AgentID] = availableSlots
			group.Nodes = append(group.Nodes, nodePreview)
		}
		if group.AvailableSlots >= group.BatchCount {
			group.ImmediateBatches = group.BatchCount
		} else {
			group.ImmediateBatches = group.AvailableSlots
		}
		if group.BatchCount > group.ImmediateBatches {
			group.WaitingBatches = group.BatchCount - group.ImmediateBatches
			if group.ImmediateBatches > 0 {
				addReason(fmt.Sprintf("%d 个批次需要等待容量释放", group.WaitingBatches))
			}
		}

		if offlineNodes > 0 {
			addReason(fmt.Sprintf("%d 个节点离线", offlineNodes))
		}
		if mismatchedNodes > 0 {
			addReason(fmt.Sprintf("%d 个在线节点不满足 selector", mismatchedNodes))
		}
		if group.MatchedNodes > 0 && group.AvailableSlots == 0 && capacityExhausted > 0 {
			addReason("匹配节点当前没有空闲槽位")
		}
		if group.MatchedNodes == 0 {
			addReason("没有在线节点满足 selector")
		}
		group.Reasons = sortedReasonSet(reasonSet)
		for _, reason := range group.Reasons {
			addOverallReason(fmt.Sprintf("%s: %s", group.TargetType, reason))
		}
		groups = append(groups, group)
	}

	overallMatchedNodes := len(overallMatched)
	overallAvailableSlots := 0
	for _, slots := range overallMatched {
		overallAvailableSlots += slots
	}
	reasons := sortedReasonSet(overallReasons)
	if overallMatchedNodes == 0 {
		reasons = append(reasons, "没有在线节点满足最终 selector")
	}
	return groups, effectiveSelectors, overallMatchedNodes, overallAvailableSlots, reasons
}

func sortedReasonSet(reasonSet map[string]struct{}) []string {
	reasons := make([]string, 0, len(reasonSet))
	for reason := range reasonSet {
		reasons = append(reasons, reason)
	}
	sort.Strings(reasons)
	return reasons
}

func previewTaskSelector(c *gin.Context) {
	var req struct {
		ProjectID          string          `json:"project_id"`
		Targets            json.RawMessage `json:"targets"`
		Config             json.RawMessage `json:"config"`
		AgentSelector      json.RawMessage `json:"agent_selector"`
		AgentSelectorRules json.RawMessage `json:"agent_selector_rules"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.ProjectID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "project_id is required"})
		return
	}
	if _, ok := requireProjectAccess(c, req.ProjectID); !ok {
		return
	}
	userSelector, err := parseAgentSelector(req.AgentSelector)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	userRules, err := parseAgentSelectorRules(req.AgentSelectorRules)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, targetMode, err := normalizeTaskConfigPayload(req.Config)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	targets, targetSummary, err := parseAndValidateTargetsForMode(req.Targets, targetMode)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	batches := groupAndBatchTargets(targets, targetMode)

	tenantID := currentTenantID(c)
	var nodes []db.Node
	scopedNodeQuery(tenantID).Find(&nodes)
	groups, effectiveSelectors, matchedNodes, availableSlots, reasons := buildSelectorPreviewGroups(batches, userSelector, userRules, nodes)

	c.JSON(http.StatusOK, gin.H{
		"matched_nodes":       matchedNodes,
		"available_slots":     availableSlots,
		"reasons":             reasons,
		"effective_selectors": effectiveSelectors,
		"groups":              groups,
		"target_summary":      targetSummary,
	})
}
