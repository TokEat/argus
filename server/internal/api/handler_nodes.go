package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/user/dddd-server/internal/db"
)

// 提供给 Agent 轮询其需强制退出的指令以及规则重载指令
func getAgentCommands(c *gin.Context) {
	id := c.Param("id")
	tenantID := currentTenantID(c)
	var subTasks []db.SubTask
	// 对于该节点正在运行但被强制退出的任务
	db.DB.Where("agent_id = ? AND tenant_id = ? AND status = 'CancelPending'", id, tenantID).Find(&subTasks)

	var cancels []string
	for _, st := range subTasks {
		cancels = append(cancels, st.ID)
	}

	ruleVersion := currentRuleVersionValue()
	reloadRules := false
	var nodes []db.Node
	if err := scopedNodeQuery(tenantID).Select("rule_version").Where("agent_id = ?", id).Limit(1).Find(&nodes).Error; err == nil && len(nodes) > 0 {
		reloadRules = shouldAgentReloadRules(nodes[0].RuleVersion, ruleVersion)
	}
	apiConfigHash := currentAPIConfigHashValue(tenantID)
	agentAPIConfigHash := strings.TrimSpace(c.Query("api_config_hash"))
	syncAPIConfig := agentAPIConfigHash != apiConfigHash

	c.JSON(http.StatusOK, gin.H{
		"cancel_tasks":    cancels,
		"reload_rules":    reloadRules,
		"rule_version":    ruleVersion,
		"sync_api_config": syncAPIConfig,
		"api_config_hash": apiConfigHash,
	})
}

type NodeResponse struct {
	db.Node
	RunningTaskDetails []map[string]interface{} `json:"RunningTaskDetails"`
}

func getNodes(c *gin.Context) {
	tenantID := currentTenantID(c)
	var nodes []db.Node
	scopedNodeQuery(tenantID).Find(&nodes)

	resp := make([]NodeResponse, 0, len(nodes))
	for _, n := range nodes {
		nr := NodeResponse{
			Node:               n,
			RunningTaskDetails: make([]map[string]interface{}, 0),
		}
		if n.RunningTaskIDs != "" && n.RunningTaskIDs != "[]" {
			var ids []string
			if err := json.Unmarshal([]byte(n.RunningTaskIDs), &ids); err == nil && len(ids) > 0 {
				var subTasks []db.SubTask
				db.DB.Where("tenant_id = ? AND id IN ?", tenantID, ids).Find(&subTasks)
				for _, sub := range subTasks {
					var targets []string
					_ = json.Unmarshal([]byte(sub.ChunkTargets), &targets)
					// 生成目标预览（前5个）
					previewLimit := 5
					preview := targets
					if len(preview) > previewLimit {
						preview = preview[:previewLimit]
					}
					nr.RunningTaskDetails = append(nr.RunningTaskDetails, map[string]interface{}{
						"task_id":        sub.ID,
						"targets":        targets,
						"target_count":   len(targets),
						"target_preview": preview,
					})
				}
			}
		}
		resp = append(resp, nr)
	}

	c.JSON(http.StatusOK, resp)
}

func deleteNode(c *gin.Context) {
	agentID := c.Param("id")
	tenantID := currentTenantID(c)

	res := scopedNodeQuery(tenantID).Where("agent_id = ?", agentID).Delete(&db.Node{})
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": res.Error.Error()})
		return
	}
	if res.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Node not found or already deleted"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

func revokeNodeToken(c *gin.Context) {
	agentID := c.Param("id")
	tenantID := currentTenantID(c)
	now := time.Now()
	res := scopedNodeQuery(tenantID).Where("agent_id = ?", agentID).Updates(map[string]interface{}{
		"token":            "",
		"token_revoked_at": &now,
		"status":           "Offline",
	})
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": res.Error.Error()})
		return
	}
	if res.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Node not found"})
		return
	}
	_ = db.DB.Create(&db.AgentSessionAudit{
		TenantID:   tenantID,
		AgentID:    agentID,
		Action:     "revoke",
		Reason:     "admin revoked agent session token",
		OperatorID: currentUserID(c),
		CreatedAt:  now,
	}).Error
	c.JSON(http.StatusOK, gin.H{"status": "revoked", "agent_id": agentID, "token_revoked_at": now})
}

func cleanOfflineNodes(c *gin.Context) {
	tenantID := currentTenantID(c)

	res := scopedNodeQuery(tenantID).Where("status = ?", "Offline").Delete(&db.Node{})
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": res.Error.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "cleaned", "count": res.RowsAffected})
}
