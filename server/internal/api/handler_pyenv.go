package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	pb "github.com/user/dddd-proto/go/scan"
	"github.com/user/dddd-proto/pyexp"
	"github.com/user/dddd-server/internal/db"
	"gorm.io/gorm"
)

type agentPyenvResponse struct {
	AgentID          string                 `json:"agent_id"`
	Status           string                 `json:"status"`
	PythonPath       string                 `json:"python_path"`
	PythonVersion    string                 `json:"python_version"`
	PipAvailable     bool                   `json:"pip_available"`
	InstallAvailable bool                   `json:"install_available"`
	LastJob          *agentPyenvJobResponse `json:"last_job,omitempty"`
	Tags             map[string]string      `json:"tags"`
}

type agentPyenvInstallRequest struct {
	ExploitRuleID uint `json:"exploit_rule_id" binding:"required"`
}

type agentPyenvJobResponse struct {
	ID               string   `json:"id"`
	TenantID         string   `json:"tenant_id"`
	AgentID          string   `json:"agent_id"`
	OperatorID       string   `json:"operator_id"`
	ExploitRuleID    uint     `json:"exploit_rule_id"`
	Requirements     []string `json:"requirements"`
	RequirementsHash string   `json:"requirements_hash"`
	Status           string   `json:"status"`
	Logs             string   `json:"logs"`
	Error            string   `json:"error"`
	StartedAt        string   `json:"started_at,omitempty"`
	FinishedAt       string   `json:"finished_at,omitempty"`
	CreatedAt        string   `json:"created_at"`
	UpdatedAt        string   `json:"updated_at"`
}

func getAgentPyenv(c *gin.Context) {
	tenantID := currentTenantID(c)
	agentID := strings.TrimSpace(c.Param("id"))
	var node db.Node
	if err := scopedNodeQuery(tenantID).Where("agent_id = ?", agentID).First(&node).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Agent not found"})
		return
	}
	tags := decodeTagMap(node.Tags)
	resp := agentPyenvResponse{
		AgentID:          node.AgentID,
		Status:           node.Status,
		PythonPath:       tags["pyexp_python"],
		PythonVersion:    tags["pyexp_python_version"],
		PipAvailable:     strings.EqualFold(tags["pyexp_pip"], "true"),
		InstallAvailable: agentPyexpInstallAvailable(tags),
		Tags:             tags,
	}
	var job db.AgentPyenvJob
	if err := db.DB.Where("tenant_id = ? AND agent_id = ?", tenantID, node.AgentID).
		Order("created_at DESC").First(&job).Error; err == nil {
		jobResp := agentPyenvJobToResponse(job)
		resp.LastJob = &jobResp
	}
	c.JSON(http.StatusOK, resp)
}

func installAgentPyenvRequirements(c *gin.Context) {
	tenantID := currentTenantID(c)
	agentID := strings.TrimSpace(c.Param("id"))
	var req agentPyenvInstallRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var node db.Node
	if err := scopedNodeQuery(tenantID).Where("agent_id = ?", agentID).First(&node).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Agent not found"})
		return
	}
	if node.Status != "Alive" {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Agent is offline"})
		return
	}
	tags := decodeTagMap(node.Tags)

	var rule db.ExploitRule
	if err := db.DB.Where("id = ? AND tenant_id = ?", req.ExploitRuleID, tenantID).First(&rule).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Exploit rule not found"})
		return
	}
	requirements := decodeStringList(rule.Requirements)
	if len(requirements) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"status":          "no_op",
			"message":         "EXP has no requirements",
			"agent_id":        agentID,
			"exploit_rule_id": rule.ID,
		})
		return
	}
	if !agentPyexpInstallAvailable(tags) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Agent does not support Python EXP dependency install"})
		return
	}
	for _, item := range requirements {
		if err := pyexp.ValidateRequirement(item); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid EXP requirement: %v", err)})
			return
		}
	}
	requirementsHash := pyexp.RequirementsHash(requirements)
	if routerRuntime().NotifyHub == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Agent notify hub is unavailable"})
		return
	}

	now := time.Now()
	job := db.AgentPyenvJob{
		ID:               uuid.NewString(),
		TenantID:         tenantID,
		AgentID:          agentID,
		OperatorID:       currentUserID(c),
		ExploitRuleID:    rule.ID,
		Requirements:     marshalJSONArray(requirements),
		RequirementsHash: requirementsHash,
		Status:           "Pending",
		StartedAt:        &now,
	}
	if err := db.DB.Create(&job).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	paramsJSON, _ := json.Marshal(map[string]interface{}{
		"job_id":            job.ID,
		"requirements":      requirements,
		"requirements_hash": job.RequirementsHash,
		"timeout_sec":       300,
	})
	cmd := &pb.DebugCommand{
		Action:     "install_pyexp_requirements",
		SessionId:  job.ID,
		TenantId:   tenantID,
		TimeoutSec: 300,
		Params:     string(paramsJSON),
	}
	if err := routerRuntime().NotifyHub.SendDebugCommand(agentID, cmd); err != nil {
		finished := time.Now()
		job.Status = "Failed"
		job.Error = fmt.Sprintf("dispatch failed: %v", err)
		job.FinishedAt = &finished
		_ = db.DB.Save(&job).Error
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": job.Error, "job": agentPyenvJobToResponse(job)})
		return
	}
	job.Status = "Running"
	_ = db.DB.Model(&job).Update("status", job.Status).Error
	c.JSON(http.StatusAccepted, agentPyenvJobToResponse(job))
}

func getAgentPyenvJob(c *gin.Context) {
	tenantID := currentTenantID(c)
	agentID := strings.TrimSpace(c.Param("id"))
	jobID := strings.TrimSpace(c.Param("job_id"))
	var job db.AgentPyenvJob
	if err := db.DB.Where("tenant_id = ? AND agent_id = ? AND id = ?", tenantID, agentID, jobID).First(&job).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Job not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, agentPyenvJobToResponse(job))
}

func handlePyenvDebugEvent(event *pb.DebugEvent) bool {
	if event == nil || (event.Type != "pyenv_log" && event.Type != "pyenv_result") {
		return false
	}
	var job db.AgentPyenvJob
	if err := db.DB.Where("id = ? AND tenant_id = ? AND agent_id = ?", event.SessionId, event.TenantId, event.AgentId).First(&job).Error; err != nil {
		return true
	}
	if event.Type == "pyenv_log" {
		line := formatPyenvLogLine(event)
		job.Logs = appendJobLog(job.Logs, line)
		_ = db.DB.Model(&job).Update("logs", job.Logs).Error
		return true
	}
	finished := time.Now()
	status := strings.TrimSpace(event.Severity)
	if status == "" {
		status = "Failed"
	}
	updates := map[string]interface{}{
		"status":      status,
		"finished_at": finished,
	}
	if strings.TrimSpace(event.Error) != "" {
		updates["error"] = event.Error
	}
	if strings.TrimSpace(event.Message) != "" {
		updates["logs"] = appendJobLog(job.Logs, formatPyenvLogLine(event))
	}
	_ = db.DB.Model(&job).Updates(updates).Error
	return true
}

func agentPyenvJobToResponse(job db.AgentPyenvJob) agentPyenvJobResponse {
	resp := agentPyenvJobResponse{
		ID:               job.ID,
		TenantID:         job.TenantID,
		AgentID:          job.AgentID,
		OperatorID:       job.OperatorID,
		ExploitRuleID:    job.ExploitRuleID,
		Requirements:     decodeStringList(job.Requirements),
		RequirementsHash: job.RequirementsHash,
		Status:           job.Status,
		Logs:             job.Logs,
		Error:            job.Error,
		CreatedAt:        job.CreatedAt.Format(timeFormatRFC3339()),
		UpdatedAt:        job.UpdatedAt.Format(timeFormatRFC3339()),
	}
	if job.StartedAt != nil {
		resp.StartedAt = job.StartedAt.Format(timeFormatRFC3339())
	}
	if job.FinishedAt != nil {
		resp.FinishedAt = job.FinishedAt.Format(timeFormatRFC3339())
	}
	return resp
}

func decodeTagMap(raw string) map[string]string {
	out := map[string]string{}
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

func agentPyexpInstallAvailable(tags map[string]string) bool {
	return strings.EqualFold(tags["pyexp_install"], "true")
}

func appendJobLog(existing, line string) string {
	line = strings.TrimRight(line, "\r\n")
	if strings.TrimSpace(line) == "" {
		return existing
	}
	if existing == "" {
		return line
	}
	return existing + "\n" + line
}

func formatPyenvLogLine(event *pb.DebugEvent) string {
	level := strings.ToUpper(strings.TrimSpace(event.Level))
	if level == "" {
		level = "INFO"
	}
	message := strings.TrimSpace(event.Message)
	if event.Error != "" {
		if message != "" {
			message += ": "
		}
		message += event.Error
	}
	return fmt.Sprintf("[%s] %s", level, message)
}
