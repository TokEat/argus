package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/TokEat/argus/server/internal/db"
	"github.com/TokEat/argus/shared/proto/go/scanpolicy"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type taskConfigRevisionResponse struct {
	Version            int             `json:"version"`
	Config             json.RawMessage `json:"config"`
	ConfigHash         string          `json:"config_hash"`
	Priority           int             `json:"priority"`
	TimeoutSec         int             `json:"timeout_sec"`
	AgentSelector      json.RawMessage `json:"agent_selector"`
	AgentSelectorRules json.RawMessage `json:"agent_selector_rules"`
	CreatedBy          string          `json:"created_by"`
	ChangeNote         string          `json:"change_note"`
	CreatedAt          time.Time       `json:"created_at"`
}

func validJSONOrEmptyObject(raw string) json.RawMessage {
	value := json.RawMessage(raw)
	if !json.Valid(value) {
		return json.RawMessage(`{}`)
	}
	return value
}

func taskConfigRevisionToResponse(revision db.TaskConfigRevision) taskConfigRevisionResponse {
	return taskConfigRevisionResponse{
		Version:            revision.Version,
		Config:             validJSONOrEmptyObject(revision.Config),
		ConfigHash:         revision.ConfigHash,
		Priority:           revision.Priority,
		TimeoutSec:         revision.TimeoutSec,
		AgentSelector:      validJSONOrEmptyObject(revision.AgentSelector),
		AgentSelectorRules: validJSONOrEmptyObject(revision.AgentSelectorRules),
		CreatedBy:          revision.CreatedBy,
		ChangeNote:         revision.ChangeNote,
		CreatedAt:          revision.CreatedAt,
	}
}

func getTaskConfigRevisions(c *gin.Context) {
	tenantID := currentTenantID(c)
	var task db.RootTask
	if err := db.DB.Where("id = ? AND tenant_id = ?", c.Param("id"), tenantID).First(&task).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
		return
	}
	if !canAccessProject(c, task.ProjectID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "project not accessible"})
		return
	}

	var revisions []db.TaskConfigRevision
	if err := db.DB.Where("root_task_id = ? AND tenant_id = ?", task.ID, tenantID).
		Order("version desc").Find(&revisions).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	items := make([]taskConfigRevisionResponse, 0, len(revisions))
	for _, revision := range revisions {
		items = append(items, taskConfigRevisionToResponse(revision))
	}
	c.JSON(http.StatusOK, gin.H{
		"task_id":                task.ID,
		"current_config_version": task.CurrentConfigVersion,
		"items":                  items,
	})
}

func updateTaskConfig(c *gin.Context) {
	var req struct {
		Config             json.RawMessage    `json:"config"`
		Priority           *int               `json:"priority"`
		TimeoutSec         *int               `json:"timeout_sec"`
		AgentSelector      json.RawMessage    `json:"agent_selector"`
		AgentSelectorRules json.RawMessage    `json:"agent_selector_rules"`
		ChangeNote         string             `json:"change_note"`
		Policy             *scanpolicy.Policy `json:"policy"`
		PlanHash           string             `json:"plan_hash"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if utf8.RuneCountInString(req.ChangeNote) > 500 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "change_note must not exceed 500 characters"})
		return
	}

	tenantID := currentTenantID(c)
	var task db.RootTask
	if err := db.DB.Where("id = ? AND tenant_id = ?", c.Param("id"), tenantID).First(&task).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
		return
	}
	if !canAccessProject(c, task.ProjectID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "project not accessible"})
		return
	}
	if task.ArchivedAt != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "archived task configuration is immutable"})
		return
	}

	var compiledPlan *scanPolicyPlan
	if req.Policy != nil {
		priority := task.Priority
		if req.Priority != nil {
			priority = *req.Priority
		}
		timeoutSec := task.TimeoutSec
		if req.TimeoutSec != nil {
			timeoutSec = *req.TimeoutSec
		}
		plan, err := compileTaskScanPolicy(c, scanPolicyPlanRequest{
			ProjectID:  task.ProjectID,
			Targets:    json.RawMessage(task.OriginalTargets),
			Policy:     *req.Policy,
			Priority:   &priority,
			TimeoutSec: &timeoutSec,
		})
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if strings.TrimSpace(req.PlanHash) == "" || !strings.EqualFold(strings.TrimSpace(req.PlanHash), plan.PlanHash) {
			c.JSON(http.StatusConflict, gin.H{
				"code":              "scan_plan_changed",
				"error":             "plan_hash does not match the current normalized plan",
				"current_plan_hash": plan.PlanHash,
			})
			return
		}
		compiledPlan = &plan
	}

	var result db.TaskConfigRevision
	unchanged := false
	err := db.DB.Transaction(func(tx *gorm.DB) error {
		var currentTask db.RootTask
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ? AND tenant_id = ?", task.ID, tenantID).First(&currentTask).Error; err != nil {
			return err
		}
		if currentTask.ArchivedAt != nil {
			return errors.New("archived task configuration is immutable")
		}
		current, err := db.CurrentTaskConfigRevision(tx, currentTask)
		if err != nil {
			return err
		}
		if current.ID == 0 {
			if err := tx.Create(&current).Error; err != nil {
				return err
			}
		}

		configJSON := current.Config
		agentSelector := current.AgentSelector
		agentSelectorRules := current.AgentSelectorRules
		if compiledPlan != nil {
			normalized, _, err := normalizeTaskConfigPayload(json.RawMessage(compiledPlan.ScannerConfig))
			if err != nil {
				return err
			}
			configJSON = normalized
			agentSelectorRules = compiledPlan.SelectorRules
			if strings.TrimSpace(agentSelector) == "" {
				agentSelector = "{}"
			}
		} else {
			if len(req.Config) > 0 {
				normalized, _, err := normalizeTaskConfigPayload(req.Config)
				if err != nil {
					return err
				}
				configJSON = normalized
			}
			if len(req.AgentSelector) > 0 {
				parsed, err := parseAgentSelector(req.AgentSelector)
				if err != nil {
					return err
				}
				agentSelector = mergeAgentSelector("{}", parsed)
			}
			if len(req.AgentSelectorRules) > 0 {
				parsed, err := parseAgentSelectorRules(req.AgentSelectorRules)
				if err != nil {
					return err
				}
				agentSelectorRules = db.SelectorRulesToJSON(parsed)
			}
		}

		priority := current.Priority
		if req.Priority != nil {
			if *req.Priority < 0 || *req.Priority > 2 {
				return errors.New("priority must be 0, 1, or 2")
			}
			priority = *req.Priority
		}
		timeoutSec := current.TimeoutSec
		if req.TimeoutSec != nil {
			if *req.TimeoutSec < 0 {
				return errors.New("timeout_sec must be greater than or equal to 0")
			}
			timeoutSec = *req.TimeoutSec
		}

		candidateTask := currentTask
		candidateTask.Config = configJSON
		candidateTask.Priority = priority
		candidateTask.TimeoutSec = timeoutSec
		candidate := db.NewTaskConfigRevision(candidateTask, current.Version+1, agentSelector, agentSelectorRules, taskOperatorID(c), req.ChangeNote)
		if candidate.ConfigHash == current.ConfigHash {
			result = current
			unchanged = true
			if compiledPlan != nil {
				if err := upsertTaskScanPolicyIntent(tx, currentTask, *compiledPlan, taskOperatorID(c)); err != nil {
					return err
				}
			}
			return nil
		}
		if err := tx.Create(&candidate).Error; err != nil {
			return err
		}
		update := tx.Model(&db.RootTask{}).
			Where("id = ? AND tenant_id = ? AND current_config_version = ? AND archived_at IS NULL", currentTask.ID, tenantID, current.Version).
			Updates(map[string]interface{}{
				"config":                 candidate.Config,
				"priority":               candidate.Priority,
				"timeout_sec":            candidate.TimeoutSec,
				"current_config_version": candidate.Version,
			})
		if update.Error != nil {
			return update.Error
		}
		if update.RowsAffected != 1 {
			return errTaskStateChanged
		}
		if compiledPlan != nil {
			if err := upsertTaskScanPolicyIntent(tx, currentTask, *compiledPlan, taskOperatorID(c)); err != nil {
				return err
			}
		}
		auditDetails := map[string]interface{}{
			"from_version": current.Version,
			"to_version":   candidate.Version,
			"from_hash":    current.ConfigHash,
			"to_hash":      candidate.ConfigHash,
		}
		if compiledPlan != nil {
			auditDetails["policy_hash"] = compiledPlan.PolicyHash
			auditDetails["plan_hash"] = compiledPlan.PlanHash
		}
		if err := recordTaskAudit(tx, currentTask, "config_update", currentTask.Status, currentTask.Status, taskOperatorID(c), auditDetails); err != nil {
			return err
		}
		result = candidate
		return nil
	})
	if err != nil {
		if writeTaskMutationError(c, err) {
			return
		}
		message := err.Error()
		if strings.Contains(message, "priority") || strings.Contains(message, "timeout_sec") || strings.Contains(message, "config contains") || strings.Contains(message, "agent_selector") {
			c.JSON(http.StatusBadRequest, gin.H{"error": message})
			return
		}
		if strings.Contains(message, "archived task") {
			c.JSON(http.StatusConflict, gin.H{"error": message})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": message})
		return
	}

	response := gin.H{
		"status":                 "configuration_saved",
		"unchanged":              unchanged,
		"current_config_version": result.Version,
		"revision":               taskConfigRevisionToResponse(result),
	}
	if compiledPlan != nil {
		response["policy_hash"] = compiledPlan.PolicyHash
		response["plan_hash"] = compiledPlan.PlanHash
	}
	c.JSON(http.StatusOK, response)
}

func nextScanStageIntentStatus(enabled bool, current string) string {
	switch current {
	case db.ScanStageIntentDerived, db.ScanStageIntentComplete, db.ScanStageIntentFailed:
		return current
	default:
		if enabled {
			return db.ScanStageIntentPending
		}
		return db.ScanStageIntentSkipped
	}
}

func upsertTaskScanPolicyIntent(tx *gorm.DB, task db.RootTask, plan scanPolicyPlan, operatorID string) error {
	policyJSON, err := json.Marshal(plan.Policy)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	var existing db.ScanPolicyIntent
	err = tx.Where("tenant_id = ? AND root_task_id = ?", task.TenantID, task.ID).First(&existing).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		intent, createErr := newScanPolicyIntent(plan, task.TenantID, task.ProjectID, task.ID, operatorID)
		if createErr != nil {
			return createErr
		}
		return tx.Create(intent).Error
	}
	if err != nil {
		return err
	}
	updates := map[string]interface{}{
		"schema_version":         plan.Policy.SchemaVersion,
		"policy_json":            string(policyJSON),
		"policy_hash":            plan.PolicyHash,
		"plan_hash":              plan.PlanHash,
		"risk_status":            nextScanStageIntentStatus(plan.Policy.Capabilities.RiskValidation, existing.RiskStatus),
		"credential_status":      nextScanStageIntentStatus(plan.Policy.Capabilities.CredentialValidation, existing.CredentialStatus),
		"authorization_actor_id": operatorID,
		"authorized_at":          &now,
		"updated_at":             now,
	}
	return tx.Model(&existing).Updates(updates).Error
}
