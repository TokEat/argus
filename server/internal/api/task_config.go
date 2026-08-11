package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/user/dddd-server/internal/db"
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
		Config             json.RawMessage `json:"config"`
		Priority           *int            `json:"priority"`
		TimeoutSec         *int            `json:"timeout_sec"`
		AgentSelector      json.RawMessage `json:"agent_selector"`
		AgentSelectorRules json.RawMessage `json:"agent_selector_rules"`
		ChangeNote         string          `json:"change_note"`
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
		if len(req.Config) > 0 {
			normalized, _, err := normalizeTaskConfigPayload(req.Config)
			if err != nil {
				return err
			}
			configJSON = normalized
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
		agentSelector := current.AgentSelector
		if len(req.AgentSelector) > 0 {
			parsed, err := parseAgentSelector(req.AgentSelector)
			if err != nil {
				return err
			}
			agentSelector = mergeAgentSelector("{}", parsed)
		}
		agentSelectorRules := current.AgentSelectorRules
		if len(req.AgentSelectorRules) > 0 {
			parsed, err := parseAgentSelectorRules(req.AgentSelectorRules)
			if err != nil {
				return err
			}
			agentSelectorRules = db.SelectorRulesToJSON(parsed)
		}

		candidateTask := currentTask
		candidateTask.Config = configJSON
		candidateTask.Priority = priority
		candidateTask.TimeoutSec = timeoutSec
		candidate := db.NewTaskConfigRevision(candidateTask, current.Version+1, agentSelector, agentSelectorRules, taskOperatorID(c), req.ChangeNote)
		if candidate.ConfigHash == current.ConfigHash {
			result = current
			unchanged = true
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
		if err := recordTaskAudit(tx, currentTask, "config_update", currentTask.Status, currentTask.Status, taskOperatorID(c), map[string]interface{}{
			"from_version": current.Version,
			"to_version":   candidate.Version,
			"from_hash":    current.ConfigHash,
			"to_hash":      candidate.ConfigHash,
		}); err != nil {
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

	c.JSON(http.StatusOK, gin.H{
		"status":                 "configuration_saved",
		"unchanged":              unchanged,
		"current_config_version": result.Version,
		"revision":               taskConfigRevisionToResponse(result),
	})
}
