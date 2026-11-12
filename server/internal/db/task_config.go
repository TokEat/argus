package db

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"
)

// TaskConfigHash identifies the complete immutable task configuration snapshot.
// It is an identity hash, not a credential or authorization token.
func TaskConfigHash(config string, priority, timeoutSec int, agentSelector, agentSelectorRules string) string {
	payload := strings.Join([]string{
		config,
		fmt.Sprintf("%d", priority),
		fmt.Sprintf("%d", timeoutSec),
		agentSelector,
		agentSelectorRules,
	}, "\x1f")
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func NewTaskConfigRevision(task RootTask, version int, agentSelector, agentSelectorRules, createdBy, changeNote string) TaskConfigRevision {
	if version < 1 {
		version = 1
	}
	if strings.TrimSpace(agentSelector) == "" {
		agentSelector = "{}"
	}
	if strings.TrimSpace(agentSelectorRules) == "" {
		agentSelectorRules = "{}"
	}
	if strings.TrimSpace(task.Config) == "" {
		task.Config = "{}"
	}
	return TaskConfigRevision{
		TenantID:           task.TenantID,
		ProjectID:          task.ProjectID,
		RootTaskID:         task.ID,
		Version:            version,
		Config:             task.Config,
		ConfigHash:         TaskConfigHash(task.Config, task.Priority, task.TimeoutSec, agentSelector, agentSelectorRules),
		Priority:           task.Priority,
		TimeoutSec:         task.TimeoutSec,
		AgentSelector:      agentSelector,
		AgentSelectorRules: agentSelectorRules,
		CreatedBy:          createdBy,
		ChangeNote:         strings.TrimSpace(changeNote),
	}
}

// CurrentTaskConfigRevision returns the immutable current snapshot. The
// RootTask fallback keeps rolling upgrades and old rows usable until backfill.
func CurrentTaskConfigRevision(tx *gorm.DB, task RootTask) (TaskConfigRevision, error) {
	version := task.CurrentConfigVersion
	if version < 1 {
		version = 1
	}
	var revision TaskConfigRevision
	err := tx.Where("tenant_id = ? AND root_task_id = ? AND version = ?", task.TenantID, task.ID, version).
		First(&revision).Error
	if err == nil {
		if strings.TrimSpace(revision.ConfigHash) == "" {
			revision.ConfigHash = TaskConfigHash(revision.Config, revision.Priority, revision.TimeoutSec, revision.AgentSelector, revision.AgentSelectorRules)
		}
		return revision, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return TaskConfigRevision{}, err
	}
	return NewTaskConfigRevision(task, version, "{}", "{}", task.UserID, "legacy task fallback"), nil
}
