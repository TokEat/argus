package db

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
)

var activeRootTaskStatuses = []string{"Queued", "Running", "PartialDone"}
var activeRunningSubTaskStatuses = []string{"Running", "CancelPending"}

type TenantQuotaUsage struct {
	ActiveTasks     int64 `json:"active_tasks"`
	RunningSubTasks int64 `json:"running_subtasks"`
	TasksToday      int64 `json:"tasks_today"`
}

type TenantQuotaError struct {
	Code    string
	Message string
}

func (e *TenantQuotaError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

func NormalizeTenantID(tenantID string) string {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return "default"
	}
	return tenantID
}

func GetTenantQuota(tx *gorm.DB, tenantID string) (TenantQuota, error) {
	tenantID = NormalizeTenantID(tenantID)
	var quota TenantQuota
	err := tx.Where("tenant_id = ?", tenantID).First(&quota).Error
	if err == nil {
		return quota, nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return TenantQuota{TenantID: tenantID}, nil
	}
	return TenantQuota{}, err
}

func UpsertTenantQuota(tx *gorm.DB, quota TenantQuota) (TenantQuota, error) {
	quota.TenantID = NormalizeTenantID(quota.TenantID)
	if quota.MaxConcurrentTasks < 0 || quota.MaxRunningSubTasks < 0 || quota.DailyTaskLimit < 0 {
		return TenantQuota{}, fmt.Errorf("quota values must be greater than or equal to 0")
	}
	var existing TenantQuota
	err := tx.Where("tenant_id = ?", quota.TenantID).First(&existing).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return TenantQuota{}, err
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		if err := tx.Create(&quota).Error; err != nil {
			return TenantQuota{}, err
		}
		return quota, nil
	}
	existing.MaxConcurrentTasks = quota.MaxConcurrentTasks
	existing.MaxRunningSubTasks = quota.MaxRunningSubTasks
	existing.DailyTaskLimit = quota.DailyTaskLimit
	if err := tx.Save(&existing).Error; err != nil {
		return TenantQuota{}, err
	}
	return existing, nil
}

func TenantQuotaUsageFor(tx *gorm.DB, tenantID string, now time.Time) (TenantQuotaUsage, error) {
	tenantID = NormalizeTenantID(tenantID)
	if now.IsZero() {
		now = time.Now()
	}
	startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	var usage TenantQuotaUsage
	if err := tx.Model(&RootTask{}).
		Where("tenant_id = ? AND status IN ?", tenantID, activeRootTaskStatuses).
		Count(&usage.ActiveTasks).Error; err != nil {
		return usage, err
	}
	if err := tx.Model(&SubTask{}).
		Where("tenant_id = ? AND status IN ?", tenantID, activeRunningSubTaskStatuses).
		Count(&usage.RunningSubTasks).Error; err != nil {
		return usage, err
	}
	if err := tx.Model(&RootTask{}).
		Where("tenant_id = ? AND created_at >= ?", tenantID, startOfDay).
		Count(&usage.TasksToday).Error; err != nil {
		return usage, err
	}
	return usage, nil
}

func CheckTenantTaskCreationQuota(tx *gorm.DB, tenantID string, now time.Time) error {
	quota, err := GetTenantQuota(tx, tenantID)
	if err != nil {
		return err
	}
	usage, err := TenantQuotaUsageFor(tx, tenantID, now)
	if err != nil {
		return err
	}
	if quota.MaxConcurrentTasks > 0 && usage.ActiveTasks >= int64(quota.MaxConcurrentTasks) {
		return &TenantQuotaError{
			Code:    "max_concurrent_tasks_exceeded",
			Message: fmt.Sprintf("tenant quota exceeded: active tasks %d/%d", usage.ActiveTasks, quota.MaxConcurrentTasks),
		}
	}
	if quota.DailyTaskLimit > 0 && usage.TasksToday >= int64(quota.DailyTaskLimit) {
		return &TenantQuotaError{
			Code:    "daily_task_limit_exceeded",
			Message: fmt.Sprintf("tenant quota exceeded: daily tasks %d/%d", usage.TasksToday, quota.DailyTaskLimit),
		}
	}
	return nil
}

func CheckTenantSubTaskClaimQuota(tx *gorm.DB, tenantID string) error {
	quota, err := GetTenantQuota(tx, tenantID)
	if err != nil {
		return err
	}
	if quota.MaxRunningSubTasks <= 0 {
		return nil
	}
	usage, err := TenantQuotaUsageFor(tx, tenantID, time.Now())
	if err != nil {
		return err
	}
	if usage.RunningSubTasks >= int64(quota.MaxRunningSubTasks) {
		return &TenantQuotaError{
			Code:    "max_running_sub_tasks_exceeded",
			Message: fmt.Sprintf("tenant quota exceeded: running subtasks %d/%d", usage.RunningSubTasks, quota.MaxRunningSubTasks),
		}
	}
	return nil
}
