package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ErrTaskNotTerminal 表示尝试硬删除一个非终态任务。硬删除物理清空全部关联数据，
// 若在任务仍运行/排队时执行会留下半删状态并误伤在途结果，故前置拦截。
var ErrTaskNotTerminal = errors.New("task is not in a terminal status")

// purgeChildTables 列出硬删除时按 root_task_id 物理清空的任务子表。
// 顺序有含义：对 root_tasks/sub_tasks/task_batches 持有 ON DELETE RESTRICT FK 的表
// （asset_discovery_notebook_distribution_*、risk_validation_execution_idempotencies、
// scan_timing_events、task_*_idempotencies）必须排在 sub_tasks/task_batches 之前删除；
// sub_tasks/task_batches 固定在切片尾部，root_tasks 不在此列、由函数体最后删除。
// 表名为硬编码常量（非用户输入），配合参数化 WHERE 使用，无注入面。
var purgeChildTables = []string{
	"asset_discovery_notebook_distribution_intents",
	"asset_discovery_notebook_distribution_materializations",
	"risk_validation_execution_idempotencies",
	"scan_timing_events",
	"task_append_idempotencies",
	"task_batch_retry_idempotencies",
	"task_creation_idempotencies",
	"task_retry_idempotencies",
	"task_audits",
	"task_config_revisions",
	"scan_observations",
	"scan_stage_derivations",
	"scan_policy_intents",
	"task_coverage_links",
	"assets",
	"fingerprint_hits",
	"vulnerabilities",
	"sensitive_findings",
	"crawl_site_candidates",
	"credential_bundles",
	"credential_finding_secrets",
	"subdomain_passive_jobs",
	"egress_ban_events",
	"ai_finding_reviews",
	"task_batches",
	"sub_tasks",
}

// purgeAuditAction 是硬删除留存的审计动作名。硬删除会先清空该任务的全部旧 task_audits，
// 再于同一事务插入一条本动作记录，作为任务本体已删后仍不可变的审计证据。
const purgeAuditAction = "hard_delete"

// PurgeRootTask 物理清空一个终态任务及其全部关联数据（不可逆）。
// 全程单事务：行锁重校验终态 → 按 root_task_id 删 26 张子表 → 按 source_task_id 删
// scan_coverages → 删 root_tasks 行 → 插入一条 hard_delete 审计。任一失败整体回滚。
// 返回每表删除行数（审计用）。tenantID/projectID 双条件保证租户隔离，绝不跨租户删行。
//
// 注意：assets/fingerprint_hits/vulnerabilities/sensitive_findings/crawl_site_candidates 按
// (project_id,target) 去重 upsert 且冲突时更新 root_task_id 为最后写入任务，故这里的删除
// 以「最后归属」为准——可能删掉其他任务也贡献过的行（产品已确认的取舍）。
func PurgeRootTask(ctx context.Context, tenantID, projectID, taskID, operatorID string) (map[string]int64, error) {
	counts := make(map[string]int64, len(purgeChildTables)+2)
	err := DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var root RootTask
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ? AND tenant_id = ?", taskID, tenantID).
			First(&root).Error; err != nil {
			return err
		}
		if !IsTerminalTaskStatus(root.Status) {
			return ErrTaskNotTerminal
		}

		for _, tbl := range purgeChildTables {
			res := tx.Exec(
				"DELETE FROM "+tbl+" WHERE tenant_id = ? AND project_id = ? AND root_task_id = ?",
				tenantID, projectID, taskID,
			)
			if res.Error != nil {
				return fmt.Errorf("purge %s: %w", tbl, res.Error)
			}
			counts[tbl] = res.RowsAffected
		}

		res := tx.Exec(
			"DELETE FROM scan_coverages WHERE tenant_id = ? AND project_id = ? AND source_task_id = ?",
			tenantID, projectID, taskID,
		)
		if res.Error != nil {
			return fmt.Errorf("purge scan_coverages: %w", res.Error)
		}
		counts["scan_coverages"] = res.RowsAffected

		res = tx.Exec(
			"DELETE FROM root_tasks WHERE tenant_id = ? AND project_id = ? AND id = ?",
			tenantID, projectID, taskID,
		)
		if res.Error != nil {
			return fmt.Errorf("purge root_tasks: %w", res.Error)
		}
		counts["root_tasks"] = res.RowsAffected

		details, err := json.Marshal(map[string]interface{}{
			"deleted":    counts,
			"purged_at":  time.Now().UTC().Format(time.RFC3339),
			"project_id": projectID,
		})
		if err != nil {
			return err
		}
		// task_audits.root_task_id 是普通列、无 FK：root_task 行已删后仍可插入指向它的审计行。
		return tx.Create(&TaskAudit{
			TenantID:     tenantID,
			ProjectID:    projectID,
			RootTaskID:   taskID,
			OperatorID:   operatorID,
			Action:       purgeAuditAction,
			BeforeStatus: root.Status,
			AfterStatus:  "purged",
			Details:      string(details),
		}).Error
	})
	if err != nil {
		return nil, err
	}
	return counts, nil
}
