package db

import (
	"strings"
	"time"
)

// UpdateSubTaskProgress 记录某个运行中子任务的实时进度（当前阶段 + 活动计数 + 输入总数 +
// 单元模式吞吐/ETA + liveness 时间）。tenant 范围更新；只触碰 progress_* 列，**不改 updated_at**——
// 超时守护以 updated_at+timeout_sec 为截止，刷新它会让长任务永不超时。随后把该 root 任务的
// 活动计数/吞吐聚合到 root_tasks.progress_done / progress_rate。
//
// 语义说明：发现模式（unit=false）下 progress_done 是「当前阶段内的活动计数」（引擎发现类
// 输出数），progress_total 是输入总数，二者单位不同，progress_done 可能远小于 progress_total，
// 只作「仍有活动、进度在推进」的实时信号，**不作为完成度占比**。单元模式（unit=true，如端口
// 扫描 connect 尝试数）二者同口径，可显示 done/total 占比；progress_rate（单元/秒）与
// progress_eta_ms（预计剩余）仅单元模式有意义，发现模式恒为 0。完成度仍以
// CompletedTargets/TotalTargets 为准。失败静默返回，绝不打断结果流。
func UpdateSubTaskProgress(tenantID, subTaskID, phase string, done, total int, rate float64, etaMillis int64) {
	tenantID = strings.TrimSpace(tenantID)
	subTaskID = strings.TrimSpace(subTaskID)
	if tenantID == "" || subTaskID == "" {
		return
	}
	now := time.Now()
	res := DB.Model(&SubTask{}).
		Where("id = ? AND tenant_id = ?", subTaskID, tenantID).
		UpdateColumns(map[string]interface{}{
			"progress_phase":      strings.TrimSpace(phase),
			"progress_done":       done,
			"progress_total":      total,
			"progress_rate":       rate,
			"progress_eta_ms":     etaMillis,
			"progress_updated_at": now,
		})
	if res.Error != nil || res.RowsAffected == 0 {
		return
	}
	var sub SubTask
	if err := DB.Select("root_task_id").First(&sub, "id = ? AND tenant_id = ?", subTaskID, tenantID).Error; err != nil {
		return
	}
	if sub.RootTaskID == "" {
		return
	}
	recomputeRootTaskProgress(tenantID, sub.RootTaskID)
}

// recomputeRootTaskProgress 把运行中子任务的活动计数求和写入 root_tasks.progress_done、
// 吞吐求和写入 root_tasks.progress_rate，供任务列表展示「仍在推进」的实时信号。仅聚合 Running
// 子任务；子任务终态后由 RefreshRootTaskStatus 的目标/批次维度进度接管。同样不改 updated_at。
// 该值是活动计数/吞吐总和，不是完成度占比；UI 仅据此做活跃动画，填充比例仍用
// CompletedTargets/TotalTargets。
func recomputeRootTaskProgress(tenantID, rootTaskID string) {
	var sums struct {
		Done int64
		Rate float64
	}
	DB.Model(&SubTask{}).
		Where("tenant_id = ? AND root_task_id = ? AND status = ?", tenantID, rootTaskID, "Running").
		Select("COALESCE(SUM(progress_done),0) AS done, COALESCE(SUM(progress_rate),0) AS rate").
		Scan(&sums)
	DB.Model(&RootTask{}).
		Where("id = ? AND tenant_id = ?", rootTaskID, tenantID).
		UpdateColumns(map[string]interface{}{
			"progress_done": sums.Done,
			"progress_rate": sums.Rate,
		})
}
