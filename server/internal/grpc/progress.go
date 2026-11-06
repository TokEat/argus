package grpc

import (
	"encoding/json"
	"strings"

	"github.com/P0lar1ght/argus/server/internal/db"
	pb "github.com/P0lar1ght/argus/shared/proto/go/scan"
	"github.com/P0lar1ght/argus/shared/proto/go/scanplan"
)

// persistScanProgress 处理细粒度进度帧：解析 ProgressEvent，按 TaskId（attempt id）
// 定位子任务并刷新其 progress_*（tenant 范围，由 UpdateSubTaskProgress 内部保证）。
// 进度帧为尽力而为信号，任何解析/归属失败都静默丢弃并继续，绝不让结果流报错。
func persistScanProgress(result *pb.ScanResult) {
	if result == nil || strings.TrimSpace(result.TaskId) == "" {
		return
	}
	var event scanplan.ProgressEvent
	if err := json.Unmarshal(result.Payload, &event); err != nil {
		return
	}
	if event.Done < 0 || event.Total < 0 || event.Rate < 0 || event.EtaMillis < 0 {
		return
	}
	var sub db.SubTask
	if err := db.DB.Select("id", "tenant_id", "root_task_id", "status").
		First(&sub, "id = ?", strings.TrimSpace(result.TaskId)).Error; err != nil {
		return
	}
	if !strings.EqualFold(strings.TrimSpace(sub.Status), "Running") {
		return
	}
	db.UpdateSubTaskProgress(sub.TenantID, sub.ID, event.Phase, event.Done, event.Total, event.Rate, event.EtaMillis)
}
