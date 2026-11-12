package api

import (
	"errors"
	"log"
	"net/http"

	"github.com/TokEat/argus/server/internal/db"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// purgeTask 硬删除（彻底清空）一个终态任务：物理删除任务及其全部关联数据，不可逆。
// 与软删除 deleteTask（归档，保留数据）不同，本端点用于真正移除任务。
// 安全门槛：租户内查找 → 项目 manage 级授权（admin/owner）→ 终态校验 → 危险操作确认
// （请求体须显式 {"confirm": true}）→ 单事务级联清空并留存一条不可变 hard_delete 审计。
func purgeTask(c *gin.Context) {
	id := c.Param("id")
	tenantID := currentTenantID(c)

	var rootTask db.RootTask
	if err := db.DB.Where("id = ? AND tenant_id = ?", id, tenantID).First(&rootTask).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
			return
		}
		log.Printf("purge task %s lookup failed: %v", id, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "彻底删除失败，请稍后重试"})
		return
	}
	if _, ok := requireProjectManage(c, rootTask.ProjectID); !ok {
		return
	}
	if !db.IsTerminalTaskStatus(rootTask.Status) {
		c.JSON(http.StatusConflict, gin.H{"error": "仅终态（已完成/失败/已停止/超时/已归档）任务可彻底删除"})
		return
	}

	var body struct {
		Confirm bool `json:"confirm"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || !body.Confirm {
		c.JSON(http.StatusBadRequest, gin.H{"error": "彻底删除不可恢复，请在请求体中显式确认 {\"confirm\": true}"})
		return
	}

	counts, err := db.PurgeRootTask(c.Request.Context(), tenantID, rootTask.ProjectID, id, taskOperatorID(c))
	if err != nil {
		if errors.Is(err, db.ErrTaskNotTerminal) {
			c.JSON(http.StatusConflict, gin.H{"error": "任务状态已变更，非终态任务不可彻底删除"})
			return
		}
		log.Printf("purge task %s failed: %v", id, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "彻底删除失败，请稍后重试"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "purged", "deleted": counts})
}
