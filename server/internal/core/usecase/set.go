package usecase

import (
	"github.com/P0lar1ght/argus/server/internal/core/domain/node"
	"github.com/P0lar1ght/argus/server/internal/core/domain/result"
	"github.com/P0lar1ght/argus/server/internal/core/domain/rule"
	"github.com/P0lar1ght/argus/server/internal/core/domain/task"
)

// Set 汇总控制面的核心用例，供 HTTP/gRPC/定时任务统一依赖。
type Set struct {
	TaskOrchestrator *TaskOrchestrator
	TaskScheduler    *TaskScheduler
	NodeRegistry     *NodeRegistry
	RuleCenter       *RuleCenter
	ResultAggregator *ResultAggregator
	DashboardQuery   *DashboardQuery
}

func NewSet(
	taskRepo task.Repository,
	taskQueue task.Queue,
	nodeRepo node.Repository,
	ruleRepo rule.Repository,
	resultRepo result.Repository,
) *Set {
	return &Set{
		TaskOrchestrator: NewTaskOrchestrator(taskRepo, taskQueue),
		TaskScheduler:    NewTaskScheduler(taskRepo, taskQueue, nodeRepo),
		NodeRegistry:     NewNodeRegistry(nodeRepo),
		RuleCenter:       NewRuleCenter(ruleRepo),
		ResultAggregator: NewResultAggregator(resultRepo),
		DashboardQuery:   NewDashboardQuery(taskRepo, nodeRepo, resultRepo),
	}
}
