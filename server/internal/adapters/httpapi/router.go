package httpapi

import (
	"github.com/P0lar1ght/argus/server/internal/adapters/ws"
	"github.com/P0lar1ght/argus/server/internal/core/usecase"
	"github.com/gin-gonic/gin"
)

// Router 作为 HTTP 适配层入口，未来用于替换当前平铺式 api 包。
type Router struct {
	engine   *gin.Engine
	handlers Handlers
}

func NewRouter(usecases *usecase.Set, hub *ws.Hub) *Router {
	engine := gin.New()
	engine.Use(gin.Recovery())

	r := &Router{
		engine: engine,
		handlers: Handlers{
			Tasks:   NewTaskHandler(usecases.TaskOrchestrator, usecases.DashboardQuery),
			Nodes:   NewNodeHandler(usecases.NodeRegistry, usecases.DashboardQuery),
			Rules:   NewRuleHandler(usecases.RuleCenter),
			Results: NewResultHandler(usecases.ResultAggregator, usecases.DashboardQuery),
			System:  NewSystemHandler(usecases.DashboardQuery, hub),
		},
	}
	r.registerRoutes()
	return r
}

func (r *Router) Engine() *gin.Engine {
	return r.engine
}

func (r *Router) registerRoutes() {
	api := r.engine.Group("/api/v2")
	r.handlers.System.Register(api)
	r.handlers.Tasks.Register(api)
	r.handlers.Nodes.Register(api)
	r.handlers.Rules.Register(api)
	r.handlers.Results.Register(api)
}
