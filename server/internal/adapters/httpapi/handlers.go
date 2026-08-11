package httpapi

import (
	"net/http"

	"github.com/P0lar1ght/argus/server/internal/adapters/ws"
	"github.com/P0lar1ght/argus/server/internal/core/usecase"
	"github.com/gin-gonic/gin"
)

type Handlers struct {
	Tasks   *TaskHandler
	Nodes   *NodeHandler
	Rules   *RuleHandler
	Results *ResultHandler
	System  *SystemHandler
}

type TaskHandler struct {
	orchestrator *usecase.TaskOrchestrator
	dashboard    *usecase.DashboardQuery
}

func NewTaskHandler(orchestrator *usecase.TaskOrchestrator, dashboard *usecase.DashboardQuery) *TaskHandler {
	return &TaskHandler{orchestrator: orchestrator, dashboard: dashboard}
}

func (h *TaskHandler) Register(api *gin.RouterGroup) {
	group := api.Group("/tasks")
	group.GET("", h.list)
	group.POST("", h.create)
	group.DELETE("/:id", h.cancel)
}

type NodeHandler struct {
	registry  *usecase.NodeRegistry
	dashboard *usecase.DashboardQuery
}

func NewNodeHandler(registry *usecase.NodeRegistry, dashboard *usecase.DashboardQuery) *NodeHandler {
	return &NodeHandler{registry: registry, dashboard: dashboard}
}

func (h *NodeHandler) Register(api *gin.RouterGroup) {
	group := api.Group("/nodes")
	group.GET("", h.list)
}

type RuleHandler struct {
	center *usecase.RuleCenter
}

func NewRuleHandler(center *usecase.RuleCenter) *RuleHandler {
	return &RuleHandler{center: center}
}

func (h *RuleHandler) Register(api *gin.RouterGroup) {
	group := api.Group("/rules")
	group.GET("/bundles/active", h.activeBundle)
	group.POST("/bundles", h.publishBundle)
}

type ResultHandler struct {
	aggregator *usecase.ResultAggregator
	dashboard  *usecase.DashboardQuery
}

func NewResultHandler(aggregator *usecase.ResultAggregator, dashboard *usecase.DashboardQuery) *ResultHandler {
	return &ResultHandler{aggregator: aggregator, dashboard: dashboard}
}

func (h *ResultHandler) Register(api *gin.RouterGroup) {
	group := api.Group("/results")
	group.GET("/summary", h.summary)
	group.GET("/vulnerabilities", h.listVulnerabilities)
}

type SystemHandler struct {
	dashboard *usecase.DashboardQuery
	hub       *ws.Hub
}

func NewSystemHandler(dashboard *usecase.DashboardQuery, hub *ws.Hub) *SystemHandler {
	return &SystemHandler{dashboard: dashboard, hub: hub}
}

func (h *SystemHandler) Register(api *gin.RouterGroup) {
	api.GET("/stats", h.stats)
	api.GET("/ws", h.websocket)
}

func (h *TaskHandler) list(c *gin.Context)          { notImplemented(c) }
func (h *TaskHandler) create(c *gin.Context)        { notImplemented(c) }
func (h *TaskHandler) cancel(c *gin.Context)        { notImplemented(c) }
func (h *NodeHandler) list(c *gin.Context)          { notImplemented(c) }
func (h *RuleHandler) activeBundle(c *gin.Context)  { notImplemented(c) }
func (h *RuleHandler) publishBundle(c *gin.Context) { notImplemented(c) }
func (h *ResultHandler) summary(c *gin.Context)     { notImplemented(c) }
func (h *ResultHandler) listVulnerabilities(c *gin.Context) {
	notImplemented(c)
}
func (h *SystemHandler) stats(c *gin.Context)     { notImplemented(c) }
func (h *SystemHandler) websocket(c *gin.Context) { notImplemented(c) }

func notImplemented(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "adapter scaffold created, handler not implemented yet",
	})
}
