package bootstrap

import (
	"github.com/user/dddd-server/internal/adapters/grpcagent"
	"github.com/user/dddd-server/internal/adapters/httpapi"
	"github.com/user/dddd-server/internal/adapters/persistence/gormrepo"
	"github.com/user/dddd-server/internal/adapters/queue"
	"github.com/user/dddd-server/internal/adapters/ws"
	"github.com/user/dddd-server/internal/config"
	"github.com/user/dddd-server/internal/core/usecase"
	"gorm.io/gorm"
)

// Application 作为新的控制面装配根，负责聚合配置、适配器和用例。
// 当前先建立结构，后续可逐步把 cmd/main.go 的直接 wiring 迁入这里。
type Application struct {
	Config       config.Config
	Repositories *gormrepo.RepositorySet
	UseCases     *usecase.Set
	Hub          *ws.Hub
	HTTP         *httpapi.Router
	GRPC         *grpcagent.Server
}

func NewPlaceholder(cfg config.Config, db *gorm.DB) *Application {
	repositories := gormrepo.NewRepositorySet(db)
	hub := ws.NewHub()
	taskQueue := queue.NewTaskQueueAdapter("placeholder")
	useCases := usecase.NewSet(repositories.Tasks, taskQueue, repositories.Nodes, repositories.Rules, repositories.Results)

	return &Application{
		Config:       cfg,
		Repositories: repositories,
		UseCases:     useCases,
		Hub:          hub,
		HTTP:         httpapi.NewRouter(useCases, hub),
		GRPC:         grpcagent.NewServer(useCases, hub),
	}
}
