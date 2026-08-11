.PHONY: cli agent server mcp legacy all clean docker infra-up infra-down infra-logs db-init db-migrate db-verify setup-local smoke-local test coverage frontend-smoke cloud-smoke source-size-check release-artifacts lint ci

COMPOSE_FILE := server/deploy/docker-compose.yml
DOCKER_COMPOSE := docker compose -f $(COMPOSE_FILE)
COVERAGE_DIR ?= /tmp/argus-coverage
VERSION ?= v0.1.0
DB_HOST ?= 127.0.0.1
POSTGRES_PORT ?= 5432
DB_PORT ?= $(POSTGRES_PORT)
POSTGRES_USER ?= postgres
POSTGRES_PASSWORD ?= argus_dev_pg_S7m9Q4r2L8xP6nV3
POSTGRES_DB ?= dddd
DB_MIGRATION_MODE ?= apply
DB_DSN ?= host=$(DB_HOST) user=$(POSTGRES_USER) password=$(POSTGRES_PASSWORD) dbname=$(POSTGRES_DB) port=$(DB_PORT) sslmode=disable

# dddd CLI 单机版
cli:
	go build -o bin/dddd ./scanner/cmd/cli

# dddd-agent 扫描节点（Phase 1 实现）
agent:
	go build -o bin/dddd-agent ./scanner/cmd/agent

# dddd-server 控制端
server:
	go build -o bin/dddd-server ./server/cmd/dddd-server

# argus-mcp 独立 MCP 代理
mcp:
	cd mcp && go build -o ../bin/argus-mcp ./cmd/argus-mcp

# 向后兼容：根目录编译
legacy:
	go build -o bin/dddd ./scanner/cmd/cli

# 全部编译
all: cli agent server mcp

# 清理
clean:
	rm -rf bin/

infra-up:
	$(DOCKER_COMPOSE) up -d --remove-orphans rabbitmq postgres

infra-down:
	$(DOCKER_COMPOSE) down --remove-orphans

infra-logs:
	$(DOCKER_COMPOSE) logs -f rabbitmq postgres

db-init:
	$(DOCKER_COMPOSE) exec -T postgres bash -lc '/docker-entrypoint-initdb.d/000-init-db.sh'

db-migrate:
	go run ./server/cmd/dddd-server --db "$(DB_DSN)" --migrate-only --db-migration-mode $(DB_MIGRATION_MODE) $(if $(filter dev-auto,$(DB_MIGRATION_MODE)),--dev,)

db-verify:
	go run ./server/cmd/dddd-server --db "$(DB_DSN)" --migrate-only --db-migration-mode verify

setup-local:
	bash server/deploy/setup-local.sh

smoke-local:
	bash test/setup-local-smoke.sh

test:
	go test ./...
	cd server && go test ./...
	npm --prefix server-ui run test -- --run

coverage:
	mkdir -p $(COVERAGE_DIR)
	go test -coverprofile=$(COVERAGE_DIR)/root.out ./...
	cd server && go test -coverprofile=$(COVERAGE_DIR)/server.out ./...
	go tool cover -func=$(COVERAGE_DIR)/root.out | tail -n 1
	cd server && go tool cover -func=$(COVERAGE_DIR)/server.out | tail -n 1

frontend-smoke:
	npm --prefix server-ui run test:smoke

cloud-smoke:
	cd server && go test ./internal/api -run TestCloudProviderMockSmoke -count=1

source-size-check:
	go run ./tools/source-size-check --root . --baseline .source-size-baseline

release-artifacts:
	./deploy/build-bundle.sh $(VERSION)

lint:
	npm --prefix server-ui run lint

ci: source-size-check lint test coverage frontend-smoke cloud-smoke
	npm --prefix server-ui run build

docker: setup-local
