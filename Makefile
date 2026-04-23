.PHONY: cli agent server legacy all clean docker infra-up infra-down infra-logs db-init db-migrate db-verify setup-local smoke-local

COMPOSE_FILE := server/deploy/docker-compose.yml
DOCKER_COMPOSE := docker compose -f $(COMPOSE_FILE)
DB_HOST ?= 127.0.0.1
POSTGRES_PORT ?= 5432
DB_PORT ?= $(POSTGRES_PORT)
POSTGRES_USER ?= postgres
POSTGRES_PASSWORD ?= root
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

# 向后兼容：根目录编译
legacy:
	go build -o bin/dddd ./scanner/cmd/cli

# 全部编译
all: cli agent server

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

docker: setup-local
