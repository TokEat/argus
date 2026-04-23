.PHONY: cli agent server legacy all clean docker infra-up infra-down infra-logs db-init db-migrate setup-local

COMPOSE_FILE := server/deploy/docker-compose.yml
DOCKER_COMPOSE := docker compose -f $(COMPOSE_FILE)

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
	go run ./server/cmd/dddd-server --migrate-only --dev

setup-local:
	bash server/deploy/setup-local.sh

docker: setup-local
