.PHONY: cli agent server yaksha yaksha-image yaksha-up yaksha-down mcp proto-scan proto-egress nuclei-embed-test legacy all clean docker infra-up infra-down infra-logs db-init db-migrate db-verify setup-local smoke-local test coverage frontend-smoke cloud-smoke source-size-check brand-check release-artifacts lint ci

COMPOSE_FILE := server/deploy/docker-compose.yml
DOCKER_COMPOSE := docker compose -f $(COMPOSE_FILE)
COVERAGE_DIR ?= /tmp/argus-coverage
VERSION ?= v0.1.0
DB_HOST ?= 127.0.0.1
POSTGRES_PORT ?= 5432
DB_PORT ?= $(POSTGRES_PORT)
POSTGRES_USER ?= postgres
POSTGRES_PASSWORD ?= argus_dev_pg_S7m9Q4r2L8xP6nV3
POSTGRES_DB ?= argus
DB_MIGRATION_MODE ?= apply
DB_DSN ?= host=$(DB_HOST) user=$(POSTGRES_USER) password=$(POSTGRES_PASSWORD) dbname=$(POSTGRES_DB) port=$(DB_PORT) sslmode=disable

# Argus CLI 单机版
cli:
	go build -o bin/argus ./scanner/cmd/cli

# argus-agent 扫描节点（Phase 1 实现）
agent:
	go build -o bin/argus-agent ./scanner/cmd/agent

# argus-server 控制端
server:
	go build -o bin/argus-server ./server/cmd/argus-server

# argus-mcp 独立 MCP 代理
mcp:
	cd mcp && go build -o ../bin/argus-mcp ./cmd/argus-mcp

# Generate shared Agent and Yaksha egress contracts with pinned generators.
proto-scan:
	@tool_dir=$$(mktemp -d); \
	GOBIN=$$tool_dir go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11; \
	GOBIN=$$tool_dir go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.1; \
	PATH=$$tool_dir:$$PATH protoc -I shared/proto \
		--go_out=shared/proto --go_opt=module=github.com/P0lar1ght/argus/shared/proto \
		--go-grpc_out=shared/proto --go-grpc_opt=module=github.com/P0lar1ght/argus/shared/proto \
		shared/proto/proto/scan/agent.proto shared/proto/proto/scan/egress.proto; \
	rm -rf $$tool_dir

proto-egress: proto-scan

# Vendored Nuclei is a nested module; root `go test ./...` does not discover
# its request-budget contract tests.
nuclei-embed-test:
	cd scanner/lib/nuclei && GOWORK=off go test ./pkg/protocols ./pkg/protocols/http ./pkg/protocols/dns ./internal/runner -run '^TestRequestBudget' -count=1

# Yaksha 独立 Yaklang EXP runtime；保持独立 module 依赖边界。
yaksha:
	cd yaksha && GOWORK=off go build -o ../bin/yaksha ./cmd/yaksha

yaksha-image:
	docker compose -f yaksha/compose.yaml build

yaksha-up:
	docker compose -f yaksha/compose.yaml up -d --build

yaksha-down:
	docker compose -f yaksha/compose.yaml down

# 向后兼容：根目录编译
legacy:
	go build -o bin/argus ./scanner/cmd/cli

# 全部编译
all: cli agent server yaksha mcp

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
	go run ./server/cmd/argus-server --db "$(DB_DSN)" --migrate-only --db-migration-mode $(DB_MIGRATION_MODE) $(if $(filter dev-auto,$(DB_MIGRATION_MODE)),--dev,)

db-verify:
	go run ./server/cmd/argus-server --db "$(DB_DSN)" --migrate-only --db-migration-mode verify

setup-local:
	bash server/deploy/setup-local.sh

smoke-local:
	bash test/setup-local-smoke.sh

test:
	go test ./...
	$(MAKE) nuclei-embed-test
	cd server && go test ./...
	cd mcp && go test ./...
	cd yaksha && GOWORK=off go test ./...
	npm --prefix server-ui run test -- --run

coverage:
	mkdir -p $(COVERAGE_DIR)
	go test -coverprofile=$(COVERAGE_DIR)/root.out ./...
	cd server && go test -coverprofile=$(COVERAGE_DIR)/server.out ./...
	cd mcp && go test -coverprofile=$(COVERAGE_DIR)/mcp.out ./...
	cd yaksha && GOWORK=off go test -coverprofile=$(COVERAGE_DIR)/yaksha.out ./...
	go tool cover -func=$(COVERAGE_DIR)/root.out | tail -n 1
	cd server && go tool cover -func=$(COVERAGE_DIR)/server.out | tail -n 1
	cd mcp && go tool cover -func=$(COVERAGE_DIR)/mcp.out | tail -n 1
	cd yaksha && go tool cover -func=$(COVERAGE_DIR)/yaksha.out | tail -n 1

frontend-smoke:
	npm --prefix server-ui run test:smoke

cloud-smoke:
	cd server && go test ./internal/api -run TestCloudProviderMockSmoke -count=1

source-size-check:
	go run ./tools/source-size-check --root . --baseline .source-size-baseline

brand-check:
	go run ./tools/brand-check --root .

release-artifacts:
	./deploy/build-bundle.sh $(VERSION)

lint:
	npm --prefix server-ui run lint

ci: source-size-check brand-check lint test coverage frontend-smoke cloud-smoke
	npm --prefix server-ui run build

docker: setup-local
