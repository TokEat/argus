.PHONY: cli agent server yaksha yaksha-image yaksha-up yaksha-down exp-lab-up exp-lab-smoke exp-lab-down mcp proto-scan proto-egress nuclei-embed-test legacy all clean clean-release docker infra-up infra-down infra-logs db-setup db-verify setup-local smoke-local test coverage frontend-smoke cloud-smoke source-size-check brand-check release-artifacts lint ci

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
POSTGRES_CONTAINER ?=
DB_DSN ?= host=$(DB_HOST) user=$(POSTGRES_USER) password=$(POSTGRES_PASSWORD) dbname=$(POSTGRES_DB) port=$(DB_PORT) sslmode=disable

# Argus CLI 单机版（当前机器 → bin/argus）
cli:
	./build.sh cli

# argus-agent 扫描节点（当前机器 → bin/argus-agent）
agent:
	./build.sh agent

# argus-server 控制端（当前机器 → bin/argus-server）
server:
	./build.sh server

# argus-mcp 独立 MCP 代理
mcp:
	./build.sh mcp

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
	./build.sh yaksha

yaksha-image:
	docker compose -f yaksha/compose.yaml build

yaksha-up:
	docker compose -f yaksha/compose.yaml up -d --build

yaksha-down:
	docker compose -f yaksha/compose.yaml down

# 本机授权 EXP 实验环境；生产 Compose 不引用该内部网络。
exp-lab-up:
	docker compose -f exp-lab/compose.yaml up -d --build
	docker compose -f yaksha/compose.yaml -f exp-lab/yaksha.override.yaml up -d --build

exp-lab-smoke:
	bash exp-lab/smoke.sh

exp-lab-down:
	docker compose -f yaksha/compose.yaml -f exp-lab/yaksha.override.yaml down
	docker compose -f exp-lab/compose.yaml down

# 向后兼容：根目录编译
legacy:
	./build.sh cli

# 全部编译（当前机器 → bin/）
all: cli agent server yaksha mcp

# 清理本机产物；交叉编译产物用 make clean-release
clean:
	rm -rf bin/

clean-release:
	rm -rf release/

infra-up:
	$(DOCKER_COMPOSE) up -d --remove-orphans rabbitmq postgres

infra-down:
	$(DOCKER_COMPOSE) down --remove-orphans

infra-logs:
	$(DOCKER_COMPOSE) logs -f rabbitmq postgres

# 数据库初始化（纯 SQL，psql 导入）。POSTGRES_CONTAINER / ARGUS_DB_CONTAINER
# 指定已有 Postgres 容器；宿主机无 psql 时自动对 compose postgres 使用 --container。
db-setup:
	@container="$(POSTGRES_CONTAINER)"; \
	if [ -z "$$container" ]; then container="$$ARGUS_DB_CONTAINER"; fi; \
	if [ -n "$$container" ]; then \
		POSTGRES_DB="$(POSTGRES_DB)" POSTGRES_USER="$(POSTGRES_USER)" \
		POSTGRES_PASSWORD="$(POSTGRES_PASSWORD)" \
		bash deploy/db-init.sh --no-backup --container "$$container"; \
	elif command -v psql >/dev/null 2>&1; then \
		POSTGRES_HOST="$(DB_HOST)" POSTGRES_PORT="$(DB_PORT)" POSTGRES_DB="$(POSTGRES_DB)" \
		POSTGRES_USER="$(POSTGRES_USER)" POSTGRES_PASSWORD="$(POSTGRES_PASSWORD)" \
		bash deploy/db-init.sh --no-backup; \
	else \
		echo "[db-setup] host 未安装 psql，改为通过 postgres 容器执行"; \
		$(DOCKER_COMPOSE) up -d --wait postgres >/dev/null; \
		cid="$$($(DOCKER_COMPOSE) ps -q postgres | tr -d '\r')"; \
		if [ -z "$$cid" ]; then echo "[db-setup] 无法解析 postgres 容器 ID" >&2; exit 1; fi; \
		POSTGRES_DB="$(POSTGRES_DB)" POSTGRES_USER="$(POSTGRES_USER)" \
		POSTGRES_PASSWORD="$(POSTGRES_PASSWORD)" \
		bash deploy/db-init.sh --no-backup --container "$$cid"; \
	fi

# 数据库校验：先用 SQL 初始化脚本收敛 schema，再跑 server 启动期同款校验测试
db-verify:
	@$(MAKE) --no-print-directory db-setup
	cd server && ARGUS_VERIFY_DSN="$(DB_DSN)" go test ./internal/db -run 'TestVerifyDatabaseReadyOnInitSQLDatabase' -count=1

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
