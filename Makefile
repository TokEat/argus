.PHONY: cli agent server legacy all clean docker

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

# Docker 镜像（Phase 2 使用）
docker:
	@echo "No project Dockerfile found. Use server/deploy/docker-compose.yml for local Redis setup."
