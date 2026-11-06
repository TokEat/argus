package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/P0lar1ght/argus/scanner/internal/agent"
	"github.com/P0lar1ght/argus/scanner/internal/engine"
)

// applyRuntimeKnobs 应用 opt-in 运行时内存/分析开关（不设则保持 Go 默认行为）：
// ARGUS_GOMEMLIMIT → debug.SetMemoryLimit（软 GC 上限，应低于宿主机物理内存留出余量）；
// ARGUS_GOGC → debug.SetGCPercent（不设则默认 GC）；
// ARGUS_PPROF_ADDR → 在该地址起 pprof（仅本机调试用，生产勿暴露未认证端口）。
func applyRuntimeKnobs() {
	if v := strings.TrimSpace(os.Getenv("ARGUS_GOMEMLIMIT")); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			log.Printf("WARNING: invalid ARGUS_GOMEMLIMIT=%q, ignored", v)
		} else {
			debug.SetMemoryLimit(n)
			log.Printf("GOMEMLIMIT set to %d bytes", n)
		}
	}
	if v := strings.TrimSpace(os.Getenv("ARGUS_GOGC")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			log.Printf("WARNING: invalid ARGUS_GOGC=%q, ignored", v)
		} else {
			debug.SetGCPercent(n)
			log.Printf("GOGC set to %d", n)
		}
	}
	if addr := strings.TrimSpace(os.Getenv("ARGUS_PPROF_ADDR")); addr != "" {
		go func() {
			log.Printf("pprof listening on %s", addr)
			if err := http.ListenAndServe(addr, nil); err != nil {
				log.Printf("pprof server stopped: %v", err)
			}
		}()
	}
}

func main() {
	serverAddr := flag.String("server", "127.0.0.1:50051", "Server gRPC address")
	apiURL := flag.String("api", "http://127.0.0.1:8085", "Server REST HTTP API address")
	hostname, _ := os.Hostname()
	// 默认 ID 按 MAC 地址派生，保证重启后仍是同一个 Agent；
	// 显式传入 --id 时以传入值为准。
	defaultID, idSource := stableAgentID(hostname)
	if defaultID == "" {
		defaultID = fmt.Sprintf("agent-%s-%d", hostname, os.Getpid())
		log.Printf("WARNING: no stable machine identifier (MAC/machine-id) found, falling back to per-boot ID %s; each restart will register a new agent", defaultID)
	} else {
		log.Printf("Default agent ID derived from %s: %s", idSource, defaultID)
	}
	agentID := flag.String("id", defaultID, "Agent unique ID")
	workers := flag.Int("workers", 0, "Number of concurrent worker goroutines (0=auto-detect from CPU cores)")
	tagsStr := flag.String("tags", "", "Node tags in key1=val1,key2=val2 format")
	psk := flag.String("psk", "", "Pre-shared key for Server authentication (env: ARGUS_AGENT_PSK)")
	grpcCA := flag.String("grpc-ca", "", "CA certificate for Server gRPC TLS (env: ARGUS_AGENT_GRPC_CA)")
	grpcServerName := flag.String("grpc-server-name", "", "Expected Server certificate name (env: ARGUS_AGENT_GRPC_SERVER_NAME)")
	flag.Parse()
	applyRuntimeKnobs()

	// 环境变量优先级高于 flag
	if envPSK := os.Getenv("ARGUS_AGENT_PSK"); envPSK != "" {
		*psk = envPSK
	}
	if value := os.Getenv("ARGUS_AGENT_GRPC_CA"); value != "" {
		*grpcCA = value
	}
	if value := os.Getenv("ARGUS_AGENT_GRPC_SERVER_NAME"); value != "" {
		*grpcServerName = value
	}
	if *grpcCA == "" && *grpcServerName != "" {
		log.Fatal("--grpc-server-name requires --grpc-ca")
	}

	// workers=0 时自动按 CPU 核心数计算并发容量
	effectiveWorkers := *workers
	if effectiveWorkers <= 0 {
		effectiveWorkers = engine.MaxConcurrentTasks()
		log.Printf("Auto-detected worker pool size from CPU: %d", effectiveWorkers)
	}

	// 解析 tags
	tags := make(map[string]string)
	if *tagsStr != "" {
		pairs := strings.Split(*tagsStr, ",")
		for _, pair := range pairs {
			kv := strings.SplitN(pair, "=", 2)
			if len(kv) == 2 {
				tags[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			}
		}
	}
	// 无标签时默认注册为通用调度节点，避免 selector 过滤导致任务积压。
	if len(tags) == 0 {
		tags["target_type"] = "all"
	}

	log.Printf("Starting argus-agent: ID=%s, Server=%s, API=%s, Workers=%d, Tags=%v, TLS=%t", *agentID, *serverAddr, *apiURL, effectiveWorkers, tags, *grpcCA != "")

	worker := agent.NewWorker(*agentID, *serverAddr, *apiURL, effectiveWorkers, tags)
	worker.SetPSK(*psk)
	if *grpcCA != "" {
		if err := worker.SetTLS(*grpcCA, *grpcServerName); err != nil {
			log.Fatalf("Configure Agent gRPC TLS: %v", err)
		}
	}
	if err := worker.Start(); err != nil {
		log.Fatalf("Agent worker failed to start: %v", err)
	}
}
