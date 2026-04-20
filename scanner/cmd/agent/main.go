package main

import (
	"flag"
	"log"
	"os"
	"strings"

	"dddd/scanner/internal/agent"
)

func main() {
	serverAddr := flag.String("server", "127.0.0.1:50051", "Server gRPC address")
	apiURL := flag.String("api", "http://127.0.0.1:8085", "Server REST HTTP API address")
	agentID := flag.String("id", "agent-local-1", "Agent unique ID")
	workers := flag.Int("workers", 1, "Number of concurrent worker goroutines")
	tagsStr := flag.String("tags", "", "Node tags in key1=val1,key2=val2 format")
	psk := flag.String("psk", "", "Pre-shared key for Server authentication (env: ARGUS_AGENT_PSK)")
	flag.Parse()

	// 环境变量优先级高于 flag
	if envPSK := os.Getenv("ARGUS_AGENT_PSK"); envPSK != "" {
		*psk = envPSK
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

	log.Printf("Starting dddd-agent: ID=%s, Server=%s, API=%s, Workers=%d, Tags=%v", *agentID, *serverAddr, *apiURL, *workers, tags)

	worker := agent.NewWorker(*agentID, *serverAddr, *apiURL, *workers, tags)
	worker.SetPSK(*psk)
	if err := worker.Start(); err != nil {
		log.Fatalf("Agent worker failed to start: %v", err)
	}
}
