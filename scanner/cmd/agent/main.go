package main

import (
	"flag"
	"log"
	"strings"

	"dddd/scanner/internal/agent"
)

func main() {
	serverAddr := flag.String("server", "127.0.0.1:50051", "Server gRPC address")
	apiURL := flag.String("api", "http://127.0.0.1:8085", "Server REST HTTP API address")
	agentID := flag.String("id", "agent-local-1", "Agent unique ID")
	workers := flag.Int("workers", 1, "Number of concurrent worker goroutines")
	tagsStr := flag.String("tags", "", "Node tags in key1=val1,key2=val2 format")
	flag.Parse()

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

	log.Printf("Starting dddd-agent: ID=%s, Server=%s, API=%s, Workers=%d, Tags=%v", *agentID, *serverAddr, *apiURL, *workers, tags)

	worker := agent.NewWorker(*agentID, *serverAddr, *apiURL, *workers, tags)
	if err := worker.Start(); err != nil {
		log.Fatalf("Agent worker failed to start: %v", err)
	}
}
