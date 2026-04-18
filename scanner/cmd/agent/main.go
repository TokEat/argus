package main

import (
	"flag"
	"log"

	"dddd/scanner/internal/agent"
)

func main() {
	serverAddr := flag.String("server", "127.0.0.1:50051", "Server gRPC address")
	apiURL := flag.String("api", "http://127.0.0.1:8085", "Server REST HTTP API address")
	agentID := flag.String("id", "agent-local-1", "Agent unique ID")
	flag.Parse()

	log.Printf("Starting dddd-agent: ID=%s, Server=%s, API=%s", *agentID, *serverAddr, *apiURL)

	worker := agent.NewWorker(*agentID, *serverAddr, *apiURL)
	if err := worker.Start(); err != nil {
		log.Fatalf("Agent worker failed to start: %v", err)
	}
}
