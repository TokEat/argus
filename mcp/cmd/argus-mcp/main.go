package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	argusmcp "github.com/TokEat/argus/mcp/internal/mcp"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	cfg, err := argusmcp.ConfigFromEnv()
	if err != nil {
		log.Fatal(err)
	}
	client := argusmcp.NewClientWithYakshaURL(cfg.BaseURL, cfg.Token, cfg.YakshaURL)
	if cfg.Transport != "stdio" {
		readyCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		if err := client.CheckYaksha(readyCtx); err != nil {
			log.Printf("Yaksha runtime not ready (%v); EXP tools will fail until it is available", err)
		}
		cancel()
	}
	server := argusmcp.NewServer(client)

	switch cfg.Transport {
	case "stdio":
		if err := server.Run(context.Background(), &sdkmcp.StdioTransport{}); err != nil {
			log.Fatal(err)
		}
	case "http", "sse":
		log.Printf("argus-mcp listening on %s", cfg.HTTPAddr)
		handler := sdkmcp.NewStreamableHTTPHandler(func(*http.Request) *sdkmcp.Server {
			return server
		}, &sdkmcp.StreamableHTTPOptions{Stateless: true})
		var root http.Handler = argusmcp.AuthenticateHTTP(cfg.MCPAuthToken, handler)
		if cfg.AppDevHost {
			root = argusmcp.NewDevAppHost(client, root)
			log.Printf("EXP Studio development host: http://%s/__dev/exp-studio", cfg.HTTPAddr)
		}
		if err := http.ListenAndServe(cfg.HTTPAddr, root); err != nil {
			log.Fatal(err)
		}
	default:
		_, _ = fmt.Fprintf(os.Stderr, "unsupported ARGUS_MCP_TRANSPORT %q\n", cfg.Transport)
		os.Exit(2)
	}
}
