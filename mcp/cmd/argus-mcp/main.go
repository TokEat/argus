package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	argusmcp "github.com/P0lar1ght/argus/mcp/internal/mcp"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	cfg, err := argusmcp.ConfigFromEnv()
	if err != nil {
		log.Fatal(err)
	}
	server := argusmcp.NewServer(argusmcp.NewClient(cfg.BaseURL, cfg.Token))

	switch cfg.Transport {
	case "stdio":
		if err := server.Run(context.Background(), &sdkmcp.StdioTransport{}); err != nil {
			log.Fatal(err)
		}
	case "http", "sse":
		log.Printf("argus-mcp listening on %s", cfg.HTTPAddr)
		handler := sdkmcp.NewStreamableHTTPHandler(func(*http.Request) *sdkmcp.Server {
			return server
		}, nil)
		if err := http.ListenAndServe(cfg.HTTPAddr, handler); err != nil {
			log.Fatal(err)
		}
	default:
		_, _ = fmt.Fprintf(os.Stderr, "unsupported ARGUS_MCP_TRANSPORT %q\n", cfg.Transport)
		os.Exit(2)
	}
}
