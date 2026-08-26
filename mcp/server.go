package mcp

import (
	argusmcp "github.com/P0lar1ght/argus/mcp/internal/mcp"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// NewServer builds an MCP server that calls Argus HTTP APIs with the given bearer token.
func NewServer(apiBaseURL, bearerToken string) *sdkmcp.Server {
	return argusmcp.NewServer(argusmcp.NewClient(apiBaseURL, bearerToken))
}
