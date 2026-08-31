package mcp

import (
	argusmcp "github.com/P0lar1ght/argus/mcp/internal/mcp"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// ToolCallRecord is one auditable MCP tools/call.
type ToolCallRecord = argusmcp.ToolCallRecord

// ToolAuditor receives high-risk MCP tool calls after elicitation succeeds.
type ToolAuditor = argusmcp.ToolAuditor

// ServerOption configures NewServer.
type ServerOption = argusmcp.ServerOption

// WithToolAuditor records auditable tools/call traffic. Standalone argus-mcp may omit it.
func WithToolAuditor(auditor ToolAuditor) ServerOption {
	return argusmcp.WithToolAuditor(auditor)
}

// AuditableToolAction reports whether a tools/call should be persisted.
func AuditableToolAction(tool string, args map[string]interface{}) (string, bool) {
	return argusmcp.AuditableToolAction(tool, args)
}

// NewServer builds an MCP server that calls Argus HTTP APIs with the given bearer token.
func NewServer(apiBaseURL, bearerToken string, opts ...ServerOption) *sdkmcp.Server {
	return argusmcp.NewServer(argusmcp.NewClient(apiBaseURL, bearerToken), opts...)
}
