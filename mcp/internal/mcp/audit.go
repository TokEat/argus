package mcp

import (
	"context"
	"strings"
	"time"
)

// ToolCallRecord is one tools/call that already passed elicitation (if any).
type ToolCallRecord struct {
	ToolName string
	Args     map[string]interface{}
	Duration time.Duration
	Err      error
}

// ToolAuditor receives high-risk MCP tool calls. Implementations must not persist secrets.
type ToolAuditor interface {
	Record(ctx context.Context, rec ToolCallRecord)
}

type serverOptions struct {
	auditor ToolAuditor
}

// ServerOption configures NewServer.
type ServerOption func(*serverOptions)

// WithToolAuditor records auditable tools/call traffic after elicitation succeeds.
func WithToolAuditor(auditor ToolAuditor) ServerOption {
	return func(o *serverOptions) {
		if o != nil {
			o.auditor = auditor
		}
	}
}

func applyServerOptions(opts []ServerOption) serverOptions {
	cfg := serverOptions{}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return cfg
}

// AuditableToolAction reports whether a tools/call should be persisted.
// Coverage matches elicitMessage: behavior-probe debug, scan create, rule publish, yaksha debug/run.
func AuditableToolAction(tool string, args map[string]interface{}) (action string, ok bool) {
	switch strings.TrimSpace(tool) {
	case "argus_debug_behavior_probe":
		return "", true
	case "argus_scan_create":
		return "", true
	case "argus_rule_apply":
		if strings.EqualFold(stringArg(args, "action"), "publish") {
			return "publish", true
		}
	case "argus_yaksha_exp":
		value := strings.ToLower(stringArg(args, "action"))
		if value == "debug" || value == "run" {
			return value, true
		}
	}
	return "", false
}

func recordAuditableTool(ctx context.Context, auditor ToolAuditor, tool string, args map[string]interface{}, duration time.Duration, err error) {
	if auditor == nil {
		return
	}
	if _, ok := AuditableToolAction(tool, args); !ok {
		return
	}
	auditor.Record(ctx, ToolCallRecord{
		ToolName: tool,
		Args:     args,
		Duration: duration,
		Err:      err,
	})
}
