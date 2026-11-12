package common

import (
	"net/url"
	"strings"

	"github.com/TokEat/argus/scanner/structs"
	"github.com/TokEat/argus/scanner/utils"
)

// TraceTarget is the standalone -tr/--trace destination (IP, CIDR, or file).
var TraceTarget string

// CLITraceRequested reports whether the invocation is a standalone traceroute.
func CLITraceRequested(args []string) bool {
	for _, arg := range args {
		if arg == "-tr" || arg == "--trace" || strings.HasPrefix(arg, "-tr=") || strings.HasPrefix(arg, "--trace=") {
			return true
		}
	}
	return false
}

func applyTraceFlag() {
	target := strings.TrimSpace(TraceTarget)
	if target == "" {
		return
	}
	structs.GlobalConfig.TraceOnly = true
	structs.GlobalConfig.TraceRoute = true
	TargetString = target
}

func hasIPv4TraceTarget(targets []string) bool {
	for _, raw := range targets {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		switch utils.GetInputType(raw) {
		case structs.TypeIP, structs.TypeCIDR, structs.TypeIPRange, structs.TypeIPPort:
			return true
		case structs.TypeURL:
			parsed, err := url.Parse(raw)
			if err != nil {
				continue
			}
			if utils.IsIPv4(parsed.Hostname()) {
				return true
			}
		}
	}
	return false
}
