//go:build !linux

package portscan

import (
	"github.com/TokEat/argus/scanner/ddout"
	"github.com/projectdiscovery/gologger"
)

// CanSYNScan is false outside Linux (no raw IPPROTO_TCP path).
func CanSYNScan() bool { return false }

func scanSYNBuiltin(ips []string, ports string, rate int, emit func(ddout.OutputMessage)) []string {
	gologger.Error().Msg("内置 SYN 扫描仅支持 Linux raw socket")
	return nil
}
