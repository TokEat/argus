package protocol

import (
	"strings"

	"github.com/lcvvvv/gonmap"
)

// CanonicalProtocol maps nmap-style and historical aliases to the short names
// used by Identify output, GoPoc dispatch, and ProtocolCheck.
func CanonicalProtocol(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return ""
	}
	return gonmap.FixProtocol(name)
}

// Unidentified reports protocols that must not override port-based fallback
// and must not block a more specific match.
func Unidentified(name string) bool {
	switch CanonicalProtocol(name) {
	case "", "tcp", "udp", "unknown", "unidentified", "ssl", "protocol", "portscan":
		return true
	default:
		return false
	}
}
