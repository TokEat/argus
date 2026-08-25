package subdomain

import (
	"net"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// apexDomain returns the registrable domain (eTLD+1) used for passive
// subdomain collection. harbor-arm.uhomecp.com → uhomecp.com.
func apexDomain(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.Trim(host, ".")
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = strings.ToLower(strings.Trim(h, "."))
	}
	if host == "" || strings.ContainsAny(host, " /?#:") {
		return ""
	}
	if net.ParseIP(host) != nil {
		return ""
	}
	if !strings.Contains(host, ".") {
		return ""
	}
	apex, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil || strings.TrimSpace(apex) == "" {
		return host
	}
	return strings.ToLower(apex)
}

func lookupInjected(injected map[string][]string, domain, apex string) ([]string, bool) {
	if injected == nil {
		return nil, false
	}
	key := strings.ToLower(strings.TrimSpace(domain))
	if list, ok := injected[key]; ok {
		return list, true
	}
	if apex != "" && apex != key {
		if list, ok := injected[apex]; ok {
			return list, true
		}
	}
	return nil, false
}

func normalizeCollectionHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.Trim(host, ".")
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = strings.ToLower(strings.Trim(h, "."))
	}
	if host == "" || strings.ContainsAny(host, " /?#:") {
		return ""
	}
	return host
}

func inputHostSet(inputs []string) map[string]struct{} {
	known := make(map[string]struct{}, len(inputs))
	for _, input := range inputs {
		if key := normalizeCollectionHost(input); key != "" {
			known[key] = struct{}{}
		}
	}
	return known
}

func dropInputHosts(hosts []string, known map[string]struct{}) []string {
	if len(hosts) == 0 || len(known) == 0 {
		return hosts
	}
	out := make([]string, 0, len(hosts))
	for _, host := range hosts {
		key := normalizeCollectionHost(host)
		if key == "" {
			continue
		}
		if _, skip := known[key]; skip {
			continue
		}
		out = append(out, host)
	}
	return out
}
