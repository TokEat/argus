package subdomainpassive

import (
	"net"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// ApexDomain returns the registrable domain (eTLD+1) used as the main domain
// for passive subdomain collection. Inputs like harbor-arm.uhomecp.com collapse
// to uhomecp.com; already-apex hosts such as jslgroup.cn are unchanged.
// Unknown or malformed hosts fall back to the normalized hostname so collection
// still runs; IPs, empty values, and URL/path-shaped strings return "".
func ApexDomain(host string) string {
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

// CollectionDomains maps scan targets to unique registrable domains in
// first-seen order. Passive jobs, cache keys, and sealed result maps all
// use this list so FQDNs under the same apex are collected once.
func CollectionDomains(targets []string) []string {
	seen := make(map[string]struct{}, len(targets))
	out := make([]string, 0, len(targets))
	for _, target := range targets {
		apex := ApexDomain(target)
		if apex == "" {
			continue
		}
		if _, ok := seen[apex]; ok {
			continue
		}
		seen[apex] = struct{}{}
		out = append(out, apex)
	}
	return out
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

// DropInputHosts removes hosts that already appear in the batch's actual
// scan targets. Collection is keyed by apex, so a query for uhomecp.com
// must not re-emit harbor-arm.uhomecp.com when that FQDN was the input.
// Empty apex entries are kept so Agents still treat the domain as collected.
func DropInputHosts(byDomain map[string][]string, inputs []string) map[string][]string {
	if len(byDomain) == 0 {
		return byDomain
	}
	known := inputHostSet(inputs)
	if len(known) == 0 {
		return byDomain
	}
	out := make(map[string][]string, len(byDomain))
	for domain, hosts := range byDomain {
		filtered := make([]string, 0, len(hosts))
		for _, host := range hosts {
			key := normalizeCollectionHost(host)
			if key == "" {
				continue
			}
			if _, skip := known[key]; skip {
				continue
			}
			filtered = append(filtered, host)
		}
		out[domain] = filtered
	}
	return out
}
