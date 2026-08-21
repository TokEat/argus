package discovery

import "github.com/P0lar1ght/argus/scanner/utils"

// TCPProbePorts is the small liveness set. It is not the -p scan list.
const TCPProbePorts = "80,443,3389,445,22"

// UDPProbePort is a commonly closed UDP port. ICMP port unreachable means up.
const UDPProbePort = 40125

// Difference returns items in all that are not in minus.
func Difference(all, minus []string) []string {
	if len(all) == 0 {
		return nil
	}
	drop := make(map[string]struct{}, len(minus))
	for _, item := range minus {
		drop[item] = struct{}{}
	}
	var out []string
	for _, item := range all {
		if _, skip := drop[item]; skip {
			continue
		}
		out = append(out, item)
	}
	return out
}

// Union concatenates and de-duplicates IPs, preserving first-seen order.
func Union(parts ...[]string) []string {
	var merged []string
	for _, part := range parts {
		merged = append(merged, part...)
	}
	return utils.RemoveDuplicateElement(merged)
}

// HostsFromIPPorts keeps the IP side of ip:port pairs.
func HostsFromIPPorts(ipPorts []string) []string {
	var hosts []string
	for _, item := range ipPorts {
		host, _, ok := splitHostPort(item)
		if !ok {
			continue
		}
		hosts = append(hosts, host)
	}
	return utils.RemoveDuplicateElement(hosts)
}

func splitHostPort(item string) (host, port string, ok bool) {
	for i := len(item) - 1; i >= 0; i-- {
		if item[i] == ':' {
			if i == 0 || i+1 >= len(item) {
				return "", "", false
			}
			return item[:i], item[i+1:], true
		}
	}
	return "", "", false
}
