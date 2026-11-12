package engine

import (
	"net"
	"net/url"
	"strings"

	"github.com/TokEat/argus/scanner/structs"
	"github.com/TokEat/argus/scanner/utils"
	"github.com/TokEat/argus/shared/proto/go/targetutil"
)

// lineageChildKey extracts the identity of the target this message describes,
// mirroring how the server derives Asset.Target from the same payload. The
// result is normalized before being used as a LineageParents key so the agent
// and server agree on the join key.
func lineageChildKey(msg structs.OutputMessage) string {
	switch msg.Type {
	case "Web", "Domain-Bind", "Finger", "Active-Finger":
		return msg.URI
	case "PortScan", "Protocol", "ProtocolCheck", "Nmap":
		if msg.IP != "" && msg.Port != "" {
			return msg.IP + ":" + msg.Port
		}
		return msg.IP
	case "IPAlive":
		return msg.IP
	case "Domain", "DNS-SubFinder", "DNS-Brute", "CDN-Domain", "RealIP",
		"Subdomain", "subdomain":
		return msg.Domain
	default:
		if msg.URI != "" {
			return msg.URI
		}
		if msg.GoPoc.Target != "" {
			return msg.GoPoc.Target
		}
		if msg.IP != "" && msg.Port != "" {
			return msg.IP + ":" + msg.Port
		}
		if msg.IP != "" {
			return msg.IP
		}
		return msg.Domain
	}
}

// deriveLineageParent determines the parent target of the message's child
// target from pipeline state known at production time. This is agent-side and
// exact: it is the reference the agent reports, not a server-side inference.
// The returned identity is normalized by the caller.
func deriveLineageParent(ctx *ScanContext, msg structs.OutputMessage, childKey string) string {
	switch msg.Type {
	case "Web", "Domain-Bind":
		// url -> the ip:port that was HTTP-probed to obtain it (host:port, bare).
		return bareHostPort(msg.URI)
	case "PortScan", "Protocol", "ProtocolCheck", "Nmap":
		// ip:port -> ip
		return msg.IP
	case "IPAlive":
		// ip -> the scan-input segment (CIDR/IP range) it was enumerated from,
		// so a host discovered by scanning "10.3.130.0/24" traces back to that
		// segment as the lineage start, not to its own derived address. When the
		// IP is not inside any segment input, fall back to a domain that resolved
		// to it (bare-IP inputs keep the domain chain they already had).
		if seg := inputSegmentForIP(ctx, msg.IP); seg != "" {
			return seg
		}
		return firstDomainForIP(ctx, msg.IP)
	case "Domain", "DNS-SubFinder", "DNS-Brute", "CDN-Domain", "Subdomain", "subdomain":
		// subdomain -> the root input domain it belongs to.
		return rootDomainSuffix(ctx, msg.Domain)
	default:
		return ""
	}
}

// RecordLineageParent stores the exact parent of the message's child target.
// Called from the pipeline's wrapped emit at the moment the child is produced,
// so the provenance is captured regardless of when the message is streamed.
func RecordLineageParent(ctx *ScanContext, msg structs.OutputMessage) {
	if ctx == nil {
		return
	}
	child := targetutil.NormalizeTarget(lineageChildKey(msg))
	if child == "" || child == "unknown" {
		return
	}
	parent := targetutil.NormalizeTarget(deriveLineageParent(ctx, msg, child))
	if parent == "" || parent == "unknown" || parent == child {
		return
	}
	ctx.LineageParentsLock.Lock()
	if ctx.LineageParents == nil {
		ctx.LineageParents = make(map[string]string)
	}
	ctx.LineageParents[child] = parent
	ctx.LineageParentsLock.Unlock()
}

// LineageSourceFor returns the parent target for the message's child target,
// for stamping onto OutputMessage.Source at the single OutputHook choke point.
// It prefers the explicitly recorded parent and falls back to derivation.
func LineageSourceFor(ctx *ScanContext, msg structs.OutputMessage) string {
	if ctx == nil {
		return ""
	}
	child := targetutil.NormalizeTarget(lineageChildKey(msg))
	if child == "" || child == "unknown" {
		return ""
	}
	ctx.LineageParentsLock.Lock()
	parent, ok := ctx.LineageParents[child]
	ctx.LineageParentsLock.Unlock()
	if ok && parent != "" {
		return parent
	}
	return targetutil.NormalizeTarget(deriveLineageParent(ctx, msg, child))
}

// bareHostPort returns "host:port" for a URL with default ports filled in,
// without the scheme. Returns "" when raw is not a URL.
func bareHostPort(raw string) string {
	if !strings.Contains(raw, "://") {
		return ""
	}
	u, err := url.Parse(targetutil.NormalizeTarget(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Host
}

// firstDomainForIP returns the first domain recorded as resolving to ip.
func firstDomainForIP(ctx *ScanContext, ip string) string {
	if ctx == nil || ip == "" {
		return ""
	}
	ctx.IPDomainMapLock.Lock()
	defer ctx.IPDomainMapLock.Unlock()
	for _, d := range ctx.IPDomainMap[ip] {
		if d != "" {
			return d
		}
	}
	return ""
}

// inputSegmentForIP returns the CIDR/IP-range input target that contains ip —
// the original scan segment the address was enumerated from. Lineage must start
// at that input, so a host found by scanning a segment traces back to the
// segment itself rather than stopping at the derived IP.
func inputSegmentForIP(ctx *ScanContext, ip string) string {
	if ctx == nil || ip == "" {
		return ""
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	for _, target := range ctx.Config.Targets {
		target = strings.TrimSpace(target)
		// Only segment inputs (CIDR / IP range) qualify: a bare-IP input is its
		// own root and must not be turned into a self-parent.
		if !strings.Contains(target, "/") && !strings.Contains(target, "-") {
			continue
		}
		if utils.TargetContainsIP(target, parsed) {
			return target
		}
	}
	return ""
}

// rootDomainSuffix returns the longest input target that is a proper suffix of
// domain (i.e. the root domain the subdomain was enumerated from).
func rootDomainSuffix(ctx *ScanContext, domain string) string {
	if ctx == nil || domain == "" {
		return ""
	}
	best := ""
	for _, target := range ctx.Config.Targets {
		target = strings.TrimSpace(target)
		if target == "" || strings.Contains(target, "/") {
			continue
		}
		if domain == target {
			continue
		}
		if strings.HasSuffix(domain, "."+target) && len(target) > len(best) {
			best = target
		}
	}
	return best
}
