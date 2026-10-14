// Package targetutil provides the single source of truth for target
// normalization shared by the agent (lineage stamping) and the server
// (lineage chain walking). Both sides must agree on the normalized form or
// parent/child targets will not join.
package targetutil

import (
	"net/url"
	"strings"
)

// NormalizeTarget normalizes a raw target string into a canonical form.
// URLs become scheme://host:port with default ports filled in (http:80,
// https:443). Empty and "unknown" are returned unchanged, as is anything that
// does not parse as a URL with a host.
func NormalizeTarget(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "unknown" {
		return raw
	}

	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil && u.Host != "" {
			host := u.Hostname()
			port := u.Port()
			if port == "" {
				switch u.Scheme {
				case "https":
					port = "443"
				case "http":
					port = "80"
				}
			}
			if port != "" {
				return u.Scheme + "://" + host + ":" + port
			}
			return u.Scheme + "://" + host
		}
	}

	return raw
}

// NormalizeTargetWithPath 与 NormalizeTarget 一样归一到 scheme://host:port，
// 但当 URL 带有路径时额外附加首段路径（/app1），用于标识"按路径反代的独立应用"资产。
// 根路径与 NormalizeTarget 完全一致；无 :// 或非 URL 的原样返回。
func NormalizeTargetWithPath(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "unknown" {
		return trimmed
	}
	if !strings.Contains(trimmed, "://") {
		return raw
	}
	u, err := url.Parse(trimmed)
	if err != nil || u.Host == "" {
		return raw
	}
	base := NormalizeTarget(trimmed)
	seg := firstPathSegment(u.Path)
	if seg == "" {
		return base
	}
	return base + "/" + seg
}

// firstPathSegment 返回路径的首个有效段（小写、去空段）；根路径返回 ""。
func firstPathSegment(p string) string {
	for _, part := range strings.Split(p, "/") {
		part = strings.TrimSpace(part)
		if part != "" {
			return strings.ToLower(part)
		}
	}
	return ""
}
