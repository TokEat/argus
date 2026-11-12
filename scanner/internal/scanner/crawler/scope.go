package crawler

import (
	"net"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// classification 描述一个链接相对种子站点的归属。
type classification int

const (
	// classInScope 同 host:port，可继续抓取。
	classInScope classification = iota
	// classRelated 同主机不同端口 / 同主域兄弟子域，作为关联站点候选上报但不抓取。
	classRelated
	// classOutOfScope 其余外链，忽略。
	classOutOfScope
)

// normalizeURL 解析并归一化 URL：小写 host、去除默认端口、去掉 fragment。
// 解析失败返回 nil。
func normalizeURL(raw string) *url.URL {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = normalizeHost(u.Host)
	u.Fragment = ""
	return u
}

// normalizeHost 小写主机名并按 scheme 去除默认端口。
func normalizeHost(hostport string) string {
	host := hostport
	port := ""
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		host, port = h, p
	} else {
		// 处理 "example.com:" 或无端口形式。
		if i := strings.LastIndex(hostport, ":"); i >= 0 && !strings.Contains(hostport[i+1:], ":") {
			host = hostport[:i]
			port = hostport[i+1:]
		}
	}
	host = strings.Trim(strings.ToLower(host), ".")
	if port != "" && isDefaultPort("", port) {
		port = ""
	}
	if port == "" {
		return host
	}
	return net.JoinHostPort(host, port)
}

// isDefaultPort 判断端口是否为该 scheme 的默认端口（空 scheme 按常见默认）。
func isDefaultPort(scheme, port string) bool {
	switch strings.ToLower(scheme) {
	case "http":
		return port == "80"
	case "https":
		return port == "443"
	}
	return port == "80" || port == "443"
}

// hostPort 返回主机名与有效端口（无显式端口时按 scheme 推断）。
func hostPort(u *url.URL) (string, int) {
	host := strings.ToLower(u.Hostname())
	port := 0
	if p := u.Port(); p != "" {
		if v, err := strconv.Atoi(p); err == nil {
			port = v
		}
	}
	if port == 0 {
		switch strings.ToLower(u.Scheme) {
		case "https":
			port = 443
		case "http":
			port = 80
		}
	}
	return host, port
}

// sameHostPort 判断两个 URL 是否同 scheme+host+port（抓取边界）。
func sameHostPort(a, b *url.URL) bool {
	if a == nil || b == nil {
		return false
	}
	ah, ap := hostPort(a)
	bh, bp := hostPort(b)
	return strings.EqualFold(a.Scheme, b.Scheme) && ah == bh && ap == bp
}

// parentDomain 返回主机名的可注册父域（有效 TLD+1）。IP 或解析失败返回空。
func parentDomain(host string) string {
	host = strings.Trim(strings.ToLower(host), ".")
	if host == "" || net.ParseIP(host) != nil {
		return ""
	}
	eTLDPlusOne, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return ""
	}
	return eTLDPlusOne
}

// classifyLink 判定一个链接相对种子的归属。
// seedIP 为种子解析到的 IP（可为空），用于识别同 IP 其他端口。
func classifyLink(link, seed *url.URL, seedIP string) classification {
	if link == nil || seed == nil {
		return classOutOfScope
	}
	if sameHostPort(link, seed) {
		return classInScope
	}
	linkHost, linkPort := hostPort(link)
	seedHost, seedPort := hostPort(seed)

	// 同 IP 其他端口。
	if seedIP != "" && net.ParseIP(linkHost) != nil && linkHost == seedIP && linkPort != seedPort {
		return classRelated
	}
	// 种子本身是 IP：仅同 IP 不同端口才算关联，其余 IP 忽略。
	if net.ParseIP(seedHost) != nil {
		return classOutOfScope
	}

	// 同主域兄弟子域。
	linkParent := parentDomain(linkHost)
	seedParent := parentDomain(seedHost)
	if linkParent != "" && linkParent == seedParent && linkHost != seedHost {
		return classRelated
	}
	return classOutOfScope
}
