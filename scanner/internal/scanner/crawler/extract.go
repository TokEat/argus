package crawler

import (
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

// LinkRef 一个从 HTML 中提取出的链接及其上下文。
type LinkRef struct {
	URL     *url.URL
	Context string // 锚文本或 title 等
}

// SensitiveHit 一次敏感信息正则预筛命中。
type SensitiveHit struct {
	Kind    string // email/phone/idcard/username/account/apikey/token/secret
	Value   string
	Snippet string // 有界上下文
}

// snippetPad 命中值前后各保留的上下文长度。
const snippetPad = 120

// 敏感信息预筛正则（仅作召回，精确判定交给服务端 AI）。
// secret/凭据赋值模式见 secrets.go。
var (
	emailRe  = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	phoneRe  = regexp.MustCompile(`(?:1[3-9]\d{9})|(?:0\d{2,3}[-\s]?\d{7,8})`)
	idcardRe = regexp.MustCompile(`\b\d{17}[\dXx]\b`)
	// jsAbsURLRe 从 JS 中提取绝对 URL。
	jsAbsURLRe = regexp.MustCompile(`["'](https?://[A-Za-z0-9.\-]+(?::\d{1,5})?(?:/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*)?)["']`)
	// jsPathRe 从 JS 中提取站点内相对路径。
	jsPathRe = regexp.MustCompile(`["'](/[A-Za-z0-9._~\-]+(?:/[A-Za-z0-9._~\-]+)+)["']`)
)

// htmlLinkAttrs 定义哪些标签的哪些属性会被当作链接提取。
var htmlLinkAttrs = map[string]bool{
	"a":      true,
	"link":   true,
	"script": true,
	"img":    true,
	"iframe": true,
	"form":   true,
	"area":   true,
}

// extractLinks 解析 HTML，提取可导航/可抓取链接（a/link/script/img/iframe/form/area）。
// 相对链接基于 base 解析。返回去重后的链接。
func extractLinks(base *url.URL, body string) []LinkRef {
	if base == nil || body == "" {
		return nil
	}
	var links []LinkRef
	seen := map[string]struct{}{}
	z := html.NewTokenizer(strings.NewReader(body))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		name, hasAttr := z.TagName()
		tag := string(name)
		var raw, text string
		if hasAttr {
			for {
				k, v, more := z.TagAttr()
				if len(k) > 0 {
					switch string(k) {
					case "href", "src", "action":
						raw = string(v)
					case "title", "alt":
						if text == "" {
							text = string(v)
						}
					}
				}
				if !more {
					break
				}
			}
		}
		if !htmlLinkAttrs[tag] || raw == "" {
			continue
		}
		if strings.HasPrefix(raw, "javascript:") || strings.HasPrefix(raw, "mailto:") || strings.HasPrefix(raw, "tel:") || strings.HasPrefix(raw, "data:") {
			continue
		}
		resolved := resolveURL(base, raw)
		if resolved == nil {
			continue
		}
		key := resolved.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		links = append(links, LinkRef{URL: resolved, Context: text})
	}
	return links
}

// resolveURL 将可能的相对链接解析为绝对 URL；仅保留 http/https。
func resolveURL(base *url.URL, raw string) *url.URL {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	r, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	if r.IsAbs() {
		if r.Scheme != "http" && r.Scheme != "https" {
			return nil
		}
		return normalizeURL(r.String())
	}
	// 协议相对链接 //host/path。
	if strings.HasPrefix(raw, "//") {
		abs, err := url.Parse(base.Scheme + ":" + raw)
		if err != nil {
			return nil
		}
		return normalizeURL(abs.String())
	}
	abs := base.ResolveReference(r)
	return normalizeURL(abs.String())
}

// extractJSRefs 提取 HTML 中 <script src> 指向的 JS 文件 URL（同站点抓取目标）。
func extractJSRefs(base *url.URL, body string) []*url.URL {
	var out []*url.URL
	for _, l := range extractLinks(base, body) {
		if strings.HasSuffix(strings.ToLower(l.URL.Path), ".js") {
			out = append(out, l.URL)
		}
	}
	return out
}

// isJSURL 判断一个 URL/内容类型是否应按 JS 处理。
func isJSURL(u *url.URL, contentType string) bool {
	if u != nil && strings.HasSuffix(strings.ToLower(u.Path), ".js") {
		return true
	}
	ct := strings.ToLower(contentType)
	return strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript")
}

// extractFromJS 从 JS 内容中提取绝对 URL 与站点内路径（用于发现更多页面/关联站点）。
func extractFromJS(base *url.URL, body string) []*url.URL {
	var out []*url.URL
	seen := map[string]struct{}{}
	add := func(u *url.URL) {
		if u == nil {
			return
		}
		key := u.String()
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			out = append(out, u)
		}
	}
	for _, m := range jsAbsURLRe.FindAllStringSubmatch(body, -1) {
		add(resolveURL(base, m[1]))
	}
	for _, m := range jsPathRe.FindAllStringSubmatch(body, -1) {
		add(resolveURL(base, m[1]))
	}
	return out
}

// snippet 提取命中位置前后各 pad 字节的上下文。
func snippet(body string, start, end, pad int) string {
	lo := start - pad
	if lo < 0 {
		lo = 0
	}
	hi := end + pad
	if hi > len(body) {
		hi = len(body)
	}
	return strings.TrimSpace(body[lo:hi])
}

// truncate 截断过长字符串。
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
