package crawler

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/html"

	"github.com/P0lar1ght/argus/scanner/structs"
)

// pathmine.go：从已抓取的 JS/HTML 内容挖掘站点内路径，按一级前缀分组画像，
// 识别"按路径反代到不同系统的独立应用"（path_app）与"仅 JS 出现的隐藏端点"
// （hidden_path），作为关联资产候选上报。
//
// 关键约束：挖掘只产出候选，绝不把新路径加入抓取前沿（不扩大爬取范围/成本）；
// 路径候选与种子同 host:port 是设计使然（反代应用挂在同站点路径下）。

// MinedPath 一条从已抓取内容中挖掘出的路径候选。
type MinedPath struct {
	Path   string // 归一后的站点内路径（/api/order）
	Origin string // js-str / js-template / html-attr / html-inline-js
	FromJS bool
}

var (
	// jsStrPathMineRe 匹配 JS 引号字符串中的站点内路径。段首字符类已排除 /，
	// 故天然跳过协议相对 //host；单段起。
	jsStrPathMineRe = regexp.MustCompile(`["'](/[A-Za-z0-9._~\-]+(?:/[A-Za-z0-9._~\-]+)*)["']`)
	// jsTmplPathMineRe 匹配模板字面量中的静态路径前缀（`/api/order/${id}` → /api/order）。
	jsTmplPathMineRe = regexp.MustCompile("`(/[A-Za-z0-9._~\\-]+(?:/[A-Za-z0-9._~\\-]+)*)[^`]*`")
	// titleRe 提取 <title> 文本（用于判断路径应用是否有独立标题）。
	titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
)

// pathRejectFirst 首段静态资源目录拒绝表：这些前缀不可能是独立应用/隐藏端点。
var pathRejectFirst = map[string]bool{
	"static": true, "assets": true, "css": true, "js": true, "images": true,
	"img": true, "fonts": true, "media": true, "_next": true, "dist": true,
	"build": true, "node_modules": true, "favicon.ico": true,
}

// minePaths 从 body 挖掘站点内路径候选。isJS=true 走 JS miner（引号串 + 模板前缀），
// 否则走 HTML miner（属性值 + 内联 script）。
func minePaths(body string, isJS bool) []MinedPath {
	if isJS {
		return mineJSPaths(body)
	}
	return mineHTMLPaths(body)
}

// mineJSPaths 挖掘 JS 中的路径：引号字符串 js-str + 模板字面量静态前缀 js-template。
func mineJSPaths(body string) []MinedPath {
	var out []MinedPath
	for _, m := range jsStrPathMineRe.FindAllStringSubmatch(body, -1) {
		if p, ok := pathOK(m[1]); ok {
			out = append(out, MinedPath{Path: p, Origin: "js-str", FromJS: true})
		}
	}
	for _, m := range jsTmplPathMineRe.FindAllStringSubmatch(body, -1) {
		if p, ok := pathOK(m[1]); ok {
			out = append(out, MinedPath{Path: p, Origin: "js-template", FromJS: true})
		}
	}
	return out
}

// mineHTMLPaths 挖掘 HTML 中的路径：所有属性值中的站点内路径 html-attr +
// 内联 script（无 src）文本跑 JS miner html-inline-js。
func mineHTMLPaths(body string) []MinedPath {
	var out []MinedPath
	var inlineJS strings.Builder
	inInlineScript := false
	z := html.NewTokenizer(strings.NewReader(body))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		switch tt {
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			src := ""
			if hasAttr {
				for {
					k, v, more := z.TagAttr()
					if string(k) == "src" {
						src = string(v)
					}
					if p, ok := mineAttrPath(string(v)); ok {
						out = append(out, MinedPath{Path: p, Origin: "html-attr"})
					}
					if !more {
						break
					}
				}
			}
			if string(name) == "script" {
				inInlineScript = src == ""
				if inInlineScript {
					inlineJS.Reset()
				}
			}
		case html.EndTagToken:
			name, _ := z.TagName()
			if string(name) == "script" && inInlineScript {
				for _, mp := range mineJSPaths(inlineJS.String()) {
					mp.Origin = "html-inline-js"
					out = append(out, mp)
				}
				inInlineScript = false
			}
		case html.TextToken:
			if inInlineScript {
				inlineJS.Write(z.Text())
			}
		}
	}
	return out
}

// mineAttrPath 判断单个属性值是否为站点内路径候选（data-url/data-href/action/href/...）。
func mineAttrPath(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if len(v) < 2 || len(v) > 128 {
		return "", false
	}
	if v[0] != '/' || v[1] == '/' {
		return "", false
	}
	if strings.ContainsAny(v, " \t\r\n\"'") {
		return "", false
	}
	return pathOK(v)
}

// pathOK 归一并校验路径候选：去 query/fragment、collapse //、去尾 /；
// 根路径、协议相对 //host、首段命中拒绝表的剔除；仅可打印 ASCII。
func pathOK(raw string) (string, bool) {
	if strings.HasPrefix(raw, "//") {
		return "", false // 协议相对（//host/path）是跨站引用，非站点内路径
	}
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		raw = raw[:i]
	}
	for strings.Contains(raw, "//") {
		raw = strings.ReplaceAll(raw, "//", "/")
	}
	raw = strings.TrimRight(raw, "/")
	if len(raw) < 2 || raw[0] != '/' {
		return "", false
	}
	seg := pathFirstSeg(raw)
	if seg == "" || pathRejectFirst[strings.ToLower(seg)] {
		return "", false
	}
	for _, r := range raw {
		if r < 0x21 || r > 0x7e {
			return "", false
		}
	}
	return raw, true
}

// pathFirstSeg 返回站点内路径的一级前缀（/app1/page → app1；根路径返回 ""）。
func pathFirstSeg(p string) string {
	rest := strings.TrimPrefix(p, "/")
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		rest = rest[:i]
	}
	return rest
}

// extractTitle 提取 <title> 文本（空则 ""）。
func extractTitle(body string) string {
	m := titleRe.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// prefixProfile 单个一级路径前缀的画像（识别独立应用/隐藏端点的依据）。
type prefixProfile struct {
	pages       int    // 实际抓到的该前缀页面数
	mined       int    // 挖掘到的该前缀路径数（HTML+JS）
	minedFromJS int    // 挖掘到的该前缀路径中来自 JS 的数量
	selfLinks   int    // 该前缀页面指向本前缀的链接数
	crossLinks int    // 该前缀页面指向其他前缀的链接数
	title       string // 该前缀着陆页 <title>
	hasLanding  bool   // 是否存在路径恰为前缀本身的着陆页
}

// selfRatio 本前缀链接自包含比例 self/(self+cross)；无链接返回 0。
func (p *prefixProfile) selfRatio() float64 {
	total := p.selfLinks + p.crossLinks
	if total == 0 {
		return 0
	}
	return float64(p.selfLinks) / float64(total)
}

// pathProfiler per-seed 累加器。maxApps<=0 时为 nil（完全不画像，零开销）。
type pathProfiler struct {
	maxApps   int
	profiles  map[string]*prefixProfile
	rootTitle string
}

func newPathProfiler(opts Options) *pathProfiler {
	if opts.MaxPathApps <= 0 {
		return nil
	}
	return &pathProfiler{maxApps: opts.MaxPathApps, profiles: map[string]*prefixProfile{}}
}

// observe 在一次抓取结果上累加画像：页面归桶计数 + 提标题 + 链接分 self/cross；
// JS/HTML body 各跑 minePaths 归桶。
func (pr *pathProfiler) observe(res fetchedResource, seed *url.URL) {
	if res.isJS {
		for _, mp := range minePaths(res.body, true) {
			pr.bumpMined(mp)
		}
		return
	}
	title := extractTitle(res.body)
	seg := pathFirstSeg(res.u.Path)
	if seg == "" {
		// 根页面：记录根标题（标题独立性的对照基准）。
		if pr.rootTitle == "" && title != "" {
			pr.rootTitle = title
		}
	} else {
		p := pr.profile(seg)
		p.pages++
		if title != "" && p.title == "" {
			p.title = title
		}
		if strings.TrimRight(res.u.Path, "/") == "/"+seg {
			p.hasLanding = true
		}
		// 链接分 self/cross：同前缀 self，跨前缀 cross。
		for _, l := range extractLinks(res.u, res.body) {
			if l.URL == nil {
				continue
			}
			if pathFirstSeg(l.URL.Path) == seg {
				p.selfLinks++
			} else {
				p.crossLinks++
			}
		}
	}
	// HTML 挖掘（含内联 JS），归桶。
	for _, mp := range minePaths(res.body, false) {
		pr.bumpMined(mp)
	}
}

// bumpMined 把一条挖掘路径计入其前缀画像。
func (pr *pathProfiler) bumpMined(mp MinedPath) {
	seg := pathFirstSeg(mp.Path)
	if seg == "" {
		return
	}
	p := pr.profile(seg)
	p.mined++
	if mp.FromJS {
		p.minedFromJS++
	}
}

func (pr *pathProfiler) profile(seg string) *prefixProfile {
	p, ok := pr.profiles[seg]
	if !ok {
		p = &prefixProfile{}
		pr.profiles[seg] = p
	}
	return p
}

// pathAppCandidate 一个通过启发式的路径前缀候选。
type pathAppCandidate struct {
	seg      string
	siteType string
	score    int
	evidence string
}

// evaluate 评估画像，产出 path_app / hidden_path 候选（受每 host:port 上限约束），
// 逐条经 reportPathApp 上报。
func (pr *pathProfiler) evaluate(source *url.URL, shared *sharedState, opts Options, emit emitFunc, stats *Stats) {
	var cands []pathAppCandidate
	for seg, p := range pr.profiles {
		if pathRejectFirst[strings.ToLower(seg)] {
			continue
		}
		if c, ok := p.classify(seg, pr.rootTitle); ok {
			cands = append(cands, c)
		}
	}
	// 按 score=pages*2+mined 降序，截断到上限。
	for i := 0; i < len(cands); i++ {
		for j := i + 1; j < len(cands); j++ {
			if cands[j].score > cands[i].score {
				cands[i], cands[j] = cands[j], cands[i]
			}
		}
	}
	if len(cands) > pr.maxApps {
		cands = cands[:pr.maxApps]
	}
	for _, c := range cands {
		reportPathApp(source, c, opts, emit, shared, stats)
	}
}

// classify 按启发式把单个前缀定型为 path_app / hidden_path；不命中返回 false。
func (p *prefixProfile) classify(seg, rootTitle string) (pathAppCandidate, bool) {
	score := p.pages*2 + p.mined
	// path_app：反代独立应用——有着陆页、≥2 页、链接自包含、标题独立于根。
	if p.hasLanding && p.pages >= 2 && p.selfRatio() >= 0.8 && p.title != "" && p.title != rootTitle {
		return pathAppCandidate{
			seg:      seg,
			siteType: "path_app",
			score:    score,
			evidence: fmt.Sprintf("path-app: pages=%d self=%.0f%% title=%q", p.pages, p.selfRatio()*100, p.title),
		}, true
	}
	// hidden_path：仅 JS 出现的隐藏端点（如 /api、/internal）——无抓取页面但 JS 多次引用。
	if p.pages == 0 && p.mined >= 3 && p.minedFromJS >= 2 {
		return pathAppCandidate{
			seg:      seg,
			siteType: "hidden_path",
			score:    score,
			evidence: fmt.Sprintf("hidden-path: mined=%d js=%d", p.mined, p.minedFromJS),
		}, true
	}
	return pathAppCandidate{}, false
}

// reportPathApp 上报一个路径前缀应用/隐藏端点候选。仿 reportSite，但**不**做
// seed-root 跳过——路径候选与种子同 host:port 正是设计目标。证据写入 LinkContext。
func reportPathApp(source *url.URL, c pathAppCandidate, opts Options, emit emitFunc, shared *sharedState, stats *Stats) {
	candidate, err := url.Parse(hostPortKey(source) + "/" + c.seg)
	if err != nil || candidate == nil {
		return
	}
	key := candidate.String()
	if _, ok := shared.emittedSites[key]; ok {
		return
	}
	shared.emittedSites[key] = struct{}{}
	stats.SitesReported++

	host, port := hostPort(candidate)
	emit(structs.OutputMessage{
		Type: PayloadTypeCrawlSite,
		URI:  key,
		CrawlSite: &structs.CrawlSiteMsg{
			SourceURL:   source.String(),
			URL:         key,
			Scheme:      candidate.Scheme,
			Host:        host,
			Port:        port,
			SiteType:    c.siteType,
			LinkContext: truncate(c.evidence, 200),
			AIControl:   opts.CrawlAI,
		},
	})
}
