package crawler

import (
	"net/url"
	"strconv"
	"sync"

	httpx "github.com/projectdiscovery/httpx"
	"github.com/projectdiscovery/httpx/common/hashes"
	"github.com/projectdiscovery/httpx/runner"
	"github.com/projectdiscovery/gologger"

	"github.com/TokEat/argus/scanner/structs"
)

// jsBodyLimit 抓取页面/JS 时的响应体读取上限（4MiB）。Minified JS bundle 常超 1MiB，
// 密钥/凭据块若恰在截断端点会漏检；MaxPages 有限故最坏内存可接受。
const jsBodyLimit = 4 << 20

// sharedState 跨种子共享的去重状态。
type sharedState struct {
	seedRoots        map[string]struct{} // 所有种子 scheme://host:port，命中则不上报为关联站点
	emittedSites     map[string]struct{} // 已上报的关联站点候选 URL
	emittedSensitive map[string]struct{} // 已上报的敏感信息 host|kind|value
}

// frontierItem 一个待抓取的资源。
type frontierItem struct {
	u     *url.URL
	depth int
	isJS  bool
}

// fetchedResource 一次抓取结果及元数据。
type fetchedResource struct {
	u           *url.URL
	depth       int
	isJS        bool
	status      int
	contentType string
	body        string
}

// CrawlSeeds 对多个种子站点执行爬取与敏感信息提取，逐条 emit 结果。
func CrawlSeeds(seeds []Seed, opts Options, emit emitFunc) Stats {
	var stats Stats
	if emit == nil {
		emit = func(structs.OutputMessage) {}
	}
	shared := &sharedState{
		seedRoots:        make(map[string]struct{}),
		emittedSites:     make(map[string]struct{}),
		emittedSensitive: make(map[string]struct{}),
	}
	normalized := make([]Seed, 0, len(seeds))
	for _, s := range seeds {
		u := normalizeURL(s.RootURL)
		if u == nil || (u.Scheme != "http" && u.Scheme != "https") {
			continue
		}
		normalized = append(normalized, Seed{RootURL: u.String(), IP: s.IP})
		shared.seedRoots[hostPortKey(u)] = struct{}{}
	}
	for _, s := range normalized {
		st := crawlSite(normalizeURL(s.RootURL), s.IP, opts, emit, shared)
		stats.PagesFetched += st.PagesFetched
		stats.SitesReported += st.SitesReported
		stats.SensitiveFound += st.SensitiveFound
	}
	return stats
}

// hostPortKey 返回 scheme://host:port 归一化键。
func hostPortKey(u *url.URL) string {
	if u == nil {
		return ""
	}
	host, port := hostPort(u)
	return u.Scheme + "://" + host + ":" + strconv.Itoa(port)
}

// crawlSite 在严格同 host:port 范围内对一个种子做 BFS 爬取。
func crawlSite(seed *url.URL, seedIP string, opts Options, emit emitFunc, shared *sharedState) Stats {
	var stats Stats
	visited := make(map[string]struct{})
	contentSeen := make(map[string]struct{})
	frontier := []frontierItem{{u: seed, depth: 0, isJS: false}}
	pages := 0
	prof := newPathProfiler(opts)

	for len(frontier) > 0 && pages < opts.maxPages() {
		// 组装本层批次并登记 visited。
		batch := make([]string, 0, len(frontier))
		meta := make(map[string]frontierItem, len(frontier))
		for _, it := range frontier {
			key := it.u.String()
			if _, ok := visited[key]; ok {
				continue
			}
			visited[key] = struct{}{}
			batch = append(batch, key)
			meta[key] = it
		}
		frontier = nil
		if len(batch) == 0 {
			continue
		}
		for _, res := range fetchBatch(batch, meta, opts) {
			if pages >= opts.maxPages() {
				break
			}
			pages++
			stats.PagesFetched++

			bodyHash := contentHash(res.body)
			dupContent := false
			if bodyHash != "" {
				if _, ok := contentSeen[bodyHash]; ok {
					dupContent = true
				} else {
					contentSeen[bodyHash] = struct{}{}
				}
			}

			if opts.EnableSensitive && !dupContent {
				stats.SensitiveFound += emitSensitive(res, opts, emit, shared)
			}
			if dupContent {
				continue
			}

			// 路径画像（仅 MaxPathApps>0 时非 nil）：记录页面/JS 到前缀桶。
			if prof != nil {
				prof.observe(res, seed)
			}

			if res.isJS {
				// JS：提取其中绝对 URL / 相对路径以发现更多页面与关联站点。
				if opts.EnableCrawl && res.depth+1 <= opts.maxDepth() {
					for _, u := range extractFromJS(res.u, res.body) {
						frontier = appendFrontier(frontier, visited, u, res.depth+1, false, seed, seedIP, res.u, "", opts, emit, shared, &stats)
					}
				}
				continue
			}

			// HTML 页面：JS 引用总是入队（敏感需要）；导航链接仅爬取开启时跟踪。
			for _, js := range extractJSRefs(res.u, res.body) {
				if opts.EnableSensitive || opts.EnableCrawl {
					if res.depth+1 <= opts.maxDepth() || !opts.EnableCrawl {
						if _, ok := visited[js.String()]; !ok {
							frontier = append(frontier, frontierItem{u: js, depth: res.depth + 1, isJS: true})
						}
					}
				}
			}
			if opts.EnableCrawl && res.depth+1 <= opts.maxDepth() {
				for _, l := range extractLinks(res.u, res.body) {
					frontier = appendFrontier(frontier, visited, l.URL, res.depth+1, false, seed, seedIP, res.u, l.Context, opts, emit, shared, &stats)
				}
			}
		}
	}

	// BFS 结束后评估路径前缀画像，上报 path_app / hidden_path 候选。
	if prof != nil {
		prof.evaluate(seed, shared, opts, emit, &stats)
	}
	return stats
}

// appendFrontier 按归属分类处理一个链接：同 host:port 入队抓取，关联站点上报，其余丢弃。
func appendFrontier(frontier []frontierItem, visited map[string]struct{}, u *url.URL, depth int, isJS bool, seed *url.URL, seedIP string, source *url.URL, context string, opts Options, emit emitFunc, shared *sharedState, stats *Stats) []frontierItem {
	if u == nil {
		return frontier
	}
	switch classifyLink(u, seed, seedIP) {
	case classInScope:
		if _, ok := visited[u.String()]; !ok {
			return append(frontier, frontierItem{u: u, depth: depth, isJS: isJS})
		}
	case classRelated:
		reportSite(source, u, context, opts, emit, shared, stats)
	}
	return frontier
}

// fetchBatch 通过 httpx 批量抓取一层 URL，回调内聚合结果（线程安全）。
func fetchBatch(batch []string, meta map[string]frontierItem, opts Options) []fetchedResource {
	var mu sync.Mutex
	var out []fetchedResource
	httpx.CallHTTPxLimit(batch, func(resp runner.Result) {
		if resp.Failed || resp.StatusCode == 0 {
			return
		}
		u := normalizeURL(resp.URL)
		if u == nil {
			u = normalizeURL(resp.Input)
		}
		if u == nil {
			return
		}
		m, ok := lookupMeta(meta, resp, u)
		if !ok {
			return
		}
		mu.Lock()
		out = append(out, fetchedResource{
			u:           u,
			depth:       m.depth,
			isJS:        m.isJS,
			status:      resp.StatusCode,
			contentType: resp.ContentType,
			body:        resp.Body,
		})
		mu.Unlock()
	}, opts.Proxy, opts.Threads, opts.Timeout, jsBodyLimit)
	return out
}

// lookupMeta 依据 Input/URL 从 meta 中找回元数据。
func lookupMeta(meta map[string]frontierItem, resp runner.Result, final *url.URL) (frontierItem, bool) {
	if m, ok := meta[resp.Input]; ok {
		return m, true
	}
	if in := normalizeURL(resp.Input); in != nil {
		if m, ok := meta[in.String()]; ok {
			return m, true
		}
	}
	if m, ok := meta[final.String()]; ok {
		return m, true
	}
	return frontierItem{}, false
}

// contentHash 计算响应体的 simhash（近似去重）；失败退回 md5。
func contentHash(body string) string {
	if body == "" {
		return ""
	}
	if h := hashes.Simhash([]byte(body)); h != "" {
		return "sim:" + h
	}
	return "md5:" + hashes.Md5([]byte(body))
}

// reportSite 上报一个"同主机不同站点"关联资产候选（去重 + 跳过种子自身）。
func reportSite(source, candidate *url.URL, context string, opts Options, emit emitFunc, shared *sharedState, stats *Stats) {
	if candidate == nil {
		return
	}
	if _, isSeed := shared.seedRoots[hostPortKey(candidate)]; isSeed {
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
			LinkContext: truncate(context, 200),
			AIControl:   opts.CrawlAI,
		},
	})
}

// emitSensitive 对单个资源做敏感信息预筛并上报（按 host|kind|value 去重）。
func emitSensitive(res fetchedResource, opts Options, emit emitFunc, shared *sharedState) int {
	host, _ := hostPort(res.u)
	count := 0
	for _, hit := range sensitiveScan(res.body) {
		key := host + "|" + hit.Kind + "|" + hit.Value
		if _, ok := shared.emittedSensitive[key]; ok {
			continue
		}
		shared.emittedSensitive[key] = struct{}{}
		count++
		emit(structs.OutputMessage{
			Type: PayloadTypeSensitiveInfo,
			URI:  res.u.String(),
			SensitiveInfo: &structs.SensitiveInfoMsg{
				SourceURL: res.u.String(),
				Host:      host,
				Kind:      hit.Kind,
				Value:     hit.Value,
				Snippet:   hit.Snippet,
				AIControl: opts.SensitiveAI,
			},
		})
	}
	return count
}

func (o Options) maxDepth() int {
	if o.MaxDepth < 1 {
		return 1
	}
	return o.MaxDepth
}

func (o Options) maxPages() int {
	if o.MaxPages < 1 {
		return 1
	}
	return o.MaxPages
}

// LogStats 输出爬取统计（由流水线阶段调用）。
func LogStats(seedCount int, stats Stats) {
	gologger.Info().Msgf("[WebCrawl] seeds=%d pages=%d sites=%d sensitive=%d",
		seedCount, stats.PagesFetched, stats.SitesReported, stats.SensitiveFound)
}
