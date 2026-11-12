package engine

import (
	"strings"

	"github.com/TokEat/argus/scanner/internal/scanner/crawler"
	"github.com/TokEat/argus/scanner/structs"
)

// runCrawlPhase 主动页面爬取 + 敏感信息提取阶段。
//
// 以 HTTP 探活得到的存活站点为种子，在严格同 host:port 范围内爬取页面与
// JS（hash 去重），提取"同主机不同站点"关联资产候选与敏感信息候选。该阶段
// 为尽力而为：失败不应中断主扫描链路。
func runCrawlPhase(ctx *ScanContext, cfg *Config) error {
	if cfg == nil || (!cfg.WebCrawl && !cfg.SensitiveInfo) {
		return nil
	}
	urlMap := currentPipelineURLMap(ctx)
	if len(urlMap) == 0 {
		return nil
	}

	seeds := make([]crawler.Seed, 0, len(urlMap))
	for rootURL, entity := range urlMap {
		rootURL = strings.TrimSpace(rootURL)
		if rootURL == "" {
			continue
		}
		seeds = append(seeds, crawler.Seed{RootURL: rootURL, IP: entity.IP})
	}
	if len(seeds) == 0 {
		return nil
	}

	threads := cfg.WebThreads
	if threads < 1 {
		threads = 1
	}
	opts := crawler.Options{
		EnableCrawl:     cfg.WebCrawl,
		EnableSensitive: cfg.SensitiveInfo,
		MaxDepth:        cfg.WebCrawlMaxDepth,
		MaxPages:        cfg.WebCrawlMaxPages,
		MaxPathApps:     cfg.WebCrawlMaxPathApps,
		Threads:         threads,
		Timeout:         cfg.WebTimeout,
		Proxy:           cfg.HTTPProxy,
		CrawlAI:         cfg.WebCrawlAI,
		SensitiveAI:     cfg.SensitiveInfoAI,
	}

	emit := func(msg structs.OutputMessage) {
		RecordLineageParent(ctx, msg)
		dispatchPipelineOutput(ctx, msg)
	}
	stats := crawler.CrawlSeeds(seeds, opts, emit)
	crawler.LogStats(len(seeds), stats)
	return nil
}
