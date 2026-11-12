// Package crawler 实现主动页面爬取与同主机关联站点提取。
//
// 爬取严格限定在种子站点（scheme://host:port）范围内：仅抓取与该种子
// 同 host:port 的页面与 JS，并通过内容 hash 去重。指向同主机其他端口或
// 同主域兄弟子域的链接不会被抓取，仅作为"关联站点资产候选"上报。页面与
// JS 内容同时作为敏感信息提取的输入。
package crawler

import "github.com/TokEat/argus/scanner/structs"

// 输出消息类型（OutputMessage.Type / gRPC PayloadType）。
const (
	PayloadTypeCrawlSite    = "CrawlSite"
	PayloadTypeSensitiveInfo = "SensitiveInfo"
)

// Options 控制爬取行为。
type Options struct {
	// EnableCrawl 开启 host:port 内 BFS 爬取与关联站点提取。
	EnableCrawl bool
	// EnableSensitive 开启页面/JS 敏感信息提取。
	EnableSensitive bool
	// MaxDepth 最大爬取深度（种子页为 0）。
	MaxDepth int
	// MaxPages 每站点最大抓取资源数（页面+JS 合计）。
	MaxPages int
	// MaxPathApps 每 host:port 最多上报的路径前缀应用/隐藏端点候选数（0=关闭路径画像）。
	MaxPathApps int
	// Threads 并发抓取线程数。
	Threads int
	// Timeout 单次抓取超时（秒）。
	Timeout int
	// Proxy 可选 HTTP 代理。
	Proxy string
	// CrawlAI 关联站点候选是否走服务端 AI 判定。
	CrawlAI bool
	// SensitiveAI 敏感信息候选是否走服务端 AI 提取。
	SensitiveAI bool
}

// Seed 一个待爬取的起始站点。
type Seed struct {
	// RootURL 归一化的站点根 URL（scheme://host:port）。
	RootURL string
	// IP 种子站点解析到的 IP，用于识别"同 IP 其他端口"的关联站点。
	IP string
}

// Stats 汇总一次爬取统计（用于日志/测试）。
type Stats struct {
	PagesFetched   int
	SitesReported  int
	SensitiveFound int
}

// emit 逐条上报 OutputMessage。
type emitFunc func(msg structs.OutputMessage)
