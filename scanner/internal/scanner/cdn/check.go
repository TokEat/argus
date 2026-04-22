// Package cdn CDN 检测模块。
// 桥接层：底层调用 utils/cdn 包的原始实现。
package cdn

import (
	"dddd/scanner/ddout"
	utlcdn "dddd/scanner/utils/cdn"
	"sync"
)

// CheckCDNs 批量 CDN 检测。
func CheckCDNs(domains []string, threads int, ipDomainMap map[string][]string, ipDomainMapLock *sync.Mutex, emit func(ddout.OutputMessage)) (cdnDomains []string, cdnResults interface{}, ips []string) {
	return utlcdn.CheckCDNs(domains, threads, ipDomainMap, ipDomainMapLock, emit)
}
