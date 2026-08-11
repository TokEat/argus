// Package discovery 主机发现模块。
// 桥接层：底层调用 common 包的原始实现。
package discovery

import (
	"github.com/P0lar1ght/argus/scanner/common"
	"github.com/P0lar1ght/argus/scanner/ddout"
)

// CheckLive ICMP 存活探测。
// 桥接 common.CheckLive()
func CheckLive(ips []string, ping bool, emit func(ddout.OutputMessage)) []string {
	return common.CheckLive(ips, ping, emit)
}
