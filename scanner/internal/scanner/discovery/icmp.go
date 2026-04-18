// Package discovery 主机发现模块。
// 桥接层：底层调用 common 包的原始实现。
package discovery

import (
	"dddd/scanner/common"
)

// CheckLive ICMP 存活探测。
// 桥接 common.CheckLive()
func CheckLive(ips []string, ping bool) []string {
	return common.CheckLive(ips, ping)
}
