// Package discovery 主机发现：同网段 ARP，其余 ICMP，ICMP 全空再 TCP。
package discovery

import (
	"github.com/TokEat/argus/scanner/common"
	"github.com/TokEat/argus/scanner/ddout"
)

// CheckLive ICMP 存活探测。
func CheckLive(ips []string, ping bool, emit func(ddout.OutputMessage)) []string {
	return common.CheckLive(ips, ping, emit)
}
