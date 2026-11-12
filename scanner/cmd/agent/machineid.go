package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
)

// virtualIfacePrefixes 是容器/桥接/隧道类虚拟网卡的常见名前缀，
// 这类网卡的 MAC 多为每次启动随机生成，必须排除，否则 ID 仍会漂移。
var virtualIfacePrefixes = []string{
	"lo", "docker", "veth", "br-", "virbr", "kube", "flannel", "cni",
	"tun", "tap", "wg", "dummy", "ifb", "gre", "erspan",
}

func isVirtualIface(name string) bool {
	name = strings.ToLower(name)
	for _, p := range virtualIfacePrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func isUsableMAC(hw net.HardwareAddr) bool {
	if len(hw) < 6 {
		return false
	}
	for _, b := range hw {
		if b != 0 {
			return true
		}
	}
	return false
}

// selectMACs 返回候选物理网卡 MAC 的排序去重列表。
// 排序是为了消除网卡枚举顺序差异，保证重启后计算结果一致。
func selectMACs(ifaces []net.Interface) []string {
	var macs []string
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		if isVirtualIface(ifi.Name) || !isUsableMAC(ifi.HardwareAddr) {
			continue
		}
		macs = append(macs, ifi.HardwareAddr.String())
	}
	sort.Strings(macs)
	return macs
}

// agentIDFromParts 用 hostname + MAC 集合的哈希构造稳定 ID，形如 agent-<host>-<12位hex>。
// 哈希不暴露原始 MAC；MAC 集合变化（如插拔网卡）才会改变 ID。
func agentIDFromParts(hostname string, macs []string) string {
	sum := sha256.Sum256([]byte(strings.Join(macs, ",")))
	if hostname == "" {
		hostname = "node"
	}
	return fmt.Sprintf("agent-%s-%s", hostname, hex.EncodeToString(sum[:])[:12])
}

// stableAgentID 生成跨重启稳定的 agent ID。
// 优先级：物理网卡 MAC 集合 → /etc/machine-id；都拿不到返回空串，由调用方兜底。
func stableAgentID(hostname string) (id, source string) {
	ifaces, err := net.Interfaces()
	if err == nil {
		if macs := selectMACs(ifaces); len(macs) > 0 {
			return agentIDFromParts(hostname, macs), "MAC address"
		}
	}
	if b, err := os.ReadFile("/etc/machine-id"); err == nil {
		if mid := strings.TrimSpace(string(b)); mid != "" {
			return agentIDFromParts(hostname, []string{"machine-id:" + mid}), "machine-id"
		}
	}
	return "", ""
}
