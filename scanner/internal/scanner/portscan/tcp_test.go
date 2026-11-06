package portscan

import (
	"fmt"
	"net"
	"reflect"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/P0lar1ght/argus/scanner/ddout"
)

func TestScanTCPLivenessEmitsOncePerHost(t *testing.T) {
	ln1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln1.Close()
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln2.Close()
	p1 := ln1.Addr().(*net.TCPAddr).Port
	p2 := ln2.Addr().(*net.TCPAddr).Port

	var hits []ddout.OutputMessage
	var units int64
	got := ScanTCP([]string{"127.0.0.1"}, fmt.Sprintf("%d,%d", p1, p2), 2, 8, 300, false, false, 0, func(msg ddout.OutputMessage) {
		hits = append(hits, msg)
	}, func() { atomic.AddInt64(&units, 1) })
	if len(hits) != 1 || hits[0].Type != "IPAlive" || hits[0].IP != "127.0.0.1" {
		t.Fatalf("liveness emits = %#v", hits)
	}
	if len(got) != 1 {
		t.Fatalf("liveness results = %v", got)
	}
	// 单元计数 = ips×ports = 1×2 = 2（每个 addr 恰被消费一次，含 backlist 跳过的）。
	if units != 2 {
		t.Fatalf("onUnit count = %d, want 2 (ips×ports)", units)
	}
}

func TestScanTCPBoundedQueueLargeCrossProduct(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	openPort := ln.Addr().(*net.TCPAddr).Port

	// 叉积（500 ips × 25 ports = 12500）远超 scanQueueCap(4096)：
	// 验证收窄 channel 后仍能完成、找到开放端口且结果数正确（无重复/丢失）。
	// 探测端口取非常用高端口段，避开本机可能在监听的端口（如 22）。
	ips := make([]string, 0, 500)
	for i := 0; i < 500; i++ {
		ips = append(ips, fmt.Sprintf("127.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff))
	}
	if ips[1] != "127.0.0.1" {
		t.Fatalf("fixture should include 127.0.0.1, got %s", ips[1])
	}
	ports := fmt.Sprintf("47813-47836,%d", openPort)
	var units int64
	got := ScanTCP(ips, ports, 2, 64, 300, false, false, 0, func(ddout.OutputMessage) {}, func() { atomic.AddInt64(&units, 1) })
	want := fmt.Sprintf("127.0.0.1:%d", openPort)
	if len(got) != 1 || got[0] != want {
		t.Fatalf("large cross product results = %v, want [%s]", got, want)
	}
	// 单元计数应精确收敛到叉积：500 ips × (24 个探测端口 + 1 开放端口) = 12500，
	// 证明每个 addr 恰被消费一次（原子计数，无丢失/重复）。
	if want := int64(500 * 25); units != want {
		t.Fatalf("onUnit count = %d, want %d (ips×ports)", units, want)
	}
}

func TestRemoveFirewall(t *testing.T) {
	got := RemoveFirewall([]string{
		"10.0.0.1:80",
		"10.0.0.1:443",
		"10.0.0.2:22",
		"10.0.0.2:22",
	}, 2)
	sort.Strings(got)

	want := []string{"10.0.0.2:22"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected firewall filtering: want=%v got=%v", want, got)
	}
}

func TestDetermineConnectTimeout(t *testing.T) {
	cases := []struct {
		ip         string
		configured int
		want       time.Duration
	}{
		{ip: "10.120.0.1", configured: 6, want: 1500 * time.Millisecond},
		{ip: "192.168.1.1", configured: 6, want: 1500 * time.Millisecond},
		{ip: "127.0.0.1", configured: 6, want: 1500 * time.Millisecond},
		{ip: "8.8.8.8", configured: 6, want: 6 * time.Second},
		{ip: "10.120.0.1", configured: 2, want: 2 * time.Second},
		{ip: "8.8.8.8", configured: 2, want: 2 * time.Second},
		{ip: "10.120.0.1", configured: 0, want: 1500 * time.Millisecond},
	}

	for _, tc := range cases {
		got := determineConnectTimeout(tc.ip, tc.configured)
		if got != tc.want {
			t.Errorf("determineConnectTimeout(%s, %d) = %v; want %v", tc.ip, tc.configured, got, tc.want)
		}
	}
}
