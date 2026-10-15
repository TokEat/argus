package portscan

import (
	"fmt"
	"net"
	"reflect"
	"sort"
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
	got := ScanTCP([]string{"127.0.0.1"}, fmt.Sprintf("%d,%d", p1, p2), 2, 8, 300, false, false, 0, func(msg ddout.OutputMessage) {
		hits = append(hits, msg)
	})
	if len(hits) != 1 || hits[0].Type != "IPAlive" || hits[0].IP != "127.0.0.1" {
		t.Fatalf("liveness emits = %#v", hits)
	}
	if len(got) != 1 {
		t.Fatalf("liveness results = %v", got)
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
