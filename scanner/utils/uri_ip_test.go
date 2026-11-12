package utils

import (
	"net"
	"testing"
)

func TestIsLocalIP(t *testing.T) {
	if !IsLocalIP("192.168.1.5") || !IsLocalIP("10.0.0.1") || !IsLocalIP("127.0.0.1") {
		t.Fatal("RFC1918 and loopback must be local")
	}
	if IsLocalIP("8.8.8.8") || IsLocalIP("not-an-ip") {
		t.Fatal("public and invalid addresses must not be local")
	}
}

func TestTargetContainsIP(t *testing.T) {
	ip := net.ParseIP("10.3.130.95")
	cases := []struct {
		name   string
		target string
		want   bool
	}{
		{"cidr inside", "10.3.130.0/24", true},
		{"cidr outside", "10.3.131.0/24", false},
		{"large cidr inside", "10.0.0.0/8", true},
		{"range inside", "10.3.130.1-10.3.130.100", true},
		{"range shorthand tail", "10.3.130.1-100", true},
		{"range outside", "10.3.130.96-10.3.130.100", false},
		{"bare ip match", "10.3.130.95", true},
		{"bare ip mismatch", "10.3.130.96", false},
		{"domain not segment", "example.com", false},
		{"url not segment", "http://10.3.130.95:8080", false},
		{"empty", "", false},
		{"malformed cidr", "10.3.130.0/33", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := TargetContainsIP(tc.target, ip); got != tc.want {
				t.Fatalf("TargetContainsIP(%q, %v) = %v want %v", tc.target, ip, got, tc.want)
			}
		})
	}
	// nil / 非 IP 输入必须安全返回 false。
	if TargetContainsIP("10.3.130.0/24", nil) {
		t.Fatal("nil ip must not be contained")
	}
	if TargetContainsIP("10.3.130.0/24", net.ParseIP("not-an-ip")) {
		t.Fatal("unparseable ip must not be contained")
	}
}
