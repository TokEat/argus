package main

import (
	"net"
	"regexp"
	"testing"
)

func hw(s string) net.HardwareAddr {
	mac, _ := net.ParseMAC(s)
	return mac
}

func TestSelectMACsSkipsLoopbackVirtualAndZero(t *testing.T) {
	ifaces := []net.Interface{
		{Name: "lo", Flags: net.FlagUp | net.FlagLoopback, HardwareAddr: hw("00:00:00:00:00:00")},
		{Name: "eth0", Flags: net.FlagUp, HardwareAddr: hw("aa:bb:cc:dd:ee:01")},
		{Name: "eth1", Flags: net.FlagUp, HardwareAddr: hw("aa:bb:cc:dd:ee:02")},
		{Name: "docker0", Flags: net.FlagUp, HardwareAddr: hw("02:42:0a:00:00:01")},
		{Name: "veth123", Flags: net.FlagUp, HardwareAddr: hw("aa:bb:cc:dd:ee:03")},
		{Name: "br-9f", Flags: net.FlagUp, HardwareAddr: hw("aa:bb:cc:dd:ee:04")},
		{Name: "bad0", Flags: net.FlagUp, HardwareAddr: hw("00:00:00")},
	}
	got := selectMACs(ifaces)
	if len(got) != 2 {
		t.Fatalf("want 2 MACs, got %v", got)
	}
	if got[0] != "aa:bb:cc:dd:ee:01" || got[1] != "aa:bb:cc:dd:ee:02" {
		t.Fatalf("unexpected selection/order: %v", got)
	}
}

func TestSelectMACsSortsRegardlessOfOrder(t *testing.T) {
	mk := func() []net.Interface {
		return []net.Interface{
			{Name: "z", Flags: net.FlagUp, HardwareAddr: hw("aa:bb:cc:dd:ee:02")},
			{Name: "a", Flags: net.FlagUp, HardwareAddr: hw("aa:bb:cc:dd:ee:01")},
		}
	}
	if a, b := selectMACs(mk()), selectMACs(mk()); len(a) != len(b) || a[0] != b[0] || a[1] != b[1] {
		t.Fatalf("order not normalized: %v vs %v", a, b)
	}
}

func TestAgentIDFromParts(t *testing.T) {
	pat := regexp.MustCompile(`^agent-web-[0-9a-f]{12}$`)
	id := agentIDFromParts("web", []string{"aa:bb:cc:dd:ee:01"})
	if !pat.MatchString(id) {
		t.Fatalf("unexpected id format: %s", id)
	}
	if again := agentIDFromParts("web", []string{"aa:bb:cc:dd:ee:01"}); again != id {
		t.Fatalf("not deterministic: %s vs %s", again, id)
	}
	if diff := agentIDFromParts("web", []string{"aa:bb:cc:dd:ee:02"}); diff == id {
		t.Fatalf("MAC change must alter id, got same %s", diff)
	}
	if empty := agentIDFromParts("", []string{"aa:bb:cc:dd:ee:01"}); empty[:6] != "agent-" {
		t.Fatalf("empty hostname fallback failed: %s", empty)
	}
}

func TestStableAgentIDSources(t *testing.T) {
	id, source := stableAgentID("testnode")
	if id == "" {
		t.Skip("no MAC and no machine-id in this environment")
	}
	if source != "MAC address" && source != "machine-id" {
		t.Fatalf("unexpected source: %s", source)
	}
	if again, _ := stableAgentID("testnode"); again != id {
		t.Fatalf("stableAgentID not deterministic: %s vs %s", again, id)
	}
	t.Logf("id=%s source=%s", id, source)
}
