package db

import "testing"

func TestScanNetworkZoneForTargetClassifiesPublicAndPrivateBoundaries(t *testing.T) {
	for _, test := range []struct {
		name    string
		agentID string
		tags    string
		target  string
		want    string
	}{
		{name: "public IPv4", agentID: "agent-a", target: "8.8.8.8", want: "public"},
		{name: "public CIDR", agentID: "agent-a", target: "8.8.8.0/24", want: "public"},
		{name: "public range", agentID: "agent-a", target: "8.8.8.8-8.8.8.10", want: "public"},
		{name: "public DNS without private zone", agentID: "agent-a", target: "https://example.com", want: "public"},
		{name: "private IPv4 tagged", agentID: "agent-a", tags: `{"network_zone":"Corp-A"}`, target: "10.0.0.1", want: "private:corp-a"},
		{name: "private URL tagged", agentID: "agent-a", tags: `{"network_zone":"Corp-A"}`, target: "http://192.168.1.10:8080", want: "private:corp-a"},
		{name: "carrier NAT tagged", agentID: "agent-a", tags: `{"network_zone":"Corp-A"}`, target: "100.64.0.1", want: "private:corp-a"},
		{name: "documentation range is not reusable as public", agentID: "agent-a", tags: `{"network_zone":"Corp-A"}`, target: "192.0.2.10", want: "private:corp-a"},
		{name: "private fallback", agentID: "agent-a", target: "10.0.0.1", want: "agent:agent-a"},
		{name: "reserved DNS fallback", agentID: "agent-a", target: "https://service.internal", want: "agent:agent-a"},
		{name: "split horizon uses zone", agentID: "agent-a", tags: `{"network_zone":"Corp-A"}`, target: "https://portal.example.com", want: "private:corp-a"},
		{name: "explicit public DNS scope", agentID: "agent-a", tags: `{"network_zone":"Corp-A","network_scope":"public"}`, target: "https://portal.example.com", want: "public"},
		{name: "public scope cannot promote private IP", agentID: "agent-a", tags: `{"network_zone":"Corp-A","network_scope":"public"}`, target: "10.0.0.1", want: "private:corp-a"},
		{name: "public scope cannot promote reserved DNS", agentID: "agent-a", tags: `{"network_zone":"Corp-A","network_scope":"public"}`, target: "https://service.internal", want: "private:corp-a"},
		{name: "explicit private DNS scope without label", agentID: "agent-a", tags: `{"network_scope":"private"}`, target: "https://portal.example.com", want: "agent:agent-a"},
		{name: "invalid tags fail closed", agentID: "agent-a", tags: `{`, target: "10.0.0.1", want: "agent:agent-a"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := scanNetworkZoneForTarget(test.agentID, test.tags, test.target); got != test.want {
				t.Fatalf("scanNetworkZoneForTarget(%q, %q, %q)=%q, want %q", test.agentID, test.tags, test.target, got, test.want)
			}
		})
	}
}

func TestScanNetworkZoneIsolationAndSharing(t *testing.T) {
	privateTarget := "10.0.0.8"
	if left, right := scanNetworkZoneForTarget("agent-a", `{"network_zone":"corp"}`, privateTarget), scanNetworkZoneForTarget("agent-b", `{"network_zone":"corp"}`, privateTarget); left != right || left != "private:corp" {
		t.Fatalf("same private zone did not share a boundary: %q/%q", left, right)
	}
	if left, right := scanNetworkZoneForTarget("agent-a", `{"network_zone":"corp-a"}`, privateTarget), scanNetworkZoneForTarget("agent-b", `{"network_zone":"corp-b"}`, privateTarget); left == right {
		t.Fatalf("different private zones were merged: %q", left)
	}
	if left, right := scanNetworkZoneForTarget("agent-a", `{}`, privateTarget), scanNetworkZoneForTarget("agent-b", `{}`, privateTarget); left == right {
		t.Fatalf("unlabelled private Agents were merged: %q", left)
	}
	if left, right := scanNetworkZoneForTarget("agent-a", `{}`, "8.8.8.8"), scanNetworkZoneForTarget("agent-b", `{}`, "8.8.8.8"); left != right || left != "public" {
		t.Fatalf("public targets did not share the public boundary: %q/%q", left, right)
	}
}
