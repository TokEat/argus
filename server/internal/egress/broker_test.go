package egress

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/TokEat/argus/server/internal/db"
	pb "github.com/TokEat/argus/shared/proto/go/scan"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func onlineTestBroker(agentID string) *Broker {
	b := NewBroker()
	b.agents[agentID] = &streamPeer{agentID: agentID, send: make(chan *pb.EgressFrame, 128), done: make(chan struct{})}
	return b
}

func TestCreateRouteBindsExactTargetsAndSingleTenant(t *testing.T) {
	b := onlineTestBroker("agent-a")
	snapshot, err := b.CreateRoute(context.Background(), RouteRequest{TenantID: "tenant-a", OperatorID: "7", AgentID: "agent-a", NetworkTargets: []string{"HTTPS://Example.Test:443"}, Timeout: time.Second})
	if err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}
	if snapshot.Status != "issued" || snapshot.AgentID != "agent-a" || snapshot.NetworkTargets[0] != "https://example.test:443" {
		t.Fatalf("unexpected route: %+v", snapshot)
	}
	if _, err := b.Revoke("tenant-b", snapshot.RouteID, "test"); err == nil {
		t.Fatal("cross-tenant revoke succeeded")
	}
	revoked, err := b.Revoke("tenant-a", snapshot.RouteID, "test")
	if err != nil || revoked.Status != "canceled" {
		t.Fatalf("revoke=%+v err=%v", revoked, err)
	}
}

func TestCreateRouteRequiresOnlineAgentAndRejectsTargetAmbiguity(t *testing.T) {
	_, err := NewBroker().CreateRoute(context.Background(), RouteRequest{TenantID: "t", OperatorID: "u", AgentID: "missing", NetworkTargets: []string{"tcp://example.test:80"}})
	if err == nil || !strings.Contains(err.Error(), "Unavailable") {
		t.Fatalf("offline error=%v", err)
	}
	b := onlineTestBroker("agent-a")
	for _, target := range []string{"https://example.test", "https://user@example.test:443", "https://example.test:443/path", "udp://example.test:53"} {
		if _, err := b.CreateRoute(context.Background(), RouteRequest{TenantID: "t", OperatorID: "u", AgentID: "agent-a", NetworkTargets: []string{target}}); err == nil {
			t.Fatalf("target %q was accepted", target)
		}
	}
}

func TestRouteConnectionBudgetAndExactAuthorization(t *testing.T) {
	b := onlineTestBroker("agent-a")
	snapshot, err := b.CreateRoute(context.Background(), RouteRequest{TenantID: "t", OperatorID: "u", AgentID: "agent-a", NetworkTargets: []string{"tcp://example.test:443"}})
	if err != nil {
		t.Fatal(err)
	}
	item := b.routes[snapshot.RouteID]
	for index := 0; index < MaxConnectionsPerRoute; index++ {
		frame := &pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_OPEN, ConnectionId: "c-" + string(rune('a'+index)), Host: "example.test", Port: 443, Protocol: "tcp"}
		if err := item.authorizeOpen(frame); err != nil {
			t.Fatalf("connection %d: %v", index, err)
		}
	}
	if err := item.authorizeOpen(&pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_OPEN, ConnectionId: "overflow", Host: "example.test", Port: 443, Protocol: "tcp"}); err == nil {
		t.Fatal("connection budget was not enforced")
	}
	if err := item.authorizeOpen(&pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_OPEN, ConnectionId: "denied", Host: "other.test", Port: 443, Protocol: "tcp"}); err == nil {
		t.Fatal("undeclared target was accepted")
	}
	if err := item.authorizeOpen(&pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_OPEN, ConnectionId: "c-a", Host: "example.test", Port: 443, Protocol: "tcp"}); err == nil {
		t.Fatal("reused connection id was accepted")
	}
}

func TestRouteRejectsUnknownConnectionsAndOutOfOrderData(t *testing.T) {
	b := onlineTestBroker("agent-a")
	snapshot, err := b.CreateRoute(context.Background(), RouteRequest{TenantID: "t", OperatorID: "u", AgentID: "agent-a", NetworkTargets: []string{"tcp://example.test:443"}})
	if err != nil {
		t.Fatal(err)
	}
	item := b.routes[snapshot.RouteID]
	if err := item.validateConnectionFrame(&pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_DATA, ConnectionId: "missing", Sequence: 1}, true); err == nil {
		t.Fatal("unknown connection was accepted")
	}
	if err := item.authorizeOpen(&pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_OPEN, ConnectionId: "c-1", Host: "example.test", Port: 443, Protocol: "tcp"}); err != nil {
		t.Fatal(err)
	}
	if err := item.validateConnectionFrame(&pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_DATA, ConnectionId: "c-1", Sequence: 2}, true); err == nil {
		t.Fatal("out-of-order sequence was accepted")
	}
	if err := item.validateConnectionFrame(&pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_DATA, ConnectionId: "c-1", Sequence: 1}, true); err != nil {
		t.Fatalf("first sequence: %v", err)
	}
	if err := item.validateConnectionFrame(&pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_DATA, ConnectionId: "c-1", Sequence: 1}, true); err == nil {
		t.Fatal("duplicate sequence was accepted")
	}
}

func TestForbiddenIPPolicy(t *testing.T) {
	for _, raw := range []string{"127.0.0.1", "0.0.0.0", "169.254.169.254", "100.100.100.200", "224.0.0.1", "fe80::1"} {
		if !ForbiddenIP(net.ParseIP(raw)) {
			t.Fatalf("%s was not forbidden", raw)
		}
	}
	for _, raw := range []string{"10.0.0.10", "192.168.1.10", "8.8.8.8"} {
		if ForbiddenIP(net.ParseIP(raw)) {
			t.Fatalf("%s was unexpectedly forbidden", raw)
		}
	}
}

func TestFrameLimit(t *testing.T) {
	if err := validateFrame(&pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_DATA, Payload: make([]byte, MaxFrameBytes+1)}); err == nil {
		t.Fatal("oversized frame accepted")
	}
}

func TestTunnelReplacementOnlyTerminatesRoutesBoundToOldPeer(t *testing.T) {
	b := onlineTestBroker("agent-a")
	old := b.agents["agent-a"]
	oldRoute, err := b.CreateRoute(context.Background(), RouteRequest{TenantID: "t", OperatorID: "u", AgentID: "agent-a", NetworkTargets: []string{"tcp://example.test:80"}})
	if err != nil {
		t.Fatal(err)
	}
	newPeer := &streamPeer{agentID: "agent-a", send: make(chan *pb.EgressFrame, 128), done: make(chan struct{})}
	b.mu.Lock()
	b.agents["agent-a"] = newPeer
	b.mu.Unlock()
	newRoute, err := b.CreateRoute(context.Background(), RouteRequest{TenantID: "t", OperatorID: "u", AgentID: "agent-a", NetworkTargets: []string{"tcp://example.test:80"}})
	if err != nil {
		t.Fatal(err)
	}
	b.terminateRoutesForPeer(old, "replaced")
	if got := b.routes[oldRoute.RouteID].snapshot().Status; got != "agent_disconnected" {
		t.Fatalf("old route status = %s", got)
	}
	if got := b.routes[newRoute.RouteID].snapshot().Status; got != "issued" {
		t.Fatalf("new route status = %s", got)
	}
}

func TestReconcileStaleAuditsAfterServerRestart(t *testing.T) {
	store, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AutoMigrate(&db.ExpEgressAudit{}); err != nil {
		t.Fatal(err)
	}
	previous := db.DB
	db.SetDB(store)
	t.Cleanup(func() { db.SetDB(previous) })
	now := time.Now().UTC()
	for index, state := range []string{"issued", "active", "completed"} {
		audit := db.ExpEgressAudit{RouteID: string(rune('a' + index)), TenantID: "t", OperatorID: "u", AgentID: "a", Targets: "[]", ResolvedIPs: "[]", Status: state, IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
		if err := store.Create(&audit).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := ReconcileStaleAudits(context.Background()); err != nil {
		t.Fatal(err)
	}
	var audits []db.ExpEgressAudit
	if err := store.Order("route_id").Find(&audits).Error; err != nil {
		t.Fatal(err)
	}
	if audits[0].Status != "aborted" || audits[0].ErrorCode != "server_restarted" || audits[0].FinishedAt == nil {
		t.Fatalf("issued audit not reconciled: %+v", audits[0])
	}
	if audits[1].Status != "aborted" || audits[2].Status != "completed" {
		t.Fatalf("unexpected reconciled states: %s, %s", audits[1].Status, audits[2].Status)
	}
}

func TestAgentSessionExpiryTerminatesBoundRoutes(t *testing.T) {
	b := onlineTestBroker("agent-a")
	peer := b.agents["agent-a"]
	snapshot, err := b.CreateRoute(context.Background(), RouteRequest{TenantID: "t", OperatorID: "u", AgentID: "agent-a", NetworkTargets: []string{"tcp://example.test:80"}})
	if err != nil {
		t.Fatal(err)
	}
	go b.expirePeer("agent-a", peer, time.Now().Add(10*time.Millisecond))
	select {
	case <-peer.done:
	case <-time.After(time.Second):
		t.Fatal("expired Agent peer remained attached")
	}
	if got := b.routes[snapshot.RouteID].snapshot(); got.Status != "agent_disconnected" || got.ErrorCode != "agent_session_expired" {
		t.Fatalf("expired route = %+v", got)
	}
}

func TestPersistRejectsMissingAuditRow(t *testing.T) {
	store, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AutoMigrate(&db.ExpEgressAudit{}); err != nil {
		t.Fatal(err)
	}
	previous := db.DB
	db.SetDB(store)
	t.Cleanup(func() { db.SetDB(previous) })
	item := &route{id: "missing", status: "active", resolvedIPs: map[string]struct{}{}, connections: map[string]struct{}{}}
	if err := NewBroker().persist(item); err == nil {
		t.Fatal("missing audit row was treated as persisted")
	}
}
