package egress

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	pb "github.com/P0lar1ght/argus/shared/proto/go/scan"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	MaxRouteDuration       = 120 * time.Second
	MaxConnectionsPerRoute = 32
	MaxBytesPerDirection   = 32 << 20
	MaxConcurrentPerAgent  = 8
	MaxFrameBytes          = 64 << 10
)

type RouteRequest struct {
	TenantID       string
	OperatorID     string
	AgentID        string
	NetworkTargets []string
	Timeout        time.Duration
}

type RouteSnapshot struct {
	RouteID         string    `json:"route_id"`
	TenantID        string    `json:"tenant_id,omitempty"`
	AgentID         string    `json:"agent_id"`
	NetworkTargets  []string  `json:"network_targets"`
	Status          string    `json:"status"`
	ConnectionCount int       `json:"connection_count"`
	BytesToAgent    int64     `json:"bytes_to_agent"`
	BytesFromAgent  int64     `json:"bytes_from_agent"`
	ExpiresAt       time.Time `json:"expires_at"`
	ErrorCode       string    `json:"error_code,omitempty"`
}

type streamPeer struct {
	agentID string
	send    chan *pb.EgressFrame
	done    chan struct{}
	stream  pb.AgentEgressService_EgressTunnelServer
}

type route struct {
	mu             sync.Mutex
	auditMu        sync.Mutex
	id             string
	tenantID       string
	operatorID     string
	agentID        string
	peer           *streamPeer
	targets        map[string]struct{}
	targetList     []string
	status         string
	errorCode      string
	expiresAt      time.Time
	claimedAt      *time.Time
	finishedAt     *time.Time
	connections    map[string]struct{}
	toAgentSeq     map[string]uint64
	fromAgentSeq   map[string]uint64
	agentClosed    map[string]bool
	closeNotify    chan struct{}
	resolvedIPs    map[string]struct{}
	bytesToAgent   int64
	bytesFromAgent int64
	fromAgent      chan *pb.EgressFrame
	done           chan struct{}
	doneOnce       sync.Once
	cleanupOnce    sync.Once
}

type Broker struct {
	mu     sync.RWMutex
	agents map[string]*streamPeer
	routes map[string]*route
}

func NewBroker() *Broker {
	return &Broker{agents: map[string]*streamPeer{}, routes: map[string]*route{}}
}

func (b *Broker) AgentOnline(agentID string) bool {
	b.mu.RLock()
	peer := b.agents[strings.TrimSpace(agentID)]
	b.mu.RUnlock()
	return peer != nil
}

func (b *Broker) DetachAgent(agentID, reason string) {
	agentID = strings.TrimSpace(agentID)
	b.mu.Lock()
	peer := b.agents[agentID]
	if peer != nil {
		delete(b.agents, agentID)
	}
	items := make([]*route, 0)
	for _, item := range b.routes {
		if item.agentID == agentID && !item.terminal() {
			items = append(items, item)
		}
	}
	b.mu.Unlock()
	for _, item := range items {
		item.finish("agent_session_revoked", reason)
		_ = b.persist(item)
		closeRouteConnections(peer, item)
	}
	if peer != nil {
		closePeer(peer)
	}
}

func (b *Broker) CreateRoute(ctx context.Context, request RouteRequest) (RouteSnapshot, error) {
	request.TenantID = strings.TrimSpace(request.TenantID)
	request.OperatorID = strings.TrimSpace(request.OperatorID)
	request.AgentID = strings.TrimSpace(request.AgentID)
	if request.TenantID == "" || request.OperatorID == "" || request.AgentID == "" {
		return RouteSnapshot{}, errors.New("tenant, operator, and agent are required")
	}
	if len(request.NetworkTargets) == 0 || len(request.NetworkTargets) > 64 {
		return RouteSnapshot{}, errors.New("network_targets must contain 1 to 64 exact targets")
	}
	targets := make(map[string]struct{}, len(request.NetworkTargets))
	list := make([]string, 0, len(request.NetworkTargets))
	for _, raw := range request.NetworkTargets {
		normalized, err := normalizeTarget(raw)
		if err != nil {
			return RouteSnapshot{}, err
		}
		if _, exists := targets[normalized]; exists {
			return RouteSnapshot{}, errors.New("network target is duplicated")
		}
		targets[normalized] = struct{}{}
		list = append(list, normalized)
	}
	duration := request.Timeout
	if duration <= 0 || duration > MaxRouteDuration {
		duration = MaxRouteDuration
	}
	now := time.Now().UTC()
	item := &route{
		id: newRouteID(), tenantID: request.TenantID, operatorID: request.OperatorID,
		agentID: request.AgentID, targets: targets, targetList: list,
		status: "issued", expiresAt: now.Add(duration), connections: map[string]struct{}{},
		toAgentSeq: map[string]uint64{}, fromAgentSeq: map[string]uint64{}, agentClosed: map[string]bool{}, closeNotify: make(chan struct{}, 1),
		resolvedIPs: map[string]struct{}{}, fromAgent: make(chan *pb.EgressFrame, 128), done: make(chan struct{}),
	}
	b.mu.Lock()
	peer := b.agents[request.AgentID]
	active := 0
	for _, existing := range b.routes {
		if existing.agentID == request.AgentID && !existing.terminal() {
			active++
		}
	}
	if peer == nil {
		b.mu.Unlock()
		return RouteSnapshot{}, errors.New("Agent Egress Unavailable: agent tunnel is offline")
	}
	if active >= MaxConcurrentPerAgent {
		b.mu.Unlock()
		return RouteSnapshot{}, fmt.Errorf("Agent Egress Unavailable: agent route budget exceeds %d", MaxConcurrentPerAgent)
	}
	item.peer = peer
	b.routes[item.id] = item
	b.mu.Unlock()

	targetJSON, _ := json.Marshal(list)
	audit := db.ExpEgressAudit{RouteID: item.id, TenantID: item.tenantID, OperatorID: item.operatorID, AgentID: item.agentID, Targets: string(targetJSON), ResolvedIPs: "[]", Status: item.status, IssuedAt: now, ExpiresAt: item.expiresAt}
	if db.DB != nil {
		if err := db.DB.WithContext(ctx).Create(&audit).Error; err != nil {
			b.mu.Lock()
			delete(b.routes, item.id)
			b.mu.Unlock()
			return RouteSnapshot{}, fmt.Errorf("persist egress route audit: %w", err)
		}
	}
	go b.expire(item)
	return item.snapshot(), nil
}

func (b *Broker) Revoke(tenantID, routeID, reason string) (RouteSnapshot, error) {
	b.mu.RLock()
	item := b.routes[strings.TrimSpace(routeID)]
	b.mu.RUnlock()
	if item == nil || item.tenantID != strings.TrimSpace(tenantID) {
		return RouteSnapshot{}, errors.New("egress route not found")
	}
	item.finish("canceled", reason)
	_ = b.persist(item)
	return item.snapshot(), nil
}

func (b *Broker) AttachAgent(agentID string, stream pb.AgentEgressService_EgressTunnelServer) error {
	return b.AttachAgentWithExpiry(agentID, nil, stream)
}

func (b *Broker) AttachAgentWithExpiry(agentID string, expiresAt *time.Time, stream pb.AgentEgressService_EgressTunnelServer) error {
	peer := &streamPeer{agentID: agentID, send: make(chan *pb.EgressFrame, 128), done: make(chan struct{}), stream: stream}
	if err := stream.Send(&pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_HELLO_ACK, AgentId: agentID}); err != nil {
		return err
	}
	b.mu.Lock()
	old := b.agents[agentID]
	b.agents[agentID] = peer
	b.mu.Unlock()
	if old != nil {
		b.terminateRoutesForPeer(old, "agent_tunnel_replaced")
		closePeer(old)
	}
	if expiresAt != nil {
		go b.expirePeer(agentID, peer, *expiresAt)
	}
	defer func() {
		b.mu.Lock()
		current := b.agents[agentID] == peer
		if current {
			delete(b.agents, agentID)
		}
		if current {
			for _, item := range b.routes {
				if item.agentID == agentID && !item.terminal() {
					item.finish("agent_disconnected", "agent_disconnected")
					_ = b.persist(item)
				}
			}
		}
		b.mu.Unlock()
		closePeer(peer)
	}()

	sendErr := make(chan error, 1)
	go func() {
		for {
			select {
			case frame := <-peer.send:
				if err := stream.Send(frame); err != nil {
					sendErr <- err
					return
				}
			case <-peer.done:
				sendErr <- io.EOF
				return
			case <-stream.Context().Done():
				sendErr <- stream.Context().Err()
				return
			}
		}
	}()
	type receiveResult struct {
		frame *pb.EgressFrame
		err   error
	}
	received := make(chan receiveResult, 1)
	go func() {
		for {
			frame, recvErr := stream.Recv()
			select {
			case received <- receiveResult{frame: frame, err: recvErr}:
			case <-stream.Context().Done():
				return
			}
			if recvErr != nil {
				return
			}
		}
	}()
	for {
		var frame *pb.EgressFrame
		var err error
		select {
		case result := <-received:
			frame, err = result.frame, result.err
		case err = <-sendErr:
			return err
		case <-peer.done:
			return io.EOF
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
		if err != nil {
			return err
		}
		if err := validateFrame(frame); err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		if frame.GetKind() == pb.EgressFrameKind_EGRESS_FRAME_PING {
			select {
			case peer.send <- &pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_PONG}:
			default:
				return status.Error(codes.ResourceExhausted, "agent egress send queue is full")
			}
			continue
		}
		b.mu.RLock()
		item := b.routes[frame.GetRouteId()]
		b.mu.RUnlock()
		if item == nil || item.agentID != agentID || item.peer != peer {
			continue
		}
		terminalClose := item.terminal() && frame.GetKind() == pb.EgressFrameKind_EGRESS_FRAME_CLOSE
		if item.terminal() && !terminalClose {
			continue
		}
		if err := item.validateConnectionFrame(frame, false); err != nil {
			item.finish("protocol_error", "invalid_agent_frame")
			_ = b.persist(item)
			continue
		}
		if frame.GetKind() == pb.EgressFrameKind_EGRESS_FRAME_CLOSE {
			item.noteAgentClosed(frame.GetConnectionId())
			if terminalClose {
				continue
			}
		}
		if len(frame.GetPayload()) > 0 {
			item.mu.Lock()
			item.bytesFromAgent += int64(len(frame.GetPayload()))
			over := item.bytesFromAgent > MaxBytesPerDirection
			item.mu.Unlock()
			if over {
				item.finish("budget_exceeded", "download_budget_exceeded")
				_ = b.persist(item)
				continue
			}
		}
		if frame.GetResolvedIp() != "" {
			item.mu.Lock()
			item.resolvedIPs[frame.GetResolvedIp()] = struct{}{}
			item.mu.Unlock()
		}
		select {
		case item.fromAgent <- frame:
		default:
			item.finish("backpressure", "gateway_receive_queue_full")
			_ = b.persist(item)
		}
		select {
		case err := <-sendErr:
			return err
		default:
		}
	}
}

func (b *Broker) expirePeer(agentID string, peer *streamPeer, deadline time.Time) {
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-peer.done:
		return
	}
	b.mu.Lock()
	if b.agents[agentID] != peer {
		b.mu.Unlock()
		return
	}
	delete(b.agents, agentID)
	b.mu.Unlock()
	b.terminateRoutesForPeer(peer, "agent_session_expired")
	closePeer(peer)
}

func (b *Broker) terminateRoutesForPeer(peer *streamPeer, reason string) {
	b.mu.RLock()
	items := make([]*route, 0)
	for _, item := range b.routes {
		if item.peer == peer && !item.terminal() {
			items = append(items, item)
		}
	}
	b.mu.RUnlock()
	for _, item := range items {
		item.finish("agent_disconnected", reason)
		_ = b.persist(item)
		closeRouteConnections(peer, item)
	}
}

func (b *Broker) Relay(stream pb.YakshaEgressGateway_RelayServer) (returnErr error) {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	if first.GetKind() != pb.EgressFrameKind_EGRESS_FRAME_HELLO || strings.TrimSpace(first.GetRouteId()) == "" {
		return status.Error(codes.InvalidArgument, "first gateway frame must be HELLO with route_id")
	}
	b.mu.RLock()
	item := b.routes[first.GetRouteId()]
	peer := (*streamPeer)(nil)
	if item != nil && b.agents[item.agentID] == item.peer {
		peer = item.peer
	}
	b.mu.RUnlock()
	if item == nil || peer == nil {
		return status.Error(codes.Unavailable, "Agent Egress Unavailable")
	}
	item.mu.Lock()
	if item.status != "issued" || time.Now().After(item.expiresAt) {
		item.mu.Unlock()
		return status.Error(codes.FailedPrecondition, "egress route is expired or already claimed")
	}
	now := time.Now().UTC()
	item.status, item.claimedAt = "active", &now
	item.mu.Unlock()
	if err := b.persist(item); err != nil {
		item.finish("audit_failed", "audit_persist_failed")
		return status.Error(codes.Unavailable, "egress audit unavailable")
	}
	if item.terminal() {
		return status.Error(codes.Canceled, "egress route became terminal before activation")
	}
	var gatewaySendMu sync.Mutex
	sendGateway := func(frame *pb.EgressFrame) error {
		gatewaySendMu.Lock()
		defer gatewaySendMu.Unlock()
		return stream.Send(frame)
	}
	if err := sendGateway(&pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_HELLO_ACK, RouteId: item.id, AgentId: item.agentID}); err != nil {
		return err
	}

	forwardErr := make(chan error, 1)
	go func() {
		for {
			select {
			case frame := <-item.fromAgent:
				if err := sendGateway(frame); err != nil {
					forwardErr <- err
					return
				}
			case <-item.done:
				forwardErr <- io.EOF
				return
			case <-stream.Context().Done():
				forwardErr <- stream.Context().Err()
				return
			}
		}
	}()
	defer func() {
		if !item.terminal() {
			state, code := "completed", ""
			if returnErr != nil {
				state, code = "gateway_disconnected", "gateway_disconnected"
			}
			item.finish(state, code)
			_ = b.persist(item)
		}
		closeRouteConnections(peer, item)
	}()
	type receiveResult struct {
		frame *pb.EgressFrame
		err   error
	}
	received := make(chan receiveResult, 1)
	go func() {
		for {
			frame, recvErr := stream.Recv()
			select {
			case received <- receiveResult{frame: frame, err: recvErr}:
			case <-stream.Context().Done():
				return
			}
			if recvErr != nil {
				return
			}
		}
	}()
	for {
		var frame *pb.EgressFrame
		var recvErr error
		select {
		case result := <-received:
			frame, recvErr = result.frame, result.err
		case err := <-forwardErr:
			return err
		case <-item.done:
			return status.Error(codes.Canceled, "egress route is terminal")
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
		if recvErr != nil {
			if recvErr == io.EOF {
				return nil
			}
			item.finish("gateway_disconnected", "gateway_disconnected")
			return recvErr
		}
		if frame.GetRouteId() == "" {
			frame.RouteId = item.id
		}
		if frame.GetRouteId() != item.id {
			return status.Error(codes.PermissionDenied, "frame route_id does not match claimed route")
		}
		if err := validateFrame(frame); err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		if frame.GetKind() == pb.EgressFrameKind_EGRESS_FRAME_OPEN {
			if err := item.authorizeOpen(frame); err != nil {
				_ = sendGateway(&pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_ERROR, RouteId: item.id, ConnectionId: frame.GetConnectionId(), ErrorCode: "target_denied", ErrorMessage: err.Error()})
				continue
			}
		} else if err := item.validateConnectionFrame(frame, true); err != nil {
			item.finish("protocol_error", "invalid_gateway_frame")
			return status.Error(codes.InvalidArgument, err.Error())
		}
		if len(frame.GetPayload()) > 0 {
			item.mu.Lock()
			item.bytesToAgent += int64(len(frame.GetPayload()))
			over := item.bytesToAgent > MaxBytesPerDirection
			item.mu.Unlock()
			if over {
				item.finish("budget_exceeded", "upload_budget_exceeded")
				return status.Error(codes.ResourceExhausted, "route upload budget exceeded")
			}
		}
		select {
		case peer.send <- frame:
		case <-peer.done:
			return status.Error(codes.Unavailable, "Agent Egress Unavailable")
		case <-stream.Context().Done():
			return stream.Context().Err()
		default:
			item.finish("backpressure", "agent_send_queue_full")
			return status.Error(codes.ResourceExhausted, "agent egress send queue is full")
		}
	}
}

func closeRouteConnections(peer *streamPeer, item *route) {
	if peer == nil || item == nil {
		return
	}
	item.cleanupOnce.Do(func() { closeRouteConnectionsOnce(peer, item) })
}

func closeRouteConnectionsOnce(peer *streamPeer, item *route) {
	item.mu.Lock()
	ids := make([]string, 0, len(item.connections))
	for id := range item.connections {
		ids = append(ids, id)
	}
	item.mu.Unlock()
	for _, id := range ids {
		timer := time.NewTimer(time.Second)
		select {
		case peer.send <- &pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_CLOSE, RouteId: item.id, ConnectionId: id}:
			_ = timer.Stop()
		case <-peer.done:
			_ = timer.Stop()
			return
		case <-timer.C:
			// The protocol has no close acknowledgement. If the ordered control
			// queue cannot accept cleanup, tear down the tunnel so the Agent's
			// stream cleanup closes every socket instead of leaving one alive.
			closePeer(peer)
			return
		}
		if !waitAgentClosed(peer, item, id, time.Second) {
			closePeer(peer)
			return
		}
	}
}

func waitAgentClosed(peer *streamPeer, item *route, connectionID string, timeout time.Duration) bool {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		item.mu.Lock()
		closed := item.agentClosed[connectionID]
		item.mu.Unlock()
		if closed {
			return true
		}
		select {
		case <-item.closeNotify:
		case <-peer.done:
			return false
		case <-timer.C:
			return false
		}
	}
}

func (r *route) noteAgentClosed(connectionID string) {
	r.mu.Lock()
	r.agentClosed[connectionID] = true
	r.mu.Unlock()
	select {
	case r.closeNotify <- struct{}{}:
	default:
	}
}

// ReconcileStaleAudits records that in-memory routes cannot survive a Server
// restart. It is intentionally idempotent and never attempts to revive them.
func ReconcileStaleAudits(ctx context.Context) error {
	if db.DB == nil {
		return nil
	}
	now := time.Now().UTC()
	return db.DB.WithContext(ctx).Model(&db.ExpEgressAudit{}).
		Where("status IN ?", []string{"issued", "active"}).
		Updates(map[string]any{
			"status":      "aborted",
			"error_code":  "server_restarted",
			"finished_at": now,
		}).Error
}

func (r *route) authorizeOpen(frame *pb.EgressFrame) error {
	if frame.GetConnectionId() == "" || frame.GetPort() < 1 || frame.GetPort() > 65535 {
		return errors.New("connection_id and valid port are required")
	}
	target, err := normalizeTarget(fmt.Sprintf("%s://%s:%d", frame.GetProtocol(), frame.GetHost(), frame.GetPort()))
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.targets[target]; !ok {
		return errors.New("network target is not authorized")
	}
	if _, exists := r.connections[frame.GetConnectionId()]; exists {
		return errors.New("connection_id was already used")
	}
	if len(r.connections) >= MaxConnectionsPerRoute {
		return fmt.Errorf("route connection budget exceeds %d", MaxConnectionsPerRoute)
	}
	r.connections[frame.GetConnectionId()] = struct{}{}
	return nil
}

func (r *route) validateConnectionFrame(frame *pb.EgressFrame, toAgent bool) error {
	switch frame.GetKind() {
	case pb.EgressFrameKind_EGRESS_FRAME_DATA, pb.EgressFrameKind_EGRESS_FRAME_HALF_CLOSE, pb.EgressFrameKind_EGRESS_FRAME_CLOSE, pb.EgressFrameKind_EGRESS_FRAME_ERROR, pb.EgressFrameKind_EGRESS_FRAME_OPEN_RESULT:
	default:
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.connections[frame.GetConnectionId()]; !exists {
		return errors.New("connection_id is not open on this route")
	}
	if frame.GetKind() != pb.EgressFrameKind_EGRESS_FRAME_DATA {
		return nil
	}
	sequences := r.fromAgentSeq
	if toAgent {
		sequences = r.toAgentSeq
	}
	expected := sequences[frame.GetConnectionId()] + 1
	if frame.GetSequence() != expected {
		return fmt.Errorf("connection data sequence is %d, want %d", frame.GetSequence(), expected)
	}
	sequences[frame.GetConnectionId()] = expected
	return nil
}

func (r *route) terminal() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.status != "issued" && r.status != "active"
}

func (r *route) finish(state, code string) {
	r.doneOnce.Do(func() {
		r.mu.Lock()
		now := time.Now().UTC()
		r.status, r.errorCode, r.finishedAt = state, code, &now
		r.mu.Unlock()
		close(r.done)
	})
}

func (r *route) snapshot() RouteSnapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	return RouteSnapshot{RouteID: r.id, TenantID: r.tenantID, AgentID: r.agentID, NetworkTargets: append([]string(nil), r.targetList...), Status: r.status, ConnectionCount: len(r.connections), BytesToAgent: r.bytesToAgent, BytesFromAgent: r.bytesFromAgent, ExpiresAt: r.expiresAt, ErrorCode: r.errorCode}
}

func (b *Broker) expire(r *route) {
	timer := time.NewTimer(time.Until(r.expiresAt))
	defer timer.Stop()
	select {
	case <-timer.C:
		r.finish("expired", "deadline_exceeded")
		_ = b.persist(r)
	case <-r.done:
	}
	cleanup := time.NewTimer(5 * time.Minute)
	defer cleanup.Stop()
	<-cleanup.C
	b.mu.Lock()
	if b.routes[r.id] == r {
		delete(b.routes, r.id)
	}
	b.mu.Unlock()
}

func (b *Broker) persist(r *route) error {
	if db.DB == nil {
		return nil
	}
	r.auditMu.Lock()
	defer r.auditMu.Unlock()
	r.mu.Lock()
	resolved := make([]string, 0, len(r.resolvedIPs))
	for ip := range r.resolvedIPs {
		resolved = append(resolved, ip)
	}
	resolvedJSON, _ := json.Marshal(resolved)
	updates := map[string]any{"status": r.status, "error_code": r.errorCode, "connection_count": len(r.connections), "bytes_to_agent": r.bytesToAgent, "bytes_from_agent": r.bytesFromAgent, "resolved_ips": string(resolvedJSON), "claimed_at": r.claimedAt, "finished_at": r.finishedAt}
	r.mu.Unlock()
	result := db.DB.Model(&db.ExpEgressAudit{}).Where("route_id = ?", r.id).Updates(updates)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return fmt.Errorf("egress audit row is unavailable")
	}
	return nil
}

func normalizeTarget(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.User != nil || parsed.Hostname() == "" || parsed.Port() == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("network target must be an exact scheme://host:port origin")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" && scheme != "tcp" {
		return "", errors.New("network target has unsupported scheme")
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 {
		return "", errors.New("network target has invalid port")
	}
	return fmt.Sprintf("%s://%s:%d", scheme, strings.ToLower(strings.TrimSuffix(parsed.Hostname(), ".")), port), nil
}

func validateFrame(frame *pb.EgressFrame) error {
	if frame == nil || frame.GetKind() == pb.EgressFrameKind_EGRESS_FRAME_UNSPECIFIED {
		return errors.New("egress frame kind is required")
	}
	if len(frame.GetPayload()) > MaxFrameBytes {
		return fmt.Errorf("egress frame exceeds %d bytes", MaxFrameBytes)
	}
	return nil
}

func newRouteID() string {
	raw := make([]byte, 16)
	_, _ = rand.Read(raw)
	return "er_" + hex.EncodeToString(raw)
}

func closePeer(peer *streamPeer) {
	select {
	case <-peer.done:
	default:
		close(peer.done)
	}
}

func ForbiddenIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	for _, raw := range []string{"169.254.169.254", "100.100.100.200", "192.0.0.192", "fd00:ec2::254"} {
		if ip.Equal(net.ParseIP(raw)) {
			return true
		}
	}
	return false
}
