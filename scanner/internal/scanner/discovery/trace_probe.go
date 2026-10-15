package discovery

import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type hopReply struct {
	from    net.IP
	dest    net.IP
	ttl     int
	reached bool
}

type icmpHub struct {
	conn *icmp.PacketConn
	mu   sync.Mutex
	subs []chan hopReply
	done chan struct{}
}

var openTraceICMP = openTraceICMPSocket

func openTraceICMPSocket() (*icmp.PacketConn, error) {
	var last error
	for _, network := range []string{"ip4:icmp", "udp4"} {
		conn, err := icmp.ListenPacket(network, "0.0.0.0")
		if err == nil {
			return conn, nil
		}
		last = err
	}
	if last == nil {
		last = fmt.Errorf("no icmp listen network")
	}
	return nil, last
}

func (h *icmpHub) publish(r hopReply) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, sub := range h.subs {
		select {
		case sub <- r:
		default:
		}
	}
}

func (h *icmpHub) subscribe() (chan hopReply, func()) {
	ch := make(chan hopReply, 16)
	h.mu.Lock()
	h.subs = append(h.subs, ch)
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		out := h.subs[:0]
		for _, sub := range h.subs {
			if sub != ch {
				out = append(out, sub)
			}
		}
		h.subs = out
	}
}

func startICMPHub() (*icmpHub, func(), error) {
	conn, err := openTraceICMP()
	if err != nil {
		return nil, nil, err
	}
	hub := &icmpHub{conn: conn, done: make(chan struct{})}
	go func() {
		buf := make([]byte, 1500)
		for {
			select {
			case <-hub.done:
				return
			default:
			}
			_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, peer, err := conn.ReadFrom(buf)
			if err != nil || n == 0 || peer == nil {
				continue
			}
			from, dest, reached, ttl, ok := parseTraceICMP(peer.String(), buf[:n])
			if !ok {
				continue
			}
			hub.publish(hopReply{from: from, dest: dest, ttl: ttl, reached: reached})
		}
	}()
	return hub, func() {
		close(hub.done)
		_ = conn.Close()
	}, nil
}

func parseTraceICMP(peer string, payload []byte) (from, dest net.IP, reached bool, ttl int, ok bool) {
	from = parseIPv4(peer)
	if from == nil {
		host, _, _ := net.SplitHostPort(peer)
		from = parseIPv4(host)
	}
	msg, err := icmp.ParseMessage(1, payload)
	if err != nil || from == nil {
		return nil, nil, false, 0, false
	}
	switch body := msg.Body.(type) {
	case *icmp.TimeExceeded:
		dest = destFromInnerIPv4(body.Data)
		return from, dest, false, innerProbeTTL(body.Data), dest != nil
	case *icmp.DstUnreach:
		dest = destFromInnerIPv4(body.Data)
		return from, dest, true, innerProbeTTL(body.Data), dest != nil
	case *icmp.Echo:
		if msg.Type == ipv4.ICMPTypeEchoReply {
			return from, from, true, 0, true
		}
		return nil, nil, false, 0, false
	default:
		return nil, nil, false, 0, false
	}
}

func destFromInnerIPv4(data []byte) net.IP {
	if len(data) < 20 {
		return nil
	}
	return net.IPv4(data[16], data[17], data[18], data[19]).To4()
}

func innerProbeTTL(data []byte) int {
	if len(data) < 20 {
		return 0
	}
	ihl := int(data[0]&0x0f) * 4
	if ihl < 20 || len(data) < ihl {
		return 0
	}
	switch data[9] {
	case 17: // UDP dest port encodes TTL
		if len(data) < ihl+4 {
			return 0
		}
		dport := int(data[ihl+2])<<8 | int(data[ihl+3])
		if dport > traceUDPBase && dport <= traceUDPBase+maxTraceHops {
			return dport - traceUDPBase
		}
	case 1: // ICMP echo sequence is the TTL
		if len(data) < ihl+8 || data[ihl] != 8 {
			return 0
		}
		seq := int(data[ihl+6])<<8 | int(data[ihl+7])
		if seq >= 1 && seq <= maxTraceHops {
			return seq
		}
	}
	return 0
}

func traceOne(dest string, maxHops int, wait time.Duration, hub *icmpHub) Route {
	dstIP := parseIPv4(dest)
	route := Route{Dest: dest}
	if dstIP == nil {
		return route
	}
	replies, unsub := hub.subscribe()
	defer unsub()
	for ttl := 1; ttl <= maxHops; ttl++ {
		hop, reached := probeHop(replies, dstIP, ttl, wait, func() {
			_ = sendTraceUDP(dstIP, ttl)
			_ = sendTraceICMP(hub.conn, dstIP, ttl)
		})
		route.Hops = append(route.Hops, hop)
		// Silent or late middle hops stay "*"; only stop when the dest answers.
		if reached || hop == dest {
			if hop == "" {
				route.Hops[len(route.Hops)-1] = dest
			}
			break
		}
	}
	return route
}

func probeHop(replies <-chan hopReply, dest net.IP, ttl int, wait time.Duration, send func()) (hop string, reached bool) {
	if wait <= 0 {
		wait = 400 * time.Millisecond
	}
	slice := wait / time.Duration(traceProbesPerHop)
	if slice < 200*time.Millisecond {
		slice = 200 * time.Millisecond
	}
	for i := 0; i < traceProbesPerHop; i++ {
		send()
		hop, reached = waitHop(replies, dest, ttl, slice)
		if hop != "" || reached {
			return hop, reached
		}
	}
	return "", false
}

func waitHop(replies <-chan hopReply, dest net.IP, ttl int, wait time.Duration) (hop string, reached bool) {
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	for {
		select {
		case r := <-replies:
			if r.dest == nil || !r.dest.Equal(dest) {
				continue
			}
			if r.reached {
				if r.from != nil {
					return r.from.String(), true
				}
				return dest.String(), true
			}
			if r.ttl != ttl {
				continue
			}
			if r.from == nil {
				return "", false
			}
			return r.from.String(), r.from.Equal(dest)
		case <-deadline.C:
			return "", false
		}
	}
}

func sendTraceUDP(dest net.IP, ttl int) error {
	c, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return err
	}
	defer c.Close()
	if err := ipv4.NewPacketConn(c).SetTTL(ttl); err != nil {
		return err
	}
	_, err = c.WriteTo([]byte{0}, &net.UDPAddr{IP: dest, Port: traceUDPBase + ttl})
	return err
}

func sendTraceICMP(conn *icmp.PacketConn, dest net.IP, ttl int) error {
	if conn == nil || dest == nil {
		return nil
	}
	// *icmp.PacketConn is not net.Conn; ipv4.NewPacketConn panics on it.
	ip4 := conn.IPv4PacketConn()
	if ip4 == nil {
		return nil
	}
	if err := ip4.SetTTL(ttl); err != nil {
		return err
	}
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{ID: os.Getpid() & 0xffff, Seq: ttl, Data: []byte("argus-tr")},
	}
	payload, err := msg.Marshal(nil)
	if err != nil {
		return err
	}
	_, err = conn.WriteTo(payload, &net.IPAddr{IP: dest})
	return err
}
