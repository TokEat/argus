//go:build linux

package portscan

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	mrand "math/rand"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/TokEat/argus/scanner/ddout"
	"github.com/TokEat/argus/scanner/utils"
	"github.com/projectdiscovery/gologger"
	"golang.org/x/sys/unix"
)

const synProbeRetries = 1

// CanSYNScan reports whether this process can open a raw TCP socket
// (typically requires CAP_NET_RAW / root on Linux).
func CanSYNScan() bool {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_TCP)
	if err != nil {
		return false
	}
	_ = unix.Close(fd)
	return true
}

func scanSYNBuiltin(ips []string, ports string, rate int, emit func(ddout.OutputMessage)) []string {
	probePorts := ParsePort(ports)
	targets := filterIPv4(ips)
	if len(targets) == 0 || len(probePorts) == 0 {
		return nil
	}
	if rate <= 0 {
		rate = 1000
	}

	srcByDst, skipped := resolveSourceIPs(targets)
	if len(skipped) > 0 {
		sample := skipped
		if len(sample) > 5 {
			sample = sample[:5]
		}
		gologger.Error().Msgf("SYN scan: failed to resolve local source IP for %d target(s), skipping: %v", len(skipped), sample)
	}
	if len(srcByDst) == 0 {
		gologger.Error().Msg("SYN scan aborted: no routable IPv4 source address for any target")
		return nil
	}
	routable := make([]string, 0, len(srcByDst))
	for host := range srcByDst {
		routable = append(routable, host)
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_TCP)
	if err != nil {
		gologger.Error().Msgf("SYN scan: raw socket unavailable: %v", err)
		return nil
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		gologger.Error().Msgf("SYN scan: IP_HDRINCL: %v", err)
		return nil
	}
	tv := unix.NsecToTimeval(int64(200 * time.Millisecond))
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	var entropyBuf [8]byte
	if _, err := rand.Read(entropyBuf[:]); err != nil {
		gologger.Error().Msgf("SYN scan: entropy: %v", err)
		return nil
	}
	entropy := binary.LittleEndian.Uint64(entropyBuf[:])
	srcPort := synEphemeralPort()
	ttl := synSessionTTL()
	window := synSessionWindow()
	ipIDCounter := synRandomUint32()
	rng := mrand.New(mrand.NewSource(int64(synRandomUint32())<<32 | int64(synRandomUint32())))

	done := make(chan struct{})
	var (
		mu      sync.Mutex
		openSet = make(map[string]struct{})
		wgRX    sync.WaitGroup
	)

	wgRX.Add(1)
	go func() {
		defer wgRX.Done()
		buf := make([]byte, 65535)
		for {
			select {
			case <-done:
				return
			default:
			}
			n, _, err := unix.Recvfrom(fd, buf, 0)
			if err != nil || n <= 0 {
				continue
			}
			seg, ok := parseIPv4TCP(buf[:n])
			if !ok {
				continue
			}
			if seg.DstPort != srcPort {
				continue
			}
			if seg.Flags&tcpFlagSYN == 0 || seg.Flags&tcpFlagACK == 0 {
				continue
			}
			if seg.Flags&tcpFlagRST != 0 {
				continue
			}
			srcIP := srcByDst[seg.SrcIP.String()]
			if srcIP == nil || !seg.DstIP.Equal(srcIP) {
				continue
			}
			if !synCookieValid(seg.Ack, seg.SrcIP, srcIP, seg.SrcPort, srcPort, entropy) {
				continue
			}
			key := seg.SrcIP.String() + ":" + strconv.Itoa(int(seg.SrcPort))
			mu.Lock()
			_, seen := openSet[key]
			if !seen {
				openSet[key] = struct{}{}
			}
			mu.Unlock()
			if seen {
				continue
			}
			// Tear down half-open; bare RST (no MSS) looks like a stack abort, not a probe template.
			rst := buildIPv4TCP(tcpSegment{
				SrcIP:   srcIP,
				DstIP:   seg.SrcIP,
				SrcPort: srcPort,
				DstPort: seg.SrcPort,
				Seq:     seg.Ack,
				Ack:     seg.Seq + 1,
				Flags:   tcpFlagRST | tcpFlagACK,
				Window:  0,
			}, ttl, nextIPID(&ipIDCounter))
			if rst != nil {
				sa := &unix.SockaddrInet4{Port: 0}
				copy(sa.Addr[:], seg.SrcIP.To4())
				_ = unix.Sendto(fd, rst, 0, sa)
			}
			if emit != nil {
				emit(ddout.OutputMessage{
					Type: "PortScan",
					IP:   seg.SrcIP.String(),
					Port: strconv.Itoa(int(seg.SrcPort)),
				})
			}
		}
	}()

	probes := shuffleProbeOrder(routable, probePorts, rng)
	passes := 1 + synProbeRetries
	gologger.Info().Msgf("SYN scan rate=%d probes=%d targets=%d retries=%d", rate, len(probes), len(routable), synProbeRetries)
	pacer := newPacketPacer(rate)

	for attempt := 0; attempt < passes; attempt++ {
		order := probes
		if attempt > 0 {
			order = append([]synProbe(nil), probes...)
			rng.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
		}
		for _, pr := range order {
			key := pr.host + ":" + strconv.Itoa(pr.port)
			mu.Lock()
			_, alreadyOpen := openSet[key]
			mu.Unlock()
			if alreadyOpen {
				continue
			}

			pacer.wait()
			dst := net.ParseIP(pr.host).To4()
			src := srcByDst[pr.host]
			if dst == nil || src == nil {
				continue
			}
			seq := synCookieSeq(dst, src, uint16(pr.port), srcPort, entropy)
			pkt := buildIPv4TCP(tcpSegment{
				SrcIP:   src,
				DstIP:   dst,
				SrcPort: srcPort,
				DstPort: uint16(pr.port),
				Seq:     seq,
				Flags:   tcpFlagSYN,
				Window:  window,
				WithMSS: true,
			}, ttl, nextIPID(&ipIDCounter))
			if pkt == nil {
				continue
			}
			sa := &unix.SockaddrInet4{Port: 0}
			copy(sa.Addr[:], dst)
			if err := unix.Sendto(fd, pkt, 0, sa); err != nil {
				gologger.Warning().Msgf("SYN scan send %s:%d: %v", pr.host, pr.port, err)
			}
		}
	}

	time.Sleep(synRecvWaitJittered())
	close(done)
	wgRX.Wait()

	mu.Lock()
	results := make([]string, 0, len(openSet))
	for k := range openSet {
		results = append(results, k)
	}
	mu.Unlock()
	gologger.AuditTimeLogger("SYN scan done open=%d skipped_targets=%d", len(results), len(skipped))
	out := utils.RemoveDuplicateElement(results)
	if out == nil {
		out = []string{}
	}
	return out
}

func resolveSourceIPs(targets []string) (map[string]net.IP, []string) {
	srcByDst := make(map[string]net.IP, len(targets))
	var skipped []string
	for _, host := range targets {
		dst := net.ParseIP(host).To4()
		if dst == nil {
			skipped = append(skipped, host)
			continue
		}
		src, err := localIPv4For(dst)
		if err != nil || src == nil {
			skipped = append(skipped, fmt.Sprintf("%s (%v)", host, err))
			continue
		}
		srcByDst[host] = src
	}
	return srcByDst, skipped
}

func filterIPv4(ips []string) []string {
	out := make([]string, 0, len(ips))
	seen := make(map[string]struct{}, len(ips))
	for _, raw := range utils.RemoveDuplicateElement(ips) {
		ip := net.ParseIP(raw)
		if ip == nil || ip.To4() == nil {
			continue
		}
		s := ip.To4().String()
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func localIPv4For(dst net.IP) (net.IP, error) {
	if dst == nil || dst.To4() == nil {
		return nil, fmt.Errorf("not an IPv4 address")
	}
	conn, err := net.Dial("udp4", net.JoinHostPort(dst.String(), "80"))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	la, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || la.IP == nil || la.IP.To4() == nil {
		return nil, fmt.Errorf("no local IPv4 for route to %s", dst)
	}
	return la.IP.To4(), nil
}
