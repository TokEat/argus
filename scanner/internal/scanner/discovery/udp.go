package discovery

import (
	"errors"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/TokEat/argus/scanner/ddout"
)

// ProbeUDP treats ICMP port unreachable (or a UDP reply) on a commonly
// closed port as proof the host is up. Timeout is not alive.
func ProbeUDP(ips []string, timeout time.Duration, threads int, emit func(ddout.OutputMessage)) []string {
	if len(ips) == 0 {
		return nil
	}
	if timeout <= 0 {
		timeout = time.Second
	}
	if threads <= 0 {
		threads = 64
	}
	if threads > len(ips) {
		threads = len(ips)
	}

	var (
		mu    sync.Mutex
		alive []string
		wg    sync.WaitGroup
	)
	jobs := make(chan string, len(ips))
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				if !udpHostAlive(ip, UDPProbePort, timeout) {
					continue
				}
				mu.Lock()
				alive = append(alive, ip)
				mu.Unlock()
				if emit != nil {
					emit(ddout.OutputMessage{Type: "IPAlive", IP: ip, AdditionalMsg: "UDP"})
				}
			}
		}()
	}
	for _, ip := range ips {
		jobs <- ip
	}
	close(jobs)
	wg.Wait()
	return Union(alive)
}

func udpHostAlive(ip string, port int, timeout time.Duration) bool {
	parsed := parseIPv4(ip)
	if parsed == nil {
		return false
	}
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: parsed, Port: port})
	if err != nil {
		return isPortUnreachable(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return false
	}
	if _, err := conn.Write([]byte{0}); err != nil {
		return isPortUnreachable(err)
	}
	buf := make([]byte, 64)
	if _, err := conn.Read(buf); err == nil {
		return true
	} else {
		return isPortUnreachable(err)
	}
}

func isPortUnreachable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	var errno syscall.Errno
	if errors.As(err, &errno) && errno == syscall.ECONNREFUSED {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection refused") || strings.Contains(msg, "port unreachable")
}
