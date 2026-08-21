package discovery

import (
	"bufio"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

func probeNeighborARP(_ LinkNet, ips []string, wait time.Duration) ([]string, bool) {
	if len(ips) == 0 {
		return nil, false
	}
	pokeUDP(ips)
	if wait <= 0 {
		wait = time.Second
	}
	time.Sleep(wait)
	cached, ok := readNeighborIPs()
	if !ok {
		return nil, false
	}
	want := make(map[string]struct{}, len(ips))
	for _, raw := range ips {
		if ip := parseIPv4(raw); ip != nil {
			want[ip.String()] = struct{}{}
		}
	}
	var alive []string
	for ip := range cached {
		if _, asked := want[ip]; asked {
			alive = append(alive, ip)
		}
	}
	return alive, true
}

func pokeUDP(ips []string) {
	var wg sync.WaitGroup
	limit := make(chan struct{}, 64)
	for _, raw := range ips {
		ip := parseIPv4(raw)
		if ip == nil {
			continue
		}
		wg.Add(1)
		limit <- struct{}{}
		go func(ip net.IP) {
			defer wg.Done()
			defer func() { <-limit }()
			conn, err := net.DialTimeout("udp4", net.JoinHostPort(ip.String(), "1"), 200*time.Millisecond)
			if err != nil {
				return
			}
			_ = conn.SetDeadline(time.Now().Add(200 * time.Millisecond))
			_, _ = conn.Write([]byte{0})
			_ = conn.Close()
		}(ip)
	}
	wg.Wait()
}

func readNeighborIPs() (map[string]struct{}, bool) {
	if runtime.GOOS == "linux" {
		return parseProcNetARP("/proc/net/arp")
	}
	return parseARPCommand()
}

func parseProcNetARP(path string) (map[string]struct{}, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	alive := make(map[string]struct{})
	scanner := bufio.NewScanner(f)
	if scanner.Scan() {
		// skip header
	}
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		ip := parseIPv4(fields[0])
		if ip == nil || !completeNeighborMAC(fields[3]) {
			continue
		}
		alive[ip.String()] = struct{}{}
	}
	return alive, true
}

func parseARPCommand() (map[string]struct{}, bool) {
	cmd := exec.Command("arp", "-an")
	out, err := cmd.Output()
	if err != nil {
		return nil, false
	}
	return parseARPAN(string(out)), true
}

func parseARPAN(output string) map[string]struct{} {
	alive := make(map[string]struct{})
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(strings.ToLower(line), "incomplete") {
			continue
		}
		ip := neighborIPFromARPLine(line)
		if ip == nil {
			continue
		}
		alive[ip.String()] = struct{}{}
	}
	return alive
}

func neighborIPFromARPLine(line string) net.IP {
	start := strings.Index(line, "(")
	end := strings.Index(line, ")")
	if start >= 0 && end > start+1 {
		return parseIPv4(line[start+1 : end])
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return nil
	}
	return parseIPv4(fields[0])
}

func completeNeighborMAC(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "*" || strings.EqualFold(raw, "incomplete") {
		return false
	}
	parts := strings.Split(raw, ":")
	if len(parts) != 6 {
		parts = strings.Split(raw, "-")
	}
	if len(parts) != 6 {
		return false
	}
	zero := true
	for _, part := range parts {
		if part != "00" && part != "0" {
			zero = false
			break
		}
	}
	return !zero
}
