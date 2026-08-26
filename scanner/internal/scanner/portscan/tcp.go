// Package portscan 端口扫描模块。
package portscan

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/P0lar1ght/argus/scanner/ddout"
	"github.com/P0lar1ght/argus/scanner/utils"
	"github.com/projectdiscovery/gologger"
)

func ScanTCP(ips []string, ports string, timeout int, workers int, portsThreshold int, portScan bool, emit func(ddout.OutputMessage)) []string {
	var aliveAddress []string
	gologger.AuditTimeLogger("开始TCP端口扫描，端口设置: %s\nTCP端口扫描目标:%s", ports, strings.Join(ips, ","))

	probePorts := ParsePort(ports)
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(probePorts), func(i, j int) {
		probePorts[i], probePorts[j] = probePorts[j], probePorts[i]
	})

	ipPortCount := make(map[string]int)
	backlist := make(map[string]struct{})
	var backlistLock sync.Mutex

	if workers > len(ips)*len(probePorts) {
		workers = len(ips) * len(probePorts)
	}
	if workers <= 0 {
		workers = 1
	}

	addrs := make(chan addr, len(ips)*len(probePorts))
	results := make(chan string, len(ips)*len(probePorts))
	var wg sync.WaitGroup

	go func() {
		for found := range results {
			aliveAddress = append(aliveAddress, found)

			parts := strings.Split(found, ":")
			ip := parts[0]
			count := ipPortCount[ip]
			if count > portsThreshold {
				backlistLock.Lock()
				if _, exists := backlist[ip]; !exists {
					backlist[ip] = struct{}{}
					gologger.Error().Msgf("%s 端口数量超出阈值,放弃扫描", ip)
				}
				backlistLock.Unlock()
			}
			ipPortCount[ip] = count + 1
			wg.Done()
		}
	}()

	for i := 0; i < workers; i++ {
		go func() {
			for item := range addrs {
				portConnect(item, results, timeout, portScan, portsThreshold, &backlist, &backlistLock, &wg, emit)
				wg.Done()
			}
		}()
	}

	for _, port := range probePorts {
		for _, host := range ips {
			wg.Add(1)
			addrs <- addr{ip: host, port: port}
		}
	}

	wg.Wait()
	close(addrs)
	close(results)
	gologger.AuditTimeLogger("TCP端口扫描结束")
	return aliveAddress
}

func ParsePort(ports string) (scanPorts []int) {
	if ports == "" {
		return
	}
	slices := strings.Split(ports, ",")
	for _, port := range slices {
		port = strings.TrimSpace(port)
		if port == "" {
			continue
		}
		upper := port
		if strings.Contains(port, "-") {
			ranges := strings.Split(port, "-")
			if len(ranges) < 2 {
				continue
			}

			startPort, _ := strconv.Atoi(ranges[0])
			endPort, _ := strconv.Atoi(ranges[1])
			if startPort < endPort {
				port = ranges[0]
				upper = ranges[1]
			} else {
				port = ranges[1]
				upper = ranges[0]
			}
		}
		start, _ := strconv.Atoi(port)
		end, _ := strconv.Atoi(upper)
		for i := start; i <= end; i++ {
			scanPorts = append(scanPorts, i)
		}
	}
	scanPorts = utils.RemoveDuplicateElementInt(scanPorts)
	return scanPorts
}

type addr struct {
	ip   string
	port int
}

func portConnect(item addr, respondingHosts chan<- string, adjustedTimeout int, portScan bool, portsThreshold int, backlist *map[string]struct{}, backlistLock *sync.Mutex, wg *sync.WaitGroup, emit func(ddout.OutputMessage)) {
	backlistLock.Lock()
	_, blocked := (*backlist)[item.ip]
	backlistLock.Unlock()
	if blocked {
		return
	}

	conn, err := utils.WrapperTcpWithTimeout("tcp4", fmt.Sprintf("%s:%d", item.ip, item.port), time.Duration(adjustedTimeout)*time.Second)
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	if err != nil {
		return
	}

	if portScan {
		if emit != nil {
			emit(ddout.OutputMessage{
				Type: "PortScan",
				IP:   item.ip,
				Port: strconv.Itoa(item.port),
			})
		}
		wg.Add(1)
		respondingHosts <- item.ip + ":" + strconv.Itoa(item.port)
		return
	}

	// Liveness: first open port proves the host is up. Later ports skip.
	backlistLock.Lock()
	if _, exists := (*backlist)[item.ip]; exists {
		backlistLock.Unlock()
		return
	}
	(*backlist)[item.ip] = struct{}{}
	backlistLock.Unlock()
	if emit != nil {
		emit(ddout.OutputMessage{
			Type:          "IPAlive",
			IP:            item.ip,
			AdditionalMsg: "TCP:" + strconv.Itoa(item.port),
		})
	}
	wg.Add(1)
	respondingHosts <- item.ip + ":" + strconv.Itoa(item.port)
}

// ScanSYN runs the built-in IPv4 TCP SYN scanner (masscan-style async TX/RX
// with SipHash SYN cookies). Returns nil when the scanner aborts before probing;
// an empty non-nil slice means the scan completed with no open ports. Callers
// should probe CanSYNScan and fall back to TCP connect scan on nil.
func ScanSYN(ips []string, ports string, synThreads int, emit func(ddout.OutputMessage)) []string {
	return scanSYNBuiltin(ips, ports, synThreads, emit)
}

func RemoveFirewall(ipPorts []string, portsThreshold int) []string {
	var results []string
	gologger.AuditTimeLogger("移除开放端口过多的目标")

	grouped := make(map[string][]string)
	for _, ipPort := range ipPorts {
		parts := strings.Split(ipPort, ":")
		if len(parts) != 2 {
			continue
		}
		grouped[parts[0]] = append(grouped[parts[0]], parts[1])
	}

	for ip, ports := range grouped {
		uniquePorts := utils.RemoveDuplicateElement(ports)
		if len(uniquePorts) >= portsThreshold {
			gologger.Error().Msgf("%s 端口数量超出阈值,已丢弃", ip)
			continue
		}
		for _, port := range uniquePorts {
			results = append(results, ip+":"+port)
		}
	}
	return utils.RemoveDuplicateElement(results)
}
