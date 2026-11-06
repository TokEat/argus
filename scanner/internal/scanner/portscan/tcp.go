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

// ScanTCP 对 ips×ports 做 TCP connect 扫描，返回开放地址（liveness 模式返回存活地址）。
// emit 在每次发现时回调；onUnit（可为 nil）在每消费一个探测单元（一个 addr）时回调，
// 供引擎按 ips×ports 口径统计 x/y 进度与 ETA。onUnit 由多个工作 goroutine 并发调用，
// 调用方需自行保证计数器并发安全（引擎 progressReporter 内部加锁）。
func ScanTCP(ips []string, ports string, timeout int, workers int, portsThreshold int, portScan bool, scatter bool, probeInterval time.Duration, emit func(ddout.OutputMessage), onUnit func()) []string {
	var aliveAddress []string
	gologger.AuditTimeLogger("开始TCP端口扫描，端口设置: %s\nTCP端口扫描目标:%s", ports, strings.Join(ips, ","))

	var pacer *scanPacer
	if scatter && probeInterval > 0 {
		pacer = newScanPacer(probeInterval)
		gologger.Info().Msgf("端口扫描打散已开启，同一目标最小探测间隔 %s", probeInterval)
	}

	probePorts := ParsePort(ports)
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(probePorts), func(i, j int) {
		probePorts[i], probePorts[j] = probePorts[j], probePorts[i]
	})

	// 队列容量固定上界：此前按 len(ips)*len(probePorts) 预分配两个 channel，
	// 大网段×多端口（如 /16×1000 端口）可达数千万元素、数 GB 内存，是 agent OOM 首因。
	// 生产者写满即阻塞（天然背压）、结果消费协程只读不阻塞，收窄容量不会死锁；
	// ipPortCount/backlist 仅为 O(ips) 级 map（数万目标数 MB 级），无需再分片。
	const scanQueueCap = 4096
	queueCap := len(ips) * len(probePorts)
	if queueCap > scanQueueCap {
		queueCap = scanQueueCap
	}

	ipPortCount := make(map[string]int)
	backlist := make(map[string]struct{})
	var backlistLock sync.Mutex

	if workers > len(ips)*len(probePorts) {
		workers = len(ips) * len(probePorts)
	}
	if workers <= 0 {
		workers = 1
	}

	addrs := make(chan addr, queueCap)
	results := make(chan string, queueCap)
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
				portConnect(item, results, timeout, portScan, portsThreshold, &backlist, &backlistLock, pacer, &wg, emit)
				if onUnit != nil {
					// 每消费一个探测单元（含被 backlist 跳过的 addr）计 1，
					// 保证 done 收敛到 len(ips)×len(probePorts) 的总数口径。
					onUnit()
				}
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

// scanPacer enforces a minimum interval between connection attempts to the
// same target so one target's ports are scattered across time instead of being
// probed back-to-back, which evades per-IP threshold auto-blocking.
type scanPacer struct {
	interval time.Duration
	mu       sync.Mutex
	next     map[string]time.Time
}

func newScanPacer(interval time.Duration) *scanPacer {
	return &scanPacer{interval: interval, next: make(map[string]time.Time)}
}

// book reserves the next available slot for ip and returns how long the caller
// must wait before its connection attempt may start.
func (p *scanPacer) book(ip string) time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	earliest := p.next[ip]
	if earliest.Before(now) {
		earliest = now
	}
	p.next[ip] = earliest.Add(p.interval)
	return earliest.Sub(now)
}

// pacedSYNRate converts a per-target probe interval into an approximate global
// scan rate: with targetCount targets each probed at most once per interval,
// the aggregate demand is targetCount*1000/intervalMillis pps. The result is
// capped by the configured rate so pacing never exceeds the operator's ceiling.
func pacedSYNRate(targetCount, intervalMillis, capRate int) int {
	if targetCount <= 0 || intervalMillis <= 0 {
		return capRate
	}
	rate := (targetCount*1000 + intervalMillis - 1) / intervalMillis
	if rate < 1 {
		rate = 1
	}
	if capRate > 0 && rate > capRate {
		rate = capRate
	}
	return rate
}

func determineConnectTimeout(ip string, configuredTimeout int) time.Duration {
	if configuredTimeout <= 0 {
		configuredTimeout = 6
	}
	// 当使用默认超时 (>=6s) 且目标为本地/内网私有地址时，自适应收敛至 1.5s，
	// 防止遭遇防火墙 DROP 静默丢包时无谓等待 6 秒。
	// 若调用方已明确配置了更小超时，则严格按调用方设定执行。
	if configuredTimeout >= 6 && utils.IsLocalIP(ip) {
		return 1500 * time.Millisecond
	}
	return time.Duration(configuredTimeout) * time.Second
}

func portConnect(item addr, respondingHosts chan<- string, adjustedTimeout int, portScan bool, portsThreshold int, backlist *map[string]struct{}, backlistLock *sync.Mutex, pacer *scanPacer, wg *sync.WaitGroup, emit func(ddout.OutputMessage)) {
	backlistLock.Lock()
	_, blocked := (*backlist)[item.ip]
	backlistLock.Unlock()
	if blocked {
		return
	}

	if pacer != nil {
		if wait := pacer.book(item.ip); wait > 0 {
			time.Sleep(wait)
		}
	}

	timeoutDur := determineConnectTimeout(item.ip, adjustedTimeout)
	conn, err := utils.WrapperTcpWithTimeout("tcp4", fmt.Sprintf("%s:%d", item.ip, item.port), timeoutDur)
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
// scatter/probeIntervalMillis 沿用本地端口扫描打散语义：开启时按
// 目标数×最小间隔 聚合计速，上限仍为 synThreads。
func ScanSYN(ips []string, ports string, synThreads int, scatter bool, probeIntervalMillis int, emit func(ddout.OutputMessage)) []string {
	rate := synThreads
	if scatter && probeIntervalMillis > 0 {
		rate = pacedSYNRate(len(ips), probeIntervalMillis, synThreads)
		gologger.Info().Msgf("SYN端口扫描打散已开启，按 %d 个目标的 %dms 间隔限速为 %d pps", len(ips), probeIntervalMillis, rate)
	}
	return scanSYNBuiltin(ips, ports, rate, emit)
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
