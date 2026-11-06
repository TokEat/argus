// Package protocol 协议识别模块。
package protocol

import (
	"fmt"
	"github.com/P0lar1ght/argus/scanner/internal/scanner/protocol/intranet"
	"github.com/P0lar1ght/argus/scanner/structs"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lcvvvv/gonmap"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/hmap/store/hybrid"
)

type Runtime struct {
	IPPortMap     map[string]string
	ServiceMap    map[string]structs.ServiceRecord
	IPPortMapLock *sync.Mutex
	BannerHMap    *hybrid.HybridMap
	emit          func(structs.OutputMessage)
}

func NewRuntime(ipPortMap map[string]string, ipPortMapLock *sync.Mutex, bannerHMap *hybrid.HybridMap, emit func(structs.OutputMessage), serviceMap map[string]structs.ServiceRecord) *Runtime {
	if serviceMap == nil {
		serviceMap = make(map[string]structs.ServiceRecord)
	}
	return &Runtime{
		IPPortMap:     ipPortMap,
		ServiceMap:    serviceMap,
		IPPortMapLock: ipPortMapLock,
		BannerHMap:    bannerHMap,
		emit:          emit,
	}
}

// Identify 对 hostPorts 做 TCP 指纹识别。emit 在每次产出识别结果时回调；onUnit
//（可为 nil）在每消费一个识别目标时回调，供引擎按 len(hostPorts) 口径统计 x/y
// 进度与 ETA。onUnit 由多个工作 goroutine 并发调用，调用方需保证计数器并发安全。
func (rt *Runtime) Identify(hostPorts []string, threads int, timeout int, onUnit func()) {
	if len(hostPorts) == 0 {
		return
	}

	hostPorts = removeDuplicate(hostPorts)
	if len(hostPorts) < threads {
		threads = len(hostPorts)
	}
	if threads <= 0 {
		threads = 1
	}

	gologger.AuditTimeLogger("TCP指纹识别，识别目标: %s", strings.Join(hostPorts, ","))

	addrs := make(chan string, len(hostPorts))
	results := make(chan protocolResult, len(hostPorts))
	var wg sync.WaitGroup

	go func() {
		for found := range results {
			rt.handleResult(found)
			wg.Done()
		}
	}()

	for i := 0; i < threads; i++ {
		go func() {
			scanner := gonmap.New()
			scanner.SetTimeout(time.Duration(timeout) * time.Second)
			for addr := range addrs {
				if onUnit != nil {
					// 每消费一个识别目标计 1（含格式非法被跳过的），保证 done 收敛到总数口径。
					onUnit()
				}
				parts := strings.Split(addr, ":")
				if len(parts) != 2 {
					results <- protocolResult{Status: int(gonmap.Closed)}
					continue
				}
				port, err := strconv.Atoi(parts[1])
				if err != nil || port > 65535 {
					results <- protocolResult{Status: int(gonmap.Closed)}
					continue
				}
				status, response := scanner.Scan(parts[0], port)
				results <- enrichResult(parts[0], port, timeout, protocolResult{
					IP:       parts[0],
					Port:     port,
					Status:   int(status),
					Response: response,
				})
			}
		}()
	}

	for _, hostPort := range hostPorts {
		wg.Add(1)
		addrs <- hostPort
	}

	wg.Wait()
	close(addrs)
	close(results)

	counts := map[string]int{}
	rt.lock()
	for hostPort, proto := range rt.IPPortMap {
		if proto == "" {
			proto = "tcp"
		}
		counts[proto]++
		if len(rt.IPPortMap) <= 30 {
			record := rt.ServiceMap[hostPort]
			if record.Product != "" || record.Version != "" {
				gologger.AuditLogger("[Protocol] %s → %s %s %s", hostPort, proto, record.Product, record.Version)
			} else {
				gologger.AuditLogger("[Protocol] %s → %s", hostPort, proto)
			}
		}
	}
	total := len(rt.IPPortMap)
	unidentified := counts["tcp"] + counts["udp"] + counts["unknown"]
	rt.unlock()
	gologger.AuditTimeLogger("[Protocol] 协议识别汇总: 总计=%d, 未识别=%d, 分类=%v", total, unidentified, counts)
	if counts["http"] == 0 && counts["https"] == 0 && total > 0 {
		gologger.AuditLogger("[Protocol] 未识别到 HTTP/HTTPS，后续 HTTP 探测将无目标")
	}

	gologger.AuditTimeLogger("TCP指纹识别结束")
}

type protocolResult struct {
	IP       string
	Port     int
	Status   int
	Response *gonmap.Response
	Enriched *structs.ServiceRecord
}

func enrichResult(host string, port, timeout int, found protocolResult) protocolResult {
	if found.Status == int(gonmap.Closed) {
		return found
	}
	current := structs.ServiceRecord{Transport: "tcp", Protocol: "tcp", Confidence: "port-hint"}
	var raw string
	if found.Response != nil {
		raw = found.Response.Raw
		if found.Response.FingerPrint != nil {
			current = recordFromFingerprint(found.Response.FingerPrint)
		}
		if rec, ok := intranet.FromBanner(raw, port); ok {
			if shouldReplace(current.Protocol, rec.Protocol) {
				current = mergeRecord(current, rec)
			} else {
				current.Extra = mergeExtra(current.Extra, rec.Extra)
			}
		}
		current.Extra = mergeExtra(current.Extra, bannerExtra(raw, current.Protocol))
	}
	wait := time.Duration(timeout) * time.Second
	if rec, ok := intranet.Probe(host, port, wait, current); ok {
		current = mergeRecord(current, rec)
		current.Extra = mergeExtra(current.Extra, rec.Extra)
	}
	if !Unidentified(current.Protocol) {
		current.Endpoint = fmt.Sprintf("%s:%d", host, port)
		found.Enriched = &current
		if found.Status == int(gonmap.Open) || found.Status == int(gonmap.NotMatched) {
			found.Status = int(gonmap.Matched)
		}
	}
	return found
}

func shouldReplace(current, next string) bool {
	if next == "" || current == next {
		return next != ""
	}
	if Unidentified(current) || current == "http2" {
		return true
	}
	if current == "smb" && (next == "netbios" || next == "netbios-ns") {
		return false
	}
	if dedicatedIntranet(next) {
		return true
	}
	return false
}

func dedicatedIntranet(protocol string) bool {
	switch protocol {
	case "ldap", "ldaps", "kerberos", "rpc", "netbios", "dns",
		"smtp", "imap", "pop3", "vnc", "rsync", "nfs",
		"postgresql", "mysql", "mariadb", "tidb", "mqtt", "amqp", "zookeeper",
		"dm", "kingbase", "nacos", "iec104", "rssp-ii", "rssp-i",
		"activemq", "cassandra", "clickhouse", "svn", "hsqldb",
		"adb", "rmi", "jmx", "jdwp", "grpc":
		return true
	default:
		return false
	}
}

func (rt *Runtime) handleResult(found protocolResult) {
	// Ports reaching Identify are already confirmed open by the port scan;
	// gonmap Closed here only means no probe matched, so keep the port in the
	// output as an unidentified tcp service instead of dropping it.
	if found.Status == int(gonmap.Closed) {
		record := structs.ServiceRecord{
			Endpoint:   fmt.Sprintf("%s:%d", found.IP, found.Port),
			Transport:  "tcp",
			Protocol:   "tcp",
			Confidence: "port-hint",
		}
		rt.storeRecord(record)
		rt.emitRecord(found.IP, found.Port, record)
		return
	}

	hostPort := fmt.Sprintf("%s:%d", found.IP, found.Port)
	if found.Enriched != nil {
		record := *found.Enriched
		record.Endpoint = hostPort
		if found.Response != nil && found.Response.Raw != "" && rt.BannerHMap != nil {
			_ = rt.BannerHMap.Set(hostPort, []byte(found.Response.Raw))
		}
		rt.storeRecord(record)
		rt.emitRecord(found.IP, found.Port, record)
		return
	}

	record := structs.ServiceRecord{
		Endpoint:   hostPort,
		Transport:  "tcp",
		Protocol:   "tcp",
		Confidence: "port-hint",
	}

	if found.Status == int(gonmap.Open) || found.Response == nil {
		if found.Port == 23 {
			record.Protocol = "telnet"
		}
		rt.storeRecord(record)
		rt.emitRecord(found.IP, found.Port, record)
		return
	}

	finger := found.Response.FingerPrint
	if finger == nil {
		finger = &gonmap.FingerPrint{}
	}
	if found.Port == 23 && finger.Service == "" {
		finger.Service = "telnet"
	}
	if rt.BannerHMap != nil && found.Response.Raw != "" {
		_ = rt.BannerHMap.Set(hostPort, []byte(found.Response.Raw))
	}

	proto := CanonicalProtocol(finger.Service)
	if proto == "" {
		if found.Port == 23 {
			proto = "telnet"
		} else {
			proto = "tcp"
		}
	}
	record.Protocol = proto
	record.Product = strings.TrimSpace(finger.ProductName)
	record.Version = strings.TrimSpace(finger.Version)
	record.Extra = mergeExtra(fingerprintExtra(finger), bannerExtra(found.Response.Raw, proto))
	if !Unidentified(proto) && finger.Service != "" {
		record.Confidence = "matched"
	}

	rt.lock()
	_, exists := rt.IPPortMap[hostPort]
	rt.unlock()
	if !exists {
		rt.storeRecord(record)
	}

	rt.emitRecord(found.IP, found.Port, record)
}

func (rt *Runtime) storeRecord(record structs.ServiceRecord) {
	rt.lock()
	if record.Transport != "udp" && rt.IPPortMap != nil {
		rt.IPPortMap[record.Endpoint] = record.Protocol
	}
	if rt.ServiceMap != nil {
		key := record.Endpoint
		if record.Transport == "udp" {
			key += "/udp"
		}
		rt.ServiceMap[key] = record
	}
	rt.unlock()
}

func (rt *Runtime) emitRecord(ip string, port int, record structs.ServiceRecord) {
	if rt.emit == nil {
		return
	}
	transport := record.Transport
	if transport == "" {
		transport = "tcp"
	}
	rt.emit(structs.OutputMessage{
		Type:          "PortScan",
		IP:            ip,
		Port:          strconv.Itoa(port),
		Protocol:      record.Protocol,
		Product:       record.Product,
		Version:       record.Version,
		Transport:     transport,
		AdditionalMsg: ServiceDetail(record.Product, record.Version, record.Extra),
	})
}

func nonEmpty(values ...string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			out = append(out, value)
		}
	}
	return out
}

func (rt *Runtime) lock() {
	if rt.IPPortMapLock != nil {
		rt.IPPortMapLock.Lock()
	}
}

func (rt *Runtime) unlock() {
	if rt.IPPortMapLock != nil {
		rt.IPPortMapLock.Unlock()
	}
}

func removeDuplicate(input []string) []string {
	if len(input) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(input))
	result := make([]string, 0, len(input))
	for _, item := range input {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		result = append(result, item)
	}
	return result
}
