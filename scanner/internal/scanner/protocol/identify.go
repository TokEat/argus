// Package protocol 协议识别模块。
package protocol

import (
	"dddd/scanner/ddout"
	"fmt"
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
	IPPortMapLock *sync.Mutex
	BannerHMap    *hybrid.HybridMap
}

func NewRuntime(ipPortMap map[string]string, ipPortMapLock *sync.Mutex, bannerHMap *hybrid.HybridMap) *Runtime {
	return &Runtime{
		IPPortMap:     ipPortMap,
		IPPortMapLock: ipPortMapLock,
		BannerHMap:    bannerHMap,
	}
}

func (rt *Runtime) Identify(hostPorts []string, threads int, timeout int) {
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
				results <- protocolResult{
					IP:       parts[0],
					Port:     port,
					Status:   int(status),
					Response: response,
				}
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
	gologger.AuditTimeLogger("TCP指纹识别结束")
}

type protocolResult struct {
	IP       string
	Port     int
	Status   int
	Response *gonmap.Response
}

func (rt *Runtime) handleResult(found protocolResult) {
	if found.Status == int(gonmap.Closed) {
		return
	}

	hostPort := fmt.Sprintf("%s:%d", found.IP, found.Port)
	if found.Status == gonmap.Open || found.Response == nil {
		proto := "tcp"
		if found.Port == 23 {
			proto = "telnet"
		}
		rt.storeProtocol(hostPort, proto)
		ddout.FormatOutput(ddout.OutputMessage{
			Type:     "Nmap",
			IP:       found.IP,
			Port:     strconv.Itoa(found.Port),
			Protocol: "tcp",
		})
		return
	}

	if found.Port == 23 && found.Response.FingerPrint.Service == "" {
		found.Response.FingerPrint.Service = "telnet"
	}

	rt.lock()
	_, exists := rt.IPPortMap[hostPort]
	rt.unlock()
	if !exists {
		if rt.BannerHMap != nil {
			_ = rt.BannerHMap.Set(hostPort, []byte(found.Response.Raw))
		}
		rt.storeProtocol(hostPort, found.Response.FingerPrint.Service)
	}

	proto := found.Response.FingerPrint.Service
	if proto == "" {
		proto = "tcp"
	}
	ddout.FormatOutput(ddout.OutputMessage{
		Type:     "Nmap",
		IP:       found.IP,
		Port:     strconv.Itoa(found.Port),
		Protocol: proto,
	})
}

func (rt *Runtime) storeProtocol(hostPort string, protocol string) {
	rt.lock()
	rt.IPPortMap[hostPort] = protocol
	rt.unlock()
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
