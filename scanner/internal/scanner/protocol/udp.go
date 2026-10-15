package protocol

import (
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/scanner/internal/scanner/protocol/intranet"
	"github.com/P0lar1ght/argus/scanner/structs"
	"github.com/projectdiscovery/gologger"
)

// IdentifyUDP probes a small intranet UDP set on already-alive hosts.
// Timeouts are closed; replies are stored as udp ServiceRecords and are not
// written into the TCP IPPortMap.
func (rt *Runtime) IdentifyUDP(hosts []string, threads, timeout int) {
	hosts = removeDuplicate(hosts)
	if len(hosts) == 0 {
		return
	}
	wait := time.Duration(timeout) * time.Second
	if wait <= 0 {
		wait = 2 * time.Second
	}
	gologger.AuditTimeLogger("UDP指纹识别，主机: %s", strings.Join(hosts, ","))
	rt.adoptUDP(intranet.ProbeHosts(hosts, intranet.DefaultUDPProbes(), wait, threads), true)
	gologger.AuditTimeLogger("UDP指纹识别结束")
}

// StoreUDP keeps already-probed UDP records without emitting another line.
func (rt *Runtime) StoreUDP(records []structs.ServiceRecord) {
	rt.adoptUDP(records, false)
}

// ImportUDP stores already-probed UDP records and emits [Port] lines
// without sending another datagram.
func (rt *Runtime) ImportUDP(records []structs.ServiceRecord) {
	rt.adoptUDP(records, true)
}

func (rt *Runtime) adoptUDP(records []structs.ServiceRecord, emit bool) {
	udpCount := 0
	for _, rec := range records {
		if rec.Endpoint == "" || rec.Transport != "udp" {
			continue
		}
		rt.storeRecord(rec)
		udpCount++
		if !emit {
			continue
		}
		host, portStr, err := net.SplitHostPort(rec.Endpoint)
		if err != nil {
			continue
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}
		rt.emitRecord(host, port, rec)
	}
	gologger.AuditTimeLogger("[Protocol] UDP识别汇总: 命中=%d", udpCount)
}

// UDPIdentifyHosts collects unicast hosts that already survived discovery
// or have an open TCP port. UDP is never sprayed at unresolved ranges.
func UDPIdentifyHosts(aliveIPs, openHostPorts []string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(host string) {
		host = strings.TrimSpace(host)
		if host == "" {
			return
		}
		if _, ok := seen[host]; ok {
			return
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	for _, ip := range aliveIPs {
		add(ip)
	}
	for _, hostPort := range openHostPorts {
		if host := hostFromEndpoint(hostPort); host != "" {
			add(host)
		}
	}
	return out
}

func hostFromEndpoint(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return ""
	}
	return host
}
