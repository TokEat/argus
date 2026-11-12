package portscan

import (
	"net"
	"time"

	"github.com/TokEat/argus/scanner/ddout"
	"github.com/TokEat/argus/scanner/internal/scanner/protocol"
	"github.com/TokEat/argus/scanner/internal/scanner/protocol/intranet"
	"github.com/TokEat/argus/scanner/structs"
	"github.com/projectdiscovery/gologger"
)

// ScanUDP probes the first-wave intranet UDP ports on already-alive hosts.
// A reply is an open UDP port. Timeout is closed and is never reported.
func ScanUDP(hosts []string, timeout, workers int, emit func(ddout.OutputMessage)) []structs.ServiceRecord {
	wait := time.Duration(timeout) * time.Second
	if wait <= 0 {
		wait = 2 * time.Second
	}
	gologger.AuditTimeLogger("开始UDP端口探测，主机: %d", len(hosts))
	records := intranet.ProbeHosts(hosts, intranet.DefaultUDPProbes(), wait, workers)
	for _, rec := range records {
		host, port, err := net.SplitHostPort(rec.Endpoint)
		if err != nil || emit == nil {
			continue
		}
		emit(ddout.OutputMessage{
			Type:          "PortScan",
			IP:            host,
			Port:          port,
			Protocol:      rec.Protocol,
			Product:       rec.Product,
			Version:       rec.Version,
			Transport:     "udp",
			AdditionalMsg: protocol.ServiceDetail(rec.Product, rec.Version, rec.Extra),
		})
	}
	gologger.AuditTimeLogger("UDP端口探测结束，命中: %d", len(records))
	return records
}
