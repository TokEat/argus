package intranet

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/P0lar1ght/argus/scanner/structs"
)

// UDPProbe is one unicast identification datagram for a high-value intranet port.
type UDPProbe struct {
	Name     string
	Port     int
	Payloads [][]byte
}

// DefaultUDPProbes is the first-wave intranet UDP set. Timeout with no
// response is treated as closed, never as an open service.
func DefaultUDPProbes() []UDPProbe {
	return []UDPProbe{
		{Name: "dns", Port: 53, Payloads: [][]byte{dnsVersionBindUDP(), dnsStatusRequest()}},
		{Name: "kerberos", Port: 88, Payloads: [][]byte{kerberosASREQUDP()}},
		{Name: "ntp", Port: 123, Payloads: [][]byte{ntpRequest()}},
		{Name: "netbios-ns", Port: 137, Payloads: [][]byte{nbstatQuery()}},
		{Name: "snmp", Port: 161, Payloads: [][]byte{snmpV1GetSysName(), snmpV3Get()}},
		{Name: "isakmp", Port: 500, Payloads: [][]byte{ikeMainMode(), ikeV2Init()}},
		{Name: "sip", Port: 5060, Payloads: [][]byte{sipOptions()}},
		{Name: "mdns", Port: 5353, Payloads: [][]byte{dnsSDQuery()}},
		{Name: "ssdp", Port: 1900, Payloads: [][]byte{ssdpSearch()}},
	}
}

// ProbeUDP sends the probe payloads to host:port and classifies the first reply.
func ProbeUDP(host string, probe UDPProbe, timeout time.Duration) (structs.ServiceRecord, bool) {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	for _, payload := range probe.Payloads {
		raw, err := sendUDP(host, probe.Port, payload, timeout)
		if err != nil || len(raw) == 0 {
			continue
		}
		if rec, ok := ClassifyUDP(probe.Name, raw); ok {
			rec.Endpoint = net.JoinHostPort(host, strconv.Itoa(probe.Port))
			rec.Transport = "udp"
			if rec.Confidence == "" {
				rec.Confidence = "enriched"
			}
			return rec, true
		}
	}
	return structs.ServiceRecord{}, false
}

// ProbeHosts sends each probe to every host. Timeouts are not open ports.
func ProbeHosts(hosts []string, probes []UDPProbe, timeout time.Duration, workers int) []structs.ServiceRecord {
	seenHost := map[string]struct{}{}
	uniq := make([]string, 0, len(hosts))
	for _, host := range hosts {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		if _, ok := seenHost[host]; ok {
			continue
		}
		seenHost[host] = struct{}{}
		uniq = append(uniq, host)
	}
	if len(uniq) == 0 || len(probes) == 0 {
		return nil
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	type job struct {
		host  string
		probe UDPProbe
	}
	jobs := make([]job, 0, len(uniq)*len(probes))
	for _, host := range uniq {
		for _, probe := range probes {
			jobs = append(jobs, job{host: host, probe: probe})
		}
	}
	if workers <= 0 || workers > len(jobs) {
		workers = len(jobs)
	}

	work := make(chan job, len(jobs))
	var (
		wg  sync.WaitGroup
		mu  sync.Mutex
		out []structs.ServiceRecord
	)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range work {
				rec, ok := ProbeUDP(item.host, item.probe, timeout)
				if !ok {
					continue
				}
				mu.Lock()
				out = append(out, rec)
				mu.Unlock()
			}
		}()
	}
	for _, item := range jobs {
		work <- item
	}
	close(work)
	wg.Wait()
	return out
}

// ClassifyUDP names a datagram using the probe that elicited it.
func ClassifyUDP(name string, raw []byte) (structs.ServiceRecord, bool) {
	if len(raw) == 0 {
		return structs.ServiceRecord{}, false
	}
	switch name {
	case "dns":
		if udpLooksDNS(raw) {
			return udpRecord("dns", "DNS", "", dnsTXTHint(raw)), true
		}
	case "mdns":
		if udpLooksDNS(raw) || strings.Contains(strings.ToLower(string(raw)), "_dns-sd") || strings.Contains(string(raw), "_udp.local") {
			return udpRecord("mdns", "mDNS", "", dnsTXTHint(raw)), true
		}
	case "snmp":
		if udpLooksSNMP(raw) {
			return udpRecord("snmp", "SNMP", snmpVersion(raw), snmpSysHint(raw)), true
		}
	case "ntp":
		if udpLooksNTP(raw) {
			return udpRecord("ntp", "NTP", ntpVersion(raw), ""), true
		}
	case "netbios-ns":
		if udpLooksDNS(raw) || (len(raw) > 12 && raw[2]&0x80 != 0) {
			return udpRecord("netbios-ns", "NetBIOS-NS", "", nbstatNames(raw)), true
		}
	case "kerberos":
		if isKerberos(string(raw)) {
			return udpRecord("kerberos", "Kerberos", "", kerberosRealm(raw)), true
		}
	case "sip":
		if strings.HasPrefix(string(raw), "SIP/2.0") {
			extra := labeledUDP("server", headerValue(string(raw), "Server"))
			if extra == "" {
				extra = labeledUDP("banner", firstLine(string(raw)))
			}
			return udpRecord("sip", "SIP", "", extra), true
		}
	case "ssdp":
		if udpLooksSSDP(raw) {
			extra := strings.TrimSpace(labeledUDP("server", headerValue(string(raw), "SERVER")) + " " + labeledUDP("location", headerValue(string(raw), "LOCATION")))
			return udpRecord("ssdp", "SSDP", "", extra), true
		}
	case "isakmp":
		if udpLooksISAKMP(raw) {
			return udpRecord("isakmp", "ISAKMP", ikeVersion(raw), ""), true
		}
	}
	return structs.ServiceRecord{}, false
}

func udpRecord(proto, product, version, extra string) structs.ServiceRecord {
	rec := record(proto, product, version, extra, "enriched")
	rec.Transport = "udp"
	return rec
}

func sendUDP(host string, port int, payload []byte, timeout time.Duration) ([]byte, error) {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(payload); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if n > 0 {
		return buf[:n], nil
	}
	return nil, err
}

func udpLooksDNS(raw []byte) bool {
	if len(raw) < 12 {
		return false
	}
	return raw[2]&0x80 != 0
}

func udpLooksNTP(raw []byte) bool {
	if len(raw) < 48 {
		return false
	}
	mode := raw[0] & 0x07
	return mode == 4 || mode == 3 || mode == 5
}

func udpLooksSNMP(raw []byte) bool {
	return len(raw) >= 5 && raw[0] == 0x30
}

func udpLooksSSDP(raw []byte) bool {
	s := string(raw)
	if !strings.Contains(s, "HTTP/1.") {
		return false
	}
	upper := strings.ToUpper(s)
	return strings.Contains(upper, "USN:") || strings.Contains(upper, "ST:") || strings.Contains(upper, "LOCATION:") || strings.Contains(upper, "NTS:")
}

func udpLooksISAKMP(raw []byte) bool {
	if len(raw) < 28 {
		return false
	}
	ver := raw[17]
	return ver == 0x10 || ver == 0x20
}

func ntpVersion(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	vn := (raw[0] >> 3) & 0x07
	if vn == 0 {
		return ""
	}
	return strconv.Itoa(int(vn))
}

func ikeVersion(raw []byte) string {
	if len(raw) < 18 {
		return ""
	}
	switch raw[17] {
	case 0x10:
		return "1"
	case 0x20:
		return "2"
	default:
		return ""
	}
}

func snmpVersion(raw []byte) string {
	i := 1
	if i >= len(raw) {
		return ""
	}
	if raw[i]&0x80 != 0 {
		i += 1 + int(raw[i]&0x7f)
	} else {
		i++
	}
	if i+2 >= len(raw) || raw[i] != 0x02 || raw[i+1] != 0x01 {
		return ""
	}
	switch raw[i+2] {
	case 0:
		return "1"
	case 1:
		return "2c"
	case 3:
		return "3"
	default:
		return ""
	}
}

func labeledUDP(key, value string) string {
	value = strings.TrimSpace(value)
	if key == "" || value == "" {
		return ""
	}
	value = strings.Join(strings.Fields(value), "_")
	if len(value) > 48 {
		value = value[:48]
	}
	return key + "=" + value
}

func kerberosRealm(raw []byte) string {
	var b strings.Builder
	for _, c := range raw {
		if c >= 32 && c < 127 {
			b.WriteByte(c)
		} else if b.Len() >= 3 {
			break
		} else {
			b.Reset()
		}
	}
	s := strings.TrimSpace(b.String())
	if len(s) < 3 || strings.EqualFold(s, "krb") {
		return ""
	}
	return labeledUDP("realm", s)
}

func snmpSysHint(raw []byte) string {
	var b strings.Builder
	for _, c := range raw {
		if c >= 32 && c < 127 {
			b.WriteByte(c)
		} else if b.Len() >= 4 {
			break
		} else {
			b.Reset()
		}
	}
	s := strings.TrimSpace(b.String())
	if len(s) < 4 || s == "public" {
		return ""
	}
	if len(s) > 60 {
		s = s[:60]
	}
	return "sys=" + strings.ReplaceAll(s, " ", "_")
}

func nbstatNames(raw []byte) string {
	var host string
	for i := 0; i+16 <= len(raw); i++ {
		if raw[i] < 'A' || raw[i] > 'Z' {
			continue
		}
		n := 0
		for n < 15 && i+n < len(raw) && raw[i+n] != 0 && raw[i+n] != ' ' {
			if (raw[i+n] < 'A' || raw[i+n] > 'Z') && (raw[i+n] < '0' || raw[i+n] > '9') && raw[i+n] != '-' {
				n = 0
				break
			}
			n++
		}
		if n >= 2 && i+15 < len(raw) && (raw[i+15] == 0x00 || raw[i+15] == 0x20) {
			host = string(raw[i : i+n])
			break
		}
	}
	if host == "" {
		return ""
	}
	return "host=" + host
}

func dnsTXTHint(raw []byte) string {
	lower := strings.ToLower(string(raw))
	if !strings.Contains(lower, "version") {
		return ""
	}
	var b strings.Builder
	for _, c := range raw {
		if c >= 32 && c < 127 {
			b.WriteByte(c)
		} else if b.Len() >= 4 {
			break
		} else {
			b.Reset()
		}
	}
	if b.Len() < 4 {
		return ""
	}
	return b.String()
}

func headerValue(raw, key string) string {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			continue
		}
		if strings.EqualFold(line[:idx], key) {
			return strings.TrimSpace(line[idx+1:])
		}
	}
	return ""
}

func dnsVersionBindUDP() []byte {
	return []byte{
		0x00, 0x06, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 'v', 'e', 'r', 's', 'i', 'o', 'n', 0x04, 'b', 'i', 'n', 'd', 0x00, 0x00, 0x10, 0x00, 0x03,
	}
}

func dnsStatusRequest() []byte {
	return []byte{0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
}

func ntpRequest() []byte {
	return []byte{
		0xe3, 0x00, 0x04, 0xfa, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0xc5, 0x4f, 0x23, 0x4b, 0x71, 0xb1, 0x52, 0xf3,
	}
}

func nbstatQuery() []byte {
	return []byte{
		0x80, 0xf0, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x20, 'C', 'K',
		'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
		'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
		0x00, 0x00, 0x21, 0x00, 0x01,
	}
}

func snmpV1GetSysName() []byte {
	// nmap SNMPv1public: community public, sysName.0
	return []byte{
		0x30, 0x82, 0x00, 0x2f, 0x02, 0x01, 0x00, 0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c',
		0xa0, 0x82, 0x00, 0x20, 0x02, 0x04, 0x4c, 0x33, 0xa7, 0x56, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
		0x30, 0x82, 0x00, 0x10, 0x30, 0x82, 0x00, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00, 0x05, 0x00,
	}
}

func snmpV3Get() []byte {
	return []byte{
		0x30, 0x3a, 0x02, 0x01, 0x03, 0x30, 0x0f, 0x02, 0x02, 0x4a, 0x69, 0x02, 0x03, 0x00, 0xff, 0xe3,
		0x04, 0x01, 0x04, 0x02, 0x01, 0x03, 0x04, 0x10, 0x30, 0x0e, 0x04, 0x00, 0x02, 0x01, 0x00, 0x02,
		0x01, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x30, 0x12, 0x04, 0x00, 0x04, 0x00, 0xa0, 0x0c,
		0x02, 0x02, 0x37, 0xf0, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00,
	}
}

func sipOptions() []byte {
	return []byte("OPTIONS sip:nm SIP/2.0\r\nVia: SIP/2.0/UDP nm;branch=foo;rport\r\nFrom: <sip:nm@nm>;tag=root\r\nTo: <sip:nm2@nm2>\r\nCall-ID: 50000\r\nCSeq: 42 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\nContact: <sip:nm@nm>\r\nAccept: application/sdp\r\n\r\n")
}

func dnsSDQuery() []byte {
	return []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x09, '_', 's', 'e', 'r', 'v', 'i', 'c', 'e', 's',
		0x07, '_', 'd', 'n', 's', '-', 's', 'd',
		0x04, '_', 'u', 'd', 'p',
		0x05, 'l', 'o', 'c', 'a', 'l',
		0x00, 0x00, 0x0c, 0x00, 0x01,
	}
}

func ssdpSearch() []byte {
	return []byte("M-SEARCH * HTTP/1.1\r\nHost: 239.255.255.250:1900\r\nMan: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n")
}

func kerberosASREQUDP() []byte {
	p := kerberosASREQ()
	if len(p) <= 4 {
		return p
	}
	return p[4:]
}

func ikeMainMode() []byte {
	// Minimal valid IKEv1 Main Mode SA (3DES/SHA/PSK/MODP1024).
	return []byte{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x10, 0x02, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x54,
		0x00, 0x00, 0x00, 0x38,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x2c,
		0x01, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x24,
		0x01, 0x01, 0x00, 0x00,
		0x80, 0x01, 0x00, 0x05,
		0x80, 0x02, 0x00, 0x02,
		0x80, 0x03, 0x00, 0x01,
		0x80, 0x04, 0x00, 0x02,
		0x80, 0x0b, 0x00, 0x01,
		0x00, 0x0c, 0x00, 0x04, 0x00, 0x00, 0x70, 0x80,
	}
}

func ikeV2Init() []byte {
	p := make([]byte, 28)
	copy(p[0:8], []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef})
	p[16] = 0
	p[17] = 0x20
	p[18] = 34
	binary.BigEndian.PutUint32(p[24:], uint32(len(p)))
	return p
}
