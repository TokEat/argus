package intranet

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"strings"
	"time"

	"github.com/TokEat/argus/scanner/structs"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

var (
	adbCNXN   = []byte("CNXN\x00\x00\x00\x01\x00\x10\x00\x00\x07\x00\x00\x00\x32\x02\x00\x00\xbc\xb1\xa7\xb1host::\x00")
	rmiHello  = []byte{0x4a, 0x52, 0x4d, 0x49, 0x00, 0x02, 0x4b}
	jdwpHello = []byte("JDWP-Handshake")
)

// Probe sends a targeted handshake when gonmap left the port unidentified.
func Probe(host string, port int, timeout time.Duration, current structs.ServiceRecord) (structs.ServiceRecord, bool) {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	if current.Protocol == "http" || current.Protocol == "https" {
		return current, false
	}
	if current.Protocol == "http2" || port == 50051 {
		if rec, ok := probeGRPC(host, port, timeout); ok {
			return rec, true
		}
		if current.Protocol == "http2" {
			return current, true
		}
	}

	hint := portHint(port)
	if hint != "" {
		if rec, ok := runNamedProbe(host, port, timeout, hint); ok {
			return rec, true
		}
	}
	if current.Protocol == "rpc" {
		if rec, ok := runNamedProbe(host, port, timeout, "nfs"); ok && rec.Protocol == "nfs" {
			return rec, true
		}
	}
	if !unidentified(current.Protocol) {
		return current, false
	}

	// Non-standard ports: try the silent intranet set, first match wins.
	for _, name := range []string{
		"smtp", "imap", "pop3", "vnc", "rsync", "svn", "hsqldb",
		"ldap", "mqtt", "amqp", "postgresql", "zookeeper",
		"rpc", "nfs", "kerberos", "dns", "netbios",
		"cassandra", "clickhouse", "activemq", "nacos",
		"dm", "kingbase", "dubbo", "rocketmq-broker", "rocketmq-namesrv",
		"epmd", "jboss-remoting", "weblogic-t3", "weblogic-iiop",
		"modbus", "pcworx", "codesys", "proconos",
		"dnp3", "s7comm", "enip", "atg", "melsec", "fins", "crimson", "iec104",
		"msmq", "sap-p4", "tidb",
	} {
		if name == hint {
			continue
		}
		if rec, ok := runNamedProbe(host, port, minDuration(timeout, 800*time.Millisecond), name); ok {
			return rec, true
		}
	}
	return current, false
}

func unidentified(protocol string) bool {
	switch protocol {
	case "", "tcp", "udp", "unknown", "unidentified", "ssl", "protocol", "portscan":
		return true
	default:
		return false
	}
}

func minDuration(a, b time.Duration) time.Duration {
	if a > 0 && a < b {
		return a
	}
	return b
}

func runNamedProbe(host string, port int, timeout time.Duration, name string) (structs.ServiceRecord, bool) {
	var payload []byte
	switch name {
	case "adb":
		payload = adbCNXN
	case "rmi", "jmx":
		payload = rmiHello
	case "jdwp":
		payload = jdwpHello
	case "grpc":
		return probeGRPC(host, port, timeout)
	case "ldap":
		payload = ldapBindReq()
	case "ldaps":
		return probeLDAPS(host, port, timeout)
	case "kerberos":
		payload = kerberosASREQ()
	case "rpc":
		payload = rpcPortmapNull()
	case "netbios":
		payload = netbiosSessionReq()
	case "dns":
		payload = dnsVersionBindTCP()
	case "smtp", "imap", "pop3", "vnc", "hsqldb", "dm", "tidb":
		payload = nil
	case "rsync":
		payload = rsyncHello()
	case "nfs":
		payload = nfsNull()
	case "postgresql", "kingbase":
		payload = postgresStartup()
	case "mqtt":
		payload = mqttConnect()
	case "amqp":
		payload = amqpHeader()
	case "dubbo":
		payload = dubboStatus()
	case "rocketmq-broker":
		payload = rocketMQRequest(26)
	case "rocketmq-namesrv":
		payload = rocketMQRequest(106)
	case "epmd":
		payload = epmdNames()
	case "jboss-remoting":
		payload = jbossRemotingProbe()
	case "weblogic-t3":
		payload = weblogicT3Hello()
	case "weblogic-iiop":
		payload = weblogicIIOPProbe()
	case "modbus":
		payload = modbusDeviceID()
	case "dnp3":
		payload = dnp3LinkStatus()
	case "s7comm":
		return probeS7(host, port, timeout)
	case "enip":
		payload = etherNetIPListIdentity()
	case "atg":
		payload = atgInventory()
	case "melsec":
		payload = melsecQBinaryRead()
	case "fins":
		payload = finsNodeAddressRequest()
	case "crimson":
		payload = crimsonServiceProbe()
	case "iec104":
		payload = iec104StartDTActivation()
	case "msmq":
		payload = msmqPing()
	case "sap-p4":
		payload = sapP4NIPing()
	case "pcworx":
		payload = pcworxProbe()
	case "codesys":
		payload = codesysProbe()
	case "proconos":
		payload = proconosProbe()
	case "zookeeper":
		payload = []byte("stat\n")
	case "nacos":
		payload = nacosRaft()
	case "activemq":
		payload = stompConnect()
	case "cassandra":
		payload = cassandraOptions()
	case "clickhouse":
		payload = clickhouseHello()
	case "svn":
		payload = svnHello()
	default:
		return structs.ServiceRecord{}, false
	}

	raw, err := probeOnce(host, port, timeout, payload)
	if err != nil || len(raw) == 0 {
		if name == "zookeeper" {
			raw, err = probeOnce(host, port, timeout, []byte("ruok"))
			if err != nil || len(raw) == 0 {
				return structs.ServiceRecord{}, false
			}
		} else if name == "ldap" || name == "ldaps" {
			raw, err = probeOnce(host, port, timeout, ldapRootDSE())
			if err != nil || len(raw) == 0 {
				return structs.ServiceRecord{}, false
			}
		} else {
			return structs.ServiceRecord{}, false
		}
	}
	rec, ok := FromBanner(string(raw), port)
	if !ok {
		return structs.ServiceRecord{}, false
	}
	if name == "kingbase" && rec.Protocol == "postgresql" {
		rec.Protocol = "kingbase"
		rec.Product = "KingbaseES"
	}
	if name == "rocketmq-broker" && rec.Protocol == "rocketmq" {
		rec.Protocol = "rocketmq-broker"
		rec.Product = "Apache RocketMQ Broker"
		rec.Extra = "role=broker"
	}
	if name == "rocketmq-namesrv" && rec.Protocol == "rocketmq" {
		rec.Protocol = "rocketmq-namesrv"
		rec.Product = "Apache RocketMQ NameServer"
		rec.Extra = "role=namesrv"
	}
	if name == "ldaps" && rec.Protocol == "ldap" {
		rec.Protocol = "ldaps"
	}
	if name == "nfs" {
		if !rpcAccepted(raw) {
			return structs.ServiceRecord{}, false
		}
		rec.Protocol = "nfs"
		rec.Product = "NFS"
	}
	return rec, true
}

func probeS7(host string, port int, timeout time.Duration) (structs.ServiceRecord, bool) {
	conn, err := dialTimeout(host, port, timeout)
	if err != nil {
		return structs.ServiceRecord{}, false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(s7COTPConnectionRequest()); err != nil {
		return structs.ServiceRecord{}, false
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return structs.ServiceRecord{}, false
	}
	cotp := append([]byte(nil), buf[:n]...)
	if !isS7(string(cotp)) {
		if rec, ok := FromBanner(string(cotp), port); ok {
			return rec, true
		}
		return structs.ServiceRecord{}, false
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(s7SetupCommunication()); err != nil {
		return record("s7comm", "Siemens S7 PLC", "", "transport=cotp", "enriched"), true
	}
	n, err = conn.Read(buf)
	if err == nil && n > 0 {
		if rec, ok := FromBanner(string(buf[:n]), port); ok && rec.Protocol == "s7comm" {
			return rec, true
		}
	}
	return record("s7comm", "Siemens S7 PLC", "", "transport=cotp", "enriched"), true
}

func rpcAccepted(raw []byte) bool {
	msg := raw
	if len(raw) >= 8 && raw[0]&0x80 != 0 {
		msg = raw[4:]
	}
	if len(msg) < 24 {
		return false
	}
	// accept_stat is at byte 20 of the RPC reply body
	return binary.BigEndian.Uint32(msg[20:24]) == 0
}

func probeLDAPS(host string, port int, timeout time.Duration) (structs.ServiceRecord, bool) {
	conn, err := dialTimeout(host, port, timeout)
	if err != nil {
		return structs.ServiceRecord{}, false
	}
	defer conn.Close()
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, ServerName: host})
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := tlsConn.Handshake(); err != nil {
		return structs.ServiceRecord{}, false
	}
	raw, err := readRaw(tlsConn, ldapBindReq(), timeout)
	if err != nil || len(raw) == 0 {
		return structs.ServiceRecord{}, false
	}
	rec, ok := FromBanner(string(raw), port)
	if !ok {
		return structs.ServiceRecord{}, false
	}
	rec.Protocol = "ldaps"
	return rec, true
}

func probeOnce(host string, port int, timeout time.Duration, payload []byte) ([]byte, error) {
	conn, err := dialTimeout(host, port, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return readRaw(conn, payload, timeout)
}

func probeBytes(host string, port int, timeout time.Duration, payload []byte) (structs.ServiceRecord, bool) {
	raw, err := probeOnce(host, port, timeout, payload)
	if err != nil || len(raw) == 0 {
		return structs.ServiceRecord{}, false
	}
	return FromBanner(string(raw), port)
}

func probeGRPC(host string, port int, timeout time.Duration) (structs.ServiceRecord, bool) {
	conn, err := dialTimeout(host, port, timeout)
	if err != nil {
		return structs.ServiceRecord{}, false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		return structs.ServiceRecord{}, false
	}
	framer := http2.NewFramer(conn, conn)
	if err := framer.WriteSettings(); err != nil {
		return structs.ServiceRecord{}, false
	}

	sawHTTP2 := false
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		_ = conn.SetDeadline(time.Now().Add(800 * time.Millisecond))
		frame, err := framer.ReadFrame()
		if err != nil {
			break
		}
		sawHTTP2 = true
		if looksLikeGRPC(frame) {
			return record("grpc", "gRPC", "", "", "enriched"), true
		}
	}
	if !sawHTTP2 {
		return structs.ServiceRecord{}, false
	}

	var hdr bytes.Buffer
	enc := hpack.NewEncoder(&hdr)
	_ = enc.WriteField(hpack.HeaderField{Name: ":method", Value: "POST"})
	_ = enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "http"})
	_ = enc.WriteField(hpack.HeaderField{Name: ":path", Value: "/argus.identify/Noop"})
	_ = enc.WriteField(hpack.HeaderField{Name: ":authority", Value: host})
	_ = enc.WriteField(hpack.HeaderField{Name: "content-type", Value: "application/grpc"})
	_ = enc.WriteField(hpack.HeaderField{Name: "te", Value: "trailers"})
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		EndHeaders:    true,
		EndStream:     true,
		BlockFragment: hdr.Bytes(),
	}); err != nil {
		return record("http2", "HTTP/2", "", "", "enriched"), true
	}
	for i := 0; i < 6; i++ {
		_ = conn.SetDeadline(time.Now().Add(800 * time.Millisecond))
		frame, err := framer.ReadFrame()
		if err != nil {
			break
		}
		if looksLikeGRPC(frame) {
			return record("grpc", "gRPC", "", "", "enriched"), true
		}
	}
	return record("http2", "HTTP/2", "", "", "enriched"), true
}

func looksLikeGRPC(frame http2.Frame) bool {
	switch f := frame.(type) {
	case *http2.MetaHeadersFrame:
		for _, field := range f.Fields {
			name := strings.ToLower(field.Name)
			value := strings.ToLower(field.Value)
			if name == "content-type" && strings.Contains(value, "grpc") {
				return true
			}
			if name == "grpc-status" {
				return true
			}
		}
	case *http2.HeadersFrame:
		if strings.Contains(strings.ToLower(string(f.HeaderBlockFragment())), "grpc") {
			return true
		}
	}
	return false
}
