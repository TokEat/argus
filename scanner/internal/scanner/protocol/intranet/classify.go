package intranet

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/TokEat/argus/scanner/internal/protocolwire"
	"github.com/TokEat/argus/scanner/structs"
)

const adbMagic = "\xbc\xb1\xa7\xb1"

// FromBanner names a service from a payload already sitting on the wire.
func FromBanner(raw string, port int) (structs.ServiceRecord, bool) {
	if raw == "" {
		return structs.ServiceRecord{}, false
	}
	lower := strings.ToLower(raw)
	activeMQVersion, activeMQ := protocolwire.ActiveMQOpenWireVersion([]byte(raw))
	tidbVersion, tidb := protocolwire.TiDBServerVersion([]byte(raw))
	iec104 := protocolwire.IsIEC104Frame([]byte(raw))
	rsspII, rsspIIOK := protocolwire.RSSPIIALE([]byte(raw))
	rsspI, rsspIOK := protocolwire.RSSPI([]byte(raw))
	switch {
	case isADB(raw):
		info := "auth=required"
		if strings.HasPrefix(raw, "CNXN") {
			info = ""
		}
		return record("adb", "Android Debug Bridge", "", info, "enriched"), true
	case isDNP3(raw):
		return record("dnp3", "DNP3", "", "", "enriched"), true
	case isS7(raw):
		return record("s7comm", "Siemens S7 PLC", "", "transport=cotp", "enriched"), true
	case isEtherNetIP(raw, port):
		return record("enip", "EtherNet/IP", "", "", "enriched"), true
	case isATG(raw, port):
		return record("atg", "Automatic Tank Gauge", "", "", "enriched"), true
	case isMELSEC(raw, port):
		return record("melsec", "MELSEC PLC", "", "", "enriched"), true
	case isFINS(raw):
		return record("fins", "Omron FINS", "", "", "enriched"), true
	case isCrimson(raw, port):
		return record("crimson", "Red Lion Crimson", "", "", "enriched"), true
	case isRMI(raw):
		proto, extra := "rmi", rmiHost(raw)
		if strings.Contains(lower, "jmx") {
			proto, extra = "jmx", joinExtra(extra, "transport=rmi")
		}
		return record(proto, "Java RMI", "", extra, "enriched"), true
	case raw == "JDWP-Handshake":
		return record("jdwp", "Java Debug Wire Protocol", "", "", "enriched"), true
	case isJavaSerialization(raw):
		return record("java-serialization", "Java serialized stream", "", "", "enriched"), true
	case iec104:
		return record("iec104", "IEC-60870-5-104", "", "", "enriched"), true
	case rsspIIOK:
		return record("rssp-ii", "RSSP-II", "", rsspII.Extra(), "enriched"), true
	case rsspIOK:
		return record("rssp-i", "RSSP-I", "", rsspI.Extra(), "enriched"), true
	case tidb:
		return record("tidb", "TiDB", tidbVersion, "", "enriched"), true
	case isHTTP2Settings(raw):
		return record("http2", "HTTP/2", "", "", "enriched"), true
	case strings.HasPrefix(raw, "RFB "):
		ver := strings.TrimSpace(strings.TrimPrefix(strings.Split(raw, "\n")[0], "RFB "))
		return record("vnc", "VNC", ver, "", "enriched"), true
	case strings.HasPrefix(raw, "@RSYNCD"):
		return record("rsync", "rsync", strings.TrimSpace(strings.TrimPrefix(raw, "@RSYNCD:")), "", "enriched"), true
	case strings.HasPrefix(raw, "* OK") || strings.HasPrefix(raw, "* PREAUTH"):
		return record("imap", "IMAP", "", firstLine(raw), "enriched"), true
	case strings.HasPrefix(raw, "+OK"):
		return record("pop3", "POP3", "", firstLine(raw), "enriched"), true
	case isSMTP(raw):
		return record("smtp", "SMTP", "", firstLine(raw), "enriched"), true
	case strings.HasPrefix(raw, "( success") || strings.Contains(raw, "edit-pipeline"):
		return record("svn", "Subversion", "", "", "enriched"), true
	case strings.Contains(raw, "HSQLDB"):
		return record("hsqldb", "HSQLDB", hsqlVersion(raw), "", "enriched"), true
	case strings.HasPrefix(raw, "AMQP"):
		return record("amqp", "AMQP", "", "", "enriched"), true
	case isDubbo(raw):
		return record("dubbo", "Apache Dubbo", "", firstLine(raw), "enriched"), true
	case isRocketMQ(raw):
		return record(rocketMQProtocol(port), rocketMQProduct(port), "", rocketMQRole(port), "enriched"), true
	case isEPMD(raw):
		return record("epmd", "Erlang Port Mapper Daemon", "", epmdExtra(raw), "enriched"), true
	case isJBossRemoting(raw):
		return record("jboss-remoting", "JBoss Remoting", "", jbossRemotingHost(raw), "enriched"), true
	case isWebLogicT3(raw):
		return record("weblogic-t3", "Oracle WebLogic T3", weblogicT3Version(raw), "", "enriched"), true
	case isIIOP(raw):
		return record("iiop", "CORBA/IIOP", "", "", "enriched"), true
	case isModbus(raw):
		return record("modbus", "Modbus TCP", "", "", "enriched"), true
	case isPCWorx(raw):
		return record("pcworx", "Phoenix Contact PCWorx", "", "", "enriched"), true
	case isCodesys(raw):
		return record("codesys", "CODESYS Runtime", "", "", "enriched"), true
	case isProConOS(raw):
		return record("proconos", "ProConOS", proconosVersion(raw), proconosExtra(raw), "enriched"), true
	case len(raw) >= 2 && raw[0] == 0x20 && raw[1] == 0x02:
		return record("mqtt", "MQTT", "", "", "enriched"), true
	case protocolwire.IsZooKeeperText([]byte(raw)):
		return record("zookeeper", "ZooKeeper", protocolwire.ZooKeeperVersion([]byte(raw)), "", "enriched"), true
	case protocolwire.IsCassandraOptionsResponse([]byte(raw)):
		return record("cassandra", "Cassandra", "", "", "enriched"), true
	case strings.Contains(raw, "ClickHouse"):
		return record("clickhouse", "ClickHouse", "", "", "enriched"), true
	case strings.Contains(lower, "kingbase"):
		return record("kingbase", "KingbaseES", "", "", "enriched"), true
	case strings.Contains(lower, "dameng") || strings.Contains(raw, "DM Database") || containsToken(raw, "DM8") || containsToken(raw, "DM7"):
		return record("dm", "Dameng", "", "", "enriched"), true
	case isNacosRaft(raw):
		return record("nacos", "Nacos", "", "transport=raft", "enriched"), true
	case activeMQ:
		return record("activemq", "ActiveMQ OpenWire transport", activeMQVersion, "", "enriched"), true
	case strings.HasPrefix(raw, "CONNECTED") && (strings.Contains(lower, "stomp") || strings.Contains(lower, "activemq")):
		return record("activemq", "ActiveMQ STOMP", "", "", "enriched"), true
	case isMSMQ(raw, port):
		return record("msmq", "Microsoft Message Queuing", "", "", "enriched"), true
	case isSAPP4(raw, port):
		return record("sap-p4", "SAP NetWeaver P4", "", "", "enriched"), true
	case isPostgresFamily(raw):
		if strings.Contains(lower, "kingbase") {
			return record("kingbase", "KingbaseES", "", "", "enriched"), true
		}
		return record("postgresql", "PostgreSQL", "", "", "enriched"), true
	case isLDAP(raw):
		return record("ldap", "LDAP", "", "", "enriched"), true
	case isKerberos(raw):
		return record("kerberos", "Kerberos", "", "", "enriched"), true
	case isDNS(raw):
		return record("dns", "DNS", "", "", "enriched"), true
	case isNetBIOS(raw):
		return record("netbios", "NetBIOS", "", "", "enriched"), true
	case isRPC(raw):
		return record("rpc", "MSRPC/Portmap", "", "", "enriched"), true
	default:
		return structs.ServiceRecord{}, false
	}
}

func record(proto, product, version, extra, confidence string) structs.ServiceRecord {
	return structs.ServiceRecord{
		Transport:  "tcp",
		Protocol:   proto,
		Product:    product,
		Version:    version,
		Extra:      extra,
		Confidence: confidence,
	}
}

func firstLine(raw string) string {
	line, _, _ := strings.Cut(raw, "\n")
	return strings.TrimSpace(strings.TrimSuffix(line, "\r"))
}

func isADB(raw string) bool {
	return strings.Contains(raw, adbMagic) && (strings.HasPrefix(raw, "CNXN") || strings.HasPrefix(raw, "AUTH"))
}

func isRMI(raw string) bool {
	if len(raw) < 7 || raw[0] != 0x4e {
		return false
	}
	n := int(raw[1])<<8 | int(raw[2])
	if n <= 0 || n > 255 || len(raw) < 3+n+2 {
		return false
	}
	host := raw[3 : 3+n]
	for _, b := range host {
		if b != '.' && b != ':' && (b < '0' || b > '9') && (b < 'a' || b > 'z') && (b < 'A' || b > 'Z') && b != '-' && b != '_' {
			return false
		}
	}
	return true
}

func rmiHost(raw string) string {
	if !isRMI(raw) {
		return ""
	}
	n := int(raw[1])<<8 | int(raw[2])
	return "host=" + raw[3:3+n]
}

func isJavaSerialization(raw string) bool {
	return strings.HasPrefix(raw, "\xac\xed\x00\x05")
}

func isHTTP2Settings(raw string) bool {
	if strings.HasPrefix(raw, "PRI * HTTP/2.0") {
		return true
	}
	return len(raw) >= 9 && raw[3] == 0x04
}

func isSMTP(raw string) bool {
	if !strings.HasPrefix(raw, "220") {
		return false
	}
	upper := strings.ToUpper(raw)
	if strings.Contains(upper, "FTP") || strings.Contains(upper, "FILEZILLA") || strings.Contains(upper, "VSFTPD") {
		return false
	}
	return strings.Contains(upper, "SMTP") || strings.Contains(upper, "ESMTP") || strings.Contains(upper, "POSTFIX") || strings.Contains(upper, "EXIM") || strings.Contains(upper, "MAIL")
}

func isNacosRaft(raw string) bool {
	if strings.Contains(raw, "HTTP/") {
		return false
	}
	lower := strings.ToLower(raw)
	return strings.Contains(lower, "nacos") || strings.Contains(lower, "jraft")
}

func isDubbo(raw string) bool {
	if strings.Contains(raw, "HTTP/") {
		return false
	}
	lower := strings.ToLower(raw)
	return strings.Contains(lower, "dubbo>") ||
		strings.Contains(lower, "dubbo service")
}

func isRocketMQ(raw string) bool {
	if strings.Contains(raw, "HTTP/") {
		return false
	}
	if strings.Contains(strings.ToLower(raw), "rocketmq") {
		return true
	}
	data := []byte(raw)
	if len(data) < 12 {
		return false
	}
	total := int(binary.BigEndian.Uint32(data[0:4]))
	if total <= 4 || total > len(data)-4 {
		return false
	}
	headerMark := binary.BigEndian.Uint32(data[4:8])
	headerLen := int(headerMark & 0x00ffffff)
	if headerLen <= 0 || headerLen > total-4 || 8+headerLen > len(data) {
		return false
	}
	header := strings.ToLower(string(data[8 : 8+headerLen]))
	return strings.Contains(header, `"code"`) && (strings.Contains(header, `"opaque"`) || strings.Contains(header, `"remark"`) || strings.Contains(header, `"extfields"`))
}

func rocketMQProduct(port int) string {
	switch port {
	case 9876:
		return "Apache RocketMQ NameServer"
	case 10909, 10911:
		return "Apache RocketMQ Broker"
	default:
		return "Apache RocketMQ"
	}
}

func rocketMQProtocol(port int) string {
	switch port {
	case 9876:
		return "rocketmq-namesrv"
	case 10909, 10911:
		return "rocketmq-broker"
	default:
		return "rocketmq"
	}
}

func rocketMQRole(port int) string {
	switch port {
	case 9876:
		return "role=namesrv"
	case 10909, 10911:
		return "role=broker"
	default:
		return ""
	}
}

func isEPMD(raw string) bool {
	data := []byte(raw)
	return len(data) >= 4 &&
		binary.BigEndian.Uint32(data[:4]) == 4369 &&
		strings.Contains(raw[4:], "name ")
}

func epmdExtra(raw string) string {
	if !strings.Contains(raw, "name ") {
		return ""
	}
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	names := make([]string, 0, 3)
	for _, line := range lines {
		if !strings.HasPrefix(line, "name ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			names = append(names, fields[1])
		}
		if len(names) == 3 {
			break
		}
	}
	if len(names) == 0 {
		return ""
	}
	return "nodes=" + strings.Join(names, ",")
}

func isJBossRemoting(raw string) bool {
	return strings.Contains(raw, "GSSAPI") && strings.Contains(raw, "DIGEST-MD5") ||
		strings.HasPrefix(raw, "\x00\x00\x00\x3e\x00\x00\x01") ||
		strings.HasPrefix(raw, "\x00\x00\x00.\x00\x00")
}

func jbossRemotingHost(raw string) string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == 0 || r == '\r' || r == '\n'
	})
	for _, field := range fields {
		if strings.Contains(field, ".") && !strings.Contains(field, "GSSAPI") && len(field) <= 64 {
			return "host=" + field
		}
	}
	return ""
}

func isWebLogicT3(raw string) bool {
	if strings.Contains(raw, "HTTP/") {
		return false
	}
	return strings.HasPrefix(raw, "HELO:") || strings.HasPrefix(strings.ToLower(raw), "t3 ")
}

func weblogicT3Version(raw string) string {
	line := firstLine(raw)
	line = strings.TrimPrefix(line, "HELO:")
	line = strings.TrimPrefix(strings.ToLower(line), "t3 ")
	fields := strings.FieldsFunc(line, func(r rune) bool {
		return r == '.' || r == ' ' || r == '\t'
	})
	if len(fields) == 0 {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(firstLine(raw), "HELO:"))
}

func isIIOP(raw string) bool {
	return strings.HasPrefix(raw, "GIOP")
}

func isModbus(raw string) bool {
	data := []byte(raw)
	if len(data) < 8 {
		return false
	}
	if binary.BigEndian.Uint16(data[2:4]) != 0 {
		return false
	}
	if binary.BigEndian.Uint16(data[0:2]) != 1 {
		return false
	}
	length := int(binary.BigEndian.Uint16(data[4:6]))
	return length > 0 && length <= len(data)-6 && (data[7] == 0x2b || data[7] == 0xab || data[7] <= 0x7f)
}

func isPCWorx(raw string) bool {
	return strings.HasPrefix(raw, "\x81\x01\x00\x14") || strings.Contains(raw, "IBETH")
}

func isCodesys(raw string) bool {
	return strings.HasPrefix(raw, "\x04\xef\xef\xb3") || strings.Contains(strings.ToUpper(raw), "CODESYS")
}

func isProConOS(raw string) bool {
	return strings.HasPrefix(raw, "\xcc\x01") && strings.Contains(raw, "ProConOS")
}

func proconosVersion(raw string) string {
	if i := strings.Index(raw, "ProConOS V"); i >= 0 {
		rest := raw[i+10:]
		fields := strings.Fields(rest)
		if len(fields) > 0 {
			return strings.Trim(fields[0], "\x00")
		}
	}
	return ""
}

func proconosExtra(raw string) string {
	parts := strings.Split(raw, "\x00")
	values := make([]string, 0, 2)
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if len(part) < 3 || strings.Contains(part, "ProConOS") {
			continue
		}
		values = append(values, part)
		if len(values) == 2 {
			break
		}
	}
	if len(values) == 0 {
		return ""
	}
	return "info=" + strings.Join(values, "/")
}

func isDNP3(raw string) bool {
	data := []byte(raw)
	return len(data) >= 2 && data[0] == 0x05 && data[1] == 0x64
}

func isS7(raw string) bool {
	data := []byte(raw)
	if len(data) < 7 || data[0] != 0x03 || data[1] != 0x00 {
		return false
	}
	length := int(binary.BigEndian.Uint16(data[2:4]))
	if length < 7 || length > len(data) {
		return false
	}
	if len(data) >= 8 && data[4] == 0x02 && data[5] == 0xf0 && data[6] == 0x80 && data[7] == 0x32 {
		return true
	}
	if data[4] >= 0x06 && (data[5] == 0xd0 || data[5] == 0xe0) {
		return true
	}
	return false
}

func isEtherNetIP(raw string, port int) bool {
	data := []byte(raw)
	if len(data) < 4 || data[0] != 0x63 || data[1] != 0x00 {
		return false
	}
	return port == 44818 || len(data) >= 24
}

func isATG(raw string, port int) bool {
	upper := strings.ToUpper(raw)
	if strings.Contains(upper, "ATG") || strings.Contains(upper, "I201") {
		return !strings.Contains(raw, "HTTP/")
	}
	if port != 10001 || len(raw) < 3 || raw[0] != 0x01 {
		return false
	}
	for i := 1; i < len(raw); i++ {
		if raw[i] == '\r' || raw[i] == '\n' {
			return true
		}
		if raw[i] < 0x20 || raw[i] > 0x7e {
			return false
		}
	}
	return true
}

func isMELSEC(raw string, port int) bool {
	data := []byte(raw)
	if len(data) < 4 || (data[0] != 0xd7 && data[0] != 0x57) {
		return false
	}
	return port == 5006 || port == 5007 || len(data) >= 9
}

func isFINS(raw string) bool {
	return len(raw) >= 8 && strings.HasPrefix(raw, "FINS")
}

func isCrimson(raw string, port int) bool {
	if strings.Contains(strings.ToLower(raw), "crimson") {
		return true
	}
	if port != 789 || len(raw) < 3 || len(raw) > 128 || strings.Contains(raw, "HTTP/") {
		return false
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] == 0 {
			return false
		}
	}
	return true
}

func isMSMQ(raw string, port int) bool {
	if strings.Contains(strings.ToUpper(raw), "MSMQ") {
		return !strings.Contains(raw, "HTTP/")
	}
	data := []byte(raw)
	if port != 1801 || len(data) < 4 {
		return false
	}
	return data[1] == 0x01 && data[2] == 0x00 && data[3] == 0x00 && (data[0] == 0x10 || data[0] == 0x11 || data[0] == 0x12)
}

func isSAPP4(raw string, port int) bool {
	if strings.Contains(raw, "HTTP/") {
		return false
	}
	upper := strings.ToUpper(raw)
	if strings.Contains(upper, "NI_PONG") || strings.Contains(upper, "NI_PING") {
		return true
	}
	return port == 50000 && (strings.Contains(upper, "SAP") || strings.Contains(upper, "NI"))
}

func isPostgresFamily(raw string) bool {
	if len(raw) < 1 {
		return false
	}
	if raw[0] == 'R' || raw[0] == 'E' {
		return strings.Contains(raw, "FATAL") || strings.Contains(raw, "postgres") || strings.Contains(raw, "password") || strings.Contains(raw, "SFATAL") || strings.Contains(raw, "Kingbase") || strings.Contains(raw, "C28P01") || strings.Contains(raw, "C28000")
	}
	return false
}

func isLDAP(raw string) bool {
	return len(raw) >= 2 && raw[0] == 0x30 && (strings.Contains(raw, "supportedLDAP") || strings.Contains(raw, "OpenLDAProotDSE") || raw[1] > 0x10 || (len(raw) > 4 && raw[2] == 0x02))
}

func isKerberos(raw string) bool {
	if len(raw) < 6 {
		return false
	}
	// TCP length prefix then APPLICATION 30 (KRB-ERROR 0x7e) or AS-REP 0x6b
	off := 0
	if raw[0] == 0 && raw[1] == 0 {
		off = 4
	}
	if off >= len(raw) {
		return false
	}
	b := raw[off]
	return b == 0x7e || b == 0x6b || b == 0x6d || (b == 0x30 && strings.Contains(raw, "krb"))
}

func isDNS(raw string) bool {
	if len(raw) < 14 {
		return false
	}
	// TCP prefixed DNS: 2-byte length + header
	msg := raw
	if int(raw[0])<<8|int(raw[1]) == len(raw)-2 {
		msg = raw[2:]
	}
	if len(msg) < 12 {
		return false
	}
	flags := int(msg[2])<<8 | int(msg[3])
	return flags&0x8000 != 0 // QR=response
}

func isRPC(raw string) bool {
	if len(raw) < 12 {
		return false
	}
	msg := raw
	if raw[0]&0x80 != 0 && len(raw) >= 8 {
		msg = raw[4:]
	}
	if len(msg) < 8 {
		return false
	}
	// reply = 1
	return binary.BigEndian.Uint32([]byte(msg[4:8])) == 1
}

func isNetBIOS(raw string) bool {
	if len(raw) == 0 {
		return false
	}
	return raw[0] == 0x82 || raw[0] == 0x83 || raw[0] == 0x84 || strings.HasPrefix(raw, "\xffSMB") || strings.Contains(raw, "SMB")
}

func isNFS(raw string) bool {
	return isRPC(raw) && (strings.Contains(raw, "nfs") || len(raw) >= 28)
}

func hsqlVersion(raw string) string {
	if i := strings.Index(raw, "Version("); i >= 0 {
		rest := raw[i+8:]
		if j := strings.Index(rest, ")"); j > 0 {
			return rest[:j]
		}
	}
	return ""
}

func zkVersion(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(line, "Zookeeper version:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Zookeeper version:"))
		}
	}
	return ""
}

func containsToken(raw, token string) bool {
	return strings.Contains(raw, token)
}

func portHint(port int) string {
	switch port {
	case 5555, 5554, 5037:
		return "adb"
	case 1098, 1099, 1199:
		return "rmi"
	case 8686, 9010:
		return "jmx"
	case 50051:
		return "grpc"
	case 389, 3268:
		return "ldap"
	case 636, 3269:
		return "ldaps"
	case 88, 464:
		return "kerberos"
	case 135, 593:
		return "rpc"
	case 139:
		return "netbios"
	case 53:
		return "dns"
	case 102:
		return "s7comm"
	case 25, 587:
		return "smtp"
	case 143:
		return "imap"
	case 110:
		return "pop3"
	case 5900, 5901, 5902, 5800:
		return "vnc"
	case 873:
		return "rsync"
	case 2049:
		return "nfs"
	case 5432, 5433:
		return "postgresql"
	case 4000:
		return "tidb"
	case 1883, 8883:
		return "mqtt"
	case 5672, 5671:
		return "amqp"
	case 20000:
		return "dnp3"
	case 20880, 22222:
		return "dubbo"
	case 9876:
		return "rocketmq-namesrv"
	case 10909, 10911:
		return "rocketmq-broker"
	case 4369:
		return "epmd"
	case 4447, 9999:
		return "jboss-remoting"
	case 7001, 7002:
		return "weblogic-t3"
	case 502:
		return "modbus"
	case 44818:
		return "enip"
	case 1962:
		return "pcworx"
	case 11740, 1217, 2455:
		return "codesys"
	case 20547:
		return "proconos"
	case 10001:
		return "atg"
	case 5006, 5007:
		return "melsec"
	case 9600:
		return "fins"
	case 789:
		return "crimson"
	case 2404:
		return "iec104"
	case 2181:
		return "zookeeper"
	case 5236:
		return "dm"
	case 54321:
		return "kingbase"
	case 7848:
		return "nacos"
	case 61616, 61613:
		return "activemq"
	case 9042:
		return "cassandra"
	case 9000:
		return "clickhouse"
	case 3690:
		return "svn"
	case 9001:
		return "hsqldb"
	case 1801:
		return "msmq"
	case 50000:
		return "sap-p4"
	default:
		return ""
	}
}

func joinExtra(parts ...string) string {
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return strings.Join(out, " ")
}

func dialTimeout(host string, port int, timeout time.Duration) (net.Conn, error) {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
}

func readRaw(conn net.Conn, payload []byte, timeout time.Duration) ([]byte, error) {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if len(payload) > 0 {
		if _, err := conn.Write(payload); err != nil {
			return nil, err
		}
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if n > 0 {
		return buf[:n], nil
	}
	return nil, err
}
