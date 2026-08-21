package protocol

import (
	"strings"
	"unicode"

	"github.com/P0lar1ght/argus/scanner/structs"
	"github.com/lcvvvv/gonmap"
)

const (
	extraValueMax = 48
	extraTotalMax = 160
	extraKeyMax   = 5
	detailMax     = 180
)

func recordFromFingerprint(fp *gonmap.FingerPrint) structs.ServiceRecord {
	rec := structs.ServiceRecord{Transport: "tcp", Protocol: "tcp", Confidence: "port-hint"}
	if fp == nil {
		return rec
	}
	if proto := CanonicalProtocol(fp.Service); proto != "" {
		rec.Protocol = proto
		if !Unidentified(proto) {
			rec.Confidence = "matched"
		}
	}
	rec.Product = strings.TrimSpace(fp.ProductName)
	rec.Version = strings.TrimSpace(fp.Version)
	rec.Extra = fingerprintExtra(fp)
	return rec
}

func fingerprintExtra(fp *gonmap.FingerPrint) string {
	if fp == nil {
		return ""
	}
	return limitExtra(mergeExtra(
		labeled("host", fp.Hostname),
		normalizeInfo(fp.Info),
		labeled("os", fp.OperatingSystem),
		labeled("device", fp.DeviceType),
	))
}

func bannerExtra(raw, protocol string) string {
	raw = strings.TrimRight(raw, "\x00")
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	specific := specificBannerExtra(raw, protocol)
	if specific != "" && (looksBinary(raw) || suppressGenericBannerExtra(protocol)) {
		return limitExtra(specific)
	}
	if extraKeyCount(specific) >= extraKeyMax {
		return limitExtra(specific)
	}
	return limitExtra(mergeExtra(specific, genericBannerExtra(raw)))
}

func specificBannerExtra(raw, protocol string) string {
	switch protocol {
	case "smb", "netbios", "microsoft-ds":
		return smbExtra([]byte(raw))
	case "netbios-ns":
		return nbstatExtra([]byte(raw))
	case "ssh":
		return labeled("banner", firstBannerLine(raw))
	case "ftp", "smtp", "imap", "pop3", "vnc", "telnet":
		return labeled("banner", firstBannerLine(raw))
	case "ldap", "ldaps":
		return ldapExtra(raw)
	case "snmp":
		return snmpBannerExtra([]byte(raw))
	case "dns", "mdns":
		return dnsBannerExtra([]byte(raw))
	case "redis":
		return redisExtra(raw)
	case "mysql", "mariadb":
		return mysqlExtra([]byte(raw))
	case "memcached":
		return memcachedExtra(raw)
	case "postgresql", "kingbase":
		return postgresExtra(raw)
	case "mongodb":
		return labeled("info", compactPrintable(raw, extraValueMax))
	case "rsync":
		return labeled("banner", firstBannerLine(raw))
	case "amqp":
		return amqpExtra([]byte(raw))
	case "zookeeper":
		return labeled("banner", firstBannerLine(raw))
	case "clickhouse", "cassandra", "activemq", "hsqldb", "dm", "dubbo", "weblogic-t3":
		return labeled("banner", firstBannerLine(raw))
	case "rocketmq", "rocketmq-broker", "rocketmq-namesrv", "epmd", "jboss-remoting", "iiop", "modbus", "pcworx", "codesys", "proconos":
		return labeled("info", compactPrintable(raw, extraValueMax))
	case "kerberos":
		return kerberosExtra(raw)
	case "sip":
		return headerExtras(raw, "Server", "User-Agent")
	case "ssdp":
		return headerExtras(raw, "SERVER", "LOCATION", "ST")
	case "rmi", "jmx":
		return labeled("host", rmiHostName(raw))
	default:
		if strings.Contains(raw, "\xffSMB") {
			return smbExtra([]byte(raw))
		}
		if strings.HasPrefix(raw, "SSH-") {
			return labeled("banner", firstBannerLine(raw))
		}
		if extra := mysqlExtra([]byte(raw)); extra != "" {
			return extra
		}
		if extra := redisExtra(raw); extra != "" {
			return extra
		}
		if extra := memcachedExtra(raw); extra != "" {
			return extra
		}
		return ""
	}
}

func genericBannerExtra(raw string) string {
	if looksBinary(raw) {
		s := compactPrintable(raw, extraValueMax)
		if len(s) < 8 || lowValueInfo(s) {
			return ""
		}
		return labeled("info", s)
	}
	line := firstBannerLine(raw)
	if len(line) < 4 || lowValueInfo(line) {
		return ""
	}
	return labeled("banner", line)
}

func suppressGenericBannerExtra(protocol string) bool {
	switch protocol {
	case "rocketmq", "rocketmq-broker", "rocketmq-namesrv", "epmd", "jboss-remoting", "iiop", "modbus", "pcworx", "codesys", "proconos":
		return true
	default:
		return false
	}
}

// ServiceDetail builds the compact default detail string shown after
// protocol: product, version, then a few key=value extras.
func ServiceDetail(product, version, extra string) string {
	extra = dropDuplicateDetails(limitExtra(extra), product, version)
	detail := strings.TrimSpace(strings.Join(nonEmpty(product, version, extra), " "))
	if len(detail) > detailMax {
		detail = strings.TrimRight(detail[:detailMax], " _")
	}
	return detail
}

func mergeRecord(base, next structs.ServiceRecord) structs.ServiceRecord {
	if next.Protocol != "" {
		base.Protocol = next.Protocol
	}
	if next.Product != "" {
		base.Product = next.Product
	}
	if next.Version != "" {
		base.Version = next.Version
	}
	if next.Transport != "" {
		base.Transport = next.Transport
	}
	if next.Confidence != "" {
		base.Confidence = next.Confidence
	}
	if next.Endpoint != "" {
		base.Endpoint = next.Endpoint
	}
	base.Extra = limitExtra(mergeExtra(base.Extra, next.Extra))
	return base
}

func mergeExtra(parts ...string) string {
	order := make([]string, 0, extraKeyMax)
	vals := map[string]string{}
	for _, part := range parts {
		for _, tok := range tokenizeExtra(part) {
			key, val, ok := strings.Cut(tok, "=")
			if !ok || strings.TrimSpace(key) == "" || strings.TrimSpace(val) == "" {
				continue
			}
			key = strings.ToLower(strings.TrimSpace(key))
			val = compactExtraValue(val)
			if val == "" || lowValueInfo(val) {
				continue
			}
			if _, exists := vals[key]; !exists {
				order = append(order, key)
			}
			vals[key] = val
		}
	}
	out := make([]string, 0, len(order))
	for _, key := range order {
		out = append(out, key+"="+vals[key])
	}
	return strings.Join(out, " ")
}

func limitExtra(extra string) string {
	tokens := strings.Fields(strings.TrimSpace(extra))
	if len(tokens) > extraKeyMax {
		tokens = tokens[:extraKeyMax]
	}
	out := make([]string, 0, len(tokens))
	total := 0
	for _, tok := range tokens {
		if total+len(tok)+1 > extraTotalMax {
			break
		}
		out = append(out, tok)
		total += len(tok) + 1
	}
	return strings.Join(out, " ")
}

func extraKeyCount(extra string) int {
	return len(strings.Fields(strings.TrimSpace(extra)))
}

func dropDuplicateDetails(extra, product, version string) string {
	product = strings.ToLower(strings.TrimSpace(product))
	version = strings.ToLower(strings.TrimSpace(version))
	keep := make([]string, 0, extraKeyMax)
	for _, tok := range strings.Fields(extra) {
		_, val, ok := strings.Cut(tok, "=")
		if !ok {
			continue
		}
		lower := strings.ToLower(strings.ReplaceAll(val, "_", " "))
		if product != "" && lower == product {
			continue
		}
		if product != "" && len(lower) >= 8 && (strings.Contains(product, lower) || strings.Contains(lower, product)) {
			continue
		}
		if version != "" && lower == version {
			continue
		}
		keep = append(keep, tok)
	}
	return strings.Join(keep, " ")
}

func tokenizeExtra(part string) []string {
	part = strings.TrimSpace(part)
	if part == "" {
		return nil
	}
	if strings.Contains(part, "=") {
		return strings.Fields(part)
	}
	if key, val, ok := strings.Cut(part, ":"); ok && !strings.Contains(key, " ") && len(strings.TrimSpace(key)) <= 16 {
		return []string{labeled(strings.TrimSpace(key), strings.TrimSpace(val))}
	}
	return []string{labeled("banner", part)}
}

func normalizeInfo(info string) string {
	info = strings.TrimSpace(info)
	if info == "" {
		return ""
	}
	if strings.Contains(info, "=") {
		return strings.Join(strings.Fields(strings.ReplaceAll(info, " ", "_")), " ")
	}
	if key, val, ok := strings.Cut(info, ":"); ok {
		return labeled(strings.TrimSpace(key), strings.TrimSpace(val))
	}
	return labeled("info", info)
}

func labeled(key, value string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	value = compactExtraValue(value)
	if key == "" || value == "" {
		return ""
	}
	return key + "=" + value
}

func compactExtraValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	value = strings.Join(strings.Fields(value), "_")
	if len(value) > extraValueMax {
		value = value[:extraValueMax]
	}
	return value
}

func firstBannerLine(raw string) string {
	line, _, _ := strings.Cut(raw, "\n")
	return strings.TrimSpace(strings.TrimSuffix(line, "\r"))
}

func lowValueInfo(s string) bool {
	switch strings.ToLower(strings.Trim(s, "_")) {
	case "", "smb", "http", "https", "public", "ok", "pong", "imok", "null":
		return true
	default:
		return false
	}
}

func looksBinary(raw string) bool {
	n := len(raw)
	if n > 80 {
		n = 80
	}
	if n == 0 {
		return false
	}
	bad := 0
	for i := 0; i < n; i++ {
		c := raw[i]
		if c == '\n' || c == '\r' || c == '\t' {
			continue
		}
		if c < 32 || c >= 127 {
			bad++
		}
	}
	return bad*4 >= n
}

func smbExtra(raw []byte) string {
	names := utf16LEStrings(raw)
	var host, workgroup, osName string
	for _, name := range names {
		switch classifySMBString(name) {
		case "os":
			if osName == "" {
				osName = name
			}
		default:
			if workgroup == "" {
				workgroup = name
			} else if host == "" && !strings.EqualFold(name, workgroup) {
				host = name
			}
		}
	}
	return mergeExtra(labeled("workgroup", workgroup), labeled("host", host), labeled("os", osName))
}

func classifySMBString(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.Contains(lower, "windows"), strings.Contains(lower, "unix"),
		strings.Contains(lower, "linux"), strings.Contains(lower, "samba"),
		strings.Contains(lower, "macos"), strings.Contains(lower, "darwin"):
		return "os"
	default:
		return "name"
	}
}

func utf16LEStrings(raw []byte) []string {
	var (
		out []string
		cur []byte
	)
	flush := func() {
		if len(cur) < 2 {
			cur = cur[:0]
			return
		}
		out = append(out, string(cur))
		cur = cur[:0]
	}
	for i := 0; i+1 < len(raw); i += 2 {
		if raw[i+1] == 0 && raw[i] >= 0x20 && raw[i] < 0x7f && unicode.IsPrint(rune(raw[i])) {
			cur = append(cur, raw[i])
			continue
		}
		flush()
	}
	flush()
	return out
}

func nbstatExtra(raw []byte) string {
	var host, workgroup string
	for i := 0; i+16 <= len(raw); i++ {
		if !nbstatNameChar(raw[i]) {
			continue
		}
		n := 0
		for n < 15 && i+n < len(raw) && raw[i+n] != 0 && raw[i+n] != ' ' {
			if !nbstatNameChar(raw[i+n]) {
				n = 0
				break
			}
			n++
		}
		if n < 2 || i+15 >= len(raw) {
			continue
		}
		name := strings.TrimSpace(string(raw[i : i+n]))
		switch raw[i+15] {
		case 0x00, 0x20:
			if host == "" {
				host = name
			}
		case 0x1c, 0x1e, 0x80:
			if workgroup == "" {
				workgroup = name
			}
		}
	}
	return mergeExtra(labeled("host", host), labeled("workgroup", workgroup))
}

func nbstatNameChar(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '-' || b == '_'
}

func ldapExtra(raw string) string {
	for _, marker := range []string{"dnsHostName", "defaultNamingContext", "namingContexts"} {
		if i := strings.Index(raw, marker); i >= 0 {
			return labeled("info", compactPrintable(raw[i:], extraValueMax))
		}
	}
	if i := strings.Index(raw, "DC="); i >= 0 {
		return labeled("dn", compactPrintable(raw[i:], extraValueMax))
	}
	return ""
}

func snmpBannerExtra(raw []byte) string {
	s := compactPrintable(string(raw), extraValueMax)
	if len(s) < 4 || strings.EqualFold(s, "public") {
		return ""
	}
	return labeled("sys", s)
}

func dnsBannerExtra(raw []byte) string {
	s := compactPrintable(string(raw), extraValueMax)
	if !strings.Contains(strings.ToLower(s), "version") {
		return ""
	}
	return labeled("txt", s)
}

func redisExtra(raw string) string {
	lower := strings.ToLower(raw)
	if i := strings.Index(lower, "redis_version:"); i >= 0 {
		return labeled("redis", firstBannerLine(raw[i+len("redis_version:"):]))
	}
	line := firstBannerLine(raw)
	if strings.HasPrefix(line, "-ERR") || strings.HasPrefix(line, "+") || strings.HasPrefix(line, "-NOAUTH") {
		return labeled("banner", line)
	}
	return ""
}

func mysqlExtra(raw []byte) string {
	if len(raw) < 7 || raw[4] != 0x0a {
		return ""
	}
	end := 5
	for end < len(raw) && raw[end] != 0 && end < 5+extraValueMax {
		if raw[end] < 32 || raw[end] >= 127 {
			return ""
		}
		end++
	}
	if end-5 < 3 {
		return ""
	}
	return labeled("server", string(raw[5:end]))
}

func memcachedExtra(raw string) string {
	line := firstBannerLine(raw)
	if strings.HasPrefix(strings.ToUpper(line), "VERSION ") {
		return labeled("server", strings.TrimSpace(line[8:]))
	}
	if strings.HasPrefix(strings.ToUpper(line), "STAT ") {
		return labeled("stat", line)
	}
	return ""
}

func postgresExtra(raw string) string {
	if raw == "" || (raw[0] != 'E' && raw[0] != 'R') {
		return ""
	}
	msg, code := "", ""
	parts := strings.Split(raw, "\x00")
	for _, part := range parts {
		if len(part) < 2 {
			continue
		}
		switch part[0] {
		case 'M':
			msg = part[1:]
		case 'C':
			code = part[1:]
		}
	}
	return mergeExtra(labeled("code", code), labeled("msg", msg))
}

func amqpExtra(raw []byte) string {
	if len(raw) < 8 || string(raw[:4]) != "AMQP" {
		return ""
	}
	return labeled("amqp", strings.Trim(strings.Trim(string(raw[4:8]), "\x00"), "."))
}

func kerberosExtra(raw string) string {
	s := compactPrintable(raw, extraValueMax)
	if len(s) < 3 || strings.EqualFold(s, "krb") {
		return ""
	}
	return labeled("realm", s)
}

func headerExtras(raw string, keys ...string) string {
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		if val := headerLineValue(raw, key); val != "" {
			parts = append(parts, labeled(strings.ToLower(key), val))
		}
	}
	return mergeExtra(parts...)
}

func headerLineValue(raw, key string) string {
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

func rmiHostName(raw string) string {
	if len(raw) < 5 || raw[0] != 0x4e {
		return ""
	}
	n := int(raw[1])<<8 | int(raw[2])
	if n <= 0 || n > 255 || len(raw) < 3+n {
		return ""
	}
	return raw[3 : 3+n]
}

func compactPrintable(raw string, max int) string {
	var b strings.Builder
	for _, r := range raw {
		if r >= 32 && r < 127 {
			b.WriteRune(r)
		} else if b.Len() >= 4 {
			break
		} else {
			b.Reset()
		}
		if b.Len() >= max {
			break
		}
	}
	return strings.TrimSpace(b.String())
}
