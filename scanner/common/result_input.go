package common

import (
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/P0lar1ght/argus/scanner/ddout"
	"github.com/P0lar1ght/argus/scanner/structs"
	"github.com/P0lar1ght/argus/scanner/utils"
)

type ingestedScanInput struct {
	Targets      []string
	Fingers      map[string][]string
	ReusedAlive  int
	ReusedPorts  int
	SkipDiscover bool
}

func resolveScanInputFile(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	info, err := os.Stat(path)
	if err != nil {
		return path
	}
	if info.IsDir() {
		return filepath.Join(path, "result.txt")
	}
	return path
}

// isFileLikeInput reports whether an input that does not exist on disk still
// looks like a file path (path separators or a common result-file extension).
// It is used to report "file not found" instead of silently treating the name
// as a domain target. CIDR and other typed inputs are deliberately excluded.
func isFileLikeInput(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || strings.Contains(s, "://") {
		return false
	}
	if strings.ContainsAny(s, "/\\") && !utils.IsCIDR(s) {
		return true
	}
	lower := strings.ToLower(s)
	for _, ext := range []string{".txt", ".log", ".json", ".csv", ".lst", ".yaml", ".yml", ".result"} {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

func ingestScanInputLines(lines []string) ingestedScanInput {
	out := ingestedScanInput{Fingers: map[string][]string{}}
	var hosts []string
	var ports []string
	currentWEBURI := ""
	portIPs := map[string]struct{}{}

	add := func(list *[]string, value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		for _, existing := range *list {
			if existing == value {
				return
			}
		}
		*list = append(*list, value)
	}

	for _, raw := range lines {
		if isWEBChildLine(raw) {
			ingestWEBChildLine(&out, currentWEBURI, raw)
			continue
		}
		currentWEBURI = ""
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if msg, ok, err := ddout.DecodeFindingLine(line); err == nil && ok {
			ingestFinding(&out, msg, add, &hosts, &ports, portIPs)
			continue
		}
		if utils.GetInputType(line) != structs.TypeUnSupport {
			add(&out.Targets, line)
			continue
		}
		switch {
		case strings.HasPrefix(line, "[Alive] "):
			if ip := firstInputField(strings.TrimPrefix(line, "[Alive] ")); utils.IsIPv4(ip) {
				add(&hosts, ip)
				out.ReusedAlive++
			}
		case strings.HasPrefix(line, "[Port] "):
			ingestReusedTextPort(&out, strings.TrimPrefix(line, "[Port] "), add, &hosts, &ports, portIPs)
		case strings.HasPrefix(line, "[Protocol] "):
			ingestReusedTextPort(&out, strings.TrimPrefix(line, "[Protocol] "), add, &hosts, &ports, portIPs)
		case strings.HasPrefix(line, "[WEB] "), strings.HasPrefix(line, "[Web] "):
			rest := strings.TrimPrefix(line, "[WEB] ")
			rest = strings.TrimPrefix(rest, "[Web] ")
			if uri := firstInputField(rest); uri != "" {
				add(&out.Targets, uri)
				currentWEBURI = uri
			}
		case strings.HasPrefix(line, "[Path] "), strings.HasPrefix(line, "[Topo] "):
			continue
		case strings.HasPrefix(line, "[Finger] "):
			ingestLegacyFingerLine(&out, line)
		case strings.HasPrefix(line, "[Active-Finger] "):
			if uri := firstInputField(strings.TrimPrefix(line, "[Active-Finger] ")); uri != "" {
				add(&out.Targets, uri)
			}
		case strings.HasSuffix(line, " open"):
			ipPort := strings.TrimSpace(strings.TrimSuffix(line, " open"))
			if utils.IsIPPort(ipPort) {
				ingestReusedPort(&out, ipPort, add, &ports, portIPs)
			}
		}
	}

	for _, ip := range hosts {
		if _, hasPort := portIPs[ip]; !hasPort {
			add(&out.Targets, ip)
		}
	}
	out.Targets = append(out.Targets, ports...)
	out.SkipDiscover = out.ReusedAlive > 0 || out.ReusedPorts > 0
	return out
}

func ingestFinding(out *ingestedScanInput, msg ddout.OutputMessage, add func(*[]string, string), hosts, ports *[]string, portIPs map[string]struct{}) {
	switch strings.TrimSpace(msg.Type) {
	case "IPAlive":
		if utils.IsIPv4(msg.IP) {
			add(hosts, msg.IP)
			out.ReusedAlive++
		}
	case "PortScan", "Protocol", "Nmap":
		if isUDPFinding(msg) {
			if utils.IsIPv4(msg.IP) {
				add(hosts, msg.IP)
				out.ReusedAlive++
			}
			return
		}
		ingestReusedPort(out, net.JoinHostPort(strings.TrimSpace(msg.IP), strings.TrimSpace(msg.Port)), add, ports, portIPs)
	case "Web", "Active-Finger":
		if strings.TrimSpace(msg.URI) != "" {
			add(&out.Targets, msg.URI)
		}
	case "Path", "Topo":
		return
	case "Finger":
		if strings.TrimSpace(msg.URI) != "" && len(msg.Finger) > 0 {
			out.Fingers[msg.URI] = append([]string(nil), msg.Finger...)
		}
	}
	if strings.TrimSpace(msg.URI) != "" && utils.GetInputType(msg.URI) != structs.TypeUnSupport {
		add(&out.Targets, msg.URI)
	}
}

func isUDPFinding(msg ddout.OutputMessage) bool {
	if strings.EqualFold(strings.TrimSpace(msg.Transport), "udp") {
		return true
	}
	return strings.HasSuffix(strings.TrimSpace(msg.Port), "/udp")
}

func ingestReusedTextPort(out *ingestedScanInput, rest string, add func(*[]string, string), hosts, ports *[]string, portIPs map[string]struct{}) {
	transport, endpoint := ddout.ParseServiceLineRest(rest)
	if transport == "udp" {
		if host, _, err := net.SplitHostPort(endpoint); err == nil && utils.IsIPv4(host) {
			add(hosts, host)
			out.ReusedAlive++
		}
		return
	}
	ingestReusedPort(out, endpoint, add, ports, portIPs)
}

func ingestReusedPort(out *ingestedScanInput, ipPort string, add func(*[]string, string), ports *[]string, portIPs map[string]struct{}) {
	ipPort = strings.TrimSpace(ipPort)
	if !utils.IsIPPort(ipPort) {
		return
	}
	host, _, err := net.SplitHostPort(ipPort)
	if err != nil {
		return
	}
	add(ports, ipPort)
	portIPs[host] = struct{}{}
	out.ReusedPorts++
}

func ingestLegacyFingerLine(out *ingestedScanInput, line string) {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return
	}
	uri := fields[1]
	tf := fields[2]
	if strings.HasPrefix(uri, "http") && len(fields) > 3 {
		tf = fields[3]
	}
	if len(tf) <= 2 {
		return
	}
	// 旧格式 [Finger] <uri> [a,b]：指纹列表带方括号，剥掉两侧括号。
	// 新格式 [Finger] <uri> a,b（formatServiceFingerLine 产物）无括号，按原样解析。
	if strings.HasPrefix(tf, "[") && strings.HasSuffix(tf, "]") {
		tf = tf[1 : len(tf)-1]
	}
	out.Fingers[uri] = parseFingerNames(tf)
}

func ingestWEBChildLine(out *ingestedScanInput, uri, line string) {
	if out == nil || strings.TrimSpace(uri) == "" {
		return
	}
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "[Finger] ") {
		return
	}
	fingers := parseFingerNames(firstInputField(strings.TrimPrefix(trimmed, "[Finger] ")))
	if len(fingers) == 0 {
		return
	}
	out.Fingers[uri] = fingers
}

func parseFingerNames(value string) []string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		value = value[1 : len(value)-1]
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func isWEBChildLine(line string) bool {
	if line == "" || (line[0] != ' ' && line[0] != '\t') {
		return false
	}
	trimmed := strings.TrimSpace(line)
	for _, prefix := range []string{"[Finger]", "[Certificates]", "[Code]", "[Size]", "[Redirect]", "[Title]"} {
		if strings.HasPrefix(trimmed, prefix) {
			return true
		}
	}
	return false
}

func firstInputField(value string) string {
	value = strings.TrimSpace(value)
	if i := strings.IndexAny(value, " \t"); i >= 0 {
		return value[:i]
	}
	return value
}
