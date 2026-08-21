package localplanner

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/P0lar1ght/argus/scanner/ddout"
	"github.com/P0lar1ght/argus/scanner/internal/localstate"
	"github.com/P0lar1ght/argus/scanner/structs"
	"github.com/P0lar1ght/argus/scanner/utils"
)

type dataResultHistory struct {
	targetSources map[string]string
	ipSources     map[string]string
}

func (history dataResultHistory) MatchTarget(target string) (string, bool) {
	if history.targetSources == nil {
		return "", false
	}
	key := historyTargetKey(target)
	if key == "" {
		return "", false
	}
	source, ok := history.targetSources[key]
	return source, ok
}

func (history dataResultHistory) MatchIP(ip string) (string, bool) {
	if history.ipSources == nil {
		return "", false
	}
	source, ok := history.ipSources[strings.TrimSpace(ip)]
	return source, ok
}

func dataResultRoot(outputFile string) string {
	dir := filepath.Dir(filepath.Clean(outputFile))
	parent := filepath.Dir(dir)
	if strings.EqualFold(filepath.Base(parent), "datas") {
		return parent
	}
	return "datas"
}

func loadDataResultHistory(root, currentOutputFile string) (dataResultHistory, []string) {
	history := dataResultHistory{targetSources: map[string]string{}, ipSources: map[string]string{}}
	root = strings.TrimSpace(root)
	if root == "" {
		return history, nil
	}
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return history, nil
	}
	if err != nil {
		return history, []string{fmt.Sprintf("read datas history root %q: %v", root, err)}
	}
	currentDir := filepath.Dir(filepath.Clean(currentOutputFile))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		runDir := filepath.Join(root, entry.Name())
		if sameHistoryPath(runDir, currentDir) {
			continue
		}
		if trusted := completedDataRun(runDir); !trusted {
			continue
		}
		history.addResultTXT(filepath.Join(runDir, "result.txt"), entry.Name())
	}
	return history, nil
}

func completedDataRun(runDir string) bool {
	summaryPath := filepath.Join(runDir, "summary.txt")
	file, err := os.Open(summaryPath)
	if os.IsNotExist(err) {
		// Legacy datas directories only had result.txt/html. Treat a non-empty
		// result.txt as trusted finding history, but do not infer zero-finding
		// target coverage from it.
		if info, statErr := os.Stat(filepath.Join(runDir, "result.txt")); statErr == nil && info.Size() > 0 {
			return true
		}
		return false
	}
	if err != nil {
		return false
	}
	defer file.Close()
	values := map[string]string{}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		key, value, ok := strings.Cut(line, "=")
		if ok {
			values[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	if err := scanner.Err(); err != nil {
		return false
	}
	return values["status"] == "completed" && values["terminal_status"] == "completed"
}

func (history dataResultHistory) addResultTXT(path, source string) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		history.addResultLine(scanner.Text(), source)
	}
}

func (history dataResultHistory) addResultLine(line, source string) {
	if message, ok, err := ddout.DecodeFindingLine(line); err == nil && ok {
		history.addFinding(message, source)
		return
	}
	if isHistoryWEBChildLine(line) {
		return
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	var target string
	switch {
	case strings.HasPrefix(line, "[Alive] "):
		target = firstField(strings.TrimPrefix(line, "[Alive] "))
	case strings.HasPrefix(line, "[Port] "):
		target = historyServiceTarget(strings.TrimPrefix(line, "[Port] "))
	case strings.HasPrefix(line, "[Protocol] "):
		target = historyServiceTarget(strings.TrimPrefix(line, "[Protocol] "))
	case strings.HasPrefix(line, "[WEB] "), strings.HasPrefix(line, "[Web] "):
		rest := strings.TrimPrefix(line, "[WEB] ")
		rest = strings.TrimPrefix(rest, "[Web] ")
		target = firstField(rest)
	case strings.HasPrefix(line, "[Finger] "):
		target = firstField(strings.TrimPrefix(line, "[Finger] "))
	case strings.HasPrefix(line, "[Active-Finger] "):
		target = firstField(strings.TrimPrefix(line, "[Active-Finger] "))
	case strings.HasPrefix(line, "[Domain] "):
		rest := strings.TrimSpace(strings.TrimPrefix(line, "[Domain] "))
		if before, after, ok := strings.Cut(rest, " -> "); ok {
			history.addTarget(before, source)
			for _, ip := range strings.Split(after, ",") {
				history.addIP(ip, source)
			}
		}
		return
	}
	if target != "" {
		history.addTarget(target, source)
	}
}

func (history dataResultHistory) addFinding(message ddout.OutputMessage, source string) {
	for _, target := range []string{message.URI, message.GoPoc.Target, message.Domain} {
		history.addTarget(target, source)
	}
	for _, ip := range message.IPs {
		history.addIP(ip, source)
	}
	if ip := strings.TrimSpace(message.IP); ip != "" {
		history.addIP(ip, source)
		if port := strings.TrimSpace(message.Port); port != "" && !strings.EqualFold(message.Transport, "udp") && !strings.HasSuffix(port, "/udp") {
			history.addTarget(net.JoinHostPort(ip, port), source)
		}
	}
}

func (history dataResultHistory) addTarget(target, source string) {
	key := historyTargetKey(target)
	if key == "" {
		return
	}
	if existing, ok := history.targetSources[key]; ok && existing <= source {
		return
	}
	history.targetSources[key] = source
	if ip := targetIP(target); ip != "" {
		history.addIP(ip, source)
	}
}

func (history dataResultHistory) addIP(value, source string) {
	ip := net.ParseIP(strings.TrimSpace(strings.Trim(value, "[]")))
	if ip == nil || ip.To4() == nil {
		return
	}
	key := ip.String()
	if existing, ok := history.ipSources[key]; ok && existing <= source {
		return
	}
	history.ipSources[key] = source
}

func targetIP(target string) string {
	target = strings.TrimSpace(target)
	if ip := net.ParseIP(target); ip != nil && ip.To4() != nil {
		return ip.String()
	}
	if host, _, err := net.SplitHostPort(target); err == nil {
		if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil && ip.To4() != nil {
			return ip.String()
		}
	}
	if parsed, err := url.Parse(target); err == nil && parsed.Host != "" {
		if ip := net.ParseIP(parsed.Hostname()); ip != nil && ip.To4() != nil {
			return ip.String()
		}
	}
	return ""
}

func historyServiceTarget(rest string) string {
	transport, endpoint := ddout.ParseServiceLineRest(rest)
	if transport == "udp" {
		host, _, err := net.SplitHostPort(endpoint)
		if err != nil {
			return ""
		}
		return host
	}
	return endpoint
}

func isHistoryWEBChildLine(line string) bool {
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

func firstField(value string) string {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func historyTargetKey(target string) string {
	target = localstate.NormalizeTargetForState(strings.TrimSpace(target))
	if target == "" || utils.GetInputType(target) == structs.TypeUnSupport {
		return ""
	}
	if parsed, err := url.Parse(target); err == nil && parsed.Scheme != "" && parsed.Host != "" {
		parsed.Scheme = strings.ToLower(parsed.Scheme)
		parsed.Host = strings.ToLower(parsed.Host)
		if (parsed.Scheme == "http" && strings.HasSuffix(parsed.Host, ":80")) || (parsed.Scheme == "https" && strings.HasSuffix(parsed.Host, ":443")) {
			host := strings.TrimSuffix(strings.TrimSuffix(parsed.Host, ":80"), ":443")
			parsed.Host = host
		}
		return parsed.String()
	}
	return strings.ToLower(target)
}

func sameHistoryPath(left, right string) bool {
	leftAbs, leftErr := filepath.Abs(filepath.Clean(left))
	rightAbs, rightErr := filepath.Abs(filepath.Clean(right))
	return leftErr == nil && rightErr == nil && strings.EqualFold(leftAbs, rightAbs)
}

func sortedHistoryTargets(history dataResultHistory) []string {
	keys := make([]string, 0, len(history.targetSources))
	for key := range history.targetSources {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
