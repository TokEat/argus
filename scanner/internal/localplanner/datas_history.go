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

func dataResultRoot(outputFile string) string {
	dir := filepath.Dir(filepath.Clean(outputFile))
	parent := filepath.Dir(dir)
	if strings.EqualFold(filepath.Base(parent), "datas") {
		return parent
	}
	return "datas"
}

func loadDataResultHistory(root, currentOutputFile string) (dataResultHistory, []string) {
	history := dataResultHistory{targetSources: map[string]string{}}
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
		history.addTargetsTSV(filepath.Join(runDir, "targets.tsv"), entry.Name())
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

func (history dataResultHistory) addTargetsTSV(path, source string) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 16*1024*1024)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		if lineNumber <= 2 || strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		fields := splitSimpleTSV(scanner.Text())
		if len(fields) < 6 {
			continue
		}
		action := strings.ToLower(strings.TrimSpace(fields[4]))
		if action != "full" && action != "incremental" {
			continue
		}
		history.addTarget(fields[2], source)
	}
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
		if target := targetFromResultLine(scanner.Text()); target != "" {
			history.addTarget(target, source)
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
}

func targetFromResultLine(line string) string {
	if message, ok, err := ddout.DecodeFindingLine(line); err == nil && ok {
		return targetFromFinding(message)
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	switch {
	case strings.HasPrefix(line, "[Alive] "):
		return firstField(strings.TrimPrefix(line, "[Alive] "))
	case strings.HasPrefix(line, "[Port] "):
		return firstField(strings.TrimPrefix(line, "[Port] "))
	case strings.HasPrefix(line, "[Web] "):
		return firstField(strings.TrimPrefix(line, "[Web] "))
	case strings.HasPrefix(line, "[Finger] "):
		return firstField(strings.TrimPrefix(line, "[Finger] "))
	case strings.HasPrefix(line, "[Active-Finger] "):
		return firstField(strings.TrimPrefix(line, "[Active-Finger] "))
	case strings.HasPrefix(line, "[Domain] "):
		rest := strings.TrimSpace(strings.TrimPrefix(line, "[Domain] "))
		if before, _, ok := strings.Cut(rest, " -> "); ok {
			return before
		}
	}
	return ""
}

func firstField(value string) string {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func targetFromFinding(message ddout.OutputMessage) string {
	if value := strings.TrimSpace(message.URI); value != "" {
		return value
	}
	if value := strings.TrimSpace(message.GoPoc.Target); value != "" {
		return value
	}
	if value := strings.TrimSpace(message.Domain); value != "" {
		return value
	}
	if value := strings.TrimSpace(message.IP); value != "" {
		if port := strings.TrimSpace(message.Port); port != "" {
			return net.JoinHostPort(value, port)
		}
		return value
	}
	return ""
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

func splitSimpleTSV(line string) []string {
	parts := strings.Split(strings.TrimRight(line, "\r\n"), "\t")
	for index := range parts {
		parts[index] = strings.ReplaceAll(parts[index], `\t`, "\t")
		parts[index] = strings.ReplaceAll(parts[index], `\n`, "\n")
		parts[index] = strings.ReplaceAll(parts[index], `\r`, "\r")
		parts[index] = strings.ReplaceAll(parts[index], `\\`, `\`)
	}
	return parts
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
