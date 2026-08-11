package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var legacyToken = strings.Repeat("d", 4)
var machineKeyLinePattern = regexp.MustCompile(`^[0-9A-Fa-f]+,[0-9A-Fa-f]+$`)

type finding struct {
	Path string
	Line int
	Text string
}

func main() {
	root := flag.String("root", ".", "repository root")
	flag.Parse()

	findings, allowed, err := scan(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "brand-check: %v\n", err)
		os.Exit(2)
	}
	for _, item := range findings {
		fmt.Printf("FAIL %s:%d: %s\n", item.Path, item.Line, item.Text)
	}
	if len(findings) > 0 {
		os.Exit(1)
	}
	fmt.Printf("brand-check: PASS (%d reviewed legacy evidence lines)\n", allowed)
}

func scan(root string) ([]finding, int, error) {
	files, err := trackedFiles(root)
	if err != nil {
		return nil, 0, err
	}
	findings := make([]finding, 0)
	allowed := 0
	for _, rel := range files {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, 0, fmt.Errorf("read %s: %w", rel, err)
		}
		if bytes.IndexByte(data, 0) >= 0 {
			continue
		}
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
		lineNo := 0
		for scanner.Scan() {
			lineNo++
			line := scanner.Text()
			if !strings.Contains(strings.ToLower(line), legacyToken) {
				continue
			}
			if allowedLegacyEvidence(rel, line) {
				allowed++
				continue
			}
			findings = append(findings, finding{Path: rel, Line: lineNo, Text: strings.TrimSpace(line)})
		}
		if err := scanner.Err(); err != nil {
			return nil, 0, fmt.Errorf("scan %s: %w", rel, err)
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Path == findings[j].Path {
			return findings[i].Line < findings[j].Line
		}
		return findings[i].Path < findings[j].Path
	})
	return findings, allowed, nil
}

func trackedFiles(root string) ([]string, error) {
	cmd := exec.Command("git", "-C", root, "ls-files", "-z")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("list tracked files: %w", err)
	}
	parts := bytes.Split(output, []byte{0})
	files := make([]string, 0, len(parts))
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}
		files = append(files, filepath.ToSlash(string(part)))
	}
	return files, nil
}

func allowedLegacyEvidence(path, line string) bool {
	trimmed := strings.TrimSpace(line)
	upperToken := strings.ToUpper(legacyToken)
	switch path {
	case "README.md":
		return strings.Contains(line, "github.com/SleepingBag945/"+legacyToken)
	case "deploy/upgrade-server.sh":
		return strings.Contains(line, "/bin/"+legacyToken+"-server")
	case "docs/performance-baselines/g31-2026-08-10.json":
		return oneOf(trimmed,
			`"case": "`+legacyToken+`-help-before",`,
			`"case": "`+legacyToken+`-help-after",`,
			`"case": "`+legacyToken+`-url-poc-off-before",`,
			`"case": "`+legacyToken+`-url-poc-off-after",`,
			`"`+legacyToken+`_help_p95_le_300ms": false,`,
		)
	case "docs/performance-baselines/g32-2026-08-10.json":
		return oneOf(trimmed,
			`"case": "g32-`+legacyToken+`-help-before",`,
			`"case": "g32-`+legacyToken+`-help-after",`,
			`"case": "`+legacyToken+`-url-poc-off-before",`,
			`"case": "g32-`+legacyToken+`-url-poc-off-after",`,
			`"`+legacyToken+`_help_p95_le_300ms": true,`,
		)
	case "scanner/common/config/dict/machineKeys.txt",
		"scanner/gopocs/dict/machineKeys.txt":
		return machineKeyLinePattern.MatchString(line) && strings.Contains(strings.ToUpper(line), upperToken)
	case "scanner/lib/gonmap/nmap-service-probes.go":
		return strings.Contains(line, "match valentinadb")
	case "scanner/common/config/pocs/bes-spark-ejb-rce.yaml",
		"scanner/common/config/pocs/bes-spark-besejb-rce.yaml",
		"scanner/common/config/pocs/tongweb-console-detect.yaml",
		"scanner/common/config/pocs/tongweb-ejb-rce-payload.yaml":
		return trimmed == "author: "+legacyToken
	case "scanner/common/config/pocs/CVE-2017-3881.yaml":
		return strings.Contains(line, "CCCC"+upperToken+"EEEE")
	case "scanner/common/config/pocs/CVE-2019-13101.yaml",
		"scanner/common/config/pocs/hanta-rce.yaml":
		return strings.HasPrefix(trimmed, "# digest:")
	case "scanner/common/config/pocs/jinghang-upload.yaml":
		return strings.Contains(line, legacyToken+".jsp")
	case "scanner/common/config/pocs/ruiyou-ConsoleExternalUploadApi-sql-rce.yaml":
		return strings.Contains(line, legacyToken+".xgi")
	default:
		return false
	}
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
