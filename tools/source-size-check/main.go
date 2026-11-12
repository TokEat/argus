package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	goLineLimit = 800
	tsLineLimit = 700
)

type finding struct {
	Path   string
	Lines  int
	Reason string
}

type scanResult struct {
	Violations       []finding
	BaselineWarnings []finding
}

func main() {
	root := flag.String("root", ".", "repository root")
	baselinePath := flag.String("baseline", ".source-size-baseline", "baseline file")
	flag.Parse()

	baseline, err := loadBaseline(*baselinePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "source-size-check: %v\n", err)
		os.Exit(2)
	}
	result, err := scan(*root, baseline)
	if err != nil {
		fmt.Fprintf(os.Stderr, "source-size-check: %v\n", err)
		os.Exit(2)
	}
	for _, item := range result.BaselineWarnings {
		fmt.Printf("WARN %s: %d lines (%s)\n", item.Path, item.Lines, item.Reason)
	}
	for _, item := range result.Violations {
		fmt.Printf("FAIL %s: %d lines (%s)\n", item.Path, item.Lines, item.Reason)
	}
	if len(result.Violations) > 0 {
		os.Exit(1)
	}
	fmt.Printf("source-size-check: PASS (%d baseline exceptions)\n", len(result.BaselineWarnings))
}

func scan(root string, baseline map[string]int) (scanResult, error) {
	result := scanResult{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if entry.IsDir() {
			if rel != "." && excludedDir(rel, entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		limit, tracked := sourceLimit(rel)
		if !tracked {
			return nil
		}
		lines, err := countLines(path)
		if err != nil {
			return err
		}
		cap, hasBaseline := baseline[rel]
		switch {
		case hasBaseline && lines > cap:
			result.Violations = append(result.Violations, finding{rel, lines, fmt.Sprintf("exceeds baseline %d", cap)})
		case hasBaseline && lines > limit:
			result.BaselineWarnings = append(result.BaselineWarnings, finding{rel, lines, fmt.Sprintf("temporary baseline %d; threshold %d", cap, limit)})
		case !hasBaseline && lines > limit:
			result.Violations = append(result.Violations, finding{rel, lines, fmt.Sprintf("exceeds threshold %d", limit)})
		}
		return nil
	})
	sort.Slice(result.Violations, func(i, j int) bool { return result.Violations[i].Path < result.Violations[j].Path })
	sort.Slice(result.BaselineWarnings, func(i, j int) bool { return result.BaselineWarnings[i].Path < result.BaselineWarnings[j].Path })
	return result, err
}

func excludedDir(rel, name string) bool {
	switch name {
	case ".git", ".worktrees", "node_modules", "generated", "dist", "release", "bin", "data", "datas", "runtime":
		return true
	}
	return rel == "scanner/lib" || strings.HasPrefix(rel, "scanner/lib/")
}

func sourceLimit(rel string) (int, bool) {
	if strings.HasSuffix(rel, ".pb.go") {
		return 0, false
	}
	switch strings.ToLower(filepath.Ext(rel)) {
	case ".go":
		return goLineLimit, true
	case ".ts", ".tsx":
		return tsLineLimit, true
	default:
		return 0, false
	}
}

func countLines(path string) (int, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	lines := 0
	for scanner.Scan() {
		lines++
	}
	return lines, scanner.Err()
}

func loadBaseline(path string) (map[string]int, error) {
	baseline := map[string]int{}
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return baseline, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid baseline line %q", line)
		}
		limit, err := strconv.Atoi(parts[1])
		if err != nil || limit <= 0 {
			return nil, fmt.Errorf("invalid baseline limit in %q", line)
		}
		baseline[filepath.ToSlash(parts[0])] = limit
	}
	return baseline, scanner.Err()
}
