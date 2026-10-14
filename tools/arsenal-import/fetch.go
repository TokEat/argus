package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// runFetch 克隆/更新源仓库到缓存目录，记录 commit SHA 与 LICENSE 摘要，
// 并枚举各源 Path 下的候选文件（yaml/yml/json）。
func runFetch(opt *options) error {
	if err := os.MkdirAll(opt.cache, 0o755); err != nil {
		return err
	}
	manifest := FetchManifest{FetchedAt: time.Now()}
	for _, spec := range sourceCatalog {
		sf := fetchOne(opt, spec)
		manifest.Sources = append(manifest.Sources, sf)
		status := "ok"
		if sf.Err != "" {
			status = "ERROR: " + sf.Err
		}
		fmt.Printf("[fetch] %-16s sha=%.12s files=%-5d %s\n", spec.Name, sf.SHA, len(sf.Files), status)
	}
	if err := writePhase(opt.workdir, "fetch", manifest); err != nil {
		return err
	}
	fmt.Printf("\n清单已写入 %s\n", phasePath(opt.workdir, "fetch"))
	return nil
}

func fetchOne(opt *options, spec SourceSpec) SourceFetch {
	sf := SourceFetch{Spec: spec}
	dir := filepath.Join(opt.cache, spec.Name)
	repoURL := "https://" + spec.Repo + ".git"

	if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
		cmd := exec.Command("git", "clone", "--depth", "1", repoURL, dir)
		if out, err := cmd.CombinedOutput(); err != nil {
			sf.Err = fmt.Sprintf("clone: %v: %s", err, strings.TrimSpace(string(out)))
			return sf
		}
	} else {
		cmd := exec.Command("git", "-C", dir, "pull", "--ff-only")
		if out, err := cmd.CombinedOutput(); err != nil {
			sf.Err = fmt.Sprintf("pull: %v: %s", err, strings.TrimSpace(string(out)))
			return sf
		}
	}
	sf.Dir = dir
	sf.SHA = gitOutput(dir, "rev-parse", "HEAD")
	sf.Branch = gitOutput(dir, "rev-parse", "--abbrev-ref", "HEAD")
	sf.License = detectLicense(dir)
	sf.Files = listSourceFiles(dir, spec.Paths)
	return sf
}

func gitOutput(dir string, args ...string) string {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func detectLicense(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		name := strings.ToLower(e.Name())
		if strings.HasPrefix(name, "license") || strings.HasPrefix(name, "copying") {
			data, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				continue
			}
			line := strings.TrimSpace(strings.SplitN(string(data), "\n", 2)[0])
			if line != "" {
				return line
			}
			return e.Name()
		}
	}
	return ""
}

// listSourceFiles 枚举源目录下指定 Paths 的规则文件（相对源根，正斜杠）。
func listSourceFiles(dir string, paths []string) []string {
	var files []string
	seen := map[string]bool{}
	for _, p := range paths {
		root := filepath.Join(dir, filepath.FromSlash(p))
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			lower := strings.ToLower(info.Name())
			if !strings.HasSuffix(lower, ".yaml") && !strings.HasSuffix(lower, ".yml") && !strings.HasSuffix(lower, ".json") {
				return nil
			}
			rel, err := filepath.Rel(dir, path)
			if err != nil {
				return nil
			}
			rel = filepath.ToSlash(rel)
			if !seen[rel] {
				seen[rel] = true
				files = append(files, rel)
			}
			return nil
		})
	}
	sort.Strings(files)
	return files
}
