package loader

import (
	"context"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/parsers"
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
	"github.com/projectdiscovery/ratelimit"
)

func TestCompileTemplatesOncePreservesSelection(t *testing.T) {
	store, paths, targets := fixtureLibrary(t, 12, 8, 6)
	for target, pocs := range targets {
		targets[target] = append(append([]string{}, pocs...), "Tags@demo@Tags", filepath.Base(paths[0]), filepath.Base(paths[1]))
	}
	exclude := []string{"skipme"}
	severities := []string{"info", "low"}

	legacy := map[string][]string{}
	for target, pocs := range targets {
		legacy[target] = templateIDs(legacyLoadTemplates(store, embed.FS{}, paths, pocs, exclude, severities))
	}
	names := unionNames(targets)
	templates.ResetTemplateCache()
	compiled := store.CompileTemplates(embed.FS{}, paths, names, exclude, severities, false)
	optimized := map[string][]string{}
	for target, pocs := range targets {
		optimized[target] = templateIDs(SelectCompiledTemplates(compiled, pocs, false, false))
	}
	for target, want := range legacy {
		got := optimized[target]
		if len(got) != len(want) {
			t.Fatalf("target %s selected %v, legacy selected %v", target, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("target %s selected %v, legacy selected %v", target, got, want)
			}
		}
	}
}

func TestCompileTemplatesSkipsUnrequestedFiles(t *testing.T) {
	store, paths, targets := fixtureLibrary(t, 20, 8, 8)
	names := unionNames(targets)

	templates.ResetTemplateCache()
	templates.ResetTemplateParseLoads()
	var wg sync.WaitGroup
	for _, pocs := range targets {
		pocs := append([]string(nil), pocs...)
		wg.Add(1)
		go func() {
			defer wg.Done()
			legacyLoadTemplates(store, embed.FS{}, paths, pocs, nil, nil)
		}()
	}
	wg.Wait()
	legacyLoads := templates.TemplateParseLoads()

	templates.ResetTemplateCache()
	templates.ResetTemplateParseLoads()
	compiled := store.CompileTemplates(embed.FS{}, paths, names, nil, nil, false)
	onceLoads := templates.TemplateParseLoads()
	if len(compiled) != 8 {
		t.Fatalf("compiled %d templates, want 8", len(compiled))
	}
	if onceLoads > 8 {
		t.Fatalf("compile-once read %d template bodies, want at most 8", onceLoads)
	}
	if legacyLoads < uint64(len(paths)) {
		t.Fatalf("per-target load read %d template bodies, want at least %d", legacyLoads, len(paths))
	}
	if onceLoads >= legacyLoads {
		t.Fatalf("compile-once reads %d, per-target reads %d", onceLoads, legacyLoads)
	}
	for target, pocs := range targets {
		got := templateIDs(SelectCompiledTemplates(compiled, pocs, false, false))
		want := templateIDs(legacyLoadTemplates(store, embed.FS{}, paths, pocs, nil, nil))
		if len(got) != 1 || len(want) != 1 || got[0] != want[0] {
			t.Fatalf("target %s selected %v, legacy selected %v", target, got, want)
		}
	}
	t.Logf("template body reads: per-target=%d compile-once=%d library=%d targets=%d", legacyLoads, onceLoads, len(paths), len(targets))
}

func BenchmarkResolveTemplates(b *testing.B) {
	store, paths, targets := fixtureLibrary(b, 80, 8, 16)
	names := unionNames(targets)
	b.ReportAllocs()

	b.Run("per-target", func(b *testing.B) {
		var loads uint64
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			templates.ResetTemplateCache()
			templates.ResetTemplateParseLoads()
			b.StartTimer()
			var wg sync.WaitGroup
			for _, pocs := range targets {
				pocs := append([]string(nil), pocs...)
				wg.Add(1)
				go func() {
					defer wg.Done()
					legacyLoadTemplates(store, embed.FS{}, paths, pocs, nil, nil)
				}()
			}
			wg.Wait()
			b.StopTimer()
			loads += templates.TemplateParseLoads()
		}
		b.ReportMetric(float64(loads)/float64(b.N), "reads/op")
	})

	b.Run("compile-once", func(b *testing.B) {
		var loads uint64
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			templates.ResetTemplateCache()
			templates.ResetTemplateParseLoads()
			b.StartTimer()
			compiled := store.CompileTemplates(embed.FS{}, paths, names, nil, nil, false)
			for _, pocs := range targets {
				SelectCompiledTemplates(compiled, pocs, false, false)
			}
			b.StopTimer()
			loads += templates.TemplateParseLoads()
		}
		b.ReportMetric(float64(loads)/float64(b.N), "reads/op")
	})
}

func fixtureLibrary(tb testing.TB, total, referenced, targetCount int) (*Store, []string, map[string][]string) {
	tb.Helper()
	if referenced > total || targetCount < 1 {
		tb.Fatalf("invalid fixture %d/%d targets %d", referenced, total, targetCount)
	}
	dir := tb.TempDir()
	paths := make([]string, 0, total)
	for i := 0; i < total; i++ {
		id := fmt.Sprintf("tpl-%02d", i)
		tag := "demo"
		severity := "info"
		if i == 0 {
			tag = "skipme"
		}
		if i == 1 {
			severity = "high"
		}
		body := fmt.Sprintf("id: %s\n\ninfo:\n  name: %s\n  author: bench\n  severity: %s\n  tags: %s\n\nrequests:\n  - method: GET\n    path:\n      - \"{{BaseURL}}\"\n    matchers:\n      - type: word\n        words:\n          - \"absent-%s\"\n", id, id, severity, tag, id)
		path := filepath.Join(dir, id+".yaml")
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			tb.Fatal(err)
		}
		paths = append(paths, path)
	}
	targets := make(map[string][]string, targetCount)
	for i := 0; i < targetCount; i++ {
		targets[fmt.Sprintf("http://target-%02d.example", i)] = []string{filepath.Base(paths[2+(i%referenced)])}
	}
	return newResolveStore(tb, dir), paths, targets
}

func unionNames(targets map[string][]string) []string {
	seen := make(map[string]struct{})
	names := make([]string, 0)
	for _, pocs := range targets {
		for _, poc := range pocs {
			if _, ok := seen[poc]; ok {
				continue
			}
			seen[poc] = struct{}{}
			names = append(names, poc)
		}
	}
	return names
}

func templateIDs(list []*templates.Template) []string {
	ids := make([]string, 0, len(list))
	for _, template := range list {
		ids = append(ids, template.ID)
	}
	return ids
}

func newResolveStore(tb testing.TB, dir string) *Store {
	tb.Helper()
	options := testutils.DefaultOptions
	testutils.Init(options)
	progressImpl, err := progress.NewStatsTicker(0, false, false, false, 0)
	if err != nil {
		tb.Fatal(err)
	}
	executerOpts := protocols.ExecutorOptions{
		Output:      testutils.NewMockOutputWriter(options.OmitTemplate),
		Options:     options,
		Progress:    progressImpl,
		Catalog:     disk.NewCatalog(dir),
		RateLimiter: ratelimit.New(context.Background(), uint(options.RateLimit), time.Second),
	}
	workflowLoader, err := parsers.NewLoader(&executerOpts)
	if err != nil {
		tb.Fatal(err)
	}
	executerOpts.WorkflowLoader = workflowLoader
	return &Store{config: &Config{ExecutorOptions: executerOpts, Catalog: executerOpts.Catalog}}
}

// legacyLoadTemplates is the previous per-target loader: every library path is parsed.
func legacyLoadTemplates(store *Store, f embed.FS, templatesList []string, pocNames []string, excludeTags []string, enableSeverities []string) []*templates.Template {
	seen := make(map[string]struct{})
	var enableSeveritiesOK []string
	var excludeTagsOK []string
	for _, value := range enableSeverities {
		if value != "" {
			enableSeveritiesOK = append(enableSeveritiesOK, value)
		}
	}
	for _, value := range excludeTags {
		if value != "" {
			excludeTagsOK = append(excludeTagsOK, value)
		}
	}
	loaded := make([]*templates.Template, 0)
	for _, templatePath := range templatesList {
		_, fileName := splitPathAndFileName(templatePath)
		if _, ok := seen[fileName]; ok {
			continue
		}
		parsed, err := templates.Parse(templatePath, store.preprocessor, store.config.ExecutorOptions)
		if err != nil {
			parsed, err = templates.EmbedParse(f, templatePath, store.preprocessor, store.config.ExecutorOptions)
		}
		if err != nil {
			continue
		}
		if len(excludeTagsOK) > 0 {
			excluded := false
			for _, tag := range parsed.Info.Tags.ToSlice() {
				for _, blocked := range excludeTags {
					if blocked == tag {
						excluded = true
						break
					}
				}
			}
			if excluded {
				continue
			}
		}
		if len(enableSeveritiesOK) > 0 {
			allowed := false
			severity := parsed.Info.SeverityHolder.Severity.String()
			for _, value := range enableSeveritiesOK {
				if strings.EqualFold(value, severity) {
					allowed = true
					break
				}
			}
			if !allowed {
				continue
			}
		}
		seen[fileName] = struct{}{}
		matched := false
		for _, pocName := range pocNames {
			foldedPath := strings.ToLower(templatePath)
			if strings.HasSuffix(foldedPath, strings.ToLower(pocName)) || strings.HasSuffix(foldedPath, strings.ToLower(strings.ReplaceAll(pocName, "/", "\\"))) {
				matched = true
				break
			}
			if strings.HasPrefix(pocName, "Tags@") && len(pocName) >= 10 {
				tagName := pocName[5 : len(pocName)-5]
				for _, tag := range parsed.Info.Tags.ToSlice() {
					if strings.EqualFold(tag, tagName) {
						matched = true
						break
					}
				}
			}
			if matched {
				break
			}
		}
		if matched && len(parsed.RequestsHeadless) == 0 {
			loaded = append(loaded, parsed)
		}
	}
	return loaded
}
