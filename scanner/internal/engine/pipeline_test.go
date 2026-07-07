package engine

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSearchEngineReturnsErrorWhenQuakeYieldsNoTargets(t *testing.T) {
	ctx := &ScanContext{
		Config: Config{
			Targets:           []string{`app="demo"`},
			Quake:             true,
			APIConfigFilePath: filepath.Join(t.TempDir(), "missing-api-config.yaml"),
		},
		IPPortMap:   map[string]string{},
		IPDomainMap: map[string][]string{},
		URLMap:      map[string]URLEntity{},
	}
	cfg := ctx.Config

	err := (&Pipeline{}).searchEngine(ctx, &cfg)

	if err == nil {
		t.Fatal("expected Quake search with no returned targets to fail")
	}
	if !strings.Contains(err.Error(), "Quake 搜索返回 0 条结果") {
		t.Fatalf("unexpected error: %v", err)
	}
}
