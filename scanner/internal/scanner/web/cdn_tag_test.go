package web

import (
	"sync"
	"testing"

	"github.com/P0lar1ght/argus/scanner/structs"
	"github.com/projectdiscovery/httpx/runner"
)

// CDN 打标：URLCallback 对命中 CDNHosts 的主机在输出消息上携带 tag=cdn。
func TestURLCallbackTagsCDNAssets(t *testing.T) {
	var tagged []structs.OutputMessage
	rt := NewRuntime(
		map[string]structs.URLEntity{}, &sync.Mutex{}, nil, nil, nil, nil, nil, nil,
		map[string][]string{}, &sync.Mutex{},
		func(msg structs.OutputMessage) { tagged = append(tagged, msg) },
	)
	rt.CDNHosts = map[string]struct{}{"cdn.example.test": {}}

	rt.URLCallback(runner.Result{URL: "http://cdn.example.test:8080/", StatusCode: 200})
	rt.URLCallback(runner.Result{URL: "http://plain.example.test/", StatusCode: 200})

	if len(tagged) != 2 {
		t.Fatalf("应发出 2 条 Web 消息，got %d", len(tagged))
	}
	if tagged[0].Tag != "cdn" {
		t.Fatalf("CDN 域名的 Web 资产必须携带 tag=cdn，got %q", tagged[0].Tag)
	}
	if tagged[1].Tag != "" {
		t.Fatalf("普通域名的 Web 资产不得携带标记，got %q", tagged[1].Tag)
	}
}

func TestAssetTagCaseInsensitiveAndEmptyRuntime(t *testing.T) {
	rt := &Runtime{CDNHosts: map[string]struct{}{"cdn.example.test": {}}}
	if got := rt.assetTag("https://CDN.EXAMPLE.TEST/x"); got != "cdn" {
		t.Fatalf("大小写不敏感匹配失败，got %q", got)
	}
	if got := rt.assetTag("http://other.test/"); got != "" {
		t.Fatalf("未命中主机不应打标，got %q", got)
	}
	var nilRuntime *Runtime
	if got := nilRuntime.assetTag("http://cdn.example.test/"); got != "" {
		t.Fatalf("nil runtime 必须安全返回空，got %q", got)
	}
}
