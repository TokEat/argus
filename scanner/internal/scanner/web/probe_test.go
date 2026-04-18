package web

import (
	"dddd/scanner/structs"
	"reflect"
	"sync"
	"testing"

	"github.com/projectdiscovery/httpx/runner"
)

func TestURLCallbackStoresWebPath(t *testing.T) {
	urlMap := make(map[string]structs.URLEntity)
	lock := &sync.Mutex{}
	rt := NewRuntime(urlMap, lock, nil, nil, nil, nil, nil, nil, map[string][]string{}, &sync.Mutex{})

	rt.URLCallback(runner.Result{
		URL:           "http://127.0.0.1:8080",
		Scheme:        "http",
		Host:          "127.0.0.1",
		Port:          "8080",
		Path:          "/",
		Title:         "Index",
		StatusCode:    200,
		ContentType:   "text/html",
		ContentLength: 12,
		Hashes: map[string]interface{}{
			"body_md5":   "body-1",
			"header_md5": "header-1",
		},
	})

	entry, ok := urlMap["http://127.0.0.1:8080"]
	if !ok {
		t.Fatalf("expected root URL to be stored")
	}
	pathEntry, ok := entry.WebPaths["/"]
	if !ok {
		t.Fatalf("expected / path to be stored")
	}
	if pathEntry.Hash != "body-1" || pathEntry.HeaderHashString != "header-1" {
		t.Fatalf("unexpected path entry: %#v", pathEntry)
	}
}

func TestDirBruteCallbackRecordsDirFallback(t *testing.T) {
	urlMap := map[string]structs.URLEntity{
		"http://example.com": {
			IP:       "1.1.1.1",
			Port:     80,
			WebPaths: map[string]structs.UrlPathEntity{"/": {}},
		},
	}
	lock := &sync.Mutex{}
	dirFallback := make(map[string][]string)
	rt := NewRuntime(
		urlMap,
		lock,
		nil,
		nil,
		nil,
		map[string][]string{"/admin": {"TestProduct"}},
		nil,
		map[string]structs.WorkFlowEntity{
			"TestProduct": {DirFallback: true},
		},
		dirFallback,
		&sync.Mutex{},
	)

	rt.DirBruteCallback(runner.Result{
		URL:         "http://example.com/admin",
		Scheme:      "http",
		Host:        "example.com",
		Port:        "80",
		Path:        "/admin",
		StatusCode:  200,
		ContentType: "text/html",
		Hashes: map[string]interface{}{
			"body_md5":   "body-admin",
			"header_md5": "header-admin",
		},
	})

	want := []string{"TestProduct"}
	if !reflect.DeepEqual(dirFallback["http://example.com"], want) {
		t.Fatalf("unexpected dir fallback results: want=%v got=%v", want, dirFallback["http://example.com"])
	}
}

func TestHostBindCallbackStoresChangedBinding(t *testing.T) {
	urlMap := map[string]structs.URLEntity{
		"http://1.1.1.1:80": {
			IP:   "1.1.1.1",
			Port: 80,
			WebPaths: map[string]structs.UrlPathEntity{
				"/": {Hash: "old-body", StatusCode: 200},
			},
		},
	}
	lock := &sync.Mutex{}
	rt := NewRuntime(urlMap, lock, map[string][]string{"1.1.1.1": {"example.com"}}, nil, nil, nil, nil, nil, map[string][]string{}, &sync.Mutex{})

	rt.HostBindCallback(runner.Result{
		URL:         "http://example.com",
		Scheme:      "http",
		Host:        "example.com",
		Port:        "80",
		Path:        "/",
		StatusCode:  200,
		Title:       "bound",
		A:           []string{"1.1.1.1"},
		ContentType: "text/html",
		Hashes: map[string]interface{}{
			"body_md5":   "new-body",
			"header_md5": "new-header",
		},
	})

	entry, ok := urlMap["http://example.com"]
	if !ok {
		t.Fatalf("expected host bind URL to be stored")
	}
	if _, ok := entry.WebPaths["/"]; !ok {
		t.Fatalf("expected host bind path to be recorded")
	}
}
