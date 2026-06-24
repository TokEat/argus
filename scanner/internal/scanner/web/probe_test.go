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
	rt := NewRuntime(urlMap, lock, nil, nil, nil, nil, nil, nil, map[string][]string{}, &sync.Mutex{}, nil)

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

func TestURLCallbackReplacesPlaceholderWebPath(t *testing.T) {
	urlMap := map[string]structs.URLEntity{
		"https://example.com": {
			IP:       "1.1.1.1",
			Port:     443,
			WebPaths: map[string]structs.UrlPathEntity{"/": {}},
		},
	}
	lock := &sync.Mutex{}
	rt := NewRuntime(urlMap, lock, nil, nil, nil, nil, nil, nil, map[string][]string{}, &sync.Mutex{}, nil)

	rt.URLCallback(runner.Result{
		URL:           "https://example.com/",
		FinalURL:      "https://example.com/portal",
		Scheme:        "https",
		Host:          "example.com",
		Port:          "443",
		Path:          "/",
		StatusCode:    200,
		ContentType:   "text/html",
		ContentLength: 2862,
		Hashes: map[string]interface{}{
			"body_md5":   "body-real",
			"header_md5": "header-real",
		},
	})

	pathEntry := urlMap["https://example.com"].WebPaths["/"]
	if pathEntry.Hash != "body-real" || pathEntry.HeaderHashString != "header-real" || pathEntry.StatusCode != 200 {
		t.Fatalf("placeholder path was not replaced: %#v", pathEntry)
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
		nil,
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

	entry := urlMap["http://example.com"]
	if _, ok := entry.WebPaths["/admin"]; !ok {
		t.Fatalf("expected dir fallback path to be recorded")
	}
}

func TestDirBruteCallbackSkipsUnmatchedPathInsert(t *testing.T) {
	urlMap := map[string]structs.URLEntity{
		"http://example.com": {
			IP:       "1.1.1.1",
			Port:     80,
			WebPaths: map[string]structs.UrlPathEntity{"/": {}},
		},
	}
	lock := &sync.Mutex{}
	rt := NewRuntime(
		urlMap,
		lock,
		nil,
		nil,
		nil,
		map[string][]string{"/admin": {"UnmatchedProduct"}},
		nil,
		map[string]structs.WorkFlowEntity{},
		map[string][]string{},
		&sync.Mutex{},
		nil,
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

	entry := urlMap["http://example.com"]
	if _, ok := entry.WebPaths["/admin"]; ok {
		t.Fatalf("unexpected unmatched path inserted into URLMap")
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
	rt := NewRuntime(urlMap, lock, map[string][]string{"1.1.1.1": {"example.com"}}, nil, nil, nil, nil, nil, map[string][]string{}, &sync.Mutex{}, nil)

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
