package web

import (
	"github.com/P0lar1ght/argus/scanner/lib/ddfinger"
	"github.com/P0lar1ght/argus/scanner/structs"
	"reflect"
	"sync"
	"testing"

	"github.com/projectdiscovery/httpx/runner"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
)

func TestURLCallbackEmitsPassiveFingersForDisplay(t *testing.T) {
	var emitted []structs.OutputMessage
	rt := NewRuntime(
		map[string]structs.URLEntity{},
		&sync.Mutex{},
		nil, nil, nil, nil,
		[]structs.FingerPEntity{{
			ProductName: "DemoCMS",
			AllString:   `title="Index"`,
			Rule:        ddfinger.ParseRule(`title="Index"`),
		}},
		nil,
		map[string][]string{},
		&sync.Mutex{},
		func(msg structs.OutputMessage) { emitted = append(emitted, msg) },
	)
	rt.URLCallback(runner.Result{
		URL:           "http://example.com/",
		Scheme:        "http",
		Host:          "example.com",
		Port:          "80",
		Path:          "/",
		Title:         "Index",
		StatusCode:    200,
		ContentLength: 12,
		Hashes: map[string]interface{}{
			"body_md5":   "body-1",
			"header_md5": "header-1",
		},
	})
	if len(emitted) != 1 || !reflect.DeepEqual(emitted[0].Finger, []string{"DemoCMS"}) {
		t.Fatalf("expected display fingers, got %#v", emitted)
	}
}

func TestURLCallbackEmitsSizeAndRedirect(t *testing.T) {
	var emitted []structs.OutputMessage
	rt := NewRuntime(map[string]structs.URLEntity{}, &sync.Mutex{}, nil, nil, nil, nil, nil, nil, map[string][]string{}, &sync.Mutex{}, func(msg structs.OutputMessage) {
		emitted = append(emitted, msg)
	})
	rt.URLCallback(runner.Result{
		URL:           "http://example.com/",
		Scheme:        "http",
		Host:          "example.com",
		Port:          "80",
		Path:          "/",
		Title:         "Home",
		StatusCode:    302,
		ContentLength: 2862,
		Location:      "https://example.com/login",
		Hashes: map[string]interface{}{
			"body_md5":   "body-1",
			"header_md5": "header-1",
		},
	})
	if len(emitted) != 1 {
		t.Fatalf("emitted = %#v", emitted)
	}
	if emitted[0].Web.Status != "302" || emitted[0].Web.Size != "2862" || emitted[0].Web.Redirect != "https://example.com/login" || emitted[0].Web.Title != "Home" {
		t.Fatalf("web fields = %#v", emitted[0].Web)
	}
}

func TestURLCallbackEmitsCertificate(t *testing.T) {
	var emitted []structs.OutputMessage
	rt := NewRuntime(map[string]structs.URLEntity{}, &sync.Mutex{}, nil, nil, nil, nil, nil, nil, map[string][]string{}, &sync.Mutex{}, func(msg structs.OutputMessage) {
		emitted = append(emitted, msg)
	})
	rt.URLCallback(runner.Result{
		URL:           "https://10.0.0.8/",
		Scheme:        "https",
		Host:          "10.0.0.8",
		Port:          "443",
		Path:          "/",
		StatusCode:    200,
		ContentLength: 12,
		TLSData: &clients.Response{
			CertificateResponse: &clients.CertificateResponse{
				SubjectAN: []string{"intranet.local", "10.0.0.8"},
				IssuerOrg: []string{"ExampleCA"},
			},
		},
		Hashes: map[string]interface{}{"body_md5": "body-1", "header_md5": "header-1"},
	})
	if len(emitted) != 1 {
		t.Fatalf("emitted = %#v", emitted)
	}
	if emitted[0].Web.Cert != "CN=intranet.local SAN=10.0.0.8 issuer=ExampleCA" {
		t.Fatalf("cert = %q", emitted[0].Web.Cert)
	}
}

func TestCompactCertificateUsesSANWhenCNEmpty(t *testing.T) {
	got := compactCertificate(runner.Result{TLSData: &clients.Response{
		CertificateResponse: &clients.CertificateResponse{
			SubjectAN: []string{"app.local", "app.local"},
			IssuerCN:  "R3",
			Expired:   true,
		},
	}})
	if got != "CN=app.local issuer=R3 expired=true" {
		t.Fatalf("compact = %q", got)
	}
	if compactCertificate(runner.Result{}) != "" {
		t.Fatal("empty TLS should stay empty")
	}
	if compactCertificate(runner.Result{TLSData: &clients.Response{}}) != "" {
		t.Fatal("nil certificate response should stay empty")
	}
}

func TestProbeURLsAddsHTTPSOnTLSPorts(t *testing.T) {
	if got := ProbeURLs("10.0.0.8:80", "http"); !reflect.DeepEqual(got, []string{"http://10.0.0.8:80"}) {
		t.Fatalf("http 80 = %v", got)
	}
	if got := ProbeURLs("10.0.0.8:443", "http"); !reflect.DeepEqual(got, []string{"http://10.0.0.8:443", "https://10.0.0.8:443"}) {
		t.Fatalf("http 443 = %v", got)
	}
	if got := ProbeURLs("10.0.0.8:8443", "https"); !reflect.DeepEqual(got, []string{"https://10.0.0.8:8443"}) {
		t.Fatalf("https 8443 = %v", got)
	}
	if got := ProbeURLs("10.0.0.8:22", "ssh"); got != nil {
		t.Fatalf("ssh = %v", got)
	}
}

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

func TestURLCallbackStoresFaviconHash(t *testing.T) {
	urlMap := make(map[string]structs.URLEntity)
	lock := &sync.Mutex{}
	rt := NewRuntime(urlMap, lock, nil, nil, nil, nil, nil, nil, map[string][]string{}, &sync.Mutex{}, nil)

	rt.URLCallback(runner.Result{
		URL:         "http://127.0.0.1:8080",
		Scheme:      "http",
		Host:        "127.0.0.1",
		Port:        "8080",
		Path:        "/",
		StatusCode:  200,
		FavIconMMH3: "-1760645692",
		Hashes: map[string]interface{}{
			"body_md5":   "body-1",
			"header_md5": "header-1",
		},
	})

	pathEntry := urlMap["http://127.0.0.1:8080"].WebPaths["/"]
	if pathEntry.IconHash != "-1760645692" {
		t.Fatalf("expected favicon hash to be stored, got %#v", pathEntry)
	}
}

func TestDirBruteCallbackCanMatchIconHashRule(t *testing.T) {
	urlMap := map[string]structs.URLEntity{
		"http://example.com": {
			IP:       "1.1.1.1",
			Port:     80,
			WebPaths: map[string]structs.UrlPathEntity{"/": {}},
		},
	}
	lock := &sync.Mutex{}
	var emitted []structs.OutputMessage
	rt := NewRuntime(
		urlMap,
		lock,
		nil,
		nil,
		nil,
		map[string][]string{"/admin": {"IconProduct"}},
		[]structs.FingerPEntity{{
			ProductName: "IconProduct",
			AllString:   `icon_hash="-1760645692"`,
			Rule:        ddfinger.ParseRule(`icon_hash="-1760645692"`),
		}},
		map[string]structs.WorkFlowEntity{
			"IconProduct": {},
		},
		map[string][]string{},
		&sync.Mutex{},
		func(msg structs.OutputMessage) {
			emitted = append(emitted, msg)
		},
	)

	rt.DirBruteCallback(runner.Result{
		URL:         "http://example.com/admin",
		Scheme:      "http",
		Host:        "example.com",
		Port:        "80",
		Path:        "/admin",
		StatusCode:  200,
		FavIconMMH3: "-1760645692",
		Hashes: map[string]interface{}{
			"body_md5":   "body-admin",
			"header_md5": "header-admin",
		},
	})

	if len(emitted) != 1 || !reflect.DeepEqual(emitted[0].Finger, []string{"IconProduct"}) {
		t.Fatalf("expected icon_hash rule to emit IconProduct, got %#v", emitted)
	}
	if emitted[0].Web.Status != "200" {
		t.Fatalf("expected active fingerprint evidence status 200, got %#v", emitted[0].Web)
	}
}

func TestURLCallbackStoresFinalURLPath(t *testing.T) {
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
	if pathEntry.Hash != "" || pathEntry.StatusCode != 0 {
		t.Fatalf("root placeholder should not be overwritten by redirected response: %#v", pathEntry)
	}

	pathEntry = urlMap["https://example.com"].WebPaths["/portal"]
	if pathEntry.Hash != "body-real" || pathEntry.HeaderHashString != "header-real" || pathEntry.StatusCode != 200 {
		t.Fatalf("final URL path was not recorded: %#v", pathEntry)
	}
}

func TestURLCallbackStoresPortFromFinalURL(t *testing.T) {
	urlMap := make(map[string]structs.URLEntity)
	lock := &sync.Mutex{}
	rt := NewRuntime(urlMap, lock, nil, nil, nil, nil, nil, nil, map[string][]string{}, &sync.Mutex{}, nil)

	rt.URLCallback(runner.Result{
		URL:           "http://example.com/",
		FinalURL:      "https://example.com/login",
		Scheme:        "http",
		Host:          "example.com",
		Port:          "80",
		Path:          "/",
		StatusCode:    200,
		ContentType:   "text/html",
		ContentLength: 2862,
		Hashes: map[string]interface{}{
			"body_md5":   "body-real",
			"header_md5": "header-real",
		},
	})

	entry, ok := urlMap["https://example.com"]
	if !ok {
		t.Fatalf("expected final URL root to be stored")
	}
	if entry.Port != 443 {
		t.Fatalf("expected port from final URL, got %d", entry.Port)
	}
}

func TestURLCallbackCollectsSameOriginRedirectLocation(t *testing.T) {
	urlMap := make(map[string]structs.URLEntity)
	lock := &sync.Mutex{}
	rt := NewRuntime(urlMap, lock, nil, nil, nil, nil, nil, nil, map[string][]string{}, &sync.Mutex{}, nil)

	rt.URLCallback(runner.Result{
		URL:        "https://example.com",
		Scheme:     "https",
		Host:       "example.com",
		Port:       "443",
		Path:       "/",
		StatusCode: 301,
		Location:   "/portal/",
		Hashes: map[string]interface{}{
			"body_md5":   "body-redirect",
			"header_md5": "header-redirect",
		},
	})

	got := rt.DrainRedirectURLs()
	want := []string{"https://example.com/portal/"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected redirect URLs: want=%v got=%v", want, got)
	}
}

func TestURLCallbackCollectsSameOriginDefaultPortRedirectLocation(t *testing.T) {
	urlMap := make(map[string]structs.URLEntity)
	lock := &sync.Mutex{}
	rt := NewRuntime(urlMap, lock, nil, nil, nil, nil, nil, nil, map[string][]string{}, &sync.Mutex{}, nil)

	rt.URLCallback(runner.Result{
		URL:        "https://example.com/portal/cas/login",
		Scheme:     "https",
		Host:       "example.com",
		Port:       "443",
		Path:       "/portal/cas/login",
		StatusCode: 302,
		Location:   "https://example.com:443/bic/ssoService/v1/casLogin",
		Hashes: map[string]interface{}{
			"body_md5":   "body-redirect",
			"header_md5": "header-redirect",
		},
	})

	got := rt.DrainRedirectURLs()
	want := []string{"https://example.com:443/bic/ssoService/v1/casLogin"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected redirect URLs: want=%v got=%v", want, got)
	}
}

func TestURLCallbackCollectsDefaultHTTPToHTTPSRedirectLocation(t *testing.T) {
	urlMap := make(map[string]structs.URLEntity)
	lock := &sync.Mutex{}
	rt := NewRuntime(urlMap, lock, nil, nil, nil, nil, nil, nil, map[string][]string{}, &sync.Mutex{}, nil)

	rt.URLCallback(runner.Result{
		URL:        "http://example.com",
		Scheme:     "http",
		Host:       "example.com",
		Port:       "80",
		Path:       "/",
		StatusCode: 301,
		Location:   "https://example.com/portal/",
		Hashes: map[string]interface{}{
			"body_md5":   "body-redirect",
			"header_md5": "header-redirect",
		},
	})

	got := rt.DrainRedirectURLs()
	want := []string{"https://example.com/portal/"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected redirect URLs: want=%v got=%v", want, got)
	}
}

func TestURLCallbackSkipsHTTPToHTTPSRedirectFromNonDefaultPort(t *testing.T) {
	urlMap := make(map[string]structs.URLEntity)
	lock := &sync.Mutex{}
	rt := NewRuntime(urlMap, lock, nil, nil, nil, nil, nil, nil, map[string][]string{}, &sync.Mutex{}, nil)

	rt.URLCallback(runner.Result{
		URL:        "http://example.com:8080",
		Scheme:     "http",
		Host:       "example.com",
		Port:       "8080",
		Path:       "/",
		StatusCode: 301,
		Location:   "https://example.com/portal/",
		Hashes: map[string]interface{}{
			"body_md5":   "body-redirect",
			"header_md5": "header-redirect",
		},
	})

	if got := rt.DrainRedirectURLs(); len(got) != 0 {
		t.Fatalf("http-to-https redirect from non-default origin should not be queued: %v", got)
	}
}

func TestURLCallbackSkipsSchemeChangeOnSameNonDefaultPort(t *testing.T) {
	urlMap := make(map[string]structs.URLEntity)
	lock := &sync.Mutex{}
	rt := NewRuntime(urlMap, lock, nil, nil, nil, nil, nil, nil, map[string][]string{}, &sync.Mutex{}, nil)

	rt.URLCallback(runner.Result{
		URL:        "http://example.com:8443",
		Scheme:     "http",
		Host:       "example.com",
		Port:       "8443",
		Path:       "/",
		StatusCode: 301,
		Location:   "https://example.com:8443/portal/",
		Hashes: map[string]interface{}{
			"body_md5":   "body-redirect",
			"header_md5": "header-redirect",
		},
	})

	if got := rt.DrainRedirectURLs(); len(got) != 0 {
		t.Fatalf("scheme change on same non-default port should not be queued: %v", got)
	}
}

func TestURLCallbackKeepsSameOriginNonDefaultPortRedirectLocation(t *testing.T) {
	urlMap := make(map[string]structs.URLEntity)
	lock := &sync.Mutex{}
	rt := NewRuntime(urlMap, lock, nil, nil, nil, nil, nil, nil, map[string][]string{}, &sync.Mutex{}, nil)

	rt.URLCallback(runner.Result{
		URL:        "https://example.com:8443",
		Scheme:     "https",
		Host:       "example.com",
		Port:       "8443",
		Path:       "/",
		StatusCode: 301,
		Location:   "/portal/",
		Hashes: map[string]interface{}{
			"body_md5":   "body-redirect",
			"header_md5": "header-redirect",
		},
	})

	got := rt.DrainRedirectURLs()
	want := []string{"https://example.com:8443/portal/"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected redirect URLs: want=%v got=%v", want, got)
	}
}

func TestURLCallbackSkipsDefaultPortRedirectFromNonDefaultPort(t *testing.T) {
	urlMap := make(map[string]structs.URLEntity)
	lock := &sync.Mutex{}
	rt := NewRuntime(urlMap, lock, nil, nil, nil, nil, nil, nil, map[string][]string{}, &sync.Mutex{}, nil)

	rt.URLCallback(runner.Result{
		URL:        "https://example.com:8443",
		Scheme:     "https",
		Host:       "example.com",
		Port:       "8443",
		Path:       "/",
		StatusCode: 302,
		Location:   "https://example.com/portal/",
		Hashes: map[string]interface{}{
			"body_md5":   "body-redirect",
			"header_md5": "header-redirect",
		},
	})

	if got := rt.DrainRedirectURLs(); len(got) != 0 {
		t.Fatalf("default-port redirect from non-default origin should not be queued: %v", got)
	}
}

func TestURLCallbackSkipsCrossOriginRedirectLocation(t *testing.T) {
	urlMap := make(map[string]structs.URLEntity)
	lock := &sync.Mutex{}
	rt := NewRuntime(urlMap, lock, nil, nil, nil, nil, nil, nil, map[string][]string{}, &sync.Mutex{}, nil)

	rt.URLCallback(runner.Result{
		URL:        "https://example.com",
		Scheme:     "https",
		Host:       "example.com",
		Port:       "443",
		Path:       "/",
		StatusCode: 302,
		Location:   "https://sso.example.net/login",
		Hashes: map[string]interface{}{
			"body_md5":   "body-redirect",
			"header_md5": "header-redirect",
		},
	})

	if got := rt.DrainRedirectURLs(); len(got) != 0 {
		t.Fatalf("cross-origin redirect should not be queued: %v", got)
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

func TestDirBruteCallbackDoesNotMarkGeneric403AsProducts(t *testing.T) {
	urlMap := map[string]structs.URLEntity{
		"http://58.210.164.90:8556": {
			IP:       "58.210.164.90",
			Port:     8556,
			WebPaths: map[string]structs.UrlPathEntity{"/": {}},
		},
	}
	var emitted []structs.OutputMessage
	rt := NewRuntime(
		urlMap,
		&sync.Mutex{},
		nil, nil, nil,
		map[string][]string{
			"/seeyon/":           {"致远互联-OA"},
			"/wui/index.html":    {"泛微-协同办公OA"},
			"/general/login.php": {"TDXK-通达OA"},
		},
		[]structs.FingerPEntity{
			{ProductName: "致远互联-OA", AllString: `path="/seeyon/"`, Rule: ddfinger.ParseRule(`path="/seeyon/"`)},
			{ProductName: "泛微-协同办公OA", AllString: `path="/wui/index.html"`, Rule: ddfinger.ParseRule(`path="/wui/index.html"`)},
			{ProductName: "TDXK-通达OA", AllString: `path="/general/login.php"`, Rule: ddfinger.ParseRule(`path="/general/login.php"`)},
			{ProductName: "TDXK-通达OA", AllString: `body="/general/login.php"`, Rule: ddfinger.ParseRule(`body="/general/login.php"`)},
		},
		nil,
		map[string][]string{},
		&sync.Mutex{},
		func(msg structs.OutputMessage) { emitted = append(emitted, msg) },
	)

	denied := runner.Result{
		Scheme:      "http",
		Host:        "58.210.164.90",
		Port:        "8556",
		StatusCode:  403,
		Title:       "403 Forbidden",
		ContentType: "text/html",
		Hashes:      map[string]interface{}{"body_md5": "same-waf", "header_md5": "same-hdr"},
	}
	for _, path := range []string{"/seeyon/", "/wui/index.html", "/general/login.php"} {
		item := denied
		item.Path = path
		item.URL = "http://58.210.164.90:8556" + path
		item.Body = `<html>403 Forbidden</html> URL: ` + item.URL
		rt.DirBruteCallback(item)
	}

	if len(emitted) != 0 {
		t.Fatalf("generic 403 directory probes should not emit active fingerprints, got %#v", emitted)
	}
}

func TestDirBruteCallbackKeepsDistinctiveContentOnProbedPath(t *testing.T) {
	urlMap := map[string]structs.URLEntity{
		"http://example.com": {
			IP:       "1.1.1.1",
			Port:     80,
			WebPaths: map[string]structs.UrlPathEntity{"/": {}},
		},
	}
	var emitted []structs.OutputMessage
	rt := NewRuntime(
		urlMap,
		&sync.Mutex{},
		nil, nil, nil,
		map[string][]string{"/seeyon/": {"致远互联-OA"}},
		[]structs.FingerPEntity{{
			ProductName: "致远互联-OA",
			AllString:   `body="seeyonProductId"`,
			Rule:        ddfinger.ParseRule(`body="seeyonProductId"`),
		}},
		nil,
		map[string][]string{},
		&sync.Mutex{},
		func(msg structs.OutputMessage) { emitted = append(emitted, msg) },
	)

	rt.DirBruteCallback(runner.Result{
		URL:         "http://example.com/seeyon/",
		Scheme:      "http",
		Host:        "example.com",
		Port:        "80",
		Path:        "/seeyon/",
		StatusCode:  200,
		Body:        `var seeyonProductId = "A8"`,
		Title:       "致远A8",
		ContentType: "text/html",
		Hashes:      map[string]interface{}{"body_md5": "seeyon-ok", "header_md5": "hdr"},
	})

	if len(emitted) != 1 || len(emitted[0].Finger) != 1 || emitted[0].Finger[0] != "致远互联-OA" {
		t.Fatalf("expected distinctive directory probe match, got %#v", emitted)
	}
}

func TestMatchingDirPathsRequiresExactRequestURI(t *testing.T) {
	rt := &Runtime{DirDB: map[string][]string{
		"/login":               {"Login"},
		"/admin/login":         {"Admin"},
		"/search?source=argus": {"Search"},
	}}

	if got := rt.matchingDirPaths("/admin/login"); !reflect.DeepEqual(got, []string{"/admin/login"}) {
		t.Fatalf("overlapping path match = %v, want exact path only", got)
	}
	if got := rt.matchingDirPaths("/search?source=argus"); !reflect.DeepEqual(got, []string{"/search?source=argus"}) {
		t.Fatalf("query path match = %v, want exact request URI", got)
	}
	if got := rt.matchingDirPaths("/prefix/login"); len(got) != 0 {
		t.Fatalf("suffix-only path unexpectedly matched: %v", got)
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

func TestDirBruteCallbackReportsEveryPathWhenAsked(t *testing.T) {
	var got []structs.OutputMessage
	rt := NewRuntime(
		map[string]structs.URLEntity{},
		&sync.Mutex{},
		nil,
		nil,
		nil,
		map[string][]string{"/admin": {"Demo"}},
		nil,
		map[string]structs.WorkFlowEntity{},
		map[string][]string{},
		&sync.Mutex{},
		func(msg structs.OutputMessage) { got = append(got, msg) },
	)
	rt.ReportAllDirProbes = true
	rt.DirBruteCallback(runner.Result{
		URL:           "http://example.com/admin",
		Path:          "/admin",
		StatusCode:    404,
		Title:         "missing",
		Body:          "<html>nope</html>",
		ContentLength: 16,
	})
	if len(got) != 1 || got[0].Type != "Dir-Probe" || got[0].Web.Status != "404" || got[0].AdditionalMsg != "<html>nope</html>" {
		t.Fatalf("expected dir probe miss with body, got %#v", got)
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
