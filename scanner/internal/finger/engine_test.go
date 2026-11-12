package finger

import (
	"github.com/TokEat/argus/scanner/lib/ddfinger"
	"github.com/TokEat/argus/scanner/structs"
	"reflect"
	"testing"

	"github.com/projectdiscovery/hmap/store/hybrid"
)

func TestIdentifyServiceFingerprints(t *testing.T) {
	bannerMap, err := hybrid.New(hybrid.DefaultDiskOptions)
	if err != nil {
		t.Fatalf("create banner map: %v", err)
	}
	defer bannerMap.Close()

	if err := bannerMap.Set("127.0.0.1:22", []byte("OpenSSH_8.9")); err != nil {
		t.Fatalf("set banner: %v", err)
	}

	rt := NewRuntime(
		map[string]string{"127.0.0.1:22": "ssh"},
		map[string]structs.URLEntity{},
		map[string][]string{},
		bannerMap,
		nil,
		nil,
		[]structs.FingerPEntity{
			{
				ProductName: "OpenSSH",
				AllString:   `banner="openssh" && protocol="ssh"`,
				Rule:        ddfinger.ParseRule(`banner="openssh" && protocol="ssh"`),
			},
		},
		nil,
	)

	rt.Identify()

	got := rt.ResultMap["ssh://127.0.0.1:22"]
	want := []string{"OpenSSH"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected service fingerprints: want=%v got=%v", want, got)
	}
}

func TestIdentifyWebFingerprints(t *testing.T) {
	bodyMap, err := hybrid.New(hybrid.DefaultDiskOptions)
	if err != nil {
		t.Fatalf("create body map: %v", err)
	}
	defer bodyMap.Close()

	headerMap, err := hybrid.New(hybrid.DefaultDiskOptions)
	if err != nil {
		t.Fatalf("create header map: %v", err)
	}
	defer headerMap.Close()

	if err := bodyMap.Set("body-md5", []byte("welcome to acme admin")); err != nil {
		t.Fatalf("set body: %v", err)
	}
	if err := headerMap.Set("header-md5", []byte("server: nginx")); err != nil {
		t.Fatalf("set header: %v", err)
	}

	rt := NewRuntime(
		map[string]string{},
		map[string]structs.URLEntity{
			"http://example.com": {
				IP:   "1.1.1.1",
				Port: 80,
				WebPaths: map[string]structs.UrlPathEntity{
					"/admin": {
						Hash:             "body-md5",
						HeaderHashString: "header-md5",
						Title:            "Admin",
						StatusCode:       200,
						ContentType:      "text/html",
						Server:           "nginx",
						Natural:          true,
					},
				},
			},
		},
		map[string][]string{},
		nil,
		bodyMap,
		headerMap,
		[]structs.FingerPEntity{
			{
				ProductName: "AcmePanel",
				AllString:   `body="acme admin" && title="admin"`,
				Rule:        ddfinger.ParseRule(`body="acme admin" && title="admin"`),
			},
		},
		nil,
	)

	rt.Identify()

	got := rt.ResultMap["http://example.com/admin"]
	want := []string{"AcmePanel"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected web fingerprints: want=%v got=%v", want, got)
	}
}

func TestIdentifyWebFingerprintsByIconHash(t *testing.T) {
	rt := NewRuntime(
		map[string]string{},
		map[string]structs.URLEntity{
			"http://example.com": {
				IP:   "1.1.1.1",
				Port: 80,
				WebPaths: map[string]structs.UrlPathEntity{
					"/": {
						IconHash: "-1760645692",
						Natural:  true,
					},
				},
			},
		},
		map[string][]string{},
		nil,
		nil,
		nil,
		[]structs.FingerPEntity{
			{
				ProductName: "IconOnlyProduct",
				AllString:   `icon_hash="-1760645692"`,
				Rule:        ddfinger.ParseRule(`icon_hash="-1760645692"`),
			},
		},
		nil,
	)

	rt.Identify()

	got := rt.ResultMap["http://example.com/"]
	want := []string{"IconOnlyProduct"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected icon hash fingerprints: want=%v got=%v", want, got)
	}
}

func TestIdentifySkipsDirectoryProbePaths(t *testing.T) {
	bodyMap, err := hybrid.New(hybrid.DefaultDiskOptions)
	if err != nil {
		t.Fatalf("create body map: %v", err)
	}
	defer bodyMap.Close()
	if err := bodyMap.Set("nacos-body", []byte(`href="/nacos/" title="Nacos"`)); err != nil {
		t.Fatalf("set body: %v", err)
	}

	rt := NewRuntime(
		map[string]string{},
		map[string]structs.URLEntity{
			"http://example.com": {
				IP:   "1.1.1.1",
				Port: 80,
				WebPaths: map[string]structs.UrlPathEntity{
					"/": {
						Hash:    "home",
						Title:   "nginx",
						Natural: true,
					},
					"/nacos/": {
						Hash:       "nacos-body",
						Title:      "Nacos",
						StatusCode: 200,
						Natural:    false,
					},
				},
			},
		},
		map[string][]string{},
		nil,
		bodyMap,
		nil,
		[]structs.FingerPEntity{{
			ProductName: "Alibaba-Nacos",
			AllString:   `body="/nacos/" || title="Nacos"`,
			Rule:        ddfinger.ParseRule(`body="/nacos/" || title="Nacos"`),
		}},
		nil,
	)

	rt.Identify()

	if _, ok := rt.ResultMap["http://example.com/nacos/"]; ok {
		t.Fatalf("directory-probe path must not become a passive Finger: %#v", rt.ResultMap)
	}
	if got := rt.ResultMap["http://example.com/"]; len(got) != 0 {
		t.Fatalf("homepage without Nacos evidence matched %v", got)
	}
}

func TestIdentifyDoesNotTreatDirProbePathEqualsAsPassiveFinger(t *testing.T) {
	rt := NewRuntime(
		map[string]string{},
		map[string]structs.URLEntity{
			"http://example.com": {
				IP:   "1.1.1.1",
				Port: 80,
				WebPaths: map[string]structs.UrlPathEntity{
					"/": {Hash: "home", Title: "nginx", Natural: true, StatusCode: 200},
					"/xxxx": {
						Hash:       "dir-hit",
						Title:      "404",
						StatusCode: 200,
						Natural:    false,
					},
				},
			},
		},
		map[string][]string{},
		nil, nil, nil,
		[]structs.FingerPEntity{{
			ProductName: "FakeProduct",
			AllString:   `path="/xxxx"`,
			Rule:        ddfinger.ParseRule(`path="/xxxx"`),
		}},
		nil,
	)

	rt.Identify()

	if _, ok := rt.ResultMap["http://example.com/xxxx"]; ok {
		t.Fatalf("scanner-chosen path must not become a passive Finger via path=: %#v", rt.ResultMap)
	}
	if got := rt.ResultMap["http://example.com/"]; len(got) != 0 {
		t.Fatalf("homepage must not match path=/xxxx, got %v", got)
	}
}
