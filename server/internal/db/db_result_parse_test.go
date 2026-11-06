package db

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestExtractFingerprintProductNamesFromFingerArray(t *testing.T) {
	payload := map[string]interface{}{
		"finger": []interface{}{"Apache", "PHP"},
	}

	got := extractFingerprintProductNames("Finger", "", payload)
	want := []string{"Apache", "PHP"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected products: want=%v got=%v", want, got)
	}
}

func TestExtractFingerprintProductNamesDedupesAndSplits(t *testing.T) {
	payload := map[string]interface{}{
		"finger": []interface{}{" Apache , PHP ", "PHP"},
	}

	got := extractFingerprintProductNames("Finger", "", payload)
	want := []string{"Apache", "PHP"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected products: want=%v got=%v", want, got)
	}
}

func TestExtractFingerprintProductNamesMergesPluginAndFinger(t *testing.T) {
	payload := map[string]interface{}{
		"finger": []interface{}{"Nginx", "Lua"},
	}

	got := extractFingerprintProductNames("Finger", "Nginx", payload)
	want := []string{"Nginx", "Lua"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected products: want=%v got=%v", want, got)
	}
}

func TestExtractFingerprintProductNamesNoSignalForGenericType(t *testing.T) {
	got := extractFingerprintProductNames("Finger", "", map[string]interface{}{})
	if len(got) != 0 {
		t.Fatalf("expected no products, got %v", got)
	}
}

func TestAddResultAsyncRoutesActiveFingerprintWithoutCreatingVulnerability(t *testing.T) {
	drainResultBuffers(t)
	taskOwnerCache.Store("task-active-fingerprint", &taskOwnerEntry{ProjectID: "project-a", TenantID: "tenant-a", RootTaskID: "root-a"})
	AddResultAsync("task-active-fingerprint", "Active-Finger", `{"uri":"http://127.0.0.1:8081","finger":["APACHE-Shiro"],"additional_msg":"[behavior-probe:shiro-detect]"}`)

	select {
	case vuln := <-vulnBuffer2:
		t.Fatalf("active product fingerprint became a vulnerability: %+v", vuln)
	default:
	}
	select {
	case fingerprint := <-fpBuffer:
		if fingerprint.ProductName != "APACHE-Shiro" || fingerprint.Target != "http://127.0.0.1:8081" || fingerprint.RootTaskID != "root-a" || fingerprint.RuleName != "behavior-probe" {
			t.Fatalf("unexpected active fingerprint row: %+v", fingerprint)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("active fingerprint was not routed to fingerprint storage")
	}
}

func TestAddResultAsyncRoutesOSINTOutputsToAssets(t *testing.T) {
	drainResultBuffers(t)
	taskOwnerCache.Store("task-osint", &taskOwnerEntry{
		ProjectID:  "project-osint",
		TenantID:   "tenant-osint",
		RootTaskID: "root-osint",
	})

	for _, payloadType := range []string{"Quake", "Hunter", "Fofa"} {
		t.Run(payloadType, func(t *testing.T) {
			drainResultBuffers(t)
			AddResultAsync("task-osint", payloadType, `{"ip":"103.4.201.190","port":"443","uri":"https://mzt_sc_gov_cn_ipv6.dynky.cn/login","protocol":"https"}`)

			select {
			case vuln := <-vulnBuffer2:
				t.Fatalf("expected %s output to be routed as asset, got vulnerability plugin=%q severity=%q target=%q", payloadType, vuln.Plugin, vuln.Severity, vuln.Target)
			default:
			}

			select {
			case asset := <-assetBuffer:
				if asset.Protocol != payloadType {
					t.Fatalf("expected protocol/source %q, got %q", payloadType, asset.Protocol)
				}
				if asset.Target != "https://mzt_sc_gov_cn_ipv6.dynky.cn:443" {
					t.Fatalf("expected uri to take priority and be normalized, got target %q", asset.Target)
				}
				if asset.Port != 443 || asset.ProjectID != "project-osint" || asset.TenantID != "tenant-osint" || asset.RootTaskID != "root-osint" {
					t.Fatalf("unexpected asset fields: %+v", asset)
				}
			case <-time.After(100 * time.Millisecond):
				t.Fatalf("expected %s output to be routed into asset buffer", payloadType)
			}
		})
	}
}

func TestAddResultAsyncPrefersOSINTIPPortWhenURIAbsent(t *testing.T) {
	drainResultBuffers(t)
	taskOwnerCache.Store("task-osint-no-uri", &taskOwnerEntry{
		ProjectID:  "project-osint",
		TenantID:   "tenant-osint",
		RootTaskID: "root-osint",
	})

	AddResultAsync("task-osint-no-uri", "Quake", `{"host":"display-name.example","url":"https://display-name.example/login","ip":"103.4.201.190","port":"443","protocol":"https"}`)

	select {
	case vuln := <-vulnBuffer2:
		t.Fatalf("expected Quake output to be routed as asset, got vulnerability plugin=%q severity=%q target=%q", vuln.Plugin, vuln.Severity, vuln.Target)
	default:
	}

	select {
	case asset := <-assetBuffer:
		if asset.Target != "103.4.201.190:443" {
			t.Fatalf("expected ip:port to take priority when uri is absent, got target %q", asset.Target)
		}
		if asset.URL != "" {
			t.Fatalf("expected non-URL OSINT target to leave asset URL empty, got %q", asset.URL)
		}
		if asset.Protocol != "Quake" || asset.Service != "https" {
			t.Fatalf("unexpected OSINT source fields: %+v", asset)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected Quake output to be routed into asset buffer")
	}
}

func TestAddResultAsyncRoutesDiscoveryOutputsToAssets(t *testing.T) {
	drainResultBuffers(t)
	taskOwnerCache.Store("task-discovery", &taskOwnerEntry{
		ProjectID:  "project-discovery",
		TenantID:   "tenant-discovery",
		RootTaskID: "root-discovery",
	})

	for _, payloadType := range []string{"DNS-SubFinder", "DNS-Brute", "CDN-Domain", "RealIP"} {
		t.Run(payloadType, func(t *testing.T) {
			drainResultBuffers(t)
			AddResultAsync("task-discovery", payloadType, `{"domain":"api.example.invalid","ips":["192.0.2.10"]}`)

			select {
			case vuln := <-vulnBuffer2:
				t.Fatalf("expected %s output to be routed as asset, got vulnerability %+v", payloadType, vuln)
			default:
			}

			select {
			case asset := <-assetBuffer:
				if asset.Target != "api.example.invalid" || asset.Protocol != payloadType {
					t.Fatalf("unexpected discovery asset: %+v", asset)
				}
			case <-time.After(100 * time.Millisecond):
				t.Fatalf("expected %s output to be routed into asset buffer", payloadType)
			}
		})
	}
}

func TestAddResultAsyncUnknownOutputDoesNotBecomeVulnerability(t *testing.T) {
	drainResultBuffers(t)
	taskOwnerCache.Store("task-unknown", &taskOwnerEntry{ProjectID: "project-a", TenantID: "tenant-a"})

	AddResultAsync("task-unknown", "future-discovery-event", `{"target":"example.invalid"}`)

	select {
	case vuln := <-vulnBuffer2:
		t.Fatalf("unknown event must not become vulnerability: %+v", vuln)
	case <-time.After(20 * time.Millisecond):
	}
}

func TestAddResultAsyncExplicitVulnerabilityTypesRemainSupported(t *testing.T) {
	drainResultBuffers(t)
	taskOwnerCache.Store("task-vuln", &taskOwnerEntry{ProjectID: "project-a", TenantID: "tenant-a"})

	for _, payloadType := range []string{"Nuclei", "GoPoc", "nuclei", "gopoc", "vulnerability"} {
		t.Run(payloadType, func(t *testing.T) {
			drainResultBuffers(t)
			AddResultAsync("task-vuln", payloadType, `{"target":"https://example.invalid","plugin":"explicit-test","severity":"high"}`)
			select {
			case vuln := <-vulnBuffer2:
				if vuln.Plugin != "explicit-test" || vuln.Severity != "High" {
					t.Fatalf("unexpected vulnerability: %+v", vuln)
				}
			case <-time.After(100 * time.Millisecond):
				t.Fatalf("expected %s to create vulnerability", payloadType)
			}
		})
	}
}

func TestAddResultAsyncProtocolCheckIsAssetEvidenceNotVulnerability(t *testing.T) {
	drainResultBuffers(t)
	taskOwnerCache.Store("task-protocol-check", &taskOwnerEntry{ProjectID: "project-a", TenantID: "tenant-a"})
	AddResultAsync("task-protocol-check", "ProtocolCheck", `{"type":"ProtocolCheck","protocol":"smb","go_poc":{"PocName":"NetBios-GetHostInfo","Target":"192.0.2.10:445"}}`)
	select {
	case vuln := <-vulnBuffer2:
		t.Fatalf("protocol evidence became a vulnerability: %+v", vuln)
	default:
	}
	select {
	case asset := <-assetBuffer:
		if asset.Target != "192.0.2.10:445" || asset.Service != "smb" || asset.Protocol != "ProtocolCheck" {
			t.Fatalf("unexpected protocol evidence asset: %+v", asset)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("protocol evidence was not routed to the asset buffer")
	}
}

func drainResultBuffers(t *testing.T) {
	t.Helper()
	for {
		select {
		case <-assetBuffer:
		case <-fpBuffer:
		case <-vulnBuffer2:
		default:
			return
		}
	}
}

func TestExtractHostAndPort(t *testing.T) {
	cases := []struct {
		name   string
		target string
		host   string
		port   int
	}{
		{"http url with path", "http://1.2.3.4:8080/login", "1.2.3.4", 8080},
		{"http default port", "http://example.invalid", "example.invalid", 80},
		{"https default port", "https://example.invalid", "example.invalid", 443},
		{"https explicit port", "https://example.invalid:8443/x", "example.invalid", 8443},
		{"host:port no scheme", "1.2.3.4:8080", "1.2.3.4", 8080},
		{"ssh url", "ssh://5.6.7.8:22", "5.6.7.8", 22},
		{"bare ip", "1.2.3.4", "1.2.3.4", 0},
		{"bare domain", "example.invalid", "example.invalid", 0},
		{"empty", "", "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host, port := extractHostAndPort(tc.target)
			if host != tc.host || port != tc.port {
				t.Fatalf("extractHostAndPort(%q) = (%q,%d), want (%q,%d)", tc.target, host, port, tc.host, tc.port)
			}
		})
	}
}

func TestAddResultAsyncPopulatesVulnHostPort(t *testing.T) {
	drainResultBuffers(t)
	taskOwnerCache.Store("task-vuln-hp", &taskOwnerEntry{ProjectID: "project-a", TenantID: "tenant-a"})

	AddResultAsync("task-vuln-hp", "Nuclei", `{"target":"http://1.2.3.4:8080/login","plugin":"poc-hp","severity":"high"}`)
	select {
	case vuln := <-vulnBuffer2:
		if vuln.Host != "1.2.3.4" || vuln.Port != 8080 {
			t.Fatalf("expected host/port populated, got host=%q port=%d", vuln.Host, vuln.Port)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected vulnerability for explicit url target")
	}

	// https 无显式端口补 443。
	AddResultAsync("task-vuln-hp", "Nuclei", `{"target":"https://example.invalid","plugin":"poc-hp2","severity":"low"}`)
	select {
	case vuln := <-vulnBuffer2:
		if vuln.Host != "example.invalid" || vuln.Port != 443 {
			t.Fatalf("expected https default 443, got host=%q port=%d", vuln.Host, vuln.Port)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected vulnerability for https target")
	}
}

func TestParseNucleiPacketOrdersByStepIndex(t *testing.T) {
	event := map[string]interface{}{
		"packet": map[string]interface{}{
			"1": map[string]interface{}{"Request": "GET /read HTTP/1.1", "Response": "HTTP/1.1 200 OK two"},
			"0": map[string]interface{}{"Request": "POST /exec HTTP/1.1", "Response": "HTTP/1.1 200 OK one"},
		},
	}
	pairs := parseNucleiPacket(event)
	if len(pairs) != 2 {
		t.Fatalf("expected 2 pairs, got %d", len(pairs))
	}
	if pairs[0].Request != "POST /exec HTTP/1.1" || pairs[1].Request != "GET /read HTTP/1.1" {
		t.Fatalf("pairs not ordered by numeric index: %+v", pairs)
	}
}

func TestParseNucleiPacketMissingOrEmpty(t *testing.T) {
	if got := parseNucleiPacket(map[string]interface{}{}); got != nil {
		t.Fatalf("expected nil for missing packet, got %v", got)
	}
	if got := parseNucleiPacket(map[string]interface{}{"packet": map[string]interface{}{}}); got != nil {
		t.Fatalf("expected nil for empty packet, got %v", got)
	}
}

func TestFormatNucleiPacketSequenceNumbersSteps(t *testing.T) {
	pairs := []nucleiPacketPair{
		{Request: "REQ1", Response: "RESP1"},
		{Request: "REQ2", Response: "RESP2"},
	}
	req, resp := formatNucleiPacketSequence(pairs)
	if !strings.Contains(req, "===== [Request 1] =====\nREQ1") || !strings.Contains(req, "===== [Request 2] =====\nREQ2") {
		t.Fatalf("request sequence missing numbered steps:\n%s", req)
	}
	if !strings.Contains(resp, "===== [Response 1] =====\nRESP1") || !strings.Contains(resp, "===== [Response 2] =====\nRESP2") {
		t.Fatalf("response sequence missing numbered steps:\n%s", resp)
	}
}

func TestAddResultAsyncExpandsNucleiPacketToSequence(t *testing.T) {
	drainResultBuffers(t)
	taskOwnerCache.Store("task-vuln-pkt", &taskOwnerEntry{ProjectID: "project-a", TenantID: "tenant-a"})

	resultEvent := `{"template-id":"multi-step-cmd","host":"http://1.2.3.4:8080","request":"GET /echo HTTP/1.1","response":"HTTP/1.1 200 OK","packet":{"0":{"Request":"POST /exec HTTP/1.1\r\n\r\ncmd=id","Response":"HTTP/1.1 200 OK"},"1":{"Request":"GET /echo HTTP/1.1","Response":"HTTP/1.1 200 OK\r\n\r\nuid=0(root)"}}}`
	AddResultAsync("task-vuln-pkt", "Nuclei", `{"nuclei":`+strconv.Quote(resultEvent)+`}`)

	select {
	case vuln := <-vulnBuffer2:
		if !strings.Contains(vuln.Request, "===== [Request 1] =====") || !strings.Contains(vuln.Request, "cmd=id") {
			t.Fatalf("request sequence missing first (send-command) step:\n%s", vuln.Request)
		}
		if !strings.Contains(vuln.Request, "===== [Request 2] =====") || !strings.Contains(vuln.Request, "GET /echo") {
			t.Fatalf("request sequence missing second (read-echo) step:\n%s", vuln.Request)
		}
		if !strings.Contains(vuln.Response, "===== [Response 1] =====") || !strings.Contains(vuln.Response, "===== [Response 2] =====") {
			t.Fatalf("response sequence missing steps:\n%s", vuln.Response)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected vulnerability for nuclei multi-step packet payload")
	}
}

func TestAddResultAsyncSinglePacketKeepsPlainRequestResponse(t *testing.T) {
	drainResultBuffers(t)
	taskOwnerCache.Store("task-vuln-1pkt", &taskOwnerEntry{ProjectID: "project-a", TenantID: "tenant-a"})

	resultEvent := `{"template-id":"single-step","host":"http://1.2.3.4:8080","request":"GET /only HTTP/1.1","response":"HTTP/1.1 200 OK","packet":{"0":{"Request":"GET /only HTTP/1.1","Response":"HTTP/1.1 200 OK"}}}`
	AddResultAsync("task-vuln-1pkt", "Nuclei", `{"nuclei":`+strconv.Quote(resultEvent)+`}`)

	select {
	case vuln := <-vulnBuffer2:
		if vuln.Request != "GET /only HTTP/1.1" {
			t.Fatalf("single-step packet must keep plain request, got %q", vuln.Request)
		}
		if strings.Contains(vuln.Request, "===== [Request 1] =====") {
			t.Fatalf("single-step packet must not be reformatted, got %q", vuln.Request)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected vulnerability for single-step nuclei payload")
	}
}
