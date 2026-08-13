package db

import (
	"reflect"
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
	AddResultAsync("task-protocol-check", "ProtocolCheck", `{"type":"ProtocolCheck","protocol":"dnp3","go_poc":{"PocName":"DNP3-Scan","Target":"192.0.2.10:20000"}}`)
	select {
	case vuln := <-vulnBuffer2:
		t.Fatalf("protocol evidence became a vulnerability: %+v", vuln)
	default:
	}
	select {
	case asset := <-assetBuffer:
		if asset.Target != "192.0.2.10:20000" || asset.Service != "dnp3" || asset.Protocol != "ProtocolCheck" {
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
