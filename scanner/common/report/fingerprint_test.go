package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/P0lar1ght/argus/scanner/structs"
)

func TestFingerprintReportAggregatesSourcesByServiceAndProduct(t *testing.T) {
	directory := t.TempDir()
	resultPath := filepath.Join(directory, "result.txt")
	reportPath := filepath.Join(directory, "report.html")
	if err := os.WriteFile(resultPath, []byte("raw fingerprint events remain authoritative\n"), 0o600); err != nil {
		t.Fatalf("write result fixture: %v", err)
	}

	startedAt := time.Date(2026, time.August, 11, 12, 0, 0, 0, time.UTC)
	session, err := NewSession(Options{
		Path: reportPath, RunID: "fingerprint-aggregation", SourceFile: resultPath, StartedAt: startedAt,
	})
	if err != nil {
		t.Fatalf("create report session: %v", err)
	}
	t.Cleanup(func() { _ = session.Abort() })

	for _, message := range []structs.OutputMessage{
		{
			Type: "Finger", URI: "https://Example.TEST/", Finger: []string{"Jenkins"},
			Web: structs.WebInfo{Status: "200", Title: "Jenkins"},
		},
		{
			Type: "Active-Finger", URI: "https://example.test:443/jenkins/login", Finger: []string{"Jenkins"},
			Web: structs.WebInfo{Status: "200", Title: "Jenkins sign in"},
		},
		{
			Type: "Active-Finger", URI: "https://example.test:443/jenkins/login", Finger: []string{"Jenkins"},
			Web: structs.WebInfo{Status: "200", Title: "Jenkins sign in"},
		},
		{
			Type: "Active-Finger", URI: "https://example.test/actuator", Finger: []string{"Spring-Actuator"},
			Web: structs.WebInfo{Status: "200"}, AdditionalMsg: "[dir-fallback]",
		},
		{
			Type: "Active-Finger", URI: "https://example.test:8443/nacos/", Finger: []string{"Alibaba-Nacos"},
			Web: structs.WebInfo{Status: "200", Title: "Nacos"}, AdditionalMsg: "[directory-probe]",
		},
		{
			Type: "Active-Finger", URI: "https://example.test/shiro", Finger: []string{"APACHE-Shiro"},
			AdditionalMsg: "[behavior-probe:shiro-detect]",
		},
	} {
		session.Observe(message)
	}

	if err := session.Finish(Summary{Status: "completed", FinishedAt: startedAt.Add(time.Second)}); err != nil {
		t.Fatalf("finish report: %v", err)
	}
	contentBytes, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	content := string(contentBytes)

	if got := strings.Count(content, `data-fingerprint-product="Jenkins"`); got != 1 {
		t.Fatalf("Jenkins card count = %d, want one aggregated card", got)
	}
	if got := strings.Count(content, `data-fingerprint-product="Spring-Actuator"`); got != 1 {
		t.Fatalf("Spring-Actuator card count = %d, want one aggregated card", got)
	}
	if got := strings.Count(content, `data-fingerprint-product="Alibaba-Nacos"`); got != 1 {
		t.Fatalf("Nacos card count = %d, want one aggregated card", got)
	}
	for _, want := range []string{
		"https://example.test:443",
		"https://Example.TEST/",
		"https://example.test:443/jenkins/login",
		"被动命中",
		"主动路径",
		"双源确认",
		"2 条来源证据",
		"路径推断",
		"疑似",
		"主动路径命中",
		"行为探针",
		"行为确认",
		"产品专用路径返回 HTTP 200，未通过产品指纹规则复核，不作为已识别、不调度 POC。",
		"6 条原始来源记录",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("aggregated report is missing %q", want)
		}
	}
	if strings.Contains(content, "主动确认") {
		t.Errorf("directory hits must not be labeled 主动确认")
	}
	if session.counts.Fingerprints != 4 {
		t.Errorf("unique fingerprint count = %d, want 4", session.counts.Fingerprints)
	}
	if session.counts.FingerprintEvents != 6 {
		t.Errorf("raw fingerprint observation count = %d, want 6", session.counts.FingerprintEvents)
	}
	if session.counts.Records != 4 {
		t.Errorf("rendered record count = %d, want 4", session.counts.Records)
	}
}

func TestFingerprintReportKeepsDifferentServiceBoundariesSeparate(t *testing.T) {
	collector := newFingerprintCollector()
	collector.Add(structs.OutputMessage{Type: "Finger", URI: "http://example.test/", Finger: []string{"nginx"}})
	collector.Add(structs.OutputMessage{Type: "Active-Finger", URI: "https://example.test/admin", Finger: []string{"nginx"}})
	collector.Add(structs.OutputMessage{Type: "Finger", URI: "https://example.test:8443/", Finger: []string{"nginx"}})

	items := collector.Items()
	if len(items) != 3 {
		t.Fatalf("service-scoped fingerprint count = %d, want 3", len(items))
	}
	want := []string{"http://example.test:80", "https://example.test:443", "https://example.test:8443"}
	for index, service := range want {
		if items[index].Fingerprint == nil || items[index].Fingerprint.Service != service {
			t.Fatalf("item %d service = %#v, want %q", index, items[index].Fingerprint, service)
		}
	}
}
