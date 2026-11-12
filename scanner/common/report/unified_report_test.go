package report

import (
	"encoding/json"
	"html"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/TokEat/argus/scanner/structs"
	interactshServer "github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	nucleiOutput "github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// TestUnifiedReportUsesConfiguredPathAndContainsCompleteScanInformation locks
// down the CLI report contract from Issue #184: result.txt remains available,
// while exactly one caller-selected HTML report contains every scan result
// category observed by the report session.
func TestUnifiedReportUsesConfiguredPathAndContainsCompleteScanInformation(t *testing.T) {
	testDir := t.TempDir()
	resultDir := filepath.Join(testDir, "scan-data")
	reportDir := filepath.Join(testDir, "reports")
	if err := os.MkdirAll(resultDir, 0o755); err != nil {
		t.Fatalf("create result directory: %v", err)
	}
	if err := os.MkdirAll(reportDir, 0o755); err != nil {
		t.Fatalf("create report directory: %v", err)
	}

	resultPath := filepath.Join(resultDir, "result.txt")
	reportPath := filepath.Join(reportDir, "operator-selected.html")
	resultData := strings.Join([]string{
		"[Alive] 192.0.2.11",
		"[Nmap] custom-tls://192.0.2.10:18443",
		"[DNS-SubFinder] passive.scan.example.test certificate-transparency",
		"[DNS-Brute] brute.scan.example.test",
		"[CDN-Domain] cdn.scan.example.test ExampleCDN",
		"[RealIP] origin.scan.example.test 192.0.2.21,192.0.2.22",
		"[Web] https://scan.example.test 200 Example Control Plane",
		"[Finger] https://scan.example.test [Test-Fingerprint-184,nginx]",
	}, "\n") + "\n"
	if err := os.WriteFile(resultPath, []byte(resultData), 0o600); err != nil {
		t.Fatalf("write result fixture: %v", err)
	}

	startedAt := time.Date(2026, time.August, 11, 8, 0, 0, 0, time.UTC)
	session, finished := newUnifiedReportTestSession(t, Options{
		Path:       reportPath,
		RunID:      "issue-184-complete-scan",
		Targets:    []string{"192.0.2.0/24", "https://scan.example.test"},
		SourceFile: resultPath,
		StartedAt:  startedAt,
	})

	for _, message := range completeScanMessages() {
		session.Observe(message)
	}
	finishUnifiedReportTestSession(t, session, finished, Summary{
		Status:     "completed",
		FinishedAt: startedAt.Add(90 * time.Second),
	})

	gotResult, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatalf("read preserved result file: %v", err)
	}
	if string(gotResult) != resultData {
		t.Fatalf("result file changed while generating report\nwant: %q\n got: %q", resultData, gotResult)
	}

	reportHTML := readReportFile(t, reportPath)
	assertArgusReportBrand(t, reportHTML)
	assertSelfContainedReportHTML(t, reportHTML)
	for _, want := range []string{
		"issue-184-complete-scan",
		"192.0.2.0/24",
		"192.0.2.11",
		"192.0.2.10",
		"18443",
		"custom-tls",
		"passive.scan.example.test",
		"certificate-transparency",
		"brute.scan.example.test",
		"cdn.scan.example.test",
		"ExampleCDN",
		"origin.scan.example.test",
		"192.0.2.21",
		"192.0.2.22",
		"https://scan.example.test",
		"200",
		"Example Control Plane",
		"CN=scan.example.test issuer=ExampleCA",
		"Test-Fingerprint-184",
		"nginx",
		"test-region-184",
		"issue-184-nuclei-template",
		"issue-184-test-poc",
		"validation completed",
		"GET /nuclei-first HTTP/1.1",
		"HTTP/1.1 401 Unauthorized",
		"POST /nuclei-second HTTP/1.1",
		"HTTP/1.1 200 OK\nContent-Length: 9\n\nvalidated",
		"GET /vulnerable HTTP/1.1",
		"HTTP/1.1 200 OK",
	} {
		if !strings.Contains(reportHTML, want) {
			t.Errorf("unified report is missing %q", want)
		}
	}
	if !strings.Contains(strings.ToUpper(reportHTML), "HIGH") {
		t.Errorf("unified report is missing vulnerability severity %q", "High")
	}
	for eventType, category := range map[string]string{
		"Nmap":          categoryServices,
		"DNS-SubFinder": categoryAssets,
		"DNS-Brute":     categoryAssets,
		"CDN-Domain":    categoryAssets,
		"RealIP":        categoryAssets,
	} {
		assertRecordCategory(t, reportHTML, eventType, category)
	}

	assertOnlyConfiguredHTMLReport(t, testDir, reportPath)
}

func TestUnifiedReportEscapesUntrustedScanData(t *testing.T) {
	testDir := t.TempDir()
	resultPath := filepath.Join(testDir, "result.txt")
	reportPath := filepath.Join(testDir, "argus-report.html")
	resultData := "preserved result output\n"
	if err := os.WriteFile(resultPath, []byte(resultData), 0o600); err != nil {
		t.Fatalf("write result fixture: %v", err)
	}

	webURI := `https://scan.example.test/?q=<script>uriProbe()</script>`
	webTitle := `<img src=x onerror="webProbe()">`
	fingerprint := `<script>fingerprintProbe()</script>`
	protocol := `<img src=x onerror="protocolProbe()">`
	description := `<img src=x onerror="descriptionProbe()">`
	target := `https://scan.example.test/?q=<script>targetProbe()</script>`
	request := `</pre><script>requestProbe()</script>`
	response := `</pre><script>responseProbe()</script>`
	rawRequest := `00000000  00 ff 3c 73 63 72 69 70 74 3e`
	rawResponse := `00000000  fe 3c 2f 70 72 65 3e`

	startedAt := time.Date(2026, time.August, 11, 9, 0, 0, 0, time.UTC)
	session, finished := newUnifiedReportTestSession(t, Options{
		Path:       reportPath,
		RunID:      "issue-184-escaping",
		Targets:    []string{target},
		SourceFile: resultPath,
		StartedAt:  startedAt,
	})
	for _, message := range []structs.OutputMessage{
		{Type: "Nmap", IP: "192.0.2.20", Port: "443", Protocol: protocol},
		{Type: "Web", URI: webURI, Web: structs.WebInfo{Status: "200", Title: webTitle}},
		{Type: "Finger", URI: webURI, Finger: []string{fingerprint}},
		{
			Type: "GoPoc",
			GoPoc: structs.GoPocsResultType{
				PocName:     "escaping-test-poc",
				Security:    "High",
				Description: description,
				Target:      target,
				InfoLeft:    request,
				InfoRight:   response,
				Exchanges: []structs.GoPocExchange{{
					Label: "binary verification", Request: rawRequest, Response: rawResponse, Encoding: "hex-dump",
				}},
			},
		},
	} {
		session.Observe(message)
	}
	finishUnifiedReportTestSession(t, session, finished, Summary{
		Status:     "completed",
		FinishedAt: startedAt.Add(time.Minute),
	})

	reportHTML := readReportFile(t, reportPath)
	assertArgusReportBrand(t, reportHTML)
	for _, untrusted := range []string{webURI, webTitle, fingerprint, protocol, description, target, request, response} {
		if strings.Contains(reportHTML, untrusted) {
			t.Errorf("report contains unescaped scan data %q", untrusted)
		}
		if escaped := html.EscapeString(untrusted); !strings.Contains(reportHTML, escaped) {
			t.Errorf("report is missing escaped scan data %q", escaped)
		}
	}
	for _, evidence := range []string{"binary verification · hex-dump", rawRequest, rawResponse} {
		if !strings.Contains(reportHTML, evidence) {
			t.Errorf("report is missing GoPoc evidence %q", evidence)
		}
	}
	assertOnlyConfiguredHTMLReport(t, testDir, reportPath)
}

func TestUnifiedReportRejectsResultPathAsHTMLDestination(t *testing.T) {
	path := filepath.Join(t.TempDir(), "result.html")
	if _, err := NewSession(Options{
		Path: path, RunID: "issue-184-path-conflict", SourceFile: path, StartedAt: time.Now(),
	}); err == nil || !strings.Contains(err.Error(), "must differ") {
		t.Fatalf("NewSession path conflict error = %v", err)
	}
}

func TestUnifiedReportAbortRemovesPrivateSpools(t *testing.T) {
	dir := t.TempDir()
	session, err := NewSession(Options{
		Path: filepath.Join(dir, "report.html"), RunID: "issue-184-abort",
		SourceFile: filepath.Join(dir, "result.txt"), StartedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("create report session: %v", err)
	}
	spoolPaths := make([]string, 0, len(session.paths))
	for _, path := range session.paths {
		spoolPaths = append(spoolPaths, path)
	}
	if err := session.Abort(); err != nil {
		t.Fatalf("abort report session: %v", err)
	}
	for _, path := range spoolPaths {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("spool %q remained after abort: %v", path, err)
		}
	}
}

func TestUnifiedReportRendersCompleteNucleiEvidenceWithUniqueIDs(t *testing.T) {
	testDir := t.TempDir()
	reportPath := filepath.Join(testDir, "nuclei-evidence.html")
	startedAt := time.Date(2026, time.August, 11, 10, 0, 0, 0, time.UTC)
	session, finished := newUnifiedReportTestSession(t, Options{
		Path:      reportPath,
		RunID:     "issue-184-nuclei-evidence",
		Targets:   []string{"https://scan.example.test"},
		StartedAt: startedAt,
	})

	standaloneRequest := "standalone-request-marker"
	standaloneResponse := "standalone-response-marker"
	standaloneCURL := "curl --request GET https://scan.example.test/standalone curl-standalone-marker"
	session.Observe(nucleiMessage(t, nucleiOutput.ResultEvent{
		TemplateID: "issue-184-standalone-evidence",
		Info: model.Info{
			Name:           "Standalone request response evidence",
			SeverityHolder: severity.Holder{Severity: severity.High},
		},
		Type:        "http",
		Matched:     "https://scan.example.test/standalone",
		Request:     standaloneRequest,
		Response:    standaloneResponse,
		CURLCommand: standaloneCURL,
	}))

	duplicateRequest := "packet-main-duplicate-request-marker"
	duplicateResponse := "packet-main-duplicate-response-marker"
	packetCURL := "curl --request POST https://scan.example.test/packet curl-packet-marker"
	session.Observe(nucleiMessage(t, nucleiOutput.ResultEvent{
		TemplateID: "issue-184-packet-evidence",
		Info: model.Info{
			Name:           "Packet evidence",
			SeverityHolder: severity.Holder{Severity: severity.Medium},
		},
		Type:        "http",
		Matched:     "https://scan.example.test/packet",
		Request:     duplicateRequest,
		Response:    duplicateResponse,
		CURLCommand: packetCURL,
		Packet: map[int]nucleiOutput.RequestResponsePair{
			0: {Request: duplicateRequest, Response: duplicateResponse},
			2: {Request: "packet-step-two-request-marker", Response: "packet-step-two-response-marker"},
		},
	}))

	finishUnifiedReportTestSession(t, session, finished, Summary{
		Status:     "completed",
		FinishedAt: startedAt.Add(time.Minute),
	})

	reportHTML := readReportFile(t, reportPath)
	for _, want := range []string{
		standaloneRequest,
		standaloneResponse,
		standaloneCURL,
		duplicateRequest,
		duplicateResponse,
		"packet-step-two-request-marker",
		"packet-step-two-response-marker",
		packetCURL,
	} {
		if !strings.Contains(reportHTML, want) {
			t.Errorf("Nuclei evidence report is missing %q", want)
		}
	}
	if count := strings.Count(reportHTML, duplicateRequest); count != 1 {
		t.Errorf("duplicate main request was rendered %d times, want 1", count)
	}
	if count := strings.Count(reportHTML, duplicateResponse); count != 1 {
		t.Errorf("duplicate main response was rendered %d times, want 1", count)
	}
	assertUniqueEvidenceIDs(t, reportHTML, 2)
}

func TestCLIReportRetainsSuccessfulCredentialEvidence(t *testing.T) {
	const (
		username = "report-admin"
		password = "report-secret-value"
	)
	reportPath := filepath.Join(t.TempDir(), "credential-report.html")
	startedAt := time.Date(2026, time.August, 13, 10, 0, 0, 0, time.UTC)
	session, finished := newUnifiedReportTestSession(t, Options{
		Path: reportPath, RunID: "credential-report-contract", Targets: []string{"192.0.2.10:22"}, StartedAt: startedAt,
	})
	result := structs.GoPocsResultType{
		PocName:  "SSH-Login",
		Security: "CRITICAL",
		Target:   "192.0.2.10:22",
		InfoLeft: "Username: " + username + "\nPassword: " + password + "\n",
		ShowMsg:  "SSH credential verified",
	}
	item := normalizeGoPoc(result)
	if item.Vulnerability == nil || len(item.Vulnerability.Exchanges) != 1 {
		t.Fatalf("credential evidence missing from report model: %+v", item)
	}
	evidence := item.Vulnerability.Exchanges[0].Request
	if !strings.Contains(evidence, username) || !strings.Contains(evidence, password) {
		t.Fatalf("CLI report redacted successful credential evidence: %q", evidence)
	}
	session.Observe(structs.OutputMessage{Type: "GoPoc", GoPoc: result})
	finishUnifiedReportTestSession(t, session, finished, Summary{Status: "completed", FinishedAt: startedAt.Add(time.Second)})
	reportHTML := readReportFile(t, reportPath)
	if !strings.Contains(reportHTML, username) || !strings.Contains(reportHTML, password) {
		t.Fatalf("rendered CLI HTML report omitted successful credential evidence")
	}
}

func TestUnifiedReportPreservesEscapedNucleiInteractionEvidence(t *testing.T) {
	testDir := t.TempDir()
	reportPath := filepath.Join(testDir, "nuclei-oast-evidence.html")
	startedAt := time.Date(2026, time.August, 11, 10, 30, 0, 0, time.UTC)
	session, finished := newUnifiedReportTestSession(t, Options{
		Path:      reportPath,
		RunID:     "issue-184-nuclei-oast",
		Targets:   []string{"https://scan.example.test"},
		StartedAt: startedAt,
	})

	rawRequest := "GET /oast?q=</pre><script>oastRequestProbe()</script> HTTP/1.1"
	rawResponse := "HTTP/1.1 200 OK\r\n\r\n</pre><script>oastResponseProbe()</script>"
	fullID := "interaction-full-id-184</pre><script>fullIDProbe()</script>"
	remoteAddress := "192.0.2.60:53000 <img src=x onerror=remoteProbe()>"
	interactionAt := time.Date(2026, time.August, 11, 10, 30, 45, 0, time.UTC)
	session.Observe(nucleiMessage(t, nucleiOutput.ResultEvent{
		TemplateID: "issue-184-oast-evidence",
		Info: model.Info{
			Name:           "OAST interaction evidence",
			SeverityHolder: severity.Holder{Severity: severity.High},
		},
		Type:    "http",
		Matched: "https://scan.example.test/oast",
		Interaction: &interactshServer.Interaction{
			Protocol:      "dns",
			FullId:        fullID,
			RawRequest:    rawRequest,
			RawResponse:   rawResponse,
			RemoteAddress: remoteAddress,
			Timestamp:     interactionAt,
		},
	}))
	finishUnifiedReportTestSession(t, session, finished, Summary{
		Status:     "completed",
		FinishedAt: startedAt.Add(time.Minute),
	})

	reportHTML := readReportFile(t, reportPath)
	if !strings.Contains(strings.ToUpper(reportHTML), "OAST") {
		t.Errorf("Nuclei interaction is not identified as OAST evidence")
	}
	for _, want := range []string{"dns", "full-id", "remote-address", "timestamp", interactionAt.Format(time.RFC3339)} {
		if !strings.Contains(reportHTML, want) {
			t.Errorf("Nuclei interaction metadata is missing %q", want)
		}
	}
	for _, untrusted := range []string{rawRequest, rawResponse, fullID, remoteAddress} {
		if strings.Contains(reportHTML, untrusted) {
			t.Errorf("report contains unescaped OAST data %q", untrusted)
		}
		if escaped := html.EscapeString(untrusted); !strings.Contains(reportHTML, escaped) {
			t.Errorf("report is missing escaped OAST data %q", escaped)
		}
	}
	evidencePattern := regexp.MustCompile(`(?s)<details class="evidence".*?` + regexp.QuoteMeta(html.EscapeString(rawRequest)) + `.*?` + regexp.QuoteMeta(html.EscapeString(rawResponse)) + `.*?</details>`)
	if !evidencePattern.MatchString(reportHTML) {
		t.Errorf("Nuclei interaction request and response are not retained together as evidence")
	}
}

func TestUnifiedReportRetainsProtectedEvidenceSpoolWhenPublishFails(t *testing.T) {
	testDir := t.TempDir()
	reportPath := filepath.Join(testDir, "already-exists.html")
	startedAt := time.Date(2026, time.August, 11, 11, 0, 0, 0, time.UTC)
	session, err := NewSession(Options{
		Path:      reportPath,
		RunID:     "issue-184-publish-failure",
		Targets:   []string{"https://scan.example.test"},
		StartedAt: startedAt,
	})
	if err != nil {
		t.Fatalf("create report session: %v", err)
	}
	spoolPaths := make([]string, 0, len(session.paths))
	for _, path := range session.paths {
		spoolPaths = append(spoolPaths, path)
	}
	t.Cleanup(func() {
		for _, path := range spoolPaths {
			_ = os.Remove(path)
		}
	})
	vulnerabilitySpool := session.paths[categoryVulnerabilities]
	if vulnerabilitySpool == "" {
		t.Fatal("report session did not create a vulnerability evidence spool")
	}

	evidenceMarker := "retained-sensitive-evidence-marker"
	session.Observe(structs.OutputMessage{
		Type: "GoPoc",
		GoPoc: structs.GoPocsResultType{
			PocName:   "publish-failure-poc",
			Security:  "High",
			Target:    "https://scan.example.test/publish-failure",
			InfoLeft:  evidenceMarker,
			InfoRight: "retained-response-marker",
		},
	})
	if err := os.WriteFile(reportPath, []byte("pre-existing operator report\n"), 0o600); err != nil {
		t.Fatalf("create publish conflict: %v", err)
	}

	err = session.Finish(Summary{Status: "completed", FinishedAt: startedAt.Add(time.Minute)})
	if err == nil {
		t.Fatal("Finish succeeded despite a pre-existing report path")
	}
	if !strings.Contains(err.Error(), reportPath) {
		t.Errorf("publish error does not identify the report path: %v", err)
	}
	if !strings.Contains(err.Error(), vulnerabilitySpool) {
		t.Errorf("publish error does not identify the retained evidence spool %q: %v", vulnerabilitySpool, err)
	}

	info, statErr := os.Stat(vulnerabilitySpool)
	if statErr != nil {
		t.Fatalf("retained vulnerability evidence spool is unavailable: %v", statErr)
	}
	if permission := info.Mode().Perm(); runtime.GOOS != "windows" && permission != 0o600 {
		t.Errorf("retained vulnerability evidence spool permissions = %04o, want 0600", permission)
	}
	spoolContents, readErr := os.ReadFile(vulnerabilitySpool)
	if readErr != nil {
		t.Fatalf("read retained vulnerability evidence spool: %v", readErr)
	}
	if !strings.Contains(string(spoolContents), evidenceMarker) {
		t.Errorf("retained vulnerability evidence spool is missing the evidence marker")
	}
}

func completeScanMessages() []structs.OutputMessage {
	return []structs.OutputMessage{
		{Type: "IPAlive", IP: "192.0.2.11", City: "test-region-184", AdditionalMsg: "icmp"},
		{Type: "Nmap", IP: "192.0.2.10", Port: "18443", Protocol: "custom-tls"},
		{Type: "DNS-SubFinder", Domain: "passive.scan.example.test", AdditionalMsg: "certificate-transparency"},
		{Type: "DNS-Brute", Domain: "brute.scan.example.test"},
		{Type: "CDN-Domain", Domain: "cdn.scan.example.test", AdditionalMsg: "ExampleCDN"},
		{Type: "RealIP", Domain: "origin.scan.example.test", IPs: []string{"192.0.2.21", "192.0.2.22"}},
		{
			Type:   "Web",
			IP:     "192.0.2.10",
			Port:   "18443",
			URI:    "https://scan.example.test",
			Web:    structs.WebInfo{Status: "200", Title: "Example Control Plane", Cert: "CN=scan.example.test issuer=ExampleCA"},
			Finger: []string{"Test-Fingerprint-184", "nginx"},
		},
		{Type: "Finger", URI: "https://scan.example.test", Finger: []string{"Test-Fingerprint-184", "nginx"}},
		{
			Type:   "Nuclei",
			URI:    "https://scan.example.test/nuclei",
			Show:   "[issue-184-nuclei-template] [high] https://scan.example.test/nuclei",
			Nuclei: `{"template-id":"issue-184-nuclei-template","info":{"name":"Issue 184 evidence test","severity":"high"},"matched-at":"https://scan.example.test/nuclei","packet":{"1":{"Request":"GET /nuclei-first HTTP/1.1","Response":"HTTP/1.1 401 Unauthorized"},"2":{"Request":"POST /nuclei-second HTTP/1.1","Response":"HTTP/1.1 200 OK\nContent-Length: 9\n\nvalidated"}}}`,
		},
		{
			Type: "GoPoc",
			GoPoc: structs.GoPocsResultType{
				PocName:     "issue-184-test-poc",
				Security:    "High",
				Description: "Synthetic authorized-test finding",
				Target:      "https://scan.example.test/vulnerable",
				InfoLeft:    "GET /vulnerable HTTP/1.1",
				InfoRight:   "HTTP/1.1 200 OK",
				ShowMsg:     "validation completed",
			},
		},
	}
}

func newUnifiedReportTestSession(t *testing.T, options Options) (*Session, *bool) {
	t.Helper()
	session, err := NewSession(options)
	if err != nil {
		t.Fatalf("create unified report session: %v", err)
	}
	finished := false
	t.Cleanup(func() {
		if !finished {
			_ = session.Abort()
		}
	})
	return session, &finished
}

func finishUnifiedReportTestSession(t *testing.T, session *Session, finished *bool, summary Summary) {
	t.Helper()
	if err := session.Finish(summary); err != nil {
		t.Fatalf("finish unified report session: %v", err)
	}
	*finished = true
}

func nucleiMessage(t *testing.T, event nucleiOutput.ResultEvent) structs.OutputMessage {
	t.Helper()
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal Nuclei result event: %v", err)
	}
	return structs.OutputMessage{
		Type:   "Nuclei",
		URI:    event.Matched,
		Show:   "[" + event.TemplateID + "] [" + event.Info.SeverityHolder.Severity.String() + "] " + event.Matched,
		Nuclei: string(payload),
	}
}

func assertUniqueEvidenceIDs(t *testing.T, reportHTML string, minimumVulnerabilities int) {
	t.Helper()
	evidenceIDPattern := regexp.MustCompile(`id="((record-[0-9]+)-(?:request|response)-[0-9]+)"`)
	matches := evidenceIDPattern.FindAllStringSubmatch(reportHTML, -1)
	if len(matches) == 0 {
		t.Fatal("report contains no request/response evidence IDs")
	}
	ids := make(map[string]struct{}, len(matches))
	vulnerabilityIDs := make(map[string]struct{}, minimumVulnerabilities)
	for _, match := range matches {
		if _, duplicate := ids[match[1]]; duplicate {
			t.Errorf("duplicate evidence element ID %q", match[1])
		}
		ids[match[1]] = struct{}{}
		vulnerabilityIDs[match[2]] = struct{}{}
	}
	if len(vulnerabilityIDs) < minimumVulnerabilities {
		t.Errorf("evidence IDs cover %d vulnerabilities, want at least %d", len(vulnerabilityIDs), minimumVulnerabilities)
	}
}

func assertRecordCategory(t *testing.T, reportHTML, eventType, category string) {
	t.Helper()
	pattern := regexp.MustCompile(`(?s)<article class="report-item record" data-category="` + regexp.QuoteMeta(category) + `"[^>]*>.*?<div class="record-meta">` + regexp.QuoteMeta(eventType) + `</div>.*?</article>`)
	if !pattern.MatchString(reportHTML) {
		t.Errorf("event type %q is not rendered in report category %q", eventType, category)
	}
}

func readReportFile(t *testing.T, reportPath string) string {
	t.Helper()
	contents, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read unified report %q: %v", reportPath, err)
	}
	return string(contents)
}

func assertArgusReportBrand(t *testing.T, reportHTML string) {
	t.Helper()
	legacyBrand := "dd" + "dd"
	lowerHTML := strings.ToLower(reportHTML)
	if strings.Contains(lowerHTML, legacyBrand) {
		t.Errorf("unified report contains legacy brand %q", legacyBrand)
	}
	titleStart := strings.Index(lowerHTML, "<title")
	titleEnd := strings.Index(lowerHTML, "</title>")
	if titleStart < 0 || titleEnd < titleStart || !strings.Contains(reportHTML[titleStart:titleEnd], "Argus") {
		t.Errorf("unified report title is not Argus branded")
	}
	bodyStart := strings.Index(lowerHTML, "<body")
	if bodyStart < 0 || !strings.Contains(reportHTML[bodyStart:], "Argus") {
		t.Errorf("unified report body is not Argus branded")
	}
	if !strings.Contains(reportHTML, "run_summary") {
		t.Errorf("unified report does not explain the process-terminal status boundary")
	}
}

func assertSelfContainedReportHTML(t *testing.T, reportHTML string) {
	t.Helper()
	lowerHTML := strings.ToLower(reportHTML)
	if count := strings.Count(lowerHTML, "<!doctype html>"); count != 1 {
		t.Errorf("unified report DOCTYPE count = %d, want exactly 1", count)
	}
	externalScriptPattern := regexp.MustCompile(`(?i)<script\b[^>]*\bsrc\s*=`)
	if externalScriptPattern.MatchString(reportHTML) {
		t.Errorf("unified report contains an external script src")
	}
	if strings.Contains(lowerHTML, "jquery") {
		t.Errorf("unified report contains jQuery")
	}
}

func assertOnlyConfiguredHTMLReport(t *testing.T, root, reportPath string) {
	t.Helper()
	var htmlFiles []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() && strings.EqualFold(filepath.Ext(entry.Name()), ".html") {
			htmlFiles = append(htmlFiles, path)
		}
		if !entry.IsDir() && strings.HasSuffix(strings.ToLower(entry.Name()), "_assets.html") {
			t.Errorf("legacy split asset report was generated: %s", path)
		}
		if !entry.IsDir() && strings.HasSuffix(strings.ToLower(entry.Name()), ".part") {
			t.Errorf("temporary report artifact was not cleaned up: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("inspect report artifacts: %v", err)
	}
	if len(htmlFiles) != 1 || htmlFiles[0] != reportPath {
		t.Fatalf("expected exactly the configured HTML report %q, got %q", reportPath, htmlFiles)
	}
}
