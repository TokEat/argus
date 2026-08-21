package ddout

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/P0lar1ght/argus/scanner/structs"
)

func TestJSONOutputIsVersionedNDJSONAndSummarizedOnce(t *testing.T) {
	resetForTest()
	t.Cleanup(resetForTest)
	var out bytes.Buffer
	writeMu.Lock()
	stdout = &out
	OutputType = "json"
	writeMu.Unlock()

	if err := BeginRun("run-1"); err != nil {
		t.Fatal(err)
	}
	if err := FormatOutputE(OutputMessage{Type: "Web", URI: "http://127.0.0.1:3000"}); err != nil {
		t.Fatal(err)
	}
	if err := EndRun(RunSummary{Status: "completed", ExitCode: 0, Counts: RunCounts{StagesReused: 2}}); err != nil {
		t.Fatal(err)
	}
	if err := EndRun(RunSummary{Status: "completed", ExitCode: 0}); err == nil {
		t.Fatal("expected duplicate EndRun to fail")
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d records, want 2: %q", len(lines), out.String())
	}
	var finding, summary JSONRecord
	if err := json.Unmarshal([]byte(lines[0]), &finding); err != nil {
		t.Fatalf("finding is not JSON: %v", err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &summary); err != nil {
		t.Fatalf("summary is not JSON: %v", err)
	}
	if finding.SchemaVersion != JSONSchemaVersion || finding.RecordType != "finding" || finding.Sequence != 1 || finding.RunID != "run-1" || finding.Finding == nil || finding.Finding.URI != "http://127.0.0.1:3000" {
		t.Fatalf("unexpected finding record: %#v", finding)
	}
	if finding.Finding.Web != nil || finding.Finding.GoPoc != nil {
		t.Fatalf("empty nested values leaked into finding: %#v", finding.Finding)
	}
	if summary.RecordType != "run_summary" || summary.Sequence != 2 || summary.Summary == nil || summary.Summary.Counts.Findings != 1 || summary.Summary.Counts.StagesReused != 2 {
		t.Fatalf("unexpected summary record: %#v", summary)
	}
}

func TestDecodeFindingLineSupportsVersionedAndLegacyFingerRecords(t *testing.T) {
	versioned, err := json.Marshal(JSONRecord{
		SchemaVersion: JSONSchemaVersion, RecordType: "finding", Sequence: 1,
		Finding: &JSONFinding{Type: "Finger", URI: "https://127.0.0.1", Finger: []string{"nginx"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	legacy := `{"type":"Finger","finger":["apache"],"uri":"http://127.0.0.1"}`
	for _, test := range []struct {
		line, uri, finger string
	}{{string(versioned), "https://127.0.0.1", "nginx"}, {legacy, "http://127.0.0.1", "apache"}} {
		message, ok, err := DecodeFindingLine(test.line)
		if err != nil || !ok || message.URI != test.uri || len(message.Finger) != 1 || message.Finger[0] != test.finger {
			t.Fatalf("DecodeFindingLine(%s) = %#v, %v, %v", test.line, message, ok, err)
		}
	}
	summary, err := json.Marshal(JSONRecord{SchemaVersion: JSONSchemaVersion, RecordType: "run_summary", Summary: &RunSummary{Status: "completed"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := DecodeFindingLine(string(summary)); err != nil || ok {
		t.Fatalf("summary decoded as finding: ok=%v err=%v", ok, err)
	}
}

func TestJSONGoPocEvidenceRoundTripsWithoutDroppingExchanges(t *testing.T) {
	want := OutputMessage{
		Type: "GoPoc",
		GoPoc: GoPocsResultType{
			PocName:  "MS17-010",
			Security: "CRITICAL",
			Exchanges: []structs.GoPocExchange{{
				Label: "SMB negotiate", Request: "00000000  ff", Response: "00000000  fe", Encoding: "hex-dump",
			}},
		},
	}
	record := JSONRecord{
		SchemaVersion: JSONSchemaVersion,
		RecordType:    "finding",
		Sequence:      1,
		Finding:       jsonFinding(want),
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	got, ok, err := DecodeFindingLine(string(encoded))
	if err != nil || !ok {
		t.Fatalf("DecodeFindingLine() ok=%v err=%v", ok, err)
	}
	if !reflect.DeepEqual(got.GoPoc.Exchanges, want.GoPoc.Exchanges) {
		t.Fatalf("GoPoc exchanges lost: got %#v want %#v", got.GoPoc.Exchanges, want.GoPoc.Exchanges)
	}
}

func TestJSONOutputRequiresRunAndRejectsPostSummaryFinding(t *testing.T) {
	resetForTest()
	t.Cleanup(resetForTest)
	writeMu.Lock()
	OutputType = "json"
	stdout = &bytes.Buffer{}
	writeMu.Unlock()
	if err := FormatOutputE(OutputMessage{Type: "IPAlive"}); err == nil {
		t.Fatal("expected missing run error")
	}
	if err := BeginRun("failed-run"); err != nil {
		t.Fatal(err)
	}
	if err := EndRun(RunSummary{Status: "failed", ExitCode: 1}); err != nil {
		t.Fatal(err)
	}
	if err := FormatOutputE(OutputMessage{Type: "IPAlive"}); err == nil {
		t.Fatal("expected post-summary error")
	}
}

func TestJSONRunRejectsInvalidIdentityAndTerminalPair(t *testing.T) {
	resetForTest()
	t.Cleanup(resetForTest)
	OutputType = "json"
	stdout = &bytes.Buffer{}
	if err := BeginRun(""); err == nil {
		t.Fatal("empty run id was accepted")
	}
	if err := BeginRun("run-1"); err != nil {
		t.Fatal(err)
	}
	if err := EndRun(RunSummary{Status: "completed", ExitCode: 1}); err == nil {
		t.Fatal("mismatched terminal status and exit code were accepted")
	}
	if err := EndRun(RunSummary{Status: "completed", ExitCode: 0}); err != nil {
		t.Fatal(err)
	}
}

func TestJSONOutputWritesIdenticalRecordsToResultFile(t *testing.T) {
	resetForTest()
	t.Cleanup(resetForTest)
	var out bytes.Buffer
	path := t.TempDir() + "/results.ndjson"
	writeMu.Lock()
	stdout, OutputType, OutputFileName = &out, "json", path
	writeMu.Unlock()
	if err := BeginRun("file-run"); err != nil {
		t.Fatal(err)
	}
	if err := FormatOutputE(OutputMessage{Type: "IPAlive", IP: "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	if err := EndRun(RunSummary{Status: "completed", ExitCode: 0}); err != nil {
		t.Fatal(err)
	}
	file, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(file) != out.String() {
		t.Fatalf("stdout and result file differ:\nstdout=%q\nfile=%q", out.String(), string(file))
	}
}

func TestJSONTerminalRecordReportsResultFileFailure(t *testing.T) {
	resetForTest()
	t.Cleanup(resetForTest)
	var out bytes.Buffer
	OutputType, OutputFileName, stdout = "json", t.TempDir()+"/missing/results.ndjson", &out
	if err := BeginRun("file-failure"); err != nil {
		t.Fatal(err)
	}
	if err := EndRun(RunSummary{Status: "completed", ExitCode: 0}); err == nil {
		t.Fatal("expected result file failure")
	}
	var record JSONRecord
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &record); err != nil {
		t.Fatalf("terminal stdout is invalid: %v: %q", err, out.String())
	}
	if record.Summary == nil || record.Summary.Status != "failed" || record.Summary.ExitCode != 1 {
		t.Fatalf("terminal record did not reflect persistence failure: %#v", record)
	}
}

func TestJSONTerminalStdoutFailureRewritesFileSummaryAsFailed(t *testing.T) {
	resetForTest()
	t.Cleanup(resetForTest)
	path := t.TempDir() + "/result.ndjson"
	stdout, OutputType, OutputFileName = failingWriter{}, "json", path
	if err := BeginRun("stdout-failure"); err != nil {
		t.Fatal(err)
	}
	if err := EndRun(RunSummary{Status: "completed", ExitCode: 0}); err == nil {
		t.Fatal("expected terminal stdout failure")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(contents)), "\n")
	if len(lines) != 1 {
		t.Fatalf("terminal records=%d, want exactly one: %q", len(lines), contents)
	}
	var record JSONRecord
	if err := json.Unmarshal([]byte(lines[0]), &record); err != nil {
		t.Fatal(err)
	}
	if record.Summary == nil || record.Summary.Status != "failed" || record.Summary.ExitCode != 1 {
		t.Fatalf("persisted terminal summary contradicts output failure: %#v", record)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("stdout unavailable")
}

func TestRenderActiveFingerIncludesFallbackTag(t *testing.T) {
	got := Render(OutputMessage{
		Type:          "Active-Finger",
		URI:           "http://127.0.0.1:8081/aaa",
		Finger:        []string{"Shiro"},
		AdditionalMsg: "[dir-fallback]",
	})
	want := "[WEB] http://127.0.0.1:8081/aaa\n     [Finger] Shiro [dir-fallback]"
	if got != want {
		t.Fatalf("unexpected render output: got %q want %q", got, want)
	}
}

func TestRenderNucleiUsesPOCTag(t *testing.T) {
	got := Render(OutputMessage{Type: "Nuclei", Show: "[cve-2021-41773] [high] http://10.0.0.8/cgi-bin/"})
	want := "[POC] [cve-2021-41773] [high] http://10.0.0.8/cgi-bin/"
	if got != want {
		t.Fatalf("unexpected render output: got %q want %q", got, want)
	}
}

func TestRenderGoPocUsesShowMsgAndSecurity(t *testing.T) {
	got := Render(OutputMessage{
		Type: "GoPoc",
		GoPoc: GoPocsResultType{
			Security: "CRITICAL",
			ShowMsg:  "http://127.0.0.1:8081 key=kPH+bIxk5D2deZiIxcaaaA==",
		},
	})
	want := "[POC] [CRITICAL] http://127.0.0.1:8081 key=kPH+bIxk5D2deZiIxcaaaA=="
	if got != want {
		t.Fatalf("unexpected render output: got %q want %q", got, want)
	}
}

func TestRenderNmapIncludesProductVersion(t *testing.T) {
	got := Render(OutputMessage{
		Type:          "Nmap",
		IP:            "10.0.0.8",
		Port:          "445",
		Protocol:      "smb",
		Product:       "Microsoft Windows SMB",
		Version:       "3.1.1",
		AdditionalMsg: "Microsoft Windows SMB 3.1.1 domain=CORP",
	})
	want := "[Port] [tcp] 10.0.0.8:445 smb Microsoft Windows SMB 3.1.1 domain=CORP"
	if got != want {
		t.Fatalf("unexpected render output: got %q want %q", got, want)
	}
}

func TestRenderTCPPortHasTransportTag(t *testing.T) {
	got := Render(OutputMessage{Type: "PortScan", IP: "10.0.0.8", Port: "445"})
	want := "[Port] [tcp] 10.0.0.8:445"
	if got != want {
		t.Fatalf("unexpected render output: got %q want %q", got, want)
	}
}

func TestRenderOtherTransportTag(t *testing.T) {
	got := Render(OutputMessage{Type: "Nmap", IP: "10.0.0.8", Port: "5000", Protocol: "sctp", Transport: "sctp"})
	want := "[Port] [other] 10.0.0.8:5000 sctp"
	if got != want {
		t.Fatalf("unexpected render output: got %q want %q", got, want)
	}
}

func TestColorizeFindingLineHighlightsWEBAndFinger(t *testing.T) {
	prev := useColor
	t.Cleanup(func() { useColor = prev })
	SetUseColor(false)
	plain := formatTextLine(OutputMessage{Type: "Finger", URI: "http://172.20.0.180/", Finger: []string{"Nginx", "GitLab"}})
	if strings.Contains(plain, "\x1b[") {
		t.Fatalf("plain format leaked ANSI: %q", plain)
	}
	SetUseColor(true)
	web := colorizeFindingLine("[WEB] http://172.20.0.180/\n     [Finger] Nginx,GitLab\n     [Code] 200")
	if !strings.Contains(web, "\x1b[") || !strings.Contains(web, "[WEB]") || !strings.Contains(web, "[Finger]") {
		t.Fatalf("web/finger not colored: %q", web)
	}
	finger := colorizeFindingLine("[Finger] ssh://172.20.0.180:22 OpenSSH")
	if !strings.Contains(finger, "\x1b[") || !strings.Contains(finger, "[Finger]") {
		t.Fatalf("service finger not colored: %q", finger)
	}
}

func TestFormatServiceFingerIsNotWEBBlock(t *testing.T) {
	line := formatTextLine(OutputMessage{Type: "Finger", URI: "ssh://172.20.0.180:22", Finger: []string{"OpenSSH", "SSH"}})
	if line != "[Finger] ssh://172.20.0.180:22 OpenSSH,SSH" {
		t.Fatalf("ssh finger = %q", line)
	}
	if shouldBufferWEB(OutputMessage{Type: "Finger", URI: "ssh://172.20.0.180:22"}) {
		t.Fatal("ssh finger must not enter the WEB buffer")
	}
	if !shouldBufferWEB(OutputMessage{Type: "Finger", URI: "http://172.20.0.180/users/sign_in"}) {
		t.Fatal("http finger should still buffer under WEB")
	}
	if shouldBufferWEB(OutputMessage{Type: "Web", URI: "ssh://172.20.0.180:22/"}) {
		t.Fatal("ssh must not enter the WEB buffer")
	}
}

func TestFormatPathAndTopoLines(t *testing.T) {
	path := formatTextLine(OutputMessage{Type: "Path", IP: "10.0.2.20", IPs: []string{"10.0.0.1", "10.0.2.1", "10.0.2.20"}, AdditionalMsg: "hops=2"})
	if path != "[Path] 10.0.2.20 hops=2 10.0.0.1 -> 10.0.2.1 -> 10.0.2.20" {
		t.Fatalf("path = %q", path)
	}
	topo := formatTextLine(OutputMessage{Type: "Topo", AdditionalMsg: "10.0.0.1 -> 10.0.2.0/24"})
	if topo != "[Topo] 10.0.0.1 -> 10.0.2.0/24" {
		t.Fatalf("topo = %q", topo)
	}
}

func TestParseServiceLineRest(t *testing.T) {
	tag, endpoint := ParseServiceLineRest("[udp] 10.0.0.8:53 dns")
	if tag != "udp" || endpoint != "10.0.0.8:53" {
		t.Fatalf("got %q %q", tag, endpoint)
	}
	tag, endpoint = ParseServiceLineRest("10.0.0.8:53/udp dns")
	if tag != "udp" || endpoint != "10.0.0.8:53" {
		t.Fatalf("legacy got %q %q", tag, endpoint)
	}
	tag, endpoint = ParseServiceLineRest("[tcp] 10.0.0.8:445")
	if tag != "tcp" || endpoint != "10.0.0.8:445" {
		t.Fatalf("tcp got %q %q", tag, endpoint)
	}
	tag, endpoint = ParseServiceLineRest("[web] 10.0.0.8:80 http")
	if tag != "web" || endpoint != "10.0.0.8:80" {
		t.Fatalf("web got %q %q", tag, endpoint)
	}
}

func TestFormatOutputMergesSameOriginRedirectIntoOneWEBBlock(t *testing.T) {
	resetForTest()
	t.Cleanup(resetForTest)
	var out bytes.Buffer
	writeMu.Lock()
	stdout = &out
	OutputType = "text"
	writeMu.Unlock()

	if err := FormatOutputE(OutputMessage{
		Type:   "Web",
		URI:    "http://172.20.0.180:80/",
		Web:    WebInfo{Status: "302", Size: "99", Redirect: "http://172.20.0.180/users/sign_in"},
		Finger: []string{"Nginx"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := FormatOutputE(OutputMessage{
		Type:   "Web",
		URI:    "http://172.20.0.180/users/sign_in",
		Web:    WebInfo{Status: "200", Size: "14351", Title: "Sign in · GitLab"},
		Finger: []string{"GitLab", "Ruby", "Nginx", "RAILS-Framework"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := FlushWEBBlocks(); err != nil {
		t.Fatal(err)
	}
	got := strings.TrimSpace(out.String())
	want := strings.Join([]string{
		"[WEB] http://172.20.0.180:80/",
		"     [Finger] Nginx,GitLab,Ruby,RAILS-Framework",
		"     [Code] 200",
		"     [Size] 14351",
		"     [Redirect] /users/sign_in",
		"     [Title] Sign in · GitLab",
	}, "\n")
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}

func TestCanonicalWEBOriginStripsDefaultPortAndPath(t *testing.T) {
	if got := canonicalWEBOrigin("http://172.20.0.180:80/users/sign_in"); got != "http://172.20.0.180/" {
		t.Fatalf("http 80 = %q", got)
	}
	if got := canonicalWEBOrigin("https://10.0.0.8:443/"); got != "https://10.0.0.8/" {
		t.Fatalf("https 443 = %q", got)
	}
	if got := canonicalWEBOrigin("http://10.0.0.8:8080/admin"); got != "http://10.0.0.8:8080/" {
		t.Fatalf("http 8080 = %q", got)
	}
}

func TestFormatOutputMergesFingerIntoOneWEBBlock(t *testing.T) {
	resetForTest()
	t.Cleanup(resetForTest)
	var out bytes.Buffer
	writeMu.Lock()
	stdout = &out
	OutputType = "text"
	writeMu.Unlock()

	if err := FormatOutputE(OutputMessage{
		Type: "Web",
		URI:  "http://10.0.0.8",
		Web:  WebInfo{Status: "200", Size: "12", Title: "Home", Cert: "CN=10.0.0.8"},
	}); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatalf("web line written before fingerprint: %q", out.String())
	}
	if err := FormatOutputE(OutputMessage{
		Type:   "Finger",
		URI:    "http://10.0.0.8/",
		Finger: []string{"nginx"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := FlushWEBBlocks(); err != nil {
		t.Fatal(err)
	}
	got := strings.TrimSpace(out.String())
	want := strings.Join([]string{
		"[WEB] http://10.0.0.8",
		"     [Finger] nginx",
		"     [Certificates] CN=10.0.0.8",
		"     [Code] 200",
		"     [Size] 12",
		"     [Title] Home",
	}, "\n")
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}

func TestRenderWEBBlockIncludesSizeAndRedirect(t *testing.T) {
	got := Render(OutputMessage{
		Type: "Web",
		URI:  "http://10.0.0.8/",
		Web: WebInfo{
			Status:   "302",
			Title:    "Moved",
			Cert:     "CN=10.0.0.8 issuer=ExampleCA",
			Size:     "2862",
			Redirect: "https://10.0.0.8/login",
		},
	})
	want := strings.Join([]string{
		"[WEB] http://10.0.0.8/",
		"     [Certificates] CN=10.0.0.8 issuer=ExampleCA",
		"     [Code] 302",
		"     [Size] 2862",
		"     [Redirect] https://10.0.0.8/login",
		"     [Title] Moved",
	}, "\n")
	if got != want {
		t.Fatalf("web block =\n%s\nwant\n%s", got, want)
	}
}

func TestRenderWEBFingerRepeatsURL(t *testing.T) {
	got := Render(OutputMessage{
		Type:   "Finger",
		URI:    "http://10.0.0.8/",
		Finger: []string{"nginx", "php"},
	})
	want := "[WEB] http://10.0.0.8/\n     [Finger] nginx,php"
	if got != want {
		t.Fatalf("finger block = %q", got)
	}
}

func TestRenderHTTPPortUsesWebTag(t *testing.T) {
	got := Render(OutputMessage{Type: "PortScan", IP: "10.0.0.8", Port: "80", Protocol: "http", Transport: "tcp"})
	want := "[Port] [web] 10.0.0.8:80 http"
	if got != want {
		t.Fatalf("unexpected render output: got %q want %q", got, want)
	}
	got = Render(OutputMessage{Type: "PortScan", IP: "10.0.0.8", Port: "443", Protocol: "https", Transport: "tcp"})
	want = "[Port] [web] 10.0.0.8:443 https"
	if got != want {
		t.Fatalf("unexpected https render: got %q want %q", got, want)
	}
}

func TestRenderUDPPort(t *testing.T) {
	got := Render(OutputMessage{
		Type:      "PortScan",
		IP:        "10.0.0.8",
		Port:      "53",
		Transport: "udp",
	})
	want := "[Port] [udp] 10.0.0.8:53"
	if got != want {
		t.Fatalf("unexpected render output: got %q want %q", got, want)
	}
}

func TestRenderUDPProtocol(t *testing.T) {
	got := Render(OutputMessage{
		Type:      "Nmap",
		IP:        "10.0.0.8",
		Port:      "53",
		Protocol:  "dns",
		Transport: "udp",
	})
	want := "[Port] [udp] 10.0.0.8:53 dns"
	if got != want {
		t.Fatalf("unexpected render output: got %q want %q", got, want)
	}
}
