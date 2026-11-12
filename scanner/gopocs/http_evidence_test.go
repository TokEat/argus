package gopocs

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/TokEat/argus/scanner/structs"
)

func TestShiroWeakKeyPublishesOnlyConfirmedHTTPExchanges(t *testing.T) {
	const key = "kPH+bIxk5D2deZiIxcaaaA=="
	previousKeys := ShiroKeys
	ShiroKeys = key + "\n"
	t.Cleanup(func() { ShiroKeys = previousKeys })

	var mu sync.Mutex
	var cookies []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		cookies = append(cookies, request.Header.Get("Cookie"))
		call := len(cookies)
		mu.Unlock()

		writer.Header().Set("X-Argus-Evidence", fmt.Sprintf("response-%d", call))
		if strings.Contains(request.Header.Get("Cookie"), "rememberMe=123") {
			writer.Header().Set("Set-Cookie", "rememberMe=deleteMe;")
		}
		_, _ = fmt.Fprintf(writer, "shiro-response-%d", call)
	}))
	defer server.Close()

	capture, info := captureProtocolFindings("", "")
	info.Url = server.URL + "/login?source=argus"
	ShiroKeyCheck(info)

	mu.Lock()
	capturedCookies := append([]string(nil), cookies...)
	mu.Unlock()
	if len(capturedCookies) != 3 {
		t.Fatalf("Shiro requests = %d, want initial detection plus two confirmations", len(capturedCookies))
	}
	if len(capture.emitted) != 1 || len(capture.stored) != 1 {
		t.Fatalf("finding copies = emitted:%d stored:%d, want one each", len(capture.emitted), len(capture.stored))
	}
	exchanges := capture.emitted[0].GoPoc.Exchanges
	if len(exchanges) != 2 {
		t.Fatalf("Shiro exchanges = %#v, want two confirmed requests", exchanges)
	}
	if len(capture.stored[0].Exchanges) != 2 {
		t.Fatalf("stored Shiro exchanges = %#v", capture.stored[0].Exchanges)
	}
	for index, exchange := range exchanges {
		if exchange.Encoding != httpSemanticTranscriptEncoding {
			t.Fatalf("exchange %d encoding = %q", index+1, exchange.Encoding)
		}
		if !strings.Contains(exchange.Request, "URL: "+info.Url) ||
			!strings.Contains(exchange.Request, "Cookie: "+capturedCookies[index+1]) {
			t.Fatalf("exchange %d did not preserve the actual request:\n%s", index+1, exchange.Request)
		}
		if strings.Contains(exchange.Request, capturedCookies[0]) {
			t.Fatalf("exchange %d retained the failed detection request", index+1)
		}
		if !strings.Contains(exchange.Response, fmt.Sprintf("X-Argus-Evidence: response-%d", index+2)) ||
			!strings.Contains(exchange.Response, fmt.Sprintf("shiro-response-%d", index+2)) {
			t.Fatalf("exchange %d did not preserve the actual response:\n%s", index+1, exchange.Response)
		}
	}
}

func TestViewStateWeakKeyPublishesSourcePageHTTPExchange(t *testing.T) {
	keys := loadMachineKeys()
	if len(keys) == 0 {
		t.Fatal("embedded ViewState key fixture is empty")
	}
	data := bytes.Repeat([]byte{0x41}, 32)
	mac := hmac.New(sha256.New, candidateKeyBytes(keys[0].validationKey))
	_, _ = mac.Write(data)
	viewState := base64.StdEncoding.EncodeToString(append(data, mac.Sum(nil)...))
	body := `<html><body><input type="hidden" name="__VIEWSTATE" value="` + viewState + `"></body></html>`

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Argus-Evidence", "viewstate-source")
		_, _ = writer.Write([]byte(body))
	}))
	defer server.Close()

	capture, info := captureProtocolFindings("", "")
	info.Url = server.URL + "/default.aspx?source=argus"
	ViewStateKeyCheck(info)

	if len(capture.emitted) != 1 || len(capture.stored) != 1 {
		t.Fatalf("finding copies = emitted:%d stored:%d, want one each", len(capture.emitted), len(capture.stored))
	}
	want := capture.emitted[0].GoPoc.Exchanges
	if len(want) != 1 || len(capture.stored[0].Exchanges) != 1 {
		t.Fatalf("ViewState exchanges = emitted:%#v stored:%#v", want, capture.stored[0].Exchanges)
	}
	exchange := want[0]
	if exchange.Encoding != httpSemanticTranscriptEncoding ||
		!strings.Contains(exchange.Request, "URL: "+info.Url) ||
		!strings.Contains(exchange.Response, "X-Argus-Evidence: viewstate-source") ||
		!strings.Contains(exchange.Response, body) {
		t.Fatalf("ViewState source exchange was not preserved: %#v", exchange)
	}
}

func TestGoPocHTTPEvidenceTruncatesOversizedShiroBodyWithoutChangingMatch(t *testing.T) {
	oversized := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Set-Cookie", "rememberMe=accepted;")
		_, _ = io.CopyN(writer, zeroReader{}, maxGoPocHTTPBodyBytes+1)
	}))
	defer oversized.Close()
	matched, exchange := sendShiroRequestWithEvidence(oversized.URL, "confirmed", "oversized")
	if !matched {
		t.Fatal("oversized evidence body changed the header-based Shiro match")
	}
	if exchange == (structs.GoPocExchange{}) || !strings.Contains(exchange.Response, "Evidence-Body-Status: truncated-at-1048576-bytes") {
		t.Fatalf("oversized Shiro response did not retain bounded evidence with a truncation marker: %#v", exchange)
	}
}

func TestViewStateEvidenceRejectsTruncatedBody(t *testing.T) {
	truncated := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		hijacker, ok := writer.(http.Hijacker)
		if !ok {
			t.Error("test server does not support hijacking")
			return
		}
		connection, buffered, err := hijacker.Hijack()
		if err != nil {
			t.Errorf("hijack response: %v", err)
			return
		}
		defer connection.Close()
		_, _ = buffered.WriteString("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n8\r\nshort")
		_ = buffered.Flush()
	}))
	defer truncated.Close()
	if _, _, _, exchange, err := fetchAndExtractViewStateWithEvidence(truncated.URL); err == nil || exchange != (structs.GoPocExchange{}) {
		t.Fatalf("truncated ViewState response produced evidence: err=%v exchange=%#v", err, exchange)
	}
}

func TestSemanticHTTPBodyAlwaysContainsByteExactBase64(t *testing.T) {
	body := []byte{0x00, 0x01, 'A', '\r', '\n', 0xff}
	transcript := semanticHTTPBody(body)
	want := base64.StdEncoding.EncodeToString(body)
	if !strings.Contains(transcript, "Body-Encoding: base64") || !strings.Contains(transcript, "Body-Base64:\n"+want) {
		t.Fatalf("HTTP body transcript is not byte preserving:\n%s", transcript)
	}
	if strings.Contains(transcript, "Body-UTF8:") {
		t.Fatalf("binary/control body should not be rendered as UTF-8 text:\n%s", transcript)
	}
}

type zeroReader struct{}

func (zeroReader) Read(buffer []byte) (int, error) {
	for index := range buffer {
		buffer[index] = 'x'
	}
	return len(buffer), nil
}
