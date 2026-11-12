package engine

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TokEat/argus/yaksha/internal/protocol"
)

func TestHTTPGetStatusAndBodyLimit(t *testing.T) {
	t.Run("status and body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte("created"))
		}))
		defer srv.Close()

		resp := execNetworkScript(t, `value, err = yaksha.httpGet("`+srv.URL+`"); yaksha.result(value)`, 5_000, srv.URL)
		if resp.Status != protocol.StatusSucceeded || resp.Result != "201 created" {
			t.Fatalf("response=%+v", resp)
		}
	})

	t.Run("body limit", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(strings.Repeat("x", maxHTTPBodyBytes+1)))
		}))
		defer srv.Close()

		resp := execNetworkScript(t, `
value, err = yaksha.httpGet("`+srv.URL+`")
if err != nil { yaksha.result(yaksha.toString(err)) }`, 5_000, srv.URL)
		if resp.Status != protocol.StatusSucceeded || !strings.Contains(resp.Result.(string), "response body exceeds") {
			t.Fatalf("response=%+v", resp)
		}
	})
}

func TestHTTPGetHonorsExecutionTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer func() {
		close(release)
		srv.Close()
	}()

	started := time.Now()
	resp := execNetworkScript(t, `
value, err = yaksha.httpGet("`+srv.URL+`")
if err != nil { panic(err) }`, 150, srv.URL)
	if resp.Status != protocol.StatusTimeout {
		t.Fatalf("response=%+v", resp)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("HTTP cancellation took %s", elapsed)
	}
}

func TestDialFailureIsReturnedToScript(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := ln.Addr().String()
	ln.Close()

	resp := execNetworkScript(t, `
value, err = yaksha.dial("`+address+`")
if err != nil { yaksha.result("failed") } else { yaksha.result(value) }`, 5_000, "tcp://"+address)
	if resp.Status != protocol.StatusSucceeded || resp.Result != "failed" {
		t.Fatalf("response=%+v", resp)
	}
}

func TestEncodingJSONAndRegexErrorPaths(t *testing.T) {
	resp := execScript(t, `
decoded, decodeErr = yaksha.b64decode("%%%")
parsed, jsonErr = yaksha.jsonLoads("not-json")
matched, regexErr = yaksha.regexMatch("[", "value")
encoded, encodeErr = yaksha.b64encode("yaksha")
yaksha.evidence("decode_error", decodeErr != nil)
yaksha.evidence("json_error", jsonErr != nil)
yaksha.evidence("regex_error", regexErr != nil)
yaksha.evidence("encode_error", encodeErr != nil)
yaksha.result(encoded)`, 5_000)
	if resp.Status != protocol.StatusSucceeded || resp.Result != "eWFrc2hh" {
		t.Fatalf("response=%+v", resp)
	}
	for _, key := range []string{"decode_error", "json_error", "regex_error"} {
		if resp.Evidence[key] != true {
			t.Fatalf("evidence[%q]=%v", key, resp.Evidence[key])
		}
	}
	if resp.Evidence["encode_error"] != false {
		t.Fatalf("evidence[encode_error]=%v", resp.Evidence["encode_error"])
	}
}
