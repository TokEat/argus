package engine

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/P0lar1ght/argus/yaksha/internal/egress"
	"github.com/P0lar1ght/argus/yaksha/internal/protocol"
)

func TestDebugRunsEXPAndReturnsDiagnosticOutputs(t *testing.T) {
	script := `
target = cli.String("target", cli.setRequired(true))
cli.check()
yaksha.log("checking " + target)
yaksha.evidence("phase", "probe")
yaksha.result({"vulnerable": false, "target": target})
`
	resp := Execute(protocol.Request{
		ID:     "debug-1",
		Action: protocol.ActionDebug,
		Script: script,
		Params: map[string]any{"target": "authorized.invalid"},
	})
	if resp.Status != protocol.StatusSucceeded || resp.Debug == nil || resp.Validation == nil || !resp.Validation.Valid {
		t.Fatalf("response=%#v", resp)
	}
	if len(resp.Logs) != 1 || resp.Evidence["phase"] != "probe" || resp.Result == nil {
		t.Fatalf("response=%#v", resp)
	}
}

func TestDebugRejectsInvalidEXPBeforeExecution(t *testing.T) {
	resp := Execute(protocol.Request{
		ID:     "debug-invalid",
		Action: protocol.ActionDebug,
		Script: `target = cli.String("target", cli.setRequired(true)); cli.check(); panic("must not execute")`,
	})
	if resp.Status != protocol.StatusFailed || resp.Debug == nil || resp.Validation == nil || resp.Validation.Valid {
		t.Fatalf("response=%#v", resp)
	}
	if !strings.HasPrefix(resp.Error, "EXP validation failed:") {
		t.Fatalf("error=%q", resp.Error)
	}
}

func TestDebugCapturesCompleteHTTPAndTCPEvents(t *testing.T) {
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("ok"))
	}))
	defer httpServer.Close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			conn.Close()
		}
	}()

	secret := "query-secret-must-not-appear"
	script := `cli.check()
httpValue, httpErr = yaksha.httpGet("` + httpServer.URL + `?token=` + secret + `")
tcpValue, tcpErr = yaksha.dial("` + listener.Addr().String() + `")
yaksha.result(httpErr == nil && tcpErr == nil)`
	resp := ExecuteWithEgress(protocol.Request{ID: "debug-events", Action: protocol.ActionDebug, Script: script, NetworkTargets: []string{httpServer.URL, "tcp://" + listener.Addr().String()}}, egress.NewDirectClient(nil, true))
	if resp.Status != protocol.StatusSucceeded || resp.Result != true || resp.Debug == nil {
		t.Fatalf("response=%#v", resp)
	}
	if len(resp.Debug.Events) != 2 {
		t.Fatalf("events=%#v", resp.Debug.Events)
	}
	if resp.Debug.Events[0].Kind != "http" || resp.Debug.Events[0].StatusCode != http.StatusCreated {
		t.Fatalf("http event=%#v", resp.Debug.Events[0])
	}
	if resp.Debug.Events[1].Kind != "tcp" || resp.Debug.Events[1].Operation != "connect" {
		t.Fatalf("tcp event=%#v", resp.Debug.Events[1])
	}
	if !strings.Contains(resp.Debug.Events[0].Target, secret) {
		t.Fatalf("debug event omitted query detail: %#v", resp.Debug.Events[0])
	}
}
