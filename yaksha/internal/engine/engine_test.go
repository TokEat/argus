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

func execScript(t *testing.T, script string, timeoutMS int64) protocol.Response {
	t.Helper()
	resp := Execute(protocol.Request{ID: "t", Script: "cli.check()\n" + script, TimeoutMS: timeoutMS})
	return resp
}

func execNetworkScript(t *testing.T, script string, timeoutMS int64, targets ...string) protocol.Response {
	t.Helper()
	return ExecuteWithEgress(protocol.Request{ID: "network-test", Script: "cli.check()\n" + script, TimeoutMS: timeoutMS, NetworkTargets: targets}, egress.NewDirectClient(nil, true))
}

func TestComplexSyntaxAndInjectedFunctions(t *testing.T) {
	script := `
sum = 0
for i = 0; i < 10; i++ {
    if i % 2 == 0 {
        sum += i
    }
}
adder = func(a) {
    return func(b) {
        return a + b
    }
}
v = adder(10)(5)
s = "hello " + "yaksha"
yaksha.log(s)
yaksha.log("sum=" + yaksha.toString(sum))
ok, rerr = yaksha.regexMatch("^hello yaksha$", s)
if !ok {
    yaksha.result("regex failed: " + yaksha.toString(rerr))
} else {
    yaksha.result(sum + v)
}
yaksha.evidence("regex_ok", ok)
`
	resp := execScript(t, script, 5000)
	if resp.Status != protocol.StatusSucceeded {
		t.Fatalf("status=%s error=%s", resp.Status, resp.Error)
	}
	if resp.Result != 35 {
		t.Fatalf("result=%v, want 35", resp.Result)
	}
	if resp.Evidence["regex_ok"] != true {
		t.Fatalf("evidence=%v", resp.Evidence)
	}
	if len(resp.Logs) != 2 {
		t.Fatalf("logs=%v", resp.Logs)
	}
}

func TestInjectedErrorIsReturnedNotThrown(t *testing.T) {
	script := `
v, err = yaksha.b64decode("!!!not-base64!!!")
if err != nil {
    yaksha.result("err:" + yaksha.toString(err))
} else {
    yaksha.result(v)
}
`
	resp := execScript(t, script, 5000)
	if resp.Status != protocol.StatusSucceeded {
		t.Fatalf("status=%s error=%s", resp.Status, resp.Error)
	}
	if got := resp.Result.(string); got[:4] != "err:" {
		t.Fatalf("result=%v, want err:...", resp.Result)
	}
}

func TestTryCatchCatchesLanguageError(t *testing.T) {
	script := `
caught = "no"
try {
    panic("boom")
} catch err {
    caught = "yes"
}
yaksha.result(caught)
`
	resp := execScript(t, script, 5000)
	if resp.Status != protocol.StatusSucceeded {
		t.Fatalf("status=%s error=%s", resp.Status, resp.Error)
	}
	if resp.Result != "yes" {
		t.Fatalf("result=%v, want yes", resp.Result)
	}
}

func TestCLIParamsBound(t *testing.T) {
	script := `
target = cli.String("target", cli.setRequired(true))
cli.check()
yaksha.result(target)
`
	resp := Execute(protocol.Request{
		ID:        "t",
		Script:    script,
		Params:    map[string]any{"target": "t1"},
		TimeoutMS: 5000,
	})
	if resp.Status != protocol.StatusSucceeded {
		t.Fatalf("status=%s error=%s", resp.Status, resp.Error)
	}
	if resp.Result != "t1" {
		t.Fatalf("result=%v, want t1", resp.Result)
	}
}

func TestOfficialCLIContractTypesAndDefaults(t *testing.T) {
	script := `
target = cli.String("target", cli.setRequired(true))
threads = cli.Int("threads", cli.setDefault(5))
ratio = cli.Float("ratio", cli.setDefault(1.5))
verify = cli.Bool("verify", cli.setDefault(true))
methods = cli.StringSlice("methods", cli.setMultipleSelect(true))
cli.check()
yaksha.result(target + "|" + yaksha.toString(threads) + "|" + yaksha.toString(ratio) + "|" + yaksha.toString(verify) + "|" + methods[0] + "," + methods[1])
`
	resp := Execute(protocol.Request{
		ID:     "t",
		Script: script,
		Params: map[string]any{
			"target":  "authorized.invalid",
			"threads": float64(8),
			"ratio":   2.25,
			"methods": []any{"GET", "POST"},
		},
		TimeoutMS: 5000,
	})
	if resp.Status != protocol.StatusSucceeded {
		t.Fatalf("status=%s error=%s validation=%#v", resp.Status, resp.Error, resp.Validation)
	}
	if resp.Result != "authorized.invalid|8|2.25|true|GET,POST" {
		t.Fatalf("result=%v", resp.Result)
	}
}

func TestRunRejectsInvalidParametersBeforeExecution(t *testing.T) {
	resp := Execute(protocol.Request{
		ID:     "t",
		Script: `target = cli.String("target", cli.setRequired(true)); cli.check(); panic("must not execute")`,
	})
	if resp.Status != protocol.StatusFailed || resp.Validation == nil || resp.Validation.Valid {
		t.Fatalf("unexpected response: %#v", resp)
	}
	if !strings.HasPrefix(resp.Error, "EXP validation failed:") {
		t.Fatalf("error=%q", resp.Error)
	}
}

func TestCLIStateIsIsolatedPerRequest(t *testing.T) {
	script := `target = cli.String("target", cli.setRequired(true)); cli.check(); yaksha.result(target)`
	first := Execute(protocol.Request{ID: "first", Script: script, Params: map[string]any{"target": "one"}})
	second := Execute(protocol.Request{ID: "second", Script: script, Params: map[string]any{"target": "two"}})
	if first.Status != protocol.StatusSucceeded || first.Result != "one" {
		t.Fatalf("first=%#v", first)
	}
	if second.Status != protocol.StatusSucceeded || second.Result != "two" {
		t.Fatalf("second=%#v", second)
	}
}

func TestHTTPGet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello"))
	}))
	defer srv.Close()

	resp := execNetworkScript(t, `
r, e = yaksha.httpGet("`+srv.URL+`")
yaksha.result(r)
`, 5000, srv.URL)
	if resp.Status != protocol.StatusSucceeded {
		t.Fatalf("status=%s error=%s", resp.Status, resp.Error)
	}
	if resp.Result != "200 hello" {
		t.Fatalf("result=%v, want '200 hello'", resp.Result)
	}
}

func TestDial(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	resp := execNetworkScript(t, `
r, e = yaksha.dial("`+ln.Addr().String()+`")
yaksha.result(r)
`, 5000, "tcp://"+ln.Addr().String())
	if resp.Status != protocol.StatusSucceeded {
		t.Fatalf("status=%s error=%s", resp.Status, resp.Error)
	}
	if resp.Result != ln.Addr().String() {
		t.Fatalf("result=%v, want %v", resp.Result, ln.Addr().String())
	}
}

func TestTimeoutKillsRunawayLoop(t *testing.T) {
	resp := execScript(t, `for 1 == 1 {}`, 300)
	if resp.Status != protocol.StatusTimeout {
		t.Fatalf("status=%s, want Timeout (error=%s)", resp.Status, resp.Error)
	}
}

func TestCryptoAndJSON(t *testing.T) {
	script := `
raw, _ = yaksha.b64decode("aGVsbG8=")
yaksha.evidence("decoded", raw)
yaksha.evidence("md5", yaksha.md5("abc"))
yaksha.evidence("sha256", yaksha.sha256("abc"))
d, _ = yaksha.jsonDumps({"a": 1})
yaksha.evidence("json", d)
yaksha.result(raw)
`
	resp := execScript(t, script, 5000)
	if resp.Status != protocol.StatusSucceeded {
		t.Fatalf("status=%s error=%s", resp.Status, resp.Error)
	}
	if resp.Result != "hello" {
		t.Fatalf("result=%v", resp.Result)
	}
	if resp.Evidence["md5"] != "900150983cd24fb0d6963f7d28e17f72" {
		t.Fatalf("md5=%v", resp.Evidence["md5"])
	}
	if resp.Evidence["json"] != `{"a":1}` {
		t.Fatalf("json=%v", resp.Evidence["json"])
	}
}
