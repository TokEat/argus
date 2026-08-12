package engine

import (
	"testing"

	"github.com/P0lar1ght/argus/yaksha/internal/protocol"
)

func TestComposeReturnsResultAndCallTree(t *testing.T) {
	child := `name = cli.String("name", cli.setRequired(true)); cli.check(); payload, err = yaksha.asset("payload"); if err != nil { panic(err) }; yaksha.log("child-log"); yaksha.evidence("payload", payload); yaksha.result(name + ":" + payload)`
	main := `cli.check(); value, err = yaksha.call("child", 4, {"name": "yaksha"}); if err != nil { panic(err) }; yaksha.result(value)`
	resp := Execute(protocol.Request{
		ID: "compose", Action: protocol.ActionDebug, Script: main,
		Dependencies: []protocol.Dependency{{ExpID: "child", Revision: 4, SourceSHA256: protocol.SourceHash(child), Script: child}},
		Assets:       []protocol.Asset{{AssetID: "payload", SHA256: protocol.SourceHash("asset"), Encoding: "utf8", Content: "asset"}},
	})
	if resp.Status != protocol.StatusSucceeded || resp.Result != "yaksha:asset" || len(resp.Calls) != 1 {
		t.Fatalf("response=%#v", resp)
	}
	call := resp.Calls[0]
	if call.Context == nil || call.Context.ExpID != "child" || call.Context.Revision != 4 || call.Logs[0] != "child-log" || call.Evidence["payload"] != "asset" {
		t.Fatalf("call=%#v", call)
	}
}

func TestComposeFailureCanBeHandledByParent(t *testing.T) {
	child := `required = cli.String("required", cli.setRequired(true)); cli.check(); yaksha.result(required)`
	main := `cli.check(); value, err = yaksha.call("child", 1, {}); yaksha.result(err != nil)`
	resp := Execute(protocol.Request{Script: main, Dependencies: []protocol.Dependency{{ExpID: "child", Revision: 1, SourceSHA256: protocol.SourceHash(child), Script: child}}})
	if resp.Status != protocol.StatusSucceeded || resp.Result != true || len(resp.Calls) != 1 || resp.Calls[0].Status != protocol.StatusFailed {
		t.Fatalf("response=%#v", resp)
	}
}
