package resolver

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/TokEat/argus/yaksha/internal/inspector"
	"github.com/TokEat/argus/yaksha/internal/protocol"
)

func TestValidateSealedDependencyAndAssetClosure(t *testing.T) {
	child := `cli.check(); value, err = yaksha.asset("payload"); if err != nil { panic(err) }; yaksha.result(value)`
	asset := "payload-body"
	req := protocol.Request{
		Script:       `cli.check(); result, err = yaksha.call("child", 2, {}); if err != nil { panic(err) }; yaksha.result(result)`,
		Dependencies: []protocol.Dependency{{ExpID: "child", Revision: 2, SourceSHA256: protocol.SourceHash(child), Script: child}},
		Assets:       []protocol.Asset{{AssetID: "payload", SHA256: protocol.SourceHash(asset), Encoding: "utf8", Content: asset}},
	}
	bundle, diagnostics := Validate(req, inspector.Inspect(req.Script))
	if len(diagnostics) != 0 || bundle.Assets["payload"] != asset || len(bundle.Dependencies) != 1 {
		t.Fatalf("bundle=%#v diagnostics=%#v", bundle, diagnostics)
	}
}

func TestValidateRejectsMissingUnusedAndCycles(t *testing.T) {
	a := `cli.check(); yaksha.call("b", 1, {})`
	b := `cli.check(); yaksha.call("a", 1, {})`
	unused := `cli.check()`
	req := protocol.Request{
		Script: `cli.check(); yaksha.call("a", 1, {}); yaksha.asset("missing")`,
		Dependencies: []protocol.Dependency{
			{ExpID: "a", Revision: 1, SourceSHA256: protocol.SourceHash(a), Script: a},
			{ExpID: "b", Revision: 1, SourceSHA256: protocol.SourceHash(b), Script: b},
			{ExpID: "unused", Revision: 1, SourceSHA256: protocol.SourceHash(unused), Script: unused},
		},
	}
	_, diagnostics := Validate(req, inspector.Inspect(req.Script))
	for _, code := range []string{"missing_asset", "dependency_cycle", "unused_dependency"} {
		if !containsCode(diagnostics, code) {
			t.Fatalf("missing %s in %#v", code, diagnostics)
		}
	}
}

func TestValidateRejectsAssetHashMismatch(t *testing.T) {
	req := protocol.Request{Script: `cli.check(); yaksha.asset("a")`, Assets: []protocol.Asset{{AssetID: "a", SHA256: fmt.Sprintf("%x", sha256.Sum256([]byte("other"))), Encoding: "utf8", Content: "value"}}}
	_, diagnostics := Validate(req, inspector.Inspect(req.Script))
	if !containsCode(diagnostics, "invalid_asset") {
		t.Fatalf("diagnostics=%#v", diagnostics)
	}
}

func containsCode(diagnostics []protocol.Diagnostic, code string) bool {
	for _, item := range diagnostics {
		if item.Code == code {
			return true
		}
	}
	return false
}
