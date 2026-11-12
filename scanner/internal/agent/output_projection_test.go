package agent

import (
	"reflect"
	"testing"

	"github.com/TokEat/argus/scanner/internal/engine"
	"github.com/TokEat/argus/scanner/structs"
)

func TestToDDOutOutputMessageKeepsGoPocEvidence(t *testing.T) {
	src := engine.OutputMessage{
		Type: "GoPoc",
		GoPoc: engine.GoPocsResultType{
			PocName:  "Shiro Weak Key",
			ShowMsg:  "http://127.0.0.1:8081 key=xxx",
			Security: "CRITICAL",
			Exchanges: []structs.GoPocExchange{{
				Label: "verification", Request: "request", Response: "response", Encoding: "text",
			}},
		},
	}

	got := toDDOutOutputMessage(src)
	if got.GoPoc.ShowMsg != src.GoPoc.ShowMsg {
		t.Fatalf("show message lost during conversion: got %q want %q", got.GoPoc.ShowMsg, src.GoPoc.ShowMsg)
	}
	if !reflect.DeepEqual(got.GoPoc.Exchanges, src.GoPoc.Exchanges) {
		t.Fatalf("exchanges lost during conversion: got %#v want %#v", got.GoPoc.Exchanges, src.GoPoc.Exchanges)
	}
}
