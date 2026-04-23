package engine

import (
	"dddd/scanner/ddout"
	"testing"
)

func TestToEngineOutputMessageKeepsGoPocShowMsg(t *testing.T) {
	src := ddout.OutputMessage{
		Type: "GoPoc",
		GoPoc: ddout.GoPocsResultType{
			PocName:  "Shiro Weak Key",
			ShowMsg:  "http://127.0.0.1:8081 key=kPH+bIxk5D2deZiIxcaaaA==",
			Security: "CRITICAL",
		},
	}

	got := toEngineOutputMessage(src)
	if got.GoPoc.ShowMsg != src.GoPoc.ShowMsg {
		t.Fatalf("show message lost during conversion: got %q want %q", got.GoPoc.ShowMsg, src.GoPoc.ShowMsg)
	}
}
