package ddout

import "testing"

func TestRenderActiveFingerIncludesFallbackTag(t *testing.T) {
	got := Render(OutputMessage{
		Type:          "Active-Finger",
		URI:           "http://127.0.0.1:8081/aaa",
		Finger:        []string{"Shiro"},
		AdditionalMsg: "[dir-fallback]",
	})
	want := "[Active-Finger] http://127.0.0.1:8081/aaa [Shiro] [dir-fallback]"
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
	want := "[CRITICAL] http://127.0.0.1:8081 key=kPH+bIxk5D2deZiIxcaaaA=="
	if got != want {
		t.Fatalf("unexpected render output: got %q want %q", got, want)
	}
}
