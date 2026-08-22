package gopocs

import (
	"reflect"
	"testing"

	"github.com/P0lar1ght/argus/scanner/structs"
)

func TestDedupePasswordsForOnlyPasswordKeepsFirstSeenOrder(t *testing.T) {
	pairs := []structs.UserPasswd{
		{UserName: "admin", Password: "root"},
		{UserName: "root", Password: "toor"},
		{UserName: "support", Password: "root"},
		{UserName: "", Password: ""},
		{UserName: "cisco", Password: ""},
	}
	got := dedupePasswordsForOnlyPassword(pairs)
	want := []structs.UserPasswd{
		{UserName: "admin", Password: "root"},
		{UserName: "root", Password: "toor"},
		{UserName: "", Password: ""},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("deduped pairs = %#v, want %#v", got, want)
	}
}

func TestDedupePasswordsForOnlyPasswordHandlesEmptyInput(t *testing.T) {
	if got := dedupePasswordsForOnlyPassword(nil); len(got) != 0 {
		t.Fatalf("deduped nil pairs = %#v, want empty", got)
	}
}
