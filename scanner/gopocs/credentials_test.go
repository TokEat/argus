package gopocs

import (
	"testing"

	"github.com/TokEat/argus/scanner/structs"
)

func TestExpandCredentialAppendCrossesUsersAndPasswords(t *testing.T) {
	info := &structs.HostInfo{UserAppend: []string{"ops"}, PasswordAppend: []string{"Spring2026"}}
	got := RemoveDuplicateUserPass(expandCredentialAppend(info, []structs.UserPasswd{
		{UserName: "root", Password: "root"},
	}))
	want := map[structs.UserPasswd]struct{}{
		{UserName: "root", Password: "root"}:       {},
		{UserName: "ops", Password: "root"}:        {},
		{UserName: "ops", Password: "Spring2026"}:  {},
		{UserName: "root", Password: "Spring2026"}: {},
	}
	if len(got) != len(want) {
		t.Fatalf("pairs = %#v", got)
	}
	for _, pair := range got {
		if _, ok := want[pair]; !ok {
			t.Fatalf("unexpected pair %#v in %#v", pair, got)
		}
	}
}

func TestIsServiceBruteTaskKeepsKeyCracksOut(t *testing.T) {
	if !isServiceBruteTask("SSH-Crack") || !isServiceBruteTask("VNC-Scan") {
		t.Fatal("service brute tasks were not detected")
	}
	if isServiceBruteTask("Shiro-Key-Crack") || isServiceBruteTask("SMB-MS17-010") {
		t.Fatal("non-brute GoPoc tasks were classified as brute")
	}
}
