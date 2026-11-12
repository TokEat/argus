package gopocs

import (
	"testing"

	"github.com/TokEat/argus/scanner/structs"
)

func TestApplyDispatchCredsCarriesCredentialPairLimit(t *testing.T) {
	info := &structs.HostInfo{}
	applyDispatchCreds(info, DispatchCreds{CredentialPairLimit: 42})
	if info.CredentialPairLimit != 42 {
		t.Fatalf("HostInfo.CredentialPairLimit = %d, want 42", info.CredentialPairLimit)
	}
}

func TestBuildScanPlanPropagatesCredentialPairLimit(t *testing.T) {
	plan := buildScanPlan(map[string]string{"127.0.0.1:22": "ssh"},
		DispatchCreds{CredentialPairLimit: 7}, func(structs.GoPocsResultType) {})
	if len(plan) == 0 {
		t.Fatal("expected ssh scan task")
	}
	for _, task := range plan {
		if task.Info.CredentialPairLimit != 7 {
			t.Fatalf("%s CredentialPairLimit = %d, want 7", task.Name, task.Info.CredentialPairLimit)
		}
	}
}

func TestLimitUserPasswdAppliesDispatchedLimitAfterUnion(t *testing.T) {
	info := &structs.HostInfo{CredentialPairLimit: 2}
	got := limitUserPasswd(info, []structs.UserPasswd{
		{UserName: "root", Password: "a"},
		{UserName: "admin", Password: "b"},
		{UserName: "ops", Password: "c"},
	})
	if len(got) != 2 || got[0].Password != "a" || got[1].Password != "b" {
		t.Fatalf("limited pairs = %#v, want first two", got)
	}
}
