package gopocs

import (
	"dddd/scanner/structs"
	"testing"
)

func TestBuildScanPlanSkipsWebServices(t *testing.T) {
	plan := buildScanPlan(map[string]string{
		"127.0.0.1:80":   "http",
		"127.0.0.1:443":  "https",
		"127.0.0.1:3306": "mysql",
	}, "", "", func(structs.GoPocsResultType) {})

	if len(plan) != 1 {
		t.Fatalf("expected only mysql scan task, got %+v", plan)
	}
	if plan[0].Name != "Mysql-Crack" {
		t.Fatalf("expected Mysql-Crack, got %s", plan[0].Name)
	}
}

func TestIsViewStateNucleiResultUsesExpectedTemplateTrigger(t *testing.T) {
	if !isViewStateNucleiResult(NucleiResult{TemplateID: "yongyou_u9_viewstate"}) {
		t.Fatal("expected yongyou_u9_viewstate to trigger ViewState scan")
	}
	if isViewStateNucleiResult(NucleiResult{TemplateID: "viewstate-rce"}) {
		t.Fatal("did not expect viewstate-rce to trigger ViewState scan")
	}
}
