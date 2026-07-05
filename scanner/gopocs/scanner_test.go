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

func TestBuildScanPlanNewProtocolTasksAreRegistered(t *testing.T) {
	plan := buildScanPlan(map[string]string{
		"127.0.0.1:102":   "s7comm",
		"127.0.0.1:389":   "ldap",
		"127.0.0.1:1099":  "rmi",
		"127.0.0.1:1801":  "unknown",
		"127.0.0.1:1883":  "mqtt",
		"127.0.0.1:2181":  "zookeeper",
		"127.0.0.1:2404":  "iec104",
		"127.0.0.1:3690":  "svn",
		"127.0.0.1:4000":  "mysql",
		"127.0.0.1:44818": "enip",
		"127.0.0.1:50000": "unknown",
		"127.0.0.1:5006":  "melsec",
		"127.0.0.1:61616": "activemq",
		"127.0.0.1:7848":  "unknown",
		"127.0.0.1:789":   "crimson",
		"127.0.0.1:9000":  "clickhouse",
		"127.0.0.1:9001":  "hsqldb",
		"127.0.0.1:9042":  "cassandra",
		"127.0.0.1:9600":  "fins",
		"127.0.0.1:10001": "atg",
		"127.0.0.1:20000": "dnp3",
	}, "", "", func(structs.GoPocsResultType) {})

	if len(plan) == 0 {
		t.Fatal("expected new protocol scan tasks")
	}
	for _, task := range plan {
		if PluginList[task.Name] == nil {
			t.Fatalf("scan task %q is not registered in PluginList", task.Name)
		}
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
