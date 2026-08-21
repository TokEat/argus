package gopocs

import (
	"errors"
	"strings"
	"testing"

	"github.com/P0lar1ght/argus/scanner/structs"
)

func TestPresentationDefaultsToInteractive(t *testing.T) {
	if !shouldRenderProgress(nil) {
		t.Fatal("zero presentation must retain interactive progress")
	}
}

func TestPresentationSuppressesRegisteredHostProgress(t *testing.T) {
	info := &structs.HostInfo{}
	presentations.Store(info, Presentation{MachineOutput: true})
	defer presentations.Delete(info)

	if shouldRenderProgress(info) {
		t.Fatal("machine output must suppress direct GoPoc progress")
	}
}

func TestBuildScanPlanSkipsWebServices(t *testing.T) {
	plan := buildScanPlan(map[string]string{
		"127.0.0.1:80":   "http",
		"127.0.0.1:443":  "https",
		"127.0.0.1:3306": "mysql",
	}, DispatchCreds{}, func(structs.GoPocsResultType) {})

	if len(plan) != 1 {
		t.Fatalf("expected only mysql scan task, got %+v", plan)
	}
	if plan[0].Name != "Mysql-Crack" {
		t.Fatalf("expected Mysql-Crack, got %s", plan[0].Name)
	}
}

func TestBuildScanPlanNewProtocolTasksAreRegistered(t *testing.T) {
	plan := buildScanPlan(map[string]string{
		"127.0.0.1:389":   "ldap",
		"127.0.0.1:1099":  "rmi",
		"127.0.0.1:1883":  "mqtt",
		"127.0.0.1:2181":  "zookeeper",
		"127.0.0.1:4369":  "unknown",
		"127.0.0.1:5672":  "amqp",
		"127.0.0.1:9000":  "clickhouse",
		"127.0.0.1:9042":  "unknown",
		"127.0.0.1:9876":  "unknown",
		"127.0.0.1:10911": "unknown",
	}, DispatchCreds{}, func(structs.GoPocsResultType) {})

	if len(plan) == 0 {
		t.Fatal("expected new protocol scan tasks")
	}
	for _, task := range plan {
		if PluginList[task.Name] == nil {
			t.Fatalf("scan task %q is not registered in PluginList", task.Name)
		}
	}
}

func TestBuildScanPlanKeepsDefaultPortFingerprintsOutOfGoPoc(t *testing.T) {
	plan := buildScanPlan(map[string]string{
		"127.0.0.1:502":   "modbus",
		"127.0.0.1:1962":  "pcworx",
		"127.0.0.1:4447":  "jboss-remoting",
		"127.0.0.1:7001":  "weblogic-t3",
		"127.0.0.1:7002":  "iiop",
		"127.0.0.1:11740": "codesys",
		"127.0.0.1:20547": "proconos",
		"127.0.0.1:20880": "dubbo",
		"127.0.0.1:20000": "dnp3",
		"127.0.0.1:102":   "s7comm",
		"127.0.0.1:44818": "enip",
		"127.0.0.1:10001": "atg",
		"127.0.0.1:5006":  "melsec",
		"127.0.0.1:9600":  "fins",
		"127.0.0.1:789":   "crimson",
		"127.0.0.1:2404":  "iec104",
		"127.0.0.1:61616": "activemq",
		"127.0.0.1:3690":  "svn",
		"127.0.0.1:9001":  "hsqldb",
		"127.0.0.1:1801":  "msmq",
		"127.0.0.1:50000": "sap-p4",
		"127.0.0.1:4000":  "tidb",
		"127.0.0.1:7848":  "nacos",
	}, DispatchCreds{}, func(structs.GoPocsResultType) {})

	if len(plan) != 0 {
		t.Fatalf("default-port fingerprints must stay in protocol identification, got GoPoc tasks: %+v", plan)
	}
}

func TestBuildScanPlanRocketMQRoleBoundaries(t *testing.T) {
	plan := buildScanPlan(map[string]string{
		"127.0.0.1:10911": "smtp",
		"127.0.0.1:12345": "rocketmq-broker",
		"127.0.0.1:12346": "rocketmq-namesrv",
	}, DispatchCreds{}, func(structs.GoPocsResultType) {})

	names := map[string]bool{}
	for _, task := range plan {
		names[task.Name+":"+task.Info.Ports] = true
	}
	if names["RocketMQ-Broker-Scan:10911"] {
		t.Fatalf("RocketMQ broker port fallback ran for identified SMTP: %+v", plan)
	}
	if !names["RocketMQ-Broker-Scan:12345"] {
		t.Fatalf("RocketMQ broker non-standard protocol trigger missing: %+v", plan)
	}
	if !names["RocketMQ-NameServer-Scan:12346"] {
		t.Fatalf("RocketMQ namesrv non-standard protocol trigger missing: %+v", plan)
	}
}

func TestBuildScanPlanUsesCanonicalProtocolOnNonStandardPort(t *testing.T) {
	plan := buildScanPlan(map[string]string{
		"127.0.0.1:2222": "ms-wbt-server",
		"127.0.0.1:5555": "java-rmi",
	}, DispatchCreds{}, func(structs.GoPocsResultType) {})

	names := map[string]string{}
	for _, task := range plan {
		names[task.Name] = task.Info.ObservedService
	}
	if names["RDP-Crack"] != "rdp" {
		t.Fatalf("RDP on 2222 missing or not canonical: %+v", plan)
	}
	if names["RMI-Scan"] != "rmi" {
		t.Fatalf("RMI on 5555 missing or not canonical: %+v", plan)
	}
	if _, ok := names["ADB-Scan"]; ok {
		t.Fatalf("ADB must not run on identified RMI at 5555: %+v", plan)
	}
}

func TestBuildScanPlanDoesNotUsePortFallbackWhenProtocolKnown(t *testing.T) {
	plan := buildScanPlan(map[string]string{
		"127.0.0.1:3306": "ssh",
		"127.0.0.1:445":  "http",
		"127.0.0.1:9000": "http",
		"127.0.0.1:9042": "smtp",
	}, DispatchCreds{}, func(structs.GoPocsResultType) {})

	for _, task := range plan {
		switch task.Name {
		case "Mysql-Crack", "SMB-Crack", "SMB-MS17-010", "NetBios-GetHostInfo", "ClickHouse-Scan", "Cassandra-Scan":
			t.Fatalf("port fallback dispatched %s for identified %s: %+v", task.Name, task.Info.ObservedService, plan)
		}
	}
	if len(plan) != 1 || plan[0].Name != "SSH-Crack" {
		t.Fatalf("expected only SSH-Crack, got %+v", plan)
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

func TestDispatcherReportsInfrastructureFailures(t *testing.T) {
	missing := &dispatcher{}
	missing.scanFunc("argus-test-missing-plugin", &structs.HostInfo{})
	if err := missing.executionError(); err == nil || !strings.Contains(err.Error(), "is unavailable") {
		t.Fatalf("missing plugin error = %v", err)
	}

	const pluginName = "argus-test-panicking-plugin"
	PluginList[pluginName] = func(*structs.HostInfo) error {
		panic("synthetic secret panic detail")
	}
	defer delete(PluginList, pluginName)

	panicking := &dispatcher{}
	panicking.scanFunc(pluginName, &structs.HostInfo{})
	err := panicking.executionError()
	if err == nil || !strings.Contains(err.Error(), "panicked") {
		t.Fatalf("panic error = %v", err)
	}
	if strings.Contains(err.Error(), "synthetic secret") {
		t.Fatalf("panic detail leaked through task error: %v", err)
	}
}

func TestDispatcherPropagatesSuccessfulSessionEvidenceFailureOnly(t *testing.T) {
	const evidencePlugin = "argus-test-evidence-limit-plugin"
	PluginList[evidencePlugin] = func(*structs.HostInfo) error {
		return errors.Join(errSuccessfulSessionEvidenceLimit, errors.New("bounded transcript unavailable"))
	}
	defer delete(PluginList, evidencePlugin)

	dispatcherWithEvidenceFailure := &dispatcher{}
	dispatcherWithEvidenceFailure.scanFunc(evidencePlugin, &structs.HostInfo{})
	if err := dispatcherWithEvidenceFailure.executionError(); !errors.Is(err, errSuccessfulSessionEvidenceLimit) {
		t.Fatalf("evidence failure was not propagated: %v", err)
	}

	const ordinaryMissPlugin = "argus-test-ordinary-miss-plugin"
	PluginList[ordinaryMissPlugin] = func(*structs.HostInfo) error {
		return errors.New("credential rejected")
	}
	defer delete(PluginList, ordinaryMissPlugin)

	dispatcherWithOrdinaryMiss := &dispatcher{}
	dispatcherWithOrdinaryMiss.scanFunc(ordinaryMissPlugin, &structs.HostInfo{})
	if err := dispatcherWithOrdinaryMiss.executionError(); err != nil {
		t.Fatalf("ordinary probe miss was promoted to a task failure: %v", err)
	}
}

func TestTelnetDispatcherPropagatesPluginPanic(t *testing.T) {
	original := PluginList["Telnet-Bypass"]
	PluginList["Telnet-Bypass"] = func(*structs.HostInfo) error {
		panic("synthetic telnet dispatcher panic")
	}
	defer func() { PluginList["Telnet-Bypass"] = original }()

	results, err := TelnetBypassDispatchScoped(map[string]string{"127.0.0.1:23": "telnet"}, 1, "", "", func(structs.OutputMessage) {})
	if len(results) != 0 {
		t.Fatalf("unexpected results after plugin panic: %#v", results)
	}
	if err == nil || !strings.Contains(err.Error(), "panicked") {
		t.Fatalf("telnet dispatcher error = %v", err)
	}
}

func TestBuildDispatchPlanUsesTaskLocalFingerprintsAndDeduplicatesViewState(t *testing.T) {
	previous := structs.GlobalResultMap
	structs.GlobalResultMap = map[string][]string{"https://legacy.example.test/": {"viewstate"}}
	defer func() { structs.GlobalResultMap = previous }()

	plan := buildDispatchPlan(
		nil,
		map[string][]string{"https://CURRENT.example.test": {"ViewState"}},
		[]NucleiResult{{TemplateID: "yongyou_u9_viewstate", Matched: "https://current.example.test/"}},
		DispatchCreds{}, func(structs.GoPocsResultType) {},
	)
	if len(plan) != 1 {
		t.Fatalf("dispatch plan = %#v, want one de-duplicated task-local trigger", plan)
	}
	if plan[0].Name != "ViewState-Key-Crack" || !strings.EqualFold(plan[0].Info.Url, "https://current.example.test/") {
		t.Fatalf("unexpected task-local trigger: %#v", plan[0])
	}
}

func TestBuildDispatchPlanNoBruteSkipsServiceCracks(t *testing.T) {
	plan := buildDispatchPlan(map[string]string{"127.0.0.1:22": "ssh", "127.0.0.1:445": "smb"}, nil, nil, DispatchCreds{NoBrute: true}, func(structs.GoPocsResultType) {})
	for _, task := range plan {
		if isServiceBruteTask(task.Name) {
			t.Fatalf("brute task leaked under -nobr: %#v", task)
		}
	}
	foundMS17 := false
	for _, task := range plan {
		if task.Name == "SMB-MS17-010" {
			foundMS17 = true
		}
	}
	if !foundMS17 {
		t.Fatal("expected SMB-MS17-010 to remain when only brute is disabled")
	}
}
