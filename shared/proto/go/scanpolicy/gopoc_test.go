package scanpolicy

import (
	"strings"
	"testing"
)

func TestGoPocCatalogIsUniqueAndGoverned(t *testing.T) {
	descriptors := GoPocDescriptors()
	seen := make(map[string]struct{}, len(descriptors))
	for _, item := range descriptors {
		if item.Plugin == "" || item.Revision < 1 || item.RequestCost < 1 || !item.Reviewed {
			t.Fatalf("ungoverned GoPoc descriptor: %+v", item)
		}
		if _, duplicate := seen[item.Plugin]; duplicate {
			t.Fatalf("duplicate GoPoc descriptor %q", item.Plugin)
		}
		seen[item.Plugin] = struct{}{}
	}
	if hash := GoPocCatalogSHA256(); len(hash) != 64 || hash != strings.ToLower(hash) {
		t.Fatalf("invalid catalog hash %q", hash)
	}
	descriptors[0].Plugin = "mutated"
	descriptors[0].Services[0] = "mutated"
	if current := GoPocDescriptors()[0]; current.Plugin == "mutated" || current.Services[0] == "mutated" {
		t.Fatal("callers can mutate the shared GoPoc descriptor authority")
	}
}

func TestGoPocEndpointResolutionSeparatesCapabilities(t *testing.T) {
	observation := strings.Repeat("a", 64)
	protocol := GoPocTargetsForEndpoint("192.0.2.10:445", "smb", 445, observation, GoPocProtocolCheck)
	vulnerabilities := GoPocTargetsForEndpoint("192.0.2.10:445", "smb", 445, observation, GoPocVulnerabilityCheck)
	if len(protocol) != 1 || protocol[0].Plugin != "NetBios-GetHostInfo" {
		t.Fatalf("unexpected protocol plan: %+v", protocol)
	}
	if len(vulnerabilities) != 1 || vulnerabilities[0].Plugin != "SMB-MS17-010" {
		t.Fatalf("unexpected vulnerability plan: %+v", vulnerabilities)
	}
	if got := GoPocTargetsForEndpoint("192.0.2.20:445", "smtp", 445, observation, GoPocVulnerabilityCheck); len(got) != 0 {
		t.Fatalf("conflicting observed service used port fallback: %+v", got)
	}
	if got := GoPocTargetsForEndpoint("192.0.2.30:4000", "mysql", 4000, observation, GoPocVulnerabilityCheck); len(got) != 0 {
		t.Fatalf("TiDB greeting fingerprint generated GoPoc target: %+v", got)
	}
	if got := GoPocTargetsForEndpoint("192.0.2.42:10911", "unknown", 10911, observation, GoPocVulnerabilityCheck); len(got) != 1 || got[0].Plugin != "RocketMQ-Broker-Scan" || got[0].Trigger != "standard_port" {
		t.Fatalf("RocketMQ broker standard-port trigger missing: %+v", got)
	}
	if got := GoPocTargetsForEndpoint("192.0.2.43:12345", "rocketmq-namesrv", 12345, observation, GoPocVulnerabilityCheck); len(got) != 1 || got[0].Plugin != "RocketMQ-NameServer-Scan" || got[0].Trigger != "protocol" {
		t.Fatalf("RocketMQ namesrv non-standard protocol trigger missing: %+v", got)
	}
	if got := GoPocTargetsForEndpoint("192.0.2.44:10911", "smtp", 10911, observation, GoPocVulnerabilityCheck); len(got) != 0 {
		t.Fatalf("conflicting service triggered RocketMQ by port: %+v", got)
	}
}

func TestGoPocCatalogKeepsDefaultPortFingerprintsOutOfTargets(t *testing.T) {
	observation := strings.Repeat("d", 64)
	for _, tc := range []struct {
		target  string
		service string
		port    int
	}{
		{"192.0.2.40:502", "modbus", 502},
		{"192.0.2.41:33333", "codesys", 33333},
		{"192.0.2.45:7001", "weblogic-t3", 7001},
		{"192.0.2.46:20880", "dubbo", 20880},
		{"192.0.2.47:20000", "dnp3", 20000},
		{"192.0.2.48:102", "s7comm", 102},
		{"192.0.2.49:44818", "enip", 44818},
		{"192.0.2.50:10001", "atg", 10001},
		{"192.0.2.51:5006", "melsec", 5006},
		{"192.0.2.52:9600", "fins", 9600},
		{"192.0.2.53:789", "crimson", 789},
		{"192.0.2.54:2404", "iec104", 2404},
		{"192.0.2.55:61616", "activemq", 61616},
		{"192.0.2.56:3690", "svn", 3690},
		{"192.0.2.57:9001", "hsqldb", 9001},
		{"192.0.2.58:1801", "msmq", 1801},
		{"192.0.2.59:50000", "sap-p4", 50000},
		{"192.0.2.66:4000", "tidb", 4000},
		{"192.0.2.67:7848", "nacos", 7848},
	} {
		if got := GoPocTargetsForEndpoint(tc.target, tc.service, tc.port, observation, GoPocProtocolCheck); len(got) != 0 {
			t.Fatalf("default-port fingerprint %s generated GoPoc target: %+v", tc.service, got)
		}
	}
}

func TestGoPocCatalogKeepsRiskValidationProtocols(t *testing.T) {
	observation := strings.Repeat("e", 64)
	for _, tc := range []struct {
		target string
		port   int
		want   string
	}{
		{"192.0.2.60:10911", 10911, "RocketMQ-Broker-Scan"},
		{"192.0.2.61:9876", 9876, "RocketMQ-NameServer-Scan"},
		{"192.0.2.62:5672", 5672, "RabbitMQ-AMQP-Scan"},
		{"192.0.2.63:4369", 4369, "EPMD-Scan"},
		{"192.0.2.64:9042", 9042, "Cassandra-Scan"},
		{"192.0.2.65:9000", 9000, "ClickHouse-Scan"},
	} {
		got := GoPocTargetsForEndpoint(tc.target, "unknown", tc.port, observation, GoPocVulnerabilityCheck)
		if len(got) != 1 || got[0].Plugin != tc.want {
			t.Fatalf("risk validation target for %s = %+v, want %s", tc.target, got, tc.want)
		}
	}
}

func TestGoPocTargetLimitForPortsReservesAtLeastOneSlot(t *testing.T) {
	got, err := GoPocTargetLimitForPorts("7001", 1, GoPocProtocolCheck)
	if err != nil {
		t.Fatal(err)
	}
	if got != 1 {
		t.Fatalf("7001 protocol target limit = %d, want 1 reserve slot", got)
	}
	got, err = GoPocTargetLimitForPorts("33333", 1, GoPocProtocolCheck)
	if err != nil {
		t.Fatal(err)
	}
	if got != 1 {
		t.Fatalf("non-standard protocol target limit = %d, want 1 reserve slot", got)
	}
	got, err = GoPocTargetLimitForPorts("7001,7002", 3, GoPocProtocolCheck)
	if err != nil {
		t.Fatal(err)
	}
	if got != 6 {
		t.Fatalf("multi-target protocol target limit = %d, want 6", got)
	}
}

func TestGoPocSignalTargetRequiresDeclaredTrigger(t *testing.T) {
	observation := strings.Repeat("b", 64)
	item, err := GoPocTargetForSignal("https://example.invalid/", "Shiro-Key-Crack", "nuclei", "shiro-detect", observation)
	if err != nil || item.Trigger != "nuclei:shiro-detect" {
		t.Fatalf("valid signal target rejected: item=%+v err=%v", item, err)
	}
	if _, err := GoPocTargetForSignal("https://example.invalid/", "Shiro-Key-Crack", "nuclei", "unreviewed", observation); err == nil {
		t.Fatal("undeclared signal was accepted")
	}
}

func TestDisabledGoPocCannotEnterScopedPlan(t *testing.T) {
	item := GoPocTarget{Target: "192.0.2.10:23", Service: "telnet", Plugin: "Telnet-Bypass", Capability: GoPocVulnerabilityCheck, Trigger: "protocol", ObservationSHA256: strings.Repeat("c", 64), PluginRevision: 1, RequestCost: 1}
	if err := ValidateGoPocTarget(item, GoPocVulnerabilityCheck); err == nil {
		t.Fatal("disabled GoPoc was accepted")
	}
}
