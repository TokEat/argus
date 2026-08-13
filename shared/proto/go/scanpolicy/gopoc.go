package scanpolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// GoPocCapability is a product-facing classification boundary. GoPoc remains
// an implementation detail: protocol checks enrich discovery, vulnerability
// checks belong to risk validation, and credential checks belong to the
// credential-validation stage.
type GoPocCapability string

const (
	GoPocCredential         GoPocCapability = "credential"
	GoPocProtocolCheck      GoPocCapability = "protocol_check"
	GoPocVulnerabilityCheck GoPocCapability = "vulnerability_check"
	GoPocCatalogVersion                     = "argus.gopoc-catalog/v1"
	MaximumGoPocTargets                     = 4096
)

type GoPocDescriptor struct {
	Plugin                string          `json:"plugin"`
	Capability            GoPocCapability `json:"capability"`
	Services              []string        `json:"services,omitempty"`
	Ports                 []int           `json:"ports,omitempty"`
	NucleiTemplates       []string        `json:"nuclei_templates,omitempty"`
	Fingerprints          []string        `json:"fingerprints,omitempty"`
	RequireServiceAndPort bool            `json:"require_service_and_port,omitempty"`
	Revision              int             `json:"revision"`
	RequestCost           int             `json:"request_cost"`
	Reviewed              bool            `json:"reviewed"`
	Enabled               bool            `json:"enabled"`
}

// GoPocTarget is the immutable Server-to-Agent execution plan for one plugin
// and one observed endpoint. Target is either host:port or an absolute URL.
type GoPocTarget struct {
	Target            string          `json:"target"`
	Service           string          `json:"service,omitempty"`
	Plugin            string          `json:"plugin"`
	Capability        GoPocCapability `json:"capability"`
	Trigger           string          `json:"trigger"`
	ObservationSHA256 string          `json:"observation_sha256"`
	PluginRevision    int             `json:"plugin_revision"`
	RequestCost       int             `json:"request_cost"`
}

func gopoc(plugin string, capability GoPocCapability, services []string, ports []int) GoPocDescriptor {
	return GoPocDescriptor{Plugin: plugin, Capability: capability, Services: services, Ports: ports, Revision: 1, RequestCost: 1, Reviewed: true, Enabled: true}
}

// The immutable GoPoc descriptor set is the single semantic authority shared by Server and Agent.
// Keep entries explicit: adding a plugin is a reviewed product change, not a
// side effect of adding a function to Scanner's legacy PluginList.
var goPocCatalog = []GoPocDescriptor{
	// Credential plugins are still resolved by CredentialServices. They are
	// listed here so the three-way classification is complete and auditable.
	gopoc("SSH-Crack", GoPocCredential, []string{"ssh"}, []int{22}),
	gopoc("FTP-Crack", GoPocCredential, []string{"ftp"}, []int{21}),
	gopoc("Mysql-Crack", GoPocCredential, []string{"mysql"}, []int{3306}),
	gopoc("Mssql-Crack", GoPocCredential, []string{"mssql", "sqlserver"}, []int{1433}),
	gopoc("Oracle-Crack", GoPocCredential, []string{"oracle"}, []int{1521}),
	gopoc("RDP-Crack", GoPocCredential, []string{"rdp"}, []int{3389}),
	gopoc("Redis-Crack", GoPocCredential, []string{"redis"}, []int{6379}),
	gopoc("SMB-Crack", GoPocCredential, []string{"smb"}, []int{445}),
	gopoc("PostgreSQL-Crack", GoPocCredential, []string{"postgresql", "postgres"}, []int{5432}),
	gopoc("Telnet-Crack", GoPocCredential, []string{"telnet"}, []int{23}),
	gopoc("VNC-Scan", GoPocCredential, []string{"vnc"}, []int{5900, 5901}),
	gopoc("Rsync-Scan", GoPocCredential, []string{"rsync"}, []int{873}),
	gopoc("DM-Scan", GoPocCredential, []string{"dm"}, []int{5236}),
	gopoc("Kingbase-Scan", GoPocCredential, []string{"kingbase"}, []int{54321}),

	gopoc("NetBios-GetHostInfo", GoPocProtocolCheck, []string{"netbios", "smb"}, []int{445}),
	gopoc("RPC-GetHostInfo", GoPocProtocolCheck, []string{"rpc"}, nil),
	gopoc("DNP3-Scan", GoPocProtocolCheck, []string{"dnp3"}, []int{20000}),
	gopoc("S7-Scan", GoPocProtocolCheck, []string{"s7comm"}, []int{102}),
	gopoc("EtherNetIP-Scan", GoPocProtocolCheck, []string{"enip"}, []int{44818}),
	gopoc("ATG-Scan", GoPocProtocolCheck, []string{"atg"}, []int{10001}),
	gopoc("MELSEC-Scan", GoPocProtocolCheck, []string{"melsec"}, []int{5006, 5007}),
	gopoc("FINS-Scan", GoPocProtocolCheck, []string{"fins"}, []int{9600}),
	gopoc("Crimson-Scan", GoPocProtocolCheck, []string{"crimson"}, []int{789}),
	gopoc("IEC104-Scan", GoPocProtocolCheck, []string{"iec104"}, []int{2404}),
	gopoc("ActiveMQ-Scan", GoPocProtocolCheck, []string{"activemq"}, []int{61616}),
	gopoc("SVN-Scan", GoPocProtocolCheck, []string{"svn"}, []int{3690}),
	gopoc("HsqlDb-Scan", GoPocProtocolCheck, []string{"hsqldb"}, []int{9001}),
	gopoc("MSMQ-Scan", GoPocProtocolCheck, nil, []int{1801}),
	gopoc("SAP-P4-Scan", GoPocProtocolCheck, nil, []int{50000}),

	gopoc("SMB-MS17-010", GoPocVulnerabilityCheck, []string{"smb"}, []int{445}),
	{Plugin: "Telnet-Bypass", Capability: GoPocVulnerabilityCheck, Services: []string{"telnet"}, Ports: []int{23}, Revision: 1, RequestCost: 1, Reviewed: true, Enabled: false},
	gopoc("Telnet-CVE-Scan", GoPocVulnerabilityCheck, []string{"telnet"}, []int{23}),
	gopoc("MongoDB-Crack", GoPocVulnerabilityCheck, []string{"mongodb"}, []int{27017}),
	gopoc("Memcache-Crack", GoPocVulnerabilityCheck, []string{"memcached"}, []int{11211}),
	gopoc("JDWP-Scan", GoPocVulnerabilityCheck, []string{"jdwp"}, nil),
	gopoc("ADB-Scan", GoPocVulnerabilityCheck, []string{"adb"}, []int{5555}),
	gopoc("LDAP-Scan", GoPocVulnerabilityCheck, []string{"ldap"}, []int{389}),
	gopoc("Zookeeper-Scan", GoPocVulnerabilityCheck, []string{"zookeeper"}, []int{2181}),
	gopoc("MQTT-Scan", GoPocVulnerabilityCheck, []string{"mqtt"}, []int{1883}),
	gopoc("Cassandra-Scan", GoPocVulnerabilityCheck, []string{"cassandra"}, []int{9042}),
	gopoc("ClickHouse-Scan", GoPocVulnerabilityCheck, []string{"clickhouse"}, []int{9000}),
	gopoc("RMI-Scan", GoPocVulnerabilityCheck, []string{"rmi"}, []int{1099}),
	{Plugin: "TiDB-Scan", Capability: GoPocVulnerabilityCheck, Services: []string{"mysql"}, Ports: []int{4000}, RequireServiceAndPort: true, Revision: 1, RequestCost: 1, Reviewed: true, Enabled: true},
	gopoc("Nacos-Raft-Scan", GoPocVulnerabilityCheck, nil, []int{7848}),
	{Plugin: "Shiro-Key-Crack", Capability: GoPocVulnerabilityCheck, NucleiTemplates: []string{"shiro-detect"}, Revision: 1, RequestCost: 128, Reviewed: true, Enabled: true},
	{Plugin: "ViewState-Key-Crack", Capability: GoPocVulnerabilityCheck, NucleiTemplates: []string{"yongyou_u9_viewstate"}, Fingerprints: []string{"viewstate"}, Revision: 1, RequestCost: 128, Reviewed: true, Enabled: true},
}

func GoPocDescriptors() []GoPocDescriptor {
	result := make([]GoPocDescriptor, len(goPocCatalog))
	for index, descriptor := range goPocCatalog {
		descriptor.Services = append([]string(nil), descriptor.Services...)
		descriptor.Ports = append([]int(nil), descriptor.Ports...)
		descriptor.NucleiTemplates = append([]string(nil), descriptor.NucleiTemplates...)
		descriptor.Fingerprints = append([]string(nil), descriptor.Fingerprints...)
		result[index] = descriptor
	}
	return result
}

func GoPocCatalogSHA256() string {
	descriptors := GoPocDescriptors()
	sort.Slice(descriptors, func(i, j int) bool { return descriptors[i].Plugin < descriptors[j].Plugin })
	encoded, _ := json.Marshal(struct {
		Version string            `json:"version"`
		Items   []GoPocDescriptor `json:"items"`
	}{Version: GoPocCatalogVersion, Items: descriptors})
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func GoPocDescriptorByName(plugin string) (GoPocDescriptor, bool) {
	for _, descriptor := range goPocCatalog {
		if descriptor.Plugin == strings.TrimSpace(plugin) {
			return descriptor, true
		}
	}
	return GoPocDescriptor{}, false
}

func GoPocMatchesEndpoint(descriptor GoPocDescriptor, service string, port int) (string, bool) {
	if !descriptor.Reviewed || !descriptor.Enabled || descriptor.Revision < 1 || descriptor.RequestCost < 1 {
		return "", false
	}
	service = strings.ToLower(strings.TrimSpace(service))
	serviceMatched, portMatched := false, false
	for _, allowed := range descriptor.Services {
		if service != "" && service == strings.ToLower(strings.TrimSpace(allowed)) {
			serviceMatched = true
			break
		}
	}
	for _, allowed := range descriptor.Ports {
		if port == allowed {
			portMatched = true
			break
		}
	}
	if descriptor.RequireServiceAndPort {
		return "protocol_and_port", serviceMatched && portMatched
	}
	if serviceMatched {
		return "protocol", true
	}
	if portMatched && (service == "" || service == "unknown" || service == "unidentified" || service == "tcp" || service == "protocol" || service == "portscan" || len(descriptor.Services) == 0) {
		return "standard_port", true
	}
	return "", false
}

func GoPocTargetsForEndpoint(target, service string, port int, observationSHA256 string, capability GoPocCapability) []GoPocTarget {
	result := make([]GoPocTarget, 0)
	for _, descriptor := range goPocCatalog {
		if descriptor.Capability != capability {
			continue
		}
		trigger, ok := GoPocMatchesEndpoint(descriptor, service, port)
		if !ok {
			continue
		}
		result = append(result, GoPocTarget{
			Target: target, Service: strings.ToLower(strings.TrimSpace(service)), Plugin: descriptor.Plugin,
			Capability: capability, Trigger: trigger, ObservationSHA256: strings.ToLower(strings.TrimSpace(observationSHA256)),
			PluginRevision: descriptor.Revision, RequestCost: descriptor.RequestCost,
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Plugin < result[j].Plugin })
	return result
}

func GoPocTargetForSignal(target, plugin, signalKind, signal, observationSHA256 string) (GoPocTarget, error) {
	descriptor, ok := GoPocDescriptorByName(plugin)
	if !ok {
		return GoPocTarget{}, fmt.Errorf("unknown GoPoc plugin %q", plugin)
	}
	item := GoPocTarget{
		Target: strings.TrimSpace(target), Plugin: plugin, Capability: descriptor.Capability,
		Trigger:           strings.ToLower(strings.TrimSpace(signalKind)) + ":" + strings.ToLower(strings.TrimSpace(signal)),
		ObservationSHA256: strings.ToLower(strings.TrimSpace(observationSHA256)), PluginRevision: descriptor.Revision,
		RequestCost: descriptor.RequestCost,
	}
	if err := ValidateGoPocTarget(item, descriptor.Capability); err != nil {
		return GoPocTarget{}, err
	}
	return item, nil
}

func ValidateGoPocTarget(target GoPocTarget, required GoPocCapability) error {
	descriptor, ok := GoPocDescriptorByName(target.Plugin)
	if !ok || !descriptor.Reviewed || !descriptor.Enabled {
		return fmt.Errorf("GoPoc plugin %q is not reviewed and enabled", target.Plugin)
	}
	if descriptor.Capability != required || target.Capability != required {
		return fmt.Errorf("GoPoc plugin %q does not belong to %q", target.Plugin, required)
	}
	if target.PluginRevision != descriptor.Revision || target.RequestCost != descriptor.RequestCost {
		return fmt.Errorf("GoPoc plugin %q governance metadata changed", target.Plugin)
	}
	if decoded, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(target.ObservationSHA256))); err != nil || len(decoded) != sha256.Size {
		return fmt.Errorf("GoPoc target %q has invalid observation sha256", target.Target)
	}
	if parsed, err := url.Parse(strings.TrimSpace(target.Target)); err == nil && parsed.Scheme != "" {
		if parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil {
			return fmt.Errorf("GoPoc target %q is not a safe HTTP URL", target.Target)
		}
		parts := strings.SplitN(strings.ToLower(strings.TrimSpace(target.Trigger)), ":", 2)
		if len(parts) != 2 || parts[1] == "" {
			return fmt.Errorf("GoPoc URL target %q has an invalid trigger", target.Target)
		}
		var allowed []string
		switch parts[0] {
		case "nuclei":
			allowed = descriptor.NucleiTemplates
		case "fingerprint":
			allowed = descriptor.Fingerprints
		default:
			return fmt.Errorf("GoPoc URL target %q has an unsupported trigger", target.Target)
		}
		for _, value := range allowed {
			if parts[1] == strings.ToLower(strings.TrimSpace(value)) {
				return nil
			}
		}
		return fmt.Errorf("GoPoc plugin %q is not eligible for the sealed URL trigger", target.Plugin)
	}
	host, portText, err := net.SplitHostPort(strings.TrimSpace(target.Target))
	if err != nil || strings.TrimSpace(host) == "" {
		return fmt.Errorf("GoPoc target %q must be host:port or an absolute HTTP URL", target.Target)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("GoPoc target %q has an invalid port", target.Target)
	}
	trigger, matches := GoPocMatchesEndpoint(descriptor, target.Service, port)
	if !matches || trigger != target.Trigger {
		return fmt.Errorf("GoPoc plugin %q is not eligible for the sealed endpoint", target.Plugin)
	}
	return nil
}
