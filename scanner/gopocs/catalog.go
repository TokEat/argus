package gopocs

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/P0lar1ght/argus/scanner/structs"
	"github.com/P0lar1ght/argus/shared/proto/go/scanpolicy"
)

type PluginCapability string

const (
	CapabilityCredential         PluginCapability = "credential"
	CapabilityProtocolCheck      PluginCapability = "protocol_check"
	CapabilityVulnerabilityCheck PluginCapability = "vulnerability_check"
)

type PluginDescriptor struct {
	Capability PluginCapability
	Services   []string
	Ports      []string
}

var PluginDescriptors = map[string]PluginDescriptor{
	"SSH-Crack":        credentialDescriptor([]string{"ssh"}, "22"),
	"FTP-Crack":        credentialDescriptor([]string{"ftp"}, "21"),
	"Mysql-Crack":      credentialDescriptor([]string{"mysql"}, "3306"),
	"Mssql-Crack":      credentialDescriptor([]string{"mssql", "sqlserver"}, "1433"),
	"Oracle-Crack":     credentialDescriptor([]string{"oracle"}, "1521"),
	"RDP-Crack":        credentialDescriptor([]string{"rdp"}, "3389"),
	"Redis-Crack":      credentialDescriptor([]string{"redis"}, "6379"),
	"SMB-Crack":        credentialDescriptor([]string{"smb"}, "445"),
	"PostgreSQL-Crack": credentialDescriptor([]string{"postgresql", "postgres"}, "5432"),
	"Telnet-Crack":     credentialDescriptor([]string{"telnet"}, "23"),
	"VNC-Scan":         credentialDescriptor([]string{"vnc"}, "5900", "5901"),
	"Rsync-Scan":       credentialDescriptor([]string{"rsync"}, "873"),
	"DM-Scan":          credentialDescriptor([]string{"dm"}, "5236"),
	"Kingbase-Scan":    credentialDescriptor([]string{"kingbase"}, "54321"),

	"SMB-MS17-010":        {Capability: CapabilityVulnerabilityCheck},
	"Telnet-Bypass":       {Capability: CapabilityVulnerabilityCheck},
	"Telnet-CVE-Scan":     {Capability: CapabilityVulnerabilityCheck},
	"Shiro-Key-Crack":     {Capability: CapabilityVulnerabilityCheck},
	"ViewState-Key-Crack": {Capability: CapabilityVulnerabilityCheck},
	"MongoDB-Crack":       {Capability: CapabilityVulnerabilityCheck},
	"Memcache-Crack":      {Capability: CapabilityVulnerabilityCheck},
	"JDWP-Scan":           {Capability: CapabilityVulnerabilityCheck},
	"ADB-Scan":            {Capability: CapabilityVulnerabilityCheck},
	"LDAP-Scan":           {Capability: CapabilityVulnerabilityCheck},
	"Zookeeper-Scan":      {Capability: CapabilityVulnerabilityCheck},
	"MQTT-Scan":           {Capability: CapabilityVulnerabilityCheck},
	"Cassandra-Scan":      {Capability: CapabilityVulnerabilityCheck},
	"ClickHouse-Scan":     {Capability: CapabilityVulnerabilityCheck},
	"RMI-Scan":            {Capability: CapabilityVulnerabilityCheck},
	"TiDB-Scan":           {Capability: CapabilityVulnerabilityCheck},
	"Nacos-Raft-Scan":     {Capability: CapabilityVulnerabilityCheck},

	"NetBios-GetHostInfo": {Capability: CapabilityProtocolCheck},
	"RPC-GetHostInfo":     {Capability: CapabilityProtocolCheck},
	"DNP3-Scan":           {Capability: CapabilityProtocolCheck},
	"S7-Scan":             {Capability: CapabilityProtocolCheck},
	"EtherNetIP-Scan":     {Capability: CapabilityProtocolCheck},
	"ATG-Scan":            {Capability: CapabilityProtocolCheck},
	"MELSEC-Scan":         {Capability: CapabilityProtocolCheck},
	"FINS-Scan":           {Capability: CapabilityProtocolCheck},
	"Crimson-Scan":        {Capability: CapabilityProtocolCheck},
	"IEC104-Scan":         {Capability: CapabilityProtocolCheck},
	"ActiveMQ-Scan":       {Capability: CapabilityProtocolCheck},
	"SVN-Scan":            {Capability: CapabilityProtocolCheck},
	"HsqlDb-Scan":         {Capability: CapabilityProtocolCheck},
	"MSMQ-Scan":           {Capability: CapabilityProtocolCheck},
	"SAP-P4-Scan":         {Capability: CapabilityProtocolCheck},
}

func init() {
	// The shared semantic catalog is the authority for credential targets. Keep
	// the local descriptor shape only because dispatch also classifies legacy
	// non-credential plugins.
	for _, descriptor := range scanpolicy.CredentialServices {
		ports := make([]string, len(descriptor.Ports))
		for i, port := range descriptor.Ports {
			ports[i] = strconv.Itoa(port)
		}
		PluginDescriptors[descriptor.Plugin] = credentialDescriptor(descriptor.Services, ports...)
	}
}

func credentialDescriptor(services []string, ports ...string) PluginDescriptor {
	return PluginDescriptor{Capability: CapabilityCredential, Services: services, Ports: ports}
}

func CredentialPluginEligible(plugin, service, port, eligibility string) error {
	descriptor, exists := PluginDescriptors[plugin]
	if !exists || descriptor.Capability != CapabilityCredential {
		return fmt.Errorf("plugin %q is not a credential plugin", plugin)
	}
	service = strings.ToLower(strings.TrimSpace(service))
	port = strings.TrimSpace(port)
	if service == "http" || service == "https" {
		return fmt.Errorf("HTTP service %q is excluded from generic credential validation", service)
	}
	switch strings.ToLower(strings.TrimSpace(eligibility)) {
	case "protocol":
		for _, allowed := range descriptor.Services {
			if service == allowed {
				return nil
			}
		}
		return fmt.Errorf("plugin %q does not support observed service %q", plugin, service)
	case "standard_port":
		if service != "" && service != "unknown" && service != "unidentified" {
			return fmt.Errorf("standard-port fallback cannot override observed service %q", service)
		}
		for _, allowed := range descriptor.Ports {
			if port == allowed {
				return nil
			}
		}
		return fmt.Errorf("plugin %q does not support fallback port %q", plugin, port)
	default:
		return fmt.Errorf("unsupported credential eligibility %q", eligibility)
	}
}

// DispatchCredentialTargets executes an already sealed target-to-plugin plan.
// It does no discovery, protocol identification, fingerprinting, or generic
// GoPoc dispatch.
func DispatchCredentialTargets(targets []structs.CredentialValidationTarget, bundle []structs.UserPasswd, pairLimit, threads, rateLimit int, emit func(structs.OutputMessage)) ([]structs.GoPocsResultType, error) {
	InitDictionaries()
	if pairLimit < 1 || pairLimit > scanpolicy.MaximumCredentialPairLimit {
		return nil, fmt.Errorf("credential pair limit must be between 1 and %d", scanpolicy.MaximumCredentialPairLimit)
	}
	if len(bundle) > pairLimit {
		return nil, fmt.Errorf("credential bundle contains %d pairs, exceeding limit %d", len(bundle), pairLimit)
	}
	if rateLimit < 1 {
		return nil, fmt.Errorf("credential validation rate limit must be positive")
	}
	if emit == nil {
		emit = func(msg structs.OutputMessage) {}
	}
	if threads <= 0 {
		threads = 1
	}
	dispatcher := &dispatcher{emit: emit, presentation: Presentation{MachineOutput: true}}
	limiter := newCredentialAttemptLimiter(rateLimit)
	plan := make([]scanTask, 0, len(targets))
	seen := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		host, port, err := splitCredentialEndpoint(target.Endpoint)
		if err != nil {
			return nil, err
		}
		if err := CredentialPluginEligible(target.Plugin, target.Service, port, target.Eligibility); err != nil {
			return nil, err
		}
		key := strings.ToLower(strings.TrimSpace(target.Endpoint)) + "\x00" + target.Plugin
		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf("duplicate credential target %q for plugin %q", target.Endpoint, target.Plugin)
		}
		seen[key] = struct{}{}
		pairs := append([]structs.UserPasswd(nil), bundle...)
		plan = append(plan, scanTask{Name: target.Plugin, Info: structs.HostInfo{
			Host: host, Ports: port, InfoStr: []string{target.Service},
			UserPassPairs: pairs, CredentialPairLimit: pairLimit, CredentialAttempt: limiter.Wait,
		}})
	}
	sort.Slice(plan, func(i, j int) bool {
		left := plan[i].Info.Host + ":" + plan[i].Info.Ports + "\x00" + plan[i].Name
		right := plan[j].Info.Host + ":" + plan[j].Info.Ports + "\x00" + plan[j].Name
		return left < right
	})
	dispatcher.allCount = len(plan)
	ch := make(chan struct{}, threads)
	var wg sync.WaitGroup
	for _, task := range plan {
		dispatcher.addScan(task.Name, task.Info, ch, &wg)
	}
	wg.Wait()
	return dispatcher.snapshotResults(), dispatcher.executionError()
}

type credentialAttemptLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func newCredentialAttemptLimiter(rateLimit int) *credentialAttemptLimiter {
	return &credentialAttemptLimiter{interval: time.Second / time.Duration(rateLimit)}
}

func (l *credentialAttemptLimiter) Wait() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if now.Before(l.next) {
		time.Sleep(l.next.Sub(now))
		now = time.Now()
	}
	l.next = now.Add(l.interval)
}

func waitCredentialAttempt(info *structs.HostInfo) {
	if info != nil && info.CredentialAttempt != nil {
		info.CredentialAttempt()
	}
}

func splitCredentialEndpoint(endpoint string) (string, string, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" || strings.Contains(endpoint, "://") || strings.ContainsAny(endpoint, "\r\n\x00") {
		return "", "", fmt.Errorf("invalid credential endpoint %q", endpoint)
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil || strings.TrimSpace(host) == "" {
		return "", "", fmt.Errorf("credential endpoint %q must be host:port", endpoint)
	}
	parsedPort, err := strconv.Atoi(port)
	if err != nil || parsedPort < 1 || parsedPort > 65535 {
		return "", "", fmt.Errorf("credential endpoint %q has an invalid port", endpoint)
	}
	return host, strconv.Itoa(parsedPort), nil
}
