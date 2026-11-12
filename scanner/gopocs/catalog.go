package gopocs

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TokEat/argus/scanner/structs"
	"github.com/TokEat/argus/shared/proto/go/scanpolicy"
)

type PluginCapability = scanpolicy.GoPocCapability
type PluginDescriptor = scanpolicy.GoPocDescriptor

const (
	CapabilityCredential         = scanpolicy.GoPocCredential
	CapabilityProtocolCheck      = scanpolicy.GoPocProtocolCheck
	CapabilityVulnerabilityCheck = scanpolicy.GoPocVulnerabilityCheck
)

var PluginDescriptors = func() map[string]PluginDescriptor {
	descriptors := scanpolicy.GoPocDescriptors()
	result := make(map[string]PluginDescriptor, len(descriptors))
	for _, descriptor := range descriptors {
		result[descriptor.Plugin] = descriptor
	}
	return result
}()

func CredentialPluginEligible(plugin, service, port, eligibility string) error {
	descriptor, exists := PluginDescriptors[plugin]
	if !exists || descriptor.Capability != CapabilityCredential || !descriptor.Reviewed || !descriptor.Enabled {
		return fmt.Errorf("plugin %q is not a credential plugin", plugin)
	}
	service = strings.ToLower(strings.TrimSpace(service))
	port = strings.TrimSpace(port)
	parsedPort, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("invalid credential port %q", port)
	}
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
			if parsedPort == allowed {
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
