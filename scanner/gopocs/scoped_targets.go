package gopocs

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/P0lar1ght/argus/scanner/structs"
	"github.com/P0lar1ght/argus/shared/proto/go/scanpolicy"
)

// DispatchGoPocTargets executes only the immutable plugin/target pairs sealed
// by the control plane. It never consults legacy global maps or broad service
// dispatch rules.
func DispatchGoPocTargets(targets []scanpolicy.GoPocTarget, catalogSHA256 string, capability scanpolicy.GoPocCapability, threads, rateLimit int, requestBudget int64, emit func(structs.OutputMessage)) ([]structs.GoPocsResultType, error) {
	if capability != scanpolicy.GoPocProtocolCheck && capability != scanpolicy.GoPocVulnerabilityCheck {
		return nil, fmt.Errorf("scoped GoPoc dispatch does not accept capability %q", capability)
	}
	if strings.ToLower(strings.TrimSpace(catalogSHA256)) != scanpolicy.GoPocCatalogSHA256() {
		return nil, fmt.Errorf("GoPoc catalog changed after the execution plan was sealed")
	}
	if len(targets) == 0 {
		return nil, nil
	}
	if len(targets) > scanpolicy.MaximumGoPocTargets {
		return nil, fmt.Errorf("GoPoc target plan exceeds %d entries", scanpolicy.MaximumGoPocTargets)
	}
	if threads < 1 || rateLimit < 1 || requestBudget < 1 {
		return nil, fmt.Errorf("scoped GoPoc dispatch requires positive concurrency, rate and request budget")
	}
	if emit == nil {
		emit = func(structs.OutputMessage) {}
	}
	items := append([]scanpolicy.GoPocTarget(nil), targets...)
	sort.Slice(items, func(i, j int) bool {
		if items[i].Target == items[j].Target {
			return items[i].Plugin < items[j].Plugin
		}
		return items[i].Target < items[j].Target
	})
	seen := make(map[string]struct{}, len(items))
	var estimated int64
	limiter := newCredentialAttemptLimiter(rateLimit)
	plan := make([]scanTask, 0, len(items))
	for _, item := range items {
		if err := scanpolicy.ValidateGoPocTarget(item, capability); err != nil {
			return nil, err
		}
		key := strings.ToLower(strings.TrimSpace(item.Target)) + "\x00" + item.Plugin
		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf("duplicate GoPoc target %q for plugin %q", item.Target, item.Plugin)
		}
		seen[key] = struct{}{}
		estimated += int64(item.RequestCost)
		if estimated > requestBudget {
			return nil, fmt.Errorf("GoPoc target plan exceeds the sealed request budget")
		}
		info, err := hostInfoForGoPocTarget(item)
		if err != nil {
			return nil, err
		}
		info.BeforeExecute = limiter.Wait
		if capability == scanpolicy.GoPocProtocolCheck {
			info.OutputType = "ProtocolCheck"
			info.ObservedService = item.Service
		}
		plan = append(plan, scanTask{Name: item.Plugin, Info: info})
	}

	InitDictionaries()
	dispatcher := &dispatcher{emit: emit, presentation: Presentation{MachineOutput: true}, allCount: len(plan)}
	ch := make(chan struct{}, threads)
	var wg sync.WaitGroup
	for _, task := range plan {
		dispatcher.addScan(task.Name, task.Info, ch, &wg)
	}
	wg.Wait()
	return dispatcher.snapshotResults(), dispatcher.executionError()
}

func hostInfoForGoPocTarget(item scanpolicy.GoPocTarget) (structs.HostInfo, error) {
	target := strings.TrimSpace(item.Target)
	if parsed, err := url.Parse(target); err == nil && parsed.Scheme != "" {
		return structs.HostInfo{Url: target, InfoStr: []string{item.Service}}, nil
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil || strings.TrimSpace(host) == "" {
		return structs.HostInfo{}, fmt.Errorf("GoPoc target %q must be host:port", target)
	}
	parsedPort, err := strconv.Atoi(port)
	if err != nil || parsedPort < 1 || parsedPort > 65535 {
		return structs.HostInfo{}, fmt.Errorf("GoPoc target %q has an invalid port", target)
	}
	return structs.HostInfo{Host: host, Ports: strconv.Itoa(parsedPort), InfoStr: []string{item.Service}}, nil
}
